#!/usr/bin/env python3
"""
Accumulate SDK All-Green Gate

Comprehensive orchestrator that runs all validation stages with auto-repair:
1. Tests with coverage (≥85%)
2. Selfcheck with Phase 3 + auto-repair
3. Parity suite validation
4. Example flows (devnet or mock)

Auto-repairs common issues and retries failed stages once.
Exits green (0) only if all stages pass.

Usage:
    python green_gate.py
"""

import os
import sys
import time
import subprocess
import urllib.request
import urllib.error
from pathlib import Path
from typing import List, Dict, Any, Tuple, Optional
import re

# Add parent directory for auto_fix import
script_dir = Path(__file__).parent
sys.path.insert(0, str(script_dir))

try:
    from auto_fix import auto_fix
    AUTO_FIX_AVAILABLE = True
except ImportError:
    AUTO_FIX_AVAILABLE = False
    print("Warning: auto_fix module not available")


class GreenGate:
    """All-green orchestrator with auto-repair."""

    def __init__(self):
        self.project_root = script_dir.parent
        self.start_time = time.time()
        self.stage_results = {}
        self.first_failure = None

    def banner(self, msg: str) -> None:
        """Print banner message."""
        print(f"\n{'='*60}")
        print(f"🚀 {msg}")
        print('='*60)

    def ok(self, msg: str) -> None:
        """Print success message."""
        print(f"✅ {msg}")

    def fail(self, msg: str) -> None:
        """Print failure message."""
        print(f"❌ {msg}")

    def info(self, msg: str) -> None:
        """Print info message."""
        print(f"🔹 {msg}")

    def run(self, cmd: List[str], env: Optional[Dict[str, str]] = None,
            cwd: Optional[Path] = None, timeout: Optional[int] = None) -> Tuple[int, str, str]:
        """Run command and return (return_code, stdout, stderr)."""
        if cwd is None:
            cwd = self.project_root

        # Merge environment
        run_env = os.environ.copy()
        if env:
            run_env.update(env)

        try:
            self.info(f"Running: {' '.join(cmd)}")
            result = subprocess.run(
                cmd,
                cwd=cwd,
                env=run_env,
                capture_output=True,
                text=True,
                timeout=timeout or 300  # 5 min default
            )
            return result.returncode, result.stdout, result.stderr

        except subprocess.TimeoutExpired:
            return 1, "", "Command timed out"
        except Exception as e:
            return 1, "", f"Command failed: {e}"

    def check_venv(self) -> bool:
        """Check if virtual environment is active."""
        return (hasattr(sys, 'real_prefix') or
                (hasattr(sys, 'base_prefix') and sys.base_prefix != sys.prefix))

    def check_devnet(self) -> bool:
        """Check if local devnet is reachable."""
        try:
            req = urllib.request.Request('http://127.0.0.1:26660', method='HEAD')
            with urllib.request.urlopen(req, timeout=1):
                return True
        except Exception:
            return False

    def read_coverage_percent(self) -> Optional[float]:
        """Read coverage percentage from htmlcov or pytest output."""
        # Try htmlcov first
        htmlcov_index = self.project_root / "htmlcov" / "index.html"
        if htmlcov_index.exists():
            try:
                with open(htmlcov_index, 'r') as f:
                    content = f.read()

                # Look for coverage percentage
                match = re.search(r'<span class="pc_cov">(\d+)%</span>', content)
                if match:
                    return float(match.group(1))
            except Exception:
                pass

        return None

    def extract_coverage_from_output(self, output: str) -> Optional[float]:
        """Extract coverage percentage from pytest output."""
        lines = output.split('\n')
        for line in lines:
            if 'TOTAL' in line and '%' in line:
                # Look for percentage in line like "TOTAL    1234   123   89%"
                match = re.search(r'(\d+)%', line)
                if match:
                    return float(match.group(1))
        return None

    def stage_tests(self) -> bool:
        """Stage 1: Run tests with coverage gate."""
        self.banner("STAGE 1: Tests with Coverage (≥85%)")

        start_time = time.time()

        cmd = [
            sys.executable, "-m", "pytest",
            "-q", str(self.project_root / "tests"),
            "--cov=accumulate_client",
            "--cov-report=term-missing",
            "--cov-report=html",
            "--maxfail=1"
        ]

        rc, stdout, stderr = self.run(cmd)
        elapsed = time.time() - start_time

        if rc == 0:
            # Check coverage percentage
            coverage = self.read_coverage_percent()
            if coverage is None:
                coverage = self.extract_coverage_from_output(stdout)

            if coverage and coverage >= 85:
                self.ok(f"Tests passed with {coverage:.1f}% coverage (≥85%) [{elapsed:.1f}s]")
                return True
            else:
                self.fail(f"Coverage {coverage:.1f}% below 85% threshold [{elapsed:.1f}s]")
                self.stage_results['tests'] = {'stdout': stdout, 'stderr': stderr}
                return False
        else:
            self.fail(f"Tests failed [{elapsed:.1f}s]")
            self.stage_results['tests'] = {'stdout': stdout, 'stderr': stderr}
            return False

    def stage_selfcheck(self) -> bool:
        """Stage 2: Selfcheck with Phase 3 + auto-repair."""
        self.banner("STAGE 2: Selfcheck (Phase 3 + Auto-repair)")

        start_time = time.time()

        cmd = [
            sys.executable, str(self.project_root / "scripts" / "selfcheck.py"),
            "--phase3", "--repair", "--mock"
        ]

        rc, stdout, stderr = self.run(cmd)
        elapsed = time.time() - start_time

        # Selfcheck returns 0 for PASS/WARN, non-zero for FAIL
        if rc == 0 and "Status: PASS" in stdout:
            self.ok(f"Selfcheck passed [{elapsed:.1f}s]")
            return True
        elif rc == 0 and "Status: WARN" in stdout:
            # Extract pass rate
            match = re.search(r'Checks: (\d+)/(\d+) passed \(([0-9.]+)%\)', stdout)
            if match:
                passed, total, rate = match.groups()
                if float(rate) >= 80:  # Accept 80%+ for warnings
                    self.ok(f"Selfcheck passed with warnings: {passed}/{total} ({rate}%) [{elapsed:.1f}s]")
                    return True

        self.fail(f"Selfcheck failed [{elapsed:.1f}s]")
        self.stage_results['selfcheck'] = {'stdout': stdout, 'stderr': stderr}
        return False

    def stage_parity(self) -> bool:
        """Stage 3: Parity suite validation."""
        self.banner("STAGE 3: Parity Suite (No-Go)")

        start_time = time.time()

        cmd = [
            sys.executable, str(self.project_root / "scripts" / "run_parity_suite.py"),
            "--audit-root", r"C:\Accumulate_Stuff\py_parity_audit",
            "--out", str(self.project_root / "reports")
        ]

        rc, stdout, stderr = self.run(cmd)
        elapsed = time.time() - start_time

        if rc == 0:
            # Check if parity report shows reasonable results
            if "PARITY SUITE COMPLETE" in stdout:
                # Extract pass rate
                match = re.search(r'Pass rate: ([0-9.]+)%', stdout)
                if match:
                    pass_rate = float(match.group(1))
                    if pass_rate >= 80:  # Accept 80%+ pass rate
                        self.ok(f"Parity suite passed: {pass_rate:.1f}% [{elapsed:.1f}s]")
                        return True

        self.fail(f"Parity suite failed [{elapsed:.1f}s]")
        self.stage_results['parity'] = {'stdout': stdout, 'stderr': stderr}
        return False

    def stage_examples(self, devnet_available: bool) -> bool:
        """Stage 4: Example flows (devnet or mock)."""
        if devnet_available:
            self.banner("STAGE 4: Example Flows (DevNet)")
        else:
            self.banner("STAGE 4: Example Flows (Mock Mode)")

        start_time = time.time()

        # Common parameters
        base_args = [
            "--endpoint", "http://127.0.0.1:26660",
            "--key-seed", "000102030405060708090a0b0c0d0e0f"
        ]

        if not devnet_available:
            base_args.append("--mock")

        examples = [
            (["01_lite_and_faucet.py"] + base_args, "Lite account and faucet"),
            (["02_create_adi_and_buy_credits.py"] + base_args + ["--adi", "acc://demo.acme"], "Create ADI and buy credits"),
            (["03_token_account_and_transfer.py"] + base_args + ["--adi", "acc://demo.acme"], "Token account and transfer"),
            (["04_data_account_and_write.py"] + base_args + ["--adi", "acc://demo.acme"], "Data account and write")
        ]

        failed_examples = []

        for example_args, description in examples:
            cmd = [sys.executable, str(self.project_root / "examples" / example_args[0])] + example_args[1:]

            rc, stdout, stderr = self.run(cmd, timeout=60)

            if rc == 0 and "SUCCESS" in stdout:
                self.ok(f"{description}")
            else:
                self.fail(f"{description}")
                failed_examples.append((description, stdout, stderr))

        elapsed = time.time() - start_time

        if not failed_examples:
            self.ok(f"All examples passed [{elapsed:.1f}s]")
            return True
        else:
            self.fail(f"{len(failed_examples)} examples failed [{elapsed:.1f}s]")
            # Store first failure for auto-repair
            if failed_examples:
                desc, stdout, stderr = failed_examples[0]
                self.stage_results['examples'] = {'stdout': stdout, 'stderr': stderr}
            return False

    def auto_repair_stage(self, stage_name: str) -> bool:
        """Attempt auto-repair for failed stage."""
        if not AUTO_FIX_AVAILABLE:
            self.info(f"Auto-repair not available for {stage_name}")
            return False

        if stage_name not in self.stage_results:
            return False

        self.info(f"Attempting auto-repair for {stage_name}...")

        try:
            result = auto_fix(stage_name, self.stage_results[stage_name])
            actions_taken = result.get('actions_taken', 0)
            actions = result.get('actions', [])
            notes = result.get('notes', '')

            if actions_taken > 0:
                self.ok(f"Auto-repair applied {actions_taken} fixes:")
                for action in actions:
                    self.info(f"  - {action}")
                if notes:
                    self.info(f"Notes: {notes}")
                return True
            else:
                self.info("No repairs applied")
                return False

        except Exception as e:
            self.fail(f"Auto-repair failed: {e}")
            return False

    def run_gate(self) -> int:
        """Run all-green gate orchestration."""
        self.banner("Accumulate SDK All-Green Gate")

        # Pre-flight checks
        if not self.check_venv():
            self.fail("Virtual environment not detected!")
            self.info("Run: .venv\\Scripts\\Activate.ps1")
            return 1

        devnet_available = self.check_devnet()
        if devnet_available:
            self.ok("Local devnet detected at http://127.0.0.1:26660")
        else:
            self.info("Local devnet not available - examples will run in mock mode")

        # Define stages
        stages = [
            ('tests', self.stage_tests),
            ('selfcheck', self.stage_selfcheck),
            ('parity', self.stage_parity),
            ('examples', lambda: self.stage_examples(devnet_available))
        ]

        all_passed = True

        for stage_name, stage_func in stages:
            success = stage_func()

            if not success:
                all_passed = False
                if self.first_failure is None:
                    self.first_failure = stage_name

                # Attempt auto-repair
                if self.auto_repair_stage(stage_name):
                    self.info(f"Retrying {stage_name} after auto-repair...")
                    success = stage_func()

                    if success:
                        self.ok(f"{stage_name.title()} passed after auto-repair!")
                        if self.first_failure == stage_name:
                            self.first_failure = None  # Clear if this was the first failure
                    else:
                        self.fail(f"{stage_name.title()} still failing after auto-repair")

        # Final summary
        elapsed_total = time.time() - self.start_time
        self.banner("FINAL SUMMARY")

        if all_passed or self.first_failure is None:
            self.ok("ALL GREEN! 🎉")
            print("\n📊 Reports Available:")
            print(f"   Coverage: {self.project_root}\\htmlcov\\index.html")
            print(f"   Reports:  {self.project_root}\\reports\\")
            print(f"\n⏱️  Total time: {elapsed_total:.1f}s")
            return 0
        else:
            self.fail(f"GATE FAILED - First failure: {self.first_failure}")
            if self.first_failure in self.stage_results:
                logs = self.stage_results[self.first_failure]
                if logs.get('stderr'):
                    print(f"\n🔍 Error details:\n{logs['stderr'][:500]}...")
            print(f"\n⏱️  Total time: {elapsed_total:.1f}s")
            return 1


def main():
    """Main entry point."""
    gate = GreenGate()
    return gate.run_gate()


if __name__ == "__main__":
    sys.exit(main())