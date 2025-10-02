#!/usr/bin/env python3
"""
Accumulate SDK Test and Debug Runner

Focused validation runner that executes:
1. Test suite with ≥85% coverage requirement
2. Example flows against local devnet (or mock mode)

Includes auto-repair capabilities for common failures.
Exits green only when all stages pass.

Usage:
    python test_and_debug.py
"""

import os
import sys
import time
import subprocess
import socket
import urllib.request
import urllib.error
import re
from pathlib import Path
from typing import List, Dict, Any, Tuple, Optional


class TestRunner:
    """Test and debug orchestrator with auto-repair."""

    def __init__(self):
        self.script_dir = Path(__file__).parent
        self.project_root = self.script_dir.parent
        self.start_time = time.time()
        self.devnet_available = False

        # Add project to path for auto_fix import
        sys.path.insert(0, str(self.script_dir))

    def banner(self, msg: str) -> None:
        """Print banner message."""
        print(f"\n{'='*50}")
        print(f">> {msg}")
        print('='*50)

    def ok(self, msg: str) -> None:
        """Print success message."""
        print(f"[OK] {msg}")

    def fail(self, msg: str) -> None:
        """Print failure message."""
        print(f"[FAIL] {msg}")

    def info(self, msg: str) -> None:
        """Print info message."""
        print(f"[INFO] {msg}")

    def run_command(self, cmd: List[str], env: Optional[Dict[str, str]] = None,
                   cwd: Optional[Path] = None, timeout: int = 300) -> Tuple[int, str, str]:
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
                timeout=timeout
            )
            return result.returncode, result.stdout, result.stderr

        except subprocess.TimeoutExpired:
            return 1, "", f"Command timed out after {timeout}s"
        except Exception as e:
            return 1, "", f"Command failed: {e}"

    def check_devnet_http(self) -> bool:
        """Check if devnet is reachable via HTTP HEAD."""
        try:
            req = urllib.request.Request('http://127.0.0.1:26660/', method='HEAD')
            with urllib.request.urlopen(req, timeout=2):
                return True
        except Exception:
            return False

    def get_devnet_status(self) -> Optional[Dict[str, Any]]:
        """Get devnet status information."""
        try:
            import json
            req = urllib.request.Request('http://127.0.0.1:26660/status')
            with urllib.request.urlopen(req, timeout=3) as response:
                data = json.loads(response.read().decode())
                return data
        except Exception:
            return None

    def check_devnet_tcp(self) -> bool:
        """Check if devnet is reachable via TCP connect."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex(('127.0.0.1', 26660))
            sock.close()
            return result == 0
        except Exception:
            return False

    def check_devnet(self) -> bool:
        """Check if local devnet is reachable."""
        # Try HTTP first (more reliable for API)
        if self.check_devnet_http():
            return True

        # Fallback to TCP check
        if self.check_devnet_tcp():
            self.info("Devnet TCP port open but HTTP may be starting up...")
            # Give it a moment and try HTTP again
            import time
            time.sleep(2)
            return self.check_devnet_http()

        return False

    def extract_coverage(self, output: str) -> Optional[float]:
        """Extract coverage percentage from pytest output."""
        # Look for TOTAL line with percentage
        for line in output.split('\n'):
            if 'TOTAL' in line and '%' in line:
                match = re.search(r'(\d+)%', line)
                if match:
                    return float(match.group(1))

        # Also check for coverage fail-under messages
        if 'FAILED' in output and 'coverage' in output.lower():
            match = re.search(r'(\d+(?:\.\d+)?)%.*coverage', output, re.IGNORECASE)
            if match:
                return float(match.group(1))

        return None

    def read_html_coverage(self) -> Optional[float]:
        """Read coverage percentage from htmlcov/index.html."""
        htmlcov_index = self.project_root / "htmlcov" / "index.html"
        if htmlcov_index.exists():
            try:
                with open(htmlcov_index, 'r') as f:
                    content = f.read()

                # Look for coverage percentage span
                match = re.search(r'<span class="pc_cov">(\d+)%</span>', content)
                if match:
                    return float(match.group(1))
            except Exception:
                pass
        return None

    def stage_tests(self) -> bool:
        """Stage 1: Run tests with coverage >=85%."""
        self.banner("STAGE 1: Tests with Coverage (>=85%)")
        start_time = time.time()

        cmd = [
            sys.executable, "-m", "pytest",
            "-q", str(self.project_root / "tests"),
            "--cov=accumulate_client",
            "--cov-report=term-missing",
            "--cov-report=html",
            "--maxfail=1"
        ]

        rc, stdout, stderr = self.run_command(cmd)
        elapsed = time.time() - start_time

        if rc == 0:
            # Check coverage percentage
            coverage = self.read_html_coverage()
            if coverage is None:
                coverage = self.extract_coverage(stdout)

            if coverage and coverage >= 85:
                self.ok(f"Tests passed with {coverage:.1f}% coverage [{elapsed:.1f}s]")
                return True
            else:
                coverage_str = f"{coverage:.1f}%" if coverage else "unknown"
                self.fail(f"Coverage {coverage_str} below 85% threshold [{elapsed:.1f}s]")
                return False
        else:
            self.fail(f"Tests failed [{elapsed:.1f}s]")
            if stderr:
                print(f"Error details: {stderr[:300]}...")
            return False

    def stage_examples(self) -> bool:
        """Stage 2: Run example flows."""
        if self.devnet_available:
            self.banner("STAGE 2: Example Flows (Live DevNet Integration)")
            self.info("Using real Accumulate devnet at http://127.0.0.1:26660")
        else:
            self.banner("STAGE 2: Example Flows (Mock Mode - DevNet Unavailable)")
            self.info("DevNet not reachable - falling back to mock transport")

        start_time = time.time()

        # Set environment for examples
        env = {
            "ACC_DEVNET_ENDPOINT": "http://127.0.0.1:26660",
            "ACC_TEST_MODE": "devnet" if self.devnet_available else "mock"
        }

        # Common parameters - always point to devnet endpoint
        base_args = [
            "--endpoint", "http://127.0.0.1:26660",
            "--key-seed", "000102030405060708090a0b0c0d0e0f"
        ]

        # Only add --mock if devnet is truly unavailable
        if not self.devnet_available:
            base_args.append("--mock")
            self.info("Adding --mock flag due to devnet unavailability")

        examples = [
            ("01_lite_and_faucet.py", base_args, "Lite account and faucet"),
            ("02_create_adi_and_buy_credits.py", base_args + ["--adi", "acc://demo.acme"], "Create ADI and buy credits"),
            ("03_token_account_and_transfer.py", base_args + ["--adi", "acc://demo.acme"], "Token account and transfer"),
            ("04_data_account_and_write.py", base_args + ["--adi", "acc://demo.acme"], "Data account and write")
        ]

        failed_examples = []

        for example_file, args, description in examples:
            cmd = [sys.executable, str(self.project_root / "examples" / example_file)] + args

            # Give more time for devnet operations
            timeout = 180 if self.devnet_available else 60

            rc, stdout, stderr = self.run_command(cmd, env=env, timeout=timeout)

            if rc == 0 and ("SUCCESS" in stdout or "🎉" in stdout):
                if self.devnet_available:
                    self.ok(f"{description} (LIVE DEVNET)")
                else:
                    self.ok(f"{description} (mock)")
            else:
                self.fail(f"{description}")
                failed_examples.append((description, stdout, stderr))

                # Show more context for devnet failures
                if self.devnet_available:
                    print(f"  DevNet Integration Error:")
                    if "Connection" in stderr or "timeout" in stderr.lower():
                        print(f"     Network issue: {stderr[:150]}...")
                        print(f"     TIP: Check if devnet is still running")
                    elif stderr:
                        print(f"     {stderr[:200]}...")
                    if "faucet" in stderr.lower():
                        print(f"     TIP: Faucet may be rate-limited or unavailable")
                else:
                    print(f"  Mock Error: {stderr[:200]}..." if stderr else "Unknown error")

        elapsed = time.time() - start_time

        if not failed_examples:
            self.ok(f"All examples passed [{elapsed:.1f}s]")
            return True
        else:
            self.fail(f"{len(failed_examples)} examples failed [{elapsed:.1f}s]")
            return False

    def auto_repair(self, stage: str, stdout: str, stderr: str) -> bool:
        """Attempt auto-repair for failed stage."""
        try:
            from auto_fix import auto_fix
        except ImportError:
            self.info("Auto-repair module not available")
            return False

        self.info(f"Attempting auto-repair for {stage}...")

        try:
            result = auto_fix(stage, {"stdout": stdout, "stderr": stderr})
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

    def run_with_repair(self, stage_name: str, stage_func) -> bool:
        """Run stage with auto-repair on failure."""
        success = stage_func()

        if not success:
            # Capture stage output for auto-repair
            # Re-run to capture logs
            if stage_name == "tests":
                cmd = [
                    sys.executable, "-m", "pytest",
                    "-q", str(self.project_root / "tests"),
                    "--cov=accumulate_client",
                    "--cov-report=term-missing",
                    "--cov-report=html",
                    "--maxfail=1"
                ]
                rc, stdout, stderr = self.run_command(cmd)
            elif stage_name == "examples":
                # For examples, just use generic error info
                stdout = "Example execution failed"
                stderr = "One or more examples failed to complete successfully"
            else:
                stdout, stderr = "", ""

            # Attempt auto-repair
            if self.auto_repair(stage_name, stdout, stderr):
                self.info(f"Retrying {stage_name} after auto-repair...")
                success = stage_func()

                if success:
                    self.ok(f"{stage_name.title()} passed after auto-repair!")
                else:
                    self.fail(f"{stage_name.title()} still failing after auto-repair")

        return success

    def run_pipeline(self) -> int:
        """Run complete test and debug pipeline."""
        self.banner("Accumulate SDK Test and Debug Runner")

        # Check devnet availability - prioritize real devnet usage
        self.devnet_available = self.check_devnet()
        if self.devnet_available:
            self.ok("Local Accumulate devnet ACTIVE at http://127.0.0.1:26660")

            # Get devnet status for additional info
            status = self.get_devnet_status()
            if status and 'data' in status:
                network = status['data'].get('network', 'unknown')
                version = status['data'].get('version', 'unknown')
                self.info(f"DevNet Info: {network} v{version}")

            self.info("Will run REAL integration tests against live devnet")
        else:
            self.fail("Local devnet NOT REACHABLE at http://127.0.0.1:26660")
            self.info("Examples will fall back to mock mode (not ideal for integration testing)")
            self.info("Start devnet: docker-compose up -d accumulate")

        # Run stages with auto-repair
        all_passed = True

        # Stage 1: Tests
        if not self.run_with_repair("tests", self.stage_tests):
            all_passed = False

        # Stage 2: Examples
        if not self.run_with_repair("examples", self.stage_examples):
            all_passed = False

        # Final summary
        elapsed_total = time.time() - self.start_time
        self.banner("FINAL SUMMARY")

        if all_passed:
            self.ok("ALL GREEN - FULL INTEGRATION SUCCESS!")

            if self.devnet_available:
                print("\nREAL DEVNET INTEGRATION COMPLETE:")
                print("   [OK] Tests passed with live coverage")
                print("   [OK] All examples executed against running devnet")
                print("   [OK] Full end-to-end transaction flow validated")
            else:
                print("\nMOCK MODE VALIDATION COMPLETE:")
                print("   [OK] Tests passed with coverage")
                print("   [OK] Examples validated in mock mode")
                print("   [WARN] Consider running against live devnet for full validation")

            print("\nReports Available:")
            print(f"   Coverage: {self.project_root}\\htmlcov\\index.html")
            print(f"   Reports:  {self.project_root}\\reports\\")

            # Show final coverage
            coverage = self.read_html_coverage()
            if coverage:
                print(f"   Final Coverage: {coverage:.1f}%")

            print(f"\nTotal time: {elapsed_total:.1f}s")
            return 0
        else:
            self.fail("PIPELINE FAILED")
            print(f"\nTotal time: {elapsed_total:.1f}s")
            print("\nTry running individual stages to debug:")
            print("   pytest -q tests/ --cov=accumulate_client --cov-report=html")
            print("   python examples/01_lite_and_faucet.py --mock --help")
            return 1


def main():
    """Main entry point."""
    runner = TestRunner()
    return runner.run_pipeline()


if __name__ == "__main__":
    sys.exit(main())