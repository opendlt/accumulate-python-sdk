#!/usr/bin/env python3
"""
Run Tests Again + Devnet Examples + RPC Discovery (Devnet ON) — v2

Focused validation pipeline that prefers DEVNET and re-runs all stages:
1. Tests + Coverage (≥85%)
2. JSON-RPC Method Discovery from devnet
3. Examples against devnet (fallback to mock per-example)
4. Final Summary with report locations

Usage:
    python run_again_devnet.py
"""

import os
import sys
import time
import subprocess
import socket
import json
import re
from pathlib import Path
from typing import Dict, Any, Tuple, Optional


class DevnetRunner:
    """Focused devnet validation pipeline runner."""

    def __init__(self):
        self.script_dir = Path(__file__).parent
        self.project_root = self.script_dir.parent
        self.start_time = time.time()
        self.devnet_endpoint = "http://127.0.0.1:26660"
        self.reports_dir = self.project_root / "reports"

        # Ensure reports directory exists
        self.reports_dir.mkdir(exist_ok=True)

        # Test parameters
        self.seed = "000102030405060708090a0b0c0d0e0f"
        self.adi = "acc://demo.acme"

    def print_stage_header(self, stage: str, description: str):
        """Print stage header."""
        print(f"\n{'='*60}")
        print(f"STAGE {stage}: {description}")
        print('='*60)

    def print_result(self, success: bool, stage: str, elapsed: float, details: str = ""):
        """Print stage result."""
        status = "PASS" if success else "FAIL"
        print(f"{status} Stage {stage}: {elapsed:.1f}s {details}")

    def run_command(self, cmd: list, cwd: Optional[Path] = None, env: Optional[Dict[str, str]] = None, timeout: int = 300) -> Tuple[int, str, str]:
        """Run command and return (return_code, stdout, stderr)."""
        if cwd is None:
            cwd = self.project_root

        # Merge environment
        run_env = os.environ.copy()
        if env:
            run_env.update(env)

        try:
            print(f"Running: {' '.join(cmd)}")
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

    def check_devnet_health(self) -> bool:
        """Quick devnet health check."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1.0)
            result = sock.connect_ex(('127.0.0.1', 26660))
            sock.close()
            return result == 0
        except Exception:
            return False

    def extract_coverage_percentage(self, output: str) -> Optional[float]:
        """Extract coverage percentage from pytest output."""
        # Look for TOTAL line with percentage
        for line in output.split('\n'):
            if 'TOTAL' in line and '%' in line:
                match = re.search(r'(\d+)%', line)
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

    def apply_auto_fix(self, stage: str, stdout: str, stderr: str) -> bool:
        """Apply auto-fix if available."""
        try:
            # Import auto_fix from unified.scripts.auto_fix
            sys.path.insert(0, str(self.script_dir))
            from auto_fix import auto_fix

            print(f"🔧 Attempting auto-repair for {stage}...")

            result = auto_fix(stage, {"stdout": stdout, "stderr": stderr})
            actions_taken = result.get('actions_taken', 0)
            actions = result.get('actions', [])

            if actions_taken > 0:
                print(f"✅ Auto-repair applied {actions_taken} fixes:")
                for action in actions:
                    print(f"  - {action}")
                return True
            else:
                print("ℹ️  No repairs applied")
                return False

        except ImportError:
            print("ℹ️  Auto-repair not available")
            return False
        except Exception as e:
            print(f"❌ Auto-repair failed: {e}")
            return False

    def stage_1_tests_coverage(self) -> bool:
        """Stage 1: Tests + Coverage (>=85%)."""
        self.print_stage_header("S1", "Tests + Coverage (>=85%)")
        start_time = time.time()

        # Run pytest with coverage
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
                coverage = self.extract_coverage_percentage(stdout)

            if coverage and coverage >= 85:
                self.print_result(True, "S1", elapsed, f"Coverage: {coverage:.1f}%")
                return True
            else:
                coverage_str = f"{coverage:.1f}%" if coverage else "unknown"
                self.print_result(False, "S1", elapsed, f"Coverage {coverage_str} below 85%")

                # Apply auto-fix and retry once
                if self.apply_auto_fix("tests", stdout, stderr):
                    print("🔄 Retrying tests after auto-repair...")
                    rc2, stdout2, stderr2 = self.run_command(cmd)
                    elapsed_retry = time.time() - start_time

                    if rc2 == 0:
                        coverage2 = self.read_html_coverage()
                        if coverage2 is None:
                            coverage2 = self.extract_coverage_percentage(stdout2)

                        if coverage2 and coverage2 >= 85:
                            self.print_result(True, "S1", elapsed_retry, f"Coverage: {coverage2:.1f}% (after auto-fix)")
                            return True

                return False
        else:
            self.print_result(False, "S1", elapsed, "Tests failed")

            # Apply auto-fix and retry once
            if self.apply_auto_fix("tests", stdout, stderr):
                print("🔄 Retrying tests after auto-repair...")
                rc2, stdout2, stderr2 = self.run_command(cmd)
                elapsed_retry = time.time() - start_time

                if rc2 == 0:
                    coverage2 = self.read_html_coverage()
                    if coverage2 is None:
                        coverage2 = self.extract_coverage_percentage(stdout2)

                    if coverage2 and coverage2 >= 85:
                        self.print_result(True, "S1", elapsed_retry, f"Coverage: {coverage2:.1f}% (after auto-fix)")
                        return True

            return False

    def stage_2_rpc_discovery(self) -> bool:
        """Stage 2: JSON-RPC Method Discovery."""
        self.print_stage_header("S2", "JSON-RPC Method Discovery (Devnet)")
        start_time = time.time()

        # Import the RPC discovery utility
        try:
            sys.path.insert(0, str(self.script_dir))
            from list_rpc_methods import discover_rpc_methods, save_rpc_reports

            methods_data = discover_rpc_methods(f"{self.devnet_endpoint}/v3")
            if methods_data:
                save_rpc_reports(methods_data, self.reports_dir)
                elapsed = time.time() - start_time
                method_count = len(methods_data.get('methods', []))
                self.print_result(True, "S2", elapsed, f"Discovered {method_count} RPC methods")
                return True
            else:
                elapsed = time.time() - start_time
                self.print_result(False, "S2", elapsed, "Failed to discover RPC methods")
                return False

        except Exception as e:
            elapsed = time.time() - start_time
            self.print_result(False, "S2", elapsed, f"RPC discovery failed: {e}")
            return False

    def stage_3_examples(self) -> bool:
        """Stage 3: Examples (Devnet first, fallback to mock per-example)."""
        self.print_stage_header("S3", "Examples (Devnet first, fallback to mock)")
        start_time = time.time()

        examples = [
            ("01_lite_and_faucet.py", []),
            ("02_create_adi_and_buy_credits.py", ["--adi", self.adi]),
            ("03_token_account_and_transfer.py", ["--adi", self.adi]),
            ("04_data_account_and_write.py", ["--adi", self.adi])
        ]

        success_count = 0
        total_examples = len(examples)

        # Set environment for examples
        env = {
            "ACC_DEVNET_ENDPOINT": self.devnet_endpoint,
            "ACC_TEST_MODE": "devnet"
        }

        for script_name, extra_args in examples:
            script_path = self.project_root / "examples" / script_name
            if not script_path.exists():
                print(f"⚠️  Example not found: {script_name}")
                continue

            print(f"\n🔄 Running {script_name} against devnet...")

            # Base command for devnet
            cmd = [
                sys.executable, str(script_path),
                "--endpoint", self.devnet_endpoint,
                "--key-seed", self.seed
            ] + extra_args

            # Try devnet first
            rc, stdout, stderr = self.run_command(cmd, env=env, timeout=180)

            if rc == 0 and ("SUCCESS" in stdout or "success" in stdout or "✅" in stdout):
                print(f"✅ {script_name} succeeded on devnet")
                success_count += 1
            else:
                print(f"❌ {script_name} failed on devnet, trying auto-fix and mock...")

                # Apply auto-fix
                self.apply_auto_fix("examples", stdout, stderr)

                # Retry with mock
                cmd_mock = cmd + ["--mock"]
                env_mock = env.copy()
                env_mock["ACC_TEST_MODE"] = "mock"

                rc2, stdout2, stderr2 = self.run_command(cmd_mock, env=env_mock, timeout=60)

                if rc2 == 0 and ("SUCCESS" in stdout2 or "success" in stdout2):
                    print(f"✅ {script_name} succeeded with --mock after auto-fix")
                    success_count += 1
                else:
                    print(f"❌ {script_name} failed even with --mock")

        elapsed = time.time() - start_time
        all_success = success_count == total_examples
        self.print_result(all_success, "S3", elapsed, f"{success_count}/{total_examples} examples succeeded")
        return all_success

    def stage_4_summary(self, s1_success: bool, s2_success: bool, s3_success: bool):
        """Stage 4: Final Summary."""
        self.print_stage_header("S4", "Final Summary")

        total_elapsed = time.time() - self.start_time
        all_green = s1_success and s2_success and s3_success

        print(f"\nFINAL RESULTS:")
        print(f"S1 Tests + Coverage: {'PASS' if s1_success else 'FAIL'}")
        print(f"S2 RPC Discovery:    {'PASS' if s2_success else 'FAIL'}")
        print(f"S3 Examples:         {'PASS' if s3_success else 'FAIL'}")
        print(f"Total time: {total_elapsed:.1f}s")

        if s1_success:
            coverage = self.read_html_coverage()
            if coverage:
                print(f"\nCoverage: {coverage:.1f}%")

        print(f"\nReport Locations:")
        print(f"   Coverage HTML: {self.project_root}\\htmlcov\\index.html")

        if s2_success:
            print(f"   RPC Methods:   {self.reports_dir}\\rpc_methods.md")
            print(f"   RPC JSON:      {self.reports_dir}\\rpc_methods.json")

        if all_green:
            print(f"\nALL GREEN - COMPLETE SUCCESS!")
            print(f"Tests passed with >=85% coverage")
            print(f"RPC methods discovered from devnet")
            print(f"All examples executed successfully")
        else:
            print(f"\nPIPELINE INCOMPLETE")
            print(f"Some stages failed. Check individual stage results above.")

        return all_green

    def run_pipeline(self) -> int:
        """Run complete validation pipeline."""
        print("Run Tests Again + Devnet Examples + RPC Discovery (Devnet ON) - v2")

        # Check devnet health
        devnet_healthy = self.check_devnet_health()
        if devnet_healthy:
            print(f"Devnet health check passed: {self.devnet_endpoint}")
        else:
            print(f"Devnet health check failed: {self.devnet_endpoint}")
            print(f"Will still attempt stages, but expect some failures.")

        # Run stages
        s1_success = self.stage_1_tests_coverage()
        s2_success = self.stage_2_rpc_discovery()
        s3_success = self.stage_3_examples()

        # Final summary
        all_green = self.stage_4_summary(s1_success, s2_success, s3_success)

        return 0 if all_green else 1


def main():
    """Main entry point."""
    runner = DevnetRunner()
    return runner.run_pipeline()


if __name__ == "__main__":
    sys.exit(main())