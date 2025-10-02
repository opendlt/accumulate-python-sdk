#!/usr/bin/env python3
"""
All-green orchestrator: Iteratively fixes tests until 100% pass with ≥85% coverage.
"""

import os
import re
import subprocess
import sys
import time
from pathlib import Path
from typing import Tuple, Optional, Dict, Any

# Add scripts directory to path
scripts_dir = Path(__file__).parent
sys.path.insert(0, str(scripts_dir))

from analyze_and_repair import analyze_and_repair


def find_repo_root() -> Path:
    """Find repository root by looking for pyproject.toml."""
    current = Path(__file__).parent
    while current != current.parent:
        if (current / "pyproject.toml").exists():
            return current
        current = current.parent
    raise RuntimeError("Could not find repository root")


def parse_pytest_output(stdout: str, stderr: str) -> Tuple[int, int, int, Optional[float]]:
    """Parse pytest output for passed/failed/errors and coverage percentage."""
    passed = failed = errors = 0
    coverage = None

    # Parse summary line: "X passed, Y failed, Z errors in Ns"
    summary_pattern = r'(\d+)\s+passed|(\d+)\s+failed|(\d+)\s+error'
    for line in stdout.split('\n') + stderr.split('\n'):
        matches = re.findall(summary_pattern, line.lower())
        for match in matches:
            if match[0]:  # passed
                passed = max(passed, int(match[0]))
            elif match[1]:  # failed
                failed = max(failed, int(match[1]))
            elif match[2]:  # errors
                errors = max(errors, int(match[2]))

    # Parse coverage: "TOTAL ... XX%"
    coverage_pattern = r'TOTAL\s+\d+\s+\d+\s+\d+\s+\d+\s+([\d.]+)%'
    for line in stdout.split('\n'):
        match = re.search(coverage_pattern, line)
        if match:
            coverage = float(match.group(1))
            break

    # Fallback: parse "Total coverage: XX.XX%"
    if coverage is None:
        alt_pattern = r'Total coverage:\s*([\d.]+)%'
        for line in stdout.split('\n'):
            match = re.search(alt_pattern, line)
            if match:
                coverage = float(match.group(1))
                break

    return passed, failed, errors, coverage


def run_pytest(unified_path: Path) -> Tuple[int, str, str, int, int, int, Optional[float]]:
    """Run pytest with coverage and return results."""
    env = os.environ.copy()
    env["ACC_DEVNET_ENDPOINT"] = "http://127.0.0.1:26660"
    env["PYTHONIOENCODING"] = "utf-8"

    cmd = [
        sys.executable, "-m", "pytest",
        "-q",
        str(unified_path / "tests"),
        "--cov=accumulate_client",
        "--cov-report=term-missing",
        "--cov-report=html",
        "--maxfail=1"
    ]

    print(f"Running: {' '.join(cmd)}")
    result = subprocess.run(
        cmd,
        cwd=unified_path,  # Run from unified directory
        capture_output=True,
        text=True,
        env=env,
        timeout=300
    )

    passed, failed, errors, coverage = parse_pytest_output(result.stdout, result.stderr)

    return result.returncode, result.stdout, result.stderr, passed, failed, errors, coverage


def run_example(example_path: Path, args: list, mock: bool = False) -> bool:
    """Run an example script and check for success."""
    env = os.environ.copy()
    env["ACC_DEVNET_ENDPOINT"] = "http://127.0.0.1:26660"
    env["PYTHONIOENCODING"] = "utf-8"

    cmd = [sys.executable, str(example_path)] + args
    if mock:
        cmd.append("--mock")

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            env=env,
            timeout=60
        )

        # Check for SUCCESS in output
        output = result.stdout + result.stderr
        return "SUCCESS" in output or "success" in output.lower()
    except Exception as e:
        print(f"  Error running example: {e}")
        return False


def main():
    """Main orchestrator loop."""
    print("=" * 60)
    print("All-Green Test Orchestrator")
    print("=" * 60)

    # Find paths - we're running from the unified directory
    unified_path = Path(__file__).parent.parent

    if not (unified_path / "pyproject.toml").exists():
        print(f"Error: Could not find pyproject.toml in {unified_path}")
        return 1

    max_iterations = 8
    iteration = 0

    while iteration < max_iterations:
        iteration += 1
        print(f"\n[Iteration {iteration}/{max_iterations}]")
        print("-" * 40)

        # Run tests
        rc, stdout, stderr, passed, failed, errors, coverage = run_pytest(unified_path)

        print(f"Results: {passed} passed, {failed} failed, {errors} errors")
        if coverage is not None:
            print(f"Coverage: {coverage:.1f}%")
        else:
            print("Coverage: unknown")

        # Check if we're green
        if errors == 0 and failed == 0 and coverage is not None and coverage >= 85:
            print("\n✅ ALL GREEN! Tests passing with adequate coverage.")
            break

        # Apply repairs
        print(f"\nApplying repairs...")
        repair_result = analyze_and_repair(stdout, stderr)
        actions_taken = repair_result.get("actions_taken", 0)
        notes = repair_result.get("notes", [])

        if actions_taken > 0:
            print(f"  {actions_taken} repairs applied:")
            for note in notes[:5]:  # Show first 5 notes
                print(f"    - {note}")
        else:
            print("  No automated repairs available")
            if iteration < max_iterations:
                print("  Continuing to next iteration...")

    # Final status
    print("\n" + "=" * 60)
    print("FINAL STATUS")
    print("=" * 60)

    if errors == 0 and failed == 0 and coverage is not None and coverage >= 85:
        print(f"✅ SUCCESS: {passed} tests passing, {coverage:.1f}% coverage")

        # Run additional validations
        print("\n[Additional Validations]")

        # RPC method discovery
        list_rpc_script = unified_path / "scripts" / "list_rpc_methods.py"
        if list_rpc_script.exists():
            print("Running RPC method discovery...")
            try:
                subprocess.run(
                    [sys.executable, str(list_rpc_script), "--out", str(unified_path / "reports")],
                    timeout=30,
                    check=True
                )
                print("  ✅ RPC methods documented")
            except Exception as e:
                print(f"  ❌ RPC discovery failed: {e}")

        # Run examples
        print("\nRunning examples against devnet...")
        examples = [
            ("01_lite_and_faucet.py", ["--endpoint", "http://127.0.0.1:26660", "--key-seed", "000102030405060708090a0b0c0d0e0f"]),
            ("02_create_adi_and_buy_credits.py", ["--endpoint", "http://127.0.0.1:26660", "--key-seed", "000102030405060708090a0b0c0d0e0f", "--adi", "acc://demo.acme"]),
            ("03_token_account_and_transfer.py", ["--endpoint", "http://127.0.0.1:26660", "--key-seed", "000102030405060708090a0b0c0d0e0f", "--adi", "acc://demo.acme"]),
            ("04_data_account_and_write.py", ["--endpoint", "http://127.0.0.1:26660", "--key-seed", "000102030405060708090a0b0c0d0e0f", "--adi", "acc://demo.acme"]),
        ]

        for script_name, args in examples:
            script_path = unified_path / "examples" / script_name
            if script_path.exists():
                print(f"  {script_name}...", end="")
                if run_example(script_path, args, mock=False):
                    print(" ✅")
                else:
                    # Retry with mock
                    if run_example(script_path, args, mock=True):
                        print(" ✅ (mock)")
                    else:
                        print(" ❌")

        # Report locations
        print("\n[Reports]")
        print(f"  Coverage HTML: {unified_path}\\htmlcov\\index.html")
        reports_dir = unified_path / "reports"
        if (reports_dir / "rpc_methods.md").exists():
            print(f"  RPC Methods: {reports_dir}\\rpc_methods.md")
        if (reports_dir / "rpc_methods.json").exists():
            print(f"  RPC JSON: {reports_dir}\\rpc_methods.json")

        return 0
    else:
        print(f"❌ FAILURE after {iteration} iterations")
        print(f"  Tests: {passed} passed, {failed} failed, {errors} errors")
        if coverage is not None:
            print(f"  Coverage: {coverage:.1f}%")
        return 1


if __name__ == "__main__":
    sys.exit(main())