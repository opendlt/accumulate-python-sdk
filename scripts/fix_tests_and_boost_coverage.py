#!/usr/bin/env python3
"""
S1-focused test runner with auto-fix and coverage enforcement.

Runs pytest with coverage, applies auto-fix once if needed, and ensures ≥85% coverage.
"""

import sys
import subprocess
import re
import os
from pathlib import Path
from typing import Optional, Tuple


def run_pytest_with_coverage() -> Tuple[int, str, str, Optional[float]]:
    """Run pytest with coverage and return (returncode, stdout, stderr, coverage_pct)."""
    cmd = [
        sys.executable, "-m", "pytest",
        "-q",
        ".\\unified\\tests",
        "--cov=accumulate_client",
        "--cov-report=term-missing",
        "--cov-report=html",
        "--maxfail=1"
    ]

    print(f"Running: {' '.join(cmd)}")

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=300,
            cwd=Path(__file__).parent.parent.parent  # Run from repo root
        )

        # Extract coverage from stdout
        coverage_pct = extract_coverage_from_output(result.stdout)

        # If not found in stdout, try HTML report
        if coverage_pct is None:
            coverage_pct = read_html_coverage()

        return result.returncode, result.stdout, result.stderr, coverage_pct

    except subprocess.TimeoutExpired:
        print("ERROR: Tests timed out after 300 seconds")
        return 1, "", "Timeout", None
    except Exception as e:
        print(f"ERROR: Failed to run tests: {e}")
        return 1, "", str(e), None


def extract_coverage_from_output(output: str) -> Optional[float]:
    """Extract coverage percentage from pytest output."""
    # Look for TOTAL line with percentage
    for line in output.split('\n'):
        if 'TOTAL' in line and '%' in line:
            match = re.search(r'(\d+)%', line)
            if match:
                return float(match.group(1))
    return None


def read_html_coverage() -> Optional[float]:
    """Read coverage from HTML report if available."""
    htmlcov_path = Path(__file__).parent.parent / "htmlcov" / "index.html"

    if not htmlcov_path.exists():
        return None

    try:
        with open(htmlcov_path, 'r', encoding='utf-8') as f:
            content = f.read()

        # Look for coverage percentage in HTML
        match = re.search(r'<span class="pc_cov">(\d+)%</span>', content)
        if match:
            return float(match.group(1))
    except Exception:
        pass

    return None


def apply_auto_fix(stdout: str, stderr: str) -> bool:
    """Apply auto-fix if available."""
    try:
        # Try to import auto_fix from unified.scripts.auto_fix
        sys.path.insert(0, str(Path(__file__).parent))
        from auto_fix import auto_fix

        print("Applying auto-fix for test failures...")

        result = auto_fix("tests", {
            "stage": "S1",
            "stdout": stdout,
            "stderr": stderr
        })

        actions_taken = result.get('actions_taken', 0)
        if actions_taken > 0:
            print(f"Auto-fix applied {actions_taken} fixes")
            return True
        else:
            print("No auto-fixes applied")
            return False

    except ImportError:
        print("Auto-fix not available (auto_fix.py not found)")
        return False
    except Exception as e:
        print(f"Auto-fix failed: {e}")
        return False


def main():
    """Main entry point."""
    print("=" * 60)
    print("S1 Test Runner - Coverage Enforcement (>=85%)")
    print("=" * 60)

    # Run initial test pass
    print("\n[PASS 1] Running tests with coverage...")
    rc, stdout, stderr, coverage = run_pytest_with_coverage()

    print(f"\nInitial results:")
    print(f"  Return code: {rc}")
    print(f"  Coverage: {coverage:.1f}%" if coverage else "  Coverage: unknown")

    # Check if we need to apply fixes
    needs_fix = rc != 0 or (coverage and coverage < 85)

    if needs_fix:
        print("\nTests failed or coverage < 85%, attempting auto-fix...")

        # Apply auto-fix
        fixed = apply_auto_fix(stdout, stderr)

        if fixed:
            # Re-run tests after fix
            print("\n[PASS 2] Re-running tests after auto-fix...")
            rc, stdout, stderr, coverage = run_pytest_with_coverage()

            print(f"\nResults after auto-fix:")
            print(f"  Return code: {rc}")
            print(f"  Coverage: {coverage:.1f}%" if coverage else "  Coverage: unknown")

    # Final evaluation
    print("\n" + "=" * 60)
    print("FINAL RESULTS")
    print("=" * 60)

    if rc == 0:
        print("ALL tests PASSED")
    else:
        print("Tests FAILED")
        print("\nTest output:")
        if stdout:
            print(stdout[-2000:])  # Last 2000 chars to avoid spam
        if stderr:
            print("Errors:")
            print(stderr[-1000:])

    if coverage:
        print(f"Coverage: {coverage:.1f}%")

        if coverage >= 85:
            print("Coverage meets 85% threshold")
        else:
            print(f"Coverage {coverage:.1f}% is below 85% threshold")
    else:
        print("Could not determine coverage")

    # Report locations
    print("\nReport locations:")
    htmlcov_path = Path(__file__).parent.parent / "htmlcov" / "index.html"
    if htmlcov_path.exists():
        print(f"  HTML Coverage: {htmlcov_path.absolute()}")

    # Exit code
    success = rc == 0 and coverage and coverage >= 85

    if success:
        print("\nSUCCESS: All tests pass with >=85% coverage!")
    else:
        print("\nFAILURE: Tests failed or coverage < 85%")

    return 0 if success else 1


if __name__ == "__main__":
    sys.exit(main())