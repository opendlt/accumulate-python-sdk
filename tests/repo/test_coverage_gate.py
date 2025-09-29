#!/usr/bin/env python3

"""
Coverage Gate Test

Enforces minimum code coverage requirements for critical modules.
Ensures comprehensive testing of codec, crypto, and canonjson functionality.
"""

import os
import subprocess
import sys
import unittest
from typing import Dict, List, Tuple


class TestCoverageGate(unittest.TestCase):
    """Test that enforces minimum code coverage requirements"""

    def setUp(self):
        """Set up coverage requirements"""
        self.repo_root = os.path.join(os.path.dirname(__file__), "..", "..")

        # Minimum coverage requirements
        self.overall_minimum = 70.0  # Overall threshold including integration code
        self.critical_minimum = 85.0  # Higher threshold for critical codec/crypto modules

        # Critical modules that must meet coverage requirements
        self.critical_modules = [
            "src/accumulate_client/codec/",
            "src/accumulate_client/crypto/",
            "src/accumulate_client/canonjson.py",
        ]

    def run_coverage_report(self) -> Tuple[float, Dict[str, float], List[str]]:
        """Run coverage report and parse results"""

        # Change to repo root for coverage commands
        original_cwd = os.getcwd()
        try:
            os.chdir(self.repo_root)

            # Run basic coverage report
            result = subprocess.run(
                [sys.executable, "-m", "coverage", "report"],
                capture_output=True,
                text=True,
                check=False,
            )

            if result.returncode != 0:
                self.fail(f"Coverage report command failed: {result.stderr}")

            return self.parse_coverage_output(result.stdout, result.stderr)

        finally:
            os.chdir(original_cwd)

    def parse_coverage_output(
        self, stdout: str, stderr: str
    ) -> Tuple[float, Dict[str, float], List[str]]:
        """Parse coverage output to extract overall and per-file coverage"""
        overall_coverage = 0.0
        file_coverage = {}
        uncovered_files = []

        lines = stdout.split("\n")
        in_report_section = False

        for line in lines:
            line = line.strip()

            # Skip header lines until we find the data section
            if "Name" in line and "Stmts" in line and "Cover" in line:
                in_report_section = True
                continue

            if line.startswith("------"):
                continue

            if not in_report_section:
                continue

            # Look for total coverage line
            if "TOTAL" in line:
                # Line format: "TOTAL    431   130    70%"
                parts = line.split()
                if len(parts) >= 4:
                    coverage_str = parts[-1]
                    if coverage_str.endswith("%"):
                        try:
                            overall_coverage = float(coverage_str.rstrip("%"))
                        except ValueError:
                            pass

            # Look for individual file coverage
            elif line and not line.startswith("Name"):
                # Line format: "src\accumulate_client\canonjson.py    15      0   100%"
                parts = line.split()
                if len(parts) >= 4:
                    filename = parts[0]
                    coverage_str = parts[-1]

                    if coverage_str.endswith("%"):
                        try:
                            coverage_pct = float(coverage_str.rstrip("%"))
                            file_coverage[filename] = coverage_pct

                            # Check if this is a critical module (normalize path separators)
                            filename_normalized = filename.replace("\\", "/")
                            if any(
                                critical.replace("\\", "/") in filename_normalized
                                for critical in self.critical_modules
                            ):
                                if coverage_pct < self.critical_minimum:
                                    uncovered_files.append(f"{filename}: {coverage_pct}%")

                        except (ValueError, IndexError):
                            continue

        # If we didn't find coverage info, check stderr
        if overall_coverage == 0.0 and stderr:
            if "No data to report" in stderr:
                raise unittest.SkipTest(
                    "No coverage data available. Run 'coverage run -m pytest' first."
                )
            else:
                self.fail(f"Coverage report failed: {stderr}")

        return overall_coverage, file_coverage, uncovered_files

    def test_overall_coverage_meets_minimum(self):
        """Test that overall coverage meets the minimum threshold"""
        overall_coverage, file_coverage, uncovered_files = self.run_coverage_report()

        self.assertGreaterEqual(
            overall_coverage,
            self.overall_minimum,
            f"Overall coverage {overall_coverage:.1f}% is below minimum {self.overall_minimum}%.\n"
            f"Files with low coverage in critical modules:\n"
            + "\n".join(f"  - {file}" for file in uncovered_files)
            if uncovered_files
            else "",
        )

    def test_critical_modules_coverage(self):
        """Test that critical modules meet higher coverage requirements"""
        # Run coverage report specifically for critical modules
        original_cwd = os.getcwd()
        try:
            os.chdir(self.repo_root)

            # Get coverage for critical modules only
            result = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "coverage",
                    "report",
                    "--include=*/codec/*,*/crypto/*,*/canonjson.py",
                ],
                capture_output=True,
                text=True,
                check=False,
            )

            if result.returncode != 0:
                self.fail(f"Critical modules coverage report failed: {result.stderr}")

            critical_overall, critical_files, critical_uncovered = self.parse_coverage_output(
                result.stdout, result.stderr
            )

        finally:
            os.chdir(original_cwd)

        # Check that critical modules meet the higher threshold
        self.assertGreaterEqual(
            critical_overall,
            self.critical_minimum,
            f"Critical modules coverage {critical_overall:.1f}% is below minimum {self.critical_minimum}%.\n"
            f"Critical modules with low coverage:\n"
            + "\n".join(f"  - {file}" for file in critical_uncovered)
            if critical_uncovered
            else "",
        )

        print(
            f"\nCritical modules coverage: {critical_overall:.1f}% (minimum: {self.critical_minimum}%)"
        )
        for filename, coverage_pct in sorted(critical_files.items()):
            status = "PASS" if coverage_pct >= self.critical_minimum else "FAIL"
            print(f"  [{status}] {filename}: {coverage_pct:.1f}%")

    def test_coverage_report_format(self):
        """Test that coverage report runs and provides useful information"""
        overall_coverage, file_coverage, uncovered_files = self.run_coverage_report()

        self.assertGreater(overall_coverage, 0, "Coverage report should show non-zero coverage")
        self.assertGreater(
            len(file_coverage), 0, "Coverage report should include individual file coverage"
        )

        print("\nCoverage Summary:")
        print(f"  Overall: {overall_coverage:.1f}% (minimum: {self.overall_minimum}%)")
        print(f"  Files analyzed: {len(file_coverage)}")

        # Show coverage for critical modules
        critical_coverage = []
        for filename, coverage_pct in sorted(file_coverage.items()):
            if any(critical in filename for critical in self.critical_modules):
                status = "✓" if coverage_pct >= self.overall_minimum else "✗"
                critical_coverage.append(f"    {status} {filename}: {coverage_pct:.1f}%")

        if critical_coverage:
            print("  Critical modules:")
            for line in critical_coverage:
                print(line)


if __name__ == "__main__":
    unittest.main()
