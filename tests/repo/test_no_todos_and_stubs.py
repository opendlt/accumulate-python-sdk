#!/usr/bin/env python3

"""
Repository Quality Gate - No TODOs and Stubs

Enforces clean code standards by scanning source files for:
- TODO/FIXME/XXX/TBD/HACK comments
- Stub implementations (pass # TODO, raise NotImplementedError, assert False)

Ensures production-ready code with no placeholder implementations.
"""

import os
import re
import unittest
from typing import List, Tuple


class TestNoTodosAndStubs(unittest.TestCase):
    """Test that enforces no TODOs, FIXMEs, or stub implementations in source code"""

    def setUp(self):
        """Set up test configuration"""
        self.repo_root = os.path.join(os.path.dirname(__file__), "..", "..")
        self.src_root = os.path.join(self.repo_root, "src")

        # Files and directories to skip
        self.skip_dirs = {
            "tests",
            "tooling",
            "__pycache__",
            ".pytest_cache",
            ".git",
            ".venv",
            "node_modules",
        }

        self.skip_files = {
            "__init__.py",  # Often contains minimal imports
        }

        # Patterns that indicate TODOs or stubs
        self.todo_patterns = [
            r"\b(TODO|FIXME|XXX|TBD|HACK)\b",
            r"#.*\b(TODO|FIXME|XXX|TBD|HACK)\b",
        ]

        self.stub_patterns = [
            r"pass\s*#.*TODO",
            r"pass\s*#.*FIXME",
            r"raise\s+NotImplementedError",
            r"assert\s+False\s*(?:#.*)?$",
            r"return\s+None\s*#.*TODO",
            r"return\s+None\s*#.*FIXME",
        ]

    def get_python_files(self, root_dir: str) -> List[str]:
        """Get all Python files in the source tree, respecting skip rules"""
        python_files = []

        if not os.path.exists(root_dir):
            return python_files

        for root, dirs, files in os.walk(root_dir):
            # Skip directories in our skip list
            dirs[:] = [d for d in dirs if d not in self.skip_dirs]

            # Skip if we're in a skipped directory path
            rel_path = os.path.relpath(root, self.repo_root)
            if any(skip_dir in rel_path.split(os.sep) for skip_dir in self.skip_dirs):
                continue

            for file in files:
                if file.endswith(".py") and file not in self.skip_files:
                    python_files.append(os.path.join(root, file))

        return python_files

    def scan_file_for_patterns(self, file_path: str, patterns: List[str]) -> List[Tuple[int, str]]:
        """Scan a file for matching patterns, return (line_number, line_content) tuples"""
        matches = []

        try:
            with open(file_path, encoding="utf-8") as f:
                for line_num, line in enumerate(f, 1):
                    line_stripped = line.strip()

                    # Skip empty lines and pure comments
                    if not line_stripped or line_stripped.startswith("#"):
                        continue

                    for pattern in patterns:
                        if re.search(pattern, line, re.IGNORECASE):
                            matches.append((line_num, line_stripped))
                            break  # Only record one match per line

        except (UnicodeDecodeError, PermissionError):
            # Skip files we can't read
            pass

        return matches

    def test_no_todo_comments(self):
        """Test that source files contain no TODO/FIXME/XXX/TBD/HACK comments"""
        python_files = self.get_python_files(self.src_root)
        self.assertGreater(len(python_files), 0, "No Python files found to scan")

        todo_violations = []

        for file_path in python_files:
            matches = self.scan_file_for_patterns(file_path, self.todo_patterns)
            if matches:
                rel_path = os.path.relpath(file_path, self.repo_root)
                for line_num, line_content in matches:
                    todo_violations.append(f"{rel_path}:{line_num}: {line_content}")

        if todo_violations:
            violation_summary = "\n".join(todo_violations)
            self.fail(
                f"Found {len(todo_violations)} TODO/FIXME/XXX/TBD/HACK comments in source code:\n"
                f"{violation_summary}\n\n"
                f"All TODO comments must be resolved before production. "
                f"Consider creating GitHub issues for future work instead."
            )

    def test_no_stub_implementations(self):
        """Test that source files contain no stub implementations"""
        python_files = self.get_python_files(self.src_root)
        self.assertGreater(len(python_files), 0, "No Python files found to scan")

        stub_violations = []

        for file_path in python_files:
            matches = self.scan_file_for_patterns(file_path, self.stub_patterns)
            if matches:
                rel_path = os.path.relpath(file_path, self.repo_root)
                for line_num, line_content in matches:
                    stub_violations.append(f"{rel_path}:{line_num}: {line_content}")

        if stub_violations:
            violation_summary = "\n".join(stub_violations)
            self.fail(
                f"Found {len(stub_violations)} stub implementations in source code:\n"
                f"{violation_summary}\n\n"
                f"All stub implementations must be completed before production. "
                f"Replace with proper implementations or remove unused code."
            )

    def test_source_files_exist(self):
        """Test that we actually found source files to scan"""
        python_files = self.get_python_files(self.src_root)

        self.assertGreater(
            len(python_files),
            5,
            f"Expected to find multiple Python files in {self.src_root}, "
            f"but only found {len(python_files)}. Check scan configuration.",
        )

        # Verify we're scanning the right modules
        expected_modules = ["codec", "crypto", "canonjson"]
        found_modules = set()

        for file_path in python_files:
            rel_path = os.path.relpath(file_path, self.src_root)
            for module in expected_modules:
                if module in rel_path:
                    found_modules.add(module)

        missing_modules = set(expected_modules) - found_modules
        if missing_modules:
            scanned_files = [os.path.relpath(f, self.repo_root) for f in python_files[:10]]
            self.fail(
                f"Expected to find files from modules {expected_modules}, "
                f"but missing {missing_modules}. "
                f"Scanned files: {scanned_files}..."
            )

    def test_scan_coverage_report(self):
        """Report on what files were scanned for transparency"""
        python_files = self.get_python_files(self.src_root)

        print(f"\nScanned {len(python_files)} Python source files:")
        for file_path in sorted(python_files):
            rel_path = os.path.relpath(file_path, self.repo_root)
            print(f"  - {rel_path}")


if __name__ == "__main__":
    unittest.main()
