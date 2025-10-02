#!/usr/bin/env python3
"""
Fix relative imports in test files.
"""

import os
import re
from pathlib import Path


def fix_imports_in_file(filepath):
    """Fix relative imports in a single file."""
    with open(filepath, 'r', encoding='utf-8') as f:
        content = f.read()

    # Check if already fixed
    if "sys.path.insert(0, str(Path(__file__).parent.parent))" in content:
        print(f"Already fixed: {filepath}")
        return False

    # Find the relative import line
    pattern = r'^from \.\.helpers import (.+)$'

    lines = content.split('\n')
    fixed_lines = []
    import_fixed = False

    for i, line in enumerate(lines):
        if re.match(pattern, line):
            # Get what's being imported
            match = re.match(pattern, line)
            imports = match.group(1)

            # Insert the sys.path fix before the import
            if not import_fixed:
                # Find where to insert (after other imports but before from ..helpers)
                insert_lines = [
                    "import sys",
                    "from pathlib import Path",
                    "",
                    "# Add parent directory to path for imports",
                    "sys.path.insert(0, str(Path(__file__).parent.parent))",
                    f"from helpers import {imports}"
                ]

                # Check if we already have sys/Path imports
                has_sys = any("import sys" in l for l in lines[:i])
                has_path = any("from pathlib import Path" in l for l in lines[:i])

                if not has_sys and not has_path:
                    fixed_lines.extend(insert_lines)
                elif has_sys and not has_path:
                    fixed_lines.extend([
                        "from pathlib import Path",
                        "",
                        "# Add parent directory to path for imports",
                        "sys.path.insert(0, str(Path(__file__).parent.parent))",
                        f"from helpers import {imports}"
                    ])
                elif has_path and not has_sys:
                    fixed_lines.extend([
                        "import sys",
                        "",
                        "# Add parent directory to path for imports",
                        "sys.path.insert(0, str(Path(__file__).parent.parent))",
                        f"from helpers import {imports}"
                    ])
                else:
                    fixed_lines.extend([
                        "",
                        "# Add parent directory to path for imports",
                        "sys.path.insert(0, str(Path(__file__).parent.parent))",
                        f"from helpers import {imports}"
                    ])
                import_fixed = True
        else:
            fixed_lines.append(line)

    if import_fixed:
        # Write back
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write('\n'.join(fixed_lines))
        print(f"Fixed: {filepath}")
        return True

    return False


def main():
    """Fix all test files with relative imports."""
    test_dir = Path(__file__).parent.parent / "tests"

    # Files to fix
    files_to_fix = [
        "fuzz/test_tx_roundtrip_fuzz.py",
        "signers/test_delegation_resolution.py",
        "signers/test_multisig_sets.py",
        "signers/test_signature_types.py",
        "tx/test_builders_roundtrip.py",
        "tx/test_execute_harness.py",
        "tx/test_fees.py",
        "tx/test_validation.py",
        "wallet/test_wallet_keystore.py",
    ]

    fixed_count = 0
    for file_path in files_to_fix:
        full_path = test_dir / file_path
        if full_path.exists():
            if fix_imports_in_file(full_path):
                fixed_count += 1
        else:
            print(f"Not found: {full_path}")

    print(f"\nFixed {fixed_count} files")


if __name__ == "__main__":
    main()