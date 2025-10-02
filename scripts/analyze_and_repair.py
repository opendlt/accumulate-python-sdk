#!/usr/bin/env python3
"""
Analyze test failures and apply targeted repairs.
"""

import re
import sys
from pathlib import Path
from typing import Dict, List, Any

# Add scripts directory to path
scripts_dir = Path(__file__).parent
sys.path.insert(0, str(scripts_dir))

from patches import (
    ensure_pyproject_deps,
    fix_import_path,
    ensure_package_export,
    create_missing_signer_ed25519,
    align_api_methods_with_parity,
    update_validation_and_fees,
    fix_invalid_escape_sequences_in_tests,
    strengthen_init_exports
)
from parity_sync import get_expected_api_methods


def analyze_and_repair(test_stdout: str, test_stderr: str) -> Dict[str, Any]:
    """
    Analyze test output and apply repairs.

    Returns:
        dict with "actions_taken" (int) and "notes" (list of strings)
    """
    actions_taken = 0
    notes = []

    combined_output = test_stdout + "\n" + test_stderr

    # 1. Check for ImportError / ModuleNotFoundError
    import_errors = re.findall(
        r"ImportError: (?:cannot import name '(\w+)'|No module named '([\w.]+)')",
        combined_output
    )

    for error in import_errors:
        if error[0]:  # Cannot import name
            name = error[0]
            notes.append(f"Missing import: {name}")

            # Common fixes for missing imports
            if "Ed25519" in name or "LegacyEd25519" in name:
                if create_missing_signer_ed25519():
                    actions_taken += 1
                    notes.append("Created Ed25519 signer implementations")

            elif "RequestBatcher" in name:
                # This is expected to be BatchClient
                if fix_import_path("RequestBatcher", "BatchClient"):
                    actions_taken += 1
                    notes.append("Fixed RequestBatcher -> BatchClient")

        elif error[1]:  # No module named
            module = error[1]
            notes.append(f"Missing module: {module}")

            # Check if it's a missing dependency
            if "websocket" in module.lower():
                if ensure_pyproject_deps(["websocket-client"], dev=False):
                    actions_taken += 1
                    notes.append("Added websocket-client dependency")
            elif "aiohttp" in module.lower():
                if ensure_pyproject_deps(["aiohttp"], dev=False):
                    actions_taken += 1
                    notes.append("Added aiohttp dependency")
            elif "cryptography" in module.lower():
                if ensure_pyproject_deps(["cryptography"], dev=False):
                    actions_taken += 1
                    notes.append("Added cryptography dependency")

    # 2. Check for AttributeError
    attr_errors = re.findall(
        r"AttributeError: .*'(\w+)' .*no attribute '(\w+)'",
        combined_output
    )

    for module_name, attr_name in attr_errors:
        notes.append(f"Missing attribute: {module_name}.{attr_name}")

        # Strengthen exports
        if strengthen_init_exports():
            actions_taken += 1
            notes.append("Strengthened package exports")
            break  # Apply once per iteration

    # 3. Check for API method count issues
    api_method_pattern = r"API methods.*expected.*(\d+).*got.*(\d+)"
    api_match = re.search(api_method_pattern, combined_output, re.IGNORECASE)

    if api_match:
        expected_count = int(api_match.group(1))
        actual_count = int(api_match.group(2))

        if actual_count < expected_count:
            # Get expected methods from parity
            expected_methods = get_expected_api_methods()
            if expected_methods and align_api_methods_with_parity(expected_methods):
                actions_taken += 1
                notes.append(f"Aligned API methods ({actual_count} -> {expected_count})")

    # 4. Check for NotImplementedError in crypto
    if "NotImplementedError" in combined_output:
        if "secp256k1" in combined_output.lower():
            # Secp256k1 is optional, but we should handle it gracefully
            notes.append("Secp256k1 not implemented (optional)")
        elif "ed25519" in combined_output.lower():
            if create_missing_signer_ed25519():
                actions_taken += 1
                notes.append("Implemented Ed25519 crypto")

    # 5. Check for validation/fee issues
    if "fee" in combined_output.lower() or "validation" in combined_output.lower():
        if "AssertionError" in combined_output:
            if update_validation_and_fees():
                actions_taken += 1
                notes.append("Updated validation/fee rules")

    # 6. Fix invalid escape sequences
    if "invalid escape sequence" in combined_output.lower():
        if fix_invalid_escape_sequences_in_tests():
            actions_taken += 1
            notes.append("Fixed invalid escape sequences")

    # 7. Check for specific missing classes
    missing_classes = [
        "TransactionCodec",
        "dumps_canonical",
        "sha256_bytes",
        "Ed25519KeyPair",
        "Ed25519Signer",
        "Ed25519Verifier",
        "LegacyEd25519Signer",
        "AccountUrl",
        "AccumulateClient"
    ]

    for cls in missing_classes:
        if f"cannot import name '{cls}'" in combined_output:
            if cls in ["Ed25519Signer", "Ed25519Verifier", "LegacyEd25519Signer", "Ed25519KeyPair"]:
                if create_missing_signer_ed25519():
                    actions_taken += 1
                    notes.append(f"Created {cls}")
            else:
                # Ensure it's exported
                if strengthen_init_exports():
                    actions_taken += 1
                    notes.append(f"Exported {cls}")
                    break

    # 8. Check for encode_canonical_json -> encode_json issue
    if "encode_canonical_json" in combined_output:
        if fix_import_path("encode_canonical_json", "encode_json"):
            actions_taken += 1
            notes.append("Fixed encode_canonical_json -> encode_json")

    if "decode_transaction" in combined_output:
        if fix_import_path("decode_transaction", "decode_binary"):
            actions_taken += 1
            notes.append("Fixed decode_transaction -> decode_binary")

    # 9. Fix BatchConfig -> BatchClient issue
    if "BatchConfig" in combined_output:
        if fix_import_path("BatchConfig", "BatchClient"):
            actions_taken += 1
            notes.append("Fixed BatchConfig import")

    # 10. Fix relative import issues
    if "attempted relative import with no known parent" in combined_output:
        # Already handled by previous fixes, but strengthen exports just in case
        if strengthen_init_exports():
            actions_taken += 1
            notes.append("Fixed relative imports via exports")

    return {
        "actions_taken": actions_taken,
        "notes": notes
    }