"""
Strict Parity Helper

Provides precise binary comparison utilities for bit-for-bit parity testing
between Python and Dart SDK implementations.
"""


def assert_hex_equal(actual: bytes, expected_hex: str, ctx: str) -> None:
    """
    Assert that actual bytes match expected hex string with detailed diff output.

    Args:
        actual: Actual bytes to compare
        expected_hex: Expected hex string (without 0x prefix)
        ctx: Context string for error messages

    Raises:
        AssertionError: If bytes don't match, with detailed diff
    """
    # Normalize expected hex (remove spaces, lowercase)
    expected_hex = expected_hex.replace(" ", "").lower()
    actual_hex = actual.hex().lower()

    if actual_hex == expected_hex:
        return  # Match - success

    # Generate detailed diff for mismatch
    expected_bytes = bytes.fromhex(expected_hex)

    print(f"\n[FAIL] Binary parity mismatch in {ctx}")
    print(f"   Expected length: {len(expected_bytes)} bytes")
    print(f"   Actual length:   {len(actual)} bytes")

    if len(actual) != len(expected_bytes):
        print("   [WARN]  Length mismatch!")

    # Generate unified diff of hex rows (16 bytes per row)
    print("\n   Hex diff (16 bytes per row):")
    print(f"   {'Offset':<8} {'Expected':<48} {'Actual':<48} {'Status'}")
    print(f"   {'-' * 8} {'-' * 48} {'-' * 48} {'-' * 10}")

    max_len = max(len(expected_bytes), len(actual))
    for i in range(0, max_len, 16):
        # Get 16-byte chunks
        exp_chunk = expected_bytes[i : i + 16] if i < len(expected_bytes) else b""
        act_chunk = actual[i : i + 16] if i < len(actual) else b""

        # Format as hex strings
        exp_hex = " ".join(f"{b:02x}" for b in exp_chunk).ljust(47)
        act_hex = " ".join(f"{b:02x}" for b in act_chunk).ljust(47)

        # Determine status
        if exp_chunk == act_chunk:
            status = "✓"
        elif len(exp_chunk) != len(act_chunk):
            status = "LENGTH"
        else:
            status = "DIFF"

        print(f"   {i:08x} {exp_hex} {act_hex} {status}")

    # Find first differing byte
    min_len = min(len(expected_bytes), len(actual))
    first_diff = None
    for i in range(min_len):
        if expected_bytes[i] != actual[i]:
            first_diff = i
            break

    if first_diff is not None:
        print(f"\n   First difference at byte offset {first_diff} (0x{first_diff:x}):")
        print(f"   Expected: 0x{expected_bytes[first_diff]:02x} ({expected_bytes[first_diff]})")
        print(f"   Actual:   0x{actual[first_diff]:02x} ({actual[first_diff]})")

    # Show context around first difference
    if first_diff is not None and min_len > 0:
        start = max(0, first_diff - 4)
        end = min(min_len, first_diff + 5)
        print(f"\n   Context (bytes {start}-{end - 1}):")
        exp_context = " ".join(f"{b:02x}" for b in expected_bytes[start:end])
        act_context = " ".join(f"{b:02x}" for b in actual[start:end])
        print(f"   Expected: {exp_context}")
        print(f"   Actual:   {act_context}")
        print(f"   Diff at:  {' ' * (3 * (first_diff - start))}^^")

    print()
    raise AssertionError(f"Binary parity mismatch in {ctx}")


def bytes_to_hex_string(data: bytes) -> str:
    """
    Convert bytes to hex string for comparison.

    Args:
        data: Bytes to convert

    Returns:
        Lowercase hex string without prefix
    """
    return data.hex().lower()


def hex_string_to_bytes(hex_str: str) -> bytes:
    """
    Convert hex string to bytes.

    Args:
        hex_str: Hex string (with or without 0x prefix, spaces allowed)

    Returns:
        Bytes from hex string
    """
    # Normalize hex string
    hex_str = hex_str.replace(" ", "").replace("0x", "").lower()
    return bytes.fromhex(hex_str)
