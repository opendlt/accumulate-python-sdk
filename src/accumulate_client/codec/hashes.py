"""
Hash Functions - 1:1 mapping to Dart hash.dart

Implements exact SHA-256 hashing semantics matching Dart hash.dart.
Provides same hash function signatures and byte handling.
"""

import hashlib


def sha256_bytes(input_bytes: bytes) -> bytes:
    """
    Compute SHA-256 hash of input bytes.

    Maps to: Dart hash.dart:4-5 Uint8List sha256Bytes(Uint8List input)

    Args:
        input_bytes: Input bytes to hash

    Returns:
        SHA-256 hash as bytes (32 bytes)
    """
    return hashlib.sha256(input_bytes).digest()


def sha256_of_bytes(bytes_data: bytes) -> bytes:
    """
    Convenience function for hashing canonical JSON bytes.

    Maps to: Dart hash.dart:9 Uint8List sha256OfBytes(Uint8List bytes)

    Use only where spec requires JSON-level canonicalization.
    Prefer binary where applicable.

    Args:
        bytes_data: Bytes to hash

    Returns:
        SHA-256 hash as bytes (32 bytes)
    """
    return sha256_bytes(bytes_data)