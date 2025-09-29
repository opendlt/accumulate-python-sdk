"""
Hash Functions - 1:1 mapping to Dart hash.dart

Implements exact SHA-256 hashing semantics matching Dart hash.dart.
Provides same hash function signatures and byte handling.
Transaction hashing follows discovered rules from Go/TypeScript.
"""

import hashlib
from typing import Dict, Any
from ..canonjson import dumps_canonical


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


def hash_transaction(header: Dict[str, Any], body: Dict[str, Any]) -> bytes:
    """
    Hash transaction using canonical JSON encoding exactly as Dart.

    Maps to: Dart transaction_codec.dart TransactionCodec.encodeTxForSigning()
    Based on Go: protocol/transaction_hash.go:27-71 and TypeScript: src/core/base.ts:13-44

    Args:
        header: Transaction header dict
        body: Transaction body dict

    Returns:
        Transaction hash for signing (32 bytes)
    """
    # Import here to avoid circular imports
    from .transaction_codec import TransactionCodec
    return TransactionCodec.encode_tx_for_signing(header, body)


def hash_signature_metadata(signature_metadata: Dict[str, Any]) -> bytes:
    """
    Hash signature metadata using canonical JSON encoding.

    Args:
        signature_metadata: Signature metadata dict

    Returns:
        Signature metadata hash (32 bytes)
    """
    metadata_json = dumps_canonical(signature_metadata).encode('utf-8')
    return sha256_bytes(metadata_json)


def create_signing_preimage(signature_metadata_hash: bytes, transaction_hash: bytes) -> bytes:
    """
    Create signing preimage exactly as Dart.

    Maps to: Dart transaction_codec.dart TransactionCodec.createSigningPreimage()
    Based on Go: protocol/signature_utils.go:50-57

    Args:
        signature_metadata_hash: Hash of signature metadata
        transaction_hash: Hash of transaction

    Returns:
        Final signing preimage (32 bytes)
    """
    # Import here to avoid circular imports
    from .transaction_codec import TransactionCodec
    return TransactionCodec.create_signing_preimage(signature_metadata_hash, transaction_hash)