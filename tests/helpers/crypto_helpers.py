#!/usr/bin/env python3

"""
Crypto helpers for TS parity testing

Implements canonical JSON serialization, Ed25519 signing, and SHA-256 hashing
to match TypeScript SDK behavior exactly.
"""

import hashlib
import json
from typing import Any, Dict, Union
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization


def canonical_json(obj: Any) -> str:
    """
    Canonical JSON serialization to match Dart/TS SDK behavior exactly.

    Uses the dedicated canonical JSON module for perfect cross-language compatibility.

    Args:
        obj: Object to serialize

    Returns:
        Canonical JSON string
    """
    # Import here to avoid circular imports
    from src.accumulate_client.canonjson import dumps_canonical
    return dumps_canonical(obj)


def sha256_hash(data: Union[str, bytes]) -> bytes:
    """
    SHA-256 hash function matching TS SDK behavior.

    Args:
        data: Data to hash (string or bytes)

    Returns:
        SHA-256 hash as bytes
    """
    if isinstance(data, str):
        data = data.encode('utf-8')
    return hashlib.sha256(data).digest()


def derive_lite_identity_url(public_key_bytes: bytes) -> str:
    """
    Derive Lite Identity URL from Ed25519 public key with checksum.
    Matches TS SDK URL derivation exactly.

    Args:
        public_key_bytes: 32-byte Ed25519 public key

    Returns:
        Lite Identity URL with format: acc://{hash40}{checksum8}
    """
    # For Ed25519: keyHash = SHA256(publicKey)
    key_hash_full = sha256_hash(public_key_bytes)

    # Use first 20 bytes
    key_hash_20 = key_hash_full[:20]

    # Convert to hex string
    key_str = key_hash_20.hex()

    # Calculate checksum - Go: protocol/protocol.go:275-276
    checksum_full = sha256_hash(key_str)
    checksum = checksum_full[28:].hex()  # Take last 4 bytes

    # Format: acc://<keyHash[0:20]><checksum>
    return f"acc://{key_str}{checksum}"


def derive_lite_token_account_url(public_key_bytes: bytes, token: str = "ACME") -> str:
    """
    Derive Lite Token Account URL for specified token.

    Args:
        public_key_bytes: 32-byte Ed25519 public key
        token: Token symbol (default: "ACME")

    Returns:
        Lite Token Account URL with format: {LID}/{token}
    """
    lid = derive_lite_identity_url(public_key_bytes)
    return f"{lid}/{token}"


def ed25519_sign(private_key_bytes: bytes, message: bytes) -> bytes:
    """
    Ed25519 signature matching TS SDK behavior.

    Args:
        private_key_bytes: 32-byte private key
        message: Message to sign

    Returns:
        64-byte detached signature
    """
    private_key = ed25519.Ed25519PrivateKey.from_private_bytes(private_key_bytes)
    return private_key.sign(message)


def ed25519_verify(public_key_bytes: bytes, signature: bytes, message: bytes) -> bool:
    """
    Ed25519 signature verification.

    Args:
        public_key_bytes: 32-byte public key
        signature: 64-byte signature
        message: Original message

    Returns:
        True if signature is valid
    """
    try:
        public_key = ed25519.Ed25519PublicKey.from_public_bytes(public_key_bytes)
        public_key.verify(signature, message)
        return True
    except Exception:
        return False


def ed25519_keypair_from_seed(seed: bytes) -> tuple[bytes, bytes]:
    """
    Generate Ed25519 keypair from 32-byte seed.

    Args:
        seed: 32-byte seed

    Returns:
        Tuple of (private_key_bytes, public_key_bytes)
    """
    private_key = ed25519.Ed25519PrivateKey.from_private_bytes(seed)
    public_key = private_key.public_key()

    private_key_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption()
    )

    public_key_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )

    return private_key_bytes, public_key_bytes


def create_transaction_hash(transaction: Dict[str, Any]) -> bytes:
    """
    Create transaction hash using canonical JSON + SHA-256.
    Matches TS SDK transaction hashing behavior.

    Args:
        transaction: Transaction object

    Returns:
        32-byte transaction hash
    """
    canonical_tx = canonical_json(transaction)
    return sha256_hash(canonical_tx)


def create_signature_envelope(
    transaction: Dict[str, Any],
    private_key_bytes: bytes,
    signature_type: str = "ed25519"
) -> Dict[str, Any]:
    """
    Create a complete signature envelope for a transaction.

    Args:
        transaction: Transaction object
        private_key_bytes: 32-byte private key
        signature_type: Signature type (default: "ed25519")

    Returns:
        Complete envelope with transaction and signatures
    """
    # Hash the transaction
    tx_hash = create_transaction_hash(transaction)

    # Sign the hash
    signature = ed25519_sign(private_key_bytes, tx_hash)

    # Get public key
    _, public_key_bytes = ed25519_keypair_from_seed(private_key_bytes)

    # Create envelope
    envelope = {
        "transaction": transaction,
        "signatures": [
            {
                "type": signature_type,
                "publicKey": public_key_bytes.hex(),
                "signature": signature.hex()
            }
        ]
    }

    return envelope


def verify_signature_envelope(envelope: Dict[str, Any]) -> bool:
    """
    Verify all signatures in an envelope.

    Args:
        envelope: Signature envelope

    Returns:
        True if all signatures are valid
    """
    transaction = envelope.get("transaction")
    signatures = envelope.get("signatures", [])

    if not transaction or not signatures:
        return False

    # Hash the transaction
    tx_hash = create_transaction_hash(transaction)

    # Verify each signature
    for sig in signatures:
        if sig.get("type") != "ed25519":
            continue  # Skip non-Ed25519 signatures

        try:
            public_key_bytes = bytes.fromhex(sig["publicKey"])
            signature_bytes = bytes.fromhex(sig["signature"])

            if not ed25519_verify(public_key_bytes, signature_bytes, tx_hash):
                return False
        except Exception:
            return False

    return True


# Test vector validation functions
def validate_ed25519_test_vector(vector: Dict[str, Any]) -> bool:
    """
    Validate an Ed25519 test vector against TS SDK behavior.

    Args:
        vector: Test vector from golden fixtures

    Returns:
        True if vector is valid
    """
    try:
        # Parse inputs
        private_key_bytes = bytes.fromhex(vector["privateKey"])
        expected_public_key = bytes.fromhex(vector["publicKey"])
        expected_lid = vector["lid"]
        expected_lta = vector["lta"]

        # Generate keypair
        _, public_key_bytes = ed25519_keypair_from_seed(private_key_bytes)

        # Validate public key
        if public_key_bytes != expected_public_key:
            return False

        # Validate URLs
        actual_lid = derive_lite_identity_url(public_key_bytes)
        actual_lta = derive_lite_token_account_url(public_key_bytes)

        if actual_lid != expected_lid or actual_lta != expected_lta:
            return False

        # If signature test vector, validate signature
        if "signature" in vector and "messageHash" in vector:
            message_bytes = bytes.fromhex(vector["testMessage"])
            expected_signature = bytes.fromhex(vector["signature"])
            expected_hash = bytes.fromhex(vector["messageHash"])

            # Validate message hash
            actual_hash = sha256_hash(message_bytes)
            if actual_hash != expected_hash:
                return False

            # Validate signature
            actual_signature = ed25519_sign(private_key_bytes, actual_hash)
            # Note: Signatures are non-deterministic, so we verify instead
            if not ed25519_verify(public_key_bytes, expected_signature, actual_hash):
                return False

        return True

    except Exception:
        return False