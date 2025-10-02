"""
Compatibility layer for test imports.

Provides aliases and wrappers for functions that tests expect.
"""

import json
import hashlib
from typing import Dict, Any, Union

from .crypto.ed25519 import Ed25519PrivateKey, Ed25519PublicKey


class Ed25519KeyPair:
    """Compatibility wrapper for Ed25519 keypair."""

    def __init__(self, private_key: Ed25519PrivateKey):
        self.private_key = private_key
        self.public_key = private_key.public_key()

    @classmethod
    def from_seed(cls, seed: bytes) -> "Ed25519KeyPair":
        """Create keypair from private key bytes (called 'seed' for compatibility)."""
        if len(seed) < 32:
            seed = seed + b'\x00' * (32 - len(seed))
        elif len(seed) > 32:
            seed = seed[:32]
        # Create private key directly from bytes (not from_seed which would hash it)
        private_key = Ed25519PrivateKey(seed)
        return cls(private_key)

    def sign(self, message: bytes) -> bytes:
        """Sign a message."""
        return self.private_key.sign(message)

    def public_key_bytes(self) -> bytes:
        """Get public key as bytes."""
        return self.public_key.to_bytes()

    def private_key_bytes(self) -> bytes:
        """Get private key as bytes."""
        return self.private_key.to_bytes()

    def verify(self, message: bytes, signature: bytes) -> bool:
        """Verify a signature against a message."""
        try:
            return self.public_key.verify(signature, message)
        except Exception:
            return False

    def derive_lite_identity_url(self) -> str:
        """
        Derive Lite Identity URL from public key.

        Returns:
            Accumulate Lite Identity URL in format acc://[40_hex_chars][8_checksum]
        """
        pub_bytes = self.public_key_bytes()

        # Step 1: SHA256 of public key
        key_hash_full = hashlib.sha256(pub_bytes).digest()

        # Step 2: Take first 20 bytes
        key_hash_20 = key_hash_full[:20]

        # Step 3: Convert to hex string
        key_str = key_hash_20.hex()

        # Step 4: Calculate checksum - SHA256 of hex string, take last 4 bytes
        checksum_full = hashlib.sha256(key_str.encode("utf-8")).digest()
        checksum = checksum_full[28:].hex()  # Last 4 bytes as hex

        return f"acc://{key_str}{checksum}"

    def derive_lite_token_account_url(self, token_url: str = "ACME") -> str:
        """
        Derive Lite Token Account URL.

        Args:
            token_url: Token identifier (default: "ACME")

        Returns:
            Accumulate Lite Token Account URL
        """
        # Get the lite identity part (without acc://)
        lite_identity = self.derive_lite_identity_url()[6:]  # Remove "acc://"

        return f"acc://{lite_identity}/{token_url}"


class TransactionCodec:
    """Compatibility wrapper for transaction encoding/decoding."""

    @staticmethod
    def encode(tx: Dict[str, Any]) -> bytes:
        """Encode transaction to canonical bytes."""
        return dumps_canonical(tx).encode()

    @staticmethod
    def decode(data: bytes) -> Dict[str, Any]:
        """Decode transaction from bytes."""
        return json.loads(data)

    @staticmethod
    def hash(tx: Dict[str, Any]) -> bytes:
        """Calculate transaction hash."""
        canonical = dumps_canonical(tx)
        return sha256_bytes(canonical.encode() if isinstance(canonical, str) else canonical)

    @staticmethod
    def encode_tx_for_signing(header: Dict[str, Any], body: Dict[str, Any]) -> bytes:
        """
        Encode transaction for signing - delegates to real implementation.

        Args:
            header: Transaction header dict
            body: Transaction body dict

        Returns:
            Transaction hash for signing (32 bytes)
        """
        # Import here to avoid circular imports
        from .codec.transaction_codec import TransactionCodec as RealTransactionCodec
        return RealTransactionCodec.encode_tx_for_signing(header, body)

    @staticmethod
    def create_signing_preimage(signature_metadata_hash: bytes, transaction_hash: bytes) -> bytes:
        """
        Create signing preimage - delegates to real implementation.

        Args:
            signature_metadata_hash: Hash of signature metadata
            transaction_hash: Hash of transaction

        Returns:
            Final signing preimage (32 bytes)
        """
        # Import here to avoid circular imports
        from .codec.transaction_codec import TransactionCodec as RealTransactionCodec
        return RealTransactionCodec.create_signing_preimage(signature_metadata_hash, transaction_hash)


def dumps_canonical(obj: Any) -> str:
    """Create canonical JSON representation - delegates to real implementation."""
    # Import here to avoid circular imports
    from .canonjson import dumps_canonical as real_dumps_canonical
    return real_dumps_canonical(obj)


def sha256_bytes(data: bytes) -> bytes:
    """Calculate SHA256 hash of bytes."""
    return hashlib.sha256(data).digest()


def sha256_hex(data: bytes) -> str:
    """Calculate SHA256 hash and return hex string."""
    return hashlib.sha256(data).hexdigest()