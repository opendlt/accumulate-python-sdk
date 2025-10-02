"""
RCD1 signer for Accumulate protocol.

Implements Factom-style RCD1 (Redeem Condition Datastructure) signatures
using ED25519 with special address derivation.
"""

import hashlib
import time
from typing import Optional, Union

from ..crypto.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from ..enums import SignatureType
from ..runtime.url import AccountUrl
from .signer import UserSigner, Verifier


def get_rcd_hash_from_public_key(public_key: bytes, rcd_type: int = 1) -> bytes:
    """
    Compute RCD hash from public key (Factom-style addressing).

    This matches the Go implementation's GetRCDHashFromPublicKey function.

    Args:
        public_key: 32-byte ED25519 public key
        rcd_type: RCD type (usually 1 for single signature)

    Returns:
        32-byte RCD hash
    """
    if len(public_key) != 32:
        raise ValueError(f"ED25519 public key must be 32 bytes, got {len(public_key)}")

    # RCD1 format: [type:1] + [public_key:32]
    rcd_data = bytes([rcd_type]) + public_key

    # Double SHA-256 hash like Bitcoin/Factom
    hash1 = hashlib.sha256(rcd_data).digest()
    hash2 = hashlib.sha256(hash1).digest()

    return hash2


class RCD1Signer(UserSigner):
    """RCD1 signer using ED25519 with Factom-style addressing."""

    def __init__(self, private_key: Ed25519PrivateKey, signer_url: Union[str, AccountUrl],
                 signer_version: int = 1, timestamp: Optional[int] = None):
        """
        Initialize RCD1 signer.

        Args:
            private_key: ED25519 private key
            signer_url: URL of the signer (string or AccountUrl object)
            signer_version: Version of the signer (default: 1)
            timestamp: Timestamp in microseconds (default: current time)
        """
        self.private_key = private_key
        self.signer_url = AccountUrl.parse(signer_url) if isinstance(signer_url, str) else signer_url
        self.signer_version = signer_version
        self.timestamp = timestamp or int(time.time() * 1_000_000)

    def get_signature_type(self) -> SignatureType:
        """Return the RCD1 signature type."""
        return SignatureType.RCD1

    def get_signer_url(self) -> AccountUrl:
        """Get the signer URL."""
        return self.signer_url

    def get_signer_version(self) -> int:
        """Get the signer version."""
        return self.signer_version

    def get_public_key(self) -> bytes:
        """Get the public key bytes."""
        return self.private_key.public_key().to_bytes()

    def get_public_key_hash(self) -> bytes:
        """Get the RCD1 hash of the public key."""
        return get_rcd_hash_from_public_key(self.get_public_key(), rcd_type=1)

    def get_signature_bytes(self, digest: bytes) -> bytes:
        """Get raw signature bytes without metadata."""
        # RCD1 uses standard ED25519 signatures
        return self.private_key.sign(digest)

    def verify(self, signature: bytes, digest: bytes) -> bool:
        """Verify a signature against a digest."""
        public_key = self.private_key.public_key()
        return public_key.verify(signature, digest)

    def sign(self, message_hash: bytes) -> bytes:
        """
        Sign a message hash using RCD1 signature format.

        Args:
            message_hash: 32-byte message hash to sign

        Returns:
            ED25519 signature (64 bytes)
        """
        return self.get_signature_bytes(message_hash)

    def to_accumulate_signature(self, transaction_hash: bytes, **kwargs) -> dict:
        """
        Create an Accumulate protocol RCD1 signature.

        Args:
            transaction_hash: Transaction hash to sign
            **kwargs: Optional fields (memo, data, vote, timestamp)

        Returns:
            Dictionary with signature data
        """
        # Get public key bytes
        public_key_bytes = self.get_public_key()

        # Create signature metadata first
        metadata = {
            'type': self.get_signature_type(),
            'publicKey': public_key_bytes.hex(),
            'signer': {
                'url': str(self.get_signer_url()),
                'version': self.get_signer_version()
            },
            'signerVersion': self.get_signer_version(),
            'timestamp': self.timestamp
        }

        # Compute signing hash (metadata hash + transaction hash)
        metadata_bytes = self._metadata_bytes(metadata)
        metadata_hash = hashlib.sha256(metadata_bytes).digest()
        signing_data = metadata_hash + transaction_hash
        signing_hash = hashlib.sha256(signing_data).digest()

        # Sign the hash
        signature_bytes = self.sign(signing_hash)

        # Return complete signature with RCD information and optional fields
        signature = {
            'type': self.get_signature_type(),
            'publicKey': public_key_bytes.hex(),
            'signature': signature_bytes.hex(),
            'signer': {
                'url': str(self.get_signer_url()),
                'version': self.get_signer_version()
            },
            'signerVersion': self.get_signer_version(),
            'timestamp': kwargs.get('timestamp', self.timestamp),
            'vote': kwargs.get('vote', self.get_vote()),
            'transactionHash': transaction_hash.hex(),
            'rcdHash': self.get_public_key_hash().hex()
        }

        # Add optional fields if provided
        if 'memo' in kwargs:
            signature['memo'] = kwargs['memo']

        if 'data' in kwargs:
            signature['data'] = kwargs['data'].hex() if isinstance(kwargs['data'], bytes) else kwargs['data']

        return signature

    def _metadata_bytes(self, metadata: dict) -> bytes:
        """
        Convert metadata dict to bytes for hashing.

        This is a simplified version - actual implementation would need
        to match the Go MarshalBinary format exactly.
        """
        # For now, use a simple deterministic encoding
        parts = [
            metadata['type'].to_bytes(1, 'big'),
            bytes.fromhex(metadata['publicKey']),
            metadata['signer']['url'].encode('utf-8'),
            metadata['signerVersion'].to_bytes(8, 'little'),
            metadata['timestamp'].to_bytes(8, 'little')
        ]
        return b''.join(parts)

    def get_rcd_data(self) -> bytes:
        """
        Get the RCD (Redeem Condition Datastructure) for this key.

        Returns:
            RCD1 data structure
        """
        # RCD1 format: [type:1] + [public_key:32]
        return bytes([1]) + self.get_public_key()


class RCD1Verifier(Verifier):
    """RCD1 signature verifier using ED25519."""

    def __init__(self, public_key: Union[Ed25519PublicKey, bytes]):
        """
        Initialize RCD1 verifier.

        Args:
            public_key: ED25519 public key or public key bytes
        """
        if isinstance(public_key, bytes):
            self.public_key = Ed25519PublicKey(public_key)
        else:
            self.public_key = public_key

    def signature_type(self) -> SignatureType:
        """Get the signature type for RCD1."""
        return SignatureType.RCD1

    def verify(self, digest: bytes, signature: bytes) -> bool:
        """
        Verify an RCD1 signature.

        Args:
            digest: 32-byte message hash that was signed
            signature: ED25519 signature to verify (64 bytes)

        Returns:
            True if signature is valid
        """
        return self.public_key.verify(signature, digest)

    def verify_accumulate_signature(self, digest: bytes, signature_obj: dict) -> bool:
        """
        Verify an Accumulate RCD1 signature object.

        Args:
            digest: Transaction digest that was signed
            signature_obj: Accumulate signature dictionary

        Returns:
            True if signature is valid
        """
        # Extract signature bytes from the signature object
        if 'signature' not in signature_obj:
            return False

        try:
            sig_bytes = bytes.fromhex(signature_obj['signature'])

            # Verify the signature length for ED25519
            if len(sig_bytes) != 64:
                return False

            return self.verify(digest, sig_bytes)
        except (ValueError, KeyError):
            return False

    def get_rcd_hash(self) -> bytes:
        """
        Get the RCD hash for this public key.

        Returns:
            32-byte RCD hash
        """
        return get_rcd_hash_from_public_key(self.public_key.to_bytes(), rcd_type=1)

    def get_rcd_data(self) -> bytes:
        """
        Get the RCD data structure for this public key.

        Returns:
            RCD1 data structure
        """
        return bytes([1]) + self.public_key.to_bytes()


# Export main classes
__all__ = [
    'RCD1Signer',
    'RCD1Verifier',
    'get_rcd_hash_from_public_key'
]