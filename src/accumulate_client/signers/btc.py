"""
BTC and BTCLegacy signers for Accumulate protocol.

Implements Bitcoin-style secp256k1 signatures with proper DER encoding
and Bitcoin-style public key hashing (SHA256 + RIPEMD-160).
"""

import hashlib
import time
from typing import Optional, Union

from ..crypto.secp256k1 import Secp256k1PrivateKey, Secp256k1PublicKey
from ..enums import SignatureType
from ..runtime.url import AccountUrl
from .signer import UserSigner, Verifier


def btc_hash(public_key_bytes: bytes) -> bytes:
    """
    Compute Bitcoin-style public key hash: SHA256 + RIPEMD-160.

    This matches the Go implementation's BTCHash function.

    Args:
        public_key_bytes: Public key bytes

    Returns:
        20-byte Bitcoin-style hash
    """
    # First apply SHA256
    sha256_hash = hashlib.sha256(public_key_bytes).digest()

    # Then apply RIPEMD-160
    ripemd = hashlib.new('ripemd160')
    ripemd.update(sha256_hash)
    return ripemd.digest()


class BTCSigner(UserSigner):
    """BTC signer using secp256k1 with DER encoding."""

    def __init__(self, private_key: Secp256k1PrivateKey, signer_url: Union[str, AccountUrl],
                 signer_version: int = 1, timestamp: Optional[int] = None):
        """
        Initialize BTC signer.

        Args:
            private_key: Secp256k1 private key
            signer_url: URL of the signer (string or AccountUrl object)
            signer_version: Version of the signer (default: 1)
            timestamp: Timestamp in microseconds (default: current time)
        """
        self.private_key = private_key
        self.signer_url = AccountUrl.parse(signer_url) if isinstance(signer_url, str) else signer_url
        self.signer_version = signer_version
        self.timestamp = timestamp or int(time.time() * 1_000_000)

    def get_signature_type(self) -> SignatureType:
        """Return the BTC signature type."""
        return SignatureType.BTC

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
        """Get the Bitcoin-style public key hash."""
        return btc_hash(self.get_public_key())

    def get_signature_bytes(self, digest: bytes) -> bytes:
        """Get raw signature bytes without metadata."""
        # Sign the message hash using secp256k1
        signature = self.private_key.sign(digest)
        # Return the signature bytes (should already be DER-encoded from secp256k1)
        return signature.signature

    def verify(self, signature: bytes, digest: bytes) -> bool:
        """Verify a signature against a digest."""
        public_key = self.private_key.public_key()
        return public_key.verify(signature, digest)

    def sign(self, message_hash: bytes) -> bytes:
        """
        Sign a message hash using BTC signature format.

        Args:
            message_hash: 32-byte message hash to sign

        Returns:
            DER-encoded signature
        """
        # Sign the message hash using secp256k1
        signature = self.private_key.sign(message_hash)

        # Return the signature bytes (should already be DER-encoded from secp256k1)
        return signature.signature

    def to_accumulate_signature(self, transaction_hash: bytes, **kwargs) -> dict:
        """
        Create an Accumulate protocol BTC signature.

        Args:
            transaction_hash: Transaction hash to sign
            **kwargs: Optional fields (memo, data, vote, timestamp)

        Returns:
            Dictionary with signature data
        """
        # Get public key bytes
        public_key = self.private_key.public_key()
        public_key_bytes = public_key.to_bytes()

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
        # This follows the Go implementation's signingHash function
        metadata_bytes = self._metadata_bytes(metadata)
        metadata_hash = hashlib.sha256(metadata_bytes).digest()
        signing_data = metadata_hash + transaction_hash
        signing_hash = hashlib.sha256(signing_data).digest()

        # Sign the hash
        signature_bytes = self.sign(signing_hash)

        # Return complete signature with optional fields
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
            'transactionHash': transaction_hash.hex()
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
        # In production, this should match the exact binary format used by Go
        parts = [
            metadata['type'].to_bytes(1, 'big'),
            bytes.fromhex(metadata['publicKey']),
            metadata['signer']['url'].encode('utf-8'),
            metadata['signerVersion'].to_bytes(8, 'little'),
            metadata['timestamp'].to_bytes(8, 'little')
        ]
        return b''.join(parts)


class BTCLegacySigner(BTCSigner):
    """BTCLegacy signer - similar to BTC but with legacy signature type."""

    def get_signature_type(self) -> SignatureType:
        """Return the BTCLegacy signature type."""
        return SignatureType.BTCLEGACY


class BTCVerifier(Verifier):
    """BTC signature verifier using secp256k1."""

    def __init__(self, public_key: Union[Secp256k1PublicKey, bytes]):
        """
        Initialize BTC verifier.

        Args:
            public_key: Secp256k1 public key or public key bytes
        """
        if isinstance(public_key, bytes):
            self.public_key = Secp256k1PublicKey(public_key)
        else:
            self.public_key = public_key

    def signature_type(self) -> SignatureType:
        """Get the signature type for BTC."""
        return SignatureType.BTC

    def verify(self, digest: bytes, signature: bytes) -> bool:
        """
        Verify a BTC signature.

        Args:
            digest: 32-byte message hash that was signed
            signature: DER-encoded signature to verify

        Returns:
            True if signature is valid
        """
        # Note: arguments are swapped in Secp256k1PublicKey.verify
        return self.public_key.verify(signature, digest)

    def verify_accumulate_signature(self, digest: bytes, signature_obj: dict) -> bool:
        """
        Verify an Accumulate BTC signature object.

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
            return self.verify(digest, sig_bytes)
        except (ValueError, KeyError):
            return False

    def get_public_key_hash(self) -> bytes:
        """
        Get the Bitcoin-style public key hash.

        Returns:
            20-byte BTC hash of public key
        """
        return btc_hash(self.public_key.to_bytes())


class BTCLegacyVerifier(BTCVerifier):
    """BTCLegacy signature verifier - same as BTC verifier."""

    def signature_type(self) -> SignatureType:
        """Get the signature type for BTCLegacy."""
        return SignatureType.BTCLEGACY


# Export main classes
__all__ = [
    'BTCSigner',
    'BTCLegacySigner',
    'BTCVerifier',
    'BTCLegacyVerifier',
    'btc_hash'
]