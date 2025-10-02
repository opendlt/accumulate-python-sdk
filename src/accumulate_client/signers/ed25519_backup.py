"""
ED25519 signer implementation.

Provides ED25519 signing functionality using the crypto module.
"""

from typing import Union
from ..crypto.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from ..enums import SignatureType


class Ed25519Signer:
    """ED25519 signer implementation."""

    def __init__(self, keypair_or_private_key: Union[Ed25519PrivateKey, tuple], authority: str = ""):
        """
        Initialize ED25519 signer.

        Args:
            keypair_or_private_key: Private key or keypair
            authority: Signing authority URL
        """
        if isinstance(keypair_or_private_key, tuple):
            self.private_key = keypair_or_private_key[0]
            self.public_key = keypair_or_private_key[1]
        else:
            self.private_key = keypair_or_private_key
            self.public_key = keypair_or_private_key.public_key()

        self.authority = authority
        self.signer_url = authority  # Add alias for compatibility

    def sign(self, data: bytes) -> bytes:
        """
        Sign data with the private key.

        Args:
            data: Data to sign

        Returns:
            Raw signature bytes
        """
        return self.private_key.sign(data)

    def to_accumulate_signature(self, transaction_hash: bytes) -> dict:
        """
        Generate Accumulate signature for transaction hash.

        Args:
            transaction_hash: Transaction hash bytes

        Returns:
            Accumulate signature dictionary
        """
        signature_bytes = self.sign(transaction_hash)

        return {
            'type': SignatureType.ED25519,
            'publicKey': self.public_key.to_bytes().hex(),
            'signature': signature_bytes.hex(),
            'signer': self.authority,  # Simple string format for test compatibility
            'signerVersion': 1,
            'timestamp': 0
        }


class Ed25519Verifier:
    """ED25519 signature verifier."""

    def __init__(self, public_key: Ed25519PublicKey):
        """
        Initialize ED25519 verifier.

        Args:
            public_key: Public key for verification
        """
        self.public_key = public_key

    def verify(self, message: bytes, signature: bytes) -> bool:
        """
        Verify signature.

        Args:
            message: Original message bytes
            signature: Signature bytes

        Returns:
            True if signature is valid
        """
        try:
            return self.public_key.verify(signature, message)
        except Exception:
            return False

    @classmethod
    def from_signature_dict(cls, sig_dict: dict) -> 'Ed25519Verifier':
        """
        Create verifier from signature dictionary.

        Args:
            sig_dict: Accumulate signature dictionary

        Returns:
            Ed25519Verifier instance
        """
        public_key_bytes = bytes.fromhex(sig_dict['publicKey'])
        public_key = Ed25519PublicKey.from_bytes(public_key_bytes)
        return cls(public_key)

