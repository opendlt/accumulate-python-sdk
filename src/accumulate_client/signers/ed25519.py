"""
ED25519 signer implementation.

Provides ED25519 signing functionality using the crypto module.
"""

from typing import Union
from ..crypto.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from ..enums import SignatureType
from ..runtime.url import AccountUrl
from .signer import UserSigner


class Ed25519Signer(UserSigner):
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

    def get_signer_url(self) -> AccountUrl:
        """
        Get the signer's URL.

        Returns:
            Account URL of the signer
        """
        return AccountUrl(self.authority)

    def get_signature_type(self) -> SignatureType:
        """
        Get the signature type.

        Returns:
            SignatureType.ED25519
        """
        return SignatureType.ED25519

    def get_public_key(self) -> bytes:
        """
        Get the public key bytes.

        Returns:
            Public key bytes
        """
        return self.public_key.to_bytes()

    def verify(self, signature: bytes, digest: bytes) -> bool:
        """
        Verify a signature against a digest.

        Args:
            signature: Signature bytes to verify
            digest: 32-byte hash that was signed

        Returns:
            True if signature is valid
        """
        try:
            return self.public_key.verify(signature, digest)
        except Exception:
            return False

    def get_signature_bytes(self, digest: bytes) -> bytes:
        """
        Get raw signature bytes without metadata.

        Args:
            digest: Hash to sign

        Returns:
            Raw signature bytes
        """
        return self.private_key.sign(digest)

    def sign(self, data: bytes) -> bytes:
        """
        Sign data with the private key.

        Args:
            data: Data to sign

        Returns:
            Raw signature bytes
        """
        return self.private_key.sign(data)

    def to_accumulate_signature(self, transaction_hash: bytes, **kwargs) -> dict:
        """
        Generate Accumulate signature for transaction hash.

        Args:
            transaction_hash: Transaction hash bytes
            **kwargs: Optional fields (memo, data, vote, timestamp)

        Returns:
            Accumulate signature dictionary
        """
        signature_bytes = self.sign(transaction_hash)

        # Base signature structure
        signature = {
            'type': self.get_signature_type(),
            'publicKey': self.public_key.to_bytes().hex(),
            'signature': signature_bytes.hex(),
            'signer': {
                'url': str(self.get_signer_url()),
                'version': self.get_signer_version()
            },
            'signerVersion': self.get_signer_version(),
            'timestamp': kwargs.get('timestamp', self.get_timestamp()),
            'vote': kwargs.get('vote', self.get_vote()),
            'transactionHash': transaction_hash.hex()
        }

        # Add optional fields if provided
        if 'memo' in kwargs:
            signature['memo'] = kwargs['memo']

        if 'data' in kwargs:
            signature['data'] = kwargs['data'].hex() if isinstance(kwargs['data'], bytes) else kwargs['data']

        return signature


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