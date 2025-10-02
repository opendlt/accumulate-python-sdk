"""
RSA-SHA256 signer for Accumulate protocol.

Implements RSA signatures with SHA-256 hashing and PKCS#1 v1.5 padding.
"""

import hashlib
import time
from typing import Optional, Union

from ..enums import SignatureType
from ..runtime.url import AccountUrl
from .signer import UserSigner, Verifier

# RSA support
try:
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa, padding
    from cryptography.hazmat.backends import default_backend
    HAS_RSA = True
except ImportError:
    HAS_RSA = False


class RSAError(Exception):
    """Exception raised for RSA-related errors."""
    pass


class RSAPrivateKey:
    """RSA private key wrapper."""

    def __init__(self, private_key_pem: bytes, password: Optional[bytes] = None):
        """
        Initialize RSA private key from PEM data.

        Args:
            private_key_pem: PEM-encoded private key
            password: Password for encrypted keys
        """
        if not HAS_RSA:
            raise RSAError("RSA functionality requires 'cryptography' library")

        self._private_key = serialization.load_pem_private_key(
            private_key_pem,
            password=password,
            backend=default_backend()
        )

        if not isinstance(self._private_key, rsa.RSAPrivateKey):
            raise RSAError("Key is not an RSA private key")

    @classmethod
    def generate(cls, key_size: int = 2048) -> 'RSAPrivateKey':
        """
        Generate a new RSA private key.

        Args:
            key_size: Key size in bits (default: 2048)

        Returns:
            New RSA private key
        """
        if not HAS_RSA:
            raise RSAError("RSA functionality requires 'cryptography' library")

        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size,
            backend=default_backend()
        )

        # Create instance with dummy PEM data - we'll store the actual key
        instance = cls.__new__(cls)
        instance._private_key = private_key
        return instance

    def public_key(self) -> 'RSAPublicKey':
        """Get the corresponding public key."""
        return RSAPublicKey(self._private_key.public_key())

    def sign(self, message: bytes) -> bytes:
        """
        Sign a message using RSA-SHA256 with PKCS#1 v1.5 padding.

        Args:
            message: Message to sign

        Returns:
            RSA signature bytes
        """
        signature = self._private_key.sign(
            message,
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        return signature

    def to_pem(self, password: Optional[bytes] = None) -> bytes:
        """
        Export private key to PEM format.

        Args:
            password: Optional password for encryption

        Returns:
            PEM-encoded private key
        """
        if password:
            encryption = serialization.BestAvailableEncryption(password)
        else:
            encryption = serialization.NoEncryption()

        return self._private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=encryption
        )

    def key_size(self) -> int:
        """Get the key size in bits."""
        return self._private_key.key_size


class RSAPublicKey:
    """RSA public key wrapper."""

    def __init__(self, public_key):
        """
        Initialize RSA public key.

        Args:
            public_key: cryptography RSAPublicKey object or PEM bytes
        """
        if not HAS_RSA:
            raise RSAError("RSA functionality requires 'cryptography' library")

        if isinstance(public_key, bytes):
            self._public_key = serialization.load_pem_public_key(
                public_key,
                backend=default_backend()
            )
        else:
            self._public_key = public_key

        if not isinstance(self._public_key, rsa.RSAPublicKey):
            raise RSAError("Key is not an RSA public key")

    def verify(self, signature: bytes, message: bytes) -> bool:
        """
        Verify a signature against a message.

        Args:
            signature: RSA signature to verify
            message: Original message

        Returns:
            True if signature is valid
        """
        try:
            self._public_key.verify(
                signature,
                message,
                padding.PKCS1v15(),
                hashes.SHA256()
            )
            return True
        except Exception:
            return False

    def to_pem(self) -> bytes:
        """
        Export public key to PEM format.

        Returns:
            PEM-encoded public key
        """
        return self._public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

    def to_der(self) -> bytes:
        """
        Export public key to DER format.

        Returns:
            DER-encoded public key
        """
        return self._public_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

    def key_size(self) -> int:
        """Get the key size in bits."""
        return self._public_key.key_size


class RSASigner(UserSigner):
    """RSA signer using SHA-256 hashing and PKCS#1 v1.5 padding."""

    def __init__(self, private_key: RSAPrivateKey, signer_url: Union[str, AccountUrl],
                 signer_version: int = 1, timestamp: Optional[int] = None):
        """
        Initialize RSA signer.

        Args:
            private_key: RSA private key
            signer_url: URL of the signer (string or AccountUrl object)
            signer_version: Version of the signer (default: 1)
            timestamp: Timestamp in microseconds (default: current time)
        """
        self.private_key = private_key
        self.signer_url = AccountUrl.parse(signer_url) if isinstance(signer_url, str) else signer_url
        self.signer_version = signer_version
        self.timestamp = timestamp or int(time.time() * 1_000_000)

    def get_signature_type(self) -> SignatureType:
        """Return the RSA-SHA256 signature type."""
        return SignatureType.RSASHA256

    def get_signer_url(self) -> AccountUrl:
        """Get the signer URL."""
        return self.signer_url

    def get_signer_version(self) -> int:
        """Get the signer version."""
        return self.signer_version

    def get_public_key(self) -> bytes:
        """Get the public key in DER format."""
        return self.private_key.public_key().to_der()

    def get_public_key_hash(self) -> bytes:
        """Get the SHA-256 hash of the public key."""
        return hashlib.sha256(self.get_public_key()).digest()

    def get_signature_bytes(self, digest: bytes) -> bytes:
        """Get raw signature bytes without metadata."""
        # RSA signs the digest directly
        return self.private_key.sign(digest)

    def verify(self, signature: bytes, digest: bytes) -> bool:
        """Verify a signature against a digest."""
        public_key = self.private_key.public_key()
        return public_key.verify(signature, digest)

    def sign(self, message_hash: bytes) -> bytes:
        """
        Sign a message hash using RSA-SHA256.

        Args:
            message_hash: 32-byte message hash to sign

        Returns:
            RSA signature bytes (key_size/8 bytes)
        """
        return self.get_signature_bytes(message_hash)

    def to_accumulate_signature(self, transaction_hash: bytes, **kwargs) -> dict:
        """
        Create an Accumulate protocol RSA signature.

        Args:
            transaction_hash: Transaction hash to sign
            **kwargs: Optional fields (memo, data, vote, timestamp)

        Returns:
            Dictionary with signature data
        """
        # Get public key bytes (DER format)
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
            'transactionHash': transaction_hash.hex(),
            'keySize': self.private_key.key_size()
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


class RSAVerifier(Verifier):
    """RSA signature verifier using SHA-256."""

    def __init__(self, public_key: Union[RSAPublicKey, bytes]):
        """
        Initialize RSA verifier.

        Args:
            public_key: RSA public key or public key bytes (DER format)
        """
        if isinstance(public_key, bytes):
            self.public_key = RSAPublicKey(public_key)
        else:
            self.public_key = public_key

    def signature_type(self) -> SignatureType:
        """Get the signature type for RSA-SHA256."""
        return SignatureType.RSASHA256

    def verify(self, digest: bytes, signature: bytes) -> bool:
        """
        Verify an RSA signature.

        Args:
            digest: 32-byte message hash that was signed
            signature: RSA signature to verify

        Returns:
            True if signature is valid
        """
        return self.public_key.verify(signature, digest)

    def verify_accumulate_signature(self, digest: bytes, signature_obj: dict) -> bool:
        """
        Verify an Accumulate RSA signature object.

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

            # Verify the signature length is reasonable for RSA
            key_size = self.public_key.key_size()
            expected_sig_len = key_size // 8

            if len(sig_bytes) != expected_sig_len:
                return False

            return self.verify(digest, sig_bytes)
        except (ValueError, KeyError):
            return False

    def get_public_key_hash(self) -> bytes:
        """
        Get the SHA-256 hash of the public key.

        Returns:
            32-byte hash of the public key
        """
        return hashlib.sha256(self.public_key.to_der()).digest()


# Utility functions
def has_rsa_support() -> bool:
    """Check if RSA functionality is available."""
    return HAS_RSA


def generate_rsa_keypair(key_size: int = 2048) -> tuple[RSAPrivateKey, RSAPublicKey]:
    """
    Generate an RSA key pair.

    Args:
        key_size: Key size in bits (default: 2048)

    Returns:
        Tuple of (private_key, public_key)
    """
    private_key = RSAPrivateKey.generate(key_size)
    public_key = private_key.public_key()
    return private_key, public_key


# Export main classes
__all__ = [
    'RSASigner',
    'RSAVerifier',
    'RSAPrivateKey',
    'RSAPublicKey',
    'RSAError',
    'has_rsa_support',
    'generate_rsa_keypair'
]