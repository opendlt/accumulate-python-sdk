"""
ECDSA-SHA256 signer for Accumulate protocol.

Implements generic ECDSA signatures with SHA-256 hashing supporting
standard curves from NIST, SECG, and Brainpool with ASN.1 DER encoding.
"""

import hashlib
import time
from typing import Optional, Union

from ..enums import SignatureType
from ..runtime.url import AccountUrl
from .signer import UserSigner, Verifier

# ECDSA support
try:
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.backends import default_backend
    HAS_ECDSA = True
except ImportError:
    HAS_ECDSA = False


class ECDSAError(Exception):
    """Exception raised for ECDSA-related errors."""
    pass


# Supported curves
SUPPORTED_CURVES = {
    # NIST curves
    'P-256': ec.SECP256R1(),
    'P-384': ec.SECP384R1(),
    'P-521': ec.SECP521R1(),

    # SECG curves
    'secp256k1': ec.SECP256K1(),
    'secp256r1': ec.SECP256R1(),
    'secp384r1': ec.SECP384R1(),
    'secp521r1': ec.SECP521R1(),

    # Brainpool curves (if available)
    'brainpoolP256r1': getattr(ec, 'BrainpoolP256R1', lambda: None)(),
    'brainpoolP384r1': getattr(ec, 'BrainpoolP384R1', lambda: None)(),
    'brainpoolP512r1': getattr(ec, 'BrainpoolP512R1', lambda: None)(),
}

# Filter out None values (unsupported curves)
SUPPORTED_CURVES = {k: v for k, v in SUPPORTED_CURVES.items() if v is not None}


class ECDSAPrivateKey:
    """ECDSA private key wrapper."""

    def __init__(self, private_key_pem: bytes, password: Optional[bytes] = None):
        """
        Initialize ECDSA private key from PEM data.

        Args:
            private_key_pem: PEM-encoded private key
            password: Password for encrypted keys
        """
        if not HAS_ECDSA:
            raise ECDSAError("ECDSA functionality requires 'cryptography' library")

        self._private_key = serialization.load_pem_private_key(
            private_key_pem,
            password=password,
            backend=default_backend()
        )

        if not isinstance(self._private_key, ec.EllipticCurvePrivateKey):
            raise ECDSAError("Key is not an ECDSA private key")

    @classmethod
    def generate(cls, curve_name: str = 'P-256') -> 'ECDSAPrivateKey':
        """
        Generate a new ECDSA private key.

        Args:
            curve_name: Curve name (default: 'P-256')

        Returns:
            New ECDSA private key
        """
        if not HAS_ECDSA:
            raise ECDSAError("ECDSA functionality requires 'cryptography' library")

        if curve_name not in SUPPORTED_CURVES:
            raise ECDSAError(f"Unsupported curve: {curve_name}")

        curve = SUPPORTED_CURVES[curve_name]
        private_key = ec.generate_private_key(curve, backend=default_backend())

        # Create instance with dummy PEM data - we'll store the actual key
        instance = cls.__new__(cls)
        instance._private_key = private_key
        return instance

    def public_key(self) -> 'ECDSAPublicKey':
        """Get the corresponding public key."""
        return ECDSAPublicKey(self._private_key.public_key())

    def sign(self, message: bytes) -> bytes:
        """
        Sign a message using ECDSA-SHA256 with DER encoding.

        Args:
            message: Message to sign

        Returns:
            ECDSA signature bytes (DER encoded)
        """
        signature = self._private_key.sign(
            message,
            ec.ECDSA(hashes.SHA256())
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

    def curve_name(self) -> str:
        """Get the name of the curve."""
        curve = self._private_key.curve
        for name, supported_curve in SUPPORTED_CURVES.items():
            if type(curve) == type(supported_curve):
                return name
        return f"Unknown curve: {type(curve).__name__}"

    def key_size(self) -> int:
        """Get the key size in bits."""
        return self._private_key.curve.key_size


class ECDSAPublicKey:
    """ECDSA public key wrapper."""

    def __init__(self, public_key):
        """
        Initialize ECDSA public key.

        Args:
            public_key: cryptography EllipticCurvePublicKey object or PEM bytes
        """
        if not HAS_ECDSA:
            raise ECDSAError("ECDSA functionality requires 'cryptography' library")

        if isinstance(public_key, bytes):
            self._public_key = serialization.load_pem_public_key(
                public_key,
                backend=default_backend()
            )
        else:
            self._public_key = public_key

        if not isinstance(self._public_key, ec.EllipticCurvePublicKey):
            raise ECDSAError("Key is not an ECDSA public key")

    def verify(self, signature: bytes, message: bytes) -> bool:
        """
        Verify a signature against a message.

        Args:
            signature: ECDSA signature to verify (DER encoded)
            message: Original message

        Returns:
            True if signature is valid
        """
        try:
            self._public_key.verify(
                signature,
                message,
                ec.ECDSA(hashes.SHA256())
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

    def curve_name(self) -> str:
        """Get the name of the curve."""
        curve = self._public_key.curve
        for name, supported_curve in SUPPORTED_CURVES.items():
            if type(curve) == type(supported_curve):
                return name
        return f"Unknown curve: {type(curve).__name__}"

    def key_size(self) -> int:
        """Get the key size in bits."""
        return self._public_key.curve.key_size


class ECDSASigner(UserSigner):
    """ECDSA signer using SHA-256 hashing and DER encoding."""

    def __init__(self, private_key: ECDSAPrivateKey, signer_url: Union[str, AccountUrl],
                 signer_version: int = 1, timestamp: Optional[int] = None):
        """
        Initialize ECDSA signer.

        Args:
            private_key: ECDSA private key
            signer_url: URL of the signer (string or AccountUrl object)
            signer_version: Version of the signer (default: 1)
            timestamp: Timestamp in microseconds (default: current time)
        """
        self.private_key = private_key
        self.signer_url = AccountUrl.parse(signer_url) if isinstance(signer_url, str) else signer_url
        self.signer_version = signer_version
        self.timestamp = timestamp or int(time.time() * 1_000_000)

    def get_signature_type(self) -> SignatureType:
        """Return the ECDSA-SHA256 signature type."""
        return SignatureType.ECDSASHA256

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
        # ECDSA signs the digest directly with DER encoding
        return self.private_key.sign(digest)

    def verify(self, signature: bytes, digest: bytes) -> bool:
        """Verify a signature against a digest."""
        public_key = self.private_key.public_key()
        return public_key.verify(signature, digest)

    def sign(self, message_hash: bytes) -> bytes:
        """
        Sign a message hash using ECDSA-SHA256.

        Args:
            message_hash: 32-byte message hash to sign

        Returns:
            ECDSA signature bytes (DER encoded, variable length)
        """
        return self.get_signature_bytes(message_hash)

    def to_accumulate_signature(self, transaction_hash: bytes, **kwargs) -> dict:
        """
        Create an Accumulate protocol ECDSA signature.

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
            'curve': self.private_key.curve_name(),
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


class ECDSAVerifier(Verifier):
    """ECDSA signature verifier using SHA-256."""

    def __init__(self, public_key: Union[ECDSAPublicKey, bytes]):
        """
        Initialize ECDSA verifier.

        Args:
            public_key: ECDSA public key or public key bytes (DER format)
        """
        if isinstance(public_key, bytes):
            self.public_key = ECDSAPublicKey(public_key)
        else:
            self.public_key = public_key

    def signature_type(self) -> SignatureType:
        """Get the signature type for ECDSA-SHA256."""
        return SignatureType.ECDSASHA256

    def verify(self, digest: bytes, signature: bytes) -> bool:
        """
        Verify an ECDSA signature.

        Args:
            digest: 32-byte message hash that was signed
            signature: ECDSA signature to verify (DER encoded)

        Returns:
            True if signature is valid
        """
        return self.public_key.verify(signature, digest)

    def verify_accumulate_signature(self, digest: bytes, signature_obj: dict) -> bool:
        """
        Verify an Accumulate ECDSA signature object.

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

            # ECDSA signatures are DER encoded and variable length
            # Basic validation: should be at least 8 bytes for minimal DER structure
            if len(sig_bytes) < 8:
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
def has_ecdsa_support() -> bool:
    """Check if ECDSA functionality is available."""
    return HAS_ECDSA


def get_supported_curves() -> list[str]:
    """Get list of supported curve names."""
    return list(SUPPORTED_CURVES.keys())


def generate_ecdsa_keypair(curve_name: str = 'P-256') -> tuple[ECDSAPrivateKey, ECDSAPublicKey]:
    """
    Generate an ECDSA key pair.

    Args:
        curve_name: Curve name (default: 'P-256')

    Returns:
        Tuple of (private_key, public_key)
    """
    private_key = ECDSAPrivateKey.generate(curve_name)
    public_key = private_key.public_key()
    return private_key, public_key


# Export main classes
__all__ = [
    'ECDSASigner',
    'ECDSAVerifier',
    'ECDSAPrivateKey',
    'ECDSAPublicKey',
    'ECDSAError',
    'has_ecdsa_support',
    'get_supported_curves',
    'generate_ecdsa_keypair',
    'SUPPORTED_CURVES'
]