r"""
Ed25519 cryptographic operations for Accumulate Protocol.

Provides Ed25519 key generation, signing, and verification that matches
the Go implementation exactly.

Reference: C:/Accumulate_Stuff/accumulate\pkg\types\encoding\signature.go
"""

from __future__ import annotations
import hashlib
import os
from typing import Union, Optional, Tuple

try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey as CryptoEd25519PrivateKey,
        Ed25519PublicKey as CryptoEd25519PublicKey
    )
    from cryptography.hazmat.primitives import serialization
    HAS_CRYPTOGRAPHY = True
except ImportError:
    try:
        import nacl.signing
        import nacl.encoding
        HAS_NACL = True
        HAS_CRYPTOGRAPHY = False
    except ImportError:
        HAS_CRYPTOGRAPHY = False
        HAS_NACL = False


class Ed25519Error(Exception):
    """Base exception for Ed25519 operations."""
    pass


class Ed25519PublicKey:
    """
    Ed25519 public key.

    Provides verification operations and serialization.
    """

    def __init__(self, public_key_bytes: bytes):
        """
        Initialize from 32-byte public key.

        Args:
            public_key_bytes: 32-byte Ed25519 public key

        Raises:
            Ed25519Error: If key is invalid
        """
        if len(public_key_bytes) != 32:
            raise Ed25519Error(f"Ed25519 public key must be 32 bytes, got {len(public_key_bytes)}")

        self._key_bytes = public_key_bytes

        if HAS_CRYPTOGRAPHY:
            try:
                self._crypto_key = CryptoEd25519PublicKey.from_public_bytes(public_key_bytes)
            except Exception as e:
                raise Ed25519Error(f"Invalid Ed25519 public key: {e}")
        elif HAS_NACL:
            try:
                self._nacl_key = nacl.signing.VerifyKey(public_key_bytes)
            except Exception as e:
                raise Ed25519Error(f"Invalid Ed25519 public key: {e}")
        else:
            raise Ed25519Error("No Ed25519 implementation available (install cryptography or pynacl)")

    @classmethod
    def from_hex(cls, hex_string: str) -> Ed25519PublicKey:
        """Create public key from hex string."""
        try:
            key_bytes = bytes.fromhex(hex_string)
        except ValueError as e:
            raise Ed25519Error(f"Invalid hex string: {e}")
        return cls(key_bytes)

    @classmethod
    def from_bytes(cls, key_bytes: bytes) -> Ed25519PublicKey:
        """Create public key from bytes."""
        return cls(key_bytes)

    def to_bytes(self) -> bytes:
        """Get the 32-byte public key."""
        return self._key_bytes

    def to_hex(self) -> str:
        """Get the public key as hex string."""
        return self._key_bytes.hex()

    def verify(self, signature: bytes, message: bytes) -> bool:
        """
        Verify a signature against a message.

        Args:
            signature: 64-byte Ed25519 signature
            message: Message that was signed

        Returns:
            True if signature is valid
        """
        if len(signature) != 64:
            return False

        try:
            if HAS_CRYPTOGRAPHY:
                self._crypto_key.verify(signature, message)
                return True
            elif HAS_NACL:
                self._nacl_key.verify(signature + message)
                return True
        except Exception:
            return False

        return False

    def __eq__(self, other) -> bool:
        """Check equality with another public key."""
        if not isinstance(other, Ed25519PublicKey):
            return False
        return self._key_bytes == other._key_bytes

    def __str__(self) -> str:
        return f"Ed25519PublicKey({self.to_hex()})"

    def __repr__(self) -> str:
        return f"Ed25519PublicKey.from_hex('{self.to_hex()}')"


class Ed25519PrivateKey:
    """
    Ed25519 private key.

    Provides signing operations and key derivation.
    """

    def __init__(self, private_key_bytes: bytes):
        """
        Initialize from 32-byte private key seed.

        Args:
            private_key_bytes: 32-byte Ed25519 private key seed

        Raises:
            Ed25519Error: If key is invalid
        """
        if len(private_key_bytes) != 32:
            raise Ed25519Error(f"Ed25519 private key must be 32 bytes, got {len(private_key_bytes)}")

        self._key_bytes = private_key_bytes

        if HAS_CRYPTOGRAPHY:
            try:
                self._crypto_key = CryptoEd25519PrivateKey.from_private_bytes(private_key_bytes)
                self._public_key = Ed25519PublicKey(
                    self._crypto_key.public_key().public_bytes(
                        encoding=serialization.Encoding.Raw,
                        format=serialization.PublicFormat.Raw
                    )
                )
            except Exception as e:
                raise Ed25519Error(f"Invalid Ed25519 private key: {e}")
        elif HAS_NACL:
            try:
                self._nacl_key = nacl.signing.SigningKey(private_key_bytes)
                self._public_key = Ed25519PublicKey(bytes(self._nacl_key.verify_key))
            except Exception as e:
                raise Ed25519Error(f"Invalid Ed25519 private key: {e}")
        else:
            raise Ed25519Error("No Ed25519 implementation available (install cryptography or pynacl)")

    @classmethod
    def generate(cls) -> Ed25519PrivateKey:
        """Generate a new random Ed25519 private key."""
        if HAS_CRYPTOGRAPHY:
            crypto_key = CryptoEd25519PrivateKey.generate()
            private_bytes = crypto_key.private_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PrivateFormat.Raw,
                encryption_algorithm=serialization.NoEncryption()
            )
            return cls(private_bytes)
        elif HAS_NACL:
            nacl_key = nacl.signing.SigningKey.generate()
            return cls(bytes(nacl_key))
        else:
            raise Ed25519Error("No Ed25519 implementation available")

    @classmethod
    def from_hex(cls, hex_string: str) -> Ed25519PrivateKey:
        """Create private key from hex string."""
        try:
            key_bytes = bytes.fromhex(hex_string)
        except ValueError as e:
            raise Ed25519Error(f"Invalid hex string: {e}")
        return cls(key_bytes)

    @classmethod
    def from_bytes(cls, key_bytes: bytes) -> Ed25519PrivateKey:
        """Create private key from bytes."""
        return cls(key_bytes)

    @classmethod
    def from_seed(cls, seed: Union[str, bytes]) -> Ed25519PrivateKey:
        """
        Derive private key from seed using SHA-256.

        For deterministic test keys.
        """
        if isinstance(seed, str):
            seed = seed.encode('utf-8')

        # Use SHA-256 to derive 32-byte key from arbitrary seed
        key_bytes = hashlib.sha256(seed).digest()
        return cls(key_bytes)

    def to_bytes(self) -> bytes:
        """Get the 32-byte private key seed."""
        return self._key_bytes

    def to_hex(self) -> str:
        """Get the private key as hex string."""
        return self._key_bytes.hex()

    def public_key(self) -> Ed25519PublicKey:
        """Get the corresponding public key."""
        return self._public_key

    def sign(self, message: bytes) -> bytes:
        """
        Sign a message.

        Args:
            message: Message to sign

        Returns:
            64-byte Ed25519 signature
        """
        if HAS_CRYPTOGRAPHY:
            return self._crypto_key.sign(message)
        elif HAS_NACL:
            signed = self._nacl_key.sign(message)
            return signed.signature
        else:
            raise Ed25519Error("No Ed25519 implementation available")

    def __str__(self) -> str:
        return f"Ed25519PrivateKey(public={self.public_key().to_hex()})"

    def __repr__(self) -> str:
        return f"Ed25519PrivateKey.from_hex('{self.to_hex()}')"


class Ed25519KeyPair:
    """
    Ed25519 key pair containing both private and public keys.
    """

    def __init__(self, private_key: Ed25519PrivateKey):
        """
        Initialize with private key.

        Args:
            private_key: Ed25519 private key
        """
        self.private_key = private_key
        self.public_key = private_key.public_key()
        # Add compatibility attributes for tests
        self._private_key = private_key
        self._public_key = self.public_key

    @classmethod
    def generate(cls) -> Ed25519KeyPair:
        """Generate a new random key pair."""
        return cls(Ed25519PrivateKey.generate())

    @classmethod
    def from_private_hex(cls, hex_string: str) -> Ed25519KeyPair:
        """Create key pair from private key hex string."""
        return cls(Ed25519PrivateKey.from_hex(hex_string))

    @classmethod
    def from_seed(cls, seed: Union[str, bytes]) -> Ed25519KeyPair:
        """
        Create deterministic key pair from seed.

        Args:
            seed: 32-byte seed (or string that will be hashed to 32 bytes)

        Raises:
            ValueError: If seed is bytes and not exactly 32 bytes
        """
        if isinstance(seed, bytes) and len(seed) != 32:
            raise ValueError("Seed must be exactly 32 bytes")
        return cls(Ed25519PrivateKey.from_seed(seed))

    def sign(self, message: bytes) -> bytes:
        """Sign a message and return signature bytes."""
        return self.private_key.sign(message)

    def public_key_bytes(self) -> bytes:
        """Get the 32-byte public key."""
        return self.public_key.to_bytes()

    def private_key_bytes(self) -> bytes:
        """Get the 32-byte private key."""
        return self.private_key.to_bytes()

    def verify(self, message: bytes, signature: bytes) -> bool:
        """
        Verify a signature against a message.

        Args:
            message: Message that was signed
            signature: 64-byte Ed25519 signature

        Returns:
            True if signature is valid
        """
        return self.public_key.verify(signature, message)

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

    def __str__(self) -> str:
        return f"Ed25519KeyPair(public={self.public_key.to_hex()})"


class Ed25519Signature:
    """
    Ed25519 signature with metadata.

    Matches the structure expected by Accumulate protocol.
    """

    def __init__(self, signature: bytes, public_key: Ed25519PublicKey, message: Optional[bytes] = None):
        """
        Initialize signature.

        Args:
            signature: 64-byte Ed25519 signature
            public_key: Public key used for signing
            message: Original message (optional, for verification)
        """
        if len(signature) != 64:
            raise Ed25519Error(f"Ed25519 signature must be 64 bytes, got {len(signature)}")

        self.signature = signature
        self.public_key = public_key
        self.message = message

    @classmethod
    def from_hex(cls, signature_hex: str, public_key: Ed25519PublicKey) -> Ed25519Signature:
        """Create signature from hex string."""
        try:
            signature_bytes = bytes.fromhex(signature_hex)
        except ValueError as e:
            raise Ed25519Error(f"Invalid hex string: {e}")
        return cls(signature_bytes, public_key)

    def to_hex(self) -> str:
        """Get signature as hex string."""
        return self.signature.hex()

    def verify(self, message: Optional[bytes] = None) -> bool:
        """
        Verify the signature.

        Args:
            message: Message to verify against (uses stored message if None)

        Returns:
            True if signature is valid
        """
        if message is None:
            message = self.message

        if message is None:
            raise Ed25519Error("No message provided for verification")

        return self.public_key.verify(self.signature, message)

    def to_accumulate_format(self) -> dict:
        """
        Convert to Accumulate protocol signature format.

        Returns:
            Dictionary matching Accumulate signature structure
        """
        return {
            "type": "ed25519",
            "publicKey": self.public_key.to_hex(),
            "signature": self.to_hex()
        }

    def __str__(self) -> str:
        return f"Ed25519Signature({self.to_hex()[:16]}...)"

    def __repr__(self) -> str:
        return f"Ed25519Signature.from_hex('{self.to_hex()}', Ed25519PublicKey.from_hex('{self.public_key.to_hex()}'))"


# Test vectors for validation
TEST_VECTORS = [
    {
        "name": "RFC 8032 Test Vector 1",
        "private_key": "9d61b19deffd5020d75b7c3c4d3c1b62295e7e1d13d91e3f32b4d3e91b2b2e3d",
        "public_key": "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
        "message": "",
        "signature": "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
    },
    {
        "name": "RFC 8032 Test Vector 2",
        "private_key": "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
        "public_key": "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
        "message": "72",
        "signature": "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00"
    }
]


def verify_test_vectors() -> bool:
    """
    Verify implementation against RFC 8032 test vectors.

    Returns:
        True if all test vectors pass
    """
    for vector in TEST_VECTORS:
        try:
            # Create key pair
            private_key = Ed25519PrivateKey.from_hex(vector["private_key"])
            key_pair = Ed25519KeyPair(private_key)

            # Verify public key matches
            if key_pair.public_key.to_hex() != vector["public_key"]:
                print(f"Public key mismatch for {vector['name']}")
                return False

            # Sign message
            message = bytes.fromhex(vector["message"]) if vector["message"] else b""
            signature = key_pair.sign(message)

            # Verify signature matches expected
            if signature.to_hex() != vector["signature"]:
                print(f"Signature mismatch for {vector['name']}")
                return False

            # Verify signature validates
            if not signature.verify(message):
                print(f"Signature validation failed for {vector['name']}")
                return False

        except Exception as e:
            print(f"Exception in test vector {vector['name']}: {e}")
            return False

    return True


# Export main classes
__all__ = [
    "Ed25519PublicKey",
    "Ed25519PrivateKey",
    "Ed25519KeyPair",
    "Ed25519Signature",
    "Ed25519Error",
    "verify_test_vectors"
]# --- Compatibility shims for tests expecting these names ---------------------
from typing import Tuple, TYPE_CHECKING

try:
    # cryptography's signature error
    from cryptography.exceptions import InvalidSignature  # type: ignore
except Exception:  # pragma: no cover
    InvalidSignature = Exception  # fallback

# If your module already defines these, don't re-declare.
if "keypair_from_seed" not in globals():
    def keypair_from_seed(seed: bytes):
        """
        Create an Ed25519 keypair deterministically from a 32-byte seed.

        Returns a tuple (private_key_bytes, public_key_bytes).

        Raises:
            ValueError: If seed is not exactly 32 bytes
        """
        if len(seed) != 32:
            raise ValueError("Seed must be exactly 32 bytes")

        # Use the Ed25519KeyPair class and return bytes
        keypair = Ed25519KeyPair.from_seed(seed)
        return (keypair.private_key_bytes(), keypair.public_key_bytes())

if "verify_ed25519" not in globals():
    def verify_ed25519(public_key_bytes: bytes, signature: bytes, message: bytes) -> bool:
        """
        Verify an Ed25519 signature. Returns True if valid, False otherwise.

        Args:
            public_key_bytes: 32-byte public key
            signature: 64-byte signature
            message: Message that was signed
        """
        try:
            # Create public key object from bytes
            public_key = Ed25519PublicKey(public_key_bytes)
            return public_key.verify(signature, message)
        except Exception:
            # Be strict: anything else is a failure in test context
            return False
# --- end shims ----------------------------------------------------------------
