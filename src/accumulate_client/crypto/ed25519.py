"""
Ed25519 KeyPair - 1:1 mapping to Dart ed25519.dart

Implements exact Ed25519 cryptographic semantics matching Dart Ed25519KeyPair class.
Uses pure Ed25519 (not Ed25519ph) for signature compatibility.
"""

import hashlib
from typing import Tuple

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519


class Ed25519KeyPair:
    """
    Ed25519 key pair with Accumulate-specific derivations.

    Maps 1:1 to Dart ed25519.dart Ed25519KeyPair class.
    Maintains same method names, signatures, and cryptographic behavior.

    LID/LTA derivation rules discovered from Go: protocol/protocol.go:280-297, 273-278
    - For Ed25519: keyHash = SHA256(publicKey)
    - LID: acc://<keyHash[0:20]><checksum> where checksum = SHA256(hex(keyHash[0:20]))[28:]
    - LTA: acc://<keyHash[0:20]><checksum>/ACME
    """

    def __init__(self, private_key: ed25519.Ed25519PrivateKey):
        """
        Initialize with Ed25519 private key.

        Maps to: Dart ed25519.dart:17 Ed25519KeyPair._(this.keyPair, this.publicKey)

        Args:
            private_key: Ed25519 private key instance
        """
        self._private_key = private_key
        self._public_key = private_key.public_key()

    @classmethod
    def generate(cls) -> "Ed25519KeyPair":
        """
        Generate a new Ed25519 key pair.

        Maps to: Dart ed25519.dart:19-24 static Future<Ed25519KeyPair> generate()

        Returns:
            New Ed25519KeyPair instance
        """
        private_key = ed25519.Ed25519PrivateKey.generate()
        return cls(private_key)

    @classmethod
    def from_seed(cls, seed32: bytes) -> "Ed25519KeyPair":
        """
        Create key pair from 32-byte seed.

        Maps to: Dart ed25519.dart:26-34 static Future<Ed25519KeyPair> fromSeed(Uint8List seed32)

        Args:
            seed32: 32-byte seed

        Returns:
            Ed25519KeyPair from seed

        Raises:
            ValueError: If seed is not exactly 32 bytes
        """
        if len(seed32) != 32:
            raise ValueError("Seed must be exactly 32 bytes")

        private_key = ed25519.Ed25519PrivateKey.from_private_bytes(seed32)
        return cls(private_key)

    def public_key_bytes(self) -> bytes:
        """
        Get public key as bytes.

        Maps to: Dart ed25519.dart:36-39 Future<Uint8List> publicKeyBytes()

        Returns:
            32-byte public key
        """
        return self._public_key.public_bytes(
            encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
        )

    def private_key_bytes(self) -> bytes:
        """
        Get private key as bytes.

        Returns:
            32-byte private key (seed)
        """
        return self._private_key.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption(),
        )

    def sign(self, msg: bytes) -> bytes:
        """
        Sign message with Ed25519.

        Maps to: Dart ed25519.dart:41-45 Future<Uint8List> sign(Uint8List msg)

        Uses pure Ed25519 (not Ed25519ph) for compatibility with Dart/TS.

        Args:
            msg: Message to sign

        Returns:
            64-byte raw signature
        """
        return self._private_key.sign(msg)

    def verify(self, msg: bytes, sig: bytes) -> bool:
        """
        Verify Ed25519 signature.

        Maps to: Dart ed25519.dart:47-55 Future<bool> verify(Uint8List msg, Uint8List sig)

        Args:
            msg: Original message
            sig: 64-byte signature

        Returns:
            True if signature is valid
        """
        try:
            self._public_key.verify(sig, msg)
            return True
        except Exception:
            return False

    def derive_lite_identity_url(self) -> str:
        """
        Derive Lite Identity URL using discovered algorithm.

        Maps to: Dart ed25519.dart:57-78 Future<AccUrl> deriveLiteIdentityUrl()

        Go: protocol/protocol.go:290-296 - keyHash = SHA256(publicKey) for Ed25519
        Go: protocol/protocol.go:273-278 - LID format with checksum

        Returns:
            Lite Identity URL with format: acc://{hash40}{checksum8}
        """
        pk = self.public_key_bytes()

        # For Ed25519: keyHash = SHA256(publicKey) - Go: protocol/protocol.go:290
        key_hash_full = hashlib.sha256(pk).digest()

        # Use first 20 bytes - Go: protocol/protocol.go:274
        key_hash_20 = key_hash_full[:20]

        # Convert to hex string - Go: protocol/protocol.go:274
        key_str = key_hash_20.hex()

        # Calculate checksum - Go: protocol/protocol.go:275-276
        checksum_full = hashlib.sha256(key_str.encode("utf-8")).digest()
        checksum = checksum_full[28:].hex()  # Take last 4 bytes

        # Format: acc://<keyHash[0:20]><checksum> - Go: protocol/protocol.go:277
        return f"acc://{key_str}{checksum}"

    def derive_lite_token_account_url(self, token: str = "ACME") -> str:
        """
        Derive Lite Token Account URL for specified token.

        Maps to: Dart ed25519.dart:80-85 Future<AccUrl> deriveLiteTokenAccountUrl()

        Go: protocol/protocol.go:267-268 - LTA = LID + "/ACME" path

        Args:
            token: Token symbol (default: "ACME")

        Returns:
            Lite Token Account URL with format: {LID}/{token}
        """
        lid = self.derive_lite_identity_url()
        return f"{lid}/{token}"


def verify_ed25519(public_key_bytes: bytes, signature: bytes, message: bytes) -> bool:
    """
    Standalone Ed25519 signature verification.

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


def keypair_from_seed(seed: bytes) -> Tuple[bytes, bytes]:
    """
    Generate Ed25519 keypair from 32-byte seed.

    Args:
        seed: 32-byte seed

    Returns:
        Tuple of (private_key_bytes, public_key_bytes)
    """
    keypair = Ed25519KeyPair.from_seed(seed)
    return keypair.private_key_bytes(), keypair.public_key_bytes()
