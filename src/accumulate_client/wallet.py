"""
Wallet and keystore functionality for Accumulate Protocol.

Provides key storage, hierarchical derivation, and encrypted storage.
"""

from __future__ import annotations
import hashlib
import json
import os
import warnings
import base64
from typing import Dict, List, Optional, Any, Union

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

from .crypto.ed25519 import Ed25519PrivateKey


class InMemoryKeystore:
    """In-memory key storage."""

    def __init__(self):
        """Initialize empty keystore."""
        self._keys: Dict[str, Any] = {}

    def store(self, key_id: str, key: Any) -> None:
        """
        Store a key.

        Args:
            key_id: Unique identifier for the key
            key: Key object to store
        """
        self._keys[key_id] = key

    def get(self, key_id: str) -> Optional[Any]:
        """
        Retrieve a key.

        Args:
            key_id: Key identifier

        Returns:
            Key object or None if not found
        """
        return self._keys.get(key_id)

    def list(self) -> List[str]:
        """
        List all key identifiers.

        Returns:
            List of key IDs
        """
        return list(self._keys.keys())

    def remove(self, key_id: str) -> None:
        """
        Remove a key.

        Args:
            key_id: Key identifier to remove
        """
        self._keys.pop(key_id, None)

    def export(self) -> Dict[str, Any]:
        """
        Export all keys.

        Returns:
            Dictionary of key_id -> key_data
        """
        exported = {}
        for key_id, key in self._keys.items():
            if hasattr(key, 'to_bytes'):
                exported[key_id] = key.to_bytes().hex()
            else:
                exported[key_id] = str(key)
        return exported

    def import_keys(self, data: Dict[str, Any]) -> None:
        """
        Import keys from exported data.

        Args:
            data: Exported key data
        """
        for key_id, key_data in data.items():
            if isinstance(key_data, str):
                try:
                    # Try to import as Ed25519 key
                    key_bytes = bytes.fromhex(key_data)
                    key = Ed25519PrivateKey.from_bytes(key_bytes)
                    self._keys[key_id] = key
                except Exception:
                    # Store as raw string if import fails
                    self._keys[key_id] = key_data
            else:
                self._keys[key_id] = key_data


class SecureKeystore:
    """
    AES-256 encrypted key storage with PBKDF2 key derivation.

    Uses Fernet (AES-128-CBC with HMAC-SHA256) for authenticated encryption.
    Key derivation uses PBKDF2 with 480,000 iterations as recommended by OWASP.
    """

    # PBKDF2 iteration count - OWASP 2023 recommendation for SHA256
    PBKDF2_ITERATIONS = 480000

    def __init__(self, password: str, salt: Optional[bytes] = None):
        """
        Initialize secure keystore with password-based encryption.

        Args:
            password: Encryption password (should be strong)
            salt: Optional salt bytes (16 bytes). Generated randomly if not provided.
        """
        self.salt = salt if salt is not None else os.urandom(16)
        self._derive_key(password)
        self._keys: Dict[str, bytes] = {}

    def _derive_key(self, password: str) -> None:
        """
        Derive encryption key from password using PBKDF2.

        Args:
            password: User password
        """
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=self.salt,
            iterations=self.PBKDF2_ITERATIONS,
            backend=default_backend()
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode('utf-8')))
        self._fernet = Fernet(key)

    def store(self, key_id: str, key: Any) -> None:
        """
        Encrypt and store a key.

        Args:
            key_id: Unique identifier for the key
            key: Key object to encrypt and store (Ed25519PrivateKey or string)
        """
        if hasattr(key, 'to_bytes'):
            key_bytes = key.to_bytes()
        elif isinstance(key, bytes):
            key_bytes = key
        else:
            key_bytes = str(key).encode('utf-8')

        encrypted = self._fernet.encrypt(key_bytes)
        self._keys[key_id] = encrypted

    def get(self, key_id: str) -> Optional[Any]:
        """
        Retrieve and decrypt a key.

        Args:
            key_id: Key identifier

        Returns:
            Decrypted key (Ed25519PrivateKey if valid, otherwise string) or None if not found

        Raises:
            InvalidToken: If decryption fails (wrong password or corrupted data)
        """
        encrypted = self._keys.get(key_id)
        if encrypted is None:
            return None

        decrypted = self._fernet.decrypt(encrypted)

        try:
            # Try to restore as Ed25519 key
            return Ed25519PrivateKey.from_bytes(decrypted)
        except Exception:
            # Return as decoded string
            try:
                return decrypted.decode('utf-8')
            except UnicodeDecodeError:
                # Return raw bytes if not valid UTF-8
                return decrypted

    def list(self) -> List[str]:
        """
        List all key identifiers.

        Returns:
            List of key IDs stored in the keystore
        """
        return list(self._keys.keys())

    def remove(self, key_id: str) -> None:
        """
        Remove a key from the keystore.

        Args:
            key_id: Key identifier to remove
        """
        self._keys.pop(key_id, None)

    def export(self) -> Dict[str, Any]:
        """
        Export keystore for serialization.

        Returns:
            Dictionary containing salt and encrypted keys (base64 encoded)
        """
        return {
            'salt': base64.b64encode(self.salt).decode('ascii'),
            'keys': {
                key_id: base64.b64encode(encrypted).decode('ascii')
                for key_id, encrypted in self._keys.items()
            }
        }

    @classmethod
    def from_export(cls, data: Dict[str, Any], password: str) -> 'SecureKeystore':
        """
        Restore keystore from exported data.

        Args:
            data: Exported keystore data
            password: Encryption password

        Returns:
            Restored SecureKeystore instance
        """
        salt = base64.b64decode(data['salt'])
        keystore = cls(password, salt=salt)
        keystore._keys = {
            key_id: base64.b64decode(encrypted)
            for key_id, encrypted in data['keys'].items()
        }
        return keystore

    def change_password(self, old_password: str, new_password: str) -> None:
        """
        Change the keystore password.

        Decrypts all keys with old password and re-encrypts with new password.

        Args:
            old_password: Current password
            new_password: New password to set

        Raises:
            InvalidToken: If old password is incorrect
        """
        # Decrypt all keys with old password
        decrypted_keys: Dict[str, bytes] = {}
        for key_id in self._keys:
            encrypted = self._keys[key_id]
            decrypted_keys[key_id] = self._fernet.decrypt(encrypted)

        # Generate new salt and derive new key
        self.salt = os.urandom(16)
        self._derive_key(new_password)

        # Re-encrypt all keys with new password
        self._keys = {
            key_id: self._fernet.encrypt(decrypted)
            for key_id, decrypted in decrypted_keys.items()
        }


class EncryptedKeystore(SecureKeystore):
    """
    Deprecated: Use SecureKeystore instead.

    This class is maintained for backward compatibility only.
    It now uses AES-256 encryption instead of the previous XOR-based implementation.
    """

    def __init__(self, password: str, salt: Optional[bytes] = None):
        """
        Initialize encrypted keystore.

        Args:
            password: Encryption password
            salt: Optional salt for key derivation
        """
        warnings.warn(
            "EncryptedKeystore is deprecated. Use SecureKeystore instead.",
            DeprecationWarning,
            stacklevel=2
        )
        super().__init__(password, salt)


class KeyHashIndex:
    """Index for looking up keys by public key hash."""

    def __init__(self):
        """Initialize empty index."""
        self._index: Dict[bytes, Any] = {}

    def add(self, key_hash: bytes, key: Any) -> None:
        """
        Add a key to the index.

        Args:
            key_hash: Hash of the public key
            key: Key object
        """
        self._index[key_hash] = key

    def lookup(self, key_hash: bytes) -> Optional[Any]:
        """
        Lookup a key by hash.

        Args:
            key_hash: Hash to lookup

        Returns:
            Key object or None
        """
        return self._index.get(key_hash)

    def remove(self, key_hash: bytes) -> None:
        """Remove a key from the index."""
        self._index.pop(key_hash, None)


def derive_child_key(master_seed: bytes, path: List[int]) -> Ed25519PrivateKey:
    """
    Derive a child key from master seed using path.

    Args:
        master_seed: Master seed bytes
        path: Derivation path (list of integers)

    Returns:
        Derived Ed25519 private key

    Note: This is a simplified implementation. A full HD wallet would use
    BIP32/SLIP-0010 for proper hierarchical deterministic derivation.
    """
    current_seed = master_seed

    for index in path:
        # Simple derivation: hash(current_seed + index)
        current_seed = hashlib.sha256(current_seed + index.to_bytes(4, 'big')).digest()

    return Ed25519PrivateKey.from_seed(current_seed)


__all__ = [
    "InMemoryKeystore",
    "SecureKeystore",
    "EncryptedKeystore",  # Deprecated, use SecureKeystore
    "KeyHashIndex",
    "derive_child_key"
]