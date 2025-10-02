"""
Wallet and keystore functionality for Accumulate Protocol.

Provides key storage, hierarchical derivation, and encrypted storage.
"""

from __future__ import annotations
import hashlib
import json
import os
from typing import Dict, List, Optional, Any, Union
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


class EncryptedKeystore:
    """Encrypted key storage (stub implementation)."""

    def __init__(self, password: str):
        """
        Initialize encrypted keystore.

        Args:
            password: Encryption password
        """
        self.password = password
        self._keys: Dict[str, bytes] = {}

    def store(self, key_id: str, key: Any) -> None:
        """
        Store an encrypted key.

        Args:
            key_id: Key identifier
            key: Key to encrypt and store
        """
        # Simple XOR encryption for demo (NOT SECURE)
        if hasattr(key, 'to_bytes'):
            key_bytes = key.to_bytes()
        else:
            key_bytes = str(key).encode()

        password_hash = hashlib.sha256(self.password.encode()).digest()
        encrypted = bytes(a ^ b for a, b in zip(key_bytes, password_hash * (len(key_bytes) // 32 + 1)))
        self._keys[key_id] = encrypted

    def get(self, key_id: str) -> Optional[Any]:
        """
        Retrieve and decrypt a key.

        Args:
            key_id: Key identifier

        Returns:
            Decrypted key or None
        """
        encrypted = self._keys.get(key_id)
        if encrypted is None:
            return None

        # Decrypt using same XOR
        password_hash = hashlib.sha256(self.password.encode()).digest()
        decrypted = bytes(a ^ b for a, b in zip(encrypted, password_hash * (len(encrypted) // 32 + 1)))

        try:
            # Try to restore as Ed25519 key
            return Ed25519PrivateKey.from_bytes(decrypted)
        except Exception:
            return decrypted.decode()

    def list(self) -> List[str]:
        """List all key identifiers."""
        return list(self._keys.keys())

    def remove(self, key_id: str) -> None:
        """Remove a key."""
        self._keys.pop(key_id, None)


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
    "EncryptedKeystore",
    "KeyHashIndex",
    "derive_child_key"
]