r"""
Key storage interface for Accumulate Protocol.

Provides secure key storage with multiple backend implementations.

Reference: C:/Accumulate_Stuff/accumulate\cmd\accumulated\wallets\keystore.go
"""

from __future__ import annotations
from abc import ABC, abstractmethod
from typing import Dict, List, Optional, Any, Union
import json
import os
import hashlib
import logging
from pathlib import Path

from ..runtime.url import AccountUrl
from ..runtime.errors import AccumulateError
from ..crypto.ed25519 import Ed25519KeyPair
from ..crypto.secp256k1 import Secp256k1KeyPair, has_secp256k1_support

logger = logging.getLogger(__name__)


class KeyStoreError(AccumulateError):
    """Key store specific errors."""
    pass


class KeyInfo:
    """
    Information about a stored key.

    Contains metadata about keys without exposing private data.
    """

    def __init__(
        self,
        key_id: str,
        public_key_hash: bytes,
        key_type: str,
        algorithm: str,
        created_at: int,
        account_url: Optional[AccountUrl] = None,
        metadata: Optional[Dict[str, Any]] = None
    ):
        """
        Initialize key information.

        Args:
            key_id: Unique identifier for the key
            public_key_hash: Hash of the public key
            key_type: Type of key (ed25519, secp256k1, etc.)
            algorithm: Signature algorithm
            created_at: Creation timestamp (Unix nanoseconds)
            account_url: Optional associated account URL
            metadata: Optional additional metadata
        """
        self.key_id = key_id
        self.public_key_hash = public_key_hash
        self.key_type = key_type
        self.algorithm = algorithm
        self.created_at = created_at
        self.account_url = account_url
        self.metadata = metadata or {}

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        result = {
            "keyId": self.key_id,
            "publicKeyHash": self.public_key_hash.hex(),
            "keyType": self.key_type,
            "algorithm": self.algorithm,
            "createdAt": self.created_at,
            "metadata": self.metadata
        }
        if self.account_url:
            result["accountUrl"] = str(self.account_url)
        return result

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> KeyInfo:
        """Create from dictionary representation."""
        return cls(
            key_id=data["keyId"],
            public_key_hash=bytes.fromhex(data["publicKeyHash"]),
            key_type=data["keyType"],
            algorithm=data["algorithm"],
            created_at=data["createdAt"],
            account_url=AccountUrl(data["accountUrl"]) if data.get("accountUrl") else None,
            metadata=data.get("metadata", {})
        )

    def __str__(self) -> str:
        return f"KeyInfo({self.key_id}, {self.algorithm})"

    def __repr__(self) -> str:
        return f"KeyInfo(id='{self.key_id}', type='{self.key_type}', algorithm='{self.algorithm}')"


class KeyStore(ABC):
    """
    Abstract key store interface.

    Defines the interface for secure key storage and retrieval.
    """

    @abstractmethod
    def store_key(self, key_id: str, key_pair: Union[Ed25519KeyPair, Secp256k1KeyPair], **metadata) -> KeyInfo:
        """
        Store a key pair.

        Args:
            key_id: Unique identifier for the key
            key_pair: Key pair to store
            **metadata: Additional metadata

        Returns:
            Key information

        Raises:
            KeyStoreError: If storage fails
        """
        pass

    @abstractmethod
    def get_key(self, key_id: str) -> Optional[Union[Ed25519KeyPair, Secp256k1KeyPair]]:
        """
        Retrieve a key pair by ID.

        Args:
            key_id: Key identifier

        Returns:
            Key pair if found, None otherwise
        """
        pass

    @abstractmethod
    def get_key_info(self, key_id: str) -> Optional[KeyInfo]:
        """
        Get key information without private data.

        Args:
            key_id: Key identifier

        Returns:
            Key information if found, None otherwise
        """
        pass

    @abstractmethod
    def list_keys(self) -> List[KeyInfo]:
        """
        List all stored keys.

        Returns:
            List of key information objects
        """
        pass

    @abstractmethod
    def delete_key(self, key_id: str) -> bool:
        """
        Delete a key.

        Args:
            key_id: Key identifier

        Returns:
            True if key was deleted
        """
        pass

    @abstractmethod
    def has_key(self, key_id: str) -> bool:
        """
        Check if a key exists.

        Args:
            key_id: Key identifier

        Returns:
            True if key exists
        """
        pass

    def find_key_by_public_key_hash(self, public_key_hash: bytes) -> Optional[KeyInfo]:
        """
        Find a key by its public key hash.

        Args:
            public_key_hash: Hash of the public key

        Returns:
            Key information if found
        """
        for key_info in self.list_keys():
            if key_info.public_key_hash == public_key_hash:
                return key_info
        return None

    def find_keys_by_account_url(self, account_url: AccountUrl) -> List[KeyInfo]:
        """
        Find keys associated with an account URL.

        Args:
            account_url: Account URL to search for

        Returns:
            List of associated key information
        """
        result = []
        for key_info in self.list_keys():
            if key_info.account_url == account_url:
                result.append(key_info)
        return result

    def get_key_count(self) -> int:
        """Get the number of stored keys."""
        return len(self.list_keys())

    def clear_all_keys(self) -> int:
        """
        Clear all stored keys.

        Returns:
            Number of keys that were deleted
        """
        keys = self.list_keys()
        deleted_count = 0
        for key_info in keys:
            if self.delete_key(key_info.key_id):
                deleted_count += 1
        return deleted_count


class MemoryKeyStore(KeyStore):
    """
    In-memory key store implementation.

    Stores keys in memory with no persistence.
    """

    def __init__(self):
        """Initialize memory key store."""
        self._keys: Dict[str, Union[Ed25519KeyPair, Secp256k1KeyPair]] = {}
        self._key_info: Dict[str, KeyInfo] = {}

    def store_key(self, key_id: str, key_pair: Union[Ed25519KeyPair, Secp256k1KeyPair], **metadata) -> KeyInfo:
        """Store a key pair in memory."""
        if key_id in self._keys:
            raise KeyStoreError(f"Key already exists: {key_id}")

        # Determine key type and algorithm
        if isinstance(key_pair, Ed25519KeyPair):
            key_type = "ed25519"
            algorithm = "ed25519"
            public_key_hash = hashlib.sha256(key_pair.public_key.to_bytes()).digest()
        elif isinstance(key_pair, Secp256k1KeyPair):
            key_type = "secp256k1"
            algorithm = "secp256k1"
            public_key_hash = hashlib.sha256(key_pair.public_key_bytes).digest()
        else:
            raise KeyStoreError(f"Unsupported key type: {type(key_pair)}")

        # Create key info
        from datetime import datetime, timezone
        created_at = int(datetime.now(timezone.utc).timestamp() * 1_000_000_000)

        key_info = KeyInfo(
            key_id=key_id,
            public_key_hash=public_key_hash,
            key_type=key_type,
            algorithm=algorithm,
            created_at=created_at,
            account_url=metadata.get("account_url"),
            metadata=metadata
        )

        # Store key and info
        self._keys[key_id] = key_pair
        self._key_info[key_id] = key_info

        logger.debug(f"Stored key {key_id} in memory key store")
        return key_info

    def get_key(self, key_id: str) -> Optional[Union[Ed25519KeyPair, Secp256k1KeyPair]]:
        """Retrieve a key pair from memory."""
        return self._keys.get(key_id)

    def get_key_info(self, key_id: str) -> Optional[KeyInfo]:
        """Get key information from memory."""
        return self._key_info.get(key_id)

    def list_keys(self) -> List[KeyInfo]:
        """List all keys in memory."""
        return list(self._key_info.values())

    def delete_key(self, key_id: str) -> bool:
        """Delete a key from memory."""
        if key_id in self._keys:
            del self._keys[key_id]
            del self._key_info[key_id]
            logger.debug(f"Deleted key {key_id} from memory key store")
            return True
        return False

    def has_key(self, key_id: str) -> bool:
        """Check if key exists in memory."""
        return key_id in self._keys

    def __str__(self) -> str:
        return f"MemoryKeyStore({len(self._keys)} keys)"

    def __repr__(self) -> str:
        return f"MemoryKeyStore(count={len(self._keys)})"


class FileKeyStore(KeyStore):
    """
    File-based key store implementation.

    Stores keys in JSON files with optional encryption.
    """

    def __init__(self, store_path: Union[str, Path], encrypted: bool = False):
        """
        Initialize file key store.

        Args:
            store_path: Directory path for key storage
            encrypted: Whether to encrypt stored keys (not implemented)
        """
        self.store_path = Path(store_path)
        self.encrypted = encrypted
        self._key_info_cache: Dict[str, KeyInfo] = {}

        # Create directory if it doesn't exist
        self.store_path.mkdir(parents=True, exist_ok=True)

        # Load existing key info
        self._load_key_info_cache()

        if encrypted:
            logger.warning("File encryption not yet implemented")

    def _get_key_file_path(self, key_id: str) -> Path:
        """Get the file path for a key."""
        safe_key_id = key_id.replace("/", "_").replace("\\", "_")
        return self.store_path / f"{safe_key_id}.key"

    def _get_info_file_path(self, key_id: str) -> Path:
        """Get the file path for key info."""
        safe_key_id = key_id.replace("/", "_").replace("\\", "_")
        return self.store_path / f"{safe_key_id}.info"

    def _load_key_info_cache(self):
        """Load key info cache from disk."""
        self._key_info_cache.clear()

        for info_file in self.store_path.glob("*.info"):
            try:
                with open(info_file, 'r') as f:
                    data = json.load(f)
                    key_info = KeyInfo.from_dict(data)
                    self._key_info_cache[key_info.key_id] = key_info
            except Exception as e:
                logger.warning(f"Failed to load key info from {info_file}: {e}")

    def store_key(self, key_id: str, key_pair: Union[Ed25519KeyPair, Secp256k1KeyPair], **metadata) -> KeyInfo:
        """Store a key pair to file."""
        key_file = self._get_key_file_path(key_id)
        info_file = self._get_info_file_path(key_id)

        if key_file.exists():
            raise KeyStoreError(f"Key file already exists: {key_file}")

        # Determine key type and serialize
        if isinstance(key_pair, Ed25519KeyPair):
            key_type = "ed25519"
            algorithm = "ed25519"
            public_key_hash = hashlib.sha256(key_pair.public_key.to_bytes()).digest()
            key_data = {
                "type": "ed25519",
                "privateKey": key_pair.private_key.to_bytes().hex(),
                "publicKey": key_pair.public_key.to_bytes().hex()
            }
        elif isinstance(key_pair, Secp256k1KeyPair):
            key_type = "secp256k1"
            algorithm = "secp256k1"
            public_key_hash = hashlib.sha256(key_pair.public_key_bytes).digest()
            key_data = {
                "type": "secp256k1",
                "privateKey": key_pair.private_key_bytes.hex(),
                "publicKey": key_pair.public_key_bytes.hex()
            }
        else:
            raise KeyStoreError(f"Unsupported key type: {type(key_pair)}")

        # Create key info
        from datetime import datetime, timezone
        created_at = int(datetime.now(timezone.utc).timestamp() * 1_000_000_000)

        key_info = KeyInfo(
            key_id=key_id,
            public_key_hash=public_key_hash,
            key_type=key_type,
            algorithm=algorithm,
            created_at=created_at,
            account_url=metadata.get("account_url"),
            metadata=metadata
        )

        # Write key file
        with open(key_file, 'w') as f:
            json.dump(key_data, f, indent=2)

        # Write info file
        with open(info_file, 'w') as f:
            json.dump(key_info.to_dict(), f, indent=2)

        # Update cache
        self._key_info_cache[key_id] = key_info

        logger.debug(f"Stored key {key_id} to file {key_file}")
        return key_info

    def get_key(self, key_id: str) -> Optional[Union[Ed25519KeyPair, Secp256k1KeyPair]]:
        """Retrieve a key pair from file."""
        key_file = self._get_key_file_path(key_id)

        if not key_file.exists():
            return None

        try:
            with open(key_file, 'r') as f:
                key_data = json.load(f)

            key_type = key_data["type"]

            if key_type == "ed25519":
                private_key_bytes = bytes.fromhex(key_data["privateKey"])
                return Ed25519KeyPair.from_private_bytes(private_key_bytes)

            elif key_type == "secp256k1":
                if not has_secp256k1_support():
                    raise KeyStoreError("SECP256K1 support not available")
                private_key_bytes = bytes.fromhex(key_data["privateKey"])
                return Secp256k1KeyPair(private_key_bytes)

            else:
                raise KeyStoreError(f"Unknown key type: {key_type}")

        except Exception as e:
            logger.error(f"Failed to load key {key_id}: {e}")
            return None

    def get_key_info(self, key_id: str) -> Optional[KeyInfo]:
        """Get key information from cache."""
        return self._key_info_cache.get(key_id)

    def list_keys(self) -> List[KeyInfo]:
        """List all keys from cache."""
        return list(self._key_info_cache.values())

    def delete_key(self, key_id: str) -> bool:
        """Delete a key file."""
        key_file = self._get_key_file_path(key_id)
        info_file = self._get_info_file_path(key_id)

        deleted = False

        if key_file.exists():
            key_file.unlink()
            deleted = True

        if info_file.exists():
            info_file.unlink()

        if key_id in self._key_info_cache:
            del self._key_info_cache[key_id]

        if deleted:
            logger.debug(f"Deleted key {key_id} from file store")

        return deleted

    def has_key(self, key_id: str) -> bool:
        """Check if key file exists."""
        return key_id in self._key_info_cache

    def __str__(self) -> str:
        return f"FileKeyStore({self.store_path}, {len(self._key_info_cache)} keys)"

    def __repr__(self) -> str:
        return f"FileKeyStore(path='{self.store_path}', count={len(self._key_info_cache)})"


# Add alias for compatibility
FileKeystore = FileKeyStore

# Export main classes
__all__ = [
    "KeyStore",
    "KeyInfo",
    "MemoryKeyStore",
    "FileKeyStore",
    "FileKeystore",
    "KeyStoreError"
]