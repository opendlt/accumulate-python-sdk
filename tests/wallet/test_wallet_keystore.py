"""
Test wallet keystore functionality.

Tests in-memory and file-backed keystores for key management,
including add/get/remove operations, export/import, and error handling.
"""

import pytest
import tempfile
import os
import json
import hashlib
from pathlib import Path
import sys

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))
from helpers import mk_ed25519_keypair, mk_identity_url, MockKeyStore

from accumulate_client.crypto.ed25519 import Ed25519PrivateKey


class InMemoryKeyStore:
    """
    In-memory keystore implementation for testing.

    TODO[ACC-P2-S915]: Replace with actual keystore when implemented
    """

    def __init__(self):
        """Initialize in-memory keystore."""
        self.keys = {}
        self.metadata = {}

    def add_key(self, identity: str, key_hash: str, private_key: bytes, metadata: dict = None):
        """Add a key to the keystore."""
        key_id = f"{identity}:{key_hash}"
        self.keys[key_id] = private_key
        self.metadata[key_id] = metadata or {}

    def get_key(self, identity: str, key_hash: str) -> bytes:
        """Get a key from the keystore."""
        key_id = f"{identity}:{key_hash}"
        if key_id not in self.keys:
            raise KeyError(f"Key not found: {key_id}")
        return self.keys[key_id]

    def remove_key(self, identity: str, key_hash: str) -> bool:
        """Remove a key from the keystore."""
        key_id = f"{identity}:{key_hash}"
        if key_id in self.keys:
            del self.keys[key_id]
            del self.metadata[key_id]
            return True
        return False

    def list_keys(self, identity: str = None) -> list:
        """List keys in the keystore."""
        if identity is None:
            return list(self.keys.keys())
        else:
            return [key_id for key_id in self.keys.keys() if key_id.startswith(f"{identity}:")]

    def get_metadata(self, identity: str, key_hash: str) -> dict:
        """Get metadata for a key."""
        key_id = f"{identity}:{key_hash}"
        return self.metadata.get(key_id, {})


class FileBackedKeyStore(InMemoryKeyStore):
    """
    File-backed keystore implementation for testing.

    TODO[ACC-P2-S916]: Replace with actual file-backed keystore when implemented
    """

    KEYSTORE_VERSION = "1.0"

    def __init__(self, file_path: str):
        """Initialize file-backed keystore."""
        super().__init__()
        self.file_path = file_path
        self.load()

    def save(self):
        """Save keystore to file."""
        data = {
            "version": self.KEYSTORE_VERSION,
            "keys": {k: v.hex() for k, v in self.keys.items()},
            "metadata": self.metadata
        }

        with open(self.file_path, 'w') as f:
            json.dump(data, f, indent=2)

    def load(self):
        """Load keystore from file."""
        if not os.path.exists(self.file_path):
            return

        try:
            with open(self.file_path, 'r') as f:
                data = json.load(f)

            # Check version compatibility
            version = data.get("version", "unknown")
            if version != self.KEYSTORE_VERSION:
                raise ValueError(f"Incompatible keystore version: {version}")

            # Load keys and metadata
            self.keys = {k: bytes.fromhex(v) for k, v in data.get("keys", {}).items()}
            self.metadata = data.get("metadata", {})

        except (json.JSONDecodeError, ValueError) as e:
            raise ValueError(f"Failed to load keystore: {e}")

    def add_key(self, identity: str, key_hash: str, private_key: bytes, metadata: dict = None):
        """Add a key and save to file."""
        super().add_key(identity, key_hash, private_key, metadata)
        self.save()

    def remove_key(self, identity: str, key_hash: str) -> bool:
        """Remove a key and save to file."""
        result = super().remove_key(identity, key_hash)
        if result:
            self.save()
        return result


def test_in_memory_keystore_basic_operations():
    """Test basic in-memory keystore operations."""
    keystore = InMemoryKeyStore()

    # Test empty keystore
    assert len(keystore.list_keys()) == 0

    # Add a key
    private_key, public_key = mk_ed25519_keypair(seed=1001)
    identity = mk_identity_url("test.acme")
    key_hash = hashlib.sha256(public_key.to_bytes()).hexdigest()

    keystore.add_key(identity, key_hash, private_key.to_bytes())

    # Test retrieval
    retrieved_key = keystore.get_key(identity, key_hash)
    assert retrieved_key == private_key.to_bytes()

    # Test listing
    keys = keystore.list_keys()
    assert len(keys) == 1
    assert f"{identity}:{key_hash}" in keys

    # Test removal
    assert keystore.remove_key(identity, key_hash) is True
    assert len(keystore.list_keys()) == 0

    # Test removal of non-existent key
    assert keystore.remove_key(identity, key_hash) is False


def test_in_memory_keystore_metadata():
    """Test keystore metadata functionality."""
    keystore = InMemoryKeyStore()

    private_key, public_key = mk_ed25519_keypair(seed=1002)
    identity = mk_identity_url("meta.acme")
    key_hash = hashlib.sha256(public_key.to_bytes()).hexdigest()

    metadata = {
        "created_at": "2024-01-01T00:00:00Z",
        "purpose": "signing",
        "algorithm": "ed25519"
    }

    keystore.add_key(identity, key_hash, private_key.to_bytes(), metadata)

    retrieved_metadata = keystore.get_metadata(identity, key_hash)
    assert retrieved_metadata == metadata


def test_in_memory_keystore_multiple_identities():
    """Test keystore with multiple identities."""
    keystore = InMemoryKeyStore()

    # Add keys for different identities
    for i in range(3):
        private_key, public_key = mk_ed25519_keypair(seed=1100 + i)
        identity = mk_identity_url(f"identity{i}.acme")
        key_hash = hashlib.sha256(public_key.to_bytes()).hexdigest()

        keystore.add_key(identity, key_hash, private_key.to_bytes())

    # Test total key count
    all_keys = keystore.list_keys()
    assert len(all_keys) == 3

    # Test filtering by identity
    identity0 = mk_identity_url("identity0.acme")
    identity0_keys = keystore.list_keys(identity0)
    assert len(identity0_keys) == 1
    assert identity0_keys[0].startswith(identity0)


def test_in_memory_keystore_error_handling():
    """Test keystore error handling."""
    keystore = InMemoryKeyStore()

    identity = mk_identity_url("error.acme")
    key_hash = "nonexistent"

    # Test getting non-existent key
    with pytest.raises(KeyError, match="Key not found"):
        keystore.get_key(identity, key_hash)

    # Test getting metadata for non-existent key
    metadata = keystore.get_metadata(identity, key_hash)
    assert metadata == {}


def test_file_backed_keystore_persistence():
    """Test file-backed keystore persistence."""
    with tempfile.TemporaryDirectory() as temp_dir:
        keystore_path = os.path.join(temp_dir, "test_keystore.json")

        # Create keystore and add key
        keystore1 = FileBackedKeyStore(keystore_path)

        private_key, public_key = mk_ed25519_keypair(seed=2001)
        identity = mk_identity_url("persist.acme")
        key_hash = hashlib.sha256(public_key.to_bytes()).hexdigest()

        keystore1.add_key(identity, key_hash, private_key.to_bytes())

        # Verify file was created
        assert os.path.exists(keystore_path)

        # Create new keystore instance from same file
        keystore2 = FileBackedKeyStore(keystore_path)

        # Verify key was loaded
        retrieved_key = keystore2.get_key(identity, key_hash)
        assert retrieved_key == private_key.to_bytes()


def test_file_backed_keystore_export_import():
    """Test keystore export/import functionality."""
    with tempfile.TemporaryDirectory() as temp_dir:
        keystore_path = os.path.join(temp_dir, "export_test.json")

        # Create keystore with multiple keys
        keystore = FileBackedKeyStore(keystore_path)

        keys_data = []
        for i in range(3):
            private_key, public_key = mk_ed25519_keypair(seed=2100 + i)
            identity = mk_identity_url(f"export{i}.acme")
            key_hash = hashlib.sha256(public_key.to_bytes()).hexdigest()

            keystore.add_key(identity, key_hash, private_key.to_bytes())
            keys_data.append((identity, key_hash, private_key.to_bytes()))

        # Verify export (file should contain all keys)
        with open(keystore_path, 'r') as f:
            exported_data = json.load(f)

        assert exported_data["version"] == FileBackedKeyStore.KEYSTORE_VERSION
        assert len(exported_data["keys"]) == 3

        # Test import by creating new keystore from exported file
        import_path = os.path.join(temp_dir, "imported.json")

        # Copy the exported file
        with open(import_path, 'w') as f:
            json.dump(exported_data, f)

        imported_keystore = FileBackedKeyStore(import_path)

        # Verify all keys were imported correctly
        for identity, key_hash, expected_key in keys_data:
            retrieved_key = imported_keystore.get_key(identity, key_hash)
            assert retrieved_key == expected_key


def test_file_backed_keystore_version_mismatch():
    """Test handling of version mismatch in keystore files."""
    with tempfile.TemporaryDirectory() as temp_dir:
        keystore_path = os.path.join(temp_dir, "version_test.json")

        # Create file with incompatible version
        incompatible_data = {
            "version": "2.0",  # Future version
            "keys": {},
            "metadata": {}
        }

        with open(keystore_path, 'w') as f:
            json.dump(incompatible_data, f)

        # Attempt to load should fail
        with pytest.raises(ValueError, match="Incompatible keystore version"):
            FileBackedKeyStore(keystore_path)


def test_file_backed_keystore_corrupted_file():
    """Test handling of corrupted keystore files."""
    with tempfile.TemporaryDirectory() as temp_dir:
        keystore_path = os.path.join(temp_dir, "corrupted.json")

        # Create corrupted JSON file
        with open(keystore_path, 'w') as f:
            f.write("{ invalid json")

        # Attempt to load should fail
        with pytest.raises(ValueError, match="Failed to load keystore"):
            FileBackedKeyStore(keystore_path)


def test_file_backed_keystore_missing_file():
    """Test file-backed keystore with missing file."""
    with tempfile.TemporaryDirectory() as temp_dir:
        keystore_path = os.path.join(temp_dir, "missing.json")

        # Should create empty keystore
        keystore = FileBackedKeyStore(keystore_path)
        assert len(keystore.list_keys()) == 0

        # Adding key should create file
        private_key, public_key = mk_ed25519_keypair(seed=3001)
        identity = mk_identity_url("missing.acme")
        key_hash = hashlib.sha256(public_key.to_bytes()).hexdigest()

        keystore.add_key(identity, key_hash, private_key.to_bytes())

        assert os.path.exists(keystore_path)


def test_file_backed_keystore_concurrent_access():
    """Test file-backed keystore behavior with multiple instances."""
    with tempfile.TemporaryDirectory() as temp_dir:
        keystore_path = os.path.join(temp_dir, "concurrent.json")

        # Create two keystore instances
        keystore1 = FileBackedKeyStore(keystore_path)
        keystore2 = FileBackedKeyStore(keystore_path)

        # Add key through first instance
        private_key, public_key = mk_ed25519_keypair(seed=4001)
        identity = mk_identity_url("concurrent.acme")
        key_hash = hashlib.sha256(public_key.to_bytes()).hexdigest()

        keystore1.add_key(identity, key_hash, private_key.to_bytes())

        # Second instance should see the key after reload
        keystore2.load()
        retrieved_key = keystore2.get_key(identity, key_hash)
        assert retrieved_key == private_key.to_bytes()


# TODO[ACC-P2-S917]: Add tests for keystore encryption/decryption when implemented
# TODO[ACC-P2-S918]: Add tests for keystore backup and recovery functionality
# TODO[ACC-P2-S919]: Add tests for keystore access control and permissions
# TODO[ACC-P2-S920]: Add tests for keystore migration between versions
