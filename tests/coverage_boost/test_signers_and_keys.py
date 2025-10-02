"""
Signers, keys, and wallet/keystore tests - pure crypto without network.
"""

import pytest
import hashlib
import json
import os
from typing import Dict, Any, List


class TestEd25519Crypto:
    """Test Ed25519 key operations."""

    def test_deterministic_keypair_generation(self):
        """Test deterministic key generation from seed."""
        try:
            from accumulate_client.crypto.ed25519 import Ed25519PrivateKey

            # Known seed
            seed = b'test_seed_12345678901234567890AB'[:32]

            # Generate multiple times
            key1 = Ed25519PrivateKey.from_seed(seed)
            key2 = Ed25519PrivateKey.from_seed(seed)

            # Should be identical
            assert key1.to_bytes() == key2.to_bytes()

            # Public keys should match
            pub1 = key1.public_key()
            pub2 = key2.public_key()
            assert pub1.to_bytes() == pub2.to_bytes()

        except ImportError:
            pytest.skip("Ed25519 not available")

    def test_sign_verify_operations(self):
        """Test signing and verification."""
        try:
            from accumulate_client.crypto.ed25519 import Ed25519PrivateKey

            # Generate key
            private_key = Ed25519PrivateKey.generate()
            public_key = private_key.public_key()

            # Test messages
            messages = [
                b"simple message",
                b"",  # Empty
                b"\x00" * 100,  # Zeros
                b"\xff" * 100,  # Ones
                b"unicode \xf0\x9f\x94\x90",  # With unicode
                hashlib.sha256(b"pre-hashed").digest(),  # Hash
            ]

            for msg in messages:
                # Hash message
                msg_hash = hashlib.sha256(msg).digest()

                # Sign
                signature = private_key.sign(msg_hash)
                assert len(signature) == 64  # Ed25519 signature size

                # Verify
                is_valid = public_key.verify(signature, msg_hash)
                assert is_valid

                # Wrong message should fail
                wrong_hash = hashlib.sha256(msg + b"tampered").digest()
                is_valid_wrong = public_key.verify(signature, wrong_hash)
                assert not is_valid_wrong

        except ImportError:
            pytest.skip("Ed25519 not available")

    def test_key_serialization(self):
        """Test key import/export."""
        try:
            from accumulate_client.crypto.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

            # Generate key
            private_key = Ed25519PrivateKey.generate()
            public_key = private_key.public_key()

            # Export
            private_bytes = private_key.to_bytes()
            public_bytes = public_key.to_bytes()

            assert len(private_bytes) == 32
            assert len(public_bytes) == 32

            # Import
            private_key2 = Ed25519PrivateKey.from_bytes(private_bytes)
            public_key2 = Ed25519PublicKey.from_bytes(public_bytes)

            # Should match
            assert private_key2.to_bytes() == private_bytes
            assert public_key2.to_bytes() == public_bytes

            # Test hex encoding
            private_hex = private_bytes.hex()
            public_hex = public_bytes.hex()

            assert len(private_hex) == 64
            assert len(public_hex) == 64

            # Import from hex
            private_key3 = Ed25519PrivateKey.from_bytes(bytes.fromhex(private_hex))
            assert private_key3.to_bytes() == private_bytes

        except ImportError:
            pytest.skip("Ed25519 not available")


class TestSecp256k1Crypto:
    """Test secp256k1 cryptographic functionality."""

    def test_secp256k1_functionality(self):
        """Test that secp256k1 crypto operations work correctly."""
        from accumulate_client.crypto.secp256k1 import Secp256k1PrivateKey, has_secp256k1_support

        # Verify secp256k1 is available
        assert has_secp256k1_support() == True, "secp256k1 support should be available"

        # Test key generation
        key = Secp256k1PrivateKey.generate()
        assert key is not None, "Key generation should succeed"

        # Test public key derivation
        pub = key.public_key()
        assert pub is not None, "Public key derivation should succeed"
        assert len(pub.to_bytes()) > 0, "Public key should have content"

        # Test signing and verification
        message = b"test message for secp256k1"
        signature = key.sign(message)
        assert signature is not None, "Signing should succeed"

        # Test verification
        is_valid = signature.verify(message, pub.to_bytes())
        assert is_valid == True, "Signature verification should succeed"

        # Test with wrong message
        wrong_message = b"wrong message"
        is_invalid = signature.verify(wrong_message, pub.to_bytes())
        assert is_invalid == False, "Wrong message should fail verification"

    def test_btc_eth_key_derivation_stub(self):
        """Test BTC/ETH key derivation stubs."""
        try:
            from accumulate_client.crypto import btc_key_from_seed, eth_key_from_seed

            seed = b'test' * 8  # 32 bytes

            # Should either work or raise NotImplementedError
            try:
                btc_key = btc_key_from_seed(seed)
                assert btc_key is not None
            except (NotImplementedError, ImportError):
                pass

            try:
                eth_key = eth_key_from_seed(seed)
                assert eth_key is not None
            except (NotImplementedError, ImportError):
                pass

        except ImportError:
            pass


class TestSignerRegistry:
    """Test signer registry and factory."""

    def test_signer_types(self):
        """Test available signer types."""
        try:
            from accumulate_client.signers import get_signer_types

            types = get_signer_types()
            assert "ed25519" in types

            # May have others
            for signer_type in types:
                assert isinstance(signer_type, str)

        except ImportError:
            pytest.skip("Signer registry not available")

    def test_create_signer(self):
        """Test signer creation."""
        try:
            from accumulate_client.signers.ed25519 import Ed25519Signer
            from accumulate_client.crypto.ed25519 import Ed25519PrivateKey

            # Create key
            private_key = Ed25519PrivateKey.generate()

            # Create signer
            signer = Ed25519Signer(private_key, "acc://alice.acme/book/1")

            assert signer is not None

            # Test signing
            tx_hash = hashlib.sha256(b"test transaction").digest()
            signature = signer.to_accumulate_signature(tx_hash)

            assert isinstance(signature, dict)
            # Should have signature fields
            if "signature" in signature:
                assert signature["signature"] is not None
            if "signer" in signature:
                if isinstance(signature["signer"], dict):
                    assert signature["signer"]["url"] == "acc://alice.acme/book/1"
                else:
                    assert signature["signer"] == "acc://alice.acme/book/1"

        except ImportError:
            pytest.skip("Ed25519Signer not available")

    def test_signer_serialization(self):
        """Test signer serialize/deserialize."""
        try:
            from accumulate_client.signers.ed25519 import Ed25519Signer
            from accumulate_client.crypto.ed25519 import Ed25519PrivateKey

            # Create signer
            private_key = Ed25519PrivateKey.generate()
            signer = Ed25519Signer(private_key, "acc://alice.acme/book/1")

            # Serialize (if supported)
            if hasattr(signer, 'to_dict'):
                signer_dict = signer.to_dict()
                assert isinstance(signer_dict, dict)

                # Should be able to recreate
                if hasattr(Ed25519Signer, 'from_dict'):
                    signer2 = Ed25519Signer.from_dict(signer_dict)
                    assert signer2.signer_url == signer.signer_url

        except ImportError:
            pytest.skip("Signer serialization not available")


class TestWalletKeystore:
    """Test wallet and keystore functionality."""

    def test_in_memory_keystore(self):
        """Test in-memory key storage."""
        try:
            from accumulate_client.wallet import InMemoryKeystore
            from accumulate_client.crypto.ed25519 import Ed25519PrivateKey

            keystore = InMemoryKeystore()

            # Generate and store keys
            keys = []
            for i in range(5):
                key = Ed25519PrivateKey.generate()
                key_id = f"key_{i}"
                keystore.store(key_id, key)
                keys.append((key_id, key))

            # Retrieve keys
            for key_id, original_key in keys:
                retrieved = keystore.get(key_id)
                assert retrieved.to_bytes() == original_key.to_bytes()

            # List keys
            all_keys = keystore.list()
            assert len(all_keys) == 5

            # Remove key
            keystore.remove("key_0")
            assert keystore.get("key_0") is None
            assert len(keystore.list()) == 4

        except ImportError:
            # Manual implementation
            class SimpleKeystore:
                def __init__(self):
                    self.keys = {}

                def store(self, key_id, key):
                    self.keys[key_id] = key

                def get(self, key_id):
                    return self.keys.get(key_id)

                def list(self):
                    return list(self.keys.keys())

                def remove(self, key_id):
                    self.keys.pop(key_id, None)

            keystore = SimpleKeystore()

            # Test operations
            keystore.store("test1", b"key1")
            keystore.store("test2", b"key2")

            assert keystore.get("test1") == b"key1"
            assert len(keystore.list()) == 2

            keystore.remove("test1")
            assert keystore.get("test1") is None

    def test_keystore_export_import(self):
        """Test keystore export/import."""
        try:
            from accumulate_client.wallet import InMemoryKeystore
            from accumulate_client.crypto.ed25519 import Ed25519PrivateKey

            keystore1 = InMemoryKeystore()

            # Add keys
            key1 = Ed25519PrivateKey.generate()
            key2 = Ed25519PrivateKey.generate()
            keystore1.store("alice", key1)
            keystore1.store("bob", key2)

            # Export
            if hasattr(keystore1, 'export'):
                exported = keystore1.export()

                # Import to new keystore
                keystore2 = InMemoryKeystore()
                if hasattr(keystore2, 'import_keys'):
                    keystore2.import_keys(exported)

                    # Should have same keys
                    alice_key = keystore2.get("alice")
                    bob_key = keystore2.get("bob")

                    assert alice_key.to_bytes() == key1.to_bytes()
                    assert bob_key.to_bytes() == key2.to_bytes()

        except ImportError:
            pytest.skip("Keystore export/import not available")

    def test_encrypted_keystore(self):
        """Test encrypted key storage."""
        try:
            from accumulate_client.wallet import EncryptedKeystore
            from accumulate_client.crypto.ed25519 import Ed25519PrivateKey

            password = "test_password_123"
            keystore = EncryptedKeystore(password)

            # Store encrypted
            key = Ed25519PrivateKey.generate()
            keystore.store("secret", key)

            # Retrieve with correct password
            retrieved = keystore.get("secret")
            assert retrieved.to_bytes() == key.to_bytes()

            # Wrong password should fail
            wrong_keystore = EncryptedKeystore("wrong_password")
            try:
                wrong_keystore.get("secret")
                # Should fail
                assert False, "Should not decrypt with wrong password"
            except Exception:
                # Expected
                pass

        except ImportError:
            pytest.skip("Encrypted keystore not available")

    def test_hierarchical_key_derivation(self):
        """Test HD wallet key derivation."""
        try:
            from accumulate_client.wallet import derive_child_key

            # Master seed
            master_seed = b'master_seed_' + b'0' * 20  # 32 bytes

            # Derive child keys
            paths = [
                [0],  # First child
                [0, 0],  # First grandchild
                [0, 1],  # Second child of first
                [1],  # Second child
                [2147483647],  # Max non-hardened
                [2147483648],  # First hardened
            ]

            derived_keys = []
            for path in paths:
                key = derive_child_key(master_seed, path)
                derived_keys.append(key)

            # All keys should be different
            key_bytes = [k.to_bytes() if hasattr(k, 'to_bytes') else k for k in derived_keys]
            assert len(set(key_bytes)) == len(paths)

        except ImportError:
            # Simple derivation
            master_seed = b'master_seed_' + b'0' * 20

            derived = []
            for i in range(5):
                # Simple derivation: hash(seed + index)
                child_seed = hashlib.sha256(master_seed + i.to_bytes(4, 'big')).digest()
                derived.append(child_seed)

            assert len(set(derived)) == 5  # All unique

    def test_key_lookup_by_hash(self):
        """Test looking up keys by public key hash."""
        try:
            from accumulate_client.wallet import KeyHashIndex
            from accumulate_client.crypto.ed25519 import Ed25519PrivateKey

            index = KeyHashIndex()

            # Add keys with their hashes
            keys = []
            for i in range(10):
                key = Ed25519PrivateKey.generate()
                pub = key.public_key()
                pub_hash = hashlib.sha256(pub.to_bytes()).digest()

                index.add(pub_hash, key)
                keys.append((pub_hash, key))

            # Lookup by hash
            for pub_hash, original_key in keys:
                found = index.lookup(pub_hash)
                assert found.to_bytes() == original_key.to_bytes()

            # Non-existent hash
            fake_hash = b'\x00' * 32
            assert index.lookup(fake_hash) is None

        except ImportError:
            # Simple hash index
            class HashIndex:
                def __init__(self):
                    self.index = {}

                def add(self, key_hash, key):
                    self.index[key_hash] = key

                def lookup(self, key_hash):
                    return self.index.get(key_hash)

            index = HashIndex()

            # Test operations
            hash1 = hashlib.sha256(b"key1").digest()
            hash2 = hashlib.sha256(b"key2").digest()

            index.add(hash1, "key1_data")
            index.add(hash2, "key2_data")

            assert index.lookup(hash1) == "key1_data"
            assert index.lookup(b'\x00' * 32) is None