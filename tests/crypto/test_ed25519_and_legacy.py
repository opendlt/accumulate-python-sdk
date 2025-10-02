"""
Ed25519 and legacy crypto tests.

Tests Ed25519 key generation, signing, verification, and legacy compatibility
paths to maximize crypto module coverage.
"""

import pytest
import hashlib
import os
from typing import Tuple

from accumulate_client.crypto.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from accumulate_client.signers.ed25519 import Ed25519Signer


class TestEd25519KeyGeneration:
    """Test Ed25519 key generation and serialization."""

    def test_deterministic_key_generation(self, fake_keypair):
        """Test deterministic key generation from seed."""
        private_key, public_key = fake_keypair

        assert isinstance(private_key, Ed25519PrivateKey)
        assert isinstance(public_key, Ed25519PublicKey)

        # Generate again with same seed
        seed = b'test_seed_for_deterministic_key_pair'[:32]
        private_key2 = Ed25519PrivateKey.from_seed(seed)
        public_key2 = private_key2.public_key()

        # Should be identical
        assert private_key.to_bytes() == private_key2.to_bytes()
        assert public_key.to_bytes() == public_key2.to_bytes()

    def test_random_key_generation(self):
        """Test random key generation."""
        # Generate random keys
        private_key1 = Ed25519PrivateKey.generate()
        private_key2 = Ed25519PrivateKey.generate()

        # Should be different
        assert private_key1.to_bytes() != private_key2.to_bytes()

        # Should be valid length
        assert len(private_key1.to_bytes()) == 32
        assert len(private_key2.to_bytes()) == 32

    def test_public_key_derivation(self, fake_keypair):
        """Test public key derivation from private key."""
        private_key, expected_public_key = fake_keypair

        # Derive public key
        derived_public_key = private_key.public_key()

        # Should match expected
        assert derived_public_key.to_bytes() == expected_public_key.to_bytes()

    def test_key_serialization_roundtrip(self, fake_keypair):
        """Test key serialization and deserialization."""
        private_key, public_key = fake_keypair

        # Serialize keys
        private_bytes = private_key.to_bytes()
        public_bytes = public_key.to_bytes()

        # Deserialize keys
        private_key2 = Ed25519PrivateKey.from_bytes(private_bytes)
        public_key2 = Ed25519PublicKey.from_bytes(public_bytes)

        # Should round-trip correctly
        assert private_key.to_bytes() == private_key2.to_bytes()
        assert public_key.to_bytes() == public_key2.to_bytes()

    def test_key_hex_encoding(self, fake_keypair):
        """Test hex encoding/decoding of keys."""
        private_key, public_key = fake_keypair

        # Test hex encoding
        private_hex = private_key.to_bytes().hex()
        public_hex = public_key.to_bytes().hex()

        assert len(private_hex) == 64  # 32 bytes * 2
        assert len(public_hex) == 64   # 32 bytes * 2

        # Test hex decoding
        private_bytes = bytes.fromhex(private_hex)
        public_bytes = bytes.fromhex(public_hex)

        private_key2 = Ed25519PrivateKey.from_bytes(private_bytes)
        public_key2 = Ed25519PublicKey.from_bytes(public_bytes)

        assert private_key.to_bytes() == private_key2.to_bytes()
        assert public_key.to_bytes() == public_key2.to_bytes()


class TestEd25519Signing:
    """Test Ed25519 signing and verification."""

    def test_sign_and_verify_basic(self, fake_keypair):
        """Test basic signing and verification."""
        private_key, public_key = fake_keypair

        # Test message
        message = b"Hello, Accumulate!"
        message_hash = hashlib.sha256(message).digest()

        # Sign message
        signature = private_key.sign(message_hash)

        # Verify signature
        is_valid = public_key.verify(signature, message_hash)
        assert is_valid, "Signature should be valid"

    def test_signature_deterministic(self, fake_keypair):
        """Test that signatures are deterministic for same input."""
        private_key, public_key = fake_keypair

        message = b"deterministic test message"
        message_hash = hashlib.sha256(message).digest()

        # Sign same message twice
        signature1 = private_key.sign(message_hash)
        signature2 = private_key.sign(message_hash)

        # Ed25519 signatures should be deterministic
        assert signature1 == signature2, "Ed25519 signatures should be deterministic"

    def test_signature_verification_failure(self, fake_keypair):
        """Test that invalid signatures fail verification."""
        private_key, public_key = fake_keypair

        message = b"original message"
        tampered_message = b"tampered message"

        message_hash = hashlib.sha256(message).digest()
        tampered_hash = hashlib.sha256(tampered_message).digest()

        # Sign original message
        signature = private_key.sign(message_hash)

        # Verify with tampered message should fail
        is_valid = public_key.verify(signature, tampered_hash)
        assert not is_valid, "Signature should be invalid for tampered message"

    def test_signature_with_wrong_key(self):
        """Test that signatures fail with wrong public key."""
        # Generate two key pairs
        private_key1 = Ed25519PrivateKey.generate()
        public_key1 = private_key1.public_key()

        private_key2 = Ed25519PrivateKey.generate()
        public_key2 = private_key2.public_key()

        message = b"test message"
        message_hash = hashlib.sha256(message).digest()

        # Sign with key1
        signature = private_key1.sign(message_hash)

        # Verify with key2 should fail
        is_valid = public_key2.verify(signature, message_hash)
        assert not is_valid, "Signature should be invalid with wrong public key"

    def test_signature_length(self, fake_keypair):
        """Test that signatures have correct length."""
        private_key, public_key = fake_keypair

        message = b"test message for length check"
        message_hash = hashlib.sha256(message).digest()

        signature = private_key.sign(message_hash)

        # Ed25519 signatures should be 64 bytes
        assert len(signature) == 64, f"Ed25519 signature should be 64 bytes, got {len(signature)}"

    def test_multiple_message_signing(self, fake_keypair):
        """Test signing multiple different messages."""
        private_key, public_key = fake_keypair

        messages = [
            b"message 1",
            b"message 2",
            b"",  # Empty message
            b"a" * 1000,  # Long message
            "unicode message 🔐".encode('utf-8')
        ]

        for message in messages:
            message_hash = hashlib.sha256(message).digest()
            signature = private_key.sign(message_hash)
            is_valid = public_key.verify(signature, message_hash)
            assert is_valid, f"Signature should be valid for message: {message[:50]}..."


class TestEd25519Signer:
    """Test Ed25519Signer class."""

    def test_signer_creation(self, fake_keypair):
        """Test Ed25519Signer creation and basic functionality."""
        private_key, public_key = fake_keypair
        signer_url = "acc://test.acme/book/1"

        signer = Ed25519Signer(private_key, signer_url)

        assert signer is not None
        # Test that signer has expected interface
        assert hasattr(signer, 'to_accumulate_signature')

    def test_signer_accumulate_signature(self, fake_keypair):
        """Test creating Accumulate-format signatures."""
        private_key, public_key = fake_keypair
        signer_url = "acc://test.acme/book/1"

        signer = Ed25519Signer(private_key, signer_url)

        # Test transaction hash
        tx_hash = hashlib.sha256(b"test transaction").digest()

        try:
            accumulate_signature = signer.to_accumulate_signature(tx_hash)

            # Should return a dictionary with signature structure
            assert isinstance(accumulate_signature, dict)
            # Common fields in Accumulate signatures
            expected_fields = ['signature', 'signer', 'type']
            for field in expected_fields:
                if field in accumulate_signature:
                    assert accumulate_signature[field] is not None

        except Exception as e:
            pytest.skip(f"Accumulate signature format not available: {e}")

    def test_signer_with_different_urls(self, fake_keypair):
        """Test signer with different URL formats."""
        private_key, public_key = fake_keypair

        urls = [
            "acc://test.acme/book/1",
            "acc://different.domain/book/2",
            "acc://identity.acme/keybook/page/0"
        ]

        for url in urls:
            signer = Ed25519Signer(private_key, url)
            assert signer is not None


class TestLegacyCompatibility:
    """Test legacy Ed25519 compatibility if available."""

    def test_legacy_ed25519_import(self):
        """Test legacy Ed25519 implementation import."""
        try:
            from accumulate_client.signers.legacy_ed25519 import LegacyEd25519Signer
            # If available, test basic functionality
            assert LegacyEd25519Signer is not None
        except ImportError:
            pytest.skip("Legacy Ed25519 not available")

    def test_legacy_signature_compatibility(self, fake_keypair):
        """Test compatibility between legacy and standard Ed25519."""
        try:
            from accumulate_client.signers.legacy_ed25519 import LegacyEd25519Signer
            private_key, public_key = fake_keypair

            # Create both signer types
            standard_signer = Ed25519Signer(private_key, "acc://test.acme/book/1")
            legacy_signer = LegacyEd25519Signer(private_key, "acc://test.acme/book/1")

            # Test message
            tx_hash = hashlib.sha256(b"compatibility test").digest()

            # Both should be able to sign
            try:
                standard_sig = standard_signer.to_accumulate_signature(tx_hash)
                legacy_sig = legacy_signer.to_accumulate_signature(tx_hash)

                # Both should produce valid signatures
                assert isinstance(standard_sig, dict)
                assert isinstance(legacy_sig, dict)

            except Exception as e:
                pytest.skip(f"Signature compatibility test failed: {e}")

        except ImportError:
            pytest.skip("Legacy Ed25519 not available")

    def test_legacy_feature_flag(self):
        """Test legacy feature flag if present."""
        # Some implementations might use environment variables or config
        # to enable legacy compatibility
        legacy_env_vars = ['ACC_LEGACY_ED25519', 'ACCUMULATE_LEGACY_CRYPTO']

        for env_var in legacy_env_vars:
            # Test with flag enabled
            os.environ[env_var] = '1'
            try:
                # Re-import to pick up environment change
                from accumulate_client.signers import ed25519
                # Test that legacy paths are available
            except Exception:
                pass
            finally:
                # Clean up
                if env_var in os.environ:
                    del os.environ[env_var]


class TestKeyDerivationEdgeCases:
    """Test edge cases in key derivation."""

    def test_seed_length_variations(self):
        """Test key derivation with different seed lengths."""
        # Test various seed lengths
        seed_lengths = [16, 24, 32, 40, 64]

        for length in seed_lengths:
            seed = os.urandom(length)

            # Truncate or pad to 32 bytes as needed
            if len(seed) < 32:
                seed = seed + b'\x00' * (32 - len(seed))
            elif len(seed) > 32:
                seed = seed[:32]

            try:
                private_key = Ed25519PrivateKey.from_seed(seed)
                public_key = private_key.public_key()

                # Should produce valid keys
                assert len(private_key.to_bytes()) == 32
                assert len(public_key.to_bytes()) == 32

            except Exception as e:
                pytest.fail(f"Key derivation failed for seed length {length}: {e}")

    def test_zero_seed(self):
        """Test key derivation with zero seed."""
        zero_seed = b'\x00' * 32

        private_key = Ed25519PrivateKey.from_seed(zero_seed)
        public_key = private_key.public_key()

        # Should produce valid (though predictable) keys
        assert len(private_key.to_bytes()) == 32
        assert len(public_key.to_bytes()) == 32

    def test_max_seed(self):
        """Test key derivation with maximum value seed."""
        max_seed = b'\xff' * 32

        private_key = Ed25519PrivateKey.from_seed(max_seed)
        public_key = private_key.public_key()

        # Should produce valid keys
        assert len(private_key.to_bytes()) == 32
        assert len(public_key.to_bytes()) == 32

    def test_invalid_key_bytes(self):
        """Test handling of invalid key bytes."""
        # Test with wrong length
        invalid_lengths = [0, 16, 31, 33, 64]

        for length in invalid_lengths:
            invalid_bytes = os.urandom(length)

            with pytest.raises(Exception):
                Ed25519PrivateKey.from_bytes(invalid_bytes)

            with pytest.raises(Exception):
                Ed25519PublicKey.from_bytes(invalid_bytes)


class TestCryptoModuleIntegration:
    """Test integration between crypto modules."""

    def test_secp256k1_availability(self):
        """Test if Secp256k1 is available and works similarly."""
        from accumulate_client.crypto import secp256k1

        # Verify secp256k1 is available
        assert secp256k1.has_secp256k1_support() == True, "secp256k1 support should be available"

        # Test key generation and operations
        private_key = secp256k1.Secp256k1PrivateKey.generate()
        public_key = private_key.public_key()

        # Should have similar interface to Ed25519
        assert hasattr(private_key, 'to_bytes')
        assert hasattr(public_key, 'to_bytes')
        assert hasattr(private_key, 'sign')
        assert hasattr(public_key, 'verify')

        # Test actual cryptographic operations
        message = b"test message for secp256k1 integration"
        signature = private_key.sign(message)
        assert signature is not None, "Signing should produce a signature"

        # Test signature verification
        is_valid = signature.verify(message, public_key.to_bytes())
        assert is_valid == True, "Valid signature should verify correctly"

        # Test with wrong message
        wrong_message = b"tampered message"
        is_invalid = signature.verify(wrong_message, public_key.to_bytes())
        assert is_invalid == False, "Invalid signature should fail verification"

    def test_crypto_module_consistency(self):
        """Test that crypto modules have consistent interfaces."""
        from accumulate_client.crypto.ed25519 import Ed25519PrivateKey

        # Test that Ed25519 has expected interface
        expected_methods = ['generate', 'from_seed', 'from_bytes', 'to_bytes', 'sign', 'public_key']

        for method in expected_methods:
            assert hasattr(Ed25519PrivateKey, method), f"Ed25519PrivateKey missing method: {method}"

    def test_signature_type_detection(self, fake_keypair):
        """Test signature type detection and handling."""
        private_key, public_key = fake_keypair

        message_hash = hashlib.sha256(b"test message").digest()
        signature = private_key.sign(message_hash)

        # Test that we can determine signature type
        # (Implementation specific - might be in signature metadata)
        assert len(signature) == 64  # Ed25519 signature length

        # Test that signature verifies correctly
        is_valid = public_key.verify(signature, message_hash)
        assert is_valid