#!/usr/bin/env python3

"""Negative tests and edge cases for ed25519.py to achieve ≥92% coverage"""

import hashlib

import pytest
from cryptography.hazmat.primitives.asymmetric import ed25519

from accumulate_client.crypto.ed25519 import Ed25519KeyPair, keypair_from_seed, verify_ed25519


class TestEd25519KeyPairNegatives:
    """Test negative cases and edge conditions for Ed25519KeyPair"""

    def test_init_with_valid_private_key(self):
        """Test normal initialization"""
        private_key = ed25519.Ed25519PrivateKey.generate()
        keypair = Ed25519KeyPair(private_key)

        assert keypair._private_key == private_key
        assert keypair._public_key is not None

    def test_generate_creates_unique_keypairs(self):
        """Test that generate() creates unique keypairs"""
        kp1 = Ed25519KeyPair.generate()
        kp2 = Ed25519KeyPair.generate()

        # Should be different keypairs
        assert kp1.public_key_bytes() != kp2.public_key_bytes()
        assert kp1.private_key_bytes() != kp2.private_key_bytes()

    def test_from_seed_valid_seed(self):
        """Test from_seed with valid 32-byte seeds"""
        # Test with zero seed
        zero_seed = b"\x00" * 32
        kp1 = Ed25519KeyPair.from_seed(zero_seed)
        assert len(kp1.public_key_bytes()) == 32
        assert len(kp1.private_key_bytes()) == 32

        # Test with max seed
        max_seed = b"\xff" * 32
        kp2 = Ed25519KeyPair.from_seed(max_seed)
        assert len(kp2.public_key_bytes()) == 32

        # Different seeds should produce different keypairs
        assert kp1.public_key_bytes() != kp2.public_key_bytes()

    def test_from_seed_deterministic(self):
        """Test that from_seed is deterministic"""
        seed = b"this is a 32 byte seed for test!"
        assert len(seed) == 32

        kp1 = Ed25519KeyPair.from_seed(seed)
        kp2 = Ed25519KeyPair.from_seed(seed)

        # Same seed should produce same keypair
        assert kp1.public_key_bytes() == kp2.public_key_bytes()
        assert kp1.private_key_bytes() == kp2.private_key_bytes()

    def test_from_seed_invalid_lengths(self):
        """Test from_seed with invalid seed lengths"""
        # Test too short
        with pytest.raises(ValueError, match="Seed must be exactly 32 bytes"):
            Ed25519KeyPair.from_seed(b"short")

        # Test too long
        with pytest.raises(ValueError, match="Seed must be exactly 32 bytes"):
            Ed25519KeyPair.from_seed(b"x" * 33)

        # Test empty
        with pytest.raises(ValueError, match="Seed must be exactly 32 bytes"):
            Ed25519KeyPair.from_seed(b"")

        # Test close but wrong lengths
        for length in [31, 33, 16, 64]:
            with pytest.raises(ValueError, match="Seed must be exactly 32 bytes"):
                Ed25519KeyPair.from_seed(b"x" * length)

    def test_public_key_bytes_format(self):
        """Test public_key_bytes returns correct format"""
        kp = Ed25519KeyPair.generate()
        pub_bytes = kp.public_key_bytes()

        assert isinstance(pub_bytes, bytes)
        assert len(pub_bytes) == 32

    def test_private_key_bytes_format(self):
        """Test private_key_bytes returns correct format"""
        kp = Ed25519KeyPair.generate()
        priv_bytes = kp.private_key_bytes()

        assert isinstance(priv_bytes, bytes)
        assert len(priv_bytes) == 32

    def test_sign_various_messages(self):
        """Test signing with various message types"""
        kp = Ed25519KeyPair.generate()

        # Test empty message
        sig = kp.sign(b"")
        assert len(sig) == 64
        assert isinstance(sig, bytes)

        # Test single byte
        sig = kp.sign(b"a")
        assert len(sig) == 64

        # Test small message
        sig = kp.sign(b"hello")
        assert len(sig) == 64

        # Test large message
        large_msg = b"x" * 10000
        sig = kp.sign(large_msg)
        assert len(sig) == 64

        # Test binary data
        binary_data = bytes(range(256))
        sig = kp.sign(binary_data)
        assert len(sig) == 64

    def test_sign_deterministic(self):
        """Test that signing is deterministic for same message"""
        seed = b"deterministic seed for testing!!"
        kp = Ed25519KeyPair.from_seed(seed)
        message = b"test message"

        sig1 = kp.sign(message)
        sig2 = kp.sign(message)

        # Same message with same key should produce same signature
        assert sig1 == sig2

    def test_verify_valid_signatures(self):
        """Test verify with valid signatures"""
        kp = Ed25519KeyPair.generate()
        message = b"test message for verification"

        signature = kp.sign(message)

        # Should verify correctly
        assert kp.verify(message, signature) is True

    def test_verify_invalid_signatures(self):
        """Test verify with invalid signatures"""
        kp = Ed25519KeyPair.generate()
        message = b"test message"
        signature = kp.sign(message)

        # Wrong message
        assert kp.verify(b"wrong message", signature) is False

        # Wrong signature (corrupted)
        corrupted_sig = signature[:-1] + b"\x00"
        assert kp.verify(message, corrupted_sig) is False

        # Completely wrong signature
        wrong_sig = b"\x00" * 64
        assert kp.verify(message, wrong_sig) is False

        # Wrong signature length
        short_sig = signature[:32]
        assert kp.verify(message, short_sig) is False

        # Too long signature
        long_sig = signature + b"\x00"
        assert kp.verify(message, long_sig) is False

    def test_verify_cross_keypair(self):
        """Test verify with signatures from different keypairs"""
        kp1 = Ed25519KeyPair.generate()
        kp2 = Ed25519KeyPair.generate()

        message = b"test message"
        sig1 = kp1.sign(message)

        # kp2 should not verify signature from kp1
        assert kp2.verify(message, sig1) is False

    def test_derive_lite_identity_url_format(self):
        """Test derive_lite_identity_url format and consistency"""
        kp = Ed25519KeyPair.generate()
        lid = kp.derive_lite_identity_url()

        # Check format
        assert lid.startswith("acc://")
        assert len(lid) == len("acc://") + 40 + 8  # acc:// + 40 hex chars + 8 checksum chars

        # Should be deterministic
        lid2 = kp.derive_lite_identity_url()
        assert lid == lid2

    def test_derive_lite_identity_url_components(self):
        """Test derive_lite_identity_url internal components"""
        # Use deterministic seed for reproducible test
        seed = b"0123456789abcdef0123456789abcdef"  # Exactly 32 bytes
        kp = Ed25519KeyPair.from_seed(seed)

        lid = kp.derive_lite_identity_url()

        # Verify format
        assert lid.startswith("acc://")
        url_part = lid[6:]  # Remove 'acc://'
        assert len(url_part) == 48  # 40 hex + 8 checksum

        # Verify it's all hex
        assert all(c in "0123456789abcdef" for c in url_part)

    def test_derive_lite_identity_url_uniqueness(self):
        """Test that different keypairs produce different LIDs"""
        kp1 = Ed25519KeyPair.generate()
        kp2 = Ed25519KeyPair.generate()

        lid1 = kp1.derive_lite_identity_url()
        lid2 = kp2.derive_lite_identity_url()

        assert lid1 != lid2

    def test_derive_lite_token_account_url_default(self):
        """Test derive_lite_token_account_url with default token"""
        kp = Ed25519KeyPair.generate()
        lta = kp.derive_lite_token_account_url()
        lid = kp.derive_lite_identity_url()

        # Should be LID + "/ACME"
        assert lta == f"{lid}/ACME"
        assert lta.endswith("/ACME")

    def test_derive_lite_token_account_url_custom_tokens(self):
        """Test derive_lite_token_account_url with various tokens"""
        kp = Ed25519KeyPair.generate()
        lid = kp.derive_lite_identity_url()

        # Test various token names
        tokens = ["ACME", "USD", "BTC", "ETH", "CustomToken123", ""]

        for token in tokens:
            lta = kp.derive_lite_token_account_url(token)
            assert lta == f"{lid}/{token}"

    def test_derive_lite_token_account_url_special_characters(self):
        """Test derive_lite_token_account_url with special characters"""
        kp = Ed25519KeyPair.generate()
        lid = kp.derive_lite_identity_url()

        # Test special characters in token names
        special_tokens = ["TOKEN-1", "TOKEN_2", "TOKEN.3", "TOKEN@4"]

        for token in special_tokens:
            lta = kp.derive_lite_token_account_url(token)
            assert lta == f"{lid}/{token}"


class TestStandaloneFunctionsNegatives:
    """Test negative cases for standalone functions"""

    def test_verify_ed25519_valid_signature(self):
        """Test verify_ed25519 with valid signature"""
        kp = Ed25519KeyPair.generate()
        message = b"test message"
        signature = kp.sign(message)
        pub_key_bytes = kp.public_key_bytes()

        assert verify_ed25519(pub_key_bytes, signature, message) is True

    def test_verify_ed25519_invalid_public_key(self):
        """Test verify_ed25519 with invalid public keys"""
        kp = Ed25519KeyPair.generate()
        message = b"test message"
        signature = kp.sign(message)

        # Wrong public key length
        assert verify_ed25519(b"short", signature, message) is False
        assert verify_ed25519(b"x" * 31, signature, message) is False
        assert verify_ed25519(b"x" * 33, signature, message) is False

        # Wrong public key data
        wrong_pub = b"\x00" * 32
        assert verify_ed25519(wrong_pub, signature, message) is False

    def test_verify_ed25519_invalid_signature(self):
        """Test verify_ed25519 with invalid signatures"""
        kp = Ed25519KeyPair.generate()
        message = b"test message"
        pub_key_bytes = kp.public_key_bytes()

        # Wrong signature length
        assert verify_ed25519(pub_key_bytes, b"short", message) is False
        assert verify_ed25519(pub_key_bytes, b"x" * 63, message) is False
        assert verify_ed25519(pub_key_bytes, b"x" * 65, message) is False

        # Wrong signature data
        wrong_sig = b"\x00" * 64
        assert verify_ed25519(pub_key_bytes, wrong_sig, message) is False

    def test_verify_ed25519_wrong_message(self):
        """Test verify_ed25519 with wrong message"""
        kp = Ed25519KeyPair.generate()
        message = b"test message"
        signature = kp.sign(message)
        pub_key_bytes = kp.public_key_bytes()

        # Wrong message
        assert verify_ed25519(pub_key_bytes, signature, b"wrong message") is False
        assert verify_ed25519(pub_key_bytes, signature, b"") is False

    def test_verify_ed25519_exception_handling(self):
        """Test verify_ed25519 exception handling"""
        # Test with completely invalid data that might cause exceptions
        invalid_data = b"not a valid key or signature"

        # Should return False, not raise exception
        assert verify_ed25519(invalid_data, invalid_data, b"message") is False

    def test_keypair_from_seed_valid(self):
        """Test keypair_from_seed with valid seed"""
        seed = b"this is a test seed for keypair!"

        priv_bytes, pub_bytes = keypair_from_seed(seed)

        assert isinstance(priv_bytes, bytes)
        assert isinstance(pub_bytes, bytes)
        assert len(priv_bytes) == 32
        assert len(pub_bytes) == 32

    def test_keypair_from_seed_deterministic(self):
        """Test keypair_from_seed is deterministic"""
        seed = b"deterministic seed for testing!!"

        priv1, pub1 = keypair_from_seed(seed)
        priv2, pub2 = keypair_from_seed(seed)

        assert priv1 == priv2
        assert pub1 == pub2

    def test_keypair_from_seed_matches_class(self):
        """Test keypair_from_seed matches Ed25519KeyPair.from_seed"""
        seed = b"fedcba9876543210fedcba9876543210"  # Exactly 32 bytes

        priv_func, pub_func = keypair_from_seed(seed)

        kp = Ed25519KeyPair.from_seed(seed)
        priv_class = kp.private_key_bytes()
        pub_class = kp.public_key_bytes()

        assert priv_func == priv_class
        assert pub_func == pub_class

    def test_keypair_from_seed_invalid_lengths(self):
        """Test keypair_from_seed with invalid seed lengths"""
        # Should raise ValueError for wrong lengths (delegated to Ed25519KeyPair.from_seed)
        with pytest.raises(ValueError, match="Seed must be exactly 32 bytes"):
            keypair_from_seed(b"short")

        with pytest.raises(ValueError, match="Seed must be exactly 32 bytes"):
            keypair_from_seed(b"x" * 31)

        with pytest.raises(ValueError, match="Seed must be exactly 32 bytes"):
            keypair_from_seed(b"x" * 33)


class TestIntegrationAndEdgeCases:
    """Test integration scenarios and edge cases"""

    def test_full_signing_verification_flow(self):
        """Test complete signing and verification flow"""
        # Generate keypair
        kp = Ed25519KeyPair.generate()

        # Create message
        message = b"Important transaction data"

        # Sign message
        signature = kp.sign(message)

        # Verify with instance method
        assert kp.verify(message, signature) is True

        # Verify with standalone function
        pub_bytes = kp.public_key_bytes()
        assert verify_ed25519(pub_bytes, signature, message) is True

    def test_url_derivation_consistency(self):
        """Test URL derivation consistency across methods"""
        seed = b"consistency test seed for urls!!"
        kp = Ed25519KeyPair.from_seed(seed)

        # Multiple calls should be consistent
        lid1 = kp.derive_lite_identity_url()
        lid2 = kp.derive_lite_identity_url()
        assert lid1 == lid2

        lta1 = kp.derive_lite_token_account_url("ACME")
        lta2 = kp.derive_lite_token_account_url("ACME")
        assert lta1 == lta2

        # LTA should be LID + token
        assert lta1 == f"{lid1}/ACME"

    def test_key_derivation_algorithm_steps(self):
        """Test individual steps of key derivation algorithm"""
        seed = b"algorithm test seed for verify!!"
        kp = Ed25519KeyPair.from_seed(seed)

        # Get public key
        pub_key = kp.public_key_bytes()
        assert len(pub_key) == 32

        # Step 1: SHA256 of public key
        key_hash_full = hashlib.sha256(pub_key).digest()
        assert len(key_hash_full) == 32

        # Step 2: Take first 20 bytes
        key_hash_20 = key_hash_full[:20]
        assert len(key_hash_20) == 20

        # Step 3: Convert to hex
        key_str = key_hash_20.hex()
        assert len(key_str) == 40

        # Step 4: Calculate checksum
        checksum_full = hashlib.sha256(key_str.encode("utf-8")).digest()
        checksum = checksum_full[28:].hex()
        assert len(checksum) == 8

        # Step 5: Verify final URL
        expected_lid = f"acc://{key_str}{checksum}"
        actual_lid = kp.derive_lite_identity_url()
        assert actual_lid == expected_lid

    def test_signature_roundtrip_with_different_messages(self):
        """Test signature roundtrip with various message types"""
        kp = Ed25519KeyPair.generate()

        test_messages = [
            b"",  # Empty
            b"a",  # Single character
            b"Hello, World!",  # Text
            b"\x00\x01\x02\x03",  # Binary
            b"Unicode: \xe2\x9c\x93",  # UTF-8
            b"x" * 1000,  # Large message
            bytes(range(256)),  # All byte values
        ]

        for message in test_messages:
            signature = kp.sign(message)
            assert kp.verify(message, signature) is True

            # Also test with standalone function
            pub_bytes = kp.public_key_bytes()
            assert verify_ed25519(pub_bytes, signature, message) is True

    def test_cross_implementation_compatibility(self):
        """Test compatibility patterns expected by other implementations"""
        # Test known seed for cross-implementation testing
        seed = bytes.fromhex("0123456789abcdef" * 4)  # 32 bytes
        kp = Ed25519KeyPair.from_seed(seed)

        # Should produce consistent results
        pub_bytes = kp.public_key_bytes()
        priv_bytes = kp.private_key_bytes()

        assert len(pub_bytes) == 32
        assert len(priv_bytes) == 32

        # Test signing with known message
        message = b"cross-implementation test message"
        signature = kp.sign(message)

        assert len(signature) == 64
        assert kp.verify(message, signature) is True

    def test_error_boundaries(self):
        """Test error handling at boundaries"""
        kp = Ed25519KeyPair.generate()

        # Test with maximum size inputs that shouldn't cause issues
        large_message = b"x" * (2**20)  # 1MB message
        signature = kp.sign(large_message)
        assert kp.verify(large_message, signature) is True

        # Test verify with clearly invalid inputs doesn't crash
        assert kp.verify(b"msg", b"") is False
        assert kp.verify(b"", b"x" * 64) is False
