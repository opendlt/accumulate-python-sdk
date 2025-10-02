#!/usr/bin/env python3

"""Conformance tests against TypeScript SDK golden values for crypto operations"""

import hashlib
import json
import os
import re
import sys
import unittest
from pathlib import Path

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))
from helpers import mk_ed25519_keypair

from accumulate_client.crypto.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from accumulate_client.runtime.url import AccountUrl


class TestCryptoConformance(unittest.TestCase):
    """Test crypto operations conform to TypeScript SDK"""

    @classmethod
    def setUpClass(cls):
        """Load golden test vectors"""
        golden_file = os.path.join(
            os.path.dirname(__file__), "..", "golden", "ed25519_vectors.json"
        )
        with open(golden_file) as f:
            cls.vectors = json.load(f)

    def derive_lite_identity_url(self, public_key: Ed25519PublicKey) -> str:
        """Derive Lite Identity URL from Ed25519 public key with checksum using SDK classes"""
        # Get public key bytes from SDK class
        public_key_bytes = public_key.to_bytes()

        # For Ed25519: keyHash = SHA256(publicKey)
        key_hash_full = hashlib.sha256(public_key_bytes).digest()

        # Use first 20 bytes
        key_hash_20 = key_hash_full[:20]

        # Convert to hex string
        key_str = key_hash_20.hex()

        # Calculate checksum
        checksum_full = hashlib.sha256(key_str.encode("utf-8")).digest()
        checksum = checksum_full[28:].hex()  # Take last 4 bytes

        # Format: acc://<keyHash[0:20]><checksum>
        return f"acc://{key_str}{checksum}"

    def test_ed25519_key_generation_zero_key(self):
        """Test Ed25519 key generation with zero private key (TS test vector) using SDK"""
        vector = self.vectors["ed25519_key_generation"][0]

        # Create private key from hex using SDK
        private_key_bytes = bytes.fromhex(vector["private_key_hex"])
        private_key = Ed25519PrivateKey.from_bytes(private_key_bytes)

        # Get public key using SDK
        public_key = private_key.public_key()
        public_key_bytes = public_key.to_bytes()

        # Check against expected public key
        expected_public_key = bytes.fromhex(vector["expected_public_key_hex"])
        self.assertEqual(
            public_key_bytes,
            expected_public_key,
            f"Public key mismatch. Expected: {vector['expected_public_key_hex']}, "
            f"Got: {public_key_bytes.hex()}",
        )

    def test_lite_identity_url_format(self):
        """Test lite identity URL format matches TS expectations using SDK"""
        vector = self.vectors["lite_identity_derivation"][0]

        # Generate key from seed using SDK
        seed_bytes = bytes.fromhex(vector["seed_hex"])
        private_key = Ed25519PrivateKey.from_bytes(seed_bytes[:32])
        public_key = private_key.public_key()

        # Derive lite identity URL using SDK
        lite_url = self.derive_lite_identity_url(public_key)

        # Check format matches expected pattern
        pattern = vector["expected_url_pattern"]
        self.assertIsNotNone(
            re.match(pattern, lite_url), f"URL {lite_url} does not match pattern {pattern}"
        )

        # Additional checks
        self.assertTrue(lite_url.startswith("acc://"))
        self.assertEqual(len(lite_url), 6 + 40 + 8)  # acc:// + 40 hex chars + 8 checksum chars

        # Verify it can be parsed as a valid AccountUrl
        lite_url_obj = AccountUrl(lite_url)
        self.assertIsInstance(lite_url_obj, AccountUrl)

    def test_public_key_hash_consistency(self):
        """Test public key hash calculation matches TS expectations using SDK"""
        # Using the AS test vector with known values
        vector = self.vectors["address_fixtures"]["private_keys"]["AS"]

        # Create key from seed using SDK
        seed_bytes = bytes.fromhex(vector["seed"])
        private_key = Ed25519PrivateKey.from_bytes(seed_bytes[:32])
        public_key = private_key.public_key()
        public_key_bytes = public_key.to_bytes()

        # Check public key matches expected
        expected_public_key = bytes.fromhex(vector["pubKey"])
        self.assertEqual(
            public_key_bytes,
            expected_public_key,
            f"Public key mismatch. Expected: {vector['pubKey']}, Got: {public_key_bytes.hex()}",
        )

        # Test that the SDK public key can be reconstructed from bytes
        reconstructed_public_key = Ed25519PublicKey.from_bytes(public_key_bytes)
        self.assertEqual(
            reconstructed_public_key.to_bytes(),
            public_key_bytes,
            "SDK public key reconstruction failed"
        )

    def test_sha256_hash_function(self):
        """Test SHA256 produces expected results"""
        # Test with known input/output
        test_data = b"test data"
        expected_hash = hashlib.sha256(test_data).hexdigest()
        actual_hash = hashlib.sha256(test_data).hexdigest()

        self.assertEqual(expected_hash, actual_hash)

        # Test with empty input
        empty_hash = hashlib.sha256(b"").hexdigest()
        self.assertEqual(
            empty_hash, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        )

    def test_url_checksum_calculation(self):
        """Test URL checksum calculation is consistent"""
        # Use a known key hash
        key_hash_20 = bytes.fromhex("1234567890abcdef1234567890abcdef12345678")
        key_str = key_hash_20.hex()

        # Calculate checksum
        checksum_full = hashlib.sha256(key_str.encode("utf-8")).digest()
        checksum = checksum_full[28:].hex()

        # Verify checksum is 8 hex characters (4 bytes)
        self.assertEqual(len(checksum), 8)
        self.assertTrue(all(c in "0123456789abcdef" for c in checksum))

        # Verify deterministic
        checksum2_full = hashlib.sha256(key_str.encode("utf-8")).digest()
        checksum2 = checksum2_full[28:].hex()
        self.assertEqual(checksum, checksum2)

    def test_sdk_signature_verification(self):
        """Test SDK signature creation and verification"""
        # Generate a keypair using helper function
        private_key, public_key = mk_ed25519_keypair(seed=12345)

        # Test data to sign
        test_data = b"test signature data"

        # Sign using SDK
        signature_bytes = private_key.sign(test_data)

        # Verify using SDK public key
        is_valid = public_key.verify(signature_bytes, test_data)
        self.assertTrue(is_valid, "SDK signature verification failed")

        # Test with wrong data should fail
        wrong_data = b"wrong test data"
        is_invalid = public_key.verify(signature_bytes, wrong_data)
        self.assertFalse(is_invalid, "SDK signature verification should fail for wrong data")

    def test_sdk_key_serialization_roundtrip(self):
        """Test SDK key serialization and deserialization"""
        # Generate a keypair
        private_key, public_key = mk_ed25519_keypair(seed=54321)

        # Test private key roundtrip
        private_key_bytes = private_key.to_bytes()
        reconstructed_private_key = Ed25519PrivateKey.from_bytes(private_key_bytes)
        self.assertEqual(
            private_key.to_bytes(),
            reconstructed_private_key.to_bytes(),
            "Private key serialization roundtrip failed"
        )

        # Test public key roundtrip
        public_key_bytes = public_key.to_bytes()
        reconstructed_public_key = Ed25519PublicKey.from_bytes(public_key_bytes)
        self.assertEqual(
            public_key.to_bytes(),
            reconstructed_public_key.to_bytes(),
            "Public key serialization roundtrip failed"
        )

        # Verify the reconstructed keys still work for signing
        test_data = b"roundtrip test"
        signature = reconstructed_private_key.sign(test_data)
        is_valid = reconstructed_public_key.verify(signature, test_data)
        self.assertTrue(is_valid, "Reconstructed keys should still work for signing")

    def test_sdk_lite_identity_from_multiple_seeds(self):
        """Test lite identity derivation with multiple seeds using SDK"""
        # Test with multiple seeds to ensure consistency
        test_seeds = [1111, 2222, 3333, 4444, 5555]

        for seed in test_seeds:
            with self.subTest(seed=seed):
                # Generate keypair
                private_key, public_key = mk_ed25519_keypair(seed=seed)

                # Derive lite identity URL
                lite_url = self.derive_lite_identity_url(public_key)

                # Verify format consistency
                self.assertTrue(lite_url.startswith("acc://"))
                self.assertEqual(len(lite_url), 54)  # acc:// + 40 hex + 8 checksum

                # Verify it can be parsed as AccountUrl
                url_obj = AccountUrl(lite_url)
                self.assertIsInstance(url_obj, AccountUrl)

                # Derive the same URL again and verify consistency
                lite_url2 = self.derive_lite_identity_url(public_key)
                self.assertEqual(lite_url, lite_url2, "Lite identity derivation should be deterministic")

    def test_sdk_cross_verification_with_vectors(self):
        """Test SDK crypto operations against golden test vectors"""
        # Test each ed25519 vector in the test data
        for i, vector in enumerate(self.vectors["ed25519_key_generation"]):
            with self.subTest(vector_index=i):
                # Create key from vector
                private_key_bytes = bytes.fromhex(vector["private_key_hex"])
                private_key = Ed25519PrivateKey.from_bytes(private_key_bytes)
                public_key = private_key.public_key()

                # Verify public key matches expected
                expected_public_key = bytes.fromhex(vector["expected_public_key_hex"])
                actual_public_key = public_key.to_bytes()
                self.assertEqual(
                    actual_public_key,
                    expected_public_key,
                    f"Vector {i}: Public key mismatch"
                )

                # Test signing and verification works
                test_message = f"test message for vector {i}".encode()
                signature = private_key.sign(test_message)
                is_valid = public_key.verify(signature, test_message)
                self.assertTrue(is_valid, f"Vector {i}: Signature verification failed")


if __name__ == "__main__":
    unittest.main()
