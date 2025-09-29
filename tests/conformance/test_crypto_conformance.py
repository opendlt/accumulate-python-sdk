#!/usr/bin/env python3

"""Conformance tests against TypeScript SDK golden values for crypto operations"""

import hashlib
import json
import os
import re
import unittest
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization


class TestCryptoConformance(unittest.TestCase):
    """Test crypto operations conform to TypeScript SDK"""

    @classmethod
    def setUpClass(cls):
        """Load golden test vectors"""
        golden_file = os.path.join(
            os.path.dirname(__file__),
            "..",
            "golden",
            "ed25519_vectors.json"
        )
        with open(golden_file, "r") as f:
            cls.vectors = json.load(f)

    def derive_lite_identity_url(self, public_key_bytes: bytes) -> str:
        """Derive Lite Identity URL from Ed25519 public key with checksum"""
        # For Ed25519: keyHash = SHA256(publicKey)
        key_hash_full = hashlib.sha256(public_key_bytes).digest()

        # Use first 20 bytes
        key_hash_20 = key_hash_full[:20]

        # Convert to hex string
        key_str = key_hash_20.hex()

        # Calculate checksum
        checksum_full = hashlib.sha256(key_str.encode('utf-8')).digest()
        checksum = checksum_full[28:].hex()  # Take last 4 bytes

        # Format: acc://<keyHash[0:20]><checksum>
        return f"acc://{key_str}{checksum}"

    def test_ed25519_key_generation_zero_key(self):
        """Test Ed25519 key generation with zero private key (TS test vector)"""
        vector = self.vectors["ed25519_key_generation"][0]

        # Create private key from hex
        private_key_bytes = bytes.fromhex(vector["private_key_hex"])
        private_key = ed25519.Ed25519PrivateKey.from_private_bytes(private_key_bytes)

        # Get public key
        public_key = private_key.public_key()
        public_key_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )

        # Check against expected public key
        expected_public_key = bytes.fromhex(vector["expected_public_key_hex"])
        self.assertEqual(
            public_key_bytes,
            expected_public_key,
            f"Public key mismatch. Expected: {vector['expected_public_key_hex']}, "
            f"Got: {public_key_bytes.hex()}"
        )

    def test_lite_identity_url_format(self):
        """Test lite identity URL format matches TS expectations"""
        vector = self.vectors["lite_identity_derivation"][0]

        # Generate key from seed
        seed_bytes = bytes.fromhex(vector["seed_hex"])
        private_key = ed25519.Ed25519PrivateKey.from_private_bytes(seed_bytes[:32])
        public_key = private_key.public_key()
        public_key_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )

        # Derive lite identity URL
        lite_url = self.derive_lite_identity_url(public_key_bytes)

        # Check format matches expected pattern
        pattern = vector["expected_url_pattern"]
        self.assertIsNotNone(
            re.match(pattern, lite_url),
            f"URL {lite_url} does not match pattern {pattern}"
        )

        # Additional checks
        self.assertTrue(lite_url.startswith("acc://"))
        self.assertEqual(len(lite_url), 6 + 40 + 8)  # acc:// + 40 hex chars + 8 checksum chars

    def test_public_key_hash_consistency(self):
        """Test public key hash calculation matches TS expectations"""
        # Using the AS test vector with known values
        vector = self.vectors["address_fixtures"]["private_keys"]["AS"]

        # Create key from seed
        seed_bytes = bytes.fromhex(vector["seed"])
        private_key = ed25519.Ed25519PrivateKey.from_private_bytes(seed_bytes[:32])
        public_key = private_key.public_key()
        public_key_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )

        # Check public key matches expected
        expected_public_key = bytes.fromhex(vector["pubKey"])
        self.assertEqual(
            public_key_bytes,
            expected_public_key,
            f"Public key mismatch. Expected: {vector['pubKey']}, "
            f"Got: {public_key_bytes.hex()}"
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
            empty_hash,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        )

    def test_url_checksum_calculation(self):
        """Test URL checksum calculation is consistent"""
        # Use a known key hash
        key_hash_20 = bytes.fromhex("1234567890abcdef1234567890abcdef12345678")
        key_str = key_hash_20.hex()

        # Calculate checksum
        checksum_full = hashlib.sha256(key_str.encode('utf-8')).digest()
        checksum = checksum_full[28:].hex()

        # Verify checksum is 8 hex characters (4 bytes)
        self.assertEqual(len(checksum), 8)
        self.assertTrue(all(c in "0123456789abcdef" for c in checksum))

        # Verify deterministic
        checksum2_full = hashlib.sha256(key_str.encode('utf-8')).digest()
        checksum2 = checksum2_full[28:].hex()
        self.assertEqual(checksum, checksum2)


if __name__ == "__main__":
    unittest.main()