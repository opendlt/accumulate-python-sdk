#!/usr/bin/env python3

"""
TypeScript SDK Parity Tests

Comprehensive conformance tests to ensure Python SDK behavior matches
TypeScript SDK exactly. Tests crypto operations, URL derivation,
JSON serialization, and transaction signing.
"""

import json
import os

# Import our crypto helpers
import sys
import unittest
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from helpers.crypto_helpers import (
    canonical_json,
    create_signature_envelope,
    create_transaction_hash,
    derive_lite_identity_url,
    derive_lite_token_account_url,
    ed25519_keypair_from_seed,
    ed25519_sign,
    ed25519_verify,
    sha256_hash,
    validate_ed25519_test_vector,
    verify_signature_envelope,
)

# Import SDK crypto classes to test direct usage
from accumulate_client.crypto.ed25519 import Ed25519PrivateKey, Ed25519PublicKey


class TestTSParity(unittest.TestCase):
    """Test Python SDK parity with TypeScript SDK"""

    @classmethod
    def setUpClass(cls):
        """Load TS golden fixtures"""
        golden_dir = os.path.join(os.path.dirname(__file__), "..", "golden")

        # Load comprehensive fixtures
        with open(os.path.join(golden_dir, "ts_parity_fixtures.json")) as f:
            cls.fixtures = json.load(f)

        # Load specific fixtures
        with open(os.path.join(golden_dir, "tx_signing_vectors.json")) as f:
            cls.signing_vectors = json.load(f)

        with open(os.path.join(golden_dir, "envelope_fixed.golden.json")) as f:
            cls.envelope_fixed = json.load(f)

        with open(os.path.join(golden_dir, "sig_ed25519.golden.json")) as f:
            cls.sig_ed25519 = json.load(f)

        with open(os.path.join(golden_dir, "tx_only.golden.json")) as f:
            cls.tx_only = json.load(f)

    def test_canonical_json_serialization(self):
        """Test canonical JSON matches TS SDK behavior"""
        for vector in self.fixtures["canonical_json_vectors"]:
            with self.subTest(name=vector["name"]):
                actual = canonical_json(vector["input"])
                expected = vector["expectedJSON"]

                self.assertEqual(
                    actual,
                    expected,
                    f"Canonical JSON mismatch for {vector['name']}:\n"
                    f"Expected: {expected}\n"
                    f"Actual:   {actual}",
                )

    def test_sha256_hashing(self):
        """Test SHA-256 hashing matches TS SDK behavior"""
        for vector in self.fixtures["hashing_vectors"]:
            with self.subTest(name=vector["name"]):
                # Test string input
                actual_hash = sha256_hash(vector["input"])
                expected_hash = bytes.fromhex(vector["expectedHash"])

                self.assertEqual(
                    actual_hash,
                    expected_hash,
                    f"SHA-256 hash mismatch for {vector['name']}:\n"
                    f"Input: {vector['input']}\n"
                    f"Expected: {vector['expectedHash']}\n"
                    f"Actual:   {actual_hash.hex()}",
                )

                # Test bytes input
                input_bytes = bytes.fromhex(vector["inputHex"])
                actual_hash_bytes = sha256_hash(input_bytes)
                self.assertEqual(actual_hash_bytes, expected_hash)

    def test_ed25519_key_generation(self):
        """Test Ed25519 key generation matches TS SDK"""
        for vector in self.signing_vectors["vectors"]:
            with self.subTest(name=vector["name"]):
                # Generate keypair from private key
                private_key_bytes = bytes.fromhex(vector["privateKey"])
                _, public_key_bytes = ed25519_keypair_from_seed(private_key_bytes)

                # Check public key matches
                expected_public_key = bytes.fromhex(vector["publicKey"])
                self.assertEqual(
                    public_key_bytes,
                    expected_public_key,
                    f"Public key mismatch for {vector['name']}:\n"
                    f"Expected: {vector['publicKey']}\n"
                    f"Actual:   {public_key_bytes.hex()}",
                )

    def test_lite_url_derivation(self):
        """Test lite URL derivation matches TS SDK"""
        for vector in self.signing_vectors["vectors"]:
            with self.subTest(name=vector["name"]):
                public_key_bytes = bytes.fromhex(vector["publicKey"])

                # Test LID derivation
                actual_lid = derive_lite_identity_url(public_key_bytes)
                expected_lid = vector["lid"]
                self.assertEqual(
                    actual_lid,
                    expected_lid,
                    f"LID mismatch for {vector['name']}:\n"
                    f"Expected: {expected_lid}\n"
                    f"Actual:   {actual_lid}",
                )

                # Test LTA derivation
                actual_lta = derive_lite_token_account_url(public_key_bytes)
                expected_lta = vector["lta"]
                self.assertEqual(
                    actual_lta,
                    expected_lta,
                    f"LTA mismatch for {vector['name']}:\n"
                    f"Expected: {expected_lta}\n"
                    f"Actual:   {actual_lta}",
                )

    def test_ed25519_signing(self):
        """Test Ed25519 signing matches TS SDK behavior"""
        # Find the test signing vector
        test_vector = None
        for vector in self.signing_vectors["vectors"]:
            if vector["name"] == "test_signing":
                test_vector = vector
                break

        self.assertIsNotNone(test_vector, "test_signing vector not found")

        # Parse vector
        private_key_bytes = bytes.fromhex(test_vector["privateKey"])
        public_key_bytes = bytes.fromhex(test_vector["publicKey"])
        message_bytes = bytes.fromhex(test_vector["testMessage"])
        expected_signature = bytes.fromhex(test_vector["signature"])
        expected_hash = bytes.fromhex(test_vector["messageHash"])

        # Test message hashing
        actual_hash = sha256_hash(message_bytes)
        self.assertEqual(
            actual_hash,
            expected_hash,
            f"Message hash mismatch:\n"
            f"Expected: {expected_hash.hex()}\n"
            f"Actual:   {actual_hash.hex()}",
        )

        # Test signature verification (signature is deterministic in TS)
        is_valid = ed25519_verify(public_key_bytes, expected_signature, actual_hash)
        self.assertTrue(is_valid, "TS signature should verify against Python crypto")

        # Test Python signature generation and verification
        python_signature = ed25519_sign(private_key_bytes, actual_hash)
        is_python_valid = ed25519_verify(public_key_bytes, python_signature, actual_hash)
        self.assertTrue(is_python_valid, "Python-generated signature should verify")

    def test_transaction_hashing(self):
        """Test transaction hashing matches TS SDK"""
        for vector in self.fixtures["transaction_vectors"]:
            with self.subTest(name=vector["name"]):
                transaction = vector["transaction"]
                expected_canonical = vector["canonicalJSON"]
                expected_hash = bytes.fromhex(vector["hash"])

                # Test canonical JSON
                actual_canonical = canonical_json(transaction)
                self.assertEqual(
                    actual_canonical,
                    expected_canonical,
                    f"Canonical JSON mismatch for {vector['name']}",
                )

                # Test hash
                actual_hash = create_transaction_hash(transaction)
                self.assertEqual(
                    actual_hash,
                    expected_hash,
                    f"Transaction hash mismatch for {vector['name']}:\n"
                    f"Expected: {expected_hash.hex()}\n"
                    f"Actual:   {actual_hash.hex()}",
                )

    def test_envelope_structure(self):
        """Test envelope structure matches TS SDK"""
        # Test against envelope_fixed.golden.json
        envelope = self.envelope_fixed

        # Validate structure
        self.assertIn("transaction", envelope)
        self.assertIn("signatures", envelope)
        self.assertIsInstance(envelope["signatures"], list)
        self.assertGreater(len(envelope["signatures"]), 0)

        # Validate transaction structure
        transaction = envelope["transaction"]
        self.assertIn("header", transaction)
        self.assertIn("body", transaction)
        self.assertIn("principal", transaction["header"])
        self.assertIn("timestamp", transaction["header"])

        # Validate signature structure
        signature = envelope["signatures"][0]
        self.assertIn("type", signature)
        self.assertIn("publicKey", signature)
        self.assertIn("signature", signature)
        self.assertEqual(signature["type"], "ed25519")

        # Validate signature format
        public_key_hex = signature["publicKey"]
        signature_hex = signature["signature"]

        # Public key should be 32 bytes (64 hex chars)
        self.assertEqual(len(public_key_hex), 64, "Public key should be 32 bytes")

        # Signature should be 64 bytes (128 hex chars)
        self.assertEqual(len(signature_hex), 128, "Signature should be 64 bytes")

        # Test that we can parse as bytes
        public_key_bytes = bytes.fromhex(public_key_hex)
        signature_bytes = bytes.fromhex(signature_hex)
        self.assertEqual(len(public_key_bytes), 32)
        self.assertEqual(len(signature_bytes), 64)

    def test_signature_verification(self):
        """Test signature verification against TS SDK signatures"""
        # Use envelope_fixed.golden.json
        envelope = self.envelope_fixed

        # Verify envelope signatures
        is_valid = verify_signature_envelope(envelope)
        self.assertTrue(is_valid, "TS-generated envelope should verify with Python crypto")

    def test_ed25519_test_vectors_validation(self):
        """Test all Ed25519 test vectors validate correctly"""
        for vector in self.signing_vectors["vectors"]:
            with self.subTest(name=vector["name"]):
                is_valid = validate_ed25519_test_vector(vector)
                self.assertTrue(is_valid, f"Test vector {vector['name']} should validate")

    def test_round_trip_envelope_creation(self):
        """Test creating and verifying envelope matches TS behavior"""
        # Use a simple transaction
        transaction = {
            "header": {"principal": "acc://test.acme/tokens", "timestamp": 1640995200000000},
            "body": {
                "type": "sendTokens",
                "to": [{"url": "acc://recipient.acme/tokens", "amount": "500000"}],
            },
        }

        # Use a known private key
        private_key_hex = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
        private_key_bytes = bytes.fromhex(private_key_hex)

        # Create envelope
        envelope = create_signature_envelope(transaction, private_key_bytes)

        # Verify envelope structure
        self.assertIn("transaction", envelope)
        self.assertIn("signatures", envelope)
        self.assertEqual(envelope["transaction"], transaction)

        # Verify signature
        is_valid = verify_signature_envelope(envelope)
        self.assertTrue(is_valid, "Round-trip envelope should verify")

    def test_canonical_json_edge_cases(self):
        """Test canonical JSON edge cases"""
        test_cases = [
            # Empty objects
            ({}, "{}"),
            ([], "[]"),
            # Nested structures
            ({"b": {"y": 2, "x": 1}, "a": 1}, '{"a":1,"b":{"x":1,"y":2}}'),
            # Numbers and strings
            ({"num": 123, "str": "test", "bool": True}, '{"bool":true,"num":123,"str":"test"}'),
            # Null values
            ({"null": None, "empty": ""}, '{"empty":"","null":null}'),
            # Unicode
            ({"unicode": "test🚀"}, '{"unicode":"test🚀"}'),
        ]

        for i, (input_obj, expected) in enumerate(test_cases):
            with self.subTest(case=i):
                actual = canonical_json(input_obj)
                self.assertEqual(actual, expected)

    def test_hex_encoding_consistency(self):
        """Test hex encoding is consistent with TS SDK"""
        test_bytes = [
            b"",
            b"\x00",
            b"\x00\x01\x02\x03",
            b"\xff\xfe\xfd\xfc",
            bytes(range(256))[:32],  # 32 bytes for key-like data
        ]

        for test_byte in test_bytes:
            with self.subTest(length=len(test_byte)):
                # Test lowercase hex (TS SDK standard)
                hex_str = test_byte.hex()
                # Check that there are no uppercase letters (Python's islower() returns False for digit-only strings)
                self.assertTrue(hex_str == hex_str.lower())

                # Test round-trip
                decoded = bytes.fromhex(hex_str)
                self.assertEqual(decoded, test_byte)

    def test_url_checksum_algorithm(self):
        """Test URL checksum algorithm matches TS SDK exactly"""
        # Test with known vectors from TS SDK
        test_cases = [
            {"keyHash": "139e3940e64b5491722088d9a0d741628fc826e0", "expectedChecksum": "a80337ad"},
            {"keyHash": "105251bb367baa372c748930531ae63d6e143c9a", "expectedChecksum": "a4470eff"},
            {"keyHash": "e0cfdc239dbe6e1929ee5a99d230682b3cf5498f", "expectedChecksum": "e115b24d"},
        ]

        for case in test_cases:
            with self.subTest(keyHash=case["keyHash"]):
                key_str = case["keyHash"]
                checksum_full = sha256_hash(key_str)
                checksum = checksum_full[28:].hex()  # Last 4 bytes

                self.assertEqual(
                    checksum, case["expectedChecksum"], f"Checksum mismatch for {key_str}"
                )

    def test_sdk_direct_integration(self):
        """Test direct SDK crypto integration versus helper functions"""
        # Test that helpers are using SDK classes by comparing results
        test_seed = bytes.fromhex("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
        test_message = b"test message for SDK integration"

        # Test 1: Key generation should match between helper and direct SDK
        helper_private, helper_public = ed25519_keypair_from_seed(test_seed)

        sdk_private = Ed25519PrivateKey.from_bytes(test_seed)
        sdk_public = sdk_private.public_key()

        self.assertEqual(helper_private, sdk_private.to_bytes(), "Helper should use SDK private key")
        self.assertEqual(helper_public, sdk_public.to_bytes(), "Helper should use SDK public key")

        # Test 2: Signing should produce valid results
        helper_signature = ed25519_sign(test_seed, test_message)
        sdk_signature = sdk_private.sign(test_message)

        # Both should be valid (signatures are non-deterministic)
        self.assertTrue(ed25519_verify(helper_public, helper_signature, test_message),
                       "Helper signature should verify")
        self.assertTrue(sdk_public.verify(sdk_signature, test_message),
                       "SDK signature should verify")

        # Cross-verification: SDK should verify helper signature and vice versa
        self.assertTrue(sdk_public.verify(helper_signature, test_message),
                       "SDK should verify helper signature")
        self.assertTrue(ed25519_verify(helper_public, sdk_signature, test_message),
                       "Helper should verify SDK signature")

    def test_sdk_url_derivation_consistency(self):
        """Test URL derivation consistency between helpers and SDK expectations"""
        # Use a test vector from the signing vectors
        vector = self.signing_vectors["vectors"][0]
        public_key_bytes = bytes.fromhex(vector["publicKey"])

        # Test lite identity URL derivation
        helper_lid = derive_lite_identity_url(public_key_bytes)
        expected_lid = vector["lid"]

        self.assertEqual(helper_lid, expected_lid, "Helper LID should match test vector")

        # Verify the URL can be parsed correctly (future: when AccountUrl supports lite parsing)
        self.assertTrue(helper_lid.startswith("acc://"), "LID should start with acc://")
        self.assertEqual(len(helper_lid), 54, "LID should be exactly 54 characters")

        # Test lite token account URL derivation
        helper_lta = derive_lite_token_account_url(public_key_bytes)
        expected_lta = vector["lta"]

        self.assertEqual(helper_lta, expected_lta, "Helper LTA should match test vector")
        self.assertTrue(helper_lta.startswith("acc://"), "LTA should start with acc://")
        self.assertTrue(helper_lta.endswith("/ACME"), "LTA should end with /ACME")

    def test_enhanced_signature_verification_matrix(self):
        """Test comprehensive signature verification matrix"""
        # Create multiple keypairs and test cross-verification
        seeds = [
            bytes.fromhex("1111111111111111111111111111111111111111111111111111111111111111"),
            bytes.fromhex("2222222222222222222222222222222222222222222222222222222222222222"),
            bytes.fromhex("3333333333333333333333333333333333333333333333333333333333333333"),
        ]

        messages = [
            b"message 1",
            b"message 2",
            b"different message"
        ]

        for i, seed in enumerate(seeds):
            with self.subTest(keypair=i):
                private_key = Ed25519PrivateKey.from_bytes(seed)
                public_key = private_key.public_key()

                for j, message in enumerate(messages):
                    with self.subTest(message=j):
                        # Sign with SDK
                        sdk_signature = private_key.sign(message)

                        # Verify with both SDK and helper
                        self.assertTrue(public_key.verify(sdk_signature, message),
                                       f"SDK verification failed for keypair {i}, message {j}")
                        self.assertTrue(ed25519_verify(public_key.to_bytes(), sdk_signature, message),
                                       f"Helper verification failed for keypair {i}, message {j}")

                        # Sign with helper
                        helper_signature = ed25519_sign(seed, message)

                        # Verify with both SDK and helper
                        self.assertTrue(public_key.verify(helper_signature, message),
                                       f"SDK verification of helper signature failed for keypair {i}, message {j}")
                        self.assertTrue(ed25519_verify(public_key.to_bytes(), helper_signature, message),
                                       f"Helper verification of helper signature failed for keypair {i}, message {j}")


if __name__ == "__main__":
    unittest.main()
