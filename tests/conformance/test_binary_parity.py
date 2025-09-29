#!/usr/bin/env python3

"""
Binary Parity Tests - Bit-for-bit compatibility with Dart SDK

Comprehensive conformance tests to ensure Python binary codec behavior
matches Dart SDK exactly. Tests primitive encoding, transaction encoding,
and envelope serialization for bit-for-bit parity.
"""

import json
import os
import sys
import unittest
from typing import Dict, Any

# Import codec modules
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))
from src.accumulate_client.codec import (
    BinaryWriter,
    BinaryReader,
    TransactionCodec,
    sha256_bytes
)
from src.accumulate_client.canonjson import dumps_canonical
from src.accumulate_client.codec.transaction_codec import AccumulateCodec
from tests.helpers.parity import assert_hex_equal


class TestBinaryParity(unittest.TestCase):
    """Test Python binary codec parity with Dart SDK"""

    @classmethod
    def setUpClass(cls):
        """Load golden fixtures from various sources"""
        golden_dir = os.path.join(os.path.dirname(__file__), "..", "golden")

        # Load Python golden fixtures (from TS parity work)
        with open(os.path.join(golden_dir, "envelope_fixed.golden.json"), "r") as f:
            cls.envelope_fixed = json.load(f)

        with open(os.path.join(golden_dir, "tx_only.golden.json"), "r") as f:
            cls.tx_only = json.load(f)

        with open(os.path.join(golden_dir, "tx_signing_vectors.json"), "r") as f:
            cls.signing_vectors = json.load(f)

    def test_primitive_encoding_parity(self):
        """Test primitive type encoding matches Dart exactly"""

        # Test uvarint encoding (from Dart binary_encoding_test.dart)
        test_cases = [
            (0, "00"),
            (1, "01"),
            (127, "7f"),
            (128, "8001"),
            (256, "8002"),
        ]

        for value, expected_hex in test_cases:
            with self.subTest(value=value):
                writer = BinaryWriter()
                writer.uvarint(value)
                actual = writer.to_bytes()
                assert_hex_equal(actual, expected_hex, f"uvarint({value})")

    def test_field_encoding_parity(self):
        """Test field encoding matches Dart exactly"""

        # Test field encoding (from Dart binary_encoding_test.dart)
        test_cases = [
            (1, b'\x2a', "012a"),  # field 1, data [42]
            (7, b'\x00', "0700"),  # field 7, data [0]
        ]

        for field, data, expected_hex in test_cases:
            with self.subTest(field=field):
                actual = AccumulateCodec.field_marshal_binary(field, data)
                assert_hex_equal(actual, expected_hex, f"field({field}, {data.hex()})")

    def test_string_encoding_parity(self):
        """Test string encoding matches Dart exactly"""

        # Test string encoding (from Dart binary_encoding_test.dart)
        test_cases = [
            ("hello", "0568656c6c6f"),  # length 5 + "hello" bytes
        ]

        for string, expected_hex in test_cases:
            with self.subTest(string=string):
                actual = AccumulateCodec.string_marshal_binary(string)
                assert_hex_equal(actual, expected_hex, f"string('{string}')")

    def test_boolean_encoding_parity(self):
        """Test boolean encoding matches Dart exactly"""

        # Test boolean encoding (from Dart binary_encoding_test.dart)
        test_cases = [
            (True, "01"),
            (False, "00"),
        ]

        for value, expected_hex in test_cases:
            with self.subTest(value=value):
                actual = AccumulateCodec.boolean_marshal_binary(value)
                assert_hex_equal(actual, expected_hex, f"boolean({value})")

    def test_bytes_encoding_parity(self):
        """Test bytes encoding matches Dart exactly"""

        # Test bytes encoding (from Dart binary_encoding_test.dart)
        test_cases = [
            (bytes([1, 2, 3]), "03010203"),  # length 3 + [1, 2, 3]
        ]

        for data, expected_hex in test_cases:
            with self.subTest(data=data.hex()):
                actual = AccumulateCodec.bytes_marshal_binary(data)
                assert_hex_equal(actual, expected_hex, f"bytes({data.hex()})")

    def test_hash_encoding_parity(self):
        """Test hash encoding matches Dart exactly"""

        # Test hash encoding (from Dart binary_encoding_test.dart)
        # 32 bytes of 0xFF, no length prefix
        hash_data = bytes([0xFF] * 32)
        expected_hex = "ff" * 32

        actual = AccumulateCodec.hash_marshal_binary(hash_data)
        assert_hex_equal(actual, expected_hex, "hash(32 bytes of 0xFF)")

        # Test invalid hash length
        with self.assertRaises(ValueError):
            AccumulateCodec.hash_marshal_binary(bytes(31))

    def test_bigint_encoding_parity(self):
        """Test BigInt encoding matches Dart exactly"""

        # Test BigInt encoding (from Dart binary_encoding_test.dart)
        test_cases = [
            (255, "01ff"),    # BigInt 255 = 0xFF, length-prefixed [1, 255]
            (256, "020100"),  # BigInt 256 = 0x100, length-prefixed [2, 1, 0]
        ]

        for value, expected_hex in test_cases:
            with self.subTest(value=value):
                actual = AccumulateCodec.bigint_marshal_binary(value)
                assert_hex_equal(actual, expected_hex, f"bigint({value})")

    def test_writer_reader_roundtrip(self):
        """Test writer/reader roundtrip maintains exact binary compatibility"""

        # Test data for roundtrip
        test_data = {
            "u8_values": [0, 1, 127, 255],
            "u32le_values": [0, 1, 0xFFFFFFFF],
            "u64le_values": [0, 1, 0xFFFFFFFFFFFFFFFF],
            "uvarint_values": [0, 1, 127, 128, 256, 16383, 16384],
            "string_values": ["", "hello", "test string"],
            "bytes_values": [b"", b"\x00", b"\x01\x02\x03", b"\xff\xfe\xfd"],
        }

        for test_type, values in test_data.items():
            for value in values:
                with self.subTest(test_type=test_type, value=value):
                    # Write value
                    writer = BinaryWriter()

                    if test_type == "u8_values":
                        writer.u8(value)
                    elif test_type == "u32le_values":
                        writer.u32le(value)
                    elif test_type == "u64le_values":
                        writer.u64le(value)
                    elif test_type == "uvarint_values":
                        writer.uvarint(value)
                    elif test_type == "string_values":
                        writer.string_ascii(value)
                    elif test_type == "bytes_values":
                        writer.len_prefixed_bytes(value)

                    # Read value back
                    data = writer.to_bytes()
                    reader = BinaryReader(data)

                    if test_type == "u8_values":
                        result = reader.u8()
                    elif test_type == "u32le_values":
                        result = reader.u32le()
                    elif test_type == "u64le_values":
                        result = reader.u64le()
                    elif test_type == "uvarint_values":
                        result = reader.uvarint()
                    elif test_type == "string_values":
                        result = reader.string_ascii()
                    elif test_type == "bytes_values":
                        result = reader.len_prefixed_bytes()

                    # Verify roundtrip
                    self.assertEqual(result, value, f"Roundtrip failed for {test_type}: {value}")

    def test_transaction_encoding_parity(self):
        """Test transaction encoding matches Dart/TS patterns"""

        # Use transaction from golden fixtures
        transaction = self.tx_only

        # Test transaction hash encoding
        header = transaction["header"]
        body = transaction["body"]

        # Encode for signing (should match Dart TransactionCodec.encodeTxForSigning)
        tx_hash = TransactionCodec.encode_tx_for_signing(header, body)

        # Verify hash is 32 bytes
        self.assertEqual(len(tx_hash), 32, "Transaction hash should be 32 bytes")

        # Test signing preimage construction
        metadata_hash = sha256_bytes(b"test metadata")
        signing_preimage = TransactionCodec.create_signing_preimage(metadata_hash, tx_hash)

        # Verify signing preimage is 32 bytes
        self.assertEqual(len(signing_preimage), 32, "Signing preimage should be 32 bytes")

    def test_envelope_encoding_parity(self):
        """Test envelope encoding for bit-for-bit parity"""

        # Use envelope from golden fixtures
        envelope = self.envelope_fixed

        # Test individual component encoding
        transaction = envelope["transaction"]
        signatures = envelope["signatures"]

        # Encode transaction header and body using canonical JSON
        header_json = dumps_canonical(transaction["header"])
        body_json = dumps_canonical(transaction["body"])

        header_bytes = AccumulateCodec.bytes_marshal_binary(header_json.encode('utf-8'))
        body_bytes = AccumulateCodec.bytes_marshal_binary(body_json.encode('utf-8'))

        # Verify encoding produces consistent lengths
        self.assertGreater(len(header_bytes), 0, "Header bytes should not be empty")
        self.assertGreater(len(body_bytes), 0, "Body bytes should not be empty")

        # Test signature encoding
        for sig in signatures:
            public_key_bytes = bytes.fromhex(sig["publicKey"])
            signature_bytes = bytes.fromhex(sig["signature"])

            # Verify key and signature lengths
            self.assertEqual(len(public_key_bytes), 32, "Public key should be 32 bytes")
            self.assertEqual(len(signature_bytes), 64, "Signature should be 64 bytes")

            # Test hash encoding (no length prefix)
            pub_key_encoded = AccumulateCodec.hash_marshal_binary(public_key_bytes)
            self.assertEqual(pub_key_encoded, public_key_bytes, "Hash encoding should not add length prefix")

    def test_golden_vector_compatibility(self):
        """Test compatibility with existing golden vectors"""

        # Test signing vectors from TS parity work
        for vector in self.signing_vectors["vectors"]:
            with self.subTest(name=vector["name"]):
                private_key_bytes = bytes.fromhex(vector["privateKey"])
                public_key_bytes = bytes.fromhex(vector["publicKey"])

                # Test key encoding
                pub_key_encoded = AccumulateCodec.hash_marshal_binary(public_key_bytes)
                assert_hex_equal(pub_key_encoded, vector["publicKey"], f"public key encoding for {vector['name']}")

                # Test private key as bytes (if used in binary encoding)
                if len(private_key_bytes) == 32:
                    priv_key_encoded = AccumulateCodec.hash_marshal_binary(private_key_bytes)
                    assert_hex_equal(priv_key_encoded, vector["privateKey"], f"private key encoding for {vector['name']}")

    def test_varint_edge_cases(self):
        """Test varint encoding edge cases for parity"""

        # Test edge cases that might differ between implementations
        edge_cases = [
            (0, "00"),                    # Zero
            (0x7F, "7f"),                # Max single-byte
            (0x80, "8001"),              # Min two-byte
            (0x3FFF, "ff7f"),            # Max two-byte
            (0x4000, "808001"),          # Min three-byte
            (0x1FFFFF, "ffff7f"),        # Max three-byte
            (0x200000, "80808001"),      # Min four-byte
        ]

        for value, expected_hex in edge_cases:
            with self.subTest(value=hex(value)):
                writer = BinaryWriter()
                writer.uvarint(value)
                actual = writer.to_bytes()
                assert_hex_equal(actual, expected_hex, f"varint edge case {hex(value)}")

                # Test roundtrip
                reader = BinaryReader(actual)
                decoded = reader.uvarint()
                self.assertEqual(decoded, value, f"Varint roundtrip failed for {hex(value)}")

    def test_endianness_consistency(self):
        """Test endianness consistency with Dart implementation"""

        # Test u32le encoding
        u32_cases = [
            (0x12345678, "78563412"),    # Little-endian
            (0x00000001, "01000000"),    # Small value
            (0xFFFFFFFF, "ffffffff"),    # Max value
        ]

        for value, expected_hex in u32_cases:
            with self.subTest(value=hex(value)):
                writer = BinaryWriter()
                writer.u32le(value)
                actual = writer.to_bytes()
                assert_hex_equal(actual, expected_hex, f"u32le({hex(value)})")

        # Test u64le encoding
        u64_cases = [
            (0x123456789ABCDEF0, "f0debc9a78563412"),  # Little-endian
            (0x0000000000000001, "0100000000000000"),  # Small value
            (0xFFFFFFFFFFFFFFFF, "ffffffffffffffff"),  # Max value
        ]

        for value, expected_hex in u64_cases:
            with self.subTest(value=hex(value)):
                writer = BinaryWriter()
                writer.u64le(value)
                actual = writer.to_bytes()
                assert_hex_equal(actual, expected_hex, f"u64le({hex(value)})")


if __name__ == "__main__":
    unittest.main()