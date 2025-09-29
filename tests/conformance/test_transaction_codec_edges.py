#!/usr/bin/env python3

"""Edge case tests for transaction_codec.py to achieve ≥90% coverage"""

import json

import pytest

from accumulate_client.codec.hashes import sha256_bytes
from accumulate_client.codec.transaction_codec import AccumulateCodec, TransactionCodec


class TestAccumulateCodecEdgeCases:
    """Test edge cases and error conditions for AccumulateCodec"""

    def test_field_marshal_binary_valid_range(self):
        """Test field_marshal_binary with valid field numbers"""
        test_data = b"test_data"

        # Test minimum valid field
        result = AccumulateCodec.field_marshal_binary(1, test_data)
        assert len(result) > len(test_data)

        # Test maximum valid field
        result = AccumulateCodec.field_marshal_binary(32, test_data)
        assert len(result) > len(test_data)

        # Test middle range
        for field_num in [5, 10, 15, 20, 25]:
            result = AccumulateCodec.field_marshal_binary(field_num, test_data)
            assert len(result) > len(test_data)

    def test_field_marshal_binary_invalid_range(self):
        """Test field_marshal_binary with invalid field numbers"""
        test_data = b"test_data"

        # Test below minimum
        with pytest.raises(ValueError, match="Field number is out of range"):
            AccumulateCodec.field_marshal_binary(0, test_data)

        # Test above maximum
        with pytest.raises(ValueError, match="Field number is out of range"):
            AccumulateCodec.field_marshal_binary(33, test_data)

        # Test negative
        with pytest.raises(ValueError, match="Field number is out of range"):
            AccumulateCodec.field_marshal_binary(-1, test_data)

        # Test very large
        with pytest.raises(ValueError, match="Field number is out of range"):
            AccumulateCodec.field_marshal_binary(1000, test_data)

    def test_uvarint_marshal_binary_edge_values(self):
        """Test uvarint_marshal_binary with edge values"""
        # Test zero
        result = AccumulateCodec.uvarint_marshal_binary(0)
        assert len(result) == 1

        # Test small values
        for val in [1, 127, 128, 255, 256]:
            result = AccumulateCodec.uvarint_marshal_binary(val)
            assert len(result) >= 1

        # Test maximum safe integer
        max_safe = 0x7FFFFFFFFFFFFFFF
        result = AccumulateCodec.uvarint_marshal_binary(max_safe)
        assert len(result) >= 1

    def test_uvarint_marshal_binary_with_field(self):
        """Test uvarint_marshal_binary with field numbers"""
        # Test with field
        result = AccumulateCodec.uvarint_marshal_binary(42, field=5)
        assert len(result) > 1

        # Test without field
        result_no_field = AccumulateCodec.uvarint_marshal_binary(42)
        assert len(result) > len(result_no_field)

    def test_uvarint_marshal_binary_overflow(self):
        """Test uvarint_marshal_binary with values exceeding safe integer range"""
        # Test value exceeding MAX_SAFE_INTEGER
        with pytest.raises(
            ValueError, match="Cannot marshal binary number greater than MAX_SAFE_INTEGER"
        ):
            AccumulateCodec.uvarint_marshal_binary(0x7FFFFFFFFFFFFFFF + 1)

        # Test very large value
        with pytest.raises(
            ValueError, match="Cannot marshal binary number greater than MAX_SAFE_INTEGER"
        ):
            AccumulateCodec.uvarint_marshal_binary(2**64)

    def test_varint_marshal_binary_signed_values(self):
        """Test varint_marshal_binary with signed values"""
        # Test positive values
        result_pos = AccumulateCodec.varint_marshal_binary(42)
        assert len(result_pos) >= 1

        # Test negative values
        result_neg = AccumulateCodec.varint_marshal_binary(-42)
        assert len(result_neg) >= 1

        # Test zero
        result_zero = AccumulateCodec.varint_marshal_binary(0)
        assert len(result_zero) >= 1

        # Test edge cases
        for val in [-1, -127, -128, -255, -256, 127, 128, 255, 256]:
            result = AccumulateCodec.varint_marshal_binary(val)
            assert len(result) >= 1

    def test_varint_marshal_binary_with_field(self):
        """Test varint_marshal_binary with field numbers"""
        # Test with field
        result = AccumulateCodec.varint_marshal_binary(-42, field=10)
        assert len(result) > 1

        # Test without field
        result_no_field = AccumulateCodec.varint_marshal_binary(-42)
        assert len(result) > len(result_no_field)

    def test_boolean_marshal_binary_values(self):
        """Test boolean_marshal_binary with true/false"""
        # Test true
        result_true = AccumulateCodec.boolean_marshal_binary(True)
        assert len(result_true) == 1
        assert result_true == b"\x01"

        # Test false
        result_false = AccumulateCodec.boolean_marshal_binary(False)
        assert len(result_false) == 1
        assert result_false == b"\x00"

    def test_boolean_marshal_binary_with_field(self):
        """Test boolean_marshal_binary with field numbers"""
        # Test with field
        result = AccumulateCodec.boolean_marshal_binary(True, field=3)
        assert len(result) > 1

        # Test without field
        result_no_field = AccumulateCodec.boolean_marshal_binary(True)
        assert len(result) > len(result_no_field)

    def test_string_marshal_binary_edge_cases(self):
        """Test string_marshal_binary with various string inputs"""
        # Test empty string
        result = AccumulateCodec.string_marshal_binary("")
        assert len(result) >= 1

        # Test simple ASCII
        result = AccumulateCodec.string_marshal_binary("hello")
        assert len(result) > 5

        # Test Unicode characters
        result = AccumulateCodec.string_marshal_binary("Hello, 世界! 🌍")
        assert len(result) > 10

        # Test special characters
        result = AccumulateCodec.string_marshal_binary("!@#$%^&*()_+-={}[]|\\:;\"'<>?,./")
        assert len(result) > 20

        # Test very long string
        long_string = "a" * 1000
        result = AccumulateCodec.string_marshal_binary(long_string)
        assert len(result) > 1000

    def test_string_marshal_binary_with_field(self):
        """Test string_marshal_binary with field numbers"""
        test_string = "test"

        # Test with field
        result = AccumulateCodec.string_marshal_binary(test_string, field=7)
        assert len(result) > len(test_string.encode("utf-8"))

        # Test without field
        result_no_field = AccumulateCodec.string_marshal_binary(test_string)
        assert len(result) > len(result_no_field)

    def test_bytes_marshal_binary_edge_cases(self):
        """Test bytes_marshal_binary with various byte inputs"""
        # Test empty bytes
        result = AccumulateCodec.bytes_marshal_binary(b"")
        assert len(result) >= 1

        # Test single byte
        result = AccumulateCodec.bytes_marshal_binary(b"a")
        assert len(result) > 1

        # Test all possible byte values
        all_bytes = bytes(range(256))
        result = AccumulateCodec.bytes_marshal_binary(all_bytes)
        assert len(result) > 256

        # Test large bytes
        large_bytes = b"x" * 10000
        result = AccumulateCodec.bytes_marshal_binary(large_bytes)
        assert len(result) > 10000

    def test_bytes_marshal_binary_with_field(self):
        """Test bytes_marshal_binary with field numbers"""
        test_bytes = b"test_data"

        # Test with field
        result = AccumulateCodec.bytes_marshal_binary(test_bytes, field=12)
        assert len(result) > len(test_bytes)

        # Test without field
        result_no_field = AccumulateCodec.bytes_marshal_binary(test_bytes)
        assert len(result) > len(result_no_field)

    def test_hash_marshal_binary_valid_hash(self):
        """Test hash_marshal_binary with valid 32-byte hashes"""
        # Test exact 32 bytes
        valid_hash = b"a" * 32
        result = AccumulateCodec.hash_marshal_binary(valid_hash)
        assert result == valid_hash

        # Test with zeros
        zero_hash = b"\x00" * 32
        result = AccumulateCodec.hash_marshal_binary(zero_hash)
        assert result == zero_hash

        # Test with all 0xFF
        max_hash = b"\xff" * 32
        result = AccumulateCodec.hash_marshal_binary(max_hash)
        assert result == max_hash

    def test_hash_marshal_binary_with_field(self):
        """Test hash_marshal_binary with field numbers"""
        valid_hash = b"a" * 32

        # Test with field
        result = AccumulateCodec.hash_marshal_binary(valid_hash, field=15)
        assert len(result) > 32

        # Test without field
        result_no_field = AccumulateCodec.hash_marshal_binary(valid_hash)
        assert len(result) > len(result_no_field)

    def test_hash_marshal_binary_invalid_length(self):
        """Test hash_marshal_binary with invalid hash lengths"""
        # Test too short
        with pytest.raises(ValueError, match="Invalid length, value is not a hash"):
            AccumulateCodec.hash_marshal_binary(b"a" * 31)

        # Test too long
        with pytest.raises(ValueError, match="Invalid length, value is not a hash"):
            AccumulateCodec.hash_marshal_binary(b"a" * 33)

        # Test empty
        with pytest.raises(ValueError, match="Invalid length, value is not a hash"):
            AccumulateCodec.hash_marshal_binary(b"")

        # Test very different lengths
        for length in [1, 16, 64, 128]:
            with pytest.raises(ValueError, match="Invalid length, value is not a hash"):
                AccumulateCodec.hash_marshal_binary(b"a" * length)

    def test_bigint_marshal_binary_valid_values(self):
        """Test bigint_marshal_binary with valid positive integers"""
        # Test zero
        result = AccumulateCodec.bigint_marshal_binary(0)
        assert len(result) >= 1

        # Test small values
        for val in [1, 255, 256, 65535, 65536]:
            result = AccumulateCodec.bigint_marshal_binary(val)
            assert len(result) >= 1

        # Test large values
        large_val = 2**128
        result = AccumulateCodec.bigint_marshal_binary(large_val)
        assert len(result) > 16

    def test_bigint_marshal_binary_with_field(self):
        """Test bigint_marshal_binary with field numbers"""
        test_val = 42

        # Test with field
        result = AccumulateCodec.bigint_marshal_binary(test_val, field=20)
        assert len(result) > 1

        # Test without field
        result_no_field = AccumulateCodec.bigint_marshal_binary(test_val)
        assert len(result) > len(result_no_field)

    def test_bigint_marshal_binary_negative_values(self):
        """Test bigint_marshal_binary with negative integers"""
        # Test negative values
        with pytest.raises(ValueError, match="Cannot marshal a negative bigint"):
            AccumulateCodec.bigint_marshal_binary(-1)

        with pytest.raises(ValueError, match="Cannot marshal a negative bigint"):
            AccumulateCodec.bigint_marshal_binary(-42)

        with pytest.raises(ValueError, match="Cannot marshal a negative bigint"):
            AccumulateCodec.bigint_marshal_binary(-(2**64))

    def test_bigint_marshal_binary_hex_conversion(self):
        """Test bigint_marshal_binary hex conversion edge cases"""
        # Test odd-length hex (should be padded)
        val = 0xF  # Single hex digit
        result = AccumulateCodec.bigint_marshal_binary(val)
        assert len(result) >= 1

        # Test even-length hex
        val = 0xFF  # Two hex digits
        result = AccumulateCodec.bigint_marshal_binary(val)
        assert len(result) >= 1

        # Test powers of 2
        for power in [1, 8, 16, 32, 64, 128]:
            val = 2**power
            result = AccumulateCodec.bigint_marshal_binary(val)
            assert len(result) >= 1


class TestTransactionCodecEdgeCases:
    """Test edge cases for TransactionCodec"""

    def test_encode_tx_for_signing_simple(self):
        """Test encode_tx_for_signing with simple inputs"""
        header = {"principal": "acc://test", "timestamp": 1234567890}
        body = {"type": "sendTokens", "to": "acc://dest", "amount": "100"}

        result = TransactionCodec.encode_tx_for_signing(header, body)
        assert len(result) == 32  # SHA256 output is 32 bytes
        assert isinstance(result, bytes)

    def test_encode_tx_for_signing_empty_structures(self):
        """Test encode_tx_for_signing with empty structures"""
        # Empty header and body
        header = {}
        body = {}

        result = TransactionCodec.encode_tx_for_signing(header, body)
        assert len(result) == 32

        # One empty, one with data
        header = {"timestamp": 123}
        body = {}
        result = TransactionCodec.encode_tx_for_signing(header, body)
        assert len(result) == 32

    def test_encode_tx_for_signing_complex_structures(self):
        """Test encode_tx_for_signing with complex nested structures"""
        header = {
            "principal": "acc://complex/test",
            "timestamp": 1234567890,
            "nonce": [1, 2, 3],
            "metadata": {"version": "2.0", "flags": {"debug": True, "test": False}},
        }

        body = {
            "type": "createIdentity",
            "url": "acc://new-identity",
            "keybook": {"pages": [{"keys": ["key1", "key2"]}, {"keys": ["key3"]}]},
            "authorities": ["acc://auth1", "acc://auth2"],
        }

        result = TransactionCodec.encode_tx_for_signing(header, body)
        assert len(result) == 32

    def test_encode_tx_for_signing_unicode_handling(self):
        """Test encode_tx_for_signing with Unicode characters"""
        header = {
            "principal": "acc://测试",
            "timestamp": 1234567890,
            "memo": "Unicode test: 🌍🚀✨",
        }

        body = {
            "type": "writeData",
            "data": "Hello, 世界! 🎉",
            "description": "Testing UTF-8: àáâãäåæçèéêë",
        }

        result = TransactionCodec.encode_tx_for_signing(header, body)
        assert len(result) == 32

    def test_encode_tx_for_signing_large_data(self):
        """Test encode_tx_for_signing with large data structures"""
        # Create large header
        header = {
            "principal": "acc://large-test",
            "timestamp": 1234567890,
            "large_field": "x" * 10000,
        }

        # Create large body
        body = {
            "type": "writeData",
            "data": "y" * 50000,
            "recipients": [f"acc://recipient-{i}" for i in range(1000)],
        }

        result = TransactionCodec.encode_tx_for_signing(header, body)
        assert len(result) == 32

    def test_encode_tx_for_signing_deterministic(self):
        """Test that encode_tx_for_signing is deterministic"""
        header = {"principal": "acc://test", "timestamp": 123}
        body = {"type": "sendTokens", "amount": "100"}

        # Multiple calls should produce same result
        result1 = TransactionCodec.encode_tx_for_signing(header, body)
        result2 = TransactionCodec.encode_tx_for_signing(header, body)
        assert result1 == result2

        # Different order should produce same result (sorted keys)
        header_reordered = {"timestamp": 123, "principal": "acc://test"}
        body_reordered = {"amount": "100", "type": "sendTokens"}

        result3 = TransactionCodec.encode_tx_for_signing(header_reordered, body_reordered)
        assert result1 == result3

    def test_create_signing_preimage_simple(self):
        """Test create_signing_preimage with simple inputs"""
        sig_meta_hash = b"a" * 32
        tx_hash = b"b" * 32

        result = TransactionCodec.create_signing_preimage(sig_meta_hash, tx_hash)
        assert len(result) == 32
        assert isinstance(result, bytes)

    def test_create_signing_preimage_edge_cases(self):
        """Test create_signing_preimage with edge case inputs"""
        # All zeros
        zero_hash = b"\x00" * 32
        result = TransactionCodec.create_signing_preimage(zero_hash, zero_hash)
        assert len(result) == 32

        # All 0xFF
        max_hash = b"\xff" * 32
        result = TransactionCodec.create_signing_preimage(max_hash, max_hash)
        assert len(result) == 32

        # Different hashes
        hash1 = sha256_bytes(b"test1")
        hash2 = sha256_bytes(b"test2")
        result = TransactionCodec.create_signing_preimage(hash1, hash2)
        assert len(result) == 32

    def test_create_signing_preimage_deterministic(self):
        """Test that create_signing_preimage is deterministic"""
        sig_meta_hash = sha256_bytes(b"signature_metadata")
        tx_hash = sha256_bytes(b"transaction_data")

        # Multiple calls should produce same result
        result1 = TransactionCodec.create_signing_preimage(sig_meta_hash, tx_hash)
        result2 = TransactionCodec.create_signing_preimage(sig_meta_hash, tx_hash)
        assert result1 == result2

        # Order matters - should produce different results
        result3 = TransactionCodec.create_signing_preimage(tx_hash, sig_meta_hash)
        assert result1 != result3

    def test_integration_full_transaction_flow(self):
        """Test integration of both encoding and signing preimage creation"""
        # Step 1: Create transaction
        header = {"principal": "acc://alice/ACME", "timestamp": 1234567890, "nonce": 1}

        body = {
            "type": "sendTokens",
            "to": [{"url": "acc://bob/ACME", "amount": "100"}],
            "memo": "Payment for services",
        }

        # Step 2: Get transaction hash
        tx_hash = TransactionCodec.encode_tx_for_signing(header, body)
        assert len(tx_hash) == 32

        # Step 3: Create signature metadata (mock)
        sig_metadata = {
            "type": "ed25519",
            "publicKey": "abcd1234" * 8,  # 32 bytes hex
            "timestamp": header["timestamp"],
        }

        # Step 4: Hash signature metadata
        sig_meta_json = json.dumps(sig_metadata, separators=(",", ":"), sort_keys=True).encode(
            "utf-8"
        )
        sig_meta_hash = sha256_bytes(sig_meta_json)

        # Step 5: Create final signing preimage
        signing_preimage = TransactionCodec.create_signing_preimage(sig_meta_hash, tx_hash)
        assert len(signing_preimage) == 32

        # Verify all components are different
        assert sig_meta_hash != tx_hash
        assert signing_preimage != tx_hash
        assert signing_preimage != sig_meta_hash
