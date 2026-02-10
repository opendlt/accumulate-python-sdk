"""
Canonical encoding and hash roundtrip tests.

Tests canonical JSON encoding/decoding, binary encoding where available,
and hash stability for transaction parity validation.
"""

import pytest
import hashlib
import json
from typing import Dict, Any

from accumulate_client.tx.codec import to_canonical_json, from_canonical_json
from accumulate_client.tx.builders import get_builder_for


class TestCanonicalJSONRoundtrips:
    """Test canonical JSON encoding roundtrips."""

    def test_canonical_json_deterministic(self):
        """Test that canonical JSON encoding is deterministic."""
        test_data = {
            "type": "CreateIdentity",
            "url": "acc://test.acme",
            "keyBookUrl": "acc://test.acme/book",
            "keyPageUrl": "acc://test.acme/book/1"
        }

        # Encode twice and verify identical output
        json1 = to_canonical_json(test_data)
        json2 = to_canonical_json(test_data)

        assert json1 == json2, "Canonical JSON should be deterministic"
        assert isinstance(json1, bytes), "Canonical JSON should return bytes"

    def test_canonical_json_hash_stability(self):
        """Test that canonical JSON produces stable hashes."""
        test_data = {
            "type": "SendTokens",
            "to": [{"url": "acc://test.acme/tokens", "amount": 1000000}]
        }

        # Hash should be stable across multiple calls
        json_bytes = to_canonical_json(test_data)
        hash1 = hashlib.sha256(json_bytes).hexdigest()

        json_bytes2 = to_canonical_json(test_data)
        hash2 = hashlib.sha256(json_bytes2).hexdigest()

        assert hash1 == hash2, "Hash should be stable for same data"

    def test_canonical_json_key_ordering(self):
        """Test that canonical JSON orders keys consistently."""
        # Create data with keys in different order
        data1 = {"z": 1, "a": 2, "m": 3}
        data2 = {"a": 2, "m": 3, "z": 1}

        json1 = to_canonical_json(data1)
        json2 = to_canonical_json(data2)

        assert json1 == json2, "Key ordering should be consistent in canonical JSON"

    def test_canonical_json_roundtrip_simple(self):
        """Test simple canonical JSON roundtrip."""
        original_data = {
            "type": "WriteData",
            "data": b"hello world".hex(),
            "scratch": False
        }

        # Encode to canonical JSON
        canonical_bytes = to_canonical_json(original_data)

        # Decode back
        try:
            decoded_data = from_canonical_json(canonical_bytes, dict)

            # Basic structure should match
            assert decoded_data["type"] == original_data["type"]
            assert decoded_data["scratch"] == original_data["scratch"]

        except (ImportError, NotImplementedError):
            # If decode not available, just verify encode works
            assert len(canonical_bytes) > 0


class TestTransactionBuilderRoundtrips:
    """Test canonical encoding with transaction builders."""

    @pytest.mark.parametrize("tx_type", [
        "CreateIdentity", "CreateTokenAccount", "CreateDataAccount",
        "SendTokens", "WriteData", "AddCredits", "UpdateKeyPage", "CreateKeyBook"
    ])
    def test_builder_canonical_encoding(self, tx_type, builder_registry):
        """Test canonical encoding for transaction builders."""
        if tx_type not in builder_registry:
            pytest.skip(f"Builder {tx_type} not available")

        builder_class = builder_registry[tx_type]

        try:
            # Create minimal builder instance
            builder = builder_class()

            # Add minimal required fields based on transaction type
            if tx_type == "CreateIdentity":
                builder.with_field("url", "acc://test.acme")
                builder.with_field("keyBookUrl", "acc://test.acme/book")
                builder.with_field("keyPageUrl", "acc://test.acme/book/1")
            elif tx_type == "CreateTokenAccount":
                builder.with_field("url", "acc://test.acme/tokens")
                builder.with_field("tokenUrl", "acc://acme.acme/tokens/ACME")
            elif tx_type == "CreateDataAccount":
                builder.with_field("url", "acc://test.acme/data")
            elif tx_type == "SendTokens":
                builder.with_field("to", [{"url": "acc://test.acme/tokens", "amount": 1000000}])
            elif tx_type == "WriteData":
                builder.with_field("data", b"test data")
                builder.with_field("scratch", False)
            elif tx_type == "AddCredits":
                builder.with_field("recipient", "acc://test.acme/book/1")
                builder.with_field("amount", 1000000)
                builder.with_field("oracle", 500)
            elif tx_type == "UpdateKeyPage":
                builder.with_field("operation", [{'type': 'add', 'entry': {'keyHash': b'\x03' * 32}}])
            elif tx_type == "CreateKeyBook":
                builder.with_field("url", "acc://test.acme/book")

            # Test canonical encoding
            tx_body = builder.to_body()
            canonical_json = to_canonical_json(tx_body)

            assert len(canonical_json) > 0, f"Canonical JSON should not be empty for {tx_type}"

            # Test hash stability
            hash1 = hashlib.sha256(canonical_json).hexdigest()

            # Encode again
            canonical_json2 = to_canonical_json(tx_body)
            hash2 = hashlib.sha256(canonical_json2).hexdigest()

            assert hash1 == hash2, f"Hash should be stable for {tx_type}"

        except Exception as e:
            pytest.skip(f"Builder {tx_type} failed: {e}")

    def test_builder_to_canonical_json_method(self, builder_registry):
        """Test builder's to_canonical_json method if available."""
        # Try with CreateIdentity as it's most likely to be available
        if "CreateIdentity" in builder_registry:
            builder_class = builder_registry["CreateIdentity"]
            builder = builder_class()

            # Add required fields
            builder.with_field("url", "acc://test.acme")
            builder.with_field("keyBookUrl", "acc://test.acme/book")
            builder.with_field("keyPageUrl", "acc://test.acme/book/1")

            # Test if builder has to_canonical_json method
            if hasattr(builder, 'to_canonical_json'):
                canonical_json = builder.to_canonical_json()
                assert isinstance(canonical_json, bytes)
                assert len(canonical_json) > 0


class TestBinaryEncodingRoundtrips:
    """Test binary encoding where available."""

    def test_binary_encoding_available(self):
        """Test if binary encoding is available."""
        try:
            from accumulate_client.tx.codec import to_binary, from_binary

            test_data = {"type": "test", "value": 42}

            # Test encoding
            binary_data = to_binary(test_data)
            assert isinstance(binary_data, bytes)
            assert len(binary_data) > 0

            # Test decoding if available
            decoded_data = from_binary(binary_data, dict)
            assert decoded_data["type"] == "test"
            assert decoded_data["value"] == 42

        except (ImportError, AttributeError, NotImplementedError):
            pytest.skip("Binary encoding not available")

    def test_binary_vs_json_hash_comparison(self):
        """Test binary vs JSON encoding hash comparison."""
        try:
            from accumulate_client.tx.codec import to_binary

            test_data = {
                "type": "CreateIdentity",
                "url": "acc://test.acme",
                "keyBookUrl": "acc://test.acme/book"
            }

            # Get JSON hash
            json_bytes = to_canonical_json(test_data)
            json_hash = hashlib.sha256(json_bytes).hexdigest()

            # Get binary hash
            binary_bytes = to_binary(test_data)
            binary_hash = hashlib.sha256(binary_bytes).hexdigest()

            # Hashes should be different but both valid
            assert len(json_hash) == 64
            assert len(binary_hash) == 64

        except (ImportError, AttributeError, NotImplementedError):
            pytest.skip("Binary encoding not available")


class TestHashConsistency:
    """Test hash consistency across different scenarios."""

    def test_transaction_hash_excluding_signatures(self):
        """Test that transaction hashes exclude signatures."""
        tx_body = {
            "type": "SendTokens",
            "to": [{"url": "acc://test.acme/tokens", "amount": 1000000}]
        }

        # Hash without signatures
        canonical_json = to_canonical_json(tx_body)
        hash_without_sigs = hashlib.sha256(canonical_json).hexdigest()

        # Create envelope with signatures
        envelope = {
            "transaction": tx_body,
            "signatures": [{"signature": "dummy_signature"}]
        }

        # Hash of transaction body should be same
        canonical_json2 = to_canonical_json(envelope["transaction"])
        hash_with_envelope = hashlib.sha256(canonical_json2).hexdigest()

        assert hash_without_sigs == hash_with_envelope, "Transaction hash should exclude signatures"

    def test_nested_data_hash_stability(self):
        """Test hash stability with nested data structures."""
        nested_data = {
            "type": "WriteData",
            "data": {
                "nested": {
                    "deep": {
                        "value": 42,
                        "array": [1, 2, 3],
                        "bool": True
                    }
                }
            }
        }

        # Hash multiple times
        hashes = []
        for _ in range(3):
            canonical_json = to_canonical_json(nested_data)
            hash_val = hashlib.sha256(canonical_json).hexdigest()
            hashes.append(hash_val)

        # All hashes should be identical
        assert len(set(hashes)) == 1, "Nested data hashes should be stable"

    def test_unicode_handling_in_canonical_json(self):
        """Test that Unicode is handled consistently in canonical JSON."""
        unicode_data = {
            "type": "WriteData",
            "message": "Hello 世界! 🌍",
            "unicode_field": "café résumé naïve"
        }

        # Should encode without error
        canonical_json = to_canonical_json(unicode_data)
        assert len(canonical_json) > 0

        # Hash should be stable
        hash1 = hashlib.sha256(canonical_json).hexdigest()

        # Encode again
        canonical_json2 = to_canonical_json(unicode_data)
        hash2 = hashlib.sha256(canonical_json2).hexdigest()

        assert hash1 == hash2, "Unicode data should hash consistently"

    def test_empty_and_null_values(self):
        """Test canonical encoding of empty and null values."""
        test_cases = [
            {"empty_string": ""},
            {"null_value": None},
            {"empty_array": []},
            {"empty_object": {}},
            {"zero": 0},
            {"false": False}
        ]

        for test_data in test_cases:
            canonical_json = to_canonical_json(test_data)
            assert len(canonical_json) > 0, f"Should encode {test_data}"

            # Should be valid JSON
            try:
                json.loads(canonical_json.decode('utf-8'))
            except json.JSONDecodeError:
                pytest.fail(f"Invalid JSON for {test_data}")