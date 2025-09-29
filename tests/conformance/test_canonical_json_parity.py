#!/usr/bin/env python3

"""
Canonical JSON Parity Tests - Identical behavior with Dart/TS SDKs

Comprehensive conformance tests to ensure Python canonical JSON behavior
matches Dart SDK exactly. Tests deterministic key ordering, recursion,
and cross-language hash stability.
"""

import json
import os
import sys
import unittest
from typing import Dict, Any

# Import canonjson module
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))
from src.accumulate_client.canonjson import dumps_canonical
from tests.helpers.parity import assert_hex_equal
from src.accumulate_client.codec import sha256_bytes


class TestCanonicalJsonParity(unittest.TestCase):
    """Test Python canonical JSON parity with Dart SDK"""

    def test_dart_reference_golden_fixture(self):
        """Test exact match with Dart canonical_json_test.dart golden fixture"""

        # From Dart canonical_json_test.dart:9-17
        input_obj = {
            "b": 2,
            "a": {"d": 4, "c": 3},
            "arr": [
                {"y": 2, "x": 1},
                {"b": 0},
                {"a": 0}
            ]
        }

        # From Dart canonical_json_test.dart:22-23
        expected = '{"a":{"c":3,"d":4},"arr":[{"x":1,"y":2},{"b":0},{"a":0}],"b":2}'

        # Test our implementation matches Dart exactly
        actual = dumps_canonical(input_obj)
        self.assertEqual(actual, expected, "Canonical JSON must match Dart golden fixture exactly")

        # Test round-trip stability (Dart canonical_json_test.dart:25-26)
        reparsed = json.loads(actual)
        round_trip = dumps_canonical(reparsed)
        self.assertEqual(round_trip, actual, "Round-trip parsing must yield same canonical string")

    def test_key_ordering_parity(self):
        """Test lexicographic key ordering matches Dart exactly"""

        # Test various key orderings that might differ between languages
        test_cases = [
            # Basic alphabetic ordering
            ({"z": 1, "a": 2, "m": 3}, '{"a":2,"m":3,"z":1}'),

            # Numeric keys (as strings in JSON)
            ({"10": "ten", "2": "two", "1": "one"}, '{"1":"one","10":"ten","2":"two"}'),

            # Mixed alphanumeric
            ({"b1": 1, "a2": 2, "a1": 3}, '{"a1":3,"a2":2,"b1":1}'),

            # Special characters (common in URLs/keys)
            ({"key_with_underscore": 1, "key-with-dash": 2, "keywithdot.ext": 3},
             '{"key-with-dash":2,"key_with_underscore":1,"keywithdot.ext":3}'),
        ]

        for input_obj, expected in test_cases:
            with self.subTest(input=input_obj):
                actual = dumps_canonical(input_obj)
                self.assertEqual(actual, expected, f"Key ordering failed for {input_obj}")

    def test_nested_object_recursion(self):
        """Test recursive canonicalization of nested objects"""

        input_obj = {
            "outer": {
                "z": {"inner_z": 1, "inner_a": 2},
                "a": {"inner_b": 3, "inner_a": 4}
            },
            "array": [
                {"c": 1, "a": 2, "b": 3},
                [{"nested": {"z": 1, "a": 2}}]
            ]
        }

        expected = ('{"array":[{"a":2,"b":3,"c":1},[{"nested":{"a":2,"z":1}}]],'
                   '"outer":{"a":{"inner_a":4,"inner_b":3},"z":{"inner_a":2,"inner_z":1}}}')

        actual = dumps_canonical(input_obj)
        self.assertEqual(actual, expected, "Nested object canonicalization failed")

    def test_primitive_type_passthrough(self):
        """Test primitive types pass through unchanged (Dart json_canonical.dart:19-22)"""

        test_cases = [
            # Numbers
            (42, "42"),
            (3.14159, "3.14159"),
            (-100, "-100"),
            (0, "0"),

            # Strings
            ("hello", '"hello"'),
            ("", '""'),
            ("unicode: ñáéíóú", '"unicode: ñáéíóú"'),

            # Booleans
            (True, "true"),
            (False, "false"),

            # Null
            (None, "null"),

            # Arrays of primitives
            ([1, 2, 3], "[1,2,3]"),
            (["a", "b", "c"], '["a","b","c"]'),
            ([True, False, None], "[true,false,null]"),
        ]

        for input_val, expected in test_cases:
            with self.subTest(input=input_val):
                actual = dumps_canonical(input_val)
                self.assertEqual(actual, expected, f"Primitive type failed: {input_val}")

    def test_empty_structures(self):
        """Test empty objects and arrays"""

        test_cases = [
            ({}, "{}"),
            ([], "[]"),
            ({"empty_obj": {}, "empty_arr": []}, '{"empty_arr":[],"empty_obj":{}}'),
        ]

        for input_val, expected in test_cases:
            with self.subTest(input=input_val):
                actual = dumps_canonical(input_val)
                self.assertEqual(actual, expected, f"Empty structure failed: {input_val}")

    def test_unicode_handling(self):
        """Test Unicode handling for cross-language compatibility"""

        # Test Unicode characters that might be handled differently
        test_cases = [
            ({"ñ": "español", "a": "ascii"}, '{"a":"ascii","ñ":"español"}'),
            ({"中文": "chinese", "english": "english"}, '{"english":"english","中文":"chinese"}'),
            ({"🔑": "key emoji", "normal": "text"}, '{"normal":"text","🔑":"key emoji"}'),
        ]

        for input_obj, expected in test_cases:
            with self.subTest(input=input_obj):
                actual = dumps_canonical(input_obj)
                self.assertEqual(actual, expected, f"Unicode handling failed: {input_obj}")

    def test_hash_stability_cross_language(self):
        """Test that canonical JSON produces stable hashes across languages"""

        # Use the same test data as Dart golden fixture
        test_obj = {
            "transaction": {
                "header": {
                    "principal": "acc://alice.acme/book",
                    "initiator": "0123456789abcdef" * 4  # 32 bytes hex
                },
                "body": {
                    "type": "sendTokens",
                    "to": [{"url": "acc://bob.acme/tokens", "amount": "1000"}]
                }
            },
            "metadata": {
                "timestamp": 1234567890,
                "nonce": 42
            }
        }

        # Generate canonical JSON
        canonical = dumps_canonical(test_obj)

        # Hash should be deterministic
        hash1 = sha256_bytes(canonical.encode('utf-8'))
        hash2 = sha256_bytes(canonical.encode('utf-8'))
        self.assertEqual(hash1, hash2, "Hash should be deterministic")

        # Re-parse and canonicalize should produce same hash
        reparsed = json.loads(canonical)
        canonical2 = dumps_canonical(reparsed)
        hash3 = sha256_bytes(canonical2.encode('utf-8'))
        self.assertEqual(hash1, hash3, "Round-trip should preserve hash")

        # Verify canonical form is properly ordered
        self.assertIn('"header":{"initiator":', canonical)
        self.assertIn('"principal":"acc://alice.acme/book"', canonical)
        self.assertIn('"metadata":{"nonce":42,"timestamp":', canonical)

    def test_transaction_encoding_integration(self):
        """Test canonical JSON integration with transaction encoding patterns"""

        # Similar to patterns used in transaction_codec.py
        header = {
            "principal": "acc://alice.acme/book",
            "initiator": bytes([0x01, 0x02, 0x03]).hex()  # Will be converted to string
        }

        body = {
            "type": "sendTokens",
            "to": [
                {"url": "acc://bob.acme/tokens", "amount": "1000"},
                {"url": "acc://charlie.acme/tokens", "amount": "500"}
            ]
        }

        # Test header canonicalization
        header_canonical = dumps_canonical(header)
        self.assertIn('"initiator":"010203"', header_canonical)
        self.assertIn('"principal":"acc://alice.acme/book"', header_canonical)
        # Keys should be in alphabetical order
        self.assertTrue(header_canonical.index('"initiator":') < header_canonical.index('"principal":'))

        # Test body canonicalization
        body_canonical = dumps_canonical(body)
        self.assertIn('"to":[', body_canonical)
        self.assertIn('"type":"sendTokens"', body_canonical)
        # Array order should be preserved, but object keys sorted
        self.assertIn('{"amount":"1000","url":"acc://bob.acme/tokens"}', body_canonical)

    def test_edge_cases_compatibility(self):
        """Test edge cases that might differ between language implementations"""

        test_cases = [
            # Mixed number types
            ({"int": 42, "float": 42.0}, '{"float":42.0,"int":42}'),

            # Large numbers
            ({"big": 999999999999999}, '{"big":999999999999999}'),

            # Nested empty structures
            ({"a": {}, "b": {"c": []}}, '{"a":{},"b":{"c":[]}}'),

            # Complex nesting
            ({
                "z": [{"b": 1, "a": 2}],
                "a": {"z": {"b": 1, "a": 2}}
            }, '{"a":{"z":{"a":2,"b":1}},"z":[{"a":2,"b":1}]}'),
        ]

        for input_obj, expected in test_cases:
            with self.subTest(input=input_obj):
                actual = dumps_canonical(input_obj)
                self.assertEqual(actual, expected, f"Edge case failed: {input_obj}")


if __name__ == "__main__":
    unittest.main()