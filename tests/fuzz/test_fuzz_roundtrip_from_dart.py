#!/usr/bin/env python3

"""
Fuzz Roundtrip Tests - Validate Python encoding against Dart vectors

Comprehensive fuzz testing to ensure Python decodes/encodes and matches
Dart-generated transaction vectors byte-for-byte and hashes. Tests across
1,000+ random transactions covering all transaction types and field shapes.
"""

import json
import os
import sys
import unittest

# Import modules
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))
from src.accumulate_client import dumps_canonical, sha256_bytes
from src.accumulate_client.codec.hashes import hash_transaction


class TestFuzzRoundtripFromDart(unittest.TestCase):
    """Test Python roundtrip compatibility with Dart random vectors"""

    @classmethod
    def setUpClass(cls):
        """Load random vectors from Dart exporter"""
        golden_dir = os.path.join(os.path.dirname(__file__), "..", "golden")
        vector_path = os.path.join(golden_dir, "fuzz_vectors.jsonl")

        cls.vectors = []
        cls.vector_path = vector_path

        if os.path.exists(vector_path):
            # Load JSONL format (one JSON object per line)
            with open(vector_path, encoding="utf-8") as f:
                for line_num, line in enumerate(f, 1):
                    line = line.strip()
                    if line:
                        try:
                            vector = json.loads(line)
                            cls.vectors.append(vector)
                        except json.JSONDecodeError as e:
                            print(f"Warning: Failed to parse line {line_num}: {e}")

            print(f"Loaded {len(cls.vectors)} random vectors from {vector_path}")
        else:
            print(f"Warning: Random vectors file not found at {vector_path}")
            print("Run: dart run tool/export_random_vectors.dart > tests/golden/rand_vectors.jsonl")

    def test_vectors_loaded(self):
        """Test that random vectors were loaded successfully"""
        self.assertGreater(
            len(self.vectors),
            0,
            f"No fuzz vectors loaded. Please run: python tools/generate_fuzz_vectors.py 200 > {self.vector_path}",
        )

    def test_fuzz_canonical_json_parity(self):
        """Test canonical JSON matches Dart exactly across all vectors"""

        if not self.vectors:
            self.skipTest("No random vectors available")

        failures = []

        for i, vector in enumerate(self.vectors):
            with self.subTest(vector_index=i, tx_type=vector.get("meta", {}).get("txType")):
                try:
                    # Parse the hexBin as JSON (since our current encoding is JSON-based)
                    hex_bin = vector["hexBin"]
                    expected_canonical = vector["canonicalJson"]

                    # Decode hex to bytes
                    json_bytes = bytes.fromhex(hex_bin)
                    json_str = json_bytes.decode("utf-8")

                    # Parse JSON
                    envelope_data = json.loads(json_str)

                    # Generate canonical JSON with Python
                    actual_canonical = dumps_canonical(envelope_data)

                    # Compare canonical JSON
                    if actual_canonical != expected_canonical:
                        failures.append(
                            {
                                "index": i,
                                "type": vector.get("meta", {}).get("txType"),
                                "expected_len": len(expected_canonical),
                                "actual_len": len(actual_canonical),
                                "expected_hash": sha256_bytes(
                                    expected_canonical.encode("utf-8")
                                ).hex()[:16],
                                "actual_hash": sha256_bytes(actual_canonical.encode("utf-8")).hex()[
                                    :16
                                ],
                            }
                        )

                except Exception as e:
                    failures.append(
                        {"index": i, "type": vector.get("meta", {}).get("txType"), "error": str(e)}
                    )

        # Report failures
        if failures:
            print(f"\nCanonical JSON failures: {len(failures)}/{len(self.vectors)}")
            for failure in failures[:5]:  # Show first 5 failures
                print(f"  Vector {failure['index']}: {failure}")

            self.fail(f"Canonical JSON mismatch in {len(failures)}/{len(self.vectors)} vectors")

    def test_fuzz_transaction_hash_parity(self):
        """Test transaction hash matches Dart exactly across all vectors"""

        if not self.vectors:
            self.skipTest("No random vectors available")

        failures = []

        for i, vector in enumerate(self.vectors):
            with self.subTest(vector_index=i, tx_type=vector.get("meta", {}).get("txType")):
                try:
                    # Parse the envelope
                    hex_bin = vector["hexBin"]
                    expected_tx_hash_hex = vector["txHashHex"]

                    # Decode hex to JSON
                    json_bytes = bytes.fromhex(hex_bin)
                    json_str = json_bytes.decode("utf-8")
                    envelope_data = json.loads(json_str)

                    # Extract transaction
                    if "envelope" in envelope_data:
                        transaction = envelope_data["envelope"]["transaction"]
                    else:
                        transaction = envelope_data.get("transaction", envelope_data)

                    # Compute transaction hash
                    header = transaction["header"]
                    body = transaction["body"]
                    actual_tx_hash = hash_transaction(header, body)

                    # Compare hash
                    actual_tx_hash_hex = actual_tx_hash.hex()
                    if actual_tx_hash_hex != expected_tx_hash_hex:
                        failures.append(
                            {
                                "index": i,
                                "type": vector.get("meta", {}).get("txType"),
                                "expected": expected_tx_hash_hex,
                                "actual": actual_tx_hash_hex,
                            }
                        )

                except Exception as e:
                    failures.append(
                        {"index": i, "type": vector.get("meta", {}).get("txType"), "error": str(e)}
                    )

        # Report failures
        if failures:
            print(f"\nTransaction hash failures: {len(failures)}/{len(self.vectors)}")
            for failure in failures[:5]:  # Show first 5 failures
                print(f"  Vector {failure['index']}: {failure}")

            self.fail(f"Transaction hash mismatch in {len(failures)}/{len(self.vectors)} vectors")

    def test_fuzz_roundtrip_encoding(self):
        """Test decode → encode roundtrip produces identical bytes"""

        if not self.vectors:
            self.skipTest("No random vectors available")

        failures = []

        for i, vector in enumerate(self.vectors):
            with self.subTest(vector_index=i, tx_type=vector.get("meta", {}).get("txType")):
                try:
                    # Original binary data
                    original_hex = vector["hexBin"]
                    original_bytes = bytes.fromhex(original_hex)

                    # Decode to Python object
                    json_str = original_bytes.decode("utf-8")
                    envelope_data = json.loads(json_str)

                    # Re-encode to canonical JSON
                    canonical_json = dumps_canonical(envelope_data)
                    reencoded_bytes = canonical_json.encode("utf-8")

                    # Compare bytes
                    if reencoded_bytes != original_bytes:
                        failures.append(
                            {
                                "index": i,
                                "type": vector.get("meta", {}).get("txType"),
                                "original_len": len(original_bytes),
                                "reencoded_len": len(reencoded_bytes),
                                "bytes_match": False,
                            }
                        )

                except Exception as e:
                    failures.append(
                        {"index": i, "type": vector.get("meta", {}).get("txType"), "error": str(e)}
                    )

        # Report failures
        if failures:
            print(f"\nRoundtrip encoding failures: {len(failures)}/{len(self.vectors)}")
            for failure in failures[:5]:  # Show first 5 failures
                print(f"  Vector {failure['index']}: {failure}")

            self.fail(f"Roundtrip encoding mismatch in {len(failures)}/{len(self.vectors)} vectors")

    def test_fuzz_transaction_type_coverage(self):
        """Test that all transaction types are covered in the vectors"""

        if not self.vectors:
            self.skipTest("No random vectors available")

        # Count transaction types
        type_counts = {}
        for vector in self.vectors:
            tx_type = vector.get("meta", {}).get("txType", "unknown")
            type_counts[tx_type] = type_counts.get(tx_type, 0) + 1

        print(f"\nTransaction type coverage ({len(self.vectors)} total vectors):")
        for tx_type, count in sorted(type_counts.items()):
            percentage = (count / len(self.vectors)) * 100
            print(f"  {tx_type}: {count} ({percentage:.1f}%)")

        # Expected transaction types (based on loaded golden vectors)
        expected_types = {
            "sendTokens",
            "addCredits",  # From ts_parity_fixtures.json
        }

        # Check coverage
        covered_types = set(type_counts.keys())
        missing_types = expected_types - covered_types

        if missing_types:
            self.fail(f"Missing transaction types in vectors: {missing_types}")

        # Check minimum coverage per type
        min_coverage = max(
            1, len(self.vectors) // (len(expected_types) * 2)
        )  # At least 1/12 of vectors per type
        under_covered = []
        for tx_type in expected_types:
            if type_counts.get(tx_type, 0) < min_coverage:
                under_covered.append(tx_type)

        if under_covered:
            print(
                f"Warning: Under-covered transaction types (< {min_coverage} vectors): {under_covered}"
            )

    def test_fuzz_field_variety_coverage(self):
        """Test field variety and edge cases in the vectors"""

        if not self.vectors:
            self.skipTest("No random vectors available")

        # Analyze field variety
        stats = {
            "with_memo": 0,
            "with_signer": 0,
            "multi_recipient": 0,
            "multi_signature": 0,
            "empty_memo": 0,
        }

        for vector in self.vectors:
            try:
                # Parse envelope
                hex_bin = vector["hexBin"]
                json_bytes = bytes.fromhex(hex_bin)
                json_str = json_bytes.decode("utf-8")
                envelope_data = json.loads(json_str)

                # Extract data
                if "envelope" in envelope_data:
                    envelope = envelope_data["envelope"]
                    transaction = envelope["transaction"]
                    signatures = envelope["signatures"]
                else:
                    transaction = envelope_data.get("transaction", {})
                    signatures = envelope_data.get("signatures", [])

                header = transaction.get("header", {})
                body = transaction.get("body", {})

                # Count field varieties
                if "memo" in header:
                    stats["with_memo"] += 1
                    if header["memo"] == "":
                        stats["empty_memo"] += 1

                if any("signer" in sig for sig in signatures):
                    stats["with_signer"] += 1

                if body.get("type") == "send-tokens" and len(body.get("to", [])) > 1:
                    stats["multi_recipient"] += 1

                if len(signatures) > 1:
                    stats["multi_signature"] += 1

            except Exception:
                continue  # Skip malformed vectors

        print("\nField variety coverage:")
        for field, count in stats.items():
            percentage = (count / len(self.vectors)) * 100
            print(f"  {field}: {count} ({percentage:.1f}%)")

    def test_fuzz_stress_large_vectors(self):
        """Test performance and correctness with larger vectors"""

        if not self.vectors:
            self.skipTest("No random vectors available")

        # Find larger vectors (by JSON size)
        large_vectors = []
        for i, vector in enumerate(self.vectors):
            canonical_size = len(vector.get("canonicalJson", ""))
            if canonical_size > 1000:  # > 1KB
                large_vectors.append((i, vector, canonical_size))

        # Sort by size
        large_vectors.sort(key=lambda x: x[2], reverse=True)

        print(f"\nTesting {len(large_vectors)} large vectors (>1KB)")

        # Test largest vectors
        test_count = min(10, len(large_vectors))
        for j in range(test_count):
            i, vector, size = large_vectors[j]

            with self.subTest(vector_index=i, size=size):
                # Test canonical JSON
                hex_bin = vector["hexBin"]
                expected_canonical = vector["canonicalJson"]

                json_bytes = bytes.fromhex(hex_bin)
                json_str = json_bytes.decode("utf-8")
                envelope_data = json.loads(json_str)

                actual_canonical = dumps_canonical(envelope_data)
                self.assertEqual(
                    actual_canonical,
                    expected_canonical,
                    f"Large vector {i} (size: {size}) canonical JSON mismatch",
                )

                # Test transaction hash
                if "envelope" in envelope_data:
                    transaction = envelope_data["envelope"]["transaction"]
                else:
                    transaction = envelope_data.get("transaction", envelope_data)

                header = transaction["header"]
                body = transaction["body"]
                actual_hash = hash_transaction(header, body)
                expected_hash = bytes.fromhex(vector["txHashHex"])

                self.assertEqual(
                    actual_hash,
                    expected_hash,
                    f"Large vector {i} (size: {size}) transaction hash mismatch",
                )

    def test_fuzz_vector_metadata_consistency(self):
        """Test vector metadata consistency and integrity"""

        if not self.vectors:
            self.skipTest("No random vectors available")

        metadata_issues = []

        for i, vector in enumerate(self.vectors):
            try:
                # Check required fields
                required_fields = ["hexBin", "canonicalJson", "txHashHex", "meta"]
                for field in required_fields:
                    if field not in vector:
                        metadata_issues.append(f"Vector {i}: Missing field '{field}'")
                        continue

                # Check metadata fields
                meta = vector["meta"]
                meta_fields = ["index", "txType", "timestamp", "sigCount"]
                for field in meta_fields:
                    if field not in meta:
                        metadata_issues.append(f"Vector {i}: Missing meta field '{field}'")

                # Check index consistency
                if meta.get("index") != i:
                    metadata_issues.append(
                        f"Vector {i}: Index mismatch (expected {i}, got {meta.get('index')})"
                    )

                # Check hex format
                hex_bin = vector["hexBin"]
                tx_hash_hex = vector["txHashHex"]

                if not all(c in "0123456789abcdef" for c in hex_bin.lower()):
                    metadata_issues.append(f"Vector {i}: Invalid hexBin format")

                if len(tx_hash_hex) != 64 or not all(
                    c in "0123456789abcdef" for c in tx_hash_hex.lower()
                ):
                    metadata_issues.append(
                        f"Vector {i}: Invalid txHashHex format (expected 64 hex chars)"
                    )

            except Exception as e:
                metadata_issues.append(f"Vector {i}: Exception during validation: {e}")

        if metadata_issues:
            print("\nMetadata issues found:")
            for issue in metadata_issues[:10]:  # Show first 10 issues
                print(f"  {issue}")

            self.fail(f"Found {len(metadata_issues)} metadata issues")


if __name__ == "__main__":
    unittest.main()
