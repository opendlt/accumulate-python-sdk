#!/usr/bin/env python3

"""
Fuzz Vector Generator - Generate systematic variations of golden vectors

Creates deterministic variations of existing golden transaction vectors for comprehensive
fuzz testing. Uses existing proven transactions and systematically varies parameters
to create large test sets while maintaining compatibility.

Usage:
    python tooling/generate_fuzz_vectors.py [count] > tests/golden/fuzz_vectors.jsonl
    python tooling/generate_fuzz_vectors.py 200 > tests/golden/fuzz_vectors.jsonl
"""

import json
import os
import sys
import random
from typing import Dict, Any, List

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from src.accumulate_client import dumps_canonical, TransactionCodec


class FuzzVectorGenerator:
    """Generate systematic variations of golden vectors for fuzz testing"""

    def __init__(self, seed: int = 42):
        """Initialize with deterministic seed"""
        self.rng = random.Random(seed)
        self.base_vectors = self.load_base_vectors()

    def load_base_vectors(self) -> List[Dict[str, Any]]:
        """Load base vectors from existing golden files"""
        base_vectors = []

        # Load golden vectors directory
        golden_dir = os.path.join(os.path.dirname(__file__), "..", "tests", "golden")

        # Load transaction vectors from ts_parity_fixtures
        ts_fixtures_path = os.path.join(golden_dir, "ts_parity_fixtures.json")
        if os.path.exists(ts_fixtures_path):
            with open(ts_fixtures_path, "r") as f:
                ts_data = json.load(f)
                # Extract transaction vectors
                for vector in ts_data.get("transaction_vectors", []):
                    if "transaction" in vector:
                        base_vectors.append(vector["transaction"])
                # Extract envelope vectors
                for vector in ts_data.get("envelope_vectors", []):
                    if "envelope" in vector and "transaction" in vector["envelope"]:
                        base_vectors.append(vector["envelope"]["transaction"])

        # Load envelope vector
        envelope_path = os.path.join(golden_dir, "envelope_fixed.golden.json")
        if os.path.exists(envelope_path):
            with open(envelope_path, "r") as f:
                envelope_data = json.load(f)
                if "transaction" in envelope_data:
                    base_vectors.append(envelope_data["transaction"])

        print(f"Loaded {len(base_vectors)} base vectors with types: {[v.get('body', {}).get('type', 'unknown') for v in base_vectors]}", file=sys.stderr)
        return base_vectors

    def generate_fuzz_vectors(self, count: int) -> List[Dict[str, Any]]:
        """Generate count fuzz vectors by varying base vectors"""
        vectors = []

        for i in range(count):
            # Select base vector cyclically
            base_idx = i % len(self.base_vectors) if self.base_vectors else 0
            base_vector = self.base_vectors[base_idx] if self.base_vectors else self.create_default_vector()

            # Generate variation
            fuzz_vector = self.create_fuzz_vector(i, base_vector)
            vectors.append(fuzz_vector)

        return vectors

    def create_default_vector(self) -> Dict[str, Any]:
        """Create a default vector if no base vectors available"""
        return {
            "transaction": {
                "header": {
                    "principal": "acc://test.acme/book",
                    "timestamp": 1234567890
                },
                "body": {
                    "type": "sendTokens",
                    "to": [{"url": "acc://recipient.acme/tokens", "amount": "1000"}]
                }
            }
        }

    def create_fuzz_vector(self, index: int, base_vector: Dict[str, Any]) -> Dict[str, Any]:
        """Create a fuzz vector by systematically varying a base vector"""


        # Create transaction from base vector
        if "header" in base_vector and "body" in base_vector:
            # This is already a transaction
            transaction = self.vary_transaction(base_vector, index)
        elif "transaction" in base_vector:
            transaction = self.vary_transaction(base_vector["transaction"], index)
        else:
            # Convert other formats to transaction format
            transaction = self.convert_to_transaction(base_vector, index)

        # Encode as canonical JSON
        canonical_json = dumps_canonical(transaction)
        canonical_bytes = canonical_json.encode('utf-8')

        # Compute transaction hash
        header = transaction["header"]
        body = transaction["body"]
        tx_hash = TransactionCodec.encode_tx_for_signing(header, body)

        return {
            "hexBin": canonical_bytes.hex(),
            "canonicalJson": canonical_json,
            "txHashHex": tx_hash.hex(),
            "meta": {
                "index": index,
                "txType": body.get("type", "unknown"),
                "timestamp": header.get("timestamp", 0),
                "sigCount": 1,
                "baseVector": "synthetic"
            }
        }

    def vary_transaction(self, base_tx: Dict[str, Any], index: int) -> Dict[str, Any]:
        """Create systematic variations of a transaction"""
        tx = json.loads(json.dumps(base_tx))  # Deep copy

        # Vary header
        header = tx.get("header", {})
        header = self.vary_header(header, index)
        tx["header"] = header

        # Vary body
        body = tx.get("body", {})
        body = self.vary_body(body, index)
        tx["body"] = body

        return tx

    def vary_header(self, base_header: Dict[str, Any], index: int) -> Dict[str, Any]:
        """Create systematic variations of transaction header"""
        header = base_header.copy()

        # Vary timestamp systematically
        base_timestamp = header.get("timestamp", 1234567890)
        header["timestamp"] = base_timestamp + (index * 3600)  # Add hours

        # Vary principal systematically
        principals = [
            "acc://alice.acme/book",
            "acc://bob.test/book",
            "acc://charlie.example/book",
            "acc://test.acme/keybook/1",
            "acc://demo.corp/keys/0"
        ]
        header["principal"] = principals[index % len(principals)]

        # Add memo for some variations
        if index % 3 == 0:
            memos = [
                "Test transaction",
                "Fuzz test variation",
                "Cross-language compatibility test",
                "",
                "Generated for testing"
            ]
            header["memo"] = memos[index % len(memos)]
        elif "memo" in header:
            del header["memo"]

        return header

    def vary_body(self, base_body: Dict[str, Any], index: int) -> Dict[str, Any]:
        """Create systematic variations of transaction body"""
        body = base_body.copy()
        tx_type = body.get("type", "sendTokens")

        if tx_type == "sendTokens":
            body = self.vary_send_tokens_body(body, index)
        elif tx_type == "addCredits":
            body = self.vary_add_credits_body(body, index)
        elif tx_type == "createIdentity":
            body = self.vary_create_identity_body(body, index)
        elif tx_type == "createTokenAccount":
            body = self.vary_create_token_account_body(body, index)
        else:
            # For other types, just vary amounts or strings if present
            body = self.vary_generic_body(body, index)

        return body

    def vary_send_tokens_body(self, base_body: Dict[str, Any], index: int) -> Dict[str, Any]:
        """Vary sendTokens transaction body"""
        body = base_body.copy()

        # Vary recipient count and amounts
        recipient_patterns = [
            [{"url": "acc://alice.acme/tokens", "amount": "1000"}],
            [{"url": "acc://bob.test/ACME", "amount": "500"}],
            [
                {"url": "acc://charlie.demo/tokens", "amount": "250"},
                {"url": "acc://david.corp/ACME", "amount": "750"}
            ],
            [
                {"url": "acc://eve.example/tokens", "amount": "100"},
                {"url": "acc://frank.test/ACME", "amount": "200"},
                {"url": "acc://grace.acme/credits", "amount": "300"}
            ]
        ]

        pattern = recipient_patterns[index % len(recipient_patterns)]
        body["to"] = pattern

        return body

    def vary_add_credits_body(self, base_body: Dict[str, Any], index: int) -> Dict[str, Any]:
        """Vary addCredits transaction body"""
        body = base_body.copy()

        # Vary recipient URL
        recipients = [
            "acc://alice.acme",
            "acc://bob.test",
            "acc://charlie.demo",
            "acc://test-account.example"
        ]
        recipient_url = recipients[index % len(recipients)]
        if "recipient" in body and isinstance(body["recipient"], dict):
            body["recipient"]["url"] = recipient_url

        # Vary amount
        amounts = ["1000000", "500000", "250000", "100000", "50000"]
        body["amount"] = amounts[index % len(amounts)]

        return body

    def vary_create_identity_body(self, base_body: Dict[str, Any], index: int) -> Dict[str, Any]:
        """Vary createIdentity transaction body"""
        body = base_body.copy()

        # Vary URL
        urls = [
            "acc://alice.acme",
            "acc://bob.test",
            "acc://charlie.demo",
            "acc://test-identity.example"
        ]
        body["url"] = urls[index % len(urls)]

        # Vary key book name
        key_books = ["book", "keybook", "keys", "primary"]
        if "keyBookName" in body:
            body["keyBookName"] = key_books[index % len(key_books)]

        # Vary public key hash
        if "publicKeyHash" in body:
            # Generate deterministic but different hash
            hash_base = f"variation{index:04d}"
            body["publicKeyHash"] = hash_base.ljust(64, '0')

        return body

    def vary_create_token_account_body(self, base_body: Dict[str, Any], index: int) -> Dict[str, Any]:
        """Vary createTokenAccount transaction body"""
        body = base_body.copy()

        # Vary URL
        urls = [
            "acc://alice.acme/tokens",
            "acc://bob.test/ACME",
            "acc://charlie.demo/credits",
            "acc://test.example/rewards"
        ]
        body["url"] = urls[index % len(urls)]

        # Vary token
        tokens = ["acc://acme", "acc://test.acme", "acc://tokens.example"]
        if "token" in body:
            body["token"] = tokens[index % len(tokens)]

        return body

    def vary_generic_body(self, base_body: Dict[str, Any], index: int) -> Dict[str, Any]:
        """Generic body variation for unknown transaction types"""
        body = base_body.copy()

        # Vary any amount fields
        if "amount" in body:
            amounts = ["1000", "500", "250", "100", "50"]
            body["amount"] = amounts[index % len(amounts)]

        # Vary any URL fields
        for key in body.keys():
            if "url" in key.lower() or "URL" in key:
                urls = [
                    "acc://alice.acme/test",
                    "acc://bob.demo/test",
                    "acc://charlie.example/test"
                ]
                body[key] = urls[index % len(urls)]

        return body

    def convert_to_transaction(self, base_vector: Dict[str, Any], index: int) -> Dict[str, Any]:
        """Convert non-transaction vectors to transaction format"""

        if "privateKey" in base_vector:
            # This is a signing vector - create synthetic transaction
            return {
                "header": {
                    "principal": f"acc://test{index}.acme/book",
                    "timestamp": 1234567890 + index * 3600
                },
                "body": {
                    "type": "sendTokens",
                    "to": [{"url": f"acc://recipient{index}.acme/tokens", "amount": str(1000 + index * 100)}]
                }
            }

        # Default transaction
        return self.create_default_vector()["transaction"]


def main():
    """Main function"""
    args = sys.argv[1:]
    count = int(args[0]) if args else 200

    print(f"Generating {count} fuzz vectors with deterministic variations", file=sys.stderr)

    generator = FuzzVectorGenerator(seed=42)
    vectors = generator.generate_fuzz_vectors(count)

    for vector in vectors:
        print(json.dumps(vector))

    print(f"Generated {len(vectors)} fuzz vectors successfully", file=sys.stderr)


if __name__ == "__main__":
    main()