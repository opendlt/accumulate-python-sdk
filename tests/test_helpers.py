"""
Test helper functions and mock objects for the test suite.
"""

import hashlib
import json
from typing import Dict, Any, Optional, List, Tuple
from pathlib import Path
import sys

# Add src to path
test_dir = Path(__file__).parent
src_dir = test_dir.parent / "src"
sys.path.insert(0, str(src_dir))

from accumulate_client.crypto.ed25519 import Ed25519PrivateKey


class MockTransport:
    """Mock transport for testing without network."""

    def __init__(self, responses: Optional[Dict[str, Any]] = None):
        self.responses = responses or {}
        self.calls = []
        self.error_on_call = None
        self.retry_count = 0

    def request(self, method: str, params: Any) -> Any:
        """Record call and return mock response."""
        self.calls.append((method, params))

        # Simulate retry behavior
        if self.error_on_call and len(self.calls) <= self.error_on_call:
            self.retry_count += 1
            raise Exception("Mock transient error")

        # Return configured response
        if method in self.responses:
            return self.responses[method]

        # Default responses
        if method == "query":
            return {"data": {"type": "identity", "url": params.get("url", "acc://test.acme")}}
        elif method == "submit":
            return {"data": {"transactionHash": "mock_hash_" + str(len(self.calls))}}
        elif method == "faucet":
            return {"data": {"transactionHash": "faucet_hash"}}
        elif method == "status":
            return {"data": {"network": "MockNet", "version": "1.0.0"}}

        return {"data": {}}


class MockClient:
    """Mock Accumulate client for testing."""

    def __init__(self, endpoint: str = "http://mock.endpoint", transport: Optional[MockTransport] = None):
        self.endpoint = endpoint
        self.transport = transport or MockTransport()
        self._balances = {}
        self._accounts = {}

    def query(self, url: str) -> Dict[str, Any]:
        """Mock query method."""
        if "/tokens" in url or "/ACME" in url:
            balance = self._balances.get(url, 100_000_000)
            return {
                "data": {
                    "balance": balance,
                    "tokenUrl": "acc://acme.acme/tokens/ACME",
                    "type": "tokenAccount"
                }
            }
        elif "/book" in url:
            return {
                "data": {
                    "creditBalance": 500_000_000,
                    "type": "keyPage"
                }
            }
        elif "/data" in url:
            return {
                "data": {
                    "entryCount": 5,
                    "type": "dataAccount"
                }
            }
        else:
            return {
                "data": {
                    "url": url,
                    "type": "identity"
                }
            }

    def submit(self, envelope: Dict[str, Any]) -> Dict[str, Any]:
        """Mock submit method."""
        return self.transport.request("submit", envelope)

    def faucet(self, account: str) -> Dict[str, Any]:
        """Mock faucet method."""
        self._balances[account] = self._balances.get(account, 0) + 500_000_000
        return self.transport.request("faucet", {"account": account})

    def status(self) -> Dict[str, Any]:
        """Mock status method."""
        return self.transport.request("status", {})

    def execute(self, transaction: Any, signers: List[Any]) -> Dict[str, Any]:
        """Mock execute method."""
        envelope = {
            "transaction": transaction,
            "signatures": [s.to_accumulate_signature({}) for s in signers]
        }
        return self.submit(envelope)


def mk_ed25519_keypair(seed: Optional[bytes] = None) -> Tuple[Ed25519PrivateKey, Any]:
    """Create a deterministic Ed25519 keypair for testing."""
    if seed is None:
        seed = b'test_seed_default_0123456789ABCD'[:32]
    elif len(seed) < 32:
        seed = seed + b'\x00' * (32 - len(seed))
    elif len(seed) > 32:
        seed = seed[:32]

    private_key = Ed25519PrivateKey.from_seed(seed)
    public_key = private_key.public_key()

    return private_key, public_key


def mk_identity_url(name: Optional[str] = None) -> str:
    """Create a test identity URL."""
    if name is None:
        name = "test"
    return f"acc://{name}.acme"


def mk_minimal_valid_body(tx_type: str) -> Dict[str, Any]:
    """Create minimal valid transaction body for testing."""
    bodies = {
        "CreateIdentity": {
            "type": "CreateIdentity",
            "url": "acc://test.acme",
            "keyBookUrl": "acc://test.acme/book",
            "keyPageUrl": "acc://test.acme/book/1",
        },
        "CreateTokenAccount": {
            "type": "CreateTokenAccount",
            "url": "acc://alice.acme/tokens",
            "tokenUrl": "acc://acme.acme/tokens/ACME",
        },
        "SendTokens": {
            "type": "SendTokens",
            "from": "acc://alice.acme/tokens",
            "to": [{"url": "acc://bob.acme/tokens", "amount": 100000}],
        },
        "WriteData": {
            "type": "WriteData",
            "dataAccount": "acc://data.acme/storage",
            "data": b"test data",
        },
        "AddCredits": {
            "type": "AddCredits",
            "recipient": "acc://test.acme/book/1",
            "amount": 1000000,
            "oracle": 500.0,
        },
        "CreateDataAccount": {
            "type": "CreateDataAccount",
            "url": "acc://data.acme/storage",
        },
        "BurnTokens": {
            "type": "BurnTokens",
            "account": "acc://alice.acme/tokens",
            "amount": 100000,
        },
        "IssueTokens": {
            "type": "IssueTokens",
            "account": "acc://issuer.acme/tokens",
            "recipient": "acc://alice.acme/tokens",
            "amount": 1000000,
        },
        "CreateKeyPage": {
            "type": "CreateKeyPage",
            "keyBook": "acc://test.acme/book",
            "keys": [{"publicKey": b'\x00' * 32, "weight": 1}],
        },
        "UpdateKey": {
            "type": "UpdateKey",
            "keyPage": "acc://test.acme/book/1",
            "oldKey": b'\x00' * 32,
            "newKey": b'\x01' * 32,
        },
    }

    return bodies.get(tx_type, {"type": tx_type})


def mk_lite_identity(public_key_bytes: bytes) -> str:
    """Create a lite identity URL from public key."""
    # First 20 bytes of public key as hex
    address = public_key_bytes[:20].hex()
    return f"acc://{address}"


def canonical_json(obj: Dict[str, Any]) -> bytes:
    """Create canonical JSON representation."""
    return json.dumps(obj, sort_keys=True, separators=(',', ':')).encode()


def calculate_tx_hash(tx_body: Dict[str, Any]) -> bytes:
    """Calculate transaction hash."""
    canonical = canonical_json(tx_body)
    return hashlib.sha256(canonical).digest()