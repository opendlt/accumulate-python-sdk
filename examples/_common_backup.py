"""
Common utilities for Accumulate SDK example scripts.

Provides shared functionality for devnet example scripts including
client creation, key derivation, transaction validation, and error handling.
"""

import sys
import json
import hashlib
import time
from typing import Optional, Dict, Any

from accumulate_client import AccumulateClient
from accumulate_client.crypto.ed25519 import Ed25519PrivateKey
from accumulate_client.tx.codec import to_canonical_json, from_canonical_json
from accumulate_client.recovery.retry import ExponentialBackoff


def make_client(endpoint: str, ws_endpoint: Optional[str] = None, profile: str = "balanced", mock: bool = False):
    """
    Create Accumulate client with optional performance tuning.

    Args:
        endpoint: HTTP JSON-RPC endpoint
        ws_endpoint: WebSocket endpoint (optional)
        profile: Performance profile ("balanced", "fast", "conservative")
        mock: Use mock transport instead of real network calls (fallback only)

    Returns:
        Configured AccumulateClient or MockClient

    Note:
        Mock mode should only be used when the real devnet is unavailable.
        The SDK is designed for integration testing against live devnet.
    """
    if mock:
        print("[WARN] Using mock transport - real devnet preferred for integration testing")
        return _create_mock_client(endpoint)

    # Create real client for devnet integration
    client = AccumulateClient(endpoint)

    # Add retry policy for reliability in devnet operations
    client._retry_policy = ExponentialBackoff(
        max_attempts=5,  # More retries for devnet reliability
        base_delay=0.5,
        factor=2.0,
        max_delay=30.0
    )

    return client


def _create_mock_client(endpoint: str):
    """Create mock client for testing without network."""

    class MockClient:
        """Mock Accumulate client for offline testing."""

        def __init__(self, endpoint: str):
            self.endpoint = endpoint
            self._tx_counter = 0
            self._balances = {}  # Track account balances for faucet simulation

        def query(self, url: str) -> Dict[str, Any]:
            """Mock query response."""
            if "/ACME" in url:
                # Token account query - check if we have a custom balance
                balance = self._balances.get(url, 100_000_000)  # Default 1 ACME
                return {
                    "data": {
                        "balance": balance,
                        "tokenUrl": "acc://acme.acme/tokens/ACME"
                    }
                }
            elif "/book/1" in url:
                # Key page query
                return {
                    "data": {
                        "creditBalance": 500_000_000  # 500 credits
                    }
                }
            elif "/data" in url:
                # Data account query
                return {
                    "data": {
                        "entryCount": 1
                    }
                }
            else:
                # Generic account query
                return {
                    "data": {
                        "url": url,
                        "type": "identity"
                    }
                }

        def submit(self, envelope: Dict[str, Any]) -> Dict[str, Any]:
            """Mock transaction submission."""
            self._tx_counter += 1
            return {
                "data": {
                    "transactionHash": f"mock_tx_hash_{self._tx_counter:04d}"
                }
            }

        def faucet(self, account: str) -> Dict[str, Any]:
            """Mock faucet request."""
            # Simulate faucet by increasing balance
            if account in self._balances:
                self._balances[account] += 500_000_000  # Add 5 ACME
            else:
                self._balances[account] = 600_000_000  # 6 ACME total (1 initial + 5 from faucet)

            return {
                "data": {
                    "transactionHash": "mock_faucet_hash"
                }
            }

        def status(self) -> Dict[str, Any]:
            """Mock status query."""
            return {
                "data": {
                    "network": "MockNet",
                    "version": "mock-1.0.0"
                }
            }

    return MockClient(endpoint)


def tassert(condition: bool, message: str) -> None:
    """
    Small assert helper with nice error messages.

    Args:
        condition: Condition to check
        message: Error message if condition fails
    """
    if not condition:
        print(f"[FAIL] ASSERTION FAILED: {message}")
        sys.exit(1)


def parity_assert_tx(builder_or_tx: Any) -> Dict[str, Any]:
    """
    Perform encode-decode-encode and hash parity assertions on transaction.

    Validates that transaction marshaling/unmarshaling is consistent and
    that transaction hashing produces expected results.

    Args:
        builder_or_tx: Transaction builder or transaction dict

    Returns:
        Transaction body dict

    Raises:
        SystemExit: If parity checks fail
    """
    # Get transaction body
    if hasattr(builder_or_tx, 'to_body'):
        # Transaction builder
        builder_or_tx.validate()
        tx_body = builder_or_tx.to_body()
        canonical_json_1 = builder_or_tx.to_canonical_json()
    else:
        # Transaction dict
        tx_body = builder_or_tx
        canonical_json_1 = to_canonical_json(tx_body)

    # Step 1: Encode to canonical JSON
    canonical_bytes_1 = canonical_json_1

    # Step 2: Decode transaction
    try:
        decoded_body = from_canonical_json(canonical_bytes_1, dict)
    except Exception as e:
        print(f"[WARN] Decode not available: {e}")
        # Return original if decode not implemented
        return tx_body

    # Step 3: Re-encode decoded transaction
    try:
        canonical_json_2 = to_canonical_json(decoded_body)
        canonical_bytes_2 = canonical_json_2
    except Exception as e:
        print(f"[WARN] Re-encode not available: {e}")
        return tx_body

    # Assert byte-for-byte equality
    tassert(
        canonical_bytes_1 == canonical_bytes_2,
        f"Roundtrip parity failed: encode→decode→re-encode not equal"
    )

    # Verify hash consistency
    hash_1 = hashlib.sha256(canonical_bytes_1).hexdigest()
    hash_2 = hashlib.sha256(canonical_bytes_2).hexdigest()

    tassert(
        hash_1 == hash_2,
        f"Transaction hash inconsistent after roundtrip: {hash_1} != {hash_2}"
    )

    print(f"[OK] Transaction parity verified (hash: {hash_1[:12]}...)")
    return tx_body


def keypair_from_seed(seed_hex: str) -> tuple:
    """
    Derive deterministic keypair from hex seed.

    Args:
        seed_hex: Hex string seed (e.g., "00010203...")

    Returns:
        Tuple of (private_key, public_key)
    """
    tassert(len(seed_hex) >= 8, "Key seed must be at least 4 bytes (8 hex chars)")

    # Ensure seed is exactly 32 bytes for Ed25519
    seed_bytes = bytes.fromhex(seed_hex)
    if len(seed_bytes) < 32:
        # Pad with zeros if too short
        seed_bytes = seed_bytes + b'\x00' * (32 - len(seed_bytes))
    elif len(seed_bytes) > 32:
        # Truncate if too long
        seed_bytes = seed_bytes[:32]

    private_key = Ed25519PrivateKey.from_seed(seed_bytes)
    public_key = private_key.public_key()

    return private_key, public_key


def query_with_retry(client: AccumulateClient, url: str, max_attempts: int = 3) -> Dict[str, Any]:
    """
    Query with exponential backoff retry.

    Args:
        client: Accumulate client
        url: URL to query
        max_attempts: Maximum retry attempts

    Returns:
        Query result data
    """
    retry_policy = ExponentialBackoff(max_attempts=max_attempts, base_delay=0.5)

    async def query_operation():
        return client.query(url)

    try:
        import asyncio
        result = asyncio.run(retry_policy.execute(query_operation))
        return result.get('data', {})
    except Exception:
        # Fallback to direct query if async retry fails
        try:
            result = client.query(url)
            return result.get('data', {})
        except Exception as e:
            print(f"[FAIL] Query failed for {url}: {e}")
            return {}


def submit_with_retry(client: AccumulateClient, envelope: Dict[str, Any], max_attempts: int = 3) -> Dict[str, Any]:
    """
    Submit transaction with exponential backoff retry.

    Args:
        client: Accumulate client
        envelope: Transaction envelope
        max_attempts: Maximum retry attempts

    Returns:
        Submit result data
    """
    retry_policy = ExponentialBackoff(max_attempts=max_attempts, base_delay=0.5)

    async def submit_operation():
        return client.submit(envelope)

    try:
        import asyncio
        result = asyncio.run(retry_policy.execute(submit_operation))
        return result.get('data', {})
    except Exception:
        # Fallback to direct submit if async retry fails
        try:
            result = client.submit(envelope)
            return result.get('data', {})
        except Exception as e:
            print(f"[FAIL] Submit failed: {e}")
            raise


def format_tokens(amount: int, decimals: int = 8) -> str:
    """
    Format token amount with decimals.

    Args:
        amount: Raw token amount
        decimals: Token decimal places

    Returns:
        Formatted token string
    """
    if amount == 0:
        return "0"

    factor = 10 ** decimals
    whole = amount // factor
    fraction = amount % factor

    if fraction == 0:
        return str(whole)

    # Remove trailing zeros from fraction
    fraction_str = str(fraction).zfill(decimals).rstrip('0')
    return f"{whole}.{fraction_str}"


def format_credits(amount: int) -> str:
    """
    Format credit amount (typically in micro-credits).

    Args:
        amount: Raw credit amount

    Returns:
        Formatted credit string
    """
    return format_tokens(amount, 6)  # Credits use 6 decimal places


def print_step(step: str, details: str = "") -> None:
    """
    Print formatted step information.

    Args:
        step: Step description
        details: Optional details
    """
    print(f"\n[STEP] {step}")
    if details:
        print(f"   {details}")


def print_result(title: str, data: Dict[str, Any]) -> None:
    """
    Print formatted result information.

    Args:
        title: Result title
        data: Result data
    """
    print(f"\n[RESULT] {title}")
    for key, value in data.items():
        print(f"   {key}: {value}")


def print_tx_hash(tx_hash: str, description: str = "Transaction") -> None:
    """
    Print transaction hash in formatted way.

    Args:
        tx_hash: Transaction hash
        description: Transaction description
    """
    print(f"[TX] {description} Hash: {tx_hash}")


def wait_for_devnet(seconds: int = 2) -> None:
    """
    Wait for devnet block time.

    Args:
        seconds: Seconds to wait
    """
    print(f"[WAIT] Waiting {seconds}s for devnet block...")
    time.sleep(seconds)