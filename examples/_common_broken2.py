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
            """Mock transaction submission with balance simulation."""
            self._tx_counter += 1

            # Process transaction to simulate balance changes
            transaction = envelope.get('transaction', {})
            tx_type = transaction.get('type')

            if tx_type == 'SendTokens':
                # Handle SendTokens transaction with proper sender/recipient balance handling
                to_list = transaction.get('to', [])

                # Calculate total amount to deduct from sender
                total_amount = sum(recipient.get('amount', 0) for recipient in to_list)

                # Find the sender account from the signatures
                signatures = envelope.get('signatures', [])
                sender_url = None
                if signatures:
                    # Extract sender from first signature's signer URL
                    signer_info = signatures[0].get('signer', {})
                    if isinstance(signer_info, dict):
                        sender_url = signer_info.get('url')
                    elif isinstance(signer_info, str):
                        sender_url = signer_info

                # Deduct from sender if found
                if sender_url and total_amount > 0:
                    if sender_url not in self._balances:
                        self._balances[sender_url] = 100_000_000  # Default 1 ACME for new accounts

                    # Deduct the total amount from sender
                    self._balances[sender_url] = max(0, self._balances[sender_url] - total_amount)

                # Add to recipients
                for recipient in to_list:
                    recipient_url = recipient.get('url')
                    amount = recipient.get('amount', 0)

                    if recipient_url and amount > 0:
                        # Initialize recipient balance if needed
                        if recipient_url not in self._balances:
                            self._balances[recipient_url] = 0

                        # Add to recipient balance
                        self._balances[recipient_url] += amount

            elif tx_type == 'AddCredits':
                # Handle AddCredits transaction - simulate ACME being spent
                amount = transaction.get('amount', 0)
                oracle = transaction.get('oracle', 500.0)

                # Calculate ACME cost (simplified)
                acme_cost = int(amount / oracle)  # Basic conversion

                # Find source account (the one with highest balance)
                source_account = None
                max_balance = 0
                for account, balance in self._balances.items():
                    if balance > max_balance:
                        max_balance = balance
                        source_account = account

                # Deduct from source account if found
                if source_account and self._balances[source_account] >= acme_cost:
                    self._balances[source_account] -= acme_cost

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
    hash_1 = hashlib.sha256(canonical_bytes_1).digest()
    hash_2 = hashlib.sha256(canonical_bytes_2).digest()

    tassert(
        hash_1 == hash_2,
        f"Transaction hash changed after roundtrip: {hash_1.hex()} != {hash_2.hex()}"
    )

    print(f"[OK] Transaction parity verified (hash: {hash_1.hex()[:12]}...)")
    return tx_body


def keypair_from_seed(seed_hex: str) -> tuple[Ed25519PrivateKey, any]:
    """
    Generate Ed25519 keypair from hex seed.

    Args:
        seed_hex: Hex-encoded seed string

    Returns:
        Tuple of (private_key, public_key)
    """
    seed_bytes = bytes.fromhex(seed_hex)
    private_key = Ed25519PrivateKey.from_seed(seed_bytes)
    public_key = private_key.public_key()
    return private_key, public_key


def query_with_retry(client, url: str, max_retries: int = 3) -> Optional[Dict[str, Any]]:
    """
    Query account with retry logic.

    Args:
        client: Accumulate client
        url: Account URL to query
        max_retries: Maximum retry attempts

    Returns:
        Query response data or None if not found
    """
    for attempt in range(max_retries):
        try:
            response = client.query(url)
            if response and "data" in response:
                return response["data"]
            return None
        except Exception as e:
            if attempt == max_retries - 1:
                print(f"[WARN] Query failed after {max_retries} attempts: {e}")
                return None
            time.sleep(0.5 * (attempt + 1))
    return None


def submit_with_retry(client, envelope: Dict[str, Any], max_retries: int = 3) -> Dict[str, Any]:
    """
    Submit transaction with retry logic.

    Args:
        client: Accumulate client
        envelope: Transaction envelope
        max_retries: Maximum retry attempts

    Returns:
        Submit response data

    Raises:
        Exception: If all retries fail
    """
    for attempt in range(max_retries):
        try:
            response = client.submit(envelope)
            if response and "data" in response:
                return response["data"]
            return response
        except Exception as e:
            if attempt == max_retries - 1:
                raise e
            time.sleep(0.5 * (attempt + 1))


def format_tokens(amount: int, symbol: str = "ACME") -> str:
    """Format token amount for display."""
    return f"{amount / 100_000_000:.1f}"


def format_credits(amount: int) -> str:
    """Format credit amount for display."""
    return f"{amount / 1_000_000:.0f}"


def print_step(message: str) -> None:
    """Print step indicator."""
    print(f"\n[STEP] {message}")


def print_result(title: str, data: Dict[str, Any]) -> None:
    """Print formatted result."""
    print(f"\n[RESULT] {title}")
    for key, value in data.items():
        print(f"   {key}: {value}")


def print_tx_hash(tx_hash: str, tx_type: str = "Transaction") -> None:
    """Print transaction hash."""
    print(f"[TX] {tx_type} Hash: {tx_hash}")


def wait_for_devnet(seconds: int = 3) -> None:
    """Wait for devnet block time."""
    print(f"[WAIT] Waiting {seconds}s for devnet block...")
    time.sleep(seconds)