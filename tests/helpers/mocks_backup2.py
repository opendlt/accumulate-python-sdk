"""
Mock implementations for testing.

Provides mock signers, clients, and transports with configurable
behavior for testing different scenarios.
"""

from __future__ import annotations
import hashlib
import time
from typing import Dict, Any, Optional, List, Union
from unittest.mock import Mock

from accumulate_client.runtime.url import AccountUrl
from accumulate_client.signers.signer import Signer
from accumulate_client.crypto.ed25519 import Ed25519PrivateKey
from accumulate_client.enums import SignatureType
from accumulate_client.api_client import AccumulateAPIError, AccumulateNetworkError, AccumulateValidationError


class MockSigner(Signer):
    """
    Mock signer that produces deterministic signatures for testing.
    """

    def __init__(self, url: Union[str, AccountUrl], seed: int = 12345):
        """
        Initialize mock signer.

        Args:
            url: Signer URL
            seed: Deterministic seed for key generation
        """
        if isinstance(url, str):
            url = AccountUrl(url)
        self.url = url
        self.seed = seed
        self._private_key = Ed25519PrivateKey.from_seed(seed.to_bytes(32, 'big'))

    def get_signer_url(self) -> AccountUrl:
        """Get the signer URL."""
        return self.url

    def to_accumulate_signature(self, data: bytes, **kwargs) -> Dict[str, Any]:
        """
        Create a deterministic mock signature.

        Args:
            data: Data to sign
            **kwargs: Additional signature parameters

        Returns:
            Mock signature dictionary
        """
        # Create deterministic signature based on seed and data
        hasher = hashlib.sha256()
        hasher.update(self.seed.to_bytes(4, 'big'))
        hasher.update(data)
        signature_bytes = hasher.digest()

        return {
            'type': 'ed25519',
            'publicKey': self._private_key.public_key().to_bytes().hex(),
            'signature': signature_bytes.hex(),
            'signer': str(self.url),
            'timestamp': int(time.time() * 1000),
            'version': 1
        }

    def sign(self, data: bytes) -> bytes:
        """
        Sign data with the mock private key.

        Args:
            data: Data to sign

        Returns:
            Signature bytes
        """
        return self._private_key.sign(data)

    def get_signature_type(self) -> SignatureType:
        """
        Get the signature type for this mock signer.

        Returns:
            ED25519 signature type
        """
        return SignatureType.ED25519

    def get_public_key(self) -> bytes:
        """
        Get the public key bytes.

        Returns:
            Public key bytes
        """
        return self._private_key.public_key().to_bytes()

    def verify(self, signature: bytes, digest: bytes) -> bool:
        """
        Verify a signature against a digest.

        Args:
            signature: Signature bytes to verify
            digest: 32-byte hash that was signed

        Returns:
            True if signature is valid
        """
        try:
            return self._private_key.public_key().verify(signature, digest)
        except Exception:
            return False


class MockTransport:
    """
    Mock transport with configurable retry and error behavior.
    """

    def __init__(self):
        """Initialize mock transport."""
        self.call_count = 0
        self.fail_count = 0
        self.max_failures = 0
        self.delay_response = False
        self.responses = {}
        self.submitted_transactions = {}

    def set_failures(self, max_failures: int):
        """Set number of calls that should fail before succeeding."""
        self.max_failures = max_failures
        self.fail_count = 0

    def set_response(self, method: str, response: Any):
        """Set mock response for a method."""
        self.responses[method] = response

    def make_request(self, method: str, params: Dict[str, Any]) -> Any:
        """
        Mock request method with configurable failures.

        Args:
            method: API method name
            params: Method parameters

        Returns:
            Mock response

        Raises:
            AccumulateNetworkError: If configured to fail
            AccumulateAPIError: If response contains error
            AccumulateValidationError: If validation error
        """
        self.call_count += 1

        # Simulate failures
        if self.fail_count < self.max_failures:
            self.fail_count += 1
            raise AccumulateNetworkError(f"Mock network error (attempt {self.fail_count})")

        # Get response
        result_data = None
        if method == 'submit':
            result_data = self._handle_submit(params)
        elif method == 'query-tx':
            result_data = self._handle_query_tx(params)
        elif method == 'status':
            result_data = self._handle_status(params)
        elif method in self.responses:
            result_data = self.responses[method]
        else:
            result_data = f'mock_{method}_response'

        # Format as JSON-RPC response
        response = {
            'jsonrpc': '2.0',
            'id': 1,
            'result': result_data
        }

        # Check for error in result data and raise appropriate exception
        if isinstance(result_data, dict) and 'error' in result_data:
            self._handle_error_response(result_data['error'])

        return response

    def _handle_error_response(self, error):
        """
        Handle error response by raising appropriate exception.

        Args:
            error: Error object from response

        Raises:
            AccumulateValidationError: For validation errors (codes >= 400 or < 0)
            AccumulateAPIError: For other API errors
        """
        if isinstance(error, dict):
            message = error.get("message", str(error) or "Unknown error")
            code = error.get("code")
            data = error.get("data")
        elif isinstance(error, str):
            message = error or "Empty error message"
            code = None
            data = None
        else:
            message = str(error) or "Unknown error"
            code = None
            data = None

        # Ensure message is never empty
        if not message:
            message = "Unknown error"

        # Categorize error based on code (matching AccumulateClient logic)
        if code is not None and (code < 0 or code >= 400):
            raise AccumulateValidationError(message, code, data)
        else:
            raise AccumulateAPIError(message, code, data)

    def _handle_submit(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Handle transaction submission."""
        envelope = params.get('envelope', {})

        # Generate mock transaction ID
        tx_data = str(envelope).encode('utf-8')
        txid = hashlib.sha256(tx_data).hexdigest()

        # Store transaction for later queries
        self.submitted_transactions[txid] = {
            'envelope': envelope,
            'status': 'pending',
            'submitted_at': time.time()
        }

        return {
            'txid': txid,
            'status': 'submitted'
        }

    def _handle_query_tx(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Handle transaction query."""
        txid = params.get('txid')

        if txid not in self.submitted_transactions:
            raise AccumulateAPIError(f"Transaction {txid} not found", code=404)

        tx_info = self.submitted_transactions[txid]

        # Simulate transaction progression
        elapsed = time.time() - tx_info['submitted_at']
        if elapsed > 2:  # After 2 seconds, mark as delivered
            tx_info['status'] = 'delivered'

        return {
            'txid': txid,
            'status': tx_info['status'],
            'envelope': tx_info['envelope'],
            'result': {
                'type': 'success',
                'fee': 1000
            }
        }

    def _handle_status(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Handle status request."""
        return {
            'network': 'mock-network',
            'version': 'mock-1.0.0',
            'commit': 'abc123def',
            'buildTime': '2023-01-01T00:00:00Z',
            'node_id': 'mock-node-123'
        }


class MockClient:
    """
    Mock AccumulateClient with configurable behavior.
    """

    def __init__(self, transport: Optional[MockTransport] = None):
        """
        Initialize mock client.

        Args:
            transport: Optional mock transport (creates default if None)
        """
        self.transport = transport or MockTransport()
        self.config = Mock()
        self.config.timeout = 30.0
        self.config.max_retries = 3
        self.config.retry_delay = 1.0
        self.config.retry_backoff = 2.0

    def _make_request(self, method: str, params: Dict[str, Any], version: str = "v3") -> Any:
        """
        Mock request method.

        Args:
            method: API method name
            params: Method parameters
            version: API version

        Returns:
            Mock response
        """
        return self.transport.make_request(method, params)

    def submit(self, envelope: Dict[str, Any], options: Any = None) -> List[Dict[str, Any]]:
        """
        Mock submit method.

        Args:
            envelope: Transaction envelope
            options: Submission options

        Returns:
            Mock submission response
        """
        result = self.transport.make_request('submit', {'envelope': envelope})
        return [result]

    def query_tx(self, txid: Union[str, bytes], **kwargs) -> Dict[str, Any]:
        """
        Mock transaction query.

        Args:
            txid: Transaction ID
            **kwargs: Query options

        Returns:
            Mock transaction response
        """
        if isinstance(txid, bytes):
            txid = txid.hex()

        return self.transport.make_request('query-tx', {'txid': txid})

    def get_transaction(self, txid: str) -> Dict[str, Any]:
        """
        Alternative transaction query method.

        Args:
            txid: Transaction ID

        Returns:
            Mock transaction response
        """
        return self.query_tx(txid)

    def submit_transaction(self, envelope: Dict[str, Any]) -> Dict[str, Any]:
        """
        Alternative submit method.

        Args:
            envelope: Transaction envelope

        Returns:
            Mock submission response
        """
        return self.transport.make_request('submit', {'envelope': envelope})

    # Add other API methods as needed
    def status(self) -> Dict[str, Any]:
        """Mock status method that uses transport."""
        return self.transport.make_request('status', {})

    def node_info(self, **kwargs) -> Dict[str, Any]:
        """Mock node info method."""
        return {
            'node_id': 'mock-node-123',
            'network': 'mock-testnet',
            'services': ['validator', 'query']
        }


class EnhancedMockClient:
    """
    Enhanced mock client that matches the expected test interface.
    """

    def __init__(self):
        """Initialize enhanced mock client with state management."""
        self.balances = {}  # Account URL -> balance
        self.transaction_counter = 0
        self.default_balance = 100000000  # Default balance in atomic units
        self.faucet_amount = 1000000  # Faucet payout amount

    def query(self, url: str) -> Dict[str, Any]:
        """
        Mock query method that returns account information.

        Args:
            url: Account URL to query

        Returns:
            Mock query response with account data
        """
        # Initialize balance if account doesn't exist
        if url not in self.balances:
            self.balances[url] = self.default_balance

        return {
            'data': {
                'url': url,
                'type': 'tokenAccount' if 'ACME' in url else 'identity',
                'balance': self.balances[url],
                'credits': 50000,
                'nonce': 1
            }
        }

    def submit(self, envelope: Dict[str, Any]) -> Dict[str, Any]:
        """
        Mock submit method that generates unique transaction hashes.

        Args:
            envelope: Transaction envelope

        Returns:
            Mock submit response with transaction hash
        """
        self.transaction_counter += 1

        # Generate deterministic transaction hash with counter
        tx_hash = f"mock_tx_hash_{self.transaction_counter:04d}"

        return {
            'data': {
                'transactionHash': tx_hash,
                'status': 'submitted'
            }
        }

    def faucet(self, account: str) -> Dict[str, Any]:
        """
        Mock faucet method that increases account balance.

        Args:
            account: Account URL to send tokens to

        Returns:
            Mock faucet response with transaction hash
        """
        # Initialize balance if account doesn't exist
        if account not in self.balances:
            self.balances[account] = self.default_balance

        # Increase balance
        self.balances[account] += self.faucet_amount

        return {
            'data': {
                'transactionHash': 'mock_faucet_hash',
                'amount': self.faucet_amount,
                'recipient': account
            }
        }

    def status(self) -> Dict[str, Any]:
        """
        Mock status method with expected format.

        Returns:
            Mock status response
        """
        return {
            'data': {
                'network': 'MockNet',
                'version': 'mock-1.0.0',
                'commit': 'abc123',
                'buildTime': '2023-01-01T00:00:00Z'
            }
        }


class MockKeyStore:
    """
    Mock keystore for testing wallet functionality.
    """

    def __init__(self):
        """Initialize mock keystore."""
        self.keys: Dict[str, Dict[str, Any]] = {}
        self.locked = False
        self.password = None

    def add_key(self, identity: str, key_hash: str, private_key: bytes, metadata: Dict[str, Any] = None):
        """
        Add a key to the mock keystore.

        Args:
            identity: Identity URL
            key_hash: Key hash
            private_key: Private key bytes
            metadata: Optional key metadata
        """
        key_id = f"{identity}:{key_hash}"
        self.keys[key_id] = {
            'identity': identity,
            'key_hash': key_hash,
            'private_key': private_key,
            'metadata': metadata or {}
        }

    def get_key(self, identity: str, key_hash: str) -> Optional[Dict[str, Any]]:
        """
        Get a key from the mock keystore.

        Args:
            identity: Identity URL
            key_hash: Key hash

        Returns:
            Key data or None if not found
        """
        key_id = f"{identity}:{key_hash}"
        return self.keys.get(key_id)

    def remove_key(self, identity: str, key_hash: str) -> bool:
        """
        Remove a key from the mock keystore.

        Args:
            identity: Identity URL
            key_hash: Key hash

        Returns:
            True if key was removed, False if not found
        """
        key_id = f"{identity}:{key_hash}"
        if key_id in self.keys:
            del self.keys[key_id]
            return True
        return False

    def list_keys(self, identity: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        List keys in the mock keystore.

        Args:
            identity: Optional identity filter

        Returns:
            List of key data
        """
        if identity is None:
            return list(self.keys.values())
        else:
            return [key for key in self.keys.values() if key['identity'] == identity]

    def lock(self):
        """Lock the keystore."""
        self.locked = True

    def unlock(self, password: str):
        """Unlock the keystore."""
        if password == self.password:
            self.locked = False
            return True
        return False

    def is_locked(self) -> bool:
        """Check if keystore is locked."""
        return self.locked


__all__ = [
    'MockSigner',
    'MockTransport',
    'MockClient',
    'EnhancedMockClient',
    'MockKeyStore'
]