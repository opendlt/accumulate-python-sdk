"""
Accumulate V3 API Client.

Provides dedicated V3 API client with full options support matching
Go pkg/api/v3 interface and Dart SDK patterns.

The V3 API is the current recommended API version for Accumulate.

Reference: C:/Accumulate_Stuff/accumulate/pkg/api/v3/api.go
"""

from __future__ import annotations
from typing import Optional, Dict, Any, List, Union
from urllib.parse import urlparse, urljoin
import requests
import json
import random

from .options import (
    SubmitOptions,
    ValidateOptions,
    FaucetOptions,
    QueryOptions,
    QueryType,
    NodeInfoOptions,
    FindServiceOptions,
    ConsensusStatusOptions,
    NetworkStatusOptions,
    MetricsOptions,
    RangeOptions,
)


class V3ApiError(Exception):
    """Exception for V3 API errors."""

    def __init__(self, message: str, code: Optional[int] = None, data: Any = None):
        super().__init__(message)
        self.code = code
        self.data = data

    def __str__(self) -> str:
        if self.code is not None:
            return f"V3ApiError({self.code}): {super().__str__()}"
        return f"V3ApiError: {super().__str__()}"


class AccumulateV3Client:
    """
    Dedicated V3 API client with full options support.

    Provides typed methods for all V3 API operations including:
    - Transaction submission and validation
    - Account and chain queries
    - Block queries
    - Network status and node information
    - Faucet access

    Example:
        ```python
        # Create client
        client = AccumulateV3Client("https://testnet.accumulatenetwork.io")

        # Query an account
        result = client.query("acc://my-adi.acme")

        # Submit a transaction with options
        result = client.submit(envelope, SubmitOptions(wait=True, verify=True))

        # Query with specific query type
        from accumulate_client.v3 import ChainQuery, RangeOptions
        result = client.query(
            "acc://my-adi.acme",
            query=ChainQuery(name="main", range=RangeOptions(start=0, count=10))
        )
        ```
    """

    def __init__(
        self,
        endpoint: str,
        timeout: float = 30.0,
        session: Optional[requests.Session] = None
    ):
        """
        Initialize the V3 client.

        Args:
            endpoint: Base endpoint URL (will append /v3 if not present)
            timeout: Request timeout in seconds (default: 30)
            session: Optional requests.Session for connection pooling
        """
        # Normalize endpoint
        endpoint = endpoint.rstrip('/')
        if not endpoint.endswith('/v3'):
            # Strip any existing version path
            if '/v2' in endpoint:
                endpoint = endpoint.replace('/v2', '')
            endpoint = endpoint + '/v3'

        self._endpoint = endpoint
        self._timeout = timeout
        self._session = session or requests.Session()
        self._owns_session = session is None

    @property
    def endpoint(self) -> str:
        """Get the API endpoint."""
        return self._endpoint

    def close(self) -> None:
        """Close the HTTP session if owned by this client."""
        if self._owns_session:
            self._session.close()

    def __enter__(self) -> AccumulateV3Client:
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.close()

    # =========================================================================
    # Low-level RPC
    # =========================================================================

    def _call(self, method: str, params: Optional[Dict[str, Any]] = None) -> Any:
        """
        Make a JSON-RPC 2.0 call.

        Args:
            method: RPC method name
            params: Method parameters

        Returns:
            Result from the RPC call

        Raises:
            V3ApiError: If the call fails
        """
        request_id = random.randint(1, 1_000_000)
        request_data: Dict[str, Any] = {
            "jsonrpc": "2.0",
            "method": method,
            "id": request_id,
        }
        if params is not None:
            request_data["params"] = params

        try:
            response = self._session.post(
                self._endpoint,
                json=request_data,
                headers={"Content-Type": "application/json"},
                timeout=self._timeout,
            )

            if response.status_code != 200:
                raise V3ApiError(
                    f"HTTP {response.status_code}: {response.reason}",
                    code=response.status_code,
                )

            response_data = response.json()

        except requests.exceptions.RequestException as e:
            raise V3ApiError(f"HTTP request failed: {e}")
        except json.JSONDecodeError as e:
            raise V3ApiError(f"Invalid JSON response: {e}")

        if "error" in response_data:
            error = response_data["error"]
            raise V3ApiError(
                error.get("message", "Unknown error"),
                code=error.get("code"),
                data=error.get("data"),
            )

        return response_data.get("result")

    def call(self, method: str, params: Optional[Dict[str, Any]] = None) -> Any:
        """
        Make a raw JSON-RPC call.

        This is exposed for advanced use cases where typed methods don't suffice.

        Args:
            method: RPC method name (e.g., "query", "submit")
            params: Method parameters

        Returns:
            Result from the RPC call
        """
        return self._call(method, params)

    # =========================================================================
    # Submitter Service
    # =========================================================================

    def submit(
        self,
        envelope: Dict[str, Any],
        options: Optional[SubmitOptions] = None
    ) -> List[Dict[str, Any]]:
        """
        Submit a transaction envelope.

        Args:
            envelope: Transaction envelope with transaction and signatures
            options: Submit options (verify, wait)

        Returns:
            List of submission results

        Example:
            ```python
            envelope = {
                "transaction": {...},
                "signatures": [...]
            }
            results = client.submit(envelope, SubmitOptions(wait=True))
            ```
        """
        params: Dict[str, Any] = {"envelope": envelope}
        if options is not None:
            params.update(options.to_dict())

        result = self._call("submit", params)
        return [result] if not isinstance(result, list) else result

    # =========================================================================
    # Validator Service
    # =========================================================================

    def validate(
        self,
        envelope: Dict[str, Any],
        options: Optional[ValidateOptions] = None
    ) -> List[Dict[str, Any]]:
        """
        Validate a transaction without submitting.

        Useful for checking if a transaction would succeed before submission.

        Args:
            envelope: Transaction envelope to validate
            options: Validation options (full)

        Returns:
            List of validation results
        """
        params: Dict[str, Any] = {"envelope": envelope}
        if options is not None:
            params.update(options.to_dict())

        result = self._call("validate", params)
        return [result] if not isinstance(result, list) else result

    # =========================================================================
    # Faucet Service
    # =========================================================================

    def faucet(
        self,
        account: str,
        options: Optional[FaucetOptions] = None
    ) -> Dict[str, Any]:
        """
        Request tokens from the faucet.

        Only available on testnet/devnet.

        Args:
            account: Account URL to fund
            options: Faucet options (token)

        Returns:
            Faucet submission result
        """
        params: Dict[str, Any] = {"account": account}
        if options is not None:
            params.update(options.to_dict())

        return self._call("faucet", params)

    # =========================================================================
    # Querier Service
    # =========================================================================

    def query(
        self,
        scope: str,
        query: Optional[QueryType] = None,
        options: Optional[QueryOptions] = None
    ) -> Dict[str, Any]:
        """
        Query an account or perform a specific query.

        Args:
            scope: Account URL to query
            query: Optional specific query type (ChainQuery, DataQuery, etc.)
            options: Query options (expand, height, prove, etc.)

        Returns:
            Query result record

        Example:
            ```python
            # Simple account query
            result = client.query("acc://my-adi.acme")

            # Chain query with range
            result = client.query(
                "acc://my-adi.acme",
                query=ChainQuery(name="main", range=RangeOptions(start=0, count=10))
            )

            # Query with options
            result = client.query(
                "acc://my-adi.acme",
                options=QueryOptions(expand=True, prove=True)
            )
            ```
        """
        params: Dict[str, Any] = {"scope": scope}
        if query is not None:
            params["query"] = query.to_dict()
        if options is not None:
            params.update(options.to_dict())

        return self._call("query", params)

    def query_account(
        self,
        url: str,
        options: Optional[QueryOptions] = None
    ) -> Dict[str, Any]:
        """
        Query account state.

        Convenience method for basic account queries.

        Args:
            url: Account URL
            options: Query options

        Returns:
            Account record
        """
        return self.query(url, options=options)

    def query_transaction(
        self,
        txid: str,
        options: Optional[QueryOptions] = None
    ) -> Dict[str, Any]:
        """
        Query a transaction by ID.

        Args:
            txid: Transaction ID (hash or URL)
            options: Query options

        Returns:
            Transaction record
        """
        return self.query(txid, options=options)

    def query_chain(
        self,
        url: str,
        chain_name: str,
        range_options: Optional[RangeOptions] = None,
        options: Optional[QueryOptions] = None
    ) -> Dict[str, Any]:
        """
        Query chain entries.

        Args:
            url: Account URL
            chain_name: Chain name (main, scratch, signature, etc.)
            range_options: Pagination options
            options: Query options

        Returns:
            Chain query result
        """
        from .options import ChainQuery
        query = ChainQuery(name=chain_name, range=range_options)
        return self.query(url, query=query, options=options)

    def query_data(
        self,
        url: str,
        index: Optional[int] = None,
        entry_hash: Optional[Union[bytes, str]] = None,
        range_options: Optional[RangeOptions] = None
    ) -> Dict[str, Any]:
        """
        Query data chain entries.

        Args:
            url: Data account URL
            index: Specific entry index
            entry_hash: Specific entry hash
            range_options: Pagination options

        Returns:
            Data query result
        """
        from .options import DataQuery
        query = DataQuery(index=index, entry=entry_hash, range=range_options)
        return self.query(url, query=query)

    def query_directory(
        self,
        url: str,
        range_options: Optional[RangeOptions] = None
    ) -> Dict[str, Any]:
        """
        Query account directory (sub-accounts).

        Args:
            url: Identity or directory URL
            range_options: Pagination options

        Returns:
            Directory listing
        """
        from .options import DirectoryQuery
        query = DirectoryQuery(range=range_options)
        return self.query(url, query=query)

    def query_pending(
        self,
        url: str,
        range_options: Optional[RangeOptions] = None
    ) -> Dict[str, Any]:
        """
        Query pending transactions.

        Args:
            url: Account URL
            range_options: Pagination options

        Returns:
            Pending transactions list
        """
        from .options import PendingQuery
        query = PendingQuery(range=range_options)
        return self.query(url, query=query)

    def query_minor_blocks(
        self,
        url: str,
        index: Optional[int] = None,
        range_options: Optional[RangeOptions] = None,
        omit_empty: bool = False
    ) -> Dict[str, Any]:
        """
        Query minor blocks.

        Args:
            url: Account URL
            index: Specific block index
            range_options: Block range options
            omit_empty: Omit empty blocks

        Returns:
            Block query result
        """
        from .options import BlockQuery
        query = BlockQuery(minor=index, minor_range=range_options, omit_empty=omit_empty)
        return self.query(url, query=query)

    def query_major_blocks(
        self,
        url: str,
        index: Optional[int] = None,
        range_options: Optional[RangeOptions] = None,
        omit_empty: bool = False
    ) -> Dict[str, Any]:
        """
        Query major blocks.

        Args:
            url: Account URL
            index: Specific block index
            range_options: Block range options
            omit_empty: Omit empty blocks

        Returns:
            Block query result
        """
        from .options import BlockQuery
        query = BlockQuery(major=index, major_range=range_options, omit_empty=omit_empty)
        return self.query(url, query=query)

    # =========================================================================
    # Search Queries
    # =========================================================================

    def search_anchor(
        self,
        url: str,
        anchor: Union[bytes, str]
    ) -> Dict[str, Any]:
        """
        Search for transactions by anchor hash.

        Args:
            url: Account URL scope
            anchor: Anchor hash (32 bytes)

        Returns:
            Search results
        """
        from .options import AnchorSearchQuery
        query = AnchorSearchQuery(anchor=anchor)
        return self.query(url, query=query)

    def search_public_key(
        self,
        url: str,
        public_key: Union[bytes, str],
        signature_type: str = "ed25519"
    ) -> Dict[str, Any]:
        """
        Search for accounts by public key.

        Args:
            url: Account URL scope
            public_key: Public key bytes
            signature_type: Signature type (ed25519, rcd1, btc, etc.)

        Returns:
            Search results
        """
        from .options import PublicKeySearchQuery
        query = PublicKeySearchQuery(public_key=public_key, type=signature_type)
        return self.query(url, query=query)

    def search_public_key_hash(
        self,
        url: str,
        key_hash: Union[bytes, str]
    ) -> Dict[str, Any]:
        """
        Search for accounts by public key hash.

        Args:
            url: Account URL scope
            key_hash: Public key hash (32 bytes)

        Returns:
            Search results
        """
        from .options import PublicKeyHashSearchQuery
        query = PublicKeyHashSearchQuery(public_key_hash=key_hash)
        return self.query(url, query=query)

    def search_delegate(
        self,
        url: str,
        delegate: str
    ) -> Dict[str, Any]:
        """
        Search for accounts delegated to a URL.

        Args:
            url: Account URL scope
            delegate: Delegate URL

        Returns:
            Search results
        """
        from .options import DelegateSearchQuery
        query = DelegateSearchQuery(delegate=delegate)
        return self.query(url, query=query)

    # =========================================================================
    # Node Service
    # =========================================================================

    def node_info(
        self,
        options: Optional[NodeInfoOptions] = None
    ) -> Dict[str, Any]:
        """
        Get node information.

        Args:
            options: Node info options (peer_id)

        Returns:
            Node information
        """
        params = options.to_dict() if options else {}
        return self._call("node-info", params if params else None)

    def find_service(
        self,
        options: Optional[FindServiceOptions] = None
    ) -> List[Dict[str, Any]]:
        """
        Find services on the network.

        Args:
            options: Find service options (network, service, known, timeout)

        Returns:
            List of service results
        """
        params = options.to_dict() if options else {}
        result = self._call("find-service", params if params else None)
        return [result] if not isinstance(result, list) else result

    # =========================================================================
    # Consensus Service
    # =========================================================================

    def consensus_status(
        self,
        options: ConsensusStatusOptions
    ) -> Dict[str, Any]:
        """
        Get consensus status for a node and partition.

        Args:
            options: Consensus status options (node_id, partition required)

        Returns:
            Consensus status
        """
        return self._call("consensus-status", options.to_dict())

    # =========================================================================
    # Network Service
    # =========================================================================

    def network_status(
        self,
        options: NetworkStatusOptions
    ) -> Dict[str, Any]:
        """
        Get network status for a partition.

        Args:
            options: Network status options (partition required)

        Returns:
            Network status
        """
        return self._call("network-status", options.to_dict())

    # =========================================================================
    # Metrics Service
    # =========================================================================

    def metrics(
        self,
        options: MetricsOptions
    ) -> Dict[str, Any]:
        """
        Get network metrics.

        Args:
            options: Metrics options (partition required, span optional)

        Returns:
            Network metrics
        """
        return self._call("metrics", options.to_dict())

    # =========================================================================
    # Snapshot Service
    # =========================================================================

    def list_snapshots(
        self,
        options: "ListSnapshotsOptions"
    ) -> List[Dict[str, Any]]:
        """
        List available snapshots from a node.

        Args:
            options: ListSnapshotsOptions (node_id and partition required)

        Returns:
            List of available snapshots
        """
        from .options import ListSnapshotsOptions
        result = self._call("list-snapshots", options.to_dict())
        return [result] if not isinstance(result, list) else result

    # =========================================================================
    # Subscribe Service (Event Streaming)
    # =========================================================================

    def subscribe(
        self,
        options: Optional["SubscribeOptions"] = None
    ) -> Dict[str, Any]:
        """
        Subscribe to events.

        Note: This initiates a subscription. For full event streaming,
        use the StreamingAccumulateClient which supports WebSocket connections.

        Args:
            options: Subscribe options (partition or account to filter events)

        Returns:
            Subscription result with stream details
        """
        from .options import SubscribeOptions
        params = options.to_dict() if options else {}
        return self._call("subscribe", params if params else None)


__all__ = [
    "AccumulateV3Client",
    "V3ApiError",
]
