"""
Accumulate V2 API Client.

Provides dedicated V2 API client for legacy API compatibility.
V2 API uses different method names than V3 and is being deprecated,
but remains available for backward compatibility with existing code.

Note: New code should use AccumulateV3Client instead.
"""

from __future__ import annotations
from typing import Optional, Dict, Any, List, Union
import requests
import json
import random


class V2ApiError(Exception):
    """Exception for V2 API errors."""

    def __init__(self, message: str, code: Optional[int] = None, data: Any = None):
        super().__init__(message)
        self.code = code
        self.data = data

    def __str__(self) -> str:
        if self.code is not None:
            return f"V2ApiError({self.code}): {super().__str__()}"
        return f"V2ApiError: {super().__str__()}"


class AccumulateV2Client:
    """
    Dedicated V2 API client for legacy compatibility.

    V2 API uses method names like 'execute', 'execute-direct', 'query',
    'query-tx', 'query-directory', etc.

    Note: V2 is deprecated. Use AccumulateV3Client for new code.

    Example:
        ```python
        # Create client
        client = AccumulateV2Client("https://testnet.accumulatenetwork.io")

        # Query an account
        result = client.query("acc://my-adi.acme")

        # Execute a transaction directly
        result = client.execute_direct(envelope)

        # Query transaction by ID
        result = client.query_tx("acc://my-adi.acme@txhash")
        ```
    """

    def __init__(
        self,
        endpoint: str,
        timeout: float = 30.0,
        session: Optional[requests.Session] = None
    ):
        """
        Initialize the V2 client.

        Args:
            endpoint: Base endpoint URL (will append /v2 if not present)
            timeout: Request timeout in seconds (default: 30)
            session: Optional requests.Session for connection pooling
        """
        # Normalize endpoint
        endpoint = endpoint.rstrip('/')
        if not endpoint.endswith('/v2'):
            # Strip any existing version path
            if '/v3' in endpoint:
                endpoint = endpoint.replace('/v3', '')
            endpoint = endpoint + '/v2'

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

    def __enter__(self) -> AccumulateV2Client:
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
            V2ApiError: If the call fails
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
                raise V2ApiError(
                    f"HTTP {response.status_code}: {response.reason}",
                    code=response.status_code,
                )

            response_data = response.json()

        except requests.exceptions.RequestException as e:
            raise V2ApiError(f"HTTP request failed: {e}")
        except json.JSONDecodeError as e:
            raise V2ApiError(f"Invalid JSON response: {e}")

        if "error" in response_data:
            error = response_data["error"]
            raise V2ApiError(
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
            method: RPC method name
            params: Method parameters

        Returns:
            Result from the RPC call
        """
        return self._call(method, params)

    # =========================================================================
    # Transaction Execution (V2-specific methods)
    # =========================================================================

    def execute(self, envelope: Dict[str, Any]) -> Dict[str, Any]:
        """
        Execute a transaction.

        Standard execution method that routes the transaction appropriately.

        Args:
            envelope: Transaction envelope with transaction and signatures

        Returns:
            Execution result with transaction ID and status
        """
        return self._call("execute", {"envelope": envelope})

    def execute_direct(self, envelope: Dict[str, Any]) -> Dict[str, Any]:
        """
        Execute a transaction directly without routing.

        Sends the transaction directly to the target partition.
        This is the primary V2 execution method.

        Args:
            envelope: Transaction envelope with transaction and signatures

        Returns:
            Execution result with transaction ID and status
        """
        return self._call("execute-direct", {"envelope": envelope})

    def execute_local(self, envelope: Dict[str, Any]) -> Dict[str, Any]:
        """
        Execute a transaction locally without routing.

        INTENDED FOR INTERNAL USE ONLY.
        Executes on the local node without network routing.

        Args:
            envelope: Transaction envelope

        Returns:
            Execution result
        """
        return self._call("execute-local", {"envelope": envelope})

    # =========================================================================
    # Query Methods (V2-specific)
    # =========================================================================

    def query(
        self,
        url: str,
        expand: Optional[bool] = None,
        height: Optional[int] = None,
        prove: Optional[bool] = None
    ) -> Dict[str, Any]:
        """
        Query an account by URL.

        Args:
            url: Account URL to query
            expand: Expand results with full details
            height: Query at specific block height
            prove: Include Merkle proofs

        Returns:
            Account query result
        """
        params: Dict[str, Any] = {"url": url}
        if expand is not None:
            params["expand"] = expand
        if height is not None:
            params["height"] = height
        if prove is not None:
            params["prove"] = prove
        return self._call("query", params)

    def query_tx(
        self,
        txid: str,
        wait: Optional[int] = None,
        ignore_pending: Optional[bool] = None
    ) -> Dict[str, Any]:
        """
        Query a transaction by ID.

        Args:
            txid: Transaction ID (hash or URL with @txhash)
            wait: Wait time in milliseconds for pending transactions
            ignore_pending: Ignore pending transactions

        Returns:
            Transaction query result
        """
        params: Dict[str, Any] = {"txid": txid}
        if wait is not None:
            params["wait"] = wait
        if ignore_pending is not None:
            params["ignorePending"] = ignore_pending
        return self._call("query-tx", params)

    def query_tx_local(self, txid: str) -> Dict[str, Any]:
        """
        Query a transaction locally.

        Args:
            txid: Transaction ID

        Returns:
            Transaction query result from local node
        """
        return self._call("query-tx-local", {"txid": txid})

    def query_directory(
        self,
        url: str,
        start: int = 0,
        count: Optional[int] = None,
        expand: Optional[bool] = None
    ) -> Dict[str, Any]:
        """
        Query directory entries of an account.

        Lists sub-accounts of an identity or directory.

        Args:
            url: Account URL
            start: Starting index
            count: Number of entries to return
            expand: Expand results

        Returns:
            Directory listing
        """
        params: Dict[str, Any] = {"url": url, "start": start}
        if count is not None:
            params["count"] = count
        if expand is not None:
            params["expand"] = expand
        return self._call("query-directory", params)

    def query_data(
        self,
        url: str,
        entry_hash: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Query a data entry.

        Args:
            url: Data account URL
            entry_hash: Optional specific entry hash

        Returns:
            Data entry result
        """
        params: Dict[str, Any] = {"url": url}
        if entry_hash is not None:
            params["entryHash"] = entry_hash
        return self._call("query-data", params)

    def query_data_set(
        self,
        url: str,
        start: int = 0,
        count: Optional[int] = None,
        expand: Optional[bool] = None
    ) -> Dict[str, Any]:
        """
        Query a range of data entries.

        Args:
            url: Data account URL
            start: Starting index
            count: Number of entries
            expand: Expand results

        Returns:
            Data entries result
        """
        params: Dict[str, Any] = {"url": url, "start": start}
        if count is not None:
            params["count"] = count
        if expand is not None:
            params["expand"] = expand
        return self._call("query-data-set", params)

    def query_tx_history(
        self,
        url: str,
        start: int = 0,
        count: Optional[int] = None,
        scratch: Optional[bool] = None
    ) -> Dict[str, Any]:
        """
        Query transaction history for an account.

        Args:
            url: Account URL
            start: Starting index
            count: Number of transactions
            scratch: Include scratch chain transactions

        Returns:
            Transaction history result
        """
        params: Dict[str, Any] = {"url": url, "start": start}
        if count is not None:
            params["count"] = count
        if scratch is not None:
            params["scratch"] = scratch
        return self._call("query-tx-history", params)

    def query_key_page_index(
        self,
        url: str,
        key: str
    ) -> Dict[str, Any]:
        """
        Query the location of a key within key book(s).

        Args:
            url: Account URL
            key: Public key or key hash (hex)

        Returns:
            Key page index result
        """
        return self._call("query-key-page-index", {"url": url, "key": key})

    def query_minor_blocks(
        self,
        url: str,
        start: int = 0,
        count: Optional[int] = None,
        tx_fetch_mode: Optional[int] = None,
        block_filter_mode: Optional[int] = None
    ) -> Dict[str, Any]:
        """
        Query minor blocks for an account.

        Args:
            url: Account URL
            start: Starting block index
            count: Number of blocks
            tx_fetch_mode: Transaction fetch mode
            block_filter_mode: Block filter mode

        Returns:
            Minor blocks result
        """
        params: Dict[str, Any] = {"url": url, "start": start}
        if count is not None:
            params["count"] = count
        if tx_fetch_mode is not None:
            params["txFetchMode"] = tx_fetch_mode
        if block_filter_mode is not None:
            params["blockFilterMode"] = block_filter_mode
        return self._call("query-minor-blocks", params)

    def query_major_blocks(
        self,
        url: str,
        start: int = 0,
        count: Optional[int] = None
    ) -> Dict[str, Any]:
        """
        Query major blocks for an account.

        Args:
            url: Account URL
            start: Starting block index
            count: Number of blocks

        Returns:
            Major blocks result
        """
        params: Dict[str, Any] = {"url": url, "start": start}
        if count is not None:
            params["count"] = count
        return self._call("query-major-blocks", params)

    def query_synth(
        self,
        source: str,
        destination: str,
        sequence_number: Optional[int] = None
    ) -> Dict[str, Any]:
        """
        Query synthetic transactions.

        Args:
            source: Source partition URL
            destination: Destination partition URL
            sequence_number: Specific sequence number

        Returns:
            Synthetic transaction result
        """
        params: Dict[str, Any] = {
            "source": source,
            "destination": destination
        }
        if sequence_number is not None:
            params["sequenceNumber"] = sequence_number
        return self._call("query-synth", params)

    # =========================================================================
    # Faucet
    # =========================================================================

    def faucet(self, url: str) -> Dict[str, Any]:
        """
        Request tokens from the faucet.

        Only available on testnet/devnet.

        Args:
            url: Account URL to fund

        Returns:
            Faucet result with transaction ID
        """
        return self._call("faucet", {"url": url})

    # =========================================================================
    # Status/Info Methods
    # =========================================================================

    def status(self) -> Dict[str, Any]:
        """
        Get node status.

        Returns:
            Node status information
        """
        return self._call("status", {})

    def version(self) -> Dict[str, Any]:
        """
        Get node software version.

        Returns:
            Version information
        """
        return self._call("version", {})

    def describe(self) -> Dict[str, Any]:
        """
        Get network description/configuration.

        Returns:
            Network description
        """
        return self._call("describe", {})

    def metrics(self) -> Dict[str, Any]:
        """
        Get network metrics.

        Returns:
            Network metrics including TPS
        """
        return self._call("metrics", {})


__all__ = [
    "AccumulateV2Client",
    "V2ApiError",
]
