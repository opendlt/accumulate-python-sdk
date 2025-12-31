"""
Accumulate SDK Facade.

Provides a unified interface for interacting with the Accumulate blockchain
with clean V2/V3 separation matching Dart SDK patterns.

The Accumulate class is the primary entry point for SDK users.

Example:
    ```python
    from accumulate_client import Accumulate

    # Connect to testnet
    acc = Accumulate.testnet()

    # Or connect to custom endpoint
    acc = Accumulate("https://my-node.example.com")

    # Use V3 API (default)
    result = acc.query("acc://my-adi.acme")
    result = acc.submit(envelope)

    # Access V2 API when needed
    result = acc.v2.execute_direct(envelope)

    # Access V3 API explicitly
    result = acc.v3.submit(envelope, SubmitOptions(wait=True))
    ```
"""

from __future__ import annotations
from typing import Optional, Dict, Any, List, Union, TYPE_CHECKING
import requests

from .v2.client import AccumulateV2Client
from .v3.client import AccumulateV3Client

if TYPE_CHECKING:
    from .v3.options import (
        SubmitOptions,
        ValidateOptions,
        FaucetOptions,
        QueryOptions,
        QueryType,
        RangeOptions,
    )


class Accumulate:
    """
    Main Accumulate SDK facade with V2 and V3 clients.

    Provides a unified interface for blockchain interaction with automatic
    routing to the appropriate API version. Default operations route to V3.

    Attributes:
        v2: AccumulateV2Client for legacy V2 API access
        v3: AccumulateV3Client for current V3 API access

    Example:
        ```python
        # Create client for testnet
        acc = Accumulate.testnet()

        # Query an account (uses V3)
        account = acc.query("acc://my-adi.acme")

        # Submit a transaction (uses V3)
        result = acc.submit(envelope)

        # Use V2 execute-direct when needed
        result = acc.execute_direct(envelope)

        # Or access V2/V3 clients directly
        result = acc.v2.query_tx_history("acc://my-adi.acme", start=0, count=10)
        result = acc.v3.query_directory("acc://my-adi.acme")
        ```
    """

    # =========================================================================
    # Well-known endpoints
    # =========================================================================

    MAINNET_ENDPOINT = "https://mainnet.accumulatenetwork.io"
    TESTNET_ENDPOINT = "https://testnet.accumulatenetwork.io"
    DEFAULT_DEVNET_PORT = 26660

    def __init__(
        self,
        endpoint: str,
        timeout: float = 30.0,
        session: Optional[requests.Session] = None
    ):
        """
        Initialize the Accumulate facade.

        Args:
            endpoint: API endpoint URL (version path will be auto-appended)
            timeout: Request timeout in seconds (default: 30)
            session: Optional shared requests.Session for connection pooling

        Example:
            ```python
            # Simple initialization
            acc = Accumulate("https://testnet.accumulatenetwork.io")

            # With custom timeout
            acc = Accumulate("https://testnet.accumulatenetwork.io", timeout=60)

            # With shared session for connection pooling
            session = requests.Session()
            acc = Accumulate("https://testnet.accumulatenetwork.io", session=session)
            ```
        """
        # Normalize the base endpoint by removing any version suffix
        base_endpoint = endpoint.rstrip('/')
        for suffix in ['/v2', '/v3']:
            if base_endpoint.endswith(suffix):
                base_endpoint = base_endpoint[:-len(suffix)]

        self._base_endpoint = base_endpoint
        self._timeout = timeout
        self._session = session or requests.Session()
        self._owns_session = session is None

        # Create versioned clients
        self.v2 = AccumulateV2Client(
            base_endpoint,
            timeout=timeout,
            session=self._session
        )
        self.v3 = AccumulateV3Client(
            base_endpoint,
            timeout=timeout,
            session=self._session
        )

    @property
    def endpoint(self) -> str:
        """Get the base endpoint (without version path)."""
        return self._base_endpoint

    def close(self) -> None:
        """
        Close the HTTP session.

        Only closes if the session was created by this facade.
        """
        if self._owns_session:
            self._session.close()

    def __enter__(self) -> Accumulate:
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.close()

    # =========================================================================
    # Factory Methods
    # =========================================================================

    @classmethod
    def mainnet(cls, **kwargs) -> Accumulate:
        """
        Connect to Accumulate mainnet.

        Args:
            **kwargs: Additional arguments passed to __init__

        Returns:
            Accumulate facade connected to mainnet

        Example:
            ```python
            acc = Accumulate.mainnet()
            ```
        """
        return cls(cls.MAINNET_ENDPOINT, **kwargs)

    @classmethod
    def testnet(cls, **kwargs) -> Accumulate:
        """
        Connect to Accumulate testnet.

        Args:
            **kwargs: Additional arguments passed to __init__

        Returns:
            Accumulate facade connected to testnet

        Example:
            ```python
            acc = Accumulate.testnet()
            ```
        """
        return cls(cls.TESTNET_ENDPOINT, **kwargs)

    @classmethod
    def devnet(cls, host: str = "localhost", port: int = None, **kwargs) -> Accumulate:
        """
        Connect to a local devnet.

        Args:
            host: Devnet host (default: localhost)
            port: Devnet port (default: 26660)
            **kwargs: Additional arguments passed to __init__

        Returns:
            Accumulate facade connected to devnet

        Example:
            ```python
            # Default localhost:26660
            acc = Accumulate.devnet()

            # Custom port
            acc = Accumulate.devnet(port=26661)

            # Custom host and port
            acc = Accumulate.devnet(host="192.168.1.100", port=26660)
            ```
        """
        if port is None:
            port = cls.DEFAULT_DEVNET_PORT
        return cls(f"http://{host}:{port}", **kwargs)

    @classmethod
    def local(cls, port: int = None, **kwargs) -> Accumulate:
        """
        Connect to localhost (alias for devnet with localhost).

        Args:
            port: Port number (default: 26660)
            **kwargs: Additional arguments passed to __init__

        Returns:
            Accumulate facade connected to localhost
        """
        return cls.devnet(host="localhost", port=port, **kwargs)

    # =========================================================================
    # V3 API Methods (Default)
    # =========================================================================

    def submit(
        self,
        envelope: Dict[str, Any],
        options: Optional[SubmitOptions] = None
    ) -> List[Dict[str, Any]]:
        """
        Submit a transaction (routes to V3).

        Args:
            envelope: Transaction envelope with transaction and signatures
            options: Submit options (verify, wait)

        Returns:
            List of submission results

        Example:
            ```python
            from accumulate_client.v3 import SubmitOptions

            result = acc.submit(envelope, SubmitOptions(wait=True))
            ```
        """
        return self.v3.submit(envelope, options)

    def validate(
        self,
        envelope: Dict[str, Any],
        options: Optional[ValidateOptions] = None
    ) -> List[Dict[str, Any]]:
        """
        Validate a transaction without submitting (routes to V3).

        Args:
            envelope: Transaction envelope to validate
            options: Validation options

        Returns:
            Validation results
        """
        return self.v3.validate(envelope, options)

    def query(
        self,
        scope: str,
        query: Optional[QueryType] = None,
        options: Optional[QueryOptions] = None
    ) -> Dict[str, Any]:
        """
        Query an account or perform a specific query (routes to V3).

        Args:
            scope: Account URL to query
            query: Optional specific query type
            options: Query options

        Returns:
            Query result

        Example:
            ```python
            # Simple query
            result = acc.query("acc://my-adi.acme")

            # With query options
            from accumulate_client.v3 import QueryOptions
            result = acc.query("acc://my-adi.acme", options=QueryOptions(expand=True))
            ```
        """
        return self.v3.query(scope, query, options)

    def query_account(
        self,
        url: str,
        options: Optional[QueryOptions] = None
    ) -> Dict[str, Any]:
        """
        Query account state (routes to V3).

        Args:
            url: Account URL
            options: Query options

        Returns:
            Account record
        """
        return self.v3.query_account(url, options)

    def query_transaction(
        self,
        txid: str,
        options: Optional[QueryOptions] = None
    ) -> Dict[str, Any]:
        """
        Query a transaction by ID (routes to V3).

        Args:
            txid: Transaction ID
            options: Query options

        Returns:
            Transaction record
        """
        return self.v3.query_transaction(txid, options)

    def query_chain(
        self,
        url: str,
        chain_name: str,
        range_options: Optional[RangeOptions] = None,
        options: Optional[QueryOptions] = None
    ) -> Dict[str, Any]:
        """
        Query chain entries (routes to V3).

        Args:
            url: Account URL
            chain_name: Chain name
            range_options: Pagination options
            options: Query options

        Returns:
            Chain query result
        """
        return self.v3.query_chain(url, chain_name, range_options, options)

    def query_data(
        self,
        url: str,
        index: Optional[int] = None,
        entry_hash: Optional[Union[bytes, str]] = None,
        range_options: Optional[RangeOptions] = None
    ) -> Dict[str, Any]:
        """
        Query data chain entries (routes to V3).

        Args:
            url: Data account URL
            index: Specific entry index
            entry_hash: Specific entry hash
            range_options: Pagination options

        Returns:
            Data query result
        """
        return self.v3.query_data(url, index, entry_hash, range_options)

    def query_directory(
        self,
        url: str,
        range_options: Optional[RangeOptions] = None
    ) -> Dict[str, Any]:
        """
        Query account directory (routes to V3).

        Args:
            url: Identity or directory URL
            range_options: Pagination options

        Returns:
            Directory listing
        """
        return self.v3.query_directory(url, range_options)

    def query_pending(
        self,
        url: str,
        range_options: Optional[RangeOptions] = None
    ) -> Dict[str, Any]:
        """
        Query pending transactions (routes to V3).

        Args:
            url: Account URL
            range_options: Pagination options

        Returns:
            Pending transactions
        """
        return self.v3.query_pending(url, range_options)

    def faucet(
        self,
        account: str,
        options: Optional[FaucetOptions] = None
    ) -> Dict[str, Any]:
        """
        Request tokens from the faucet (routes to V3).

        Only available on testnet/devnet.

        Args:
            account: Account URL to fund
            options: Faucet options

        Returns:
            Faucet result
        """
        return self.v3.faucet(account, options)

    # =========================================================================
    # V2 Convenience Methods
    # =========================================================================

    def execute_direct(self, envelope: Dict[str, Any]) -> Dict[str, Any]:
        """
        Execute transaction directly (routes to V2).

        This is the primary V2 execution method.

        Args:
            envelope: Transaction envelope

        Returns:
            Execution result
        """
        return self.v2.execute_direct(envelope)

    def execute(self, envelope: Dict[str, Any]) -> Dict[str, Any]:
        """
        Execute a transaction (routes to V2).

        Args:
            envelope: Transaction envelope

        Returns:
            Execution result
        """
        return self.v2.execute(envelope)

    # =========================================================================
    # Utility Methods
    # =========================================================================

    def get_version_info(self) -> Dict[str, str]:
        """
        Get API version information.

        Returns:
            Dictionary with endpoint info
        """
        return {
            "base_endpoint": self._base_endpoint,
            "v2_endpoint": self.v2.endpoint,
            "v3_endpoint": self.v3.endpoint,
        }


# =============================================================================
# Convenience Aliases
# =============================================================================

# Alias for common usage
AccumulateClient = Accumulate


__all__ = [
    "Accumulate",
    "AccumulateClient",
]
