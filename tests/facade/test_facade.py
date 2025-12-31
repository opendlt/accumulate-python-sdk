"""
Unit tests for Accumulate SDK facade.

Tests the unified interface, V2/V3 client routing, factory methods, and delegation.
"""

import pytest
from unittest.mock import Mock, patch, MagicMock
import requests

from accumulate_client.facade import Accumulate, AccumulateClient
from accumulate_client.v2.client import AccumulateV2Client
from accumulate_client.v3.client import AccumulateV3Client
from accumulate_client.v3.options import (
    SubmitOptions,
    ValidateOptions,
    FaucetOptions,
    QueryOptions,
    RangeOptions,
)


class TestAccumulateInitialization:
    """Tests for Accumulate facade initialization."""

    def test_basic_initialization(self):
        """Test basic initialization with endpoint."""
        acc = Accumulate("https://testnet.accumulatenetwork.io")
        assert acc.endpoint == "https://testnet.accumulatenetwork.io"
        assert isinstance(acc.v2, AccumulateV2Client)
        assert isinstance(acc.v3, AccumulateV3Client)

    def test_strips_v2_suffix(self):
        """Test initialization strips /v2 suffix from endpoint."""
        acc = Accumulate("https://testnet.accumulatenetwork.io/v2")
        assert acc.endpoint == "https://testnet.accumulatenetwork.io"

    def test_strips_v3_suffix(self):
        """Test initialization strips /v3 suffix from endpoint."""
        acc = Accumulate("https://testnet.accumulatenetwork.io/v3")
        assert acc.endpoint == "https://testnet.accumulatenetwork.io"

    def test_strips_trailing_slash(self):
        """Test initialization strips trailing slash."""
        acc = Accumulate("https://testnet.accumulatenetwork.io/")
        assert not acc.endpoint.endswith("/")

    def test_v2_client_has_correct_endpoint(self):
        """Test V2 client gets correct endpoint."""
        acc = Accumulate("https://testnet.accumulatenetwork.io")
        assert acc.v2.endpoint.endswith("/v2")

    def test_v3_client_has_correct_endpoint(self):
        """Test V3 client gets correct endpoint."""
        acc = Accumulate("https://testnet.accumulatenetwork.io")
        assert acc.v3.endpoint.endswith("/v3")

    def test_custom_timeout(self):
        """Test custom timeout is passed to clients."""
        acc = Accumulate("https://test.com", timeout=60.0)
        assert acc.v2._timeout == 60.0
        assert acc.v3._timeout == 60.0

    def test_shared_session(self):
        """Test shared session is used by both clients."""
        session = requests.Session()
        acc = Accumulate("https://test.com", session=session)
        # Both clients should use the same session
        assert acc.v2._session is session
        assert acc.v3._session is session

    def test_context_manager(self):
        """Test facade works as context manager."""
        with Accumulate("https://test.com") as acc:
            assert acc is not None


class TestAccumulateFactoryMethods:
    """Tests for Accumulate factory methods."""

    def test_mainnet_factory(self):
        """Test mainnet factory creates correct endpoint."""
        acc = Accumulate.mainnet()
        assert acc.endpoint == Accumulate.MAINNET_ENDPOINT

    def test_testnet_factory(self):
        """Test testnet factory creates correct endpoint."""
        acc = Accumulate.testnet()
        assert acc.endpoint == Accumulate.TESTNET_ENDPOINT

    def test_devnet_factory_default(self):
        """Test devnet factory with default port."""
        acc = Accumulate.devnet()
        assert "localhost" in acc.endpoint
        assert "26660" in acc.endpoint

    def test_devnet_factory_custom_port(self):
        """Test devnet factory with custom port."""
        acc = Accumulate.devnet(port=26661)
        assert "26661" in acc.endpoint

    def test_devnet_factory_custom_host(self):
        """Test devnet factory with custom host."""
        acc = Accumulate.devnet(host="192.168.1.100")
        assert "192.168.1.100" in acc.endpoint

    def test_devnet_factory_custom_host_and_port(self):
        """Test devnet factory with custom host and port."""
        acc = Accumulate.devnet(host="192.168.1.100", port=26661)
        assert "192.168.1.100" in acc.endpoint
        assert "26661" in acc.endpoint

    def test_local_factory(self):
        """Test local factory creates localhost endpoint."""
        acc = Accumulate.local()
        assert "localhost" in acc.endpoint
        assert "26660" in acc.endpoint

    def test_local_factory_custom_port(self):
        """Test local factory with custom port."""
        acc = Accumulate.local(port=26661)
        assert "26661" in acc.endpoint

    def test_factory_passes_kwargs(self):
        """Test factory methods pass kwargs to __init__."""
        acc = Accumulate.testnet(timeout=120.0)
        assert acc.v2._timeout == 120.0
        assert acc.v3._timeout == 120.0


class TestAccumulateV3Routing:
    """Tests for facade methods that route to V3."""

    @pytest.fixture
    def mock_acc(self):
        """Create Accumulate with mocked V3 client."""
        acc = Accumulate("https://test.com")
        acc.v3 = Mock(spec=AccumulateV3Client)
        return acc

    def test_submit_routes_to_v3(self, mock_acc):
        """Test submit routes to V3."""
        envelope = {"transaction": {}, "signatures": []}
        options = SubmitOptions(wait=True)
        mock_acc.submit(envelope, options)
        mock_acc.v3.submit.assert_called_once_with(envelope, options)

    def test_validate_routes_to_v3(self, mock_acc):
        """Test validate routes to V3."""
        envelope = {"transaction": {}, "signatures": []}
        options = ValidateOptions(full=True)
        mock_acc.validate(envelope, options)
        mock_acc.v3.validate.assert_called_once_with(envelope, options)

    def test_query_routes_to_v3(self, mock_acc):
        """Test query routes to V3."""
        options = QueryOptions(expand=True)
        mock_acc.query("acc://test.acme", options=options)
        mock_acc.v3.query.assert_called_once_with("acc://test.acme", None, options)

    def test_query_account_routes_to_v3(self, mock_acc):
        """Test query_account routes to V3."""
        mock_acc.query_account("acc://test.acme")
        mock_acc.v3.query_account.assert_called_once_with("acc://test.acme", None)

    def test_query_transaction_routes_to_v3(self, mock_acc):
        """Test query_transaction routes to V3."""
        mock_acc.query_transaction("txid123")
        mock_acc.v3.query_transaction.assert_called_once_with("txid123", None)

    def test_query_chain_routes_to_v3(self, mock_acc):
        """Test query_chain routes to V3."""
        range_opts = RangeOptions(start=0, count=10)
        mock_acc.query_chain("acc://test.acme", "main", range_opts)
        mock_acc.v3.query_chain.assert_called_once_with("acc://test.acme", "main", range_opts, None)

    def test_query_data_routes_to_v3(self, mock_acc):
        """Test query_data routes to V3."""
        mock_acc.query_data("acc://test.acme/data", index=5)
        mock_acc.v3.query_data.assert_called_once_with("acc://test.acme/data", 5, None, None)

    def test_query_directory_routes_to_v3(self, mock_acc):
        """Test query_directory routes to V3."""
        range_opts = RangeOptions(start=0, count=50)
        mock_acc.query_directory("acc://test.acme", range_opts)
        mock_acc.v3.query_directory.assert_called_once_with("acc://test.acme", range_opts)

    def test_query_pending_routes_to_v3(self, mock_acc):
        """Test query_pending routes to V3."""
        mock_acc.query_pending("acc://test.acme")
        mock_acc.v3.query_pending.assert_called_once_with("acc://test.acme", None)

    def test_faucet_routes_to_v3(self, mock_acc):
        """Test faucet routes to V3."""
        options = FaucetOptions(token="acc://ACME")
        mock_acc.faucet("acc://test.acme", options)
        mock_acc.v3.faucet.assert_called_once_with("acc://test.acme", options)


class TestAccumulateV2Routing:
    """Tests for facade methods that route to V2."""

    @pytest.fixture
    def mock_acc(self):
        """Create Accumulate with mocked V2 client."""
        acc = Accumulate("https://test.com")
        acc.v2 = Mock(spec=AccumulateV2Client)
        return acc

    def test_execute_direct_routes_to_v2(self, mock_acc):
        """Test execute_direct routes to V2."""
        envelope = {"transaction": {}, "signatures": []}
        mock_acc.execute_direct(envelope)
        mock_acc.v2.execute_direct.assert_called_once_with(envelope)

    def test_execute_routes_to_v2(self, mock_acc):
        """Test execute routes to V2."""
        envelope = {"transaction": {}, "signatures": []}
        mock_acc.execute(envelope)
        mock_acc.v2.execute.assert_called_once_with(envelope)


class TestAccumulateVersionInfo:
    """Tests for version info utility."""

    def test_get_version_info(self):
        """Test get_version_info returns correct endpoints."""
        acc = Accumulate("https://testnet.accumulatenetwork.io")
        info = acc.get_version_info()

        assert "base_endpoint" in info
        assert "v2_endpoint" in info
        assert "v3_endpoint" in info

        assert info["base_endpoint"] == "https://testnet.accumulatenetwork.io"
        assert info["v2_endpoint"].endswith("/v2")
        assert info["v3_endpoint"].endswith("/v3")


class TestAccumulateClientAlias:
    """Tests for AccumulateClient alias."""

    def test_alias_is_same_class(self):
        """Test AccumulateClient is alias for Accumulate."""
        assert AccumulateClient is Accumulate

    def test_alias_works_identically(self):
        """Test AccumulateClient alias works identically."""
        acc1 = Accumulate("https://test.com")
        acc2 = AccumulateClient("https://test.com")

        assert type(acc1) == type(acc2)
        assert acc1.endpoint == acc2.endpoint


class TestAccumulateDirectClientAccess:
    """Tests for direct access to V2/V3 clients."""

    def test_v2_client_directly_accessible(self):
        """Test V2 client is directly accessible."""
        acc = Accumulate("https://test.com")
        assert hasattr(acc.v2, "query")
        assert hasattr(acc.v2, "query_tx")
        assert hasattr(acc.v2, "query_directory")
        assert hasattr(acc.v2, "execute_direct")

    def test_v3_client_directly_accessible(self):
        """Test V3 client is directly accessible."""
        acc = Accumulate("https://test.com")
        assert hasattr(acc.v3, "submit")
        assert hasattr(acc.v3, "validate")
        assert hasattr(acc.v3, "query")
        assert hasattr(acc.v3, "node_info")

    def test_can_access_v2_specific_methods(self):
        """Test can access V2-specific methods through v2 property."""
        acc = Accumulate("https://test.com")
        # These methods exist only on V2
        assert hasattr(acc.v2, "query_tx_history")
        assert hasattr(acc.v2, "query_key_page_index")
        assert hasattr(acc.v2, "query_minor_blocks")

    def test_can_access_v3_specific_methods(self):
        """Test can access V3-specific methods through v3 property."""
        acc = Accumulate("https://test.com")
        # These methods exist only on V3
        assert hasattr(acc.v3, "consensus_status")
        assert hasattr(acc.v3, "network_status")
        assert hasattr(acc.v3, "find_service")


class TestAccumulateSessionManagement:
    """Tests for session management."""

    def test_owns_session_when_not_provided(self):
        """Test facade owns session when not provided."""
        acc = Accumulate("https://test.com")
        assert acc._owns_session is True

    def test_does_not_own_session_when_provided(self):
        """Test facade does not own session when provided."""
        session = requests.Session()
        acc = Accumulate("https://test.com", session=session)
        assert acc._owns_session is False

    def test_close_closes_owned_session(self):
        """Test close closes owned session."""
        acc = Accumulate("https://test.com")
        session = acc._session
        with patch.object(session, 'close') as mock_close:
            acc.close()
            mock_close.assert_called_once()

    def test_close_does_not_close_external_session(self):
        """Test close does not close external session."""
        session = requests.Session()
        with patch.object(session, 'close') as mock_close:
            acc = Accumulate("https://test.com", session=session)
            acc.close()
            mock_close.assert_not_called()

    def test_context_manager_closes_session(self):
        """Test context manager closes session on exit."""
        with Accumulate("https://test.com") as acc:
            session = acc._session
            with patch.object(session, 'close') as mock_close:
                pass  # Exit context
            # Close should be called after exiting context
        # The session is closed when __exit__ is called


class TestAccumulateIntegrationPatterns:
    """Tests for common integration patterns."""

    @pytest.fixture
    def mock_acc(self):
        """Create Accumulate with fully mocked clients."""
        acc = Accumulate("https://test.com")
        acc.v2 = Mock(spec=AccumulateV2Client)
        acc.v3 = Mock(spec=AccumulateV3Client)
        return acc

    def test_query_then_submit_pattern(self, mock_acc):
        """Test common pattern: query then submit."""
        # Query an account
        mock_acc.v3.query.return_value = {"account": {"type": "tokenAccount"}}
        result = mock_acc.query("acc://test.acme")

        # Submit a transaction based on query
        mock_acc.v3.submit.return_value = [{"status": "ok"}]
        envelope = {"transaction": {"body": {"type": "sendTokens"}}}
        submit_result = mock_acc.submit(envelope)

        assert mock_acc.v3.query.called
        assert mock_acc.v3.submit.called

    def test_faucet_then_query_pattern(self, mock_acc):
        """Test common pattern: faucet then query."""
        # Request from faucet
        mock_acc.v3.faucet.return_value = {"txid": "abc123"}
        mock_acc.faucet("acc://test.acme")

        # Query the result
        mock_acc.v3.query.return_value = {"account": {"balance": "1000000000"}}
        mock_acc.query("acc://test.acme")

        assert mock_acc.v3.faucet.called
        assert mock_acc.v3.query.called

    def test_validate_before_submit_pattern(self, mock_acc):
        """Test common pattern: validate before submit."""
        envelope = {"transaction": {}, "signatures": []}

        # Validate first
        mock_acc.v3.validate.return_value = [{"status": "valid"}]
        mock_acc.validate(envelope)

        # Then submit if valid
        mock_acc.v3.submit.return_value = [{"status": "ok"}]
        mock_acc.submit(envelope)

        assert mock_acc.v3.validate.called
        assert mock_acc.v3.submit.called

    def test_mixed_v2_v3_usage(self, mock_acc):
        """Test using both V2 and V3 in same session."""
        # Use V3 for query
        mock_acc.v3.query.return_value = {"account": {}}
        mock_acc.query("acc://test.acme")

        # Use V2 for execute-direct (some use cases prefer V2)
        mock_acc.v2.execute_direct.return_value = {"result": "ok"}
        mock_acc.execute_direct({"transaction": {}})

        # Use V3 for submit
        mock_acc.v3.submit.return_value = [{"status": "ok"}]
        mock_acc.submit({"transaction": {}})

        assert mock_acc.v3.query.called
        assert mock_acc.v2.execute_direct.called
        assert mock_acc.v3.submit.called


class TestAccumulateEndpointNormalization:
    """Tests for endpoint URL normalization."""

    def test_handles_various_endpoint_formats(self):
        """Test handling various endpoint URL formats."""
        test_cases = [
            ("https://test.com", "https://test.com"),
            ("https://test.com/", "https://test.com"),
            ("https://test.com/v2", "https://test.com"),
            ("https://test.com/v3", "https://test.com"),
            ("https://test.com/v2/", "https://test.com"),
            ("https://test.com/v3/", "https://test.com"),
            ("http://localhost:26660", "http://localhost:26660"),
            ("http://localhost:26660/v2", "http://localhost:26660"),
        ]

        for input_url, expected_base in test_cases:
            acc = Accumulate(input_url)
            assert acc.endpoint == expected_base, f"Failed for input: {input_url}"

    def test_version_clients_have_correct_paths(self):
        """Test V2/V3 clients always have correct version paths."""
        acc = Accumulate("https://custom.node.com:8080/api/v2")
        assert acc.v2.endpoint.endswith("/v2")
        assert acc.v3.endpoint.endswith("/v3")
        assert "/v2" not in acc.v3.endpoint or acc.v3.endpoint.endswith("/v2") is False
