"""
Unit tests for V3 API client.

Tests client initialization, endpoint handling, method signatures, and RPC calls.
"""

import pytest
from unittest.mock import Mock, patch, MagicMock
import json

from accumulate_client.v3.client import AccumulateV3Client, V3ApiError
from accumulate_client.v3.options import (
    SubmitOptions,
    ValidateOptions,
    FaucetOptions,
    QueryOptions,
    RangeOptions,
    ChainQuery,
    DataQuery,
    DirectoryQuery,
    PendingQuery,
    BlockQuery,
    AnchorSearchQuery,
    PublicKeySearchQuery,
    PublicKeyHashSearchQuery,
    DelegateSearchQuery,
    NodeInfoOptions,
    ServiceAddress,
    FindServiceOptions,
    ConsensusStatusOptions,
    NetworkStatusOptions,
    MetricsOptions,
)


class TestV3ClientInitialization:
    """Tests for V3 client initialization."""

    def test_endpoint_auto_suffix(self):
        """Test endpoint gets /v3 suffix automatically."""
        client = AccumulateV3Client("https://testnet.accumulatenetwork.io")
        assert client.endpoint.endswith("/v3")

    def test_endpoint_preserves_v3(self):
        """Test endpoint preserves existing /v3 suffix."""
        client = AccumulateV3Client("https://testnet.accumulatenetwork.io/v3")
        assert client.endpoint == "https://testnet.accumulatenetwork.io/v3"

    def test_endpoint_replaces_v2(self):
        """Test endpoint replaces /v2 with /v3."""
        client = AccumulateV3Client("https://testnet.accumulatenetwork.io/v2")
        assert client.endpoint.endswith("/v3")
        assert "/v2" not in client.endpoint

    def test_endpoint_strips_trailing_slash(self):
        """Test endpoint strips trailing slash before appending."""
        client = AccumulateV3Client("https://testnet.accumulatenetwork.io/")
        assert not client.endpoint.endswith("//v3")
        assert client.endpoint.endswith("/v3")

    def test_custom_timeout(self):
        """Test custom timeout is set."""
        client = AccumulateV3Client("https://test.com", timeout=60.0)
        assert client._timeout == 60.0

    def test_default_timeout(self):
        """Test default timeout."""
        client = AccumulateV3Client("https://test.com")
        assert client._timeout == 30.0

    def test_context_manager(self):
        """Test client works as context manager."""
        with AccumulateV3Client("https://test.com") as client:
            assert client is not None


class TestV3ApiError:
    """Tests for V3ApiError exception."""

    def test_basic_error(self):
        """Test basic error message."""
        err = V3ApiError("Test error")
        assert "Test error" in str(err)

    def test_error_with_code(self):
        """Test error with code."""
        err = V3ApiError("Test error", code=500)
        assert "500" in str(err)
        assert err.code == 500

    def test_error_with_data(self):
        """Test error with data."""
        err = V3ApiError("Test error", data={"details": "info"})
        assert err.data == {"details": "info"}


class TestV3ClientSubmitterService:
    """Tests for V3 client submitter/validator service methods."""

    @pytest.fixture
    def mock_client(self):
        """Create a client with mocked _call."""
        client = AccumulateV3Client("https://test.com")
        client._call = Mock(return_value={"result": "test"})
        return client

    def test_submit_basic(self, mock_client):
        """Test submit with basic envelope."""
        envelope = {"transaction": {"body": {"type": "test"}}, "signatures": []}
        mock_client.submit(envelope)
        mock_client._call.assert_called_once_with("submit", {"envelope": envelope})

    def test_submit_with_options(self, mock_client):
        """Test submit with options."""
        envelope = {"transaction": {}, "signatures": []}
        options = SubmitOptions(verify=True, wait=True)
        mock_client.submit(envelope, options)
        call_args = mock_client._call.call_args
        assert call_args[0][0] == "submit"
        params = call_args[0][1]
        assert params["envelope"] == envelope
        assert params["verify"] is True
        assert params["wait"] is True

    def test_submit_returns_list(self, mock_client):
        """Test submit returns list of results."""
        mock_client._call.return_value = {"status": "ok"}
        result = mock_client.submit({})
        assert isinstance(result, list)
        assert result[0] == {"status": "ok"}

    def test_submit_preserves_list_result(self, mock_client):
        """Test submit preserves list result from RPC."""
        mock_client._call.return_value = [{"status": "ok"}, {"status": "ok2"}]
        result = mock_client.submit({})
        assert len(result) == 2

    def test_validate_basic(self, mock_client):
        """Test validate with basic envelope."""
        envelope = {"transaction": {}, "signatures": []}
        mock_client.validate(envelope)
        mock_client._call.assert_called_once_with("validate", {"envelope": envelope})

    def test_validate_with_options(self, mock_client):
        """Test validate with full option."""
        envelope = {"transaction": {}, "signatures": []}
        options = ValidateOptions(full=True)
        mock_client.validate(envelope, options)
        call_args = mock_client._call.call_args
        params = call_args[0][1]
        assert params["full"] is True


class TestV3ClientFaucetService:
    """Tests for V3 client faucet service methods."""

    @pytest.fixture
    def mock_client(self):
        """Create a client with mocked _call."""
        client = AccumulateV3Client("https://test.com")
        client._call = Mock(return_value={"txid": "abc123"})
        return client

    def test_faucet_basic(self, mock_client):
        """Test faucet with account URL."""
        mock_client.faucet("acc://test.acme")
        mock_client._call.assert_called_once_with("faucet", {"account": "acc://test.acme"})

    def test_faucet_with_options(self, mock_client):
        """Test faucet with token option."""
        options = FaucetOptions(token="acc://ACME")
        mock_client.faucet("acc://test.acme", options)
        call_args = mock_client._call.call_args
        params = call_args[0][1]
        assert params["account"] == "acc://test.acme"
        assert params["token"] == "acc://ACME"


class TestV3ClientQuerierService:
    """Tests for V3 client querier service methods."""

    @pytest.fixture
    def mock_client(self):
        """Create a client with mocked _call."""
        client = AccumulateV3Client("https://test.com")
        client._call = Mock(return_value={"data": {}})
        return client

    def test_query_basic(self, mock_client):
        """Test basic query with scope."""
        mock_client.query("acc://test.acme")
        mock_client._call.assert_called_once_with("query", {"scope": "acc://test.acme"})

    def test_query_with_chain_query(self, mock_client):
        """Test query with ChainQuery."""
        query = ChainQuery(name="main", range=RangeOptions(start=0, count=10))
        mock_client.query("acc://test.acme", query=query)
        call_args = mock_client._call.call_args
        params = call_args[0][1]
        assert params["scope"] == "acc://test.acme"
        assert params["query"]["queryType"] == "chain"
        assert params["query"]["name"] == "main"

    def test_query_with_options(self, mock_client):
        """Test query with QueryOptions."""
        options = QueryOptions(expand=True, prove=True, height=100)
        mock_client.query("acc://test.acme", options=options)
        call_args = mock_client._call.call_args
        params = call_args[0][1]
        assert params["expand"] is True
        assert params["prove"] is True
        assert params["height"] == 100

    def test_query_account(self, mock_client):
        """Test query_account convenience method."""
        mock_client.query_account("acc://test.acme")
        mock_client._call.assert_called_once_with("query", {"scope": "acc://test.acme"})

    def test_query_transaction(self, mock_client):
        """Test query_transaction convenience method."""
        mock_client.query_transaction("abc123")
        mock_client._call.assert_called_once_with("query", {"scope": "abc123"})

    def test_query_chain(self, mock_client):
        """Test query_chain convenience method."""
        range_opts = RangeOptions(start=0, count=10)
        mock_client.query_chain("acc://test.acme", "main", range_opts)
        call_args = mock_client._call.call_args
        params = call_args[0][1]
        assert params["query"]["queryType"] == "chain"
        assert params["query"]["name"] == "main"
        assert params["query"]["range"]["start"] == 0
        assert params["query"]["range"]["count"] == 10

    def test_query_data_by_index(self, mock_client):
        """Test query_data with index."""
        mock_client.query_data("acc://test.acme/data", index=5)
        call_args = mock_client._call.call_args
        params = call_args[0][1]
        assert params["query"]["queryType"] == "data"
        assert params["query"]["index"] == 5

    def test_query_data_by_hash(self, mock_client):
        """Test query_data with entry hash."""
        mock_client.query_data("acc://test.acme/data", entry_hash="abcd1234")
        call_args = mock_client._call.call_args
        params = call_args[0][1]
        assert params["query"]["queryType"] == "data"
        assert params["query"]["entry"] == "abcd1234"

    def test_query_directory(self, mock_client):
        """Test query_directory convenience method."""
        range_opts = RangeOptions(start=0, count=50)
        mock_client.query_directory("acc://test.acme", range_opts)
        call_args = mock_client._call.call_args
        params = call_args[0][1]
        assert params["query"]["queryType"] == "directory"
        assert params["query"]["range"]["count"] == 50

    def test_query_pending(self, mock_client):
        """Test query_pending convenience method."""
        mock_client.query_pending("acc://test.acme")
        call_args = mock_client._call.call_args
        params = call_args[0][1]
        assert params["query"]["queryType"] == "pending"

    def test_query_minor_blocks(self, mock_client):
        """Test query_minor_blocks convenience method."""
        mock_client.query_minor_blocks("acc://test.acme", index=100)
        call_args = mock_client._call.call_args
        params = call_args[0][1]
        assert params["query"]["queryType"] == "block"
        assert params["query"]["minor"] == 100

    def test_query_major_blocks(self, mock_client):
        """Test query_major_blocks convenience method."""
        range_opts = RangeOptions(start=0, count=5)
        mock_client.query_major_blocks("acc://test.acme", range_options=range_opts, omit_empty=True)
        call_args = mock_client._call.call_args
        params = call_args[0][1]
        assert params["query"]["queryType"] == "block"
        assert params["query"]["omitEmpty"] is True
        assert params["query"]["majorRange"]["count"] == 5


class TestV3ClientSearchQueries:
    """Tests for V3 client search query methods."""

    @pytest.fixture
    def mock_client(self):
        """Create a client with mocked _call."""
        client = AccumulateV3Client("https://test.com")
        client._call = Mock(return_value={"records": []})
        return client

    def test_search_anchor(self, mock_client):
        """Test search_anchor method."""
        mock_client.search_anchor("acc://test.acme", "abcd1234" * 8)
        call_args = mock_client._call.call_args
        params = call_args[0][1]
        assert params["query"]["queryType"] == "anchor"
        assert params["query"]["anchor"] == "abcd1234" * 8

    def test_search_public_key(self, mock_client):
        """Test search_public_key method."""
        pubkey = "abcd" * 16  # 32 bytes hex
        mock_client.search_public_key("acc://test.acme", pubkey, "ed25519")
        call_args = mock_client._call.call_args
        params = call_args[0][1]
        assert params["query"]["queryType"] == "publicKey"
        assert params["query"]["publicKey"] == pubkey
        assert params["query"]["type"] == "ed25519"

    def test_search_public_key_hash(self, mock_client):
        """Test search_public_key_hash method."""
        keyhash = "1234" * 16
        mock_client.search_public_key_hash("acc://test.acme", keyhash)
        call_args = mock_client._call.call_args
        params = call_args[0][1]
        assert params["query"]["queryType"] == "publicKeyHash"
        assert params["query"]["publicKeyHash"] == keyhash

    def test_search_delegate(self, mock_client):
        """Test search_delegate method."""
        mock_client.search_delegate("acc://test.acme", "acc://delegate.acme")
        call_args = mock_client._call.call_args
        params = call_args[0][1]
        assert params["query"]["queryType"] == "delegate"
        assert params["query"]["delegate"] == "acc://delegate.acme"


class TestV3ClientNodeService:
    """Tests for V3 client node service methods."""

    @pytest.fixture
    def mock_client(self):
        """Create a client with mocked _call."""
        client = AccumulateV3Client("https://test.com")
        client._call = Mock(return_value={"nodeId": "test-node"})
        return client

    def test_node_info_basic(self, mock_client):
        """Test node_info without options."""
        mock_client.node_info()
        mock_client._call.assert_called_once_with("node-info", None)

    def test_node_info_with_options(self, mock_client):
        """Test node_info with peer_id option."""
        options = NodeInfoOptions(peer_id="peer123")
        mock_client.node_info(options)
        call_args = mock_client._call.call_args
        params = call_args[0][1]
        assert params["peerID"] == "peer123"

    def test_find_service_basic(self, mock_client):
        """Test find_service without options."""
        mock_client._call.return_value = []
        mock_client.find_service()
        mock_client._call.assert_called_once_with("find-service", None)

    def test_find_service_with_options(self, mock_client):
        """Test find_service with options."""
        mock_client._call.return_value = [{"address": "test"}]
        options = FindServiceOptions(
            network="mainnet",
            service=ServiceAddress(type="node", argument="query"),
            known=True,
            timeout=5.0
        )
        result = mock_client.find_service(options)
        call_args = mock_client._call.call_args
        params = call_args[0][1]
        assert params["network"] == "mainnet"
        assert params["service"]["type"] == "node"
        assert params["known"] is True
        assert isinstance(result, list)


class TestV3ClientConsensusService:
    """Tests for V3 client consensus service methods."""

    @pytest.fixture
    def mock_client(self):
        """Create a client with mocked _call."""
        client = AccumulateV3Client("https://test.com")
        client._call = Mock(return_value={"status": "ok"})
        return client

    def test_consensus_status(self, mock_client):
        """Test consensus_status method."""
        options = ConsensusStatusOptions(
            node_id="node123",
            partition="Directory"
        )
        mock_client.consensus_status(options)
        call_args = mock_client._call.call_args
        params = call_args[0][1]
        assert params["nodeID"] == "node123"
        assert params["partition"] == "Directory"

    def test_consensus_status_with_includes(self, mock_client):
        """Test consensus_status with include options."""
        options = ConsensusStatusOptions(
            node_id="node123",
            partition="Directory",
            include_peers=True,
            include_accumulate=True
        )
        mock_client.consensus_status(options)
        call_args = mock_client._call.call_args
        params = call_args[0][1]
        assert params["includePeers"] is True
        assert params["includeAccumulate"] is True


class TestV3ClientNetworkService:
    """Tests for V3 client network service methods."""

    @pytest.fixture
    def mock_client(self):
        """Create a client with mocked _call."""
        client = AccumulateV3Client("https://test.com")
        client._call = Mock(return_value={"partition": "Directory"})
        return client

    def test_network_status(self, mock_client):
        """Test network_status method."""
        options = NetworkStatusOptions(partition="Directory")
        mock_client.network_status(options)
        call_args = mock_client._call.call_args
        params = call_args[0][1]
        assert params["partition"] == "Directory"


class TestV3ClientMetricsService:
    """Tests for V3 client metrics service methods."""

    @pytest.fixture
    def mock_client(self):
        """Create a client with mocked _call."""
        client = AccumulateV3Client("https://test.com")
        client._call = Mock(return_value={"metrics": {}})
        return client

    def test_metrics(self, mock_client):
        """Test metrics method."""
        options = MetricsOptions(partition="Directory", span=3600)
        mock_client.metrics(options)
        call_args = mock_client._call.call_args
        params = call_args[0][1]
        assert params["partition"] == "Directory"
        assert params["span"] == 3600


class TestV3ClientRpcCall:
    """Tests for V3 client RPC call mechanism."""

    @patch('requests.Session')
    def test_call_creates_correct_request(self, mock_session_class):
        """Test _call creates correct JSON-RPC request."""
        mock_session = MagicMock()
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"jsonrpc": "2.0", "result": {"test": "data"}, "id": 1}
        mock_session.post.return_value = mock_response
        mock_session_class.return_value = mock_session

        client = AccumulateV3Client("https://test.com")
        result = client._call("test-method", {"param": "value"})

        # Verify the POST call
        mock_session.post.assert_called_once()
        call_args = mock_session.post.call_args

        # Check URL
        assert call_args[0][0] == "https://test.com/v3"

        # Check request body
        request_body = call_args[1]["json"]
        assert request_body["jsonrpc"] == "2.0"
        assert request_body["method"] == "test-method"
        assert request_body["params"] == {"param": "value"}
        assert "id" in request_body

    @patch('requests.Session')
    def test_call_handles_error_response(self, mock_session_class):
        """Test _call handles error response."""
        mock_session = MagicMock()
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "jsonrpc": "2.0",
            "error": {"code": -32600, "message": "Invalid request"},
            "id": 1
        }
        mock_session.post.return_value = mock_response
        mock_session_class.return_value = mock_session

        client = AccumulateV3Client("https://test.com")
        with pytest.raises(V3ApiError) as exc_info:
            client._call("test-method", {})

        assert "Invalid request" in str(exc_info.value)
        assert exc_info.value.code == -32600

    @patch('requests.Session')
    def test_call_handles_http_error(self, mock_session_class):
        """Test _call handles HTTP error status."""
        mock_session = MagicMock()
        mock_response = MagicMock()
        mock_response.status_code = 500
        mock_response.reason = "Internal Server Error"
        mock_session.post.return_value = mock_response
        mock_session_class.return_value = mock_session

        client = AccumulateV3Client("https://test.com")
        with pytest.raises(V3ApiError) as exc_info:
            client._call("test-method", {})

        assert "500" in str(exc_info.value)

    @patch('requests.Session')
    def test_call_handles_connection_error(self, mock_session_class):
        """Test _call handles connection errors."""
        import requests as req
        mock_session = MagicMock()
        mock_session.post.side_effect = req.exceptions.ConnectionError("Connection refused")
        mock_session_class.return_value = mock_session

        client = AccumulateV3Client("https://test.com")
        with pytest.raises(V3ApiError) as exc_info:
            client._call("test-method", {})

        assert "Connection refused" in str(exc_info.value) or "request failed" in str(exc_info.value).lower()

    @patch('requests.Session')
    def test_call_no_params(self, mock_session_class):
        """Test _call with no parameters."""
        mock_session = MagicMock()
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"jsonrpc": "2.0", "result": {}, "id": 1}
        mock_session.post.return_value = mock_response
        mock_session_class.return_value = mock_session

        client = AccumulateV3Client("https://test.com")
        client._call("test-method")

        call_args = mock_session.post.call_args
        request_body = call_args[1]["json"]
        assert "params" not in request_body


class TestV3MethodNames:
    """Tests to verify V3 uses correct method names."""

    @pytest.fixture
    def client(self):
        """Create a client with mocked _call."""
        client = AccumulateV3Client("https://test.com")
        client._call = Mock(return_value={})
        return client

    def test_submit_method_name(self, client):
        """Test submit uses correct method name."""
        client.submit({})
        assert client._call.call_args[0][0] == "submit"

    def test_validate_method_name(self, client):
        """Test validate uses correct method name."""
        client.validate({})
        assert client._call.call_args[0][0] == "validate"

    def test_faucet_method_name(self, client):
        """Test faucet uses correct method name."""
        client.faucet("url")
        assert client._call.call_args[0][0] == "faucet"

    def test_query_method_name(self, client):
        """Test query uses correct method name."""
        client.query("url")
        assert client._call.call_args[0][0] == "query"

    def test_node_info_method_name(self, client):
        """Test node-info uses correct method name."""
        client.node_info()
        assert client._call.call_args[0][0] == "node-info"

    def test_find_service_method_name(self, client):
        """Test find-service uses correct method name."""
        client._call.return_value = []
        client.find_service()
        assert client._call.call_args[0][0] == "find-service"

    def test_consensus_status_method_name(self, client):
        """Test consensus-status uses correct method name."""
        options = ConsensusStatusOptions(node_id="test", partition="Directory")
        client.consensus_status(options)
        assert client._call.call_args[0][0] == "consensus-status"

    def test_network_status_method_name(self, client):
        """Test network-status uses correct method name."""
        options = NetworkStatusOptions(partition="Directory")
        client.network_status(options)
        assert client._call.call_args[0][0] == "network-status"

    def test_metrics_method_name(self, client):
        """Test metrics uses correct method name."""
        options = MetricsOptions(partition="Directory")
        client.metrics(options)
        assert client._call.call_args[0][0] == "metrics"

    def test_list_snapshots_method_name(self, client):
        """Test list-snapshots uses correct method name."""
        from accumulate_client.v3.options import ListSnapshotsOptions
        client._call.return_value = []
        options = ListSnapshotsOptions(node_id="node123", partition="Directory")
        client.list_snapshots(options)
        assert client._call.call_args[0][0] == "list-snapshots"

    def test_subscribe_method_name(self, client):
        """Test subscribe uses correct method name."""
        client.subscribe()
        assert client._call.call_args[0][0] == "subscribe"


class TestV3ClientSnapshotService:
    """Tests for V3 client snapshot service methods."""

    @pytest.fixture
    def mock_client(self):
        """Create a client with mocked _call."""
        client = AccumulateV3Client("https://test.com")
        client._call = Mock(return_value=[{"name": "snapshot1"}])
        return client

    def test_list_snapshots_basic(self, mock_client):
        """Test list_snapshots with options."""
        from accumulate_client.v3.options import ListSnapshotsOptions
        options = ListSnapshotsOptions(node_id="node123", partition="Directory")
        result = mock_client.list_snapshots(options)
        mock_client._call.assert_called_once()
        call_args = mock_client._call.call_args
        params = call_args[0][1]
        assert params["nodeID"] == "node123"
        assert params["partition"] == "Directory"
        assert isinstance(result, list)

    def test_list_snapshots_returns_list(self, mock_client):
        """Test list_snapshots returns list of results."""
        from accumulate_client.v3.options import ListSnapshotsOptions
        mock_client._call.return_value = {"name": "snapshot1"}  # Single result
        options = ListSnapshotsOptions(node_id="node123", partition="Directory")
        result = mock_client.list_snapshots(options)
        assert isinstance(result, list)
        assert result[0] == {"name": "snapshot1"}


class TestV3ClientSubscribeService:
    """Tests for V3 client subscribe service methods."""

    @pytest.fixture
    def mock_client(self):
        """Create a client with mocked _call."""
        client = AccumulateV3Client("https://test.com")
        client._call = Mock(return_value={"subscriptionId": "sub123"})
        return client

    def test_subscribe_basic(self, mock_client):
        """Test subscribe without options."""
        result = mock_client.subscribe()
        mock_client._call.assert_called_once_with("subscribe", None)
        assert result == {"subscriptionId": "sub123"}

    def test_subscribe_with_partition(self, mock_client):
        """Test subscribe with partition option."""
        from accumulate_client.v3.options import SubscribeOptions
        options = SubscribeOptions(partition="Directory")
        mock_client.subscribe(options)
        call_args = mock_client._call.call_args
        params = call_args[0][1]
        assert params["partition"] == "Directory"

    def test_subscribe_with_account(self, mock_client):
        """Test subscribe with account option."""
        from accumulate_client.v3.options import SubscribeOptions
        options = SubscribeOptions(account="acc://test.acme")
        mock_client.subscribe(options)
        call_args = mock_client._call.call_args
        params = call_args[0][1]
        assert params["account"] == "acc://test.acme"


class TestV3ClientPublicCall:
    """Tests for public call method."""

    @pytest.fixture
    def mock_client(self):
        """Create a client with mocked _call."""
        client = AccumulateV3Client("https://test.com")
        client._call = Mock(return_value={"custom": "result"})
        return client

    def test_call_public_method(self, mock_client):
        """Test public call method for advanced use cases."""
        result = mock_client.call("custom-method", {"custom": "params"})
        mock_client._call.assert_called_once_with("custom-method", {"custom": "params"})
        assert result == {"custom": "result"}

    def test_call_without_params(self, mock_client):
        """Test public call method without params."""
        mock_client.call("status")
        mock_client._call.assert_called_once_with("status", None)
