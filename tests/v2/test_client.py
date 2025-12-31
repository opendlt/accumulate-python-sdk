"""
Unit tests for V2 API client.

Tests client initialization, endpoint handling, and method signatures.
"""

import pytest
from unittest.mock import Mock, patch, MagicMock
import json

from accumulate_client.v2.client import AccumulateV2Client, V2ApiError


class TestV2ClientInitialization:
    """Tests for V2 client initialization."""

    def test_endpoint_auto_suffix(self):
        """Test endpoint gets /v2 suffix automatically."""
        client = AccumulateV2Client("https://testnet.accumulatenetwork.io")
        assert client.endpoint.endswith("/v2")

    def test_endpoint_preserves_v2(self):
        """Test endpoint preserves existing /v2 suffix."""
        client = AccumulateV2Client("https://testnet.accumulatenetwork.io/v2")
        assert client.endpoint == "https://testnet.accumulatenetwork.io/v2"

    def test_endpoint_replaces_v3(self):
        """Test endpoint replaces /v3 with /v2."""
        client = AccumulateV2Client("https://testnet.accumulatenetwork.io/v3")
        assert client.endpoint.endswith("/v2")
        assert "/v3" not in client.endpoint

    def test_endpoint_strips_trailing_slash(self):
        """Test endpoint strips trailing slash before appending."""
        client = AccumulateV2Client("https://testnet.accumulatenetwork.io/")
        assert not client.endpoint.endswith("//v2")
        assert client.endpoint.endswith("/v2")

    def test_custom_timeout(self):
        """Test custom timeout is set."""
        client = AccumulateV2Client("https://test.com", timeout=60.0)
        assert client._timeout == 60.0

    def test_default_timeout(self):
        """Test default timeout."""
        client = AccumulateV2Client("https://test.com")
        assert client._timeout == 30.0

    def test_context_manager(self):
        """Test client works as context manager."""
        with AccumulateV2Client("https://test.com") as client:
            assert client is not None


class TestV2ApiError:
    """Tests for V2ApiError exception."""

    def test_basic_error(self):
        """Test basic error message."""
        err = V2ApiError("Test error")
        assert "Test error" in str(err)

    def test_error_with_code(self):
        """Test error with code."""
        err = V2ApiError("Test error", code=500)
        assert "500" in str(err)
        assert err.code == 500

    def test_error_with_data(self):
        """Test error with data."""
        err = V2ApiError("Test error", data={"details": "info"})
        assert err.data == {"details": "info"}


class TestV2ClientMethods:
    """Tests for V2 client method signatures and structure."""

    @pytest.fixture
    def mock_client(self):
        """Create a client with mocked HTTP."""
        client = AccumulateV2Client("https://test.com")
        # Mock the _call method to return test data
        client._call = Mock(return_value={"result": "test"})
        return client

    def test_execute_method_exists(self, mock_client):
        """Test execute method exists and calls _call."""
        result = mock_client.execute({"test": "envelope"})
        mock_client._call.assert_called_once_with("execute", {"envelope": {"test": "envelope"}})

    def test_execute_direct_method(self, mock_client):
        """Test execute_direct method."""
        result = mock_client.execute_direct({"test": "envelope"})
        mock_client._call.assert_called_once_with("execute-direct", {"envelope": {"test": "envelope"}})

    def test_execute_local_method(self, mock_client):
        """Test execute_local method."""
        result = mock_client.execute_local({"test": "envelope"})
        mock_client._call.assert_called_once_with("execute-local", {"envelope": {"test": "envelope"}})

    def test_query_method_basic(self, mock_client):
        """Test query method with basic URL."""
        result = mock_client.query("acc://test.acme")
        mock_client._call.assert_called_once()
        call_args = mock_client._call.call_args
        assert call_args[0][0] == "query"
        assert call_args[0][1]["url"] == "acc://test.acme"

    def test_query_method_with_options(self, mock_client):
        """Test query method with options."""
        result = mock_client.query("acc://test.acme", expand=True, height=100, prove=True)
        call_args = mock_client._call.call_args
        assert call_args[0][1]["expand"] is True
        assert call_args[0][1]["height"] == 100
        assert call_args[0][1]["prove"] is True

    def test_query_tx_method(self, mock_client):
        """Test query_tx method."""
        result = mock_client.query_tx("acc://test.acme@abc123")
        mock_client._call.assert_called_once_with("query-tx", {"txid": "acc://test.acme@abc123"})

    def test_query_tx_with_wait(self, mock_client):
        """Test query_tx method with wait option."""
        result = mock_client.query_tx("txid", wait=5000)
        call_args = mock_client._call.call_args
        assert call_args[0][1]["wait"] == 5000

    def test_query_tx_local_method(self, mock_client):
        """Test query_tx_local method."""
        result = mock_client.query_tx_local("txid")
        mock_client._call.assert_called_once_with("query-tx-local", {"txid": "txid"})

    def test_query_directory_method(self, mock_client):
        """Test query_directory method."""
        result = mock_client.query_directory("acc://test.acme", start=0, count=10)
        call_args = mock_client._call.call_args
        assert call_args[0][0] == "query-directory"
        assert call_args[0][1]["url"] == "acc://test.acme"
        assert call_args[0][1]["start"] == 0
        assert call_args[0][1]["count"] == 10

    def test_query_data_method(self, mock_client):
        """Test query_data method."""
        result = mock_client.query_data("acc://test.acme/data")
        mock_client._call.assert_called_once()
        call_args = mock_client._call.call_args
        assert call_args[0][0] == "query-data"

    def test_query_data_set_method(self, mock_client):
        """Test query_data_set method."""
        result = mock_client.query_data_set("acc://test.acme/data", start=0, count=5)
        call_args = mock_client._call.call_args
        assert call_args[0][0] == "query-data-set"
        assert call_args[0][1]["count"] == 5

    def test_query_tx_history_method(self, mock_client):
        """Test query_tx_history method."""
        result = mock_client.query_tx_history("acc://test.acme", start=0, count=20)
        call_args = mock_client._call.call_args
        assert call_args[0][0] == "query-tx-history"
        assert call_args[0][1]["count"] == 20

    def test_query_key_page_index_method(self, mock_client):
        """Test query_key_page_index method."""
        result = mock_client.query_key_page_index("acc://test.acme", "abcd1234")
        call_args = mock_client._call.call_args
        assert call_args[0][0] == "query-key-page-index"
        assert call_args[0][1]["key"] == "abcd1234"

    def test_query_minor_blocks_method(self, mock_client):
        """Test query_minor_blocks method."""
        result = mock_client.query_minor_blocks("acc://test.acme", start=0, count=10)
        call_args = mock_client._call.call_args
        assert call_args[0][0] == "query-minor-blocks"

    def test_query_major_blocks_method(self, mock_client):
        """Test query_major_blocks method."""
        result = mock_client.query_major_blocks("acc://test.acme", start=0, count=5)
        call_args = mock_client._call.call_args
        assert call_args[0][0] == "query-major-blocks"

    def test_query_synth_method(self, mock_client):
        """Test query_synth method."""
        result = mock_client.query_synth("source", "destination")
        call_args = mock_client._call.call_args
        assert call_args[0][0] == "query-synth"
        assert call_args[0][1]["source"] == "source"
        assert call_args[0][1]["destination"] == "destination"

    def test_faucet_method(self, mock_client):
        """Test faucet method."""
        result = mock_client.faucet("acc://test.acme")
        mock_client._call.assert_called_once_with("faucet", {"url": "acc://test.acme"})

    def test_status_method(self, mock_client):
        """Test status method."""
        result = mock_client.status()
        mock_client._call.assert_called_once_with("status", {})

    def test_version_method(self, mock_client):
        """Test version method."""
        result = mock_client.version()
        mock_client._call.assert_called_once_with("version", {})

    def test_describe_method(self, mock_client):
        """Test describe method."""
        result = mock_client.describe()
        mock_client._call.assert_called_once_with("describe", {})

    def test_metrics_method(self, mock_client):
        """Test metrics method."""
        result = mock_client.metrics()
        mock_client._call.assert_called_once_with("metrics", {})


class TestV2ClientRpcCall:
    """Tests for V2 client RPC call mechanism."""

    @patch('requests.Session')
    def test_call_creates_correct_request(self, mock_session_class):
        """Test _call creates correct JSON-RPC request."""
        mock_session = MagicMock()
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"jsonrpc": "2.0", "result": {"test": "data"}, "id": 1}
        mock_session.post.return_value = mock_response
        mock_session_class.return_value = mock_session

        client = AccumulateV2Client("https://test.com")
        result = client._call("test-method", {"param": "value"})

        # Verify the POST call
        mock_session.post.assert_called_once()
        call_args = mock_session.post.call_args

        # Check URL
        assert call_args[0][0] == "https://test.com/v2"

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

        client = AccumulateV2Client("https://test.com")
        with pytest.raises(V2ApiError) as exc_info:
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

        client = AccumulateV2Client("https://test.com")
        with pytest.raises(V2ApiError) as exc_info:
            client._call("test-method", {})

        assert "500" in str(exc_info.value)


class TestV2MethodNames:
    """Tests to verify V2 uses correct method names."""

    @pytest.fixture
    def client(self):
        """Create a client with mocked _call."""
        client = AccumulateV2Client("https://test.com")
        client._call = Mock(return_value={})
        return client

    def test_execute_method_name(self, client):
        """Test execute uses correct method name."""
        client.execute({})
        assert client._call.call_args[0][0] == "execute"

    def test_execute_direct_method_name(self, client):
        """Test execute-direct uses correct method name."""
        client.execute_direct({})
        assert client._call.call_args[0][0] == "execute-direct"

    def test_query_method_name(self, client):
        """Test query uses correct method name."""
        client.query("url")
        assert client._call.call_args[0][0] == "query"

    def test_query_tx_method_name(self, client):
        """Test query-tx uses correct method name."""
        client.query_tx("txid")
        assert client._call.call_args[0][0] == "query-tx"

    def test_query_directory_method_name(self, client):
        """Test query-directory uses correct method name."""
        client.query_directory("url")
        assert client._call.call_args[0][0] == "query-directory"

    def test_faucet_method_name(self, client):
        """Test faucet uses correct method name."""
        client.faucet("url")
        assert client._call.call_args[0][0] == "faucet"
