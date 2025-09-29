#!/usr/bin/env python3

"""Unit tests for AccumulateClient public API with FakeJsonRpcClient injection"""

import pytest
from unittest.mock import Mock, patch, MagicMock
import requests

from accumulate_client.client import AccumulateClient


class FakeJsonRpcClient:
    """Fake JSON-RPC client that records calls and returns configurable responses"""

    def __init__(self):
        self.calls = []
        self.responses = {}
        self.default_response = {"result": "success"}
        self.should_raise_http_error = False
        self.should_raise_json_error = False

    def post(self, url, json=None, headers=None):
        """Mock the requests.Session.post method"""
        # Record the call
        call_record = {
            "url": url,
            "json": json,
            "headers": headers,
            "method": json.get("method") if json else None,
            "params": json.get("params") if json else None
        }
        self.calls.append(call_record)

        # Create mock response
        mock_response = Mock()

        if self.should_raise_http_error:
            mock_response.raise_for_status.side_effect = requests.exceptions.HTTPError("HTTP Error")
            return mock_response

        mock_response.raise_for_status.return_value = None

        if self.should_raise_json_error:
            mock_response.json.side_effect = ValueError("Invalid JSON")
            return mock_response

        # Determine response based on method
        method = json.get("method") if json else "unknown"

        if method in self.responses:
            response_data = self.responses[method]
        else:
            response_data = self.default_response.copy()

        # Add RPC error if configured
        if hasattr(self, '_next_rpc_error') and self._next_rpc_error:
            response_data = {"error": self._next_rpc_error}
            delattr(self, '_next_rpc_error')

        mock_response.json.return_value = response_data
        return mock_response

    def set_response(self, method: str, response: dict):
        """Set a specific response for a method"""
        self.responses[method] = response

    def set_rpc_error(self, error: dict):
        """Set the next call to return an RPC error"""
        self._next_rpc_error = error

    def get_last_call(self):
        """Get the last recorded call"""
        return self.calls[-1] if self.calls else None

    def get_calls_for_method(self, method: str):
        """Get all calls for a specific method"""
        return [call for call in self.calls if call.get("method") == method]


class TestAccumulateClientPublicAPI:
    """Test the public API of AccumulateClient"""

    def test_init(self):
        """Test client initialization"""
        client = AccumulateClient("http://test.example.com")
        assert client.server_url == "http://test.example.com"
        assert client.session is not None

    def test_close(self):
        """Test client close method"""
        client = AccumulateClient("http://test.example.com")
        with patch.object(client.session, 'close') as mock_close:
            client.close()
            mock_close.assert_called_once()

    @patch('accumulate_client.client.requests.Session')
    def test_call_success(self, mock_session_class):
        """Test successful call method"""
        # Setup
        fake_client = FakeJsonRpcClient()
        mock_session = Mock()
        mock_session.post = fake_client.post
        mock_session_class.return_value = mock_session

        client = AccumulateClient("http://test.example.com")
        fake_client.set_response("test-method", {"result": {"data": "test_result"}})

        # Execute
        result = client.call("test-method", {"param1": "value1"})

        # Verify
        assert result == {"data": "test_result"}
        assert len(fake_client.calls) == 1

        call = fake_client.get_last_call()
        assert call["method"] == "test-method"
        assert call["params"] == {"param1": "value1"}
        assert call["url"] == "http://test.example.com"
        assert call["headers"] == {"Content-Type": "application/json"}

    @patch('accumulate_client.client.requests.Session')
    def test_call_with_none_params(self, mock_session_class):
        """Test call method with None params"""
        # Setup
        fake_client = FakeJsonRpcClient()
        mock_session = Mock()
        mock_session.post = fake_client.post
        mock_session_class.return_value = mock_session

        client = AccumulateClient("http://test.example.com")

        # Execute
        result = client.call("test-method")

        # Verify
        call = fake_client.get_last_call()
        assert call["params"] == {}  # None params should become empty dict

    @patch('accumulate_client.client.requests.Session')
    def test_call_rpc_error(self, mock_session_class):
        """Test call method with RPC error"""
        # Setup
        fake_client = FakeJsonRpcClient()
        mock_session = Mock()
        mock_session.post = fake_client.post
        mock_session_class.return_value = mock_session

        client = AccumulateClient("http://test.example.com")
        fake_client.set_rpc_error({"code": -32600, "message": "Invalid Request"})

        # Execute & Verify
        with pytest.raises(Exception) as exc_info:
            client.call("invalid-method")

        assert "JSON-RPC Error" in str(exc_info.value)
        assert "Invalid Request" in str(exc_info.value)

    @patch('accumulate_client.client.requests.Session')
    def test_call_http_error(self, mock_session_class):
        """Test call method with HTTP error"""
        # Setup
        fake_client = FakeJsonRpcClient()
        fake_client.should_raise_http_error = True
        mock_session = Mock()
        mock_session.post = fake_client.post
        mock_session_class.return_value = mock_session

        client = AccumulateClient("http://test.example.com")

        # Execute & Verify
        with pytest.raises(requests.exceptions.HTTPError):
            client.call("test-method")

    @patch('accumulate_client.client.requests.Session')
    def test_describe(self, mock_session_class):
        """Test describe method"""
        # Setup
        fake_client = FakeJsonRpcClient()
        mock_session = Mock()
        mock_session.post = fake_client.post
        mock_session_class.return_value = mock_session

        client = AccumulateClient("http://test.example.com")
        fake_client.set_response("describe", {"result": {"version": "1.0"}})

        # Execute
        result = client.describe()

        # Verify
        assert result == {"version": "1.0"}
        call = fake_client.get_last_call()
        assert call["method"] == "describe"

    @patch('accumulate_client.client.requests.Session')
    def test_status(self, mock_session_class):
        """Test status method"""
        # Setup
        fake_client = FakeJsonRpcClient()
        mock_session = Mock()
        mock_session.post = fake_client.post
        mock_session_class.return_value = mock_session

        client = AccumulateClient("http://test.example.com")
        fake_client.set_response("status", {"result": {"status": "running"}})

        # Execute
        result = client.status()

        # Verify
        assert result == {"status": "running"}
        call = fake_client.get_last_call()
        assert call["method"] == "status"

    @patch('accumulate_client.client.requests.Session')
    def test_version(self, mock_session_class):
        """Test version method"""
        # Setup
        fake_client = FakeJsonRpcClient()
        mock_session = Mock()
        mock_session.post = fake_client.post
        mock_session_class.return_value = mock_session

        client = AccumulateClient("http://test.example.com")
        fake_client.set_response("version", {"result": {"version": "2.0.1"}})

        # Execute
        result = client.version()

        # Verify
        assert result == {"version": "2.0.1"}
        call = fake_client.get_last_call()
        assert call["method"] == "version"

    @patch('accumulate_client.client.requests.Session')
    def test_faucet(self, mock_session_class):
        """Test faucet method"""
        # Setup
        fake_client = FakeJsonRpcClient()
        mock_session = Mock()
        mock_session.post = fake_client.post
        mock_session_class.return_value = mock_session

        client = AccumulateClient("http://test.example.com")
        fake_client.set_response("faucet", {"result": {"transactionHash": "0x123"}})

        # Execute
        result = client.faucet({"url": "acc://test/ACME"})

        # Verify
        assert result == {"transactionHash": "0x123"}
        call = fake_client.get_last_call()
        assert call["method"] == "faucet"
        assert call["params"] == {"url": "acc://test/ACME"}

    @patch('accumulate_client.client.requests.Session')
    def test_execute_methods(self, mock_session_class):
        """Test various execute_* methods"""
        # Setup
        fake_client = FakeJsonRpcClient()
        mock_session = Mock()
        mock_session.post = fake_client.post
        mock_session_class.return_value = mock_session

        client = AccumulateClient("http://test.example.com")

        # Test execute
        result = client.execute({"type": "sendTokens"})
        call = fake_client.get_last_call()
        assert call["method"] == "execute"

        # Test execute_add_credits
        client.execute_add_credits({"recipient": "acc://test"})
        call = fake_client.get_last_call()
        assert call["method"] == "add-credits"

        # Test execute_send_tokens
        client.execute_send_tokens({"to": "acc://dest", "amount": "100"})
        call = fake_client.get_last_call()
        assert call["method"] == "send-tokens"

        # Test execute_create_identity
        client.execute_create_identity({"url": "acc://new-identity"})
        call = fake_client.get_last_call()
        assert call["method"] == "create-identity"

        # Test execute_create_token_account
        client.execute_create_token_account({"url": "acc://token-account"})
        call = fake_client.get_last_call()
        assert call["method"] == "create-token-account"

    @patch('accumulate_client.client.requests.Session')
    def test_query_methods(self, mock_session_class):
        """Test various query_* methods"""
        # Setup
        fake_client = FakeJsonRpcClient()
        mock_session = Mock()
        mock_session.post = fake_client.post
        mock_session_class.return_value = mock_session

        client = AccumulateClient("http://test.example.com")

        # Note: The query method without parameters is tested in test_duplicate_methods
        # Here we test the parameterized query methods

        # Test query_tx
        client.query_tx({"txid": "0x123"})
        call = fake_client.get_last_call()
        assert call["method"] == "query-tx"

        # Test query_tx_history
        client.query_tx_history({"url": "acc://test", "count": 10})
        call = fake_client.get_last_call()
        assert call["method"] == "query-tx-history"

        # Test query_data
        client.query_data({"url": "acc://test#data", "index": 0})
        call = fake_client.get_last_call()
        assert call["method"] == "query-data"

        # Test query_directory
        client.query_directory({"url": "acc://test"})
        call = fake_client.get_last_call()
        assert call["method"] == "query-directory"

    @patch('accumulate_client.client.requests.Session')
    def test_additional_execute_methods(self, mock_session_class):
        """Test additional execute_* methods for coverage"""
        # Setup
        fake_client = FakeJsonRpcClient()
        mock_session = Mock()
        mock_session.post = fake_client.post
        mock_session_class.return_value = mock_session

        client = AccumulateClient("http://test.example.com")

        # Test execute_burn_tokens
        client.execute_burn_tokens({"amount": "100"})
        call = fake_client.get_last_call()
        assert call["method"] == "burn-tokens"

        # Test execute_create_adi
        client.execute_create_adi({"url": "acc://adi"})
        call = fake_client.get_last_call()
        assert call["method"] == "create-adi"

        # Test execute_create_data_account
        client.execute_create_data_account({"url": "acc://data"})
        call = fake_client.get_last_call()
        assert call["method"] == "create-data-account"

        # Test execute_create_key_book
        client.execute_create_key_book({"url": "acc://keybook"})
        call = fake_client.get_last_call()
        assert call["method"] == "create-key-book"

        # Test execute_create_key_page
        client.execute_create_key_page({"url": "acc://keypage"})
        call = fake_client.get_last_call()
        assert call["method"] == "create-key-page"

        # Test execute_create_token
        client.execute_create_token({"url": "acc://token"})
        call = fake_client.get_last_call()
        assert call["method"] == "create-token"

        # Test execute_direct
        client.execute_direct({"envelope": {}})
        call = fake_client.get_last_call()
        assert call["method"] == "execute-direct"

        # Test execute_issue_tokens
        client.execute_issue_tokens({"to": "acc://dest", "amount": "1000"})
        call = fake_client.get_last_call()
        assert call["method"] == "issue-tokens"

        # Test execute_local
        client.execute_local({"transaction": {}})
        call = fake_client.get_last_call()
        assert call["method"] == "execute-local"

        # Test execute_update_account_auth
        client.execute_update_account_auth({"url": "acc://test"})
        call = fake_client.get_last_call()
        assert call["method"] == "update-account-auth"

        # Test execute_update_key
        client.execute_update_key({"oldKey": "old", "newKey": "new"})
        call = fake_client.get_last_call()
        assert call["method"] == "update-key"

        # Test execute_update_key_page
        client.execute_update_key_page({"url": "acc://keypage"})
        call = fake_client.get_last_call()
        assert call["method"] == "update-key-page"

        # Test execute_write_data
        client.execute_write_data({"url": "acc://data", "data": "test"})
        call = fake_client.get_last_call()
        assert call["method"] == "write-data"

        # Test execute_write_data_to
        client.execute_write_data_to({"url": "acc://data", "data": "test"})
        call = fake_client.get_last_call()
        assert call["method"] == "write-data-to"

    @patch('accumulate_client.client.requests.Session')
    def test_additional_query_methods(self, mock_session_class):
        """Test additional query_* methods for coverage"""
        # Setup
        fake_client = FakeJsonRpcClient()
        mock_session = Mock()
        mock_session.post = fake_client.post
        mock_session_class.return_value = mock_session

        client = AccumulateClient("http://test.example.com")

        # Test query_data_set
        client.query_data_set({"url": "acc://data", "start": 0, "count": 10})
        call = fake_client.get_last_call()
        assert call["method"] == "query-data-set"

        # Test query_key_page_index
        client.query_key_page_index({"url": "acc://keybook", "key": "pubkey"})
        call = fake_client.get_last_call()
        assert call["method"] == "query-key-index"

        # Test query_major_blocks
        client.query_major_blocks({"url": "acc://test"})
        call = fake_client.get_last_call()
        assert call["method"] == "query-major-blocks"

        # Test query_minor_blocks
        client.query_minor_blocks({"url": "acc://test"})
        call = fake_client.get_last_call()
        assert call["method"] == "query-minor-blocks"

        # Test query_synth
        client.query_synth({"url": "acc://synth"})
        call = fake_client.get_last_call()
        assert call["method"] == "query-synth"

        # Test query_tx_local
        client.query_tx_local({"txid": "0x123"})
        call = fake_client.get_last_call()
        assert call["method"] == "query-tx-local"

        # Test metrics
        client.metrics({"metric": "tps"})
        call = fake_client.get_last_call()
        assert call["method"] == "metrics"

    @patch('accumulate_client.client.requests.Session')
    def test_v3_api_methods(self, mock_session_class):
        """Test V3 API methods"""
        # Setup
        fake_client = FakeJsonRpcClient()
        mock_session = Mock()
        mock_session.post = fake_client.post
        mock_session_class.return_value = mock_session

        client = AccumulateClient("http://test.example.com")

        # Test query_block
        client.query_block({"height": 100})
        call = fake_client.get_last_call()
        assert call["method"] == "query-block"

        # Test query_chain
        client.query_chain({"url": "acc://test#chain"})
        call = fake_client.get_last_call()
        assert call["method"] == "query-chain"

        # Test submit
        client.submit({"envelope": {}})
        call = fake_client.get_last_call()
        assert call["method"] == "submit"

        # Test submit_multi
        client.submit_multi({"envelopes": [{}]})
        call = fake_client.get_last_call()
        assert call["method"] == "submit-multi"

    @patch('accumulate_client.client.requests.Session')
    def test_duplicate_methods(self, mock_session_class):
        """Test the duplicate method definitions for coverage"""
        # Setup
        fake_client = FakeJsonRpcClient()
        mock_session = Mock()
        mock_session.post = fake_client.post
        mock_session_class.return_value = mock_session

        client = AccumulateClient("http://test.example.com")

        # The last execute definition (line 178) should override the first one
        result = client.execute({"type": "test"})
        call = fake_client.get_last_call()
        assert call["method"] == "execute"

        # Test the parameterless query method (line 202)
        result = client.query()
        call = fake_client.get_last_call()
        assert call["method"] == "query"
        assert call["params"] == {}

    @patch('accumulate_client.client.requests.Session')
    def test_edge_cases(self, mock_session_class):
        """Test edge cases for better coverage"""
        # Setup
        fake_client = FakeJsonRpcClient()
        mock_session = Mock()
        mock_session.post = fake_client.post
        mock_session_class.return_value = mock_session

        client = AccumulateClient("http://test.example.com")

        # Test call with empty params
        client.call("test", {})
        call = fake_client.get_last_call()
        assert call["params"] == {}

        # Test call with complex params
        complex_params = {
            "nested": {"key": "value"},
            "list": [1, 2, 3],
            "bool": True,
            "null": None
        }
        client.call("complex", complex_params)
        call = fake_client.get_last_call()
        assert call["params"] == complex_params

    @patch('accumulate_client.client.requests.Session')
    def test_response_without_result(self, mock_session_class):
        """Test response handling when result is missing"""
        # Setup
        fake_client = FakeJsonRpcClient()
        mock_session = Mock()
        mock_session.post = fake_client.post
        mock_session_class.return_value = mock_session

        client = AccumulateClient("http://test.example.com")
        fake_client.set_response("test", {})  # No result field

        # Execute
        result = client.call("test")

        # Verify - should return None when result field is missing
        assert result is None