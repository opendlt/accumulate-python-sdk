#!/usr/bin/env python3

"""Unit tests for JsonRpcClient with mocked HTTP calls"""

import json
import pytest
import requests
from unittest.mock import Mock, patch

from accumulate_client.json_rpc_client import JsonRpcClient, JsonRpcException


class MockResponse:
    """Mock response for testing"""

    def __init__(self, status_code=200, json_data=None, raise_for_status=None,
                 reason="OK", raise_for_json=False):
        self.status_code = status_code
        self.reason = reason
        self._json_data = json_data or {}
        self._raise_for_status = raise_for_status
        self._raise_for_json = raise_for_json

    def json(self):
        if self._raise_for_json:
            raise json.JSONDecodeError("Invalid JSON", "", 0)
        return self._json_data

    def raise_for_status(self):
        if self._raise_for_status:
            raise self._raise_for_status


class TestJsonRpcClient:
    """Test cases for JsonRpcClient"""

    def test_init_default_timeout(self):
        """Test client initialization with default timeout"""
        client = JsonRpcClient("http://test.example.com")
        assert client._server_url == "http://test.example.com"
        assert client._timeout == 30.0
        assert client._session is not None

    def test_init_custom_timeout(self):
        """Test client initialization with custom timeout"""
        client = JsonRpcClient("http://test.example.com", timeout=60.0)
        assert client._timeout == 60.0

    @patch('accumulate_client.json_rpc_client.requests.Session.post')
    def test_call_success_with_result(self, mock_post):
        """Test successful RPC call that returns result"""
        # Setup
        client = JsonRpcClient("http://test.example.com")
        mock_response = MockResponse(
            status_code=200,
            json_data={"jsonrpc": "2.0", "result": {"status": "success"}, "id": 123}
        )
        mock_post.return_value = mock_response

        # Execute
        result = client.call("test_method", {"param1": "value1"})

        # Verify
        assert result == {"status": "success"}
        mock_post.assert_called_once()

        # Verify request structure
        call_args = mock_post.call_args
        assert call_args[1]['json']['jsonrpc'] == "2.0"
        assert call_args[1]['json']['method'] == "test_method"
        assert call_args[1]['json']['params'] == {"param1": "value1"}
        assert 'id' in call_args[1]['json']
        assert call_args[1]['headers'] == {"Content-Type": "application/json"}
        assert call_args[1]['timeout'] == 30.0

    @patch('accumulate_client.json_rpc_client.requests.Session.post')
    def test_call_success_no_params(self, mock_post):
        """Test successful RPC call without parameters"""
        # Setup
        client = JsonRpcClient("http://test.example.com")
        mock_response = MockResponse(
            status_code=200,
            json_data={"jsonrpc": "2.0", "result": "ok", "id": 123}
        )
        mock_post.return_value = mock_response

        # Execute
        result = client.call("status")

        # Verify
        assert result == "ok"

        # Verify request structure - no params field when None
        call_args = mock_post.call_args
        request_data = call_args[1]['json']
        assert "params" not in request_data or request_data.get("params") is None

    @patch('accumulate_client.json_rpc_client.requests.Session.post')
    def test_call_rpc_error(self, mock_post):
        """Test RPC call that returns error"""
        # Setup
        client = JsonRpcClient("http://test.example.com")
        mock_response = MockResponse(
            status_code=200,
            json_data={
                "jsonrpc": "2.0",
                "error": {
                    "code": -32600,
                    "message": "Invalid Request",
                    "data": {"details": "Missing method"}
                },
                "id": 123
            }
        )
        mock_post.return_value = mock_response

        # Execute & Verify
        with pytest.raises(JsonRpcException) as exc_info:
            client.call("invalid_method")

        assert exc_info.value.code == -32600
        assert "Invalid Request" in str(exc_info.value)
        assert exc_info.value.data == {"details": "Missing method"}

    @patch('accumulate_client.json_rpc_client.requests.Session.post')
    def test_call_rpc_error_minimal(self, mock_post):
        """Test RPC call with minimal error info"""
        # Setup
        client = JsonRpcClient("http://test.example.com")
        mock_response = MockResponse(
            status_code=200,
            json_data={
                "jsonrpc": "2.0",
                "error": {},
                "id": 123
            }
        )
        mock_post.return_value = mock_response

        # Execute & Verify
        with pytest.raises(JsonRpcException) as exc_info:
            client.call("method")

        assert "Unknown error" in str(exc_info.value)
        assert exc_info.value.code is None

    @patch('accumulate_client.json_rpc_client.requests.Session.post')
    def test_call_http_error(self, mock_post):
        """Test RPC call with HTTP error status"""
        # Setup
        client = JsonRpcClient("http://test.example.com")
        mock_response = MockResponse(
            status_code=500,
            reason="Internal Server Error"
        )
        mock_post.return_value = mock_response

        # Execute & Verify
        with pytest.raises(JsonRpcException) as exc_info:
            client.call("test_method")

        assert exc_info.value.code == 500
        assert "HTTP 500" in str(exc_info.value)
        assert "Internal Server Error" in str(exc_info.value)

    @patch('accumulate_client.json_rpc_client.requests.Session.post')
    def test_call_request_exception(self, mock_post):
        """Test RPC call with request exception (timeout, connection error, etc.)"""
        # Setup
        client = JsonRpcClient("http://test.example.com")
        mock_post.side_effect = requests.exceptions.RequestException("Connection failed")

        # Execute & Verify
        with pytest.raises(JsonRpcException) as exc_info:
            client.call("test_method")

        assert "HTTP request failed" in str(exc_info.value)
        assert "Connection failed" in str(exc_info.value)

    @patch('accumulate_client.json_rpc_client.requests.Session.post')
    def test_call_timeout_exception(self, mock_post):
        """Test RPC call with timeout exception"""
        # Setup
        client = JsonRpcClient("http://test.example.com")
        mock_post.side_effect = requests.exceptions.Timeout("Request timeout")

        # Execute & Verify
        with pytest.raises(JsonRpcException) as exc_info:
            client.call("test_method")

        assert "HTTP request failed" in str(exc_info.value)
        assert "Request timeout" in str(exc_info.value)

    @patch('accumulate_client.json_rpc_client.requests.Session.post')
    def test_call_json_decode_error(self, mock_post):
        """Test RPC call with invalid JSON response"""
        # Setup
        client = JsonRpcClient("http://test.example.com")
        mock_response = MockResponse(
            status_code=200,
            raise_for_json=True
        )
        mock_post.return_value = mock_response

        # Execute & Verify
        with pytest.raises(JsonRpcException) as exc_info:
            client.call("test_method")

        assert "Invalid JSON response" in str(exc_info.value)

    @patch('accumulate_client.json_rpc_client.requests.Session.post')
    def test_batch_success(self, mock_post):
        """Test successful batch RPC call"""
        # Setup
        client = JsonRpcClient("http://test.example.com")
        mock_response = MockResponse(
            status_code=200,
            json_data=[
                {"jsonrpc": "2.0", "result": "result1", "id": 0},
                {"jsonrpc": "2.0", "result": {"data": "result2"}, "id": 1}
            ]
        )
        mock_post.return_value = mock_response

        # Execute
        requests_list = [
            {"method": "method1", "params": {"arg": "val1"}},
            {"method": "method2"}
        ]
        results = client.batch(requests_list)

        # Verify
        assert results == ["result1", {"data": "result2"}]

        # Verify batch request structure
        call_args = mock_post.call_args
        batch_request = call_args[1]['json']
        assert len(batch_request) == 2
        assert batch_request[0]['method'] == "method1"
        assert batch_request[0]['params'] == {"arg": "val1"}
        assert batch_request[0]['id'] == 0
        assert batch_request[1]['method'] == "method2"
        assert batch_request[1]['id'] == 1
        assert "params" not in batch_request[1] or batch_request[1].get("params") is None

    @patch('accumulate_client.json_rpc_client.requests.Session.post')
    def test_batch_with_error(self, mock_post):
        """Test batch RPC call with error in one response"""
        # Setup
        client = JsonRpcClient("http://test.example.com")
        mock_response = MockResponse(
            status_code=200,
            json_data=[
                {"jsonrpc": "2.0", "result": "result1", "id": 0},
                {
                    "jsonrpc": "2.0",
                    "error": {"code": -32601, "message": "Method not found"},
                    "id": 1
                }
            ]
        )
        mock_post.return_value = mock_response

        # Execute & Verify
        requests_list = [
            {"method": "method1"},
            {"method": "invalid_method"}
        ]

        with pytest.raises(JsonRpcException) as exc_info:
            client.batch(requests_list)

        assert exc_info.value.code == -32601
        assert "Method not found" in str(exc_info.value)

    @patch('accumulate_client.json_rpc_client.requests.Session.post')
    def test_batch_http_error(self, mock_post):
        """Test batch RPC call with HTTP error"""
        # Setup
        client = JsonRpcClient("http://test.example.com")
        mock_response = MockResponse(
            status_code=404,
            reason="Not Found"
        )
        mock_post.return_value = mock_response

        # Execute & Verify
        requests_list = [{"method": "method1"}]

        with pytest.raises(JsonRpcException) as exc_info:
            client.batch(requests_list)

        assert exc_info.value.code == 404
        assert "HTTP 404" in str(exc_info.value)

    @patch('accumulate_client.json_rpc_client.requests.Session.post')
    def test_batch_request_exception(self, mock_post):
        """Test batch RPC call with request exception"""
        # Setup
        client = JsonRpcClient("http://test.example.com")
        mock_post.side_effect = requests.exceptions.ConnectionError("Connection failed")

        # Execute & Verify
        requests_list = [{"method": "method1"}]

        with pytest.raises(JsonRpcException) as exc_info:
            client.batch(requests_list)

        assert "HTTP request failed" in str(exc_info.value)

    @patch('accumulate_client.json_rpc_client.requests.Session.post')
    def test_batch_json_decode_error(self, mock_post):
        """Test batch RPC call with invalid JSON response"""
        # Setup
        client = JsonRpcClient("http://test.example.com")
        mock_response = MockResponse(
            status_code=200,
            raise_for_json=True  # This will trigger JSONDecodeError
        )
        mock_post.return_value = mock_response

        # Execute & Verify
        requests_list = [{"method": "method1"}]

        with pytest.raises(JsonRpcException) as exc_info:
            client.batch(requests_list)

        assert "Invalid JSON response" in str(exc_info.value)

    def test_context_manager(self):
        """Test client as context manager"""
        with patch.object(JsonRpcClient, 'close') as mock_close:
            with JsonRpcClient("http://test.example.com") as client:
                assert isinstance(client, JsonRpcClient)
            mock_close.assert_called_once()

    def test_close(self):
        """Test close method"""
        client = JsonRpcClient("http://test.example.com")
        with patch.object(client._session, 'close') as mock_close:
            client.close()
            mock_close.assert_called_once()

    def test_json_rpc_exception_str_with_code(self):
        """Test JsonRpcException string representation with code"""
        exc = JsonRpcException("Test error", code=123, data={"info": "test"})
        assert str(exc) == "JsonRpcException(123): Test error"
        assert exc.code == 123
        assert exc.data == {"info": "test"}

    def test_json_rpc_exception_str_without_code(self):
        """Test JsonRpcException string representation without code"""
        exc = JsonRpcException("Test error")
        assert str(exc) == "JsonRpcException: Test error"
        assert exc.code is None
        assert exc.data is None

    @patch('accumulate_client.json_rpc_client.requests.Session.post')
    def test_call_with_various_param_types(self, mock_post):
        """Test RPC call with various parameter types"""
        # Setup
        client = JsonRpcClient("http://test.example.com")
        mock_response = MockResponse(
            status_code=200,
            json_data={"jsonrpc": "2.0", "result": "ok", "id": 123}
        )
        mock_post.return_value = mock_response

        # Test with different param types
        test_cases = [
            {"param": "string"},
            [1, 2, 3],
            "simple_string",
            123,
            True,
            None
        ]

        for params in test_cases:
            result = client.call("test_method", params)
            assert result == "ok"

            # Verify params are passed correctly
            call_args = mock_post.call_args
            if params is not None:
                assert call_args[1]['json']['params'] == params
            else:
                assert 'params' not in call_args[1]['json'] or call_args[1]['json'].get('params') is None