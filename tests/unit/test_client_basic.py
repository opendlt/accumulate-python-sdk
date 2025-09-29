#!/usr/bin/env python3

"""Basic unit tests for AccumulateClient"""

import unittest
from unittest.mock import Mock, patch

from accumulate_client import AccumulateClient


class TestAccumulateClientBasic(unittest.TestCase):
    """Basic tests for AccumulateClient functionality"""

    def setUp(self):
        """Set up test client"""
        self.client = AccumulateClient("http://localhost:26660/v2")

    def tearDown(self):
        """Clean up"""
        self.client.close()

    def test_client_initialization(self):
        """Test client initializes correctly"""
        self.assertEqual(self.client.server_url, "http://localhost:26660/v2")
        self.assertIsNotNone(self.client.session)

    @patch("requests.Session.post")
    def test_successful_rpc_call(self, mock_post):
        """Test successful JSON-RPC call"""
        # Mock successful response
        mock_response = Mock()
        mock_response.raise_for_status.return_value = None
        mock_response.json.return_value = {"jsonrpc": "2.0", "result": {"version": "test"}, "id": 1}
        mock_post.return_value = mock_response

        # Make call
        result = self.client.call("describe")

        # Verify request
        mock_post.assert_called_once()
        call_args = mock_post.call_args
        self.assertEqual(call_args[1]["json"]["method"], "describe")
        self.assertEqual(call_args[1]["json"]["jsonrpc"], "2.0")

        # Verify result
        self.assertEqual(result, {"version": "test"})

    @patch("requests.Session.post")
    def test_rpc_error_response(self, mock_post):
        """Test JSON-RPC error response handling"""
        # Mock error response
        mock_response = Mock()
        mock_response.raise_for_status.return_value = None
        mock_response.json.return_value = {
            "jsonrpc": "2.0",
            "error": {"code": -32600, "message": "Invalid request"},
            "id": 1,
        }
        mock_post.return_value = mock_response

        # Verify exception is raised
        with self.assertRaises(Exception) as context:
            self.client.call("invalid")

        self.assertIn("Invalid request", str(context.exception))

    @patch("requests.Session.post")
    def test_describe_method(self, mock_post):
        """Test describe method"""
        # Mock response
        mock_response = Mock()
        mock_response.raise_for_status.return_value = None
        mock_response.json.return_value = {
            "jsonrpc": "2.0",
            "result": {"version": "1.0.0", "network": "DevNet"},
            "id": 1,
        }
        mock_post.return_value = mock_response

        result = self.client.describe()

        # Verify the call was made correctly
        mock_post.assert_called_once()
        call_args = mock_post.call_args
        self.assertEqual(call_args[1]["json"]["method"], "describe")

        # Verify result
        self.assertEqual(result["version"], "1.0.0")
        self.assertEqual(result["network"], "DevNet")

    @patch("requests.Session.post")
    def test_faucet_method(self, mock_post):
        """Test faucet method"""
        # Mock response
        mock_response = Mock()
        mock_response.raise_for_status.return_value = None
        mock_response.json.return_value = {
            "jsonrpc": "2.0",
            "result": {"transactionHash": "abc123", "txid": "abc123"},
            "id": 1,
        }
        mock_post.return_value = mock_response

        result = self.client.faucet({"url": "acc://test"})

        # Verify the call was made correctly
        mock_post.assert_called_once()
        call_args = mock_post.call_args
        self.assertEqual(call_args[1]["json"]["method"], "faucet")
        self.assertEqual(call_args[1]["json"]["params"], {"url": "acc://test"})

        # Verify result
        self.assertEqual(result["transactionHash"], "abc123")

    def test_close_method(self):
        """Test client close method"""
        # Should not raise any exceptions
        self.client.close()

    def test_method_availability(self):
        """Test that expected methods are available"""
        # Check that key methods exist
        self.assertTrue(hasattr(self.client, "describe"))
        self.assertTrue(hasattr(self.client, "faucet"))
        self.assertTrue(hasattr(self.client, "call"))
        self.assertTrue(hasattr(self.client, "close"))

        # Check methods are callable
        self.assertTrue(callable(self.client.describe))
        self.assertTrue(callable(self.client.faucet))
        self.assertTrue(callable(self.client.call))
        self.assertTrue(callable(self.client.close))


if __name__ == "__main__":
    unittest.main()
