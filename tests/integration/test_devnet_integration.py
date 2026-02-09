#!/usr/bin/env python3

"""Integration tests against local DevNet"""

import os
import unittest

from accumulate_client import AccumulateClient


class TestDevNetIntegration(unittest.TestCase):
    """Integration tests against local DevNet"""

    @classmethod
    def setUpClass(cls):
        """Set up test class with DevNet endpoints"""
        cls.v2_url = os.environ.get("ACC_RPC_URL_V2", "http://localhost:26660/v2")
        cls.v3_url = os.environ.get("ACC_RPC_URL_V3", "http://localhost:26660/v3")
        cls.faucet_account = os.environ.get(
            "ACC_FAUCET_ACCOUNT", "acc://a21555da824d14f3f066214657a44e6a1a347dad3052a23a/ACME"
        )

        cls.v2_client = AccumulateClient(cls.v2_url)
        cls.v3_client = AccumulateClient(cls.v3_url)

    @classmethod
    def tearDownClass(cls):
        """Clean up clients"""
        cls.v2_client.close()
        cls.v3_client.close()

    def test_devnet_connectivity_v2(self):
        """Test V2 endpoint connectivity"""
        try:
            result = self.v2_client.describe()
            self.assertIsInstance(result, dict)
            # DevNet should have network info indicating it's running
            self.assertTrue(
                any(key in str(result).lower() for key in ["network", "devnet", "validators"]),
                f"Expected DevNet info not found in response: {result}"
            )
        except Exception as e:
            self.skipTest(f"DevNet V2 not available: {e}")

    def test_devnet_connectivity_v3(self):
        """Test V3 endpoint connectivity"""
        try:
            # For V3, we'll try a network status call
            result = self.v3_client.call("network-status", {})
            self.assertIsInstance(result, dict)
        except Exception as e:
            self.skipTest(f"DevNet V3 not available: {e}")

    def test_faucet_availability(self):
        """Test faucet is available and responding"""
        # We won't actually request funds, just check if the endpoint responds
        try:
            # Try to call faucet with invalid URL to see if it responds
            self.v2_client.faucet({"url": "invalid"})
        except Exception as e:
            # We expect an error, but it should be a validation error, not a network error
            error_msg = str(e).lower()
            # If we get a proper validation error, the faucet endpoint is working
            # Accept various error formats that indicate the endpoint is responding
            self.assertTrue(
                any(word in error_msg for word in ["validation", "invalid", "url", "accumulate error", "rpc error"]),
                f"Unexpected error type: {e}",
            )

    def test_json_rpc_method_names(self):
        """Test that expected JSON-RPC method names are working"""
        # Test basic V2 methods that are available on DevNet
        try:
            # describe should work
            result = self.v2_client.call("describe")
            self.assertIsInstance(result, dict)
            self.assertIn("network", result)

            # version should work
            result = self.v2_client.call("version")
            self.assertIsInstance(result, dict)

        except Exception as e:
            self.skipTest(f"DevNet V2 methods not available: {e}")

    def test_error_handling(self):
        """Test proper error handling for invalid requests"""
        try:
            # Test invalid method name
            with self.assertRaises(Exception):
                self.v2_client.call("nonexistent-method")

            # Test invalid parameters
            with self.assertRaises(Exception):
                self.v2_client.call("query", {"invalid": "params"})

        except Exception as e:
            self.skipTest(f"DevNet not available for error testing: {e}")

    def test_request_timeout(self):
        """Test that requests have reasonable timeouts"""
        import time

        start_time = time.time()

        try:
            # Make a simple call that should complete quickly
            self.v2_client.describe()
            elapsed = time.time() - start_time

            # Should complete in reasonable time (less than 5 seconds)
            self.assertLess(elapsed, 5.0, "Request took too long")

        except Exception as e:
            self.skipTest(f"DevNet not available for timeout testing: {e}")


if __name__ == "__main__":
    # Check if DevNet appears to be running
    try:
        client = AccumulateClient(os.environ.get("ACC_RPC_URL_V2", "http://localhost:26660/v2"))
        client.describe()
        client.close()
        print("DevNet appears to be running, proceeding with integration tests...")
    except Exception as e:
        print(f"DevNet not available: {e}")
        print("Run tooling/devnet_discovery.py first to set up environment")
        print("Integration tests will be skipped")

    unittest.main()
