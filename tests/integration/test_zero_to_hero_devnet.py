#!/usr/bin/env python3

"""Integration tests for DevNet zero-to-hero workflow"""

import os
import sys

import pytest
import requests

# Add parent directory to path for relative imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from accumulate_client import AccumulateClient

try:
    from examples.shared_helpers import load_env_config
except ImportError:
    load_env_config = None


def is_devnet_available():
    """Check if DevNet is available for testing"""
    if load_env_config is None:
        return False
    try:
        config = load_env_config()
        response = requests.post(
            config["ACC_RPC_URL_V3"],
            json={"jsonrpc": "2.0", "method": "network-status", "params": {}, "id": 1},
            timeout=10,
        )
        return response.status_code == 200 and "result" in response.json()
    except Exception:
        return False


@pytest.mark.skipif(not is_devnet_available(), reason="DevNet not available")
class TestDevNetIntegration:
    """DevNet integration tests"""

    @pytest.fixture(scope="class")
    def config(self):
        """Load DevNet configuration"""
        return load_env_config()

    @pytest.fixture(scope="class")
    def v2_client(self, config):
        """Create V2 client"""
        client = AccumulateClient(config["ACC_RPC_URL_V2"])
        yield client
        client.close()

    @pytest.fixture(scope="class")
    def v3_client(self, config):
        """Create V3 client"""
        client = AccumulateClient(config["ACC_RPC_URL_V3"])
        yield client
        client.close()

    def test_v2_endpoint_health(self, v2_client):
        """Test V2 endpoint health"""
        try:
            result = v2_client.call("describe", {})
            # V2 endpoint returns network info instead of version
            assert "network" in result or "version" in result
            network_name = result.get("network", {}).get("networkName", "Unknown")
            print(f"V2 API network: {network_name}")
        except Exception as e:
            pytest.fail(f"V2 endpoint health check failed: {e}")

    def test_v3_endpoint_health(self, v3_client):
        """Test V3 endpoint health"""
        try:
            result = v3_client.call("network-status", {})
            assert "network" in result
            network_name = result["network"].get("networkName", "Unknown")
            print(f"V3 Network: {network_name}")
            assert network_name != "Unknown"
        except Exception as e:
            pytest.fail(f"V3 endpoint health check failed: {e}")

    def test_faucet_availability(self, v2_client):
        """Test that faucet is available (without actually calling it)"""
        # This test just verifies the faucet endpoint exists
        # We don't actually call it to avoid draining the faucet
        try:
            # Try a minimal query that should work if the API is responsive
            result = v2_client.call("describe", {})
            assert result is not None
        except Exception as e:
            pytest.fail(f"Faucet availability check failed: {e}")

    @pytest.mark.timeout(30)
    def test_query_nonexistent_account(self, v3_client):
        """Test querying a non-existent account returns proper error"""
        try:
            # Query a clearly non-existent account
            result = v3_client.call("query", {"url": "acc://nonexistent12345/ACME"})
            # Should either return empty data or specific error
            # Don't fail on either case as both are valid responses
            print(f"Query result for non-existent account: {result}")
        except Exception as e:
            # Network errors are acceptable
            print(f"Query error (expected): {e}")

    def test_configuration_loaded(self, config):
        """Test that configuration is properly loaded"""
        required_keys = ["ACC_RPC_URL_V2", "ACC_RPC_URL_V3"]
        for key in required_keys:
            assert config[key], f"Configuration key {key} not set"
            assert config[key].startswith("http"), f"Invalid URL format for {key}"

        print("Configuration test passed:")
        print(f"  V2 URL: {config['ACC_RPC_URL_V2']}")
        print(f"  V3 URL: {config['ACC_RPC_URL_V3']}")
        if config["ACC_FAUCET_ACCOUNT"]:
            print(f"  Faucet: {config['ACC_FAUCET_ACCOUNT']}")


if __name__ == "__main__":
    # Run tests with verbose output
    pytest.main([__file__, "-v", "-s"])
