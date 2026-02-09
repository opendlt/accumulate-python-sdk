#!/usr/bin/env python3

"""Shared helper functions for examples"""

import os
import sys
import requests

# Add parent directory to path for relative imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def load_env_config():
    """Load DevNet configuration from environment or .env.local"""
    config = {
        'ACC_RPC_URL_V2': os.environ.get('ACC_RPC_URL_V2', 'http://localhost:26660/v2'),
        'ACC_RPC_URL_V3': os.environ.get('ACC_RPC_URL_V3', 'http://localhost:26660/v3'),
        'ACC_FAUCET_ACCOUNT': os.environ.get('ACC_FAUCET_ACCOUNT', ''),
        'ACC_DEVNET_DIR': os.environ.get('ACC_DEVNET_DIR', '')
    }

    # Try to load from .env.local
    env_local_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), '.env.local')
    if os.path.exists(env_local_path):
        with open(env_local_path, 'r') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#') and '=' in line:
                    key, value = line.split('=', 1)
                    if key in config and not os.environ.get(key):
                        config[key] = value

    return config


def test_devnet_connectivity(config):
    """Test DevNet connectivity and fail fast if down"""
    print("Testing DevNet connectivity...")

    try:
        response = requests.post(
            config['ACC_RPC_URL_V3'],
            json={"jsonrpc":"2.0","method":"network-status","params":{},"id":1},
            timeout=5
        )
        if response.status_code == 200:
            result = response.json()
            if 'result' in result:
                network_name = result['result'].get('network', {}).get('networkName', 'Unknown')
                print(f"[OK] DevNet connected: {network_name}")
            else:
                raise Exception("Invalid V3 response")
        else:
            raise Exception(f"V3 endpoint returned {response.status_code}")
    except Exception as e:
        print(f"[ERROR] DevNet connection failed: {e}")
        print("Please ensure DevNet is running and run: python tooling/devnet_discovery.py")
        sys.exit(1)


def print_endpoints(config):
    """Print DevNet endpoints"""
    print(f"\nDevNet Endpoints:")
    print(f"  V2 API: {config['ACC_RPC_URL_V2']}")
    print(f"  V3 API: {config['ACC_RPC_URL_V3']}")
    if config['ACC_FAUCET_ACCOUNT']:
        print(f"  Faucet: {config['ACC_FAUCET_ACCOUNT']}")
    print()


def load_keys_and_urls():
    """Load keys and URLs from previous examples"""
    keys_dir = "examples/.keys"

    # Load private key
    private_key_file = f"{keys_dir}/ed25519_private.key"
    if not os.path.exists(private_key_file):
        print("ERROR: Private key not found. Run 100_keygen_lite_urls.py first.")
        sys.exit(1)

    with open(private_key_file, "rb") as f:
        private_key_bytes = f.read()

    # Load URLs
    urls_file = f"{keys_dir}/urls.txt"
    if not os.path.exists(urls_file):
        print("ERROR: URLs file not found. Run 100_keygen_lite_urls.py first.")
        sys.exit(1)

    urls = {}
    with open(urls_file, "r") as f:
        for line in f:
            key, value = line.strip().split("=", 1)
            urls[key] = value

    return private_key_bytes, urls