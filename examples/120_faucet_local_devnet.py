#!/usr/bin/env python3

"""Fund Lite Token Account using discovered faucet; verify balance"""

import os
import sys
import time
import requests

# Add parent directory to path for relative imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from accumulate_client import AccumulateClient


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
        # Test V3 endpoint
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
        print("Please ensure DevNet is running and run: python tool/devnet_discovery.py")
        sys.exit(1)


def load_urls():
    """Load URLs from previous example"""
    keys_dir = "examples/.keys"
    urls_file = f"{keys_dir}/urls.txt"

    if not os.path.exists(urls_file):
        print("ERROR: URLs file not found. Run 100_keygen_lite_urls.py first.")
        sys.exit(1)

    urls = {}
    with open(urls_file, "r") as f:
        for line in f:
            key, value = line.strip().split("=", 1)
            urls[key] = value

    return urls


def main():
    """Main example function"""
    print("=== Fund LTA using Local DevNet Faucet ===")

    # Load and display DevNet configuration
    config = load_env_config()
    print(f"\nDevNet Endpoints:")
    print(f"  V2 API: {config['ACC_RPC_URL_V2']}")
    print(f"  V3 API: {config['ACC_RPC_URL_V3']}")
    if config['ACC_FAUCET_ACCOUNT']:
        print(f"  Faucet: {config['ACC_FAUCET_ACCOUNT']}")
    print()

    # Test connectivity and fail fast
    test_devnet_connectivity(config)

    # Load URLs from previous example
    urls = load_urls()
    lta = urls["LTA"]
    print(f"Target LTA: {lta}")

    # Create clients
    v2_client = AccumulateClient(config['ACC_RPC_URL_V2'])
    v3_client = AccumulateClient(config['ACC_RPC_URL_V3'])

    try:
        # Check initial balance
        print("\nChecking initial balance...")
        try:
            query_result = v3_client.call('query', {"url": lta})
            if "data" in query_result and query_result["data"]:
                initial_balance = query_result["data"].get("balance", "0")
                print(f"Initial balance: {initial_balance} ACME")
            else:
                print("Initial balance: 0 ACME (account does not exist yet)")
                initial_balance = "0"
        except Exception as e:
            print(f"Initial balance: 0 ACME (account does not exist: {e})")
            initial_balance = "0"

        # Request tokens from faucet
        print(f"\nRequesting tokens from faucet for {lta}...")
        faucet_result = v2_client.faucet({
            "url": lta
        })

        print("Faucet request successful!")
        print(f"Transaction hash: {faucet_result.get('transactionHash', 'Unknown')}")

        # Wait a moment for transaction to be processed
        print("Waiting 3 seconds for transaction to be processed...")
        time.sleep(3)

        # Check final balance
        print("\nChecking final balance...")
        query_result = v3_client.call('query', {"url": lta})
        if "data" in query_result and query_result["data"]:
            final_balance = query_result["data"].get("balance", "0")
            print(f"Final balance: {final_balance} ACME")

            # Calculate difference
            initial_val = int(initial_balance) if initial_balance.isdigit() else 0
            final_val = int(final_balance) if final_balance.isdigit() else 0
            diff = final_val - initial_val
            if diff > 0:
                print(f"Successfully received {diff} tokens!")
            else:
                print("Warning: Balance did not increase as expected")
        else:
            print("Error: Could not query final balance")

    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)

    finally:
        v2_client.close()
        v3_client.close()


if __name__ == "__main__":
    main()