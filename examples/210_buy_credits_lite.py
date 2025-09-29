#!/usr/bin/env python3

"""Buy credits for a Lite Identity using Lite Token Account"""

import os
import sys
import time
import requests

# Add parent directory to path for relative imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from accumulate_client import AccumulateClient
from tests.helpers.crypto_helpers import (
    create_transaction_hash,
    create_signature_envelope
)


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
                print(f"✓ DevNet connected: {network_name}")
            else:
                raise Exception("Invalid V3 response")
        else:
            raise Exception(f"V3 endpoint returned {response.status_code}")
    except Exception as e:
        print(f"✗ DevNet connection failed: {e}")
        print("Please ensure DevNet is running and run: python tool/devnet_discovery.py")
        sys.exit(1)


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


def main():
    """Main example function"""
    print("=== Buy Credits for Lite Identity ===")

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

    # Load keys and URLs
    private_key_bytes, urls = load_keys_and_urls()
    lid = urls["LID"]
    lta = urls["LTA"]

    print(f"Lite Identity: {lid}")
    print(f"Lite Token Account: {lta}")

    # Create clients
    v2_client = AccumulateClient(config['ACC_RPC_URL_V2'])
    v3_client = AccumulateClient(config['ACC_RPC_URL_V3'])

    try:
        # Check LTA balance first
        print("Checking LTA balance...")
        try:
            lta_balance = client.query({"url": lta})
            print(f"LTA balance query: {lta_balance}")
            if not lta_balance.get("data") or int(lta_balance["data"].get("balance", "0")) == 0:
                print("LTA has no balance. Run 120_faucet_local_devnet.py first to fund the LTA")
                return
        except Exception as e:
            print(f"LTA not found or no balance: {e}")
            print("Run 120_faucet_local_devnet.py first to fund the LTA")
            return

        # Build AddCredits transaction
        print("Building AddCredits transaction...")

        add_credits_tx = create_add_credits_transaction(
            recipient_url=lid,
            amount="1000000"  # Amount in credits to purchase
        )

        # Create and sign envelope
        envelope = create_envelope(lta, add_credits_tx, private_key)

        print("Submitting AddCredits transaction...")
        submit_result = client.execute(envelope)
        print(f"Submit result: {submit_result}")

        # Extract transaction hash if available
        tx_hash = submit_result.get('transactionHash') or submit_result.get('txid')
        if tx_hash:
            print(f"[OK] Transaction submitted with hash: {tx_hash}")

            # Wait for transaction to process
            print("Waiting for transaction to process...")
            time.sleep(5)

            # Query the transaction to verify
            try:
                tx_query = client.query_tx({"txid": tx_hash})
                print(f"Transaction query result: {tx_query}")
            except Exception as e:
                print(f"Transaction query failed: {e}")

            # Check LID credits
            print("Checking LID credits...")
            try:
                lid_query = client.query({"url": lid})
                print(f"LID query result: {lid_query}")
                if lid_query.get("data"):
                    credits = lid_query["data"].get("creditBalance", "0")
                    print(f"LID credits: {credits}")
            except Exception as e:
                print(f"LID query failed: {e}")

            print("[OK] AddCredits transaction completed!")
        else:
            print("[ERROR] No transaction hash returned")

    except Exception as e:
        print(f"[ERROR] AddCredits transaction failed: {e}")
        print("This might be due to:")
        print("  - Insufficient balance in LTA")
        print("  - Incorrect transaction format")
        print("  - DevNet processing issues")

    finally:
        client.close()


if __name__ == "__main__":
    main()