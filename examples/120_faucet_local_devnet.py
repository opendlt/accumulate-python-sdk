#!/usr/bin/env python3

"""Fund Lite Token Account using discovered faucet; verify balance"""

import os
import sys
import time
from accumulate_client import AccumulateClient


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

    # Load environment variables (set by devnet_discovery.py)
    v2_url = os.environ.get('ACC_RPC_URL_V2', 'http://localhost:26660/v2')
    v3_url = os.environ.get('ACC_RPC_URL_V3', 'http://localhost:26660/v3')
    faucet_account = os.environ.get('ACC_FAUCET_ACCOUNT', 'acc://a21555da824d14f3f066214657a44e6a1a347dad3052a23a/ACME')

    print(f"Using V2 endpoint: {v2_url}")
    print(f"Using V3 endpoint: {v3_url}")
    print(f"Using faucet account: {faucet_account}")

    # Load URLs from previous example
    urls = load_urls()
    lta = urls["LTA"]
    print(f"Target LTA: {lta}")

    # Create clients
    v2_client = AccumulateClient(v2_url)
    v3_client = AccumulateClient(v3_url)

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