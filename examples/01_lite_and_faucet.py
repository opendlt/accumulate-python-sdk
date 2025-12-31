#!/usr/bin/env python3
"""
Example 1: Create Lite Account and Faucet ACME

Creates a lite identity from deterministic seed and requests ACME tokens
from the devnet faucet. Demonstrates basic account creation and token acquisition.

Usage:
    python 01_lite_and_faucet.py --key-seed 000102030405060708090a0b0c0d0e0f
"""

import argparse
import sys
import time
from pathlib import Path

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent))

from _common import (
    make_client, tassert, keypair_from_seed, query_with_retry,
    format_tokens, print_step, print_result, print_tx_hash, wait_for_devnet
)


def main():
    parser = argparse.ArgumentParser(description="Create lite account and faucet ACME")
    parser.add_argument(
        "--endpoint",
        default="http://127.0.0.1:26660",
        help="Accumulate API endpoint"
    )
    parser.add_argument(
        "--ws-endpoint",
        default="ws://127.0.0.1:26661",
        help="WebSocket endpoint (unused in this script)"
    )
    parser.add_argument(
        "--key-seed",
        required=True,
        help="Hex seed for deterministic key generation (e.g., 000102030405...)"
    )
    parser.add_argument(
        "--token",
        default="acc://acme.acme/tokens/ACME",
        help="Token URL for faucet"
    )
    parser.add_argument(
        "--replay-store",
        help="Optional path for transaction replay store"
    )
    parser.add_argument(
        "--mock",
        action="store_true",
        help="Use mock transport instead of real network calls"
    )

    args = parser.parse_args()

    print("=== Accumulate SDK Example 1: Lite Account and Faucet ===")
    print(f"Endpoint: {args.endpoint}")
    print(f"Key Seed: {args.key_seed[:12]}...")

    # Step 1: Create client
    print_step("Creating client connection")
    client = make_client(args.endpoint, mock=args.mock)

    if args.mock:
        print("   Using mock transport (offline mode)")

    # Step 2: Derive keypair from seed
    print_step("Deriving keypair from seed")
    private_key, public_key = keypair_from_seed(args.key_seed)

    # Generate lite identity URL from public key
    pub_key_hash = public_key.to_bytes()[:20]  # First 20 bytes as address
    lite_identity = f"acc://{pub_key_hash.hex()}"
    lite_token_account = f"{lite_identity}/ACME"

    print_result("Derived Identity", {
        "Lite Identity": lite_identity,
        "Lite Token Account": lite_token_account,
        "Public Key": public_key.to_bytes().hex()
    })

    # Step 3: Check initial balance
    print_step("Checking initial balance")
    initial_balance_data = query_with_retry(client, lite_token_account)

    if initial_balance_data:
        initial_balance = initial_balance_data.get('balance', 0)
        print(f"   Initial Balance: {format_tokens(initial_balance)} ACME")
    else:
        print("   Account does not exist yet (balance: 0)")
        initial_balance = 0

    # Step 4: Request tokens from faucet
    print_step("Requesting tokens from faucet")
    print(f"   Target: {lite_token_account}")

    try:
        faucet_result = client.faucet(lite_token_account)
        faucet_data = faucet_result.get('data', {})

        if 'transactionHash' in faucet_data:
            print_tx_hash(faucet_data['transactionHash'], "Faucet")
        else:
            print("[OK] Faucet request completed")

    except Exception as e:
        print(f"[FAIL] Faucet request failed: {e}")
        print("💡 Make sure the devnet is running and faucet is available")
        sys.exit(1)

    # Step 5: Wait for transaction to process
    wait_for_devnet(3)

    # Step 6: Check final balance
    print_step("Checking final balance after faucet")
    final_balance_data = query_with_retry(client, lite_token_account)

    if final_balance_data:
        final_balance = final_balance_data.get('balance', 0)
        token_url = final_balance_data.get('tokenUrl', args.token)

        print_result("Final Account Status", {
            "Account URL": lite_token_account,
            "Token URL": token_url,
            "Final Balance": format_tokens(final_balance) + " ACME",
            "Balance Change": f"+{format_tokens(final_balance - initial_balance)} ACME"
        })

        # Verify we received tokens
        tassert(final_balance > initial_balance, "No tokens received from faucet")

    else:
        print("[FAIL] Failed to query final balance")
        sys.exit(1)

    # Step 7: Summary
    print("\nSUCCESS: Lite account created and funded!")
    print(f"Account: {lite_token_account}")
    print(f"Balance: {format_tokens(final_balance)} ACME")
    print("\nNext: Run 02_create_adi_and_buy_credits.py to create an ADI")


if __name__ == "__main__":
    main()