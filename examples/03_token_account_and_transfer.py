#!/usr/bin/env python3
"""
Example 3: Token Account and Transfer

Creates an ADI token account for ACME tokens and transfers ACME from
the lite token account to the new ADI token account.

Usage:
    python 03_token_account_and_transfer.py --key-seed 000102030405060708090a0b0c0d0e0f --adi acc://demo.acme
"""

import argparse
import sys
import hashlib
import time
from pathlib import Path

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent))

from _common import (
    make_client, tassert, parity_assert_tx, keypair_from_seed,
    query_with_retry, submit_with_retry, format_tokens, format_credits,
    print_step, print_result, print_tx_hash, wait_for_devnet
)

from accumulate_client.tx.builders import get_builder_for
from accumulate_client.signers.ed25519 import Ed25519Signer


def main():
    parser = argparse.ArgumentParser(description="Create token account and transfer ACME")
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
        help="Hex seed for deterministic key generation"
    )
    parser.add_argument(
        "--adi",
        required=True,
        help="ADI URL (e.g., acc://demo.acme)"
    )
    parser.add_argument(
        "--token",
        default="acc://acme.acme/tokens/ACME",
        help="Token URL for transfers"
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

    print("=== Accumulate SDK Example 3: Token Account and Transfer ===")
    print(f"Endpoint: {args.endpoint}")
    print(f"ADI: {args.adi}")
    print(f"Token: {args.token}")
    print(f"Key Seed: {args.key_seed[:12]}...")

    # Step 1: Create client and derive keys
    print_step("Creating client and deriving keys")
    client = make_client(args.endpoint, mock=args.mock)

    if args.mock:
        print("   Using mock transport (offline mode)")
    private_key, public_key = keypair_from_seed(args.key_seed)

    # Generate accounts
    pub_key_hash = public_key.to_bytes()[:20]
    lite_identity = f"acc://{pub_key_hash.hex()}"
    lite_token_account = f"{lite_identity}/ACME"

    adi_url = args.adi
    key_book_url = f"{adi_url}/book"
    key_page_url = f"{key_book_url}/1"
    adi_token_account = f"{adi_url}/tokens"

    print_result("Account Structure", {
        "Lite Token Account": lite_token_account,
        "ADI URL": adi_url,
        "ADI Token Account": adi_token_account,
        "Key Page": key_page_url
    })

    # Step 2: Verify prerequisites
    print_step("Verifying prerequisites")

    # Check lite account balance
    lite_data = query_with_retry(client, lite_token_account)
    tassert(lite_data, "Lite account not found - run 01_lite_and_faucet.py first")

    lite_balance = lite_data.get('balance', 0)
    print(f"   Lite Balance: {format_tokens(lite_balance)} ACME")
    tassert(lite_balance > 50_000_000, "Insufficient ACME for transfer (need >0.5 ACME)")

    # Check ADI exists
    adi_data = query_with_retry(client, adi_url)
    tassert(adi_data, "ADI not found - run 02_create_adi_and_buy_credits.py first")

    # Check key page credits
    key_page_data = query_with_retry(client, key_page_url)
    tassert(key_page_data, "Key page not found")

    credits = key_page_data.get('creditBalance', 0)
    print(f"   Key Page Credits: {format_credits(credits)}")
    tassert(credits > 5_000_000, "Insufficient credits for transactions (need >5 credits)")

    # Step 3: Check if ADI token account already exists
    print_step("Checking ADI token account")
    adi_token_data = query_with_retry(client, adi_token_account)

    if adi_token_data:
        adi_balance = adi_token_data.get('balance', 0)
        print(f"   ADI Token Account exists with balance: {format_tokens(adi_balance)} ACME")
    else:
        print("   ADI Token Account does not exist - will create")

        # Step 4: Create ADI token account
        print_step("Creating ADI token account")

        # Build CreateTokenAccount transaction
        create_token_builder = get_builder_for('CreateTokenAccount')
        create_token_builder.with_field('url', adi_token_account)
        create_token_builder.with_field('tokenUrl', args.token)

        # Validate transaction parity
        parity_assert_tx(create_token_builder)

        # Create signature (signed by ADI key)
        canonical_json = create_token_builder.to_canonical_json()
        tx_hash = hashlib.sha256(canonical_json).digest()

        adi_signer = Ed25519Signer(private_key, key_page_url)
        signature = adi_signer.to_accumulate_signature(tx_hash)

        # Submit transaction
        envelope = {
            'transaction': create_token_builder.to_body(),
            'signatures': [signature]
        }

        result = submit_with_retry(client, envelope)
        print_tx_hash(result.get('transactionHash', 'unknown'), "CreateTokenAccount")

        wait_for_devnet(3)

        # Verify creation
        adi_token_data = query_with_retry(client, adi_token_account)
        tassert(adi_token_data, "Failed to create ADI token account")
        print("   [OK] ADI token account created successfully")

    # Step 5: Transfer ACME from lite to ADI
    print_step("Transferring ACME from lite to ADI token account")

    # Transfer amount (leave some in lite account for future use)
    transfer_amount = min(lite_balance - 10_000_000, 100_000_000)  # Transfer max 1 ACME, leave 0.1
    tassert(transfer_amount > 0, "No tokens available to transfer")

    print(f"   Transfer Amount: {format_tokens(transfer_amount)} ACME")

    # Build SendTokens transaction
    send_tokens_builder = get_builder_for('SendTokens')
    send_tokens_builder.with_field('to', [{
        'url': adi_token_account,
        'amount': transfer_amount
    }])

    # Validate transaction parity
    parity_assert_tx(send_tokens_builder)

    # Create signature (signed by lite account)
    canonical_json = send_tokens_builder.to_canonical_json()
    tx_hash = hashlib.sha256(canonical_json).digest()

    lite_signer = Ed25519Signer(private_key, lite_token_account)
    signature = lite_signer.to_accumulate_signature(tx_hash)

    # Submit transaction
    envelope = {
        'transaction': send_tokens_builder.to_body(),
        'signatures': [signature]
    }

    result = submit_with_retry(client, envelope)
    print_tx_hash(result.get('transactionHash', 'unknown'), "SendTokens")

    wait_for_devnet(3)

    # Step 6: Verify final balances
    print_step("Verifying final balances")

    # Check lite account final balance
    final_lite_data = query_with_retry(client, lite_token_account)
    final_lite_balance = final_lite_data.get('balance', 0)

    # Check ADI token account final balance
    final_adi_data = query_with_retry(client, adi_token_account)
    final_adi_balance = final_adi_data.get('balance', 0)

    # Calculate changes
    lite_change = final_lite_balance - lite_balance
    adi_change = final_adi_balance - (adi_token_data.get('balance', 0) if adi_token_data else 0)

    print_result("Final Balances", {
        "Lite Account": f"{format_tokens(final_lite_balance)} ACME ({lite_change:+,} change)",
        "ADI Token Account": f"{format_tokens(final_adi_balance)} ACME ({adi_change:+,} change)",
        "Transfer Amount": format_tokens(transfer_amount) + " ACME",
        "Transaction Success": "[OK]" if adi_change == transfer_amount else "[FAIL]"
    })

    # Verify transfer worked
    tassert(
        adi_change == transfer_amount,
        f"Transfer verification failed: expected {transfer_amount}, got {adi_change}"
    )

    print("\n[SUCCESS] SUCCESS: Token account created and transfer completed!")
    print(f" Lite Account: {format_tokens(final_lite_balance)} ACME")
    print(f"  ADI Token Account: {format_tokens(final_adi_balance)} ACME")
    print(f" Transferred: {format_tokens(transfer_amount)} ACME")
    print("\nNext: Run 04_data_account_and_write.py to create data accounts")


if __name__ == "__main__":
    main()