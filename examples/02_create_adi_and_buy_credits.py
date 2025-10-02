#!/usr/bin/env python3
"""
Example 2: Create ADI and Buy Credits

Creates an Accumulate Digital Identity (ADI) with KeyBook/KeyPage structure
and purchases credits for the ADI key page to enable transaction execution.

Usage:
    python 02_create_adi_and_buy_credits.py --key-seed 000102030405060708090a0b0c0d0e0f --adi acc://demo.acme
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
    parser = argparse.ArgumentParser(description="Create ADI and buy credits")
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
        help="ADI URL to create (e.g., acc://demo.acme)"
    )
    parser.add_argument(
        "--token",
        default="acc://acme.acme/tokens/ACME",
        help="Token URL for transactions"
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

    print("=== Accumulate SDK Example 2: Create ADI and Buy Credits ===")
    print(f"Endpoint: {args.endpoint}")
    print(f"ADI: {args.adi}")
    print(f"Key Seed: {args.key_seed[:12]}...")

    # Step 1: Create client and derive keys
    print_step("Creating client and deriving keys")
    client = make_client(args.endpoint, mock=args.mock)

    if args.mock:
        print("[WARN] Using mock transport - real devnet preferred for integration testing")
        print("   Using mock transport (offline mode)")
    private_key, public_key = keypair_from_seed(args.key_seed)

    # Generate lite identity (same as script 1)
    pub_key_hash = public_key.to_bytes()[:20]
    lite_identity = f"acc://{pub_key_hash.hex()}"
    lite_token_account = f"{lite_identity}/ACME"

    # ADI structure
    adi_url = args.adi
    key_book_url = f"{adi_url}/book"
    key_page_url = f"{key_book_url}/1"

    print_result("Identity Structure", {
        "Lite Identity": lite_identity,
        "Lite Token Account": lite_token_account,
        "ADI URL": adi_url,
        "Key Book": key_book_url,
        "Key Page": key_page_url
    })

    # Step 2: Check lite account balance
    print_step("Checking lite account balance")
    lite_balance_data = query_with_retry(client, lite_token_account)

    tassert(lite_balance_data, "Lite account not found - run 01_lite_and_faucet.py first")

    lite_balance = lite_balance_data.get('balance', 0)
    print(f"   Lite Balance: {format_tokens(lite_balance)} ACME")

    tassert(lite_balance > 0, "Insufficient ACME balance - run faucet first")

    # Step 3: Check if ADI already exists
    print_step("Checking if ADI already exists")
    existing_adi = query_with_retry(client, adi_url)

    if existing_adi:
        print(f"   ADI already exists: {adi_url}")

        # Check key page credits
        key_page_data = query_with_retry(client, key_page_url)
        if key_page_data:
            credits = key_page_data.get('creditBalance', 0)
            print(f"   Key Page Credits: {format_credits(credits)}")

            if credits > 1000000:  # > 1 credit
                print("[SUCCESS] ADI exists with sufficient credits")
                print("[OK] ADI already created with sufficient credits")
                return

        print("   Need to add credits to key page")
    else:
        print("   ADI does not exist - will create")

    # Step 4: Add credits to lite account first
    print_step("Adding credits to lite account for ADI creation")

    # Build AddCredits transaction for lite account
    add_credits_builder = get_builder_for('AddCredits')
    add_credits_builder.with_field('recipient', lite_identity)
    add_credits_builder.with_field('amount', 100_000_000)  # 100 credits
    add_credits_builder.with_field('oracle', 500.0)  # Price oracle

    # Validate transaction parity
    parity_assert_tx(add_credits_builder)

    # Create signature
    canonical_json = add_credits_builder.to_canonical_json()
    tx_hash = hashlib.sha256(canonical_json).digest()  # Fixed: removed .encode()

    lite_signer = Ed25519Signer(private_key, lite_token_account)
    signature = lite_signer.to_accumulate_signature(tx_hash)

    # Submit transaction
    envelope = {
        'transaction': add_credits_builder.to_body(),
        'signatures': [signature]
    }

    result = submit_with_retry(client, envelope)
    print_tx_hash(result.get('transactionHash', 'unknown'), "AddCredits (Lite)")

    wait_for_devnet(3)

    # Step 5: Create ADI if it doesn't exist
    if not existing_adi:
        print_step("Creating ADI identity")

        # Build CreateIdentity transaction
        create_identity_builder = get_builder_for('CreateIdentity')
        create_identity_builder.with_field('url', adi_url)
        create_identity_builder.with_field('keyBookUrl', key_book_url)
        create_identity_builder.with_field('keyPageUrl', key_page_url)

        # Validate transaction parity
        parity_assert_tx(create_identity_builder)

        # Create signature
        canonical_json = create_identity_builder.to_canonical_json()
        tx_hash = hashlib.sha256(canonical_json).digest()  # Fixed: removed .encode()

        signature = lite_signer.to_accumulate_signature(tx_hash)

        # Submit transaction
        envelope = {
            'transaction': create_identity_builder.to_body(),
            'signatures': [signature]
        }

        result = submit_with_retry(client, envelope)
        print_tx_hash(result.get('transactionHash', 'unknown'), "CreateIdentity")

        wait_for_devnet(3)

    # Step 6: Add credits to ADI key page
    print_step("Adding credits to ADI key page")

    # Build AddCredits transaction for key page
    add_credits_adi_builder = get_builder_for('AddCredits')
    add_credits_adi_builder.with_field('recipient', key_page_url)
    add_credits_adi_builder.with_field('amount', 500_000_000)  # 500 credits
    add_credits_adi_builder.with_field('oracle', 500.0)  # Price oracle

    # Validate transaction parity
    parity_assert_tx(add_credits_adi_builder)

    # Create signature
    canonical_json = add_credits_adi_builder.to_canonical_json()
    tx_hash = hashlib.sha256(canonical_json).digest()  # Fixed: removed .encode()

    signature = lite_signer.to_accumulate_signature(tx_hash)

    # Submit transaction
    envelope = {
        'transaction': add_credits_adi_builder.to_body(),
        'signatures': [signature]
    }

    result = submit_with_retry(client, envelope)
    print_tx_hash(result.get('transactionHash', 'unknown'), "AddCredits (ADI)")

    wait_for_devnet(3)

    # Step 7: Verify final state
    print_step("Verifying final state")

    # Check ADI exists
    final_adi = query_with_retry(client, adi_url)
    tassert(final_adi, "ADI creation failed")

    # Check key page credits
    final_key_page = query_with_retry(client, key_page_url)
    tassert(final_key_page, "Key page creation failed")

    final_credits = final_key_page.get('creditBalance', 0)

    print_result("Final State", {
        "ADI URL": adi_url,
        "Key Page": key_page_url,
        "Credits": format_credits(final_credits),
        "Status": "SUCCESS" if final_credits > 0 else "FAILED"
    })

    tassert(final_credits > 0, "ADI key page should have credits")

    print("\n[SUCCESS] ADI created and credits purchased successfully!")
    print("Next: Run 03_token_account_and_transfer.py to create token accounts")


if __name__ == "__main__":
    main()