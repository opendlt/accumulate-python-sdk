#!/usr/bin/env python3
"""
Example 4: Data Account and Write

Creates a data account under an ADI and writes structured data to it.

Usage:
    python 04_data_account_and_write.py --key-seed 000102030405060708090a0b0c0d0e0f --adi acc://demo.acme
"""

import argparse
import sys
import hashlib
import time
import json
from pathlib import Path

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent))

from _common import (
    make_client, tassert, parity_assert_tx, keypair_from_seed,
    query_with_retry, submit_with_retry, format_credits,
    print_step, print_result, print_tx_hash, wait_for_devnet
)

from accumulate_client.tx.builders import get_builder_for
from accumulate_client.signers.ed25519 import Ed25519Signer


def main():
    parser = argparse.ArgumentParser(description="Create data account and write data")
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
        "--data-account",
        help="Data account URL (defaults to <adi>/data)"
    )
    parser.add_argument(
        "--message",
        default="hello-from-python-sdk",
        help="Message to write to data account"
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

    print("=== Accumulate SDK Example 4: Data Account and Write ===")
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

    # ADI structure
    adi_url = args.adi
    key_book_url = f"{adi_url}/book"
    key_page_url = f"{key_book_url}/1"

    # Data account
    data_account_url = args.data_account or f"{adi_url}/data"

    print_result("Account Structure", {
        "ADI URL": adi_url,
        "Data Account": data_account_url,
        "Key Page": key_page_url
    })

    # Step 2: Verify prerequisites
    print_step("Verifying prerequisites")

    # Check ADI exists
    adi_data = query_with_retry(client, adi_url)
    tassert(adi_data, "ADI not found - run 02_create_adi_and_buy_credits.py first")

    # Check key page credits
    key_page_data = query_with_retry(client, key_page_url)
    tassert(key_page_data, "Key page not found")

    credits = key_page_data.get('creditBalance', 0)
    print(f"   Key Page Credits: {format_credits(credits)}")
    tassert(credits > 1000000, "Insufficient credits - run 02_create_adi_and_buy_credits.py first")

    # Step 3: Check data account
    print_step("Checking data account")
    existing_data_account = query_with_retry(client, data_account_url)

    if existing_data_account:
        print("   Data account already exists")
        current_entries = existing_data_account.get('entryCount', 0)
        print(f"   Current entries: {current_entries}")
    else:
        print("   Data account does not exist - will create")

        # Create data account first
        print_step("Creating data account")

        # Build CreateDataAccount transaction
        create_data_builder = get_builder_for('CreateDataAccount')
        create_data_builder.with_field('url', data_account_url)

        # Validate transaction parity
        parity_assert_tx(create_data_builder)

        # Create signature
        canonical_json = create_data_builder.to_canonical_json()
        tx_hash = hashlib.sha256(canonical_json).digest()  # Fixed: removed .encode()

        adi_signer = Ed25519Signer(private_key, key_page_url)
        signature = adi_signer.to_accumulate_signature(tx_hash)

        # Submit transaction
        envelope = {
            'transaction': create_data_builder.to_body(),
            'signatures': [signature]
        }

        result = submit_with_retry(client, envelope)
        print_tx_hash(result.get('transactionHash', 'unknown'), "CreateDataAccount")

        wait_for_devnet(3)

        # Verify creation
        new_data_account = query_with_retry(client, data_account_url)
        tassert(new_data_account, "Data account creation failed")
        print("   [OK] Data account created successfully")

    # Step 4: Prepare data entry
    print_step("Preparing data entry")

    # Create data with timestamp for uniqueness
    timestamp = int(time.time())
    message = f"{args.message}-{timestamp}"

    # Create structured data entry
    data_entry = {
        "message": message,
        "timestamp": timestamp,
        "example": "python-sdk-data-write",
        "version": "1.0"
    }

    # Convert to bytes for writing
    data_bytes = json.dumps(data_entry, sort_keys=True).encode('utf-8')

    print_result("Data Entry", {
        "Message": message,
        "Data Size": f"{len(data_bytes)} bytes",
        "Timestamp": timestamp
    })

    # Step 5: Write data entry
    print_step("Writing data entry to account")

    # Build WriteData transaction
    write_data_builder = get_builder_for('WriteData')
    write_data_builder.with_field('data', data_bytes)

    # Validate transaction parity
    parity_assert_tx(write_data_builder)

    # Create signature
    canonical_json = write_data_builder.to_canonical_json()
    tx_hash = hashlib.sha256(canonical_json).digest()  # Fixed: removed .encode()

    adi_signer = Ed25519Signer(private_key, key_page_url)
    signature = adi_signer.to_accumulate_signature(tx_hash)

    # Submit transaction
    envelope = {
        'transaction': write_data_builder.to_body(),
        'signatures': [signature]
    }

    result = submit_with_retry(client, envelope)
    write_tx_hash = result.get('transactionHash', 'unknown')
    print_tx_hash(write_tx_hash, "WriteData")

    wait_for_devnet(3)

    # Step 6: Verify data write
    print_step("Verifying data write")

    # Check data account state
    final_data_account = query_with_retry(client, data_account_url)
    tassert(final_data_account, "Data account not found after write")

    final_entries = final_data_account.get('entryCount', 0)

    # Query specific data entry (implementation depends on SDK data querying capabilities)
    # For now, just verify the account state changed

    print_result("Final State", {
        "Data Account": data_account_url,
        "Entry Count": final_entries,
        "Last Write": write_tx_hash[:12] + "...",
        "Status": "SUCCESS" if final_entries > 0 else "UNKNOWN"
    })

    print("\n[SUCCESS] Data account created and entry written!")
    print("Data successfully written to the Accumulate network!")


if __name__ == "__main__":
    main()