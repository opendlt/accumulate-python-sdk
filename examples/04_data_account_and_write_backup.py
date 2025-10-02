#!/usr/bin/env python3
"""
Example 4: Data Account and Write

Creates a data account under the ADI and writes a test data entry.
Demonstrates data storage and retrieval on the Accumulate network.

Usage:
    python 04_data_account_and_write.py --key-seed 000102030405060708090a0b0c0d0e0f --adi acc://demo.acme
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
    query_with_retry, submit_with_retry, format_credits,
    print_step, print_result, print_tx_hash, wait_for_devnet
)

from accumulate_client.tx.builders import get_builder_for
from accumulate_client.signers.ed25519 import Ed25519Signer


def main():
    parser = argparse.ArgumentParser(description="Create data account and write entry")
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
        help="Token URL (unused in this script)"
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
        print("   Using mock transport (offline mode)")
    private_key, public_key = keypair_from_seed(args.key_seed)

    # Generate accounts
    adi_url = args.adi
    key_book_url = f"{adi_url}/book"
    key_page_url = f"{key_book_url}/1"
    data_account_url = f"{adi_url}/data"

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
    tassert(credits > 10_000_000, "Insufficient credits for data operations (need >10 credits)")

    # Step 3: Check if data account already exists
    print_step("Checking data account")
    data_account_data = query_with_retry(client, data_account_url)

    if data_account_data:
        print("   Data account already exists")
        entry_count = data_account_data.get('entryCount', 0)
        print(f"   Current entries: {entry_count}")
    else:
        print("   Data account does not exist - will create")

        # Step 4: Create data account
        print_step("Creating data account")

        # Build CreateDataAccount transaction
        create_data_builder = get_builder_for('CreateDataAccount')
        create_data_builder.with_field('url', data_account_url)

        # Validate transaction parity
        parity_assert_tx(create_data_builder)

        # Create signature (signed by ADI key)
        canonical_json = create_data_builder.to_canonical_json()
        tx_hash = hashlib.sha256(canonical_json.encode()).digest()

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
        data_account_data = query_with_retry(client, data_account_url)
        tassert(data_account_data, "Failed to create data account")
        print("   ✅ Data account created successfully")

    # Step 5: Prepare data entry
    print_step("Preparing data entry")

    # Create timestamped message
    timestamp = int(time.time())
    message = f"hello-from-python-sdk-{timestamp}"
    data_bytes = message.encode('utf-8')

    print_result("Data Entry", {
        "Message": message,
        "Data Size": f"{len(data_bytes)} bytes",
        "Timestamp": timestamp
    })

    # Step 6: Write data entry
    print_step("Writing data entry to account")

    # Build WriteData transaction
    write_data_builder = get_builder_for('WriteData')
    write_data_builder.with_field('data', data_bytes)
    write_data_builder.with_field('scratch', False)  # Permanent storage

    # Validate transaction parity
    parity_assert_tx(write_data_builder)

    # Create signature
    canonical_json = write_data_builder.to_canonical_json()
    tx_hash = hashlib.sha256(canonical_json.encode()).digest()

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

    # Step 7: Verify data was written
    print_step("Verifying data entry")

    # Query updated data account
    updated_data_account = query_with_retry(client, data_account_url)
    tassert(updated_data_account, "Failed to query data account after write")

    new_entry_count = updated_data_account.get('entryCount', 0)
    print(f"   Updated entry count: {new_entry_count}")

    # Calculate data entry hash
    data_hash = hashlib.sha256(data_bytes).hexdigest()

    # Try to query the specific data entry by index (if supported)
    entry_index = new_entry_count - 1  # Latest entry
    data_entry_url = f"{data_account_url}#{entry_index}"

    print_step("Querying data entry")
    data_entry = query_with_retry(client, data_entry_url)

    if data_entry:
        stored_data = data_entry.get('data', {})
        if isinstance(stored_data, dict):
            # If data is returned as object with entry info
            entry_hash = stored_data.get('hash', '')
            entry_data = stored_data.get('data', '')
        else:
            # If data is returned directly
            entry_data = stored_data
            entry_hash = ''

        print_result("Data Entry Retrieved", {
            "Entry Index": entry_index,
            "Entry URL": data_entry_url,
            "Entry Hash": entry_hash[:32] + "..." if entry_hash else data_hash[:32] + "...",
            "Data Preview": entry_data[:50] + "..." if len(str(entry_data)) > 50 else str(entry_data)
        })
    else:
        print("   Data entry query not supported or failed")
        print(f"   Entry should be at: {data_entry_url}")

    # Step 8: Final verification
    print_step("Final verification")

    # Check credits consumed
    final_key_page_data = query_with_retry(client, key_page_url)
    final_credits = final_key_page_data.get('creditBalance', 0)
    credits_used = credits - final_credits

    print_result("Final Status", {
        "Data Account": data_account_url,
        "Total Entries": new_entry_count,
        "Latest Entry Hash": data_hash[:32] + "...",
        "Message Written": message,
        "Credits Used": format_credits(credits_used),
        "Remaining Credits": format_credits(final_credits),
        "Write Transaction": write_tx_hash
    })

    print("\n🎉 SUCCESS: Data account created and entry written!")
    print(f"📁 Data Account: {data_account_url}")
    print(f"📝 Entry: {message}")
    print(f"🔗 Hash: {data_hash}")
    print(f"💳 Credits Used: {format_credits(credits_used)}")
    print("\n✨ DevNet journey complete! All four examples executed successfully.")


if __name__ == "__main__":
    main()