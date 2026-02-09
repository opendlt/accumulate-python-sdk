#!/usr/bin/env python3
"""
SDK Example 12: QuickStart Demo (V3)

This example demonstrates:
- Using the QuickStart API for ultra-simple development
- Creating wallets, ADIs, and accounts with minimal code
- Writing data and managing keys

The QuickStart API reduces hundreds of lines of boilerplate to just
a few lines per operation.

Uses Kermit public testnet endpoints by default.
"""

import time

from accumulate_client.convenience import QuickStart


def main():
    print("=== SDK Example 12: QuickStart Demo (Python) ===\n")
    print("The QuickStart API provides the simplest possible interface to Accumulate.\n")

    # Choose network
    use_kermit = True  # Set to False for local devnet

    if use_kermit:
        print("Connecting to Kermit testnet...")
        acc = QuickStart.kermit()
    else:
        print("Connecting to local DevNet...")
        acc = QuickStart.devnet()

    try:
        run_quickstart_demo(acc)
    finally:
        acc.close()


def run_quickstart_demo(acc: QuickStart):
    """Run the QuickStart demonstration."""

    # =========================================================
    # Step 1: Create a Wallet
    # =========================================================
    print("\n--- Step 1: Create a Wallet ---\n")

    wallet = acc.create_wallet()

    print(f"Created wallet:")
    print(f"  Lite Identity: {wallet.lite_identity}")
    print(f"  Lite Token Account: {wallet.lite_token_account}")
    print(f"  Public Key Hash: {wallet.public_key_hash[:32]}...")
    print("")

    # =========================================================
    # Step 2: Fund the Wallet
    # =========================================================
    print("--- Step 2: Fund the Wallet ---\n")

    acc.fund_wallet(wallet, times=5, wait_seconds=15)

    # Check balance
    balance = acc.get_balance(wallet)
    if balance == 0:
        print("WARNING: Wallet not funded - faucet may not be available")
        print("Continuing with demo (some operations may fail)...")
    else:
        print(f"Balance: {balance} units ({balance / 100000000:.2f} ACME)")
    print("")

    # =========================================================
    # Step 3: Create an ADI
    # =========================================================
    print("--- Step 3: Create an ADI ---\n")

    timestamp = int(time.time() * 1000)
    adi_name = f"quickstart-demo-{timestamp}"

    print(f"Creating ADI: {adi_name}")
    adi = acc.setup_adi(wallet, adi_name)

    print(f"\nADI created:")
    print(f"  URL: {adi.url}")
    print(f"  Key Book: {adi.key_book_url}")
    print(f"  Key Page: {adi.key_page_url}")
    print("")

    # Wait for ADI to be confirmed
    time.sleep(5)

    # =========================================================
    # Step 4: Buy Credits for ADI
    # =========================================================
    print("--- Step 4: Buy Credits for ADI ---\n")

    acc.buy_credits_for_adi(wallet, adi, credits=500)
    print("")

    # Wait for credits
    time.sleep(5)

    # =========================================================
    # Step 5: Check Key Page Info
    # =========================================================
    print("--- Step 5: Check Key Page Info ---\n")

    key_page_info = acc.get_key_page_info(adi.key_page_url)
    if key_page_info:
        print(f"Key Page State:")
        print(f"  Version: {key_page_info.version}")
        print(f"  Credits: {key_page_info.credits}")
        print(f"  Threshold: {key_page_info.threshold}")
        print(f"  Keys: {key_page_info.key_count}")
    else:
        print("Could not query key page (may still be pending)")
    print("")

    # =========================================================
    # Step 6: Create Token Account
    # =========================================================
    print("--- Step 6: Create Token Account ---\n")

    acc.create_token_account(adi, "tokens")
    print("")

    time.sleep(5)

    # =========================================================
    # Step 7: Create Data Account
    # =========================================================
    print("--- Step 7: Create Data Account ---\n")

    acc.create_data_account(adi, "mydata")
    print("")

    time.sleep(5)

    # =========================================================
    # Step 8: Write Data
    # =========================================================
    print("--- Step 8: Write Data ---\n")

    acc.write_data(adi, "mydata", [
        "Hello from QuickStart!",
        "Python SDK Example",
        f"Timestamp: {timestamp}"
    ])
    print("")

    time.sleep(5)

    # =========================================================
    # Step 9: Add Another Key
    # =========================================================
    print("--- Step 9: Add Another Key ---\n")

    from accumulate_client.crypto.ed25519 import Ed25519PrivateKey
    new_key = Ed25519PrivateKey.generate()

    acc.add_key_to_adi(adi, new_key)
    print("")

    time.sleep(5)

    # =========================================================
    # Step 10: Set Multi-Sig Threshold
    # =========================================================
    print("--- Step 10: Set Multi-Sig Threshold ---\n")

    acc.set_multisig_threshold(adi, threshold=2)
    print("")

    # =========================================================
    # Summary
    # =========================================================
    print("=== Summary ===\n")
    print("QuickStart API achievements:")
    print(f"  1. Created wallet with lite accounts")
    print(f"  2. Funded wallet via faucet")
    print(f"  3. Created ADI: {adi.url}")
    print(f"  4. Purchased credits for ADI key page")
    print(f"  5. Created token account: {adi.url}/tokens")
    print(f"  6. Created data account: {adi.url}/mydata")
    print(f"  7. Wrote 3 data entries")
    print(f"  8. Added second key to key page")
    print(f"  9. Set multi-sig threshold to 2")
    print("")
    print("Lines of code comparison:")
    print("  - Traditional API: ~500+ lines")
    print("  - QuickStart API: ~50 lines")
    print("")
    print("QuickStart is ideal for:")
    print("  - Rapid prototyping")
    print("  - Testing and development")
    print("  - Learning Accumulate")
    print("  - Simple applications")
    print("")
    print("For production apps with more control, use SmartSigner directly.")


def show_api_comparison():
    """Show the API comparison between traditional and QuickStart."""
    print("""
=== API Comparison ===

--- Traditional API (verbose) ---
```python
from accumulate_client import Accumulate
from accumulate_client.crypto.ed25519 import Ed25519PrivateKey
import hashlib
import time

# Create client
client = Accumulate("https://kermit.accumulatenetwork.io")

# Generate keypair
keypair = Ed25519PrivateKey.generate()
public_key = keypair.public_key().to_bytes()
public_key_hash = hashlib.sha256(public_key).digest()

# Derive lite URLs
lite_identity = f"acc://{public_key_hash[:20].hex()}"
lite_token_account = f"{lite_identity}/ACME"

# Fund via faucet (manual HTTP request)
import requests
for i in range(5):
    response = requests.post(
        "https://kermit.accumulatenetwork.io/v2",
        json={...}
    )
    time.sleep(2)

# Get oracle price
network_status = client.v3.network_status()
oracle = network_status.get("oracle", {}).get("price")

# Calculate credits amount
credits = 1000
amount = (credits * 10000000000) // oracle

# Build transaction
transaction = {
    "header": {...},
    "body": {...}
}

# Sign manually
import json
tx_bytes = json.dumps(transaction, sort_keys=True).encode()
tx_hash = hashlib.sha256(tx_bytes).digest()
signature = keypair.sign(tx_hash)

# Build envelope
envelope = {
    "transaction": transaction,
    "signatures": [{...}]
}

# Submit
result = client.v3.submit(envelope)

# Wait for confirmation
for i in range(30):
    try:
        tx_result = client.v3.query(txid)
        if tx_result.get("status", {}).get("delivered"):
            break
    except:
        pass
    time.sleep(2)

# ... and repeat for every operation
```

--- QuickStart API (simple) ---
```python
from accumulate_client.convenience import QuickStart

# Connect
acc = QuickStart.kermit()

# Create wallet
wallet = acc.create_wallet()

# Fund it
acc.fund_wallet(wallet)

# Create ADI
adi = acc.setup_adi(wallet, "my-adi")

# Done!
```
""")


if __name__ == "__main__":
    main()
