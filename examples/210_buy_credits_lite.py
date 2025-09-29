#!/usr/bin/env python3

"""Purchase credits for a lite identity using tokens from LTA"""

import hashlib
import json
import os
import sys
import time
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization
from accumulate_client import AccumulateClient


def load_keys_and_urls():
    """Load keys and URLs from previous examples"""
    keys_dir = "examples/.keys"

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

    # Load private key
    private_key_file = f"{keys_dir}/ed25519_private.key"
    if not os.path.exists(private_key_file):
        print("ERROR: Private key file not found. Run 100_keygen_lite_urls.py first.")
        sys.exit(1)

    with open(private_key_file, "rb") as f:
        private_key_bytes = f.read()

    private_key = ed25519.Ed25519PrivateKey.from_private_bytes(private_key_bytes)

    return urls, private_key


def create_add_credits_transaction(recipient_url: str, amount: str) -> dict:
    """Create AddCredits transaction body"""
    return {
        "type": "addCredits",
        "recipient": {"url": recipient_url},
        "amount": amount
    }


def create_envelope(principal: str, transaction: dict, private_key: ed25519.Ed25519PrivateKey) -> dict:
    """Create and sign transaction envelope"""
    # Create transaction with timestamp
    timestamp = int(time.time() * 1000000)  # microseconds
    tx_data = {
        "header": {
            "principal": principal,
            "timestamp": timestamp
        },
        "body": transaction
    }

    # Create canonical JSON for signing
    tx_json = json.dumps(tx_data, separators=(',', ':'), sort_keys=True)
    tx_bytes = tx_json.encode('utf-8')

    # Hash for signing
    tx_hash = hashlib.sha256(tx_bytes).digest()

    # Sign the hash
    signature = private_key.sign(tx_hash)

    # Create envelope
    envelope = {
        "transaction": tx_data,
        "signatures": [{
            "type": "ed25519",
            "publicKey": private_key.public_key().public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw
            ).hex(),
            "signature": signature.hex()
        }]
    }

    return envelope


def main():
    """Main example function"""
    print("=== Buy Credits for Lite Identity ===")

    # Load environment variables
    v3_url = os.environ.get('ACC_RPC_URL_V3', 'http://localhost:26660/v3')
    print(f"Using V3 endpoint: {v3_url}")

    # Load keys and URLs
    urls, private_key = load_keys_and_urls()
    lid = urls["LID"]
    lta = urls["LTA"]

    print(f"Lite Identity (LID): {lid}")
    print(f"Lite Token Account (LTA): {lta}")

    # Create client
    client = AccumulateClient(v3_url)

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