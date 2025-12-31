#!/usr/bin/env python3
"""
SDK Example 10: Update Key Page Threshold (V3)

This example demonstrates:
- Updating key page threshold for multi-sig
- Requires multiple keys for multi-sig operations

Uses local DevNet endpoint (configure as needed).
"""

import sys
import os
import time
import hashlib

# Add parent to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from src.accumulate_client import Accumulate, NetworkStatusOptions
from src.accumulate_client.convenience import SmartSigner, TxBody, KeyManager
from src.accumulate_client.crypto.ed25519 import Ed25519KeyPair

# Kermit public testnet endpoints
ENDPOINT_V2 = "https://kermit.accumulatenetwork.io/v2"
ENDPOINT_V3 = "https://kermit.accumulatenetwork.io/v3"

# For local DevNet testing, uncomment these:
# ENDPOINT_V2 = "http://127.0.0.1:26660/v2"
# ENDPOINT_V3 = "http://127.0.0.1:26660/v3"

DELAY_SECONDS = 15


def main():
    print(f"V3 API Endpoint: {ENDPOINT_V3}")
    print("Example 10: Update Key Page Threshold (Multi-Sig)")
    test_features()


def delay_before_print():
    time.sleep(DELAY_SECONDS)


def test_features():
    base_endpoint = ENDPOINT_V3.replace("/v3", "")
    client = Accumulate(base_endpoint)

    try:
        # Generate key pairs
        lite_kp = Ed25519KeyPair.generate()
        adi_kp = Ed25519KeyPair.generate()
        second_key = Ed25519KeyPair.generate()

        # Derive lite identity and token account URLs (with checksum)
        lid = lite_kp.derive_lite_identity_url()
        lta = lite_kp.derive_lite_token_account_url("ACME")

        print_keypair_details(lite_kp)

        # Fund the lite account with faucet
        print(f"Lite account URL: {lta}\n")
        add_funds_to_account(client, lta, times=5)

        # Wait for faucet to process
        print("Waiting for faucet transactions to process...")
        time.sleep(15)

        # Add credits to the lite identity
        add_credits(client, lid, lta, 500, lite_kp)

        # Wait for addCredits to settle
        print("Waiting for addCredits to settle...")
        time.sleep(15)

        # Create an ADI
        adi_name = f"threshold-{int(time.time() * 1000)}"
        create_adi(client, lid, lta, adi_kp, adi_name, lite_kp)

        # Wait for ADI creation to settle
        print("Waiting for ADI creation to settle...")
        time.sleep(15)

        # Add credits to ADI key page
        key_page_url = f"acc://{adi_name}.acme/book/1"
        key_book_url = f"acc://{adi_name}.acme/book"
        print(f"Key Page URL: {key_page_url}")
        print(f"Key Book URL: {key_book_url}")
        add_credits_to_adi_key_page(client, lid, lta, key_page_url, 500, lite_kp)

        # Pause to allow the addCredits transaction to settle
        print("Pausing to allow addCredits transaction to settle...")
        time.sleep(20)

        # ========================================
        # THRESHOLD UPDATE OPERATIONS
        # ========================================

        # First, query the current key page state
        print("\n=== Querying Initial Key Page State ===")
        query_key_page_state(client, key_page_url)

        # Add a second key to the key page so we can set threshold to 2
        print("\n=== Adding Second Key to Key Page ===")
        second_key_bytes = second_key.public_key_bytes()
        second_key_hash = hashlib.sha256(second_key_bytes).digest()
        update_key_page_add_key(client, key_page_url, second_key_hash, adi_kp, key_page_url)

        # Wait for key addition to settle
        print("Waiting for key addition to settle...")
        time.sleep(20)

        # Query key page again to see the new key
        print("\n=== Querying Key Page After Adding Second Key ===")
        query_key_page_state(client, key_page_url)

        # Now update the threshold to 2 (require both keys to sign)
        print("\n=== Updating Key Page Threshold to 2 ===")
        update_key_page_threshold(client, key_page_url, 2, adi_kp, key_page_url)

        # Wait for threshold update to settle
        print("Waiting for threshold update to settle...")
        time.sleep(20)

        # Query key page again to verify threshold change
        print("\n=== Querying Key Page After Threshold Update ===")
        query_key_page_state(client, key_page_url)

        # Demonstrate setting threshold back to 1
        print("\n=== Setting Threshold Back to 1 ===")
        update_key_page_threshold(client, key_page_url, 1, adi_kp, key_page_url)

        # Wait for threshold update to settle
        print("Waiting for threshold update to settle...")
        time.sleep(20)

        # Final query
        print("\n=== Final Key Page State ===")
        query_key_page_state(client, key_page_url)

        print(f"\n=== Example 10 Completed Successfully! ===")
        print(f"Created ADI: acc://{adi_name}.acme")
        print(f"Key Book URL: {key_book_url}")
        print(f"Key Page URL: {key_page_url}")
        print("Added second key to key page")
        print("Demonstrated threshold updates (1 -> 2 -> 1)")

    finally:
        client.close()


def update_key_page_threshold(client, key_page_url: str, new_threshold: int,
                               signer, signer_key_page_url: str):
    """Update key page threshold."""
    print(f"Updating key page threshold: {key_page_url} to {new_threshold}")

    try:
        # Query current key page version for signing
        signer_version = 1
        try:
            key_page_query = client.v3.query(signer_key_page_url)
            if key_page_query.get("account"):
                signer_version = key_page_query["account"].get("version", 1)
                print(f"Current key page version: {signer_version}")
        except Exception as e:
            print(f"Warning: Could not query key page version, using default: {e}")

        # Create smart signer and submit
        smart_signer = SmartSigner(client.v3, signer, signer_key_page_url)

        body = TxBody.update_key_page([
            TxBody.set_threshold_operation(new_threshold)
        ])

        result = smart_signer.sign_submit_and_wait(
            principal=key_page_url,
            body=body,
            memo=f"Update key page threshold to {new_threshold}",
            max_attempts=30
        )

        if result.success:
            print(f"UpdateKeyPage (threshold) Transaction ID: {result.txid}")
        else:
            print(f"UpdateKeyPage (threshold) FAILED: {result.error}")

    except Exception as e:
        print(f"Error updating key page threshold: {e}")


def update_key_page_add_key(client, key_page_url: str, key_hash: bytes,
                             signer, signer_key_page_url: str):
    """Add key to key page."""
    print(f"Adding key to key page: {key_page_url}")

    try:
        # Query current key page version for signing
        signer_version = 1
        try:
            key_page_query = client.v3.query(signer_key_page_url)
            if key_page_query.get("account"):
                signer_version = key_page_query["account"].get("version", 1)
                print(f"Current key page version: {signer_version}")
        except Exception as e:
            print(f"Warning: Could not query key page version, using default: {e}")

        # Create smart signer and submit
        smart_signer = SmartSigner(client.v3, signer, signer_key_page_url)

        body = TxBody.update_key_page([
            TxBody.add_key_operation(key_hash)
        ])

        result = smart_signer.sign_submit_and_wait(
            principal=key_page_url,
            body=body,
            memo="Add new key to key page",
            max_attempts=30
        )

        if result.success:
            print(f"UpdateKeyPage (add key) Transaction ID: {result.txid}")
        else:
            print(f"UpdateKeyPage (add key) FAILED: {result.error}")

    except Exception as e:
        print(f"Error adding key to key page: {e}")


def query_key_page_state(client, key_page_url: str):
    """Query key page state."""
    try:
        print(f"Querying key page: {key_page_url}")

        key_page_query = client.v3.query(key_page_url)

        print("Key page query result:")

        # Display key page information
        if key_page_query.get("account"):
            data = key_page_query["account"]
            print(f"  Type: {data.get('type', 'Unknown')}")
            print(f"  URL: {data.get('url', key_page_url)}")
            print(f"  Version: {data.get('version', 'Unknown')}")
            print(f"  Accept Threshold: {data.get('acceptThreshold', data.get('threshold', 'Not set'))}")
            print(f"  Credits: {data.get('creditBalance', data.get('credits', 'Unknown'))}")

            if data.get("keys"):
                keys = data["keys"]
                print(f"  Keys ({len(keys)}):")
                for i, key in enumerate(keys):
                    if isinstance(key, dict):
                        pub_key_hash = key.get("publicKeyHash", key.get("publicKey", "N/A"))
                        print(f"    Key {i + 1}: {pub_key_hash}")
                    else:
                        print(f"    Key {i + 1}: {key}")
        elif key_page_query.get("data"):
            data = key_page_query["data"]
            print(f"  Type: {data.get('type', 'Unknown')}")
            print(f"  URL: {data.get('url', key_page_url)}")
            print(f"  Threshold: {data.get('threshold', 'Not set')}")
        else:
            print(f"  Raw response: {key_page_query}")

    except Exception as e:
        print(f"Error querying key page state: {e}")


def create_adi(client, from_lid: str, from_lta: str, adi_signer,
               adi_name: str, funding_signer):
    """Create ADI."""
    identity_url = f"acc://{adi_name}.acme"
    book_url = f"{identity_url}/book"

    public_key = adi_signer.public_key_bytes()
    key_hash = hashlib.sha256(public_key).digest()
    key_hash_hex = key_hash.hex()

    print("Preparing to create identity:")
    print(f"ADI URL: {identity_url}")
    print(f"Key Book URL: {book_url}")
    print(f"Key Hash: {key_hash_hex}")

    try:
        smart_signer = SmartSigner(client.v3, funding_signer, from_lid)

        result = smart_signer.sign_submit_and_wait(
            principal=from_lta,
            body=TxBody.create_identity(identity_url, book_url, key_hash_hex),
            memo="Create identity via Python SDK V3",
            max_attempts=30
        )

        if result.success:
            print(f"Create identity response: {result.txid}")
        else:
            print(f"Create identity FAILED: {result.error}")

    except Exception as e:
        print(f"Error creating ADI: {e}")


def add_credits_to_adi_key_page(client, from_lid: str, from_lta: str,
                                 key_page_url: str, credit_amount: int, signer):
    """Add credits to ADI key page."""
    print(f"Adding credits to ADI key page: {key_page_url} with amount: {credit_amount}")

    try:
        network_status = client.v3.network_status(NetworkStatusOptions(partition="directory"))
        oracle = network_status.get("oracle", {}).get("price", 500000)
        print(f"Current oracle price: {oracle}")

        calculated_amount = credit_amount * 2000000

        smart_signer = SmartSigner(client.v3, signer, from_lid)

        result = smart_signer.sign_submit_and_wait(
            principal=from_lta,
            body=TxBody.add_credits(key_page_url, str(calculated_amount), oracle),
            memo="Add credits to key page",
            max_attempts=30
        )

        if result.success:
            print(f"Add credits response: {result.txid}")
        else:
            print(f"Add credits FAILED: {result.error}")

    except Exception as e:
        print(f"Error adding credits: {e}")


def add_funds_to_account(client, account_url: str, times: int = 10):
    """Add funds from faucet."""
    import requests

    for i in range(times):
        try:
            print(f"Adding funds attempt {i + 1}/{times} to {account_url}")

            response = requests.post(
                client.v2.endpoint,
                json={
                    "jsonrpc": "2.0",
                    "method": "faucet",
                    "params": {"url": account_url},
                    "id": i + 1
                },
                timeout=30
            )

            result = response.json()
            print(f"Faucet response: {result}")

            if result.get("result", {}).get("txid"):
                txid = result["result"]["txid"]
                print(f"Faucet transaction ID: {txid}")
                time.sleep(3)
        except Exception as e:
            print(f"Faucet attempt {i + 1} failed: {e}")
            if i < times - 1:
                time.sleep(3)


def print_keypair_details(kp):
    """Print keypair details."""
    public_key = kp.public_key_bytes()
    public_key_hex = public_key.hex()

    print(f"Public Key: {public_key_hex}")
    print("Private Key: [HIDDEN - Use kp.to_bytes() to access]")
    print("")


def add_credits(client, recipient: str, from_account: str, credit_amount: int, signer):
    """Add credits to account."""
    print("Preparing to add credits:")
    print(f"Recipient URL: {recipient}")
    print(f"From Account: {from_account}")
    print(f"Credit Amount: {credit_amount}")

    try:
        print("Getting current oracle price from network...")
        network_status = client.v3.network_status(NetworkStatusOptions(partition="directory"))
        oracle = network_status.get("oracle", {}).get("price", 500000)
        print(f"Current oracle price: {oracle}")

        calculated_amount = credit_amount * 2000000
        print(f"Calculated amount: {calculated_amount}")

        smart_signer = SmartSigner(client.v3, signer, recipient)

        result = smart_signer.sign_submit_and_wait(
            principal=from_account,
            body=TxBody.add_credits(recipient, str(calculated_amount), oracle),
            memo="Add credits",
            max_attempts=30
        )

        if result.success:
            print(f"Add credits response: {result.txid}")
        else:
            print(f"Add credits FAILED: {result.error}")

    except Exception as e:
        print(f"Error adding credits: {e}")


if __name__ == "__main__":
    main()
