#!/usr/bin/env python3
"""
SDK Example 9: Key Management (V3)

This example demonstrates:
- Creating key pages and key books
- Updating key pages (adding/removing keys)
- Using SmartSigner and KeyManager APIs

Uses Kermit public testnet endpoints.
"""

import time
import hashlib

from accumulate_client import Accumulate, NetworkStatusOptions
from accumulate_client.convenience import SmartSigner, TxBody, KeyManager
from accumulate_client.crypto.ed25519 import Ed25519KeyPair

# Kermit public testnet endpoints
KERMIT_V2 = "https://kermit.accumulatenetwork.io/v2"
KERMIT_V3 = "https://kermit.accumulatenetwork.io/v3"

# For local DevNet testing, uncomment these:
# KERMIT_V2 = "http://127.0.0.1:26660/v2"
# KERMIT_V3 = "http://127.0.0.1:26660/v3"


def main():
    print("=== SDK Example 9: Key Management (Python) ===\n")
    print(f"Endpoint: {KERMIT_V3}\n")
    test_features()


def test_features():
    base_endpoint = KERMIT_V3.replace("/v3", "")
    client = Accumulate(base_endpoint)

    try:
        # =========================================================
        # Step 1: Generate key pairs
        # =========================================================
        print("--- Step 1: Generate Key Pairs ---\n")

        lite_kp = Ed25519KeyPair.generate()
        adi_kp = Ed25519KeyPair.generate()

        # Derive lite identity and token account URLs (with checksum)
        lid = lite_kp.derive_lite_identity_url()
        lta = lite_kp.derive_lite_token_account_url("ACME")

        print(f"Lite Identity: {lid}")
        print(f"Lite Token Account: {lta}\n")

        # Collect all TxIDs for verification
        tx_ids = []

        # =========================================================
        # Step 2: Fund the lite account via faucet
        # =========================================================
        print("--- Step 2: Fund Account via Faucet ---\n")

        fund_account(client, lta, faucet_requests=5)

        print("\nPolling for balance...")
        balance = poll_for_balance(client, lta)
        if balance is None or balance == 0:
            print("ERROR: Account not funded. Stopping.")
            return
        print(f"Balance confirmed: {balance}\n")

        # =========================================================
        # Step 3: Add credits to lite identity
        # =========================================================
        print("--- Step 3: Add Credits to Lite Identity ---\n")

        lite_signer = SmartSigner(client.v3, lite_kp, lid)

        network_status = client.v3.network_status(NetworkStatusOptions(partition="directory"))
        oracle = network_status.get("oracle", {}).get("price", 500000)
        print(f"Oracle price: {oracle}")

        credits = 1000
        amount = (credits * 10000000000) // oracle

        add_credits_result = lite_signer.sign_submit_and_wait(
            principal=lta,
            body=TxBody.add_credits(lid, str(amount), oracle),
            memo="Add credits to lite identity",
            max_attempts=30
        )

        if add_credits_result.success:
            print(f"AddCredits SUCCESS - TxID: {add_credits_result.txid}\n")
            tx_ids.append(("AddCredits (lite identity)", add_credits_result.txid))
        else:
            print(f"AddCredits FAILED: {add_credits_result.error}")
            return

        # =========================================================
        # Step 4: Create an ADI
        # =========================================================
        print("--- Step 4: Create ADI ---\n")

        timestamp = int(time.time() * 1000)
        adi_name = f"sdk-keymgmt-{timestamp}"
        identity_url = f"acc://{adi_name}.acme"
        book_url = f"{identity_url}/book"
        key_page_url = f"{book_url}/1"

        adi_pub = adi_kp.public_key_bytes()
        adi_key_hash = hashlib.sha256(adi_pub).digest()

        print(f"ADI URL: {identity_url}")
        print(f"Key Book URL: {book_url}")
        print(f"Key Page URL: {key_page_url}\n")

        create_adi_result = lite_signer.sign_submit_and_wait(
            principal=lta,
            body=TxBody.create_identity(identity_url, book_url, adi_key_hash.hex()),
            memo="Create ADI via Python SDK",
            max_attempts=30
        )

        if create_adi_result.success:
            print(f"CreateIdentity SUCCESS - TxID: {create_adi_result.txid}\n")
            tx_ids.append(("CreateIdentity", create_adi_result.txid))
        else:
            print(f"CreateIdentity FAILED: {create_adi_result.error}")
            return

        # =========================================================
        # Step 5: Add credits to ADI key page
        # =========================================================
        print("--- Step 5: Add Credits to ADI Key Page ---\n")

        key_page_credits = 500
        key_page_amount = (key_page_credits * 10000000000) // oracle

        add_key_page_credits_result = lite_signer.sign_submit_and_wait(
            principal=lta,
            body=TxBody.add_credits(key_page_url, str(key_page_amount), oracle),
            memo="Add credits to ADI key page",
            max_attempts=30
        )

        if add_key_page_credits_result.success:
            print(f"AddCredits to key page SUCCESS - TxID: {add_key_page_credits_result.txid}\n")
            tx_ids.append(("AddCredits (key page)", add_key_page_credits_result.txid))
        else:
            print(f"AddCredits to key page FAILED: {add_key_page_credits_result.error}")
            return

        time.sleep(5)

        # =========================================================
        # Step 6: Use KeyManager to Query Key Page
        # =========================================================
        print("--- Step 6: Query Key Page Using KeyManager ---\n")

        # Wait longer for key page to be available
        print("Waiting for key page to be queryable...")
        time.sleep(10)

        key_manager = KeyManager(client.v3, key_page_url)

        # Retry querying key page
        key_page_state = None
        for attempt in range(10):
            try:
                key_page_state = key_manager.get_key_page_state()
                break
            except Exception as e:
                print(f"  Attempt {attempt+1}/10: Key page not yet available...")
                time.sleep(3)

        if key_page_state:
            print("Key Page State:")
            print(f"  URL: {key_page_state.url}")
            print(f"  Version: {key_page_state.version}")
            print(f"  Credit Balance: {key_page_state.credits}")
            print(f"  Accept Threshold: {key_page_state.threshold}")
            print(f"  Keys ({key_page_state.key_count}):")
            for key in key_page_state.keys:
                print(f"    - {key[:32]}..." if len(key) > 32 else f"    - {key}")
        else:
            print("Warning: Could not query key page (may still be propagating)")
        print("")

        # =========================================================
        # Step 7: Create New Key Page Under Existing Key Book
        # =========================================================
        print("--- Step 7: Create New Key Page ---\n")

        adi_signer = SmartSigner(client.v3, adi_kp, key_page_url)

        # Generate new keypair for new key page
        new_page2_kp = Ed25519KeyPair.generate()
        new_page2_pub = new_page2_kp.public_key_bytes()
        new_page2_key_hash = hashlib.sha256(new_page2_pub).digest()

        print(f"Creating new key page under {book_url}")

        create_key_page_result = adi_signer.sign_submit_and_wait(
            principal=book_url,
            body=TxBody.create_key_page([{"keyHash": new_page2_key_hash.hex()}]),
            memo="Create new key page",
            max_attempts=30
        )

        if create_key_page_result.success:
            print(f"CreateKeyPage SUCCESS - TxID: {create_key_page_result.txid}")
            print(f"New key page URL: {book_url}/2\n")
            tx_ids.append(("CreateKeyPage", create_key_page_result.txid))
        else:
            print(f"CreateKeyPage FAILED: {create_key_page_result.error}\n")

        time.sleep(5)

        # =========================================================
        # Step 8: Create New Key Book
        # =========================================================
        print("--- Step 8: Create New Key Book ---\n")

        # Generate new keypair for new key book
        new_book_kp = Ed25519KeyPair.generate()
        new_book_pub = new_book_kp.public_key_bytes()
        new_book_key_hash = hashlib.sha256(new_book_pub).digest()
        new_key_book_url = f"{identity_url}/book2"

        print(f"Creating new key book at {new_key_book_url}")

        create_key_book_result = adi_signer.sign_submit_and_wait(
            principal=identity_url,
            body=TxBody.create_key_book(new_key_book_url, new_book_key_hash.hex()),
            memo="Create new key book",
            max_attempts=30
        )

        if create_key_book_result.success:
            print(f"CreateKeyBook SUCCESS - TxID: {create_key_book_result.txid}\n")
            tx_ids.append(("CreateKeyBook", create_key_book_result.txid))
        else:
            print(f"CreateKeyBook FAILED: {create_key_book_result.error}\n")

        time.sleep(5)

        # =========================================================
        # Step 9: Add Key to Existing Key Page Using SmartSigner
        # =========================================================
        print("--- Step 9: Add Key to Key Page ---\n")

        # Generate a new key to add
        new_key_to_add = Ed25519KeyPair.generate()

        print(f"Adding new key to {key_page_url} using SmartSigner.add_key()")

        add_key_result = adi_signer.add_key(new_key_to_add)

        if add_key_result.success:
            print(f"AddKey SUCCESS - TxID: {add_key_result.txid}")
            tx_ids.append(("AddKey", add_key_result.txid))
        else:
            print(f"AddKey FAILED: {add_key_result.error}")

        time.sleep(5)

        # =========================================================
        # Step 10: Query Updated Key Page State
        # =========================================================
        print("\n--- Step 10: Query Updated Key Page ---\n")

        # Retry querying key page
        updated_key_page_state = None
        for attempt in range(10):
            try:
                updated_key_page_state = key_manager.get_key_page_state()
                break
            except Exception as e:
                print(f"  Attempt {attempt+1}/10: Key page not yet available...")
                time.sleep(3)

        if updated_key_page_state:
            print("Updated Key Page State:")
            print(f"  Version: {updated_key_page_state.version}")
            print(f"  Keys ({updated_key_page_state.key_count}):")
            for key in updated_key_page_state.keys:
                display_key = f"{key[:16]}..." if len(key) > 16 else key
                print(f"    - {display_key}")
        else:
            print("Warning: Could not query key page (may still be propagating)")
        print("")

        # =========================================================
        # Summary
        # =========================================================
        print("=== Summary ===\n")
        print(f"Created ADI: {identity_url}")
        print(f"Original Key Book: {book_url}")
        print(f"Original Key Page: {key_page_url}")
        print("\nKey Management Operations:")
        print("  1. Queried key page state with KeyManager")
        print(f"  2. Created new key page: {book_url}/2")
        print(f"  3. Created new key book: {new_key_book_url}")
        print("  4. Added new key to existing key page")
        print("\nUsed SmartSigner and KeyManager APIs!")
        print("  - SmartSigner.add_key() for adding keys")
        print("  - KeyManager.get_key_page_state() for querying")

        # =========================================================
        # TxID Report
        # =========================================================
        print("\n=== TRANSACTION IDs FOR VERIFICATION ===\n")
        for tx_name, txid in tx_ids:
            print(f"  {tx_name}: {txid}")
        print(f"\nTotal transactions: {len(tx_ids)}")
        print("Example 9 COMPLETED SUCCESSFULLY!")

    finally:
        client.close()


def fund_account(client: Accumulate, account_url: str, faucet_requests: int = 5):
    """Fund an account using the faucet."""
    import requests

    print(f"Requesting funds from faucet ({faucet_requests} times)...")
    v2_endpoint = client.v2.endpoint

    for i in range(faucet_requests):
        try:
            response = requests.post(
                v2_endpoint,
                json={
                    "jsonrpc": "2.0",
                    "method": "faucet",
                    "params": {"url": account_url},
                    "id": i + 1
                },
                timeout=30
            )
            result = response.json()
            txid = result.get("result", {}).get("txid", "submitted")
            print(f"  Faucet {i+1}/{faucet_requests}: {str(txid)[:40]}...")
            time.sleep(2)
        except Exception as e:
            print(f"  Faucet {i+1}/{faucet_requests} failed: {e}")


def poll_for_balance(client: Accumulate, account_url: str, max_attempts: int = 30) -> int:
    """Poll for account balance."""
    for i in range(max_attempts):
        try:
            result = client.v3.query(account_url)
            balance = result.get("account", {}).get("balance")
            if balance is not None:
                balance_int = int(balance) if isinstance(balance, (int, str)) else 0
                if balance_int > 0:
                    return balance_int
            print(f"  Waiting for balance... (attempt {i+1}/{max_attempts})")
        except Exception:
            pass
        time.sleep(2)
    return 0


if __name__ == "__main__":
    main()
