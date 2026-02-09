#!/usr/bin/env python3
"""
SDK Example 2: Accumulate Identities (ADI) (V3)

This example demonstrates:
- Creating lite identities and token accounts
- Creating ADIs (Accumulate Digital Identities)
- Adding credits to lite identities and key pages
- Using SmartSigner API for auto-version tracking

Uses Kermit public testnet endpoints.
"""

import time
import hashlib

from accumulate_client import Accumulate, NetworkStatusOptions
from accumulate_client.convenience import SmartSigner, TxBody
from accumulate_client.crypto.ed25519 import Ed25519KeyPair

# Kermit public testnet endpoints
KERMIT_V2 = "https://kermit.accumulatenetwork.io/v2"
KERMIT_V3 = "https://kermit.accumulatenetwork.io/v3"

# For local DevNet testing, uncomment these:
# KERMIT_V2 = "http://127.0.0.1:26660/v2"
# KERMIT_V3 = "http://127.0.0.1:26660/v3"


def main():
    print("=== SDK Example 2: ADI Creation (Python) ===\n")
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
        print(f"Lite Token Account: {lta}")
        print(f"Public Key Hash: {lite_kp.public_key_bytes().hex()[:32]}...\n")

        # Collect all TxIDs for verification
        tx_ids = []

        # =========================================================
        # Step 2: Fund the lite account via faucet
        # =========================================================
        print("--- Step 2: Fund Account via Faucet ---\n")

        fund_account(client, lta, faucet_requests=3)

        # Poll for balance
        print("\nPolling for balance...")
        balance = poll_for_balance(client, lta)
        if balance is None or balance == 0:
            print("ERROR: Account not funded. Stopping.")
            return
        print(f"Balance confirmed: {balance}\n")

        # =========================================================
        # Step 3: Add credits to lite identity using SmartSigner
        # =========================================================
        print("--- Step 3: Add Credits to Lite Identity ---\n")

        # Create SmartSigner for lite identity
        lite_signer = SmartSigner(client.v3, lite_kp, lid)

        # Get oracle price
        network_status = client.v3.network_status(NetworkStatusOptions(partition="directory"))
        oracle = network_status.get("oracle", {}).get("price", 500000)
        print(f"Oracle price: {oracle}")

        # Calculate amount for 500 credits (need more for ADI creation)
        credits = 500
        amount = (credits * 10000000000) // oracle
        print(f"Buying {credits} credits for {amount} ACME sub-units")

        add_credits_result = lite_signer.sign_submit_and_wait(
            principal=lta,
            body=TxBody.add_credits(lid, str(amount), oracle),
            memo="Add credits to lite identity",
            max_attempts=30
        )

        if add_credits_result.success:
            print(f"AddCredits SUCCESS - TxID: {add_credits_result.txid}")
            tx_ids.append(("AddCredits (lite identity)", add_credits_result.txid))
        else:
            print(f"AddCredits FAILED: {add_credits_result.error}")
            print("Continuing anyway to demonstrate API...")

        # Verify credits were added
        time.sleep(3)
        try:
            lid_query = client.v3.query(lid)
            credit_balance = lid_query.get("account", {}).get("creditBalance")
            print(f"Lite identity credit balance: {credit_balance}\n")
        except Exception as e:
            print(f"Could not query credit balance: {e}\n")

        # =========================================================
        # Step 4: Create an ADI
        # =========================================================
        print("--- Step 4: Create ADI ---\n")

        # Generate unique ADI name with timestamp
        timestamp = int(time.time() * 1000)
        adi_name = f"sdk-adi-{timestamp}"
        identity_url = f"acc://{adi_name}.acme"
        book_url = f"{identity_url}/book"

        # Get key hash for ADI key
        adi_pub = adi_kp.public_key_bytes()
        adi_key_hash = hashlib.sha256(adi_pub).digest()
        adi_key_hash_hex = adi_key_hash.hex()

        print(f"ADI URL: {identity_url}")
        print(f"Key Book URL: {book_url}")
        print(f"ADI Key Hash: {adi_key_hash_hex[:32]}...\n")

        create_adi_result = lite_signer.sign_submit_and_wait(
            principal=lta,
            body=TxBody.create_identity(identity_url, book_url, adi_key_hash_hex),
            memo="Create ADI via Python SDK",
            max_attempts=30
        )

        if create_adi_result.success:
            print(f"CreateIdentity SUCCESS - TxID: {create_adi_result.txid}")
            tx_ids.append(("CreateIdentity", create_adi_result.txid))
        else:
            print(f"CreateIdentity FAILED: {create_adi_result.error}")
            return

        # Verify ADI was created
        time.sleep(5)
        try:
            adi_query = client.v3.query(identity_url)
            print(f"ADI created: {adi_query.get('account', {}).get('url')}")
            print(f"ADI type: {adi_query.get('account', {}).get('type')}\n")
        except Exception as e:
            print(f"Could not verify ADI: {e}\n")

        # =========================================================
        # Step 5: Add credits to ADI key page
        # =========================================================
        print("--- Step 5: Add Credits to ADI Key Page ---\n")

        key_page_url = f"{book_url}/1"
        print(f"Key Page URL: {key_page_url}")

        # Calculate amount for 200 credits
        key_page_credits = 200
        key_page_amount = (key_page_credits * 10000000000) // oracle
        print(f"Buying {key_page_credits} credits for {key_page_amount} ACME sub-units")

        add_key_page_credits_result = lite_signer.sign_submit_and_wait(
            principal=lta,
            body=TxBody.add_credits(key_page_url, str(key_page_amount), oracle),
            memo="Add credits to ADI key page",
            max_attempts=30
        )

        if add_key_page_credits_result.success:
            print(f"AddCredits to key page SUCCESS - TxID: {add_key_page_credits_result.txid}")
            tx_ids.append(("AddCredits (key page)", add_key_page_credits_result.txid))
        else:
            print(f"AddCredits to key page FAILED: {add_key_page_credits_result.error}")

        # Verify credits were added to key page
        time.sleep(5)
        try:
            key_page_query = client.v3.query(key_page_url)
            key_page_cred_balance = key_page_query.get("account", {}).get("creditBalance")
            print(f"Key page credit balance: {key_page_cred_balance}\n")
        except Exception as e:
            print(f"Could not query key page: {e}\n")

        # =========================================================
        # Summary
        # =========================================================
        print("=== Summary ===\n")
        print(f"Created lite identity: {lid}")
        print(f"Created ADI: {identity_url}")
        print(f"ADI Key Book: {book_url}")
        print(f"ADI Key Page: {key_page_url}")
        print("\nUsed SmartSigner API for all transactions!")
        print("No manual version tracking needed.")

        # =========================================================
        # TxID Report
        # =========================================================
        print("\n=== TRANSACTION IDs FOR VERIFICATION ===\n")
        for tx_name, txid in tx_ids:
            print(f"  {tx_name}: {txid}")
        print(f"\nTotal transactions: {len(tx_ids)}")
        print("Example 2 COMPLETED SUCCESSFULLY!")

    finally:
        client.close()


def fund_account(client: Accumulate, account_url: str, faucet_requests: int = 3):
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
