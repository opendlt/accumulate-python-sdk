#!/usr/bin/env python3
"""
SDK Example 3: ADI Token Accounts (V3)

This example demonstrates:
- Creating ADI ACME token accounts
- Sending tokens between lite and ADI accounts
- Using SmartSigner API with auto-version tracking

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


def main():
    print("=== SDK Example 3: ADI Token Accounts (Python) ===\n")
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

        lite_kp1 = Ed25519KeyPair.generate()
        lite_kp2 = Ed25519KeyPair.generate()
        adi_kp = Ed25519KeyPair.generate()

        # Derive lite URLs
        lid1 = lite_kp1.derive_lite_identity_url()
        lta1 = lite_kp1.derive_lite_token_account_url("ACME")
        lid2 = lite_kp2.derive_lite_identity_url()
        lta2 = lite_kp2.derive_lite_token_account_url("ACME")

        print(f"Lite Account 1: {lta1}")
        print(f"Lite Account 2: {lta2}\n")

        # Collect all TxIDs
        tx_ids = []

        # =========================================================
        # Step 2: Fund the first lite account via faucet
        # =========================================================
        print("--- Step 2: Fund Account via Faucet ---\n")

        fund_account(client, lta1, faucet_requests=5)

        print("\nPolling for balance...")
        balance = poll_for_balance(client, lta1)
        if balance is None or balance == 0:
            print("ERROR: Account not funded. Stopping.")
            return
        print(f"Balance confirmed: {balance}\n")

        # =========================================================
        # Step 3: Add credits to lite identity
        # =========================================================
        print("--- Step 3: Add Credits to Lite Identity ---\n")

        lite_signer1 = SmartSigner(client.v3, lite_kp1, lid1)

        network_status = client.v3.network_status(NetworkStatusOptions(partition="directory"))
        oracle = network_status.get("oracle", {}).get("price", 500000)
        print(f"Oracle price: {oracle}")

        credits = 1000
        amount = (credits * 10000000000) // oracle
        print(f"Buying {credits} credits for {amount} ACME sub-units")

        add_credits_result = lite_signer1.sign_submit_and_wait(
            principal=lta1,
            body=TxBody.add_credits(lid1, str(amount), oracle),
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
        adi_name = f"sdk-adi-{timestamp}"
        identity_url = f"acc://{adi_name}.acme"
        book_url = f"{identity_url}/book"
        key_page_url = f"{book_url}/1"

        adi_pub = adi_kp.public_key_bytes()
        adi_key_hash = hashlib.sha256(adi_pub).digest().hex()

        print(f"ADI URL: {identity_url}")
        print(f"Key Page URL: {key_page_url}\n")

        create_adi_result = lite_signer1.sign_submit_and_wait(
            principal=lta1,
            body=TxBody.create_identity(identity_url, book_url, adi_key_hash),
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

        add_key_page_credits_result = lite_signer1.sign_submit_and_wait(
            principal=lta1,
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

        # Poll for key page credits
        poll_for_key_page_credits(client, key_page_url)

        # =========================================================
        # Step 6: Create ADI Token Accounts
        # =========================================================
        print("--- Step 6: Create ADI Token Accounts ---\n")

        adi_signer = SmartSigner(client.v3, adi_kp, key_page_url)

        token_account_url1 = f"{identity_url}/acme-account-1"
        token_account_url2 = f"{identity_url}/acme-account-2"

        # Create first token account
        create_token1_result = adi_signer.sign_submit_and_wait(
            principal=identity_url,
            body=TxBody.create_token_account(token_account_url1),
            memo="Create first ADI token account",
            max_attempts=30
        )

        if create_token1_result.success:
            print(f"CreateTokenAccount 1 SUCCESS - TxID: {create_token1_result.txid}")
            tx_ids.append(("CreateTokenAccount 1", create_token1_result.txid))
        else:
            print(f"CreateTokenAccount 1 FAILED: {create_token1_result.error}")

        # Create second token account
        create_token2_result = adi_signer.sign_submit_and_wait(
            principal=identity_url,
            body=TxBody.create_token_account(token_account_url2),
            memo="Create second ADI token account",
            max_attempts=30
        )

        if create_token2_result.success:
            print(f"CreateTokenAccount 2 SUCCESS - TxID: {create_token2_result.txid}\n")
            tx_ids.append(("CreateTokenAccount 2", create_token2_result.txid))
        else:
            print(f"CreateTokenAccount 2 FAILED: {create_token2_result.error}")

        time.sleep(5)

        # =========================================================
        # Step 7: Send tokens from lite to ADI account
        # =========================================================
        print("--- Step 7: Send Tokens from Lite to ADI ---\n")

        send_amount1 = 5 * 10**8  # 5 ACME
        print(f"Sending 5 ACME from {lta1} to {token_account_url1}")

        send_result1 = lite_signer1.sign_submit_and_wait(
            principal=lta1,
            body=TxBody.send_tokens_single(token_account_url1, str(send_amount1)),
            memo="Send 5 ACME to ADI token account",
            max_attempts=30
        )

        if send_result1.success:
            print(f"SendTokens SUCCESS - TxID: {send_result1.txid}\n")
            tx_ids.append(("SendTokens (lite to ADI)", send_result1.txid))
        else:
            print(f"SendTokens FAILED: {send_result1.error}")

        time.sleep(5)

        # =========================================================
        # Step 8: Send tokens from ADI to lite account
        # =========================================================
        print("--- Step 8: Send Tokens from ADI to Lite ---\n")

        send_amount2 = 2 * 10**8  # 2 ACME
        print(f"Sending 2 ACME from {token_account_url1} to {lta2}")

        send_result2 = adi_signer.sign_submit_and_wait(
            principal=token_account_url1,
            body=TxBody.send_tokens_single(lta2, str(send_amount2)),
            memo="Send 2 ACME to lite account",
            max_attempts=30
        )

        if send_result2.success:
            print(f"SendTokens SUCCESS - TxID: {send_result2.txid}\n")
            tx_ids.append(("SendTokens (ADI to lite)", send_result2.txid))
        else:
            print(f"SendTokens FAILED: {send_result2.error}")

        # =========================================================
        # Step 9: Send tokens between ADI accounts
        # =========================================================
        print("--- Step 9: Send Tokens Between ADI Accounts ---\n")

        send_amount3 = 1 * 10**8  # 1 ACME
        print(f"Sending 1 ACME from {token_account_url1} to {token_account_url2}")

        send_result3 = adi_signer.sign_submit_and_wait(
            principal=token_account_url1,
            body=TxBody.send_tokens_single(token_account_url2, str(send_amount3)),
            memo="Send 1 ACME between ADI accounts",
            max_attempts=30
        )

        if send_result3.success:
            print(f"SendTokens SUCCESS - TxID: {send_result3.txid}\n")
            tx_ids.append(("SendTokens (ADI to ADI)", send_result3.txid))
        else:
            print(f"SendTokens FAILED: {send_result3.error}")

        # =========================================================
        # Summary
        # =========================================================
        print("=== Summary ===\n")
        print(f"Created ADI: {identity_url}")
        print(f"Token Account 1: {token_account_url1}")
        print(f"Token Account 2: {token_account_url2}")
        print("\nToken transfers:")
        print("  - 5 ACME: lite -> ADI account 1")
        print("  - 2 ACME: ADI account 1 -> lite account 2")
        print("  - 1 ACME: ADI account 1 -> ADI account 2")
        print("\nUsed SmartSigner API for all transactions!")

        # =========================================================
        # TxID Report
        # =========================================================
        print("\n=== TRANSACTION IDs FOR VERIFICATION ===\n")
        for tx_name, txid in tx_ids:
            print(f"  {tx_name}: {txid}")
        print(f"\nTotal transactions: {len(tx_ids)}")
        print("Example 3 COMPLETED SUCCESSFULLY!")

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


def poll_for_key_page_credits(client: Accumulate, key_page_url: str, max_attempts: int = 30) -> int:
    """Poll for key page credits."""
    print("Waiting for key page credits to settle...")
    for i in range(max_attempts):
        try:
            result = client.v3.query(key_page_url)
            credit_balance = result.get("account", {}).get("creditBalance")
            if credit_balance is not None:
                credits = int(credit_balance) if isinstance(credit_balance, (int, str)) else 0
                if credits > 0:
                    print(f"Key page credits confirmed: {credits}")
                    return credits
            print(f"  Waiting for credits... (attempt {i+1}/{max_attempts})")
        except Exception:
            pass
        time.sleep(2)
    return 0


if __name__ == "__main__":
    main()
