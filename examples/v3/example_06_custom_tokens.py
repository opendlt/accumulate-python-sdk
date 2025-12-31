#!/usr/bin/env python3
"""
SDK Example 6: Custom Tokens (V3)

This example demonstrates:
- Creating custom token issuers
- Creating token accounts for custom tokens
- Issuing tokens to accounts
- Transferring custom tokens between accounts
- Using SmartSigner API for auto-version tracking

Uses Kermit public testnet endpoints.
"""

import sys
import os
import time
import hashlib

# Add parent to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from src.accumulate_client import Accumulate, NetworkStatusOptions
from src.accumulate_client.convenience import SmartSigner, TxBody
from src.accumulate_client.crypto.ed25519 import Ed25519KeyPair

# Kermit public testnet endpoints
KERMIT_V2 = "https://kermit.accumulatenetwork.io/v2"
KERMIT_V3 = "https://kermit.accumulatenetwork.io/v3"


def main():
    print("=== SDK Example 6: Custom Tokens (Python) ===\n")
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

        # Derive lite URLs
        lid = lite_kp.derive_lite_identity_url()
        lta = lite_kp.derive_lite_token_account_url("ACME")

        print(f"Lite Identity: {lid}")
        print(f"Lite Token Account: {lta}\n")

        # Collect all TxIDs
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
        print(f"Buying {credits} credits for {amount} ACME sub-units")

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
        adi_name = f"sdk-tokens-{timestamp}"
        identity_url = f"acc://{adi_name}.acme"
        book_url = f"{identity_url}/book"
        key_page_url = f"{book_url}/1"

        adi_pub = adi_kp.public_key_bytes()
        adi_key_hash = hashlib.sha256(adi_pub).digest().hex()

        print(f"ADI URL: {identity_url}")
        print(f"Key Page URL: {key_page_url}\n")

        create_adi_result = lite_signer.sign_submit_and_wait(
            principal=lta,
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

        poll_for_key_page_credits(client, key_page_url)

        # =========================================================
        # Step 6: Create Custom Token Issuer
        # =========================================================
        print("--- Step 6: Create Custom Token ---\n")

        adi_signer = SmartSigner(client.v3, adi_kp, key_page_url)

        custom_token_url = f"{identity_url}/mytoken"
        symbol = "MYTKN"
        precision = 4

        print("Creating custom token:")
        print(f"  URL: {custom_token_url}")
        print(f"  Symbol: {symbol}")
        print(f"  Precision: {precision}\n")

        create_token_result = adi_signer.sign_submit_and_wait(
            principal=identity_url,
            body=TxBody.create_token(custom_token_url, symbol, precision),
            memo=f"Create custom token: {symbol}",
            max_attempts=30
        )

        if create_token_result.success:
            print(f"CreateToken SUCCESS - TxID: {create_token_result.txid}\n")
            tx_ids.append(("CreateToken", create_token_result.txid))
        else:
            print(f"CreateToken FAILED: {create_token_result.error}")

        time.sleep(5)

        # =========================================================
        # Step 7: Create Token Accounts for Custom Token
        # =========================================================
        print("--- Step 7: Create Custom Token Accounts ---\n")

        token_account1_url = f"{identity_url}/tokenAccount1"
        token_account2_url = f"{identity_url}/tokenAccount2"

        # Create first token account (using custom token URL)
        create_account1_result = adi_signer.sign_submit_and_wait(
            principal=identity_url,
            body=TxBody.create_token_account(token_account1_url, custom_token_url),
            memo="Create token account 1",
            max_attempts=30
        )

        if create_account1_result.success:
            print(f"CreateTokenAccount 1 SUCCESS - TxID: {create_account1_result.txid}")
            tx_ids.append(("CreateTokenAccount 1", create_account1_result.txid))
        else:
            print(f"CreateTokenAccount 1 FAILED: {create_account1_result.error}")

        # Create second token account
        create_account2_result = adi_signer.sign_submit_and_wait(
            principal=identity_url,
            body=TxBody.create_token_account(token_account2_url, custom_token_url),
            memo="Create token account 2",
            max_attempts=30
        )

        if create_account2_result.success:
            print(f"CreateTokenAccount 2 SUCCESS - TxID: {create_account2_result.txid}\n")
            tx_ids.append(("CreateTokenAccount 2", create_account2_result.txid))
        else:
            print(f"CreateTokenAccount 2 FAILED: {create_account2_result.error}")

        time.sleep(5)

        # =========================================================
        # Step 8: Issue Tokens to First Account
        # =========================================================
        print("--- Step 8: Issue Custom Tokens ---\n")

        issue_amount = 100000  # 10.0000 MYTKN (4 decimal precision)
        print(f"Issuing {issue_amount} tokens to {token_account1_url}")

        issue_result = adi_signer.sign_submit_and_wait(
            principal=custom_token_url,
            body=TxBody.issue_tokens_single(token_account1_url, str(issue_amount)),
            memo=f"Issue {issue_amount} tokens",
            max_attempts=30
        )

        if issue_result.success:
            print(f"IssueTokens SUCCESS - TxID: {issue_result.txid}\n")
            tx_ids.append(("IssueTokens", issue_result.txid))
        else:
            print(f"IssueTokens FAILED: {issue_result.error}")

        time.sleep(5)

        # =========================================================
        # Step 9: Transfer Tokens Between Accounts
        # =========================================================
        print("--- Step 9: Send Custom Tokens ---\n")

        send_amount = 25000  # 2.5000 MYTKN
        print(f"Sending {send_amount} tokens from {token_account1_url} to {token_account2_url}")

        send_result = adi_signer.sign_submit_and_wait(
            principal=token_account1_url,
            body=TxBody.send_tokens_single(token_account2_url, str(send_amount)),
            memo="Send custom tokens",
            max_attempts=30
        )

        if send_result.success:
            print(f"SendTokens SUCCESS - TxID: {send_result.txid}\n")
            tx_ids.append(("SendTokens (custom)", send_result.txid))
        else:
            print(f"SendTokens FAILED: {send_result.error}")

        # =========================================================
        # Summary
        # =========================================================
        print("=== Summary ===\n")
        print(f"Created ADI: {identity_url}")
        print(f"Created custom token: {custom_token_url}")
        print(f"  Symbol: {symbol}")
        print(f"  Precision: {precision}")
        print(f"Token Account 1: {token_account1_url}")
        print(f"Token Account 2: {token_account2_url}")
        print("\nOperations:")
        print(f"  - Issued {issue_amount} tokens to Account 1")
        print(f"  - Transferred {send_amount} tokens to Account 2")
        print("\nUsed SmartSigner API for all transactions!")

        # =========================================================
        # TxID Report
        # =========================================================
        print("\n=== TRANSACTION IDs FOR VERIFICATION ===\n")
        for tx_name, txid in tx_ids:
            print(f"  {tx_name}: {txid}")
        print(f"\nTotal transactions: {len(tx_ids)}")
        print("Example 6 COMPLETED SUCCESSFULLY!")

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
