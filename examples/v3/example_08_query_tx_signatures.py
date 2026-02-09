#!/usr/bin/env python3
"""
SDK Example 8: Query Transactions & Signatures (V3)

This example demonstrates:
- Querying transactions, signatures, memo data, and account information
- Using SmartSigner API for auto-version tracking

Uses Kermit public testnet endpoints.
"""

import time
import hashlib
import json

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
    print("=== SDK Example 8: Query Transactions & Signatures (Python) ===\n")
    print(f"Endpoint: {KERMIT_V3}\n")
    test_query_features()


def test_query_features():
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
        adi_name = f"sdk-query-{timestamp}"
        identity_url = f"acc://{adi_name}.acme"
        book_url = f"{identity_url}/book"
        key_page_url = f"{book_url}/1"

        adi_pub = adi_kp.public_key_bytes()
        adi_key_hash = hashlib.sha256(adi_pub).digest()

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

        key_page_credits = 300
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
        # Step 6: Create ADI Token Accounts
        # =========================================================
        print("--- Step 6: Create ADI Token Accounts ---\n")

        adi_signer = SmartSigner(client.v3, adi_kp, key_page_url)

        tokens_account_url = f"{identity_url}/tokens"
        savings_account_url = f"{identity_url}/savings"

        create_tokens1_result = adi_signer.sign_submit_and_wait(
            principal=identity_url,
            body=TxBody.create_token_account(tokens_account_url),
            memo="Create tokens account",
            max_attempts=30
        )

        if create_tokens1_result.success:
            print(f"CreateTokenAccount (tokens) SUCCESS - TxID: {create_tokens1_result.txid}")
            tx_ids.append(("CreateTokenAccount (tokens)", create_tokens1_result.txid))

        create_savings_result = adi_signer.sign_submit_and_wait(
            principal=identity_url,
            body=TxBody.create_token_account(savings_account_url),
            memo="Create savings account",
            max_attempts=30
        )

        if create_savings_result.success:
            print(f"CreateTokenAccount (savings) SUCCESS - TxID: {create_savings_result.txid}\n")
            tx_ids.append(("CreateTokenAccount (savings)", create_savings_result.txid))

        time.sleep(5)

        # =========================================================
        # Step 7: Fund ADI Token Account
        # =========================================================
        print("--- Step 7: Fund ADI Token Account ---\n")

        fund_result = lite_signer.sign_submit_and_wait(
            principal=lta,
            body=TxBody.send_tokens_single(tokens_account_url, "1000000000"),  # 10 ACME
            memo="Fund ADI tokens account",
            max_attempts=30
        )

        if fund_result.success:
            print(f"Fund tokens account SUCCESS - TxID: {fund_result.txid}\n")
            tx_ids.append(("SendTokens (fund ADI)", fund_result.txid))

        time.sleep(5)

        # =========================================================
        # Step 8: Send Transaction with Memo for Query Demo
        # =========================================================
        print("--- Step 8: Send Transaction with Memo ---\n")

        test_memo = "Query Test Signature Memo V3"
        print(f"Sending transaction with memo: {test_memo}")

        send_result = adi_signer.sign_submit_and_wait(
            principal=tokens_account_url,
            body=TxBody.send_tokens_single(savings_account_url, "100000000"),  # 1 ACME
            memo=test_memo,
            max_attempts=30
        )

        demo_txid = None
        if send_result.success:
            demo_txid = send_result.txid
            print(f"SendTokens SUCCESS - TxID: {demo_txid}\n")
            tx_ids.append(("SendTokens (with memo)", demo_txid))

        time.sleep(5)

        # =========================================================
        # Step 9: Query Transaction by ID
        # =========================================================
        print("--- Step 9: Query Transaction by ID ---\n")

        if demo_txid:
            query_transaction_by_id(client, demo_txid)

        # =========================================================
        # Step 10: Query Account Information
        # =========================================================
        print("--- Step 10: Query Account Information ---\n")

        query_account_information(client, tokens_account_url)
        query_account_information(client, savings_account_url)

        # =========================================================
        # Step 11: Query Key Page Information
        # =========================================================
        print("--- Step 11: Query Key Page Information ---\n")

        query_key_page_information(client, key_page_url)

        # =========================================================
        # Step 12: Query Lite Account
        # =========================================================
        print("--- Step 12: Query Lite Account ---\n")

        query_account_information(client, lta)
        query_account_information(client, lid)

        # =========================================================
        # Summary
        # =========================================================
        print("\n=== Summary ===\n")
        print(f"Created ADI: {identity_url}")
        print(f"Token Accounts: {tokens_account_url}, {savings_account_url}")
        print("Demonstrated queries for:")
        print("  - Transaction by ID")
        print("  - Account information")
        print("  - Key page information")
        print("  - Lite account information")
        print("\nUsed SmartSigner API for all transactions!")

        # =========================================================
        # TxID Report
        # =========================================================
        print("\n=== TRANSACTION IDs FOR VERIFICATION ===\n")
        for tx_name, txid in tx_ids:
            print(f"  {tx_name}: {txid}")
        print(f"\nTotal transactions: {len(tx_ids)}")
        print("Example 8 COMPLETED SUCCESSFULLY!")

    except Exception as e:
        print(f"Error during query testing: {e}")
        import traceback
        traceback.print_exc()
    finally:
        client.close()


def query_transaction_by_id(client: Accumulate, txid: str):
    """Query a specific transaction by its ID."""
    try:
        print(f"Transaction ID: {txid}")

        # Extract tx hash from txid
        tx_hash = txid.split("@")[0].replace("acc://", "")
        tx_query = client.v3.query(f"acc://{tx_hash}@unknown")

        print("\nTransaction query result:")
        print(json.dumps(tx_query, indent=2, default=str))

        # Extract and display signature information if available
        if isinstance(tx_query, dict) and tx_query.get("signatures"):
            signatures = tx_query["signatures"]
            print("\n--- Signature Information ---")
            for i, sig in enumerate(signatures):
                print(f"Signature {i}:")
                print(f"  Type: {sig.get('type', 'Unknown')}")
                pub_key = sig.get('publicKey', 'N/A')
                if len(str(pub_key)) > 20:
                    pub_key = str(pub_key)[:20]
                print(f"  PublicKey: {pub_key}...")

        # Extract and display transaction body information
        if isinstance(tx_query, dict) and tx_query.get("transaction"):
            tx = tx_query["transaction"]
            print("\n--- Transaction Information ---")
            print(f"  Principal: {tx.get('header', {}).get('principal')}")
            print(f"  Memo: {tx.get('header', {}).get('memo')}")
            print(f"  Body Type: {tx.get('body', {}).get('type')}")
        print("")

    except Exception as e:
        print(f"Error querying transaction by ID: {e}\n")


def query_account_information(client: Accumulate, account_url: str):
    """Query account information."""
    try:
        print(f"Querying: {account_url}")

        account_query = client.v3.query(account_url)

        # Display account-specific information
        if isinstance(account_query, dict) and account_query.get("account"):
            data = account_query["account"]
            print(f"  Type: {data.get('type')}")
            print(f"  URL: {data.get('url')}")
            if data.get("balance") is not None:
                print(f"  Balance: {data.get('balance')}")
            if data.get("creditBalance") is not None:
                print(f"  Credits: {data.get('creditBalance')}")
            if data.get("tokenUrl") is not None:
                print(f"  Token URL: {data.get('tokenUrl')}")
        print("")

    except Exception as e:
        print(f"  Error: {e}\n")


def query_key_page_information(client: Accumulate, key_page_url: str):
    """Query key page information."""
    try:
        print(f"Querying Key Page: {key_page_url}")

        key_page_query = client.v3.query(key_page_url)

        # Display key page-specific information
        if isinstance(key_page_query, dict) and key_page_query.get("account"):
            data = key_page_query["account"]
            print(f"  Type: {data.get('type')}")
            print(f"  URL: {data.get('url')}")
            print(f"  Version: {data.get('version')}")
            if data.get("acceptThreshold") is not None:
                print(f"  Accept Threshold: {data.get('acceptThreshold')}")
            if data.get("keys") is not None:
                keys = data["keys"]
                print(f"  Keys count: {len(keys)}")
            if data.get("creditBalance") is not None:
                print(f"  Credits: {data.get('creditBalance')}")
        print("")

    except Exception as e:
        print(f"  Error: {e}\n")


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
