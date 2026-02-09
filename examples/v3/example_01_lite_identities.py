#!/usr/bin/env python3
"""
SDK Example 1: Lite Identities (V3)

This example demonstrates:
- Creating lite identities and token accounts
- Using the SmartSigner API for auto-version tracking
- Funding accounts via faucet
- Adding credits and sending tokens

Uses Kermit public testnet endpoints.
"""

import time

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
    print("=== SDK Example 1: Lite Identities (Python) ===\n")
    print(f"Endpoint: {KERMIT_V3}\n")
    test_lite_identities()


def test_lite_identities():
    base_endpoint = KERMIT_V3.replace("/v3", "")
    client = Accumulate(base_endpoint)

    try:
        # =========================================================
        # Step 1: Generate key pairs for two lite identities
        # =========================================================
        print("--- Step 1: Generate Key Pairs ---\n")

        kp1 = Ed25519KeyPair.generate()
        kp2 = Ed25519KeyPair.generate()

        # Derive lite identity and token account URLs (with checksum)
        lid1 = kp1.derive_lite_identity_url()
        lta1 = kp1.derive_lite_token_account_url("ACME")
        lid2 = kp2.derive_lite_identity_url()
        lta2 = kp2.derive_lite_token_account_url("ACME")

        print(f"Lite Identity 1: {lid1}")
        print(f"Lite Token Account 1: {lta1}")
        print(f"Public Key Hash 1: {kp1.public_key_bytes().hex()[:32]}...\n")

        print(f"Lite Identity 2: {lid2}")
        print(f"Lite Token Account 2: {lta2}")
        print(f"Public Key Hash 2: {kp2.public_key_bytes().hex()[:32]}...\n")

        # Collect all TxIDs for verification
        tx_ids = []

        # =========================================================
        # Step 2: Fund the first lite account via faucet
        # =========================================================
        print("--- Step 2: Fund Account via Faucet ---\n")

        fund_account(client, lta1, faucet_requests=5)

        # Poll for balance
        print("\nPolling for balance...")
        balance = poll_for_balance(client, lta1)
        if balance is None or balance == 0:
            print("ERROR: Account not funded. Stopping.")
            return
        print(f"Balance confirmed: {balance}\n")

        # =========================================================
        # Step 3: Add credits to lite identity using SmartSigner
        # =========================================================
        print("--- Step 3: Add Credits (using SmartSigner) ---\n")

        # Create SmartSigner - auto-queries signer version!
        signer1 = SmartSigner(client.v3, kp1, lid1)

        # Get oracle price
        network_status = client.v3.network_status(NetworkStatusOptions(partition="directory"))
        oracle = network_status.get("oracle", {}).get("price", 500000)
        print(f"Oracle price: {oracle}")

        # Calculate amount for 1000 credits
        credits = 1000
        amount = (credits * 10000000000) // oracle
        print(f"Buying {credits} credits for {amount} ACME sub-units")

        # Use SmartSigner to sign and submit - no manual version tracking!
        # Set verbose=True to see full RPC request/response for debugging
        add_credits_result = signer1.sign_submit_and_wait(
            principal=lta1,
            body=TxBody.add_credits(lid1, str(amount), oracle),
            memo="Add credits to lite identity",
            max_attempts=30
        )

        if add_credits_result.success:
            print(f"AddCredits SUCCESS - TxID: {add_credits_result.txid}")
            tx_ids.append(("AddCredits (lite identity)", add_credits_result.txid))
        else:
            print(f"AddCredits FAILED: {add_credits_result.error}")
            print(f"Full response: {add_credits_result.response}")
            print("Continuing anyway to demonstrate API...")

        # Verify credits were added
        time.sleep(5)
        try:
            lid_query = client.v3.query(lid1)
            credit_balance = lid_query.get("account", {}).get("creditBalance")
            print(f"Lite identity credit balance: {credit_balance}\n")
        except Exception as e:
            print(f"Could not query credit balance: {e}\n")

        # =========================================================
        # Step 4: Send tokens from lta1 to lta2
        # =========================================================
        print("--- Step 4: Send Tokens ---\n")

        send_amount = 100000000  # 1 ACME (8 decimal places)
        print(f"Sending 1 ACME from {lta1} to {lta2}")

        send_result = signer1.sign_submit_and_wait(
            principal=lta1,
            body=TxBody.send_tokens_single(lta2, str(send_amount)),
            memo="Send 1 ACME",
            max_attempts=30
        )

        if send_result.success:
            print(f"SendTokens SUCCESS - TxID: {send_result.txid}")
            tx_ids.append(("SendTokens", send_result.txid))
        else:
            print(f"SendTokens FAILED: {send_result.error}")
            print(f"Full response: {send_result.response}")

        # Check recipient balance
        time.sleep(5)
        try:
            lta2_query = client.v3.query(lta2)
            recipient_balance = lta2_query.get("account", {}).get("balance")
            print(f"Recipient balance: {recipient_balance}\n")
        except Exception as e:
            print(f"Could not query recipient: {e}\n")

        # =========================================================
        # Summary
        # =========================================================
        print("=== Summary ===\n")
        print("Created two lite identities:")
        print(f"  1. {lid1}")
        print(f"  2. {lid2}")
        print("\nUsed SmartSigner API which:")
        print("  - Automatically queries signer version")
        print("  - Provides sign(), signAndSubmit(), signSubmitAndWait()")
        print("  - No manual version tracking needed!")

        # =========================================================
        # TxID Report
        # =========================================================
        print("\n=== TRANSACTION IDs FOR VERIFICATION ===\n")
        for tx_name, txid in tx_ids:
            print(f"  {tx_name}: {txid}")
        print(f"\nTotal transactions: {len(tx_ids)}")
        print("Example 1 COMPLETED SUCCESSFULLY!")

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
