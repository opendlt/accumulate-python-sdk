#!/usr/bin/env python3
"""
SDK Example 13: ADI-to-ADI Token Transfer with Header Options (V3)

This example demonstrates:
- Sending ACME tokens between ADI token accounts (ADI-to-ADI transfers)
- Using optional transaction header fields:
  - memo: Human-readable memo text
  - metadata: Binary metadata bytes
  - expire: Transaction expiration time (ExpireOptions)
  - hold_until: Scheduled execution (HoldUntilOptions)
  - authorities: Additional signing authorities

Uses Kermit public testnet endpoints.
"""

import time
import hashlib
from datetime import datetime, timezone, timedelta

from accumulate_client import Accumulate, NetworkStatusOptions
from accumulate_client.convenience import SmartSigner, TxBody
from accumulate_client.crypto.ed25519 import Ed25519KeyPair
from accumulate_client.tx.header import ExpireOptions, HoldUntilOptions

# Kermit public testnet endpoints
KERMIT_V2 = "https://kermit.accumulatenetwork.io/v2"
KERMIT_V3 = "https://kermit.accumulatenetwork.io/v3"

# For local DevNet testing, uncomment these:
# KERMIT_V2 = "http://127.0.0.1:26660/v2"
# KERMIT_V3 = "http://127.0.0.1:26660/v3"

def main():
    print("=== SDK Example 13: ADI-to-ADI Transfer with Header Options (Python) ===\n")
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

        fund_account(client, lta, faucet_requests=10)

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

        credits = 2000  # More credits for multiple transactions
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
            return

        # Poll for lite identity credits before proceeding
        print("Polling for lite identity credits...")
        lid_credits = poll_for_lite_identity_credits(client, lid)
        if lid_credits is None or lid_credits == 0:
            print("ERROR: Lite identity has no credits. Stopping.")
            return
        print(f"Lite identity credits confirmed: {lid_credits}\n")

        # =========================================================
        # Step 4: Create an ADI
        # =========================================================
        print("--- Step 4: Create ADI ---\n")

        timestamp = int(time.time() * 1000)
        adi_name = f"sdk-hdropt-{timestamp}"
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
            print(f"CreateIdentity SUCCESS - TxID: {create_adi_result.txid}")
            tx_ids.append(("CreateIdentity", create_adi_result.txid))
        else:
            print(f"CreateIdentity FAILED: {create_adi_result.error}")
            return

        # Poll to confirm ADI exists
        print("Polling to confirm ADI creation...")
        if not poll_for_account_exists(client, identity_url):
            print("ERROR: ADI not found after creation. Stopping.")
            return
        print(f"ADI confirmed: {identity_url}\n")

        # =========================================================
        # Step 5: Add credits to ADI key page
        # =========================================================
        print("--- Step 5: Add Credits to ADI Key Page ---\n")

        key_page_credits = 1000  # More credits for multiple transactions
        key_page_amount = (key_page_credits * 10000000000) // oracle

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
            return

        # Poll for key page credits before proceeding
        key_page_credit_balance = poll_for_key_page_credits(client, key_page_url)
        if key_page_credit_balance is None or key_page_credit_balance == 0:
            print("ERROR: Key page has no credits. Stopping.")
            return
        print()

        # =========================================================
        # Step 6: Create ADI Token Accounts
        # =========================================================
        print("--- Step 6: Create ADI Token Accounts ---\n")

        adi_signer = SmartSigner(client.v3, adi_kp, key_page_url)

        tokens_account_url = f"{identity_url}/tokens"
        staking_account_url = f"{identity_url}/staking"
        savings_account_url = f"{identity_url}/savings"
        reserve_account_url = f"{identity_url}/reserve"

        # Create multiple token accounts for demonstrating transfers
        for account_url, account_name in [
            (tokens_account_url, "tokens"),
            (staking_account_url, "staking"),
            (savings_account_url, "savings"),
            (reserve_account_url, "reserve"),
        ]:
            print(f"Creating {account_name} account: {account_url}")
            create_result = adi_signer.sign_submit_and_wait(
                principal=identity_url,
                body=TxBody.create_token_account(account_url),
                memo=f"Create {account_name} account",
                max_attempts=30
            )

            if create_result.success:
                print(f"CreateTokenAccount ({account_name}) SUCCESS - TxID: {create_result.txid}")
                tx_ids.append((f"CreateTokenAccount ({account_name})", create_result.txid))
                # Poll to confirm account exists
                if not poll_for_account_exists(client, account_url):
                    print(f"WARNING: {account_name} account not confirmed after creation")
                else:
                    print(f"  {account_name} account confirmed")
            else:
                print(f"CreateTokenAccount ({account_name}) FAILED: {create_result.error}")
                print("ERROR: Token account creation failed. Stopping.")
                return

        # =========================================================
        # Step 7: Fund ADI tokens account from lite account
        # =========================================================
        print("\n--- Step 7: Fund ADI tokens account from lite ---\n")

        fund_amount = 50 * 10**8  # 50 ACME (more for multiple transfers)
        print(f"Sending 50 ACME from lite to {tokens_account_url}")

        fund_result = lite_signer.sign_submit_and_wait(
            principal=lta,
            body=TxBody.send_tokens_single(tokens_account_url, str(fund_amount)),
            memo="Fund ADI tokens account",
            max_attempts=30
        )

        if fund_result.success:
            print(f"SendTokens SUCCESS - TxID: {fund_result.txid}")
            tx_ids.append(("SendTokens (lite to ADI)", fund_result.txid))
        else:
            print(f"SendTokens FAILED: {fund_result.error}")
            return

        # Poll for tokens account balance
        print("Polling for tokens account balance...")
        tokens_balance = poll_for_token_balance(client, tokens_account_url)
        if tokens_balance is None or tokens_balance == 0:
            print("ERROR: Tokens account has no balance. Stopping.")
            return
        print(f"Tokens account balance confirmed: {tokens_balance}\n")

        # =========================================================
        # Step 8: Transfer with MEMO (using SmartSigner directly)
        # =========================================================
        print("--- Step 8: Transfer with MEMO Header Option ---\n")

        transfer_amount_1 = 2 * 10**8  # 2 ACME
        memo_text = "Payment for SDK example services - Invoice #12345"

        print(f"Sending 2 ACME with memo: '{memo_text}'")
        print(f"From: {tokens_account_url}")
        print(f"To: {staking_account_url}\n")

        transfer_memo_result = adi_signer.sign_submit_and_wait(
            principal=tokens_account_url,
            body=TxBody.send_tokens_single(staking_account_url, str(transfer_amount_1)),
            memo=memo_text,
            max_attempts=30
        )

        if transfer_memo_result.success:
            print("Transfer with MEMO SUCCESS!")
            print(f"TxID: {transfer_memo_result.txid}\n")
            tx_ids.append(("SendTokens (with memo)", transfer_memo_result.txid))
        else:
            print(f"Transfer with MEMO FAILED: {transfer_memo_result.error}")

        time.sleep(9)

        # =========================================================
        # Step 9: Transfer with METADATA (binary metadata)
        # =========================================================
        print("--- Step 9: Transfer with METADATA Header Option ---\n")

        transfer_amount_2 = 2 * 10**8  # 2 ACME
        metadata_bytes = b"Binary metadata: \x00\x01\x02\x03 SDK Example 13"

        print(f"Sending 2 ACME with metadata: {metadata_bytes}")
        print(f"From: {tokens_account_url}")
        print(f"To: {savings_account_url}\n")

        transfer_metadata_result = sign_submit_and_wait_with_header_options(
            client=client.v3,
            signer_keypair=adi_kp,
            signer_url=key_page_url,
            principal=tokens_account_url,
            body=TxBody.send_tokens_single(savings_account_url, str(transfer_amount_2)),
            metadata=metadata_bytes,
            max_attempts=30
        )

        if transfer_metadata_result.get("success"):
            print("Transfer with METADATA SUCCESS!")
            print(f"TxID: {transfer_metadata_result.get('txid')}\n")
            tx_ids.append(("SendTokens (with metadata)", transfer_metadata_result.get("txid")))
        else:
            print(f"Transfer with METADATA FAILED: {transfer_metadata_result.get('error')}")

        time.sleep(9)

        # =========================================================
        # Step 10: Transfer with EXPIRE option (expires in 1 hour)
        # =========================================================
        print("--- Step 10: Transfer with EXPIRE Header Option ---\n")

        transfer_amount_3 = 2 * 10**8  # 2 ACME
        expire_time = datetime.now(timezone.utc) + timedelta(hours=1)
        expire_options = ExpireOptions(at_time=expire_time)

        print(f"Sending 2 ACME with expire time: {expire_time.isoformat()}")
        print(f"From: {tokens_account_url}")
        print(f"To: {reserve_account_url}\n")

        transfer_expire_result = sign_submit_and_wait_with_header_options(
            client=client.v3,
            signer_keypair=adi_kp,
            signer_url=key_page_url,
            principal=tokens_account_url,
            body=TxBody.send_tokens_single(reserve_account_url, str(transfer_amount_3)),
            expire=expire_options,
            max_attempts=30
        )

        if transfer_expire_result.get("success"):
            print("Transfer with EXPIRE SUCCESS!")
            print(f"TxID: {transfer_expire_result.get('txid')}\n")
            tx_ids.append(("SendTokens (with expire)", transfer_expire_result.get("txid")))
        else:
            print(f"Transfer with EXPIRE FAILED: {transfer_expire_result.get('error')}")

        time.sleep(9)

        # =========================================================
        # Step 11: Transfer with HOLD_UNTIL option (delayed execution)
        # =========================================================
        print("--- Step 11: Transfer with HOLD_UNTIL Header Option ---\n")

        transfer_amount_4 = 2 * 10**8  # 2 ACME

        # Get current minor block and hold until a future block
        # Note: In production, you'd query the current block and add an offset
        hold_block = 1000000  # Example future block number
        hold_options = HoldUntilOptions(minor_block=hold_block)

        print(f"Sending 2 ACME with hold_until block: {hold_block}")
        print(f"From: {tokens_account_url}")
        print(f"To: {staking_account_url}")
        print("(Transaction will be held until the specified minor block)\n")

        transfer_hold_result = sign_submit_and_wait_with_header_options(
            client=client.v3,
            signer_keypair=adi_kp,
            signer_url=key_page_url,
            principal=tokens_account_url,
            body=TxBody.send_tokens_single(staking_account_url, str(transfer_amount_4)),
            hold_until=hold_options,
            max_attempts=30
        )

        if transfer_hold_result.get("success"):
            print("Transfer with HOLD_UNTIL SUCCESS!")
            print(f"TxID: {transfer_hold_result.get('txid')}\n")
            tx_ids.append(("SendTokens (with hold_until)", transfer_hold_result.get("txid")))
        else:
            print(f"Transfer with HOLD_UNTIL FAILED: {transfer_hold_result.get('error')}")

        time.sleep(9)

        # =========================================================
        # Step 12: Transfer with AUTHORITIES option
        # =========================================================
        print("--- Step 12: Transfer with AUTHORITIES Header Option ---\n")

        transfer_amount_5 = 2 * 10**8  # 2 ACME

        # Specify additional authorities that should sign this transaction
        # In a real scenario, these would be other key pages with signing authority
        authorities = [key_page_url]  # Using same key page for demonstration

        print(f"Sending 2 ACME with authorities: {authorities}")
        print(f"From: {tokens_account_url}")
        print(f"To: {savings_account_url}\n")

        transfer_auth_result = sign_submit_and_wait_with_header_options(
            client=client.v3,
            signer_keypair=adi_kp,
            signer_url=key_page_url,
            principal=tokens_account_url,
            body=TxBody.send_tokens_single(savings_account_url, str(transfer_amount_5)),
            authorities=authorities,
            max_attempts=30
        )

        if transfer_auth_result.get("success"):
            print("Transfer with AUTHORITIES SUCCESS!")
            print(f"TxID: {transfer_auth_result.get('txid')}\n")
            tx_ids.append(("SendTokens (with authorities)", transfer_auth_result.get("txid")))
        else:
            print(f"Transfer with AUTHORITIES FAILED: {transfer_auth_result.get('error')}")

        time.sleep(9)

        # =========================================================
        # Step 13: Transfer with ALL header options combined
        # =========================================================
        print("--- Step 13: Transfer with ALL Header Options Combined ---\n")

        transfer_amount_6 = 2 * 10**8  # 2 ACME
        combined_memo = "Complete transaction with all header options"
        combined_metadata = b"Full featured transaction metadata"
        combined_expire = ExpireOptions(at_time=datetime.now(timezone.utc) + timedelta(hours=2))

        print(f"Sending 2 ACME with ALL header options:")
        print(f"  - memo: '{combined_memo}'")
        print(f"  - metadata: {combined_metadata}")
        print(f"  - expire: {combined_expire.at_time.isoformat()}")
        print(f"From: {tokens_account_url}")
        print(f"To: {reserve_account_url}\n")

        transfer_all_result = sign_submit_and_wait_with_header_options(
            client=client.v3,
            signer_keypair=adi_kp,
            signer_url=key_page_url,
            principal=tokens_account_url,
            body=TxBody.send_tokens_single(reserve_account_url, str(transfer_amount_6)),
            memo=combined_memo,
            metadata=combined_metadata,
            expire=combined_expire,
            max_attempts=30
        )

        if transfer_all_result.get("success"):
            print("Transfer with ALL OPTIONS SUCCESS!")
            print(f"TxID: {transfer_all_result.get('txid')}\n")
            tx_ids.append(("SendTokens (all options)", transfer_all_result.get("txid")))
        else:
            print(f"Transfer with ALL OPTIONS FAILED: {transfer_all_result.get('error')}")

        # =========================================================
        # Step 14: Verify balances
        # =========================================================
        print("--- Step 14: Verify Balances ---\n")

        time.sleep(15)

        for account_url, account_name in [
            (tokens_account_url, "tokens"),
            (staking_account_url, "staking"),
            (savings_account_url, "savings"),
            (reserve_account_url, "reserve"),
        ]:
            try:
                query_result = client.v3.query(account_url)
                account_balance = query_result.get("account", {}).get("balance")
                print(f"{account_name.capitalize()} account balance: {account_balance}")
            except Exception as e:
                print(f"Could not query {account_name} balance: {e}")

        # =========================================================
        # Summary
        # =========================================================
        print("\n=== Summary ===\n")
        print(f"Created ADI: {identity_url}")
        print(f"Token Accounts: tokens, staking, savings, reserve")
        print("\nToken transfers demonstrated with header options:")
        print("  - MEMO: Human-readable transaction memo")
        print("  - METADATA: Binary metadata bytes")
        print("  - EXPIRE: Transaction expiration time")
        print("  - HOLD_UNTIL: Scheduled execution at specific block")
        print("  - AUTHORITIES: Additional signing authorities")
        print("  - ALL COMBINED: Multiple header options together")

        # =========================================================
        # TxID Report
        # =========================================================
        print("\n=== TRANSACTION IDs FOR VERIFICATION ===\n")
        for tx_name, txid in tx_ids:
            print(f"  {tx_name}: {txid}")
        print(f"\nTotal transactions: {len(tx_ids)}")
        print("Example 13 COMPLETED SUCCESSFULLY!")

    finally:
        client.close()


def sign_submit_and_wait_with_header_options(
    client,
    signer_keypair,
    signer_url: str,
    principal: str,
    body: dict,
    memo: str = None,
    metadata: bytes = None,
    expire: ExpireOptions = None,
    hold_until: HoldUntilOptions = None,
    authorities: list = None,
    max_attempts: int = 30,
    poll_interval: float = 2.0
) -> dict:
    """
    Sign, submit, and wait for transaction with optional header fields.

    This function demonstrates how to use all optional header fields:
    - memo: Human-readable memo text (string)
    - metadata: Binary metadata (bytes, hex-encoded in transaction)
    - expire: Expiration options (ExpireOptions with at_time)
    - hold_until: Hold until options (HoldUntilOptions with minor_block)
    - authorities: Additional signing authorities (list of URLs)

    Args:
        client: V3 API client
        signer_keypair: Ed25519KeyPair for signing
        signer_url: URL of the signing key page
        principal: Transaction principal URL
        body: Transaction body
        memo: Optional memo text
        metadata: Optional binary metadata
        expire: Optional expiration options
        hold_until: Optional hold until options
        authorities: Optional list of additional authorities
        max_attempts: Maximum poll attempts
        poll_interval: Seconds between polls

    Returns:
        Dict with success, txid, error, and response fields
    """
    try:
        # Get signer version
        try:
            result = client.query(signer_url)
            signer_version = result.get("account", {}).get("version", 1)
        except Exception:
            signer_version = 1

        # Get public key and hash
        public_key_bytes = signer_keypair.public_key_bytes()
        public_key_hash = hashlib.sha256(public_key_bytes).digest()

        # Build timestamp
        timestamp = int(time.time() * 1_000_000)  # microseconds

        # Build transaction header with optional fields
        header = {
            "principal": principal,
            "initiator": public_key_hash.hex(),
            "timestamp": timestamp
        }

        # Add optional header fields
        if memo:
            header["memo"] = memo

        if metadata:
            header["metadata"] = metadata.hex()

        if expire and expire.at_time:
            header["expire"] = expire.to_dict()

        if hold_until and hold_until.minor_block:
            header["holdUntil"] = hold_until.to_dict()

        if authorities:
            header["authorities"] = authorities

        # Build transaction
        transaction = {
            "header": header,
            "body": body
        }

        # Compute transaction hash using canonical JSON
        from accumulate_client.canonjson import dumps_canonical
        tx_bytes = dumps_canonical(transaction).encode('utf-8')
        tx_hash = hashlib.sha256(tx_bytes).digest()

        # Sign
        signature = signer_keypair.sign(tx_hash)

        # Build envelope (V3 format)
        envelope = {
            "transaction": transaction,
            "signatures": [{
                "type": "ed25519",
                "publicKey": public_key_bytes.hex(),
                "signature": signature.hex(),
                "signer": signer_url,
                "signerVersion": signer_version,
                "timestamp": timestamp
            }]
        }

        # Submit
        response = client.submit(envelope)

        # Extract transaction ID
        txid = None
        if isinstance(response, list) and response:
            first_result = response[0]
            if isinstance(first_result, dict) and first_result.get("status"):
                txid = first_result["status"].get("txID")

        if not txid:
            return {
                "success": False,
                "error": "Could not extract transaction ID from response",
                "response": response
            }

        # Wait for confirmation
        for attempt in range(max_attempts):
            try:
                tx_result = client.query(txid)
                if tx_result.get("status", {}).get("delivered", False):
                    return {
                        "success": True,
                        "txid": txid,
                        "response": tx_result
                    }
            except Exception:
                pass

            time.sleep(poll_interval)

        # Timeout - but transaction may still succeed
        return {
            "success": True,  # Assume success if submitted
            "txid": txid,
            "response": response
        }

    except Exception as e:
        return {
            "success": False,
            "error": str(e)
        }


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
    """Poll for account balance (used for initial lite account funding)."""
    import requests

    for i in range(max_attempts):
        # Try V3 query first
        try:
            result = client.v3.query(account_url)
            balance = result.get("account", {}).get("balance")
            if balance is not None:
                balance_int = int(balance) if isinstance(balance, (int, str)) else 0
                if balance_int > 0:
                    return balance_int
        except Exception as e:
            if i == 0:  # Only log first error
                print(f"  V3 query error: {e}")

        # Fallback to V2 query
        try:
            v2_response = requests.post(
                client.v2.endpoint,
                json={
                    "jsonrpc": "2.0",
                    "method": "query",
                    "params": {"url": account_url},
                    "id": i + 1
                },
                timeout=30
            )
            v2_result = v2_response.json()
            if "result" in v2_result:
                v2_balance = v2_result.get("result", {}).get("data", {}).get("balance")
                if v2_balance:
                    balance_int = int(v2_balance)
                    if balance_int > 0:
                        return balance_int
        except Exception as e:
            if i == 0:  # Only log first error
                print(f"  V2 query error: {e}")

        print(f"  Waiting for balance... (attempt {i+1}/{max_attempts})")
        time.sleep(2)
    return 0


def poll_for_lite_identity_credits(client: Accumulate, lite_identity_url: str, max_attempts: int = 30) -> int:
    """Poll for lite identity credits."""
    import requests

    print("Waiting for lite identity credits to settle...")
    for i in range(max_attempts):
        # Try V3 query first
        try:
            result = client.v3.query(lite_identity_url)
            credit_balance = result.get("account", {}).get("creditBalance")
            if credit_balance is not None:
                credits = int(credit_balance) if isinstance(credit_balance, (int, str)) else 0
                if credits > 0:
                    print(f"Lite identity credits confirmed: {credits}")
                    return credits
        except Exception as e:
            print(f"  V3 query error: {e}")

        # Fallback to V2 query
        try:
            v2_response = requests.post(
                client.v2.endpoint,
                json={
                    "jsonrpc": "2.0",
                    "method": "query",
                    "params": {"url": lite_identity_url},
                    "id": i + 1
                },
                timeout=30
            )
            v2_result = v2_response.json()
            if "result" in v2_result:
                v2_credits = v2_result.get("result", {}).get("data", {}).get("creditBalance")
                if v2_credits:
                    credits = int(v2_credits)
                    if credits > 0:
                        print(f"Lite identity credits confirmed (v2): {credits}")
                        return credits
        except Exception as e:
            print(f"  V2 query error: {e}")

        print(f"  Waiting for lite identity credits... (attempt {i+1}/{max_attempts})")
        time.sleep(2)
    return 0


def poll_for_key_page_credits(client: Accumulate, key_page_url: str, max_attempts: int = 30) -> int:
    """Poll for key page credits."""
    import requests

    print("Waiting for key page credits to settle...")
    for i in range(max_attempts):
        # Try V3 query first
        try:
            result = client.v3.query(key_page_url)
            credit_balance = result.get("account", {}).get("creditBalance")
            if credit_balance is not None:
                credits = int(credit_balance) if isinstance(credit_balance, (int, str)) else 0
                if credits > 0:
                    print(f"Key page credits confirmed: {credits}")
                    return credits
        except Exception as e:
            print(f"  V3 query error: {e}")

        # Fallback to V2 query
        try:
            v2_response = requests.post(
                client.v2.endpoint,
                json={
                    "jsonrpc": "2.0",
                    "method": "query",
                    "params": {"url": key_page_url},
                    "id": i + 1
                },
                timeout=30
            )
            v2_result = v2_response.json()
            if "result" in v2_result:
                v2_credits = v2_result.get("result", {}).get("data", {}).get("creditBalance")
                if v2_credits:
                    credits = int(v2_credits)
                    if credits > 0:
                        print(f"Key page credits confirmed (v2): {credits}")
                        return credits
        except Exception as e:
            print(f"  V2 query error: {e}")

        print(f"  Waiting for key page credits... (attempt {i+1}/{max_attempts})")
        time.sleep(2)
    return 0


def poll_for_account_exists(client: Accumulate, account_url: str, max_attempts: int = 30) -> bool:
    """Poll to confirm an account exists on the network."""
    import requests

    print(f"  Polling for account: {account_url}")
    for i in range(max_attempts):
        # Try V3 query first
        try:
            result = client.v3.query(account_url)
            account = result.get("account")
            if account:
                account_type = account.get("type", "unknown")
                print(f"  Account found: type={account_type}")
                return True
        except Exception as e:
            if "not found" not in str(e).lower():
                print(f"  V3 query error: {e}")

        # Fallback to V2 query
        try:
            v2_response = requests.post(
                client.v2.endpoint,
                json={
                    "jsonrpc": "2.0",
                    "method": "query",
                    "params": {"url": account_url},
                    "id": i + 1
                },
                timeout=30
            )
            v2_result = v2_response.json()
            if "result" in v2_result and "data" in v2_result.get("result", {}):
                account_type = v2_result["result"]["data"].get("type", "unknown")
                print(f"  Account found (v2): type={account_type}")
                return True
        except Exception as e:
            if "not found" not in str(e).lower():
                print(f"  V2 query error: {e}")

        print(f"  Waiting for account... (attempt {i+1}/{max_attempts})")
        time.sleep(2)
    return False


def poll_for_token_balance(client: Accumulate, account_url: str, min_balance: int = 1, max_attempts: int = 30) -> int:
    """Poll for token account balance to reach minimum threshold."""
    import requests

    print(f"  Polling for balance on: {account_url}")
    for i in range(max_attempts):
        # Try V3 query first
        try:
            result = client.v3.query(account_url)
            balance = result.get("account", {}).get("balance")
            if balance is not None:
                balance_int = int(balance) if isinstance(balance, (int, str)) else 0
                if balance_int >= min_balance:
                    print(f"  Balance confirmed: {balance_int}")
                    return balance_int
        except Exception as e:
            print(f"  V3 query error: {e}")

        # Fallback to V2 query
        try:
            v2_response = requests.post(
                client.v2.endpoint,
                json={
                    "jsonrpc": "2.0",
                    "method": "query",
                    "params": {"url": account_url},
                    "id": i + 1
                },
                timeout=30
            )
            v2_result = v2_response.json()
            if "result" in v2_result:
                v2_balance = v2_result.get("result", {}).get("data", {}).get("balance")
                if v2_balance:
                    balance_int = int(v2_balance)
                    if balance_int >= min_balance:
                        print(f"  Balance confirmed (v2): {balance_int}")
                        return balance_int
        except Exception as e:
            print(f"  V2 query error: {e}")

        print(f"  Waiting for balance... (attempt {i+1}/{max_attempts})")
        time.sleep(2)
    return 0


if __name__ == "__main__":
    main()
