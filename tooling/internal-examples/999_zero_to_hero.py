#!/usr/bin/env python3

"""
Zero-to-Hero: Complete Accumulate Python SDK demonstration

This example demonstrates the complete flow:
1. Generate Ed25519 keypair and derive Lite URLs
2. Fund Lite Token Account from faucet
3. Buy credits for Lite Identity
4. Create ADI (Accumulate Digital Identity)
5. Create token account in ADI
6. Send tokens from LTA to ADI token account

Demonstrates same semantics as Dart zero-to-hero.
"""

import os
import sys
import time

# Add parent directory to path for relative imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from shared_helpers import load_env_config, test_devnet_connectivity, print_endpoints
from accumulate_client import AccumulateClient
from tests.helpers.crypto_helpers import (
    derive_lite_identity_url,
    derive_lite_token_account_url,
    create_signature_envelope,
    create_transaction_hash,
    ed25519_keypair_from_seed
)
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization
import secrets


def generate_keypair():
    """Generate new Ed25519 keypair"""
    print("🔑 Generating Ed25519 keypair...")

    # Generate new private key
    private_key = ed25519.Ed25519PrivateKey.generate()

    # Get key bytes
    private_key_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption()
    )
    public_key_bytes = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )

    # Derive URLs
    lid = derive_lite_identity_url(public_key_bytes)
    lta = derive_lite_token_account_url(public_key_bytes)

    print(f"  Private Key: {private_key_bytes.hex()}")
    print(f"  Public Key:  {public_key_bytes.hex()}")
    print(f"  LID:         {lid}")
    print(f"  LTA:         {lta}")

    return private_key_bytes, public_key_bytes, lid, lta


def fund_lta_from_faucet(v2_client, lta):
    """Fund LTA from DevNet faucet"""
    print(f"💰 Funding LTA from faucet: {lta}")

    try:
        # Request tokens from faucet
        faucet_result = v2_client.faucet({"url": lta})

        if "transactionHash" in faucet_result:
            tx_hash = faucet_result["transactionHash"]
            print(f"  ✓ Faucet transaction: {tx_hash}")
            return tx_hash
        else:
            print(f"  ✗ Faucet failed: {faucet_result}")
            return None
    except Exception as e:
        print(f"  ✗ Faucet error: {e}")
        return None


def buy_credits(v2_client, v3_client, private_key_bytes, lid, lta):
    """Buy credits for LID using LTA"""
    print(f"🏪 Buying credits for LID: {lid}")

    # Check LTA balance first
    try:
        query_result = v3_client.call('query', {"url": lta})
        if "data" in query_result and query_result["data"]:
            lta_balance = int(query_result["data"].get("balance", "0"))
            print(f"  LTA balance: {lta_balance} ACME")
            if lta_balance < 50000:  # Need at least 0.05 ACME
                print("  ✗ Insufficient LTA balance")
                return None
        else:
            print("  ✗ LTA does not exist")
            return None
    except Exception as e:
        print(f"  ✗ LTA query error: {e}")
        return None

    # Create add credits transaction
    transaction = {
        "header": {
            "principal": lta,
            "timestamp": int(time.time() * 1000000)
        },
        "body": {
            "type": "addCredits",
            "recipient": {"url": lid},
            "amount": "50000"  # 0.05 ACME = 500 credits
        }
    }

    # Create signature envelope
    envelope = create_signature_envelope(transaction, private_key_bytes)
    tx_hash = create_transaction_hash(transaction).hex()
    print(f"  Transaction hash: {tx_hash}")

    # Submit transaction
    try:
        submit_result = v2_client.call('submit', envelope)
        if "transactionHash" in submit_result:
            submitted_hash = submit_result["transactionHash"]
            print(f"  ✓ Credits transaction: {submitted_hash}")
            return submitted_hash
        else:
            print(f"  ✗ Submit failed: {submit_result}")
            return None
    except Exception as e:
        print(f"  ✗ Submit error: {e}")
        return None


def create_adi(v2_client, private_key_bytes, lid, adi_name):
    """Create ADI (Accumulate Digital Identity)"""
    adi_url = f"acc://{adi_name}.acme"
    print(f"🏢 Creating ADI: {adi_url}")

    # Create ADI transaction
    transaction = {
        "header": {
            "principal": lid,
            "timestamp": int(time.time() * 1000000)
        },
        "body": {
            "type": "createIdentity",
            "url": adi_url,
            "keyBookUrl": f"{adi_url}/book",
            "keyPageUrl": f"{adi_url}/book/1"
        }
    }

    # Create signature envelope
    envelope = create_signature_envelope(transaction, private_key_bytes)
    tx_hash = create_transaction_hash(transaction).hex()
    print(f"  Transaction hash: {tx_hash}")

    # Submit transaction
    try:
        submit_result = v2_client.call('submit', envelope)
        if "transactionHash" in submit_result:
            submitted_hash = submit_result["transactionHash"]
            print(f"  ✓ ADI creation: {submitted_hash}")
            return adi_url, submitted_hash
        else:
            print(f"  ✗ Submit failed: {submit_result}")
            return None, None
    except Exception as e:
        print(f"  ✗ Submit error: {e}")
        return None, None


def create_token_account(v2_client, private_key_bytes, adi_url, account_name):
    """Create token account in ADI"""
    token_account_url = f"{adi_url}/{account_name}"
    print(f"🪙 Creating token account: {token_account_url}")

    # Create token account transaction
    transaction = {
        "header": {
            "principal": f"{adi_url}/book/1",  # Key page as principal
            "timestamp": int(time.time() * 1000000)
        },
        "body": {
            "type": "createTokenAccount",
            "url": token_account_url,
            "tokenUrl": "acc://ACME",
            "keyBookUrl": f"{adi_url}/book"
        }
    }

    # Create signature envelope
    envelope = create_signature_envelope(transaction, private_key_bytes)
    tx_hash = create_transaction_hash(transaction).hex()
    print(f"  Transaction hash: {tx_hash}")

    # Submit transaction
    try:
        submit_result = v2_client.call('submit', envelope)
        if "transactionHash" in submit_result:
            submitted_hash = submit_result["transactionHash"]
            print(f"  ✓ Token account creation: {submitted_hash}")
            return token_account_url, submitted_hash
        else:
            print(f"  ✗ Submit failed: {submit_result}")
            return None, None
    except Exception as e:
        print(f"  ✗ Submit error: {e}")
        return None, None


def send_tokens(v2_client, private_key_bytes, lta, token_account_url, amount):
    """Send tokens from LTA to ADI token account"""
    print(f"💸 Sending {amount} ACME from LTA to {token_account_url}")

    # Create send tokens transaction
    transaction = {
        "header": {
            "principal": lta,
            "timestamp": int(time.time() * 1000000)
        },
        "body": {
            "type": "sendTokens",
            "to": [
                {
                    "url": token_account_url,
                    "amount": str(amount)
                }
            ]
        }
    }

    # Create signature envelope
    envelope = create_signature_envelope(transaction, private_key_bytes)
    tx_hash = create_transaction_hash(transaction).hex()
    print(f"  Transaction hash: {tx_hash}")

    # Submit transaction
    try:
        submit_result = v2_client.call('submit', envelope)
        if "transactionHash" in submit_result:
            submitted_hash = submit_result["transactionHash"]
            print(f"  ✓ Token transfer: {submitted_hash}")
            return submitted_hash
        else:
            print(f"  ✗ Submit failed: {submit_result}")
            return None
    except Exception as e:
        print(f"  ✗ Submit error: {e}")
        return None


def check_balances(v3_client, lta, lid, token_account_url=None):
    """Check balances and print final state"""
    print("📊 Final balances:")

    # Check LTA balance
    try:
        query_result = v3_client.call('query', {"url": lta})
        if "data" in query_result and query_result["data"]:
            lta_balance = query_result["data"].get("balance", "0")
            print(f"  LTA ({lta}): {lta_balance} ACME")
        else:
            print(f"  LTA ({lta}): 0 ACME")
    except Exception as e:
        print(f"  LTA ({lta}): Error - {e}")

    # Check LID credits
    try:
        query_result = v3_client.call('query', {"url": lid})
        if "data" in query_result and query_result["data"]:
            credits = query_result["data"].get("creditBalance", "0")
            print(f"  LID ({lid}): {credits} credits")
        else:
            print(f"  LID ({lid}): 0 credits")
    except Exception as e:
        print(f"  LID ({lid}): Error - {e}")

    # Check token account balance if provided
    if token_account_url:
        try:
            query_result = v3_client.call('query', {"url": token_account_url})
            if "data" in query_result and query_result["data"]:
                balance = query_result["data"].get("balance", "0")
                print(f"  Token Account ({token_account_url}): {balance} ACME")
            else:
                print(f"  Token Account ({token_account_url}): 0 ACME")
        except Exception as e:
            print(f"  Token Account ({token_account_url}): Error - {e}")


def main():
    """Main zero-to-hero demonstration"""
    print(">>> === Accumulate Python SDK: Zero to Hero ===")
    print()

    # Load configuration
    config = load_env_config()
    print_endpoints(config)

    # Test connectivity
    test_devnet_connectivity(config)

    # Create clients
    v2_client = AccumulateClient(config['ACC_RPC_URL_V2'])
    v3_client = AccumulateClient(config['ACC_RPC_URL_V3'])

    try:
        # Step 1: Generate keypair
        private_key_bytes, public_key_bytes, lid, lta = generate_keypair()
        print()

        # Step 2: Fund LTA from faucet
        faucet_tx = fund_lta_from_faucet(v2_client, lta)
        if not faucet_tx:
            print("[ERROR] Failed to fund LTA from faucet")
            return

        # Wait for faucet transaction
        print("[WAIT] Waiting 5 seconds for faucet transaction...")
        time.sleep(5)
        print()

        # Step 3: Buy credits for LID
        credits_tx = buy_credits(v2_client, v3_client, private_key_bytes, lid, lta)
        if not credits_tx:
            print("[ERROR] Failed to buy credits")
            return

        # Wait for credits transaction
        print("[WAIT] Waiting 5 seconds for credits transaction...")
        time.sleep(5)
        print()

        # Step 4: Create ADI
        adi_name = f"hero-{secrets.token_hex(4)}"  # Random ADI name
        adi_url, adi_tx = create_adi(v2_client, private_key_bytes, lid, adi_name)
        if not adi_url:
            print("[ERROR] Failed to create ADI")
            return

        # Wait for ADI creation
        print("[WAIT] Waiting 8 seconds for ADI creation...")
        time.sleep(8)
        print()

        # Step 5: Create token account in ADI
        token_account_url, token_account_tx = create_token_account(
            v2_client, private_key_bytes, adi_url, "tokens"
        )
        if not token_account_url:
            print("[ERROR] Failed to create token account")
            return

        # Wait for token account creation
        print("[WAIT] Waiting 5 seconds for token account creation...")
        time.sleep(5)
        print()

        # Step 6: Send tokens from LTA to ADI token account
        send_tx = send_tokens(v2_client, private_key_bytes, lta, token_account_url, 100000)
        if not send_tx:
            print("[ERROR] Failed to send tokens")
            return

        # Wait for token transfer
        print("[WAIT] Waiting 5 seconds for token transfer...")
        time.sleep(5)
        print()

        # Final: Check all balances
        check_balances(v3_client, lta, lid, token_account_url)
        print()

        # Summary
        print("🎉 === Zero-to-Hero Complete! ===")
        print("📝 Transaction Summary:")
        print(f"  🏦 Faucet:           {faucet_tx}")
        print(f"  🏪 Buy Credits:      {credits_tx}")
        print(f"  🏢 Create ADI:       {adi_tx}")
        print(f"  🪙 Token Account:    {token_account_tx}")
        print(f"  💸 Send Tokens:     {send_tx}")
        print()
        print("🔗 Final URLs:")
        print(f"  Lite Identity:       {lid}")
        print(f"  Lite Token Account:  {lta}")
        print(f"  ADI:                 {adi_url}")
        print(f"  Token Account:       {token_account_url}")
        print()
        print("[OK] Successfully demonstrated complete Accumulate workflow!")

    except Exception as e:
        print(f"[ERROR] Zero-to-hero failed: {e}")
        sys.exit(1)

    finally:
        v2_client.close()
        v3_client.close()


if __name__ == "__main__":
    main()