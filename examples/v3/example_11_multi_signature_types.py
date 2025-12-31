#!/usr/bin/env python3
"""
SDK Example 11: Multi-Signature Types (V3)

This example demonstrates:
- All signature types supported by Accumulate
- Ed25519, Legacy Ed25519, RCD1, BTC, ETH signatures
- Using different key types for signing transactions

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
from src.accumulate_client.signers import (
    Ed25519Signer,
    LegacyEd25519Signer,
    RCD1Signer,
    BTCSigner,
    ETHSigner,
    get_signer_types,
    get_implemented_signer_types,
)

# Kermit public testnet endpoints
KERMIT_V2 = "https://kermit.accumulatenetwork.io/v2"
KERMIT_V3 = "https://kermit.accumulatenetwork.io/v3"

# For local DevNet testing, uncomment these:
# KERMIT_V2 = "http://127.0.0.1:26660/v2"
# KERMIT_V3 = "http://127.0.0.1:26660/v3"


def main():
    print("=== SDK Example 11: Multi-Signature Types (Python) ===\n")
    print(f"Endpoint: {KERMIT_V3}\n")
    demonstrate_signature_types()


def demonstrate_signature_types():
    base_endpoint = KERMIT_V3.replace("/v3", "")
    client = Accumulate(base_endpoint)

    try:
        # =========================================================
        # Step 1: List all supported signature types
        # =========================================================
        print("--- Step 1: Supported Signature Types ---\n")

        all_types = get_signer_types()
        implemented_types = get_implemented_signer_types()

        print(f"All signature types ({len(all_types)}):")
        for sig_type in sorted(all_types):
            status = "implemented" if sig_type in implemented_types else "placeholder"
            print(f"  - {sig_type}: {status}")
        print("")

        # =========================================================
        # Step 2: Demonstrate Ed25519 Signature
        # =========================================================
        print("--- Step 2: Ed25519 Signature ---\n")

        ed25519_kp = Ed25519KeyPair.generate()
        ed25519_pub = ed25519_kp.public_key_bytes()
        ed25519_signer = Ed25519Signer(ed25519_kp.private_key)

        test_message = b"Hello Accumulate!"
        ed25519_sig = ed25519_signer.sign(test_message)

        print(f"Public Key (Ed25519): {ed25519_pub.hex()[:32]}...")
        print(f"Signature length: {len(ed25519_sig)} bytes")
        print(f"Signature valid: {ed25519_signer.verify(ed25519_sig, test_message)}")
        print("")

        # =========================================================
        # Step 3: Demonstrate Legacy Ed25519 Signature
        # =========================================================
        print("--- Step 3: Legacy Ed25519 Signature ---\n")

        legacy_ed25519_kp = Ed25519KeyPair.generate()
        # LegacyEd25519Signer requires signer_url parameter, pass bytes to avoid import path issues
        legacy_signer = LegacyEd25519Signer(legacy_ed25519_kp.private_key_bytes(), "acc://demo/page")

        # LegacyEd25519 uses SHA-256 digest for signing/verification
        test_digest = hashlib.sha256(test_message).digest()
        legacy_sig = legacy_signer.sign(test_digest)

        print(f"Public Key (Legacy Ed25519): {legacy_signer.get_public_key().hex()[:32]}...")
        print(f"Signature length: {len(legacy_sig)} bytes")
        print(f"Signature valid: {legacy_signer.verify(legacy_sig, test_digest)}")
        print("")

        # =========================================================
        # Step 4: Demonstrate RCD1 Signature (Factom Compatibility)
        # =========================================================
        print("--- Step 4: RCD1 Signature (Factom Compatibility) ---\n")

        rcd1_kp = Ed25519KeyPair.generate()
        # RCD1Signer requires signer_url parameter
        # Note: Must use private_key object, not bytes, for RCD1Signer
        rcd1_signer = RCD1Signer(rcd1_kp.private_key, "acc://demo/page")

        # RCD1 also uses message hash for signing
        rcd1_sig = rcd1_signer.sign(test_digest)

        print(f"Public Key (RCD1): {rcd1_signer.get_public_key().hex()[:32]}...")
        print(f"Signature length: {len(rcd1_sig)} bytes")
        print(f"Signature valid: {rcd1_signer.verify(rcd1_sig, test_digest)}")
        print("Note: RCD1 uses SHA256d (double-SHA256) for hashing")
        print("")

        # =========================================================
        # Step 5: Demonstrate BTC Signature (Secp256k1)
        # =========================================================
        print("--- Step 5: BTC Signature (Secp256k1) ---\n")

        try:
            # BTC signatures require secp256k1 library
            # Generate 32-byte random private key for secp256k1
            btc_private_key = os.urandom(32)
            btc_signer = BTCSigner(btc_private_key)

            btc_sig = btc_signer.sign(test_message)

            print(f"Public Key (BTC/Secp256k1): {btc_signer.get_public_key().hex()[:32]}...")
            print(f"Signature length: {len(btc_sig)} bytes")
            print(f"Signature valid: {btc_signer.verify(btc_sig, test_message)}")
        except ImportError as e:
            print(f"BTC signer requires 'secp256k1' or 'coincurve' package: {e}")
        except Exception as e:
            print(f"BTC signature demo skipped (optional dependency): {e}")
        print("")

        # =========================================================
        # Step 6: Demonstrate ETH Signature
        # =========================================================
        print("--- Step 6: ETH Signature ---\n")

        try:
            # ETH signatures also use secp256k1
            eth_private_key = os.urandom(32)
            eth_signer = ETHSigner(eth_private_key)

            eth_sig = eth_signer.sign(test_message)

            print(f"Public Key (ETH): {eth_signer.get_public_key().hex()[:32]}...")
            print(f"Signature length: {len(eth_sig)} bytes")
            print(f"Signature valid: {eth_signer.verify(eth_sig, test_message)}")
        except ImportError as e:
            print(f"ETH signer requires 'secp256k1' or 'coincurve' package: {e}")
        except Exception as e:
            print(f"ETH signature demo skipped (optional dependency): {e}")
        print("")

        # =========================================================
        # Step 7: Practical Transaction with Ed25519
        # =========================================================
        print("--- Step 7: Practical Transaction Demo with Ed25519 ---\n")

        # Generate keys and derive lite account
        lite_kp = Ed25519KeyPair.generate()
        lid = lite_kp.derive_lite_identity_url()
        lta = lite_kp.derive_lite_token_account_url("ACME")

        print(f"Lite Identity: {lid}")
        print(f"Lite Token Account: {lta}")

        # Fund via faucet
        print("\nRequesting funds from faucet...")
        fund_account(client, lta, faucet_requests=3)

        # Wait and poll for balance
        print("\nPolling for balance...")
        balance = poll_for_balance(client, lta)
        if balance is None or balance == 0:
            print("Account not funded - stopping demo here")
            print("(Run against a network with faucet to see full demo)")
            return

        print(f"Balance confirmed: {balance}")

        # Add credits using SmartSigner
        print("\nAdding credits to lite identity...")

        lite_signer = SmartSigner(client.v3, lite_kp, lid)

        network_status = client.v3.network_status(NetworkStatusOptions(partition="directory"))
        oracle = network_status.get("oracle", {}).get("price", 500000)

        credits = 100
        amount = (credits * 10000000000) // oracle

        add_credits_result = lite_signer.sign_submit_and_wait(
            principal=lta,
            body=TxBody.add_credits(lid, str(amount), oracle),
            memo="Add credits (multi-sig types demo)",
            max_attempts=30
        )

        if add_credits_result.success:
            print(f"AddCredits SUCCESS - TxID: {add_credits_result.txid}")
        else:
            print(f"AddCredits FAILED: {add_credits_result.error}")

        # =========================================================
        # Summary
        # =========================================================
        print("\n=== Summary ===\n")
        print("Demonstrated signature types:")
        print("  1. Ed25519 - Standard Accumulate signature")
        print("  2. Legacy Ed25519 - Pre-signed message format")
        print("  3. RCD1 - Factom compatibility (SHA256d)")
        print("  4. BTC - Bitcoin/Secp256k1 (requires secp256k1)")
        print("  5. ETH - Ethereum/Secp256k1 (requires secp256k1)")
        print("")
        print("Additional supported types (not demoed):")
        print("  - BTC Legacy - Legacy Bitcoin format")
        print("  - TypedData - EIP-712 typed data signatures")
        print("  - RSA SHA256 - RSA with SHA256")
        print("  - ECDSA SHA256 - ECDSA with SHA256")
        print("  - Delegated - Delegated authority signatures")
        print("  - Authority - Authority signatures")
        print("  - SignatureSet - Multiple signatures")
        print("  - Remote - Cross-partition signatures")
        print("")
        print("For production use:")
        print("  - Ed25519 is recommended for most use cases")
        print("  - RCD1 for Factom migration")
        print("  - BTC/ETH for blockchain interoperability")

    finally:
        client.close()


def fund_account(client: Accumulate, account_url: str, faucet_requests: int = 3):
    """Fund an account using the faucet."""
    import requests

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


def poll_for_balance(client: Accumulate, account_url: str, max_attempts: int = 20) -> int:
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
