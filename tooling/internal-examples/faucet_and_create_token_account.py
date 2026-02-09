#!/usr/bin/env python3
"""
Faucet and Create Token Account Example

Demonstrates requesting credits from the faucet, creating a token account,
and querying the resulting account state.

This example shows:
1. Requesting credits from the ACME faucet
2. Creating a token account for a specific token
3. Querying account balances and state
4. Error handling for faucet and account operations
"""

import argparse
import json
import hashlib
import sys
import os
from pathlib import Path
from typing import Optional, Dict, Any

# Add src to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from accumulate_client.api_client import AccumulateClient
from accumulate_client.tx.builders import get_builder_for
from accumulate_client.signers.ed25519 import Ed25519Signer
from accumulate_client.crypto.ed25519 import Ed25519PrivateKey
from accumulate_client.runtime.url import AccountUrl


def generate_or_load_keypair(keys_dir: Path, identity_name: str) -> tuple[Ed25519PrivateKey, str]:
    """
    Generate or load an Ed25519 keypair for the identity.

    Args:
        keys_dir: Directory to store/load keys
        identity_name: Name of the identity

    Returns:
        Tuple of (private_key, public_key_hex)
    """
    keys_dir.mkdir(exist_ok=True)
    private_key_file = keys_dir / f"{identity_name}_private.key"

    if private_key_file.exists():
        print(f"Loading existing keypair for {identity_name}")
        with open(private_key_file, 'r') as f:
            private_key_hex = f.read().strip()
        private_key = Ed25519PrivateKey.from_hex(private_key_hex)
    else:
        print(f"Generating new keypair for {identity_name}")
        private_key = Ed25519PrivateKey.generate()
        with open(private_key_file, 'w') as f:
            f.write(private_key.to_hex())
        # Set restrictive permissions
        private_key_file.chmod(0o600)

    public_key_hex = private_key.public_key().to_hex()
    print(f"Public key: {public_key_hex}")

    return private_key, public_key_hex


def wait_for_transaction(client: AccumulateClient, txid: str, timeout: int = 30) -> dict:
    """
    Wait for a transaction to be processed.

    Args:
        client: Accumulate client
        txid: Transaction ID to wait for
        timeout: Maximum seconds to wait

    Returns:
        Transaction result
    """
    import time

    print(f"Waiting for transaction {txid}...")
    start_time = time.time()

    while time.time() - start_time < timeout:
        try:
            result = client.query_tx(txid)
            if result.get('data', {}).get('status') == 'delivered':
                print(f"Transaction {txid} delivered successfully")
                return result
            elif result.get('data', {}).get('status') == 'failed':
                print(f"Transaction {txid} failed: {result.get('data', {}).get('error')}")
                return result
        except Exception as e:
            # Transaction might not be found yet
            pass

        time.sleep(2)

    raise TimeoutError(f"Transaction {txid} did not complete within {timeout} seconds")


def request_faucet(client: AccumulateClient, account_url: str, amount: int = 10000,
                  mock: bool = False) -> Optional[str]:
    """
    Request credits from the Accumulate faucet.

    Args:
        client: Accumulate client
        account_url: Account URL to fund
        amount: Amount of credits to request
        mock: Whether to use mock mode

    Returns:
        Transaction ID if successful, None if error
    """
    print(f"Requesting {amount} credits from faucet for {account_url}")

    if mock:
        print("MOCK MODE: Would request faucet credits")
        return "mock-faucet-txid"

    try:
        result = client.faucet(account_url, amount)
        txid = result.get('data', {}).get('transactionHash')

        if txid:
            print(f"Faucet request submitted with txid: {txid}")
        else:
            print(f"Faucet response: {result}")

        return txid
    except Exception as e:
        print(f"Faucet request failed: {e}")
        return None


def create_token_account(client: AccumulateClient, private_key: Ed25519PrivateKey,
                        token_account_url: str, token_url: str, identity_url: str,
                        wait: bool = True, mock: bool = False) -> Optional[str]:
    """
    Create a token account for a specific token.

    Args:
        client: Accumulate client
        private_key: Private key for signing
        token_account_url: URL for the new token account
        token_url: URL of the token to create account for
        identity_url: Identity that owns the account
        wait: Whether to wait for transaction completion
        mock: Whether to use mock mode

    Returns:
        Transaction ID if successful, None if error
    """
    print(f"Creating token account:")
    print(f"  Account: {token_account_url}")
    print(f"  Token: {token_url}")
    print(f"  Owner: {identity_url}")

    # Build CreateTokenAccount transaction
    builder = get_builder_for('CreateTokenAccount')
    builder.with_field('url', token_account_url)
    builder.with_field('tokenUrl', token_url)
    builder.with_field('keyBookUrl', f"{identity_url}/book")
    builder.with_field('scratch', False)

    # Validate the transaction
    try:
        builder.validate()
        print("CreateTokenAccount transaction is valid")
    except Exception as e:
        print(f"CreateTokenAccount validation failed: {e}")
        return None

    # Create transaction body and envelope
    body = builder.to_body()
    canonical_json = builder.to_canonical_json()
    print(f"CreateTokenAccount canonical JSON: {canonical_json}")

    # Sign the transaction
    tx_hash = hashlib.sha256(canonical_json.encode()).digest()
    signer = Ed25519Signer(private_key, f"{identity_url}/book/1")
    signature = signer.to_accumulate_signature(tx_hash)

    # Create envelope
    envelope = {
        'transaction': body,
        'signatures': [signature]
    }

    if mock:
        print("MOCK MODE: Would submit CreateTokenAccount transaction")
        return "mock-create-token-account-txid"

    try:
        # Submit transaction
        result = client.submit(envelope)
        txid = result.get('data', {}).get('transactionHash')
        print(f"CreateTokenAccount submitted with txid: {txid}")

        if wait and txid:
            wait_for_transaction(client, txid)

        return txid
    except Exception as e:
        print(f"Failed to submit CreateTokenAccount: {e}")
        return None


def query_account_state(client: AccumulateClient, account_url: str,
                       mock: bool = False) -> Optional[Dict[str, Any]]:
    """
    Query the state of an account.

    Args:
        client: Accumulate client
        account_url: Account URL to query
        mock: Whether to use mock mode

    Returns:
        Account state if successful, None if error
    """
    print(f"Querying account state: {account_url}")

    if mock:
        print("MOCK MODE: Would query account state")
        return {
            "data": {
                "type": "tokenAccount",
                "url": account_url,
                "balance": "5000",
                "tokenUrl": "acc://ACME",
                "creditBalance": "10000"
            }
        }

    try:
        result = client.query(account_url)
        account_data = result.get('data', {})

        print(f"Account type: {account_data.get('type', 'unknown')}")
        if 'balance' in account_data:
            print(f"Token balance: {account_data['balance']}")
        if 'creditBalance' in account_data:
            print(f"Credit balance: {account_data['creditBalance']}")
        if 'tokenUrl' in account_data:
            print(f"Token URL: {account_data['tokenUrl']}")

        return result
    except Exception as e:
        print(f"Failed to query account: {e}")
        return None


def main():
    """Main faucet and token account example function."""
    parser = argparse.ArgumentParser(
        description='Request faucet credits and create token account on Accumulate',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
    # Request faucet and create ACME token account
    python faucet_and_create_token_account.py --identity alice.acme

    # Use testnet with custom token
    python faucet_and_create_token_account.py --api https://testnet.acme.com/v3 --token acc://USDC.acme

    # Mock mode (no actual submission)
    python faucet_and_create_token_account.py --mock --identity test.acme

    # Request specific faucet amount
    python faucet_and_create_token_account.py --faucet-amount 20000 --identity bob.acme
        """
    )

    parser.add_argument('--api', default='http://localhost:26660/v3',
                       help='Accumulate API endpoint (default: %(default)s)')
    parser.add_argument('--identity', default='faucet-example.acme',
                       help='Identity name to use (default: %(default)s)')
    parser.add_argument('--token', default='acc://ACME',
                       help='Token URL to create account for (default: %(default)s)')
    parser.add_argument('--faucet-amount', type=int, default=10000,
                       help='Amount of credits to request from faucet (default: %(default)s)')
    parser.add_argument('--keys', type=Path, default=Path('./examples/.keys'),
                       help='Directory to store keys (default: %(default)s)')
    parser.add_argument('--wait', action='store_true', default=True,
                       help='Wait for transaction completion (default)')
    parser.add_argument('--no-wait', action='store_false', dest='wait',
                       help='Don\'t wait for transaction completion')
    parser.add_argument('--mock', action='store_true',
                       help='Mock mode - don\'t actually submit transactions')
    parser.add_argument('--verbose', '-v', action='store_true',
                       help='Verbose output')

    args = parser.parse_args()

    if args.verbose:
        import logging
        logging.basicConfig(level=logging.DEBUG)

    print("Accumulate Faucet and Token Account Example")
    print("=" * 45)
    print(f"API endpoint: {args.api}")
    print(f"Identity: {args.identity}")
    print(f"Token: {args.token}")
    print(f"Faucet amount: {args.faucet_amount}")
    print(f"Mock mode: {args.mock}")
    print()

    # Create client
    if args.mock:
        from tests.helpers import MockClient, MockTransport
        transport = MockTransport()
        client = MockClient(transport)
        print("Using mock client")
    else:
        client = AccumulateClient(args.api)
        print(f"Connected to {args.api}")

    try:
        # Generate or load keypair
        private_key, public_key_hex = generate_or_load_keypair(args.keys, args.identity)

        # Create URLs
        identity_url = f"acc://{args.identity}"
        lite_account_url = f"acc://{public_key_hex}"
        token_account_url = f"{identity_url}/tokens"

        print(f"\nIdentity URL: {identity_url}")
        print(f"Lite account URL: {lite_account_url}")
        print(f"Token account URL: {token_account_url}")

        # Step 1: Request faucet credits for the lite account
        print(f"\n--- Step 1: Request Faucet Credits ---")
        faucet_txid = request_faucet(client, lite_account_url, args.faucet_amount, mock=args.mock)

        if faucet_txid:
            print(f"✓ Faucet request transaction: {faucet_txid}")
            if args.wait and not args.mock:
                wait_for_transaction(client, faucet_txid)
        else:
            print("⚠ Faucet request failed or not available")

        # Step 2: Query lite account state after faucet
        print(f"\n--- Step 2: Query Lite Account After Faucet ---")
        lite_state = query_account_state(client, lite_account_url, mock=args.mock)

        # Step 3: Create token account
        print(f"\n--- Step 3: Create Token Account ---")
        create_txid = create_token_account(
            client, private_key, token_account_url, args.token, identity_url,
            wait=args.wait, mock=args.mock
        )

        if create_txid:
            print(f"✓ Token account creation transaction: {create_txid}")
        else:
            print("✗ Failed to create token account")
            return 1

        # Step 4: Query token account state
        print(f"\n--- Step 4: Query Token Account State ---")
        token_state = query_account_state(client, token_account_url, mock=args.mock)

        # Step 5: Query identity state
        print(f"\n--- Step 5: Query Identity State ---")
        identity_state = query_account_state(client, identity_url, mock=args.mock)

        print(f"\n✓ Faucet and token account example completed successfully!")
        print(f"✓ Lite account: {lite_account_url}")
        print(f"✓ Token account: {token_account_url}")
        print(f"✓ Identity: {identity_url}")

        return 0

    except Exception as e:
        print(f"\n✗ Example failed: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        return 1


if __name__ == '__main__':
    sys.exit(main())