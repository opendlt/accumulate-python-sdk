#!/usr/bin/env python3
"""
Multisig Token Transfer Example

Demonstrates creating a multisig signature set (threshold 2/3) and submitting
a SendTokens transaction with multiple signatures.

This example shows:
1. Creating multiple Ed25519 keypairs for multisig
2. Building a SendTokens transaction
3. Creating a threshold signature set (2 out of 3 required)
4. Signing with multiple keys
5. Submitting the multisig transaction
"""

import argparse
import json
import hashlib
import sys
import os
from pathlib import Path
from typing import List, Tuple

# Add src to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from accumulate_client import Accumulate
from accumulate_client.tx.builders import get_builder_for
from accumulate_client.signers.ed25519 import Ed25519Signer
from accumulate_client.crypto.ed25519 import Ed25519PrivateKey
from accumulate_client.runtime.url import AccountUrl


def generate_multisig_keys(keys_dir: Path, account_name: str, count: int = 3) -> List[Tuple[Ed25519PrivateKey, str]]:
    """
    Generate or load multiple keypairs for multisig.

    Args:
        keys_dir: Directory to store/load keys
        account_name: Name of the account
        count: Number of keys to generate

    Returns:
        List of (private_key, public_key_hex) tuples
    """
    keys_dir.mkdir(exist_ok=True)
    keypairs = []

    for i in range(count):
        key_name = f"{account_name}_multisig_{i+1}"
        private_key_file = keys_dir / f"{key_name}_private.key"

        if private_key_file.exists():
            print(f"Loading existing key {i+1}/{count} for {account_name}")
            with open(private_key_file, 'r') as f:
                private_key_hex = f.read().strip()
            private_key = Ed25519PrivateKey.from_hex(private_key_hex)
        else:
            print(f"Generating new key {i+1}/{count} for {account_name}")
            private_key = Ed25519PrivateKey.generate()
            with open(private_key_file, 'w') as f:
                f.write(private_key.to_hex())
            # Set restrictive permissions
            private_key_file.chmod(0o600)

        public_key_hex = private_key.public_key().to_hex()
        print(f"Key {i+1} public key: {public_key_hex}")
        keypairs.append((private_key, public_key_hex))

    return keypairs


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


def create_multisig_send_tokens(
        client: AccumulateClient,
        keypairs: List[Tuple[Ed25519PrivateKey, str]],
        from_account: str,
        to_account: str,
        amount: int,
        threshold: int = 2,
        wait: bool = True,
        mock: bool = False
) -> str:
    """
    Create and submit a multisig SendTokens transaction.

    Args:
        client: Accumulate client
        keypairs: List of (private_key, public_key_hex) for multisig
        from_account: Source account URL
        to_account: Destination account URL
        amount: Amount to send (in credits)
        threshold: Number of signatures required
        wait: Whether to wait for transaction completion
        mock: Whether to use mock submission

    Returns:
        Transaction ID
    """
    print(f"Creating multisig SendTokens transaction:")
    print(f"  From: {from_account}")
    print(f"  To: {to_account}")
    print(f"  Amount: {amount}")
    print(f"  Threshold: {threshold}/{len(keypairs)}")

    # Build SendTokens transaction
    builder = get_builder_for('SendTokens')
    builder.with_field('to', to_account)
    builder.with_field('amount', amount)

    # Validate the transaction
    try:
        builder.validate()
        print("SendTokens transaction is valid")
    except Exception as e:
        print(f"SendTokens validation failed: {e}")
        return None

    # Create transaction body and envelope
    body = builder.to_body()
    canonical_json = builder.to_canonical_json()
    print(f"SendTokens canonical JSON: {canonical_json}")

    # Sign with multiple keys (up to threshold)
    tx_hash = hashlib.sha256(canonical_json.encode()).digest()
    signatures = []

    # Use the first 'threshold' number of keys for signing
    signing_keys = keypairs[:threshold]

    for i, (private_key, public_key_hex) in enumerate(signing_keys):
        key_page_url = f"{from_account}/book/{i+1}"
        signer = Ed25519Signer(private_key, key_page_url)
        signature = signer.to_accumulate_signature(tx_hash)

        # Add multisig metadata
        signature['vote'] = 'accept'
        signature['memo'] = f'Multisig signature {i+1}/{threshold}'

        signatures.append(signature)
        print(f"  ✓ Signed with key {i+1}/{threshold}")

    # Create multisig envelope
    envelope = {
        'transaction': body,
        'signatures': signatures
    }

    # Add multisig metadata to envelope
    envelope['multiSig'] = {
        'threshold': threshold,
        'totalKeys': len(keypairs),
        'signaturesProvided': len(signatures)
    }

    if mock:
        print("MOCK MODE: Would submit multisig SendTokens transaction")
        print(f"Mock envelope: {json.dumps(envelope, indent=2)}")
        return "mock-multisig-send-tokens-txid"

    try:
        # Submit transaction
        result = client.submit(envelope)
        txid = result.get('data', {}).get('transactionHash')
        print(f"Multisig SendTokens submitted with txid: {txid}")

        if wait and txid:
            wait_for_transaction(client, txid)

        return txid
    except Exception as e:
        print(f"Failed to submit multisig SendTokens: {e}")
        return None


def main():
    """Main multisig example function."""
    parser = argparse.ArgumentParser(
        description='Multisig token transfer on Accumulate',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
    # Transfer tokens using 2/3 multisig
    python multisig_transfer_tokens.py --from acc://alice.acme/tokens --to acc://bob.acme/tokens --amount 1000

    # Use testnet with custom threshold
    python multisig_transfer_tokens.py --api https://testnet.acme.com/v3 --threshold 3 --keys 4 --amount 500

    # Mock mode (no actual submission)
    python multisig_transfer_tokens.py --mock --from acc://test.acme/tokens --to acc://dest.acme/tokens --amount 100

    # Don't wait for transaction completion
    python multisig_transfer_tokens.py --no-wait --amount 250
        """
    )

    parser.add_argument('--api', default='http://localhost:26660/v3',
                       help='Accumulate API endpoint (default: %(default)s)')
    parser.add_argument('--from', dest='from_account', default='acc://multisig-sender.acme/tokens',
                       help='Source account URL (default: %(default)s)')
    parser.add_argument('--to', dest='to_account', default='acc://multisig-recipient.acme/tokens',
                       help='Destination account URL (default: %(default)s)')
    parser.add_argument('--amount', type=int, default=1000,
                       help='Amount to transfer in credits (default: %(default)s)')
    parser.add_argument('--threshold', type=int, default=2,
                       help='Number of signatures required (default: %(default)s)')
    parser.add_argument('--keys', type=int, default=3,
                       help='Total number of keys to generate (default: %(default)s)')
    parser.add_argument('--keys-dir', type=Path, default=Path('./examples/.keys'),
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

    # Validate arguments
    if args.threshold > args.keys:
        print(f"Error: Threshold ({args.threshold}) cannot be greater than total keys ({args.keys})")
        return 1

    if args.threshold < 1:
        print(f"Error: Threshold must be at least 1")
        return 1

    print("Accumulate Multisig Token Transfer Example")
    print("=" * 45)
    print(f"API endpoint: {args.api}")
    print(f"From account: {args.from_account}")
    print(f"To account: {args.to_account}")
    print(f"Amount: {args.amount}")
    print(f"Multisig: {args.threshold}/{args.keys}")
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
        # Extract account name from URL for key generation
        from_url_parts = args.from_account.replace('acc://', '').split('/')
        account_name = from_url_parts[0]

        # Generate multisig keypairs
        print(f"\nGenerating {args.keys} keypairs for multisig...")
        keypairs = generate_multisig_keys(args.keys_dir, account_name, args.keys)

        # Create and submit multisig transaction
        txid = create_multisig_send_tokens(
            client,
            keypairs,
            args.from_account,
            args.to_account,
            args.amount,
            threshold=args.threshold,
            wait=args.wait,
            mock=args.mock
        )

        if txid:
            print(f"\n✓ Multisig token transfer transaction: {txid}")
            print(f"✓ Successfully sent {args.amount} tokens from {args.from_account} to {args.to_account}")
            print(f"✓ Used {args.threshold}/{args.keys} multisig signatures")
        else:
            print("\n✗ Failed to submit multisig transaction")
            return 1

        print("\n✓ Multisig example completed successfully!")
        return 0

    except Exception as e:
        print(f"\n✗ Multisig example failed: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        return 1


if __name__ == '__main__':
    sys.exit(main())