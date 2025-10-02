#!/usr/bin/env python3
"""
Submit Identity and Write Data Example

Demonstrates the complete flow of creating an identity, signing transactions,
and writing data to the Accumulate network.

This example shows:
1. Generating/loading Ed25519 keypairs
2. Building CreateIdentity transactions
3. Signing and submitting transactions
4. Building WriteData transactions
5. Waiting for transaction receipts
"""

import argparse
import json
import hashlib
import sys
import os
from pathlib import Path
from typing import Optional

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


def create_identity(client: AccumulateClient, private_key: Ed25519PrivateKey,
                   identity_url: str, wait: bool = True, mock: bool = False) -> Optional[str]:
    """
    Create an identity on the Accumulate network.

    Args:
        client: Accumulate client
        private_key: Private key for signing
        identity_url: Identity URL to create
        wait: Whether to wait for transaction completion
        mock: Whether to use mock submission

    Returns:
        Transaction ID if submitted, None if error
    """
    print(f"Creating identity: {identity_url}")

    # Build CreateIdentity transaction
    builder = get_builder_for('CreateIdentity')
    builder.with_field('url', identity_url)
    builder.with_field('keyBookUrl', f"{identity_url}/book")
    builder.with_field('keyPageUrl', f"{identity_url}/book/1")

    # Validate the transaction
    try:
        builder.validate()
        print("CreateIdentity transaction is valid")
    except Exception as e:
        print(f"CreateIdentity validation failed: {e}")
        return None

    # Create transaction body and envelope
    body = builder.to_body()
    canonical_json = builder.to_canonical_json()
    print(f"CreateIdentity canonical JSON: {canonical_json}")

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
        print("MOCK MODE: Would submit CreateIdentity transaction")
        return "mock-create-identity-txid"

    try:
        # Submit transaction
        result = client.submit(envelope)
        txid = result.get('data', {}).get('transactionHash')
        print(f"CreateIdentity submitted with txid: {txid}")

        if wait and txid:
            wait_for_transaction(client, txid)

        return txid
    except Exception as e:
        print(f"Failed to submit CreateIdentity: {e}")
        return None


def write_data(client: AccumulateClient, private_key: Ed25519PrivateKey,
               identity_url: str, data: bytes, wait: bool = True, mock: bool = False) -> Optional[str]:
    """
    Write data to the identity's data account.

    Args:
        client: Accumulate client
        private_key: Private key for signing
        identity_url: Identity URL that owns the data account
        data: Data to write
        wait: Whether to wait for transaction completion
        mock: Whether to use mock submission

    Returns:
        Transaction ID if submitted, None if error
    """
    data_account_url = f"{identity_url}/data"
    print(f"Writing data to: {data_account_url}")
    print(f"Data: {data}")

    # Build WriteData transaction
    builder = get_builder_for('WriteData')
    builder.with_field('data', data)
    builder.with_field('scratch', False)

    # Validate the transaction
    try:
        builder.validate()
        print("WriteData transaction is valid")
    except Exception as e:
        print(f"WriteData validation failed: {e}")
        return None

    # Create transaction body and envelope
    body = builder.to_body()
    canonical_json = builder.to_canonical_json()
    print(f"WriteData canonical JSON: {canonical_json}")

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
        print("MOCK MODE: Would submit WriteData transaction")
        return "mock-write-data-txid"

    try:
        # Submit transaction
        result = client.submit(envelope)
        txid = result.get('data', {}).get('transactionHash')
        print(f"WriteData submitted with txid: {txid}")

        if wait and txid:
            wait_for_transaction(client, txid)

        return txid
    except Exception as e:
        print(f"Failed to submit WriteData: {e}")
        return None


def main():
    """Main example function."""
    parser = argparse.ArgumentParser(
        description='Submit identity creation and write data to Accumulate',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
    # Create identity and write data on local network
    python submit_identity_and_write_data.py --identity alice.acme

    # Use testnet with custom API endpoint
    python submit_identity_and_write_data.py --api https://testnet.acme.com/v3 --identity bob.acme

    # Mock mode (no actual submission)
    python submit_identity_and_write_data.py --mock --identity test.acme

    # Don't wait for transaction completion
    python submit_identity_and_write_data.py --no-wait --identity charlie.acme
        """
    )

    parser.add_argument('--api', default='http://localhost:26660/v3',
                       help='Accumulate API endpoint (default: %(default)s)')
    parser.add_argument('--identity', default='example.acme',
                       help='Identity name to create (default: %(default)s)')
    parser.add_argument('--data', default='Hello from Accumulate SDK!',
                       help='Data to write (default: %(default)s)')
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

    print("Accumulate Identity and Data Example")
    print("=" * 40)
    print(f"API endpoint: {args.api}")
    print(f"Identity: {args.identity}")
    print(f"Data: {args.data}")
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

        # Create identity URL
        identity_url = f"acc://{args.identity}"

        # Create identity
        create_txid = create_identity(client, private_key, identity_url,
                                    wait=args.wait, mock=args.mock)

        if create_txid:
            print(f"✓ Identity creation transaction: {create_txid}")
        else:
            print("✗ Failed to create identity")
            return 1

        # Write data
        data_bytes = args.data.encode('utf-8')
        write_txid = write_data(client, private_key, identity_url, data_bytes,
                              wait=args.wait, mock=args.mock)

        if write_txid:
            print(f"✓ Data write transaction: {write_txid}")
        else:
            print("✗ Failed to write data")
            return 1

        print("\n✓ Example completed successfully!")
        return 0

    except Exception as e:
        print(f"\n✗ Example failed: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        return 1


if __name__ == '__main__':
    sys.exit(main())