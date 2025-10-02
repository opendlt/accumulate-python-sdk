#!/usr/bin/env python3
"""Debug transaction structure."""

import sys
import json
from pathlib import Path

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent))

from _common import make_client, keypair_from_seed
from accumulate_client.tx.builders import get_builder_for
from accumulate_client.signers.ed25519 import Ed25519Signer

def main():
    # Create mock client
    client = make_client("http://127.0.0.1:26660", mock=True)

    # Derive keys
    private_key, public_key = keypair_from_seed("000102030405060708090a0b0c0d0e0f")

    # Generate accounts
    pub_key_hash = public_key.to_bytes()[:20]
    lite_identity = f"acc://{pub_key_hash.hex()}"
    lite_token_account = f"{lite_identity}/ACME"
    adi_token_account = "acc://demo.acme/tokens"

    print(f"Lite Token Account: {lite_token_account}")
    print(f"ADI Token Account: {adi_token_account}")

    # Build SendTokens transaction
    send_tokens_builder = get_builder_for('SendTokens')
    send_tokens_builder.with_field('to', [{
        'url': adi_token_account,
        'amount': 90_000_000
    }])

    # Create signature
    import hashlib
    canonical_json = send_tokens_builder.to_canonical_json()
    tx_hash = hashlib.sha256(canonical_json).digest()

    lite_signer = Ed25519Signer(private_key, lite_token_account)
    signature = lite_signer.to_accumulate_signature(tx_hash)

    # Create envelope
    envelope = {
        'transaction': send_tokens_builder.to_body(),
        'signatures': [signature]
    }

    print("\n=== TRANSACTION ENVELOPE ===")
    print(json.dumps(envelope, indent=2, default=str))

    print("\n=== SIGNATURE STRUCTURE ===")
    print(json.dumps(signature, indent=2, default=str))

    # Submit transaction
    result = client.submit(envelope)
    print(f"\n=== RESULT ===")
    print(json.dumps(result, indent=2, default=str))

if __name__ == "__main__":
    main()