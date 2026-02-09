#!/usr/bin/env python3

"""Generate Ed25519 keypair and derive Lite Identity + Token Account URLs"""

import os
import sys

# Add parent directory to path for relative imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tests.helpers.crypto_helpers import (
    derive_lite_identity_url,
    derive_lite_token_account_url,
    ed25519_keypair_from_seed
)
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization


def load_env_config():
    """Load DevNet configuration from environment or .env.local"""
    config = {
        'ACC_RPC_URL_V2': os.environ.get('ACC_RPC_URL_V2', 'http://localhost:26660/v2'),
        'ACC_RPC_URL_V3': os.environ.get('ACC_RPC_URL_V3', 'http://localhost:26660/v3'),
        'ACC_FAUCET_ACCOUNT': os.environ.get('ACC_FAUCET_ACCOUNT', ''),
        'ACC_DEVNET_DIR': os.environ.get('ACC_DEVNET_DIR', '')
    }

    # Try to load from .env.local
    env_local_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), '.env.local')
    if os.path.exists(env_local_path):
        with open(env_local_path, 'r') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#') and '=' in line:
                    key, value = line.split('=', 1)
                    if key in config and not os.environ.get(key):
                        config[key] = value

    return config


def bytes_to_hex(data: bytes) -> str:
    """Convert bytes to hex string"""
    return data.hex()


def main():
    """Main example function"""
    print("=== Accumulate Key Generation & Lite URL Derivation ===")

    # Load and display DevNet configuration
    config = load_env_config()
    print(f"\nDevNet Endpoints:")
    print(f"  V2 API: {config['ACC_RPC_URL_V2']}")
    print(f"  V3 API: {config['ACC_RPC_URL_V3']}")
    if config['ACC_FAUCET_ACCOUNT']:
        print(f"  Faucet: {config['ACC_FAUCET_ACCOUNT']}")
    print()

    # Generate new Ed25519 key pair
    print("Generating Ed25519 key pair...")
    private_key = ed25519.Ed25519PrivateKey.generate()
    public_key = private_key.public_key()

    # Get key bytes
    private_key_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption()
    )
    public_key_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )

    # Display keys
    print(f"Private Key: {bytes_to_hex(private_key_bytes)}")
    print(f"Public Key: {bytes_to_hex(public_key_bytes)}")

    # Derive Lite Identity URL using crypto helpers
    lid = derive_lite_identity_url(public_key_bytes)
    print(f"Lite Identity (LID): {lid}")

    # Derive Lite Token Account URL for ACME
    lta = derive_lite_token_account_url(public_key_bytes)
    print(f"Lite Token Account (LTA): {lta}")

    print("\nThese URLs can be used to:")
    print("- LID: Identity for signing transactions")
    print("- LTA: Receive ACME tokens from faucet or transfers")

    # Save keys for use in other examples
    keys_dir = "examples/.keys"
    os.makedirs(keys_dir, exist_ok=True)

    with open(f"{keys_dir}/ed25519_private.key", "wb") as f:
        f.write(private_key_bytes)

    with open(f"{keys_dir}/ed25519_public.key", "wb") as f:
        f.write(public_key_bytes)

    with open(f"{keys_dir}/urls.txt", "w") as f:
        f.write(f"LID={lid}\n")
        f.write(f"LTA={lta}\n")

    print(f"\nKeys saved to {keys_dir}/ for use in subsequent examples")


if __name__ == "__main__":
    main()