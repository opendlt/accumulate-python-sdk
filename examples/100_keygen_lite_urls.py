#!/usr/bin/env python3

"""Generate Ed25519 keypair and derive Lite Identity + Token Account URLs"""

import hashlib
import os
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization


def bytes_to_hex(data: bytes) -> str:
    """Convert bytes to hex string"""
    return data.hex()


def derive_lite_identity_url(public_key_bytes: bytes) -> str:
    """Derive Lite Identity URL from Ed25519 public key with checksum"""
    # For Ed25519: keyHash = SHA256(publicKey) - Go: protocol/protocol.go:290
    key_hash_full = hashlib.sha256(public_key_bytes).digest()

    # Use first 20 bytes - Go: protocol/protocol.go:274
    key_hash_20 = key_hash_full[:20]

    # Convert to hex string - Go: protocol/protocol.go:274
    key_str = key_hash_20.hex()

    # Calculate checksum - Go: protocol/protocol.go:275-276
    checksum_full = hashlib.sha256(key_str.encode('utf-8')).digest()
    checksum = checksum_full[28:].hex()  # Take last 4 bytes

    # Format: acc://<keyHash[0:20]><checksum> - Go: protocol/protocol.go:277
    return f"acc://{key_str}{checksum}"


def derive_lite_token_account_url(public_key_bytes: bytes, token="ACME") -> str:
    """Derive Lite Token Account URL for ACME"""
    # LTA = LID + "/ACME" path - Go: protocol/protocol.go:267-268
    lid = derive_lite_identity_url(public_key_bytes)
    return f"{lid}/{token}"


def main():
    """Main example function"""
    print("=== Accumulate Key Generation & Lite URL Derivation ===")

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

    # Derive Lite Identity URL
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