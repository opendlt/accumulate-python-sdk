#!/usr/bin/env python3
"""
Basic Usage Example for Accumulate Python SDK

This example demonstrates how to use the enhanced Accumulate Python SDK
to interact with the Accumulate network.
"""

import asyncio
from accumulate_client import (
    AccumulateClient, mainnet_client, testnet_client, local_client,
    AccountUrl, hash_sha256_hex, encode_json
)


def demonstrate_url_handling():
    """Demonstrate URL parsing and manipulation."""
    print("=== URL Handling ===")

    # Create URLs
    identity_url = AccountUrl("acc://example.acme")
    token_url = identity_url.join("tokens")
    data_url = identity_url.join("data")

    print(f"Identity URL: {identity_url}")
    print(f"Token URL: {token_url}")
    print(f"Data URL: {data_url}")
    print(f"Identity: {identity_url.identity}")
    print(f"Path: {token_url.path}")
    print(f"Is lite: {identity_url.is_lite}")
    print(f"Account type hint: {token_url.account_type_hint()}")
    print()


def demonstrate_encoding():
    """Demonstrate encoding and hashing."""
    print("=== Encoding & Hashing ===")

    # Create some test data
    test_data = {
        "type": "createIdentity",
        "url": "acc://example.acme",
        "publicKey": "abcd1234" * 8,  # 64 hex chars
        "timestamp": 1234567890
    }

    # JSON encoding
    json_str = encode_json(test_data)
    print(f"Canonical JSON: {json_str}")

    # Hashing
    data_hash = hash_sha256_hex(json_str)
    print(f"SHA-256 hash: {data_hash}")
    print()


def demonstrate_client_creation():
    """Demonstrate client creation and configuration."""
    print("=== Client Creation ===")

    # Create clients for different networks
    mainnet = mainnet_client(debug=True)
    testnet = testnet_client(timeout=60.0)
    local = local_client()

    print(f"Mainnet client: {mainnet.config.endpoint}")
    print(f"Testnet client: {testnet.config.endpoint}")
    print(f"Local client: {local.config.endpoint}")

    # Custom client
    custom_client = AccumulateClient("https://custom.accumulate.io")
    print(f"Custom client: {custom_client.config.endpoint}")
    print()


async def demonstrate_api_calls():
    """Demonstrate API calls (requires network access)."""
    print("=== API Calls (Network Required) ===")

    # Use testnet for demonstration
    client = testnet_client(timeout=10.0)

    try:
        # Get node status
        print("Fetching node status...")
        status = await asyncio.to_thread(client.status)
        print(f"Status response type: {type(status)}")

        # Get network description
        print("Fetching network description...")
        description = await asyncio.to_thread(client.describe)
        print(f"Description response type: {type(description)}")

        print("API calls successful!")

    except Exception as e:
        print(f"API calls failed (this is expected without network): {e}")

    print()


def demonstrate_error_handling():
    """Demonstrate error handling."""
    print("=== Error Handling ===")

    from accumulate_client.runtime.errors import (
        AccumulateError, ValidationError, NetworkError
    )

    # Create some test errors
    try:
        raise ValidationError("Invalid transaction", details={"field": "signature"})
    except ValidationError as e:
        print(f"Caught validation error: {e}")
        print(f"Error code: {e.code}")
        print(f"Error details: {e.details}")

    print()


async def main():
    """Run all demonstrations."""
    print("Accumulate Python SDK - Basic Usage Examples")
    print("=" * 50)
    print()

    demonstrate_url_handling()
    demonstrate_encoding()
    demonstrate_client_creation()
    await demonstrate_api_calls()
    demonstrate_error_handling()

    print("Examples completed!")


if __name__ == "__main__":
    asyncio.run(main())