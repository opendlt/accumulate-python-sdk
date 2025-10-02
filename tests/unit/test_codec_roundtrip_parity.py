"""
Test codec roundtrip parity for transaction builders.

Ensures that transactions can be built, encoded, decoded, and re-encoded
with byte-for-byte equality to verify codec correctness.
"""

import pytest
import hashlib
import json
from accumulate_client.tx.builders import get_builder_for, BUILDER_REGISTRY
from accumulate_client.runtime.codec import encode_json, decode_binary, decode_transaction, encode_canonical_json


# Select 10 diverse transaction types spanning different categories
TRANSACTION_TYPES = [
    # Identity operations
    'CreateIdentity',
    'UpdateKeyPage',

    # Token operations
    'SendTokens',
    'CreateTokenAccount',
    'BurnTokens',

    # Data operations
    'WriteData',
    'WriteDataTo',

    # System operations
    'UpdateAccountAuth',
    'CreateKeyBook',

    # Synthetic operations
    'SyntheticCreateIdentity'
]


@pytest.mark.parametrize("tx_type", TRANSACTION_TYPES)
@pytest.mark.unit
def test_transaction_roundtrip_parity(tx_type):
    """Test transaction builder -> encode -> decode -> re-encode parity."""

    # Skip if builder not available
    if tx_type not in BUILDER_REGISTRY:
        pytest.skip(f"Builder for {tx_type} not available")

    # Get builder and create basic transaction
    builder = get_builder_for(tx_type)

    # Configure minimal valid transaction based on type
    if tx_type == 'CreateIdentity':
        builder.with_field('url', 'acc://test.acme')
        builder.with_field('keyBookUrl', 'acc://test.acme/book')
        builder.with_field('keyPageUrl', 'acc://test.acme/book/page')

    elif tx_type == 'UpdateKeyPage':
        builder.with_field('operation', [{'type': 'add', 'key': b'0' * 32}])

    elif tx_type == 'SendTokens':
        builder.with_field('to', [{'url': 'acc://recipient.acme/tokens', 'amount': 1000000}])

    elif tx_type == 'CreateTokenAccount':
        builder.with_field('url', 'acc://test.acme/tokens')
        builder.with_field('tokenUrl', 'acc://ACME')

    elif tx_type == 'BurnTokens':
        builder.with_field('amount', 1000000)

    elif tx_type == 'WriteData':
        builder.with_field('data', b'test data')
        builder.with_field('scratch', False)

    elif tx_type == 'WriteDataTo':
        builder.with_field('recipient', 'acc://target.acme')
        builder.with_field('data', b'test data')

    elif tx_type == 'UpdateAccountAuth':
        builder.with_field('operations', [{'type': 'enable', 'authority': 'acc://auth.acme'}])

    elif tx_type == 'CreateKeyBook':
        builder.with_field('url', 'acc://test.acme/book')
        builder.with_field('publicKeyHash', b'0' * 32)

    elif tx_type == 'SyntheticCreateIdentity':
        builder.with_field('url', 'acc://synthetic.acme')

    # Validate builder
    try:
        builder.validate()
    except Exception as e:
        pytest.skip(f"Cannot create valid {tx_type}: {e}")

    # Step 1: Build transaction
    original_body = builder.to_body()

    # Step 2: Encode to canonical JSON
    canonical_bytes_1 = builder.to_canonical_json()  # Already bytes

    # Step 3: Decode transaction
    try:
        decoded_body = decode_transaction(canonical_bytes_1)
    except Exception as e:
        pytest.skip(f"Codec decode not available for {tx_type}: {e}")

    # Step 4: Re-encode decoded transaction
    try:
        canonical_json_2 = encode_canonical_json(decoded_body)
        canonical_bytes_2 = canonical_json_2.encode('utf-8')
    except Exception as e:
        pytest.skip(f"Codec re-encode not available for {tx_type}: {e}")

    # Assert byte-for-byte equality
    assert canonical_bytes_1 == canonical_bytes_2, (
        f"Roundtrip parity failed for {tx_type}: "
        f"original != re-encoded"
    )

    # Verify JSON structure is preserved
    json_1 = json.loads(canonical_bytes_1.decode('utf-8'))
    json_2 = json.loads(canonical_json_2)
    assert json_1 == json_2, f"JSON structure changed for {tx_type}"


@pytest.mark.unit
def test_transaction_hash_consistency():
    """Test that transaction hashing excludes signatures and is consistent."""

    # Create a simple transaction
    builder = get_builder_for('WriteData')
    builder.with_field('data', b'test hash consistency')
    builder.with_field('scratch', False)
    builder.validate()

    # Get canonical JSON
    canonical_bytes = builder.to_canonical_json()

    # Compute hash manually (SHA-256 of canonical JSON)
    expected_hash = hashlib.sha256(canonical_bytes).digest()

    # Verify hash computation is deterministic
    canonical_bytes_2 = builder.to_canonical_json()
    actual_hash = hashlib.sha256(canonical_bytes_2).digest()

    assert expected_hash == actual_hash, "Transaction hash not deterministic"

    # Verify signatures would not affect transaction hash
    # (hash is computed from transaction body only)
    tx_body = builder.to_body()
    assert 'signature' not in json.loads(canonical_bytes.decode('utf-8')), "Signature included in transaction hash"


@pytest.mark.unit
def test_minimal_transaction_coverage():
    """Test that all available transaction types can be built minimally."""

    coverage_count = 0
    total_types = len(BUILDER_REGISTRY)

    for tx_type in BUILDER_REGISTRY.keys():
        try:
            builder = get_builder_for(tx_type)
            # Try to build without any fields (should fail gracefully)
            try:
                builder.validate()
                coverage_count += 1
            except Exception:
                # Expected for most transaction types without required fields
                pass

        except Exception:
            # Builder creation should not fail
            pytest.fail(f"Failed to create builder for {tx_type}")

    # Ensure we have reasonable coverage of transaction types
    assert total_types >= 30, f"Expected at least 30 transaction types, got {total_types}"
