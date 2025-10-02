"""
Fuzz testing for transaction roundtrip consistency.

Tests transaction builders with randomized inputs to verify
serialization consistency and error handling robustness.
"""

import pytest
import os
import json
import random
import string
import secrets
from typing import Any, Dict, List
import sys
from pathlib import Path

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))
from helpers import mk_identity_url, mk_ed25519_keypair

from accumulate_client.tx.builders import BUILDER_REGISTRY, get_builder_for
from accumulate_client.tx.validation import ValidationError


# Get fuzz iteration count from environment
FUZZ_COUNT = int(os.environ.get('ACC_FUZZ_COUNT', '500'))

# Statistics tracking
fuzz_stats = {
    'total_iterations': 0,
    'validation_failures': 0,
    'successful_validations': 0,
    'serialization_failures': 0,
    'roundtrip_failures': 0,
    'roundtrip_successes': 0,
    'min_size': float('inf'),
    'max_size': 0,
    'total_size': 0,
    'tx_type_counts': {}
}


def random_string(min_len=1, max_len=50) -> str:
    """Generate random string."""
    length = random.randint(min_len, max_len)
    return ''.join(random.choices(string.ascii_letters + string.digits, k=length))


def random_bytes(min_len=1, max_len=1024) -> bytes:
    """Generate random bytes."""
    length = random.randint(min_len, max_len)
    return secrets.token_bytes(length)


def random_url() -> str:
    """Generate random Accumulate URL."""
    # Mix valid and potentially invalid URLs
    if random.random() < 0.8:  # 80% valid URLs
        identity = random_string(3, 20).lower()
        if random.random() < 0.5:
            return f"acc://{identity}.acme"
        else:
            subpath = random_string(3, 20).lower()
            return f"acc://{identity}.acme/{subpath}"
    else:  # 20% potentially invalid URLs
        return random_string(5, 30)


def random_amount() -> int:
    """Generate random amount (mix of valid and invalid)."""
    if random.random() < 0.7:  # 70% positive amounts
        return random.randint(1, 2**32)
    elif random.random() < 0.9:  # 20% zero
        return 0
    else:  # 10% negative
        return random.randint(-2**16, -1)


def random_hash() -> bytes:
    """Generate random hash bytes."""
    return secrets.token_bytes(32)  # 32-byte hashes


def random_key() -> bytes:
    """Generate random key bytes."""
    return secrets.token_bytes(32)  # 32-byte keys


def random_operation() -> str:
    """Generate random operation string."""
    operations = ['add', 'remove', 'update', 'create', 'delete', 'modify']
    return random.choice(operations)


def generate_random_field_value(field_name: str) -> Any:
    """Generate random value based on field name heuristics."""
    field_lower = field_name.lower()

    if 'url' in field_lower:
        return random_url()
    elif 'amount' in field_lower or 'balance' in field_lower or 'fee' in field_lower:
        return random_amount()
    elif 'data' in field_lower and field_name != 'metadata':
        return random_bytes()
    elif 'hash' in field_lower:
        return random_hash()
    elif 'key' in field_lower:
        return random_key()
    elif 'operation' in field_lower:
        return random_operation()
    elif 'precision' in field_lower:
        return random.randint(0, 18)
    elif 'symbol' in field_lower:
        return random_string(1, 10).upper()
    elif 'height' in field_lower:
        return random.randint(0, 1000000)
    elif 'threshold' in field_lower:
        return random.randint(1, 10)
    elif 'version' in field_lower:
        return f"{random.randint(1, 9)}.{random.randint(0, 9)}.{random.randint(0, 9)}"
    elif 'timestamp' in field_lower:
        return random.randint(0, 2**32)
    elif 'memo' in field_lower:
        return random_string(0, 100)
    elif 'scratch' in field_lower:
        return random.choice([True, False])
    elif field_name in ('to', 'recipient', 'origin', 'source', 'target', 'authority'):
        return random_url()
    elif field_name in ('keys', 'operations', 'authorities'):
        # Generate random lists
        length = random.randint(0, 5)
        if 'keys' in field_name:
            return [random_key() for _ in range(length)]
        elif 'operations' in field_name:
            return [random_operation() for _ in range(length)]
        else:
            return [random_url() for _ in range(length)]
    elif field_name in ('oracle',):
        return random.uniform(0.001, 1.0)
    else:
        # Default random values based on probability
        rand = random.random()
        if rand < 0.3:
            return random_string()
        elif rand < 0.5:
            return random_amount()
        elif rand < 0.7:
            return random_bytes()
        elif rand < 0.9:
            return random.choice([True, False])
        else:
            return None


def randomize_transaction_fields(tx_type: str, builder) -> Dict[str, Any]:
    """Randomize transaction fields for the given type."""
    # Define potential fields for each transaction type
    common_fields = ['url', 'amount', 'data', 'memo', 'timestamp']

    type_specific_fields = {
        'CreateIdentity': ['url', 'keyBookUrl', 'keyPageUrl'],
        'CreateKeyBook': ['url', 'publicKeyHash', 'authorities'],
        'CreateKeyPage': ['keys'],
        'UpdateKeyPage': ['operation', 'key', 'newKey'],
        'UpdateKey': ['newKeyHash', 'priority'],
        'CreateToken': ['url', 'symbol', 'precision', 'properties', 'supplyLimit'],
        'CreateTokenAccount': ['url', 'tokenUrl', 'keyBookUrl', 'scratch'],
        'CreateLiteTokenAccount': [],
        'SendTokens': ['to', 'amount', 'meta', 'hash'],
        'IssueTokens': ['recipient', 'amount'],
        'BurnTokens': ['amount'],
        'CreateDataAccount': ['url', 'keyBookUrl', 'scratch'],
        'WriteData': ['data', 'scratch', 'entryHash', 'writeToState'],
        'WriteDataTo': ['recipient', 'data', 'scratch', 'entryHash', 'writeToState'],
        'AddCredits': ['recipient', 'amount', 'oracle'],
        'BurnCredits': ['amount'],
        'TransferCredits': ['to', 'amount'],
        'UpdateAccountAuth': ['authority', 'operations'],
        'LockAccount': ['height'],
        'AcmeFaucet': ['url'],
        'NetworkMaintenance': ['operation', 'target'],
        'SystemGenesis': ['networkName', 'version', 'globals'],
        'SystemWriteData': ['data', 'writeToState'],
        'DirectoryAnchor': ['source', 'rootChainAnchor', 'stateTreeAnchor'],
        'BlockValidatorAnchor': ['source', 'rootChainAnchor', 'stateTreeAnchor', 'minorBlocks'],
        'SyntheticCreateIdentity': ['url', 'cause'],
        'SyntheticWriteData': ['data', 'cause'],
        'SyntheticDepositTokens': ['token', 'amount', 'cause'],
        'SyntheticDepositCredits': ['amount', 'cause'],
        'SyntheticBurnTokens': ['amount', 'cause'],
        'SyntheticForwardTransaction': ['envelope', 'cause'],
        'RemoteTransaction': ['hash']
    }

    # Get fields for this transaction type
    fields_to_randomize = type_specific_fields.get(tx_type, common_fields)

    # Add some random extra fields
    extra_fields = [f'randomField{i}' for i in range(random.randint(0, 3))]
    fields_to_randomize.extend(extra_fields)

    # Randomize each field
    randomized_fields = {}
    for field_name in fields_to_randomize:
        if random.random() < 0.7:  # 70% chance to include each field
            try:
                value = generate_random_field_value(field_name)
                builder.with_field(field_name, value)
                randomized_fields[field_name] = value
            except Exception:
                # Skip fields that cause immediate errors during setting
                pass

    return randomized_fields


@pytest.mark.fuzz
@pytest.mark.parametrize("iteration", range(FUZZ_COUNT))
def test_transaction_roundtrip_fuzz(iteration):
    """Fuzz test transaction roundtrip consistency."""
    global fuzz_stats

    fuzz_stats['total_iterations'] += 1

    # Choose random transaction type
    tx_type = random.choice(list(BUILDER_REGISTRY.keys()))
    fuzz_stats['tx_type_counts'][tx_type] = fuzz_stats['tx_type_counts'].get(tx_type, 0) + 1

    try:
        # Create builder and randomize fields
        builder = get_builder_for(tx_type)
        randomized_fields = randomize_transaction_fields(tx_type, builder)

        # Test validation
        is_valid = False
        try:
            builder.validate()
            is_valid = True
            fuzz_stats['successful_validations'] += 1
        except ValidationError:
            # Expected for many random inputs
            fuzz_stats['validation_failures'] += 1
        except Exception as e:
            # Unexpected validation errors
            fuzz_stats['validation_failures'] += 1
            print(f"Unexpected validation error for {tx_type}: {e}")

        # For valid bodies, test serialization roundtrip
        if is_valid:
            try:
                # Test canonical JSON serialization
                canonical_json = builder.to_canonical_json()
                assert canonical_json is not None
                assert len(canonical_json) > 0

                # Test binary serialization
                binary_data = builder.to_binary()
                assert binary_data is not None
                assert len(binary_data) > 0

                # Track sizes
                json_size = len(canonical_json)
                binary_size = len(binary_data)
                total_size = json_size + binary_size

                fuzz_stats['min_size'] = min(fuzz_stats['min_size'], total_size)
                fuzz_stats['max_size'] = max(fuzz_stats['max_size'], total_size)
                fuzz_stats['total_size'] += total_size

                # Test roundtrip consistency
                try:
                    body1 = builder.to_body()
                    builder2 = builder.from_model(body1)

                    canonical_json2 = builder2.to_canonical_json()
                    binary_data2 = builder2.to_binary()

                    # Roundtrip should be consistent
                    if canonical_json == canonical_json2 and binary_data == binary_data2:
                        fuzz_stats['roundtrip_successes'] += 1
                    else:
                        fuzz_stats['roundtrip_failures'] += 1
                        print(f"Roundtrip inconsistency for {tx_type}")

                except Exception as e:
                    fuzz_stats['roundtrip_failures'] += 1
                    print(f"Roundtrip failed for {tx_type}: {e}")

            except Exception as e:
                fuzz_stats['serialization_failures'] += 1
                print(f"Serialization failed for {tx_type}: {e}")

    except Exception as e:
        print(f"Unexpected error fuzzing {tx_type}: {e}")


def test_fuzz_statistics():
    """Print fuzz testing statistics after all iterations."""
    # This test runs after all fuzz iterations
    if fuzz_stats['total_iterations'] == 0:
        pytest.skip("No fuzz iterations completed")

    print("\n" + "="*60)
    print("FUZZ TESTING STATISTICS")
    print("="*60)

    total = fuzz_stats['total_iterations']
    print(f"Total iterations: {total}")

    # Validation statistics
    valid_pct = (fuzz_stats['successful_validations'] / total) * 100 if total > 0 else 0
    invalid_pct = (fuzz_stats['validation_failures'] / total) * 100 if total > 0 else 0
    print(f"Validation: {fuzz_stats['successful_validations']} valid ({valid_pct:.1f}%), "
          f"{fuzz_stats['validation_failures']} invalid ({invalid_pct:.1f}%)")

    # Serialization statistics
    if fuzz_stats['successful_validations'] > 0:
        ser_failure_pct = (fuzz_stats['serialization_failures'] / fuzz_stats['successful_validations']) * 100
        print(f"Serialization failures: {fuzz_stats['serialization_failures']} ({ser_failure_pct:.1f}% of valid)")

    # Roundtrip statistics
    total_roundtrip = fuzz_stats['roundtrip_successes'] + fuzz_stats['roundtrip_failures']
    if total_roundtrip > 0:
        roundtrip_success_pct = (fuzz_stats['roundtrip_successes'] / total_roundtrip) * 100
        print(f"Roundtrip: {fuzz_stats['roundtrip_successes']} successes ({roundtrip_success_pct:.1f}%), "
              f"{fuzz_stats['roundtrip_failures']} failures")

    # Size statistics
    if fuzz_stats['total_size'] > 0 and fuzz_stats['successful_validations'] > 0:
        avg_size = fuzz_stats['total_size'] / fuzz_stats['successful_validations']
        print(f"Sizes: min={fuzz_stats['min_size']} bytes, "
              f"avg={avg_size:.0f} bytes, "
              f"max={fuzz_stats['max_size']} bytes")

    # Transaction type distribution
    print(f"\nTransaction type distribution (top 10):")
    sorted_types = sorted(fuzz_stats['tx_type_counts'].items(), key=lambda x: x[1], reverse=True)
    for tx_type, count in sorted_types[:10]:
        pct = (count / total) * 100
        print(f"  {tx_type}: {count} ({pct:.1f}%)")

    # Save statistics to file for reporting
    stats_file = "tests/fuzz/_stats.json"
    os.makedirs(os.path.dirname(stats_file), exist_ok=True)
    with open(stats_file, 'w') as f:
        json.dump(fuzz_stats, f, indent=2)

    # Assertions for test quality
    assert total >= FUZZ_COUNT, f"Expected {FUZZ_COUNT} iterations, got {total}"

    # At least some validations should succeed (even with random data)
    if total >= 100:  # Only check for reasonable sample sizes
        assert fuzz_stats['successful_validations'] > 0, "No successful validations in fuzz test"

    # Roundtrip consistency should be very high for valid transactions
    if fuzz_stats['roundtrip_successes'] + fuzz_stats['roundtrip_failures'] > 10:
        roundtrip_rate = fuzz_stats['roundtrip_successes'] / (fuzz_stats['roundtrip_successes'] + fuzz_stats['roundtrip_failures'])
        assert roundtrip_rate >= 0.95, f"Roundtrip success rate too low: {roundtrip_rate:.2f}"


def test_fuzz_edge_cases():
    """Test specific edge cases discovered during fuzzing."""
    edge_cases = [
        # Empty strings
        {'url': ''},
        {'data': b''},

        # Very long strings
        {'url': 'acc://' + 'x' * 1000 + '.acme'},
        {'data': b'x' * 10000},

        # Special characters
        {'url': 'acc://test!@#$%.acme'},
        {'memo': 'test\n\r\t\0memo'},

        # Boundary values
        {'amount': 0},
        {'amount': 2**63 - 1},
        {'amount': -1},

        # None values
        {'url': None},
        {'amount': None},
    ]

    for i, edge_fields in enumerate(edge_cases):
        try:
            builder = get_builder_for('SendTokens')  # Use common transaction type

            for field_name, field_value in edge_fields.items():
                builder.with_field(field_name, field_value)

            # Should handle gracefully (either validate or fail cleanly)
            try:
                builder.validate()
                # If validation passes, serialization should work
                canonical_json = builder.to_canonical_json()
                binary_data = builder.to_binary()
                assert len(canonical_json) > 0
                assert len(binary_data) > 0
            except ValidationError:
                # Expected for edge cases
                pass

        except Exception as e:
            pytest.fail(f"Edge case {i} caused unexpected error: {e}")


# TODO[ACC-P2-S949]: Add fuzz testing for signature generation and verification
# TODO[ACC-P2-S950]: Add fuzz testing for client API parameter combinations
# TODO[ACC-P2-S951]: Add fuzz testing for transaction envelope construction
# TODO[ACC-P2-S952]: Add fuzz testing for error handling and recovery paths
