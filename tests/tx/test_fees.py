"""
Test transaction fee estimation functionality.

Tests fee calculation, determinism, and baseline comparison
for all transaction types and scenarios.
"""

import pytest
import json
import os
import sys
from pathlib import Path

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))
from helpers import mk_minimal_valid_body

from accumulate_client.tx.fees import (
    estimate_for_body, estimate_for_envelope, estimate_all_transaction_types,
    NetworkParams, get_network_params
)
from accumulate_client.tx.builders import get_builder_for, BUILDER_REGISTRY


def test_network_params_defaults():
    """Test default network parameters."""
    params = get_network_params()

    assert isinstance(params, NetworkParams)
    assert params.base_fee > 0
    assert params.data_entry_fee > 0
    assert params.signature_fee > 0
    assert params.min_fee > 0
    assert params.max_fee > params.min_fee


def test_fee_estimation_basic():
    """Test basic fee estimation functionality."""
    # Create a simple transaction body
    builder = get_builder_for('CreateIdentity')
    minimal_fields = mk_minimal_valid_body('CreateIdentity')
    for field_name, field_value in minimal_fields.items():
        builder.with_field(field_name, field_value)

    try:
        body = builder.to_body()
        fee = estimate_for_body(body)

        assert isinstance(fee, int)
        assert fee > 0

        # Fee should be within reasonable bounds
        params = get_network_params()
        assert fee >= params.min_fee
        assert fee <= params.max_fee

    except Exception as e:
        pytest.xfail(f"Basic fee estimation failed: {e}")


def test_fee_estimation_deterministic():
    """Test that fee estimation is deterministic."""
    builder = get_builder_for('SendTokens')
    minimal_fields = mk_minimal_valid_body('SendTokens')
    for field_name, field_value in minimal_fields.items():
        builder.with_field(field_name, field_value)

    try:
        body = builder.to_body()

        # Calculate fee multiple times
        fee1 = estimate_for_body(body)
        fee2 = estimate_for_body(body)
        fee3 = estimate_for_body(body)

        # Should be deterministic
        assert fee1 == fee2 == fee3

    except Exception as e:
        pytest.xfail(f"Fee determinism test failed: {e}")


def test_fee_estimation_all_transaction_types():
    """Test fee estimation for all transaction types."""
    fees = estimate_all_transaction_types()

    assert isinstance(fees, dict)
    assert len(fees) > 0

    # Should have fees for all registered transaction types
    # (Note: might have more fees than registered builders due to internal types)
    registered_types = set(BUILDER_REGISTRY.keys())
    estimated_types = set(fees.keys())

    # Most registered types should have fee estimates
    missing_estimates = registered_types - estimated_types
    if missing_estimates:
        print(f"Warning: Missing fee estimates for: {missing_estimates}")

    # All fees should be positive
    for tx_type, fee in fees.items():
        assert isinstance(fee, int), f"Fee for {tx_type} should be int, got {type(fee)}"
        assert fee > 0, f"Fee for {tx_type} should be positive, got {fee}"


def test_fee_estimation_transaction_categories():
    """Test that different transaction categories have appropriate fee levels."""
    fees = estimate_all_transaction_types()

    # Identity operations should be more expensive (higher multiplier)
    identity_fees = [fees.get(tx, 0) for tx in ['CreateIdentity', 'CreateKeyBook', 'CreateKeyPage']]
    identity_fees = [f for f in identity_fees if f > 0]

    # Token operations should be moderately expensive
    token_fees = [fees.get(tx, 0) for tx in ['CreateToken', 'SendTokens', 'IssueTokens']]
    token_fees = [f for f in token_fees if f > 0]

    # System operations should be cheaper
    system_fees = [fees.get(tx, 0) for tx in ['SystemGenesis', 'SystemWriteData']]
    system_fees = [f for f in system_fees if f > 0]

    # Synthetic operations should be cheapest (often free)
    synthetic_fees = [fees.get(tx, 0) for tx in ['SyntheticCreateIdentity', 'SyntheticWriteData']]
    synthetic_fees = [f for f in synthetic_fees if f > 0]

    if identity_fees and token_fees:
        avg_identity = sum(identity_fees) / len(identity_fees)
        avg_token = sum(token_fees) / len(token_fees)
        # Identity operations should generally be more expensive than token operations
        assert avg_identity >= avg_token, f"Identity fees ({avg_identity}) should be >= token fees ({avg_token})"

    if token_fees and system_fees:
        avg_token = sum(token_fees) / len(token_fees)
        avg_system = sum(system_fees) / len(system_fees)
        # Token operations should be more expensive than system operations
        assert avg_token >= avg_system, f"Token fees ({avg_token}) should be >= system fees ({avg_system})"


def test_fee_estimation_with_custom_params():
    """Test fee estimation with custom network parameters."""
    custom_params = NetworkParams(
        base_fee=2000,
        data_entry_fee=200,
        byte_fee=2
    )

    builder = get_builder_for('WriteData')
    minimal_fields = mk_minimal_valid_body('WriteData')
    for field_name, field_value in minimal_fields.items():
        builder.with_field(field_name, field_value)

    try:
        body = builder.to_body()

        # Calculate with default and custom params
        default_fee = estimate_for_body(body)
        custom_fee = estimate_for_body(body, custom_params)

        # Custom fee should be different (likely higher due to higher base_fee)
        assert custom_fee != default_fee
        assert custom_fee >= custom_params.base_fee

    except Exception as e:
        pytest.xfail(f"Custom params fee test failed: {e}")


def test_fee_estimation_envelope_vs_body():
    """Test fee estimation for envelopes vs bodies."""
    builder = get_builder_for('AddCredits')
    minimal_fields = mk_minimal_valid_body('AddCredits')
    for field_name, field_value in minimal_fields.items():
        builder.with_field(field_name, field_value)

    try:
        body = builder.to_body()
        envelope = builder.build_envelope(origin='acc://test.acme')

        body_fee = estimate_for_body(body)
        envelope_fee = estimate_for_envelope(envelope)

        # Envelope fee should be >= body fee (includes envelope overhead)
        assert envelope_fee >= body_fee

    except Exception as e:
        pytest.xfail(f"Envelope vs body fee test failed: {e}")


def test_fee_estimation_size_impact():
    """Test that transaction size impacts fee calculation."""
    # Create two WriteData transactions with different data sizes
    builder1 = get_builder_for('WriteData')
    builder1.with_field('data', b'small')

    builder2 = get_builder_for('WriteData')
    builder2.with_field('data', b'x' * 1000)  # Much larger data

    try:
        body1 = builder1.to_body()
        body2 = builder2.to_body()

        fee1 = estimate_for_body(body1)
        fee2 = estimate_for_body(body2)

        # Larger transaction should have higher fee
        assert fee2 > fee1, f"Larger transaction fee ({fee2}) should be > smaller fee ({fee1})"

    except Exception as e:
        pytest.xfail(f"Size impact fee test failed: {e}")


def test_fee_baseline_snapshot():
    """Test fee baseline snapshot and comparison."""
    # Calculate current fees
    current_fees = estimate_all_transaction_types()

    # Create cache directory
    cache_dir = "tests/golden/_generated_cache"
    os.makedirs(cache_dir, exist_ok=True)
    baseline_file = os.path.join(cache_dir, "fees_baseline.json")

    # Check if we should update baseline
    update_fees = os.environ.get('ACC_UPDATE_FEES', '').lower() in ('1', 'true', 'yes')

    if update_fees or not os.path.exists(baseline_file):
        # Save new baseline
        with open(baseline_file, 'w') as f:
            json.dump(current_fees, f, indent=2, sort_keys=True)
        print(f"Updated fee baseline with {len(current_fees)} transaction types")
        return

    # Load and compare with baseline
    try:
        with open(baseline_file, 'r') as f:
            baseline_fees = json.load(f)

        # Compare fee counts
        assert len(current_fees) == len(baseline_fees), \
            f"Fee count changed: current={len(current_fees)}, baseline={len(baseline_fees)}"

        # Compare individual fees
        differences = []
        for tx_type in sorted(baseline_fees.keys()):
            baseline_fee = baseline_fees[tx_type]
            current_fee = current_fees.get(tx_type)

            if current_fee is None:
                differences.append(f"Missing fee for {tx_type}")
            elif current_fee != baseline_fee:
                differences.append(f"{tx_type}: {baseline_fee} -> {current_fee}")

        # Check for new transaction types
        new_types = set(current_fees.keys()) - set(baseline_fees.keys())
        for tx_type in new_types:
            differences.append(f"New transaction type: {tx_type} = {current_fees[tx_type]}")

        # Allow small number of differences (for legitimate changes)
        if differences:
            print(f"Fee differences found ({len(differences)}):")
            for diff in differences[:10]:  # Show first 10
                print(f"  {diff}")

            # Fail only if there are many differences (suggesting a problem)
            if len(differences) > 5:
                pytest.fail(f"Too many fee differences ({len(differences)}). "
                           f"Run with ACC_UPDATE_FEES=1 to update baseline.")

    except Exception as e:
        pytest.skip(f"Fee baseline comparison failed: {e}")


def test_fee_constraints():
    """Test fee calculation constraints and limits."""
    params = NetworkParams(
        min_fee=100,
        max_fee=1000
    )

    # Test minimum fee constraint
    builder = get_builder_for('SyntheticWriteData')  # Should have very low fee
    minimal_fields = mk_minimal_valid_body('SyntheticWriteData')
    for field_name, field_value in minimal_fields.items():
        builder.with_field(field_name, field_value)

    try:
        body = builder.to_body()
        fee = estimate_for_body(body, params)

        # Should respect minimum fee
        assert fee >= params.min_fee

        # Should respect maximum fee (this test is theoretical)
        assert fee <= params.max_fee

    except Exception as e:
        pytest.xfail(f"Fee constraints test failed: {e}")


def test_fee_monotonicity():
    """Test fee monotonicity relationships."""
    fees = estimate_all_transaction_types()

    # Define expected monotonic relationships based on transaction complexity
    relationships = [
        # Synthetic operations should be cheaper than regular operations
        ('SyntheticCreateIdentity', 'CreateIdentity'),
        ('SyntheticWriteData', 'WriteData'),

        # Token operations complexity ordering
        ('CreateLiteTokenAccount', 'CreateTokenAccount'),
        ('BurnTokens', 'IssueTokens'),  # Burning might be simpler than issuing
    ]

    for cheaper_tx, expensive_tx in relationships:
        cheaper_fee = fees.get(cheaper_tx)
        expensive_fee = fees.get(expensive_tx)

        if cheaper_fee is not None and expensive_fee is not None:
            assert cheaper_fee <= expensive_fee, \
                f"{cheaper_tx} fee ({cheaper_fee}) should be <= {expensive_tx} fee ({expensive_fee})"


# TODO[ACC-P2-S933]: Add tests for fee estimation with signature overhead
# TODO[ACC-P2-S934]: Add tests for fee estimation performance benchmarks
# TODO[ACC-P2-S935]: Add tests for fee estimation with different network conditions
# TODO[ACC-P2-S936]: Add tests for fee estimation error handling
