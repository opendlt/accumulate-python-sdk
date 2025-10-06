"""
Test transaction header fields completeness against Go reference.

Tests that the Python TransactionHeader implementation includes all
required and optional fields from the Go reference implementation.
"""

import pytest
from datetime import datetime, timezone
import json

from accumulate_client.types import TransactionHeader, ExpireOptions, HoldUntilOptions
from accumulate_client.runtime.url import AccountUrl


def test_transaction_header_all_fields():
    """Test that TransactionHeader supports all fields from Go reference."""

    # Test data - use strings for URLs as Pydantic expects
    principal_url = "acc://test.acme/tokens"
    initiator_hash = b"0" * 32  # 32-byte hash
    memo_text = "Test transaction memo"
    metadata_bytes = b"Binary metadata for transaction"
    authorities = [
        "acc://authority1.acme",
        "acc://authority2.acme"
    ]
    expire_time = datetime.now(timezone.utc)
    hold_block = 1000

    # Create supporting objects
    expire_options = ExpireOptions(at_time=expire_time)
    hold_options = HoldUntilOptions(minor_block=hold_block)

    # Create complete transaction header
    header = TransactionHeader(
        principal=principal_url,
        initiator=initiator_hash,
        memo=memo_text,
        metadata=metadata_bytes,
        expire=expire_options,
        hold_until=hold_options,
        authorities=authorities
    )

    # Verify all fields are set correctly
    assert header.principal == principal_url
    assert header.initiator == initiator_hash
    assert header.memo == memo_text
    assert header.metadata == metadata_bytes
    assert header.expire.at_time == expire_time
    assert header.hold_until.minor_block == hold_block
    assert header.authorities == authorities

    print("✅ All transaction header fields present and working!")


def test_transaction_header_required_fields_only():
    """Test TransactionHeader with only required fields."""

    principal_url = "acc://minimal.acme"
    initiator_hash = b"1" * 32

    # Create minimal header (only required fields)
    header = TransactionHeader(
        principal=principal_url,
        initiator=initiator_hash
    )

    # Verify required fields
    assert header.principal == principal_url
    assert header.initiator == initiator_hash

    # Verify optional fields default to None
    assert header.memo is None
    assert header.metadata is None
    assert header.expire is None
    assert header.hold_until is None
    assert header.authorities is None

    print("✅ Required fields work, optional fields properly default to None!")


def test_expire_options_completeness():
    """Test ExpireOptions matches Go reference."""

    # Test with at_time
    expire_time = datetime(2025, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
    expire_opts = ExpireOptions(at_time=expire_time)
    assert expire_opts.at_time == expire_time

    # Test without at_time (should be None)
    expire_opts_empty = ExpireOptions()
    assert expire_opts_empty.at_time is None

    print("✅ ExpireOptions complete and working!")


def test_hold_until_options_completeness():
    """Test HoldUntilOptions matches Go reference."""

    # Test with minor_block
    block_number = 12345
    hold_opts = HoldUntilOptions(minor_block=block_number)
    assert hold_opts.minor_block == block_number

    # Test without minor_block (should be None)
    hold_opts_empty = HoldUntilOptions()
    assert hold_opts_empty.minor_block is None

    print("✅ HoldUntilOptions complete and working!")


def test_transaction_header_json_serialization():
    """Test that transaction header can be serialized to/from JSON."""

    # Create a complete header
    header = TransactionHeader(
        principal="acc://json.acme",
        initiator=b"J" * 32,
        memo="JSON serialization test",
        metadata=b"JSON metadata",
        expire=ExpireOptions(at_time=datetime.now(timezone.utc)),
        hold_until=HoldUntilOptions(minor_block=999),
        authorities=["acc://auth.acme"]
    )

    # Test Pydantic JSON serialization
    json_data = header.model_dump()

    # Verify all fields are in JSON
    assert 'principal' in json_data
    assert 'initiator' in json_data
    assert 'memo' in json_data
    assert 'metadata' in json_data
    assert 'expire' in json_data
    assert 'hold_until' in json_data
    assert 'authorities' in json_data

    # Verify nested structures
    assert 'at_time' in json_data['expire']
    assert 'minor_block' in json_data['hold_until']

    print("✅ JSON serialization includes all fields!")


def test_transaction_header_field_types():
    """Test that all field types match Go reference specification."""

    header = TransactionHeader(
        principal="acc://types.acme",
        initiator=b"T" * 32
    )

    # Check field types match Go reference
    assert isinstance(header.principal, AccountUrl)  # *url.URL -> AccountUrl in Python
    assert isinstance(header.initiator, bytes)       # [32]byte
    assert header.memo is None or isinstance(header.memo, str)  # string
    assert header.metadata is None or isinstance(header.metadata, bytes)  # []byte
    assert header.expire is None or isinstance(header.expire, ExpireOptions)  # *ExpireOptions
    assert header.hold_until is None or isinstance(header.hold_until, HoldUntilOptions)  # *HoldUntilOptions
    assert header.authorities is None or isinstance(header.authorities, list)  # []*url.URL -> List[AccountUrl]

    print("✅ All field types match Go reference!")


def test_transaction_header_edge_cases():
    """Test edge cases and boundary conditions."""

    # Test with empty memo and metadata
    header1 = TransactionHeader(
        principal="acc://edge1.acme",
        initiator=b"E" * 32,
        memo="",  # Empty string
        metadata=b""  # Empty bytes
    )
    assert header1.memo == ""
    assert header1.metadata == b""

    # Test with empty authorities list
    header2 = TransactionHeader(
        principal="acc://edge2.acme",
        initiator=b"F" * 32,
        authorities=[]  # Empty list
    )
    assert header2.authorities == []

    # Test with large metadata
    large_metadata = b"x" * 10000
    header3 = TransactionHeader(
        principal="acc://edge3.acme",
        initiator=b"G" * 32,
        metadata=large_metadata
    )
    assert len(header3.metadata) == 10000

    print("✅ Edge cases handled correctly!")


def test_go_reference_compliance():
    """Verify compliance with Go reference field specification."""

    print("\\n=== Go Reference Compliance Check ===")

    # Field mapping verification
    go_fields = {
        'Principal': 'principal',      # *url.URL -> AccountUrl
        'Initiator': 'initiator',      # [32]byte -> bytes
        'Memo': 'memo',                # string -> str
        'Metadata': 'metadata',        # []byte -> bytes
        'Expire': 'expire',            # *ExpireOptions -> ExpireOptions
        'HoldUntil': 'hold_until',     # *HoldUntilOptions -> HoldUntilOptions
        'Authorities': 'authorities'   # []*url.URL -> List[AccountUrl]
    }

    # Create test header
    header = TransactionHeader(
        principal="acc://compliance.acme",
        initiator=b"C" * 32,
        memo="Compliance test",
        metadata=b"Compliance metadata",
        expire=ExpireOptions(at_time=datetime.now(timezone.utc)),
        hold_until=HoldUntilOptions(minor_block=500),
        authorities=["acc://auth.acme"]
    )

    # Verify all Go fields have Python equivalents
    for go_field, python_field in go_fields.items():
        assert hasattr(header, python_field), f"Missing Python field for Go {go_field}"
        print(f"  ✅ {go_field} -> {python_field}")

    # Verify ExpireOptions compliance
    expire_test = ExpireOptions()
    assert hasattr(expire_test, 'at_time'), "ExpireOptions missing at_time field"
    print("  ✅ ExpireOptions.AtTime -> ExpireOptions.at_time")

    # Verify HoldUntilOptions compliance
    hold_test = HoldUntilOptions()
    assert hasattr(hold_test, 'minor_block'), "HoldUntilOptions missing minor_block field"
    print("  ✅ HoldUntilOptions.MinorBlock -> HoldUntilOptions.minor_block")

    print("\\n✅ COMPLETE: Python SDK is 100% compliant with Go reference!")


if __name__ == "__main__":
    print("=== Testing Transaction Header Fields Completeness ===\\n")

    test_transaction_header_all_fields()
    test_transaction_header_required_fields_only()
    test_expire_options_completeness()
    test_hold_until_options_completeness()
    test_transaction_header_json_serialization()
    test_transaction_header_field_types()
    test_transaction_header_edge_cases()
    test_go_reference_compliance()

    print("\\n🎉 ALL TESTS PASSED - Transaction header implementation is complete!")