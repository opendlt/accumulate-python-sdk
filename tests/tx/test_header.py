"""
Unit tests for transaction header types (Phase 4).

Tests ExpireOptions, HoldUntilOptions, TransactionHeader, and helper functions.
"""

import pytest
from datetime import datetime, timezone, timedelta
from pydantic import ValidationError

from accumulate_client.tx.header import (
    ExpireOptions,
    HoldUntilOptions,
    TransactionHeader,
    TransactionEnvelope,
    create_simple_header,
    create_expiring_header,
    create_scheduled_header,
    create_multisig_header,
)
from accumulate_client.runtime.url import AccountUrl


class TestExpireOptions:
    """Tests for ExpireOptions class."""

    def test_create_empty(self):
        """Test creating ExpireOptions with no at_time."""
        opts = ExpireOptions()
        assert opts.at_time is None
        assert not opts  # Should be falsy when empty
        assert opts.to_dict() == {}

    def test_create_with_datetime(self):
        """Test creating ExpireOptions with a datetime."""
        now = datetime.now(timezone.utc)
        opts = ExpireOptions(at_time=now)
        assert opts.at_time == now
        assert opts  # Should be truthy when set
        assert "atTime" in opts.to_dict()

    def test_from_timestamp_nanoseconds(self):
        """Test creating from nanosecond timestamp."""
        # Known timestamp: 1700000000 seconds = 2023-11-14 22:13:20 UTC
        ts_ns = 1700000000 * 10**9
        opts = ExpireOptions.from_timestamp(ts_ns, unit='ns')
        assert opts.at_time is not None
        assert opts.at_time.year == 2023

    def test_from_timestamp_seconds(self):
        """Test creating from second timestamp."""
        ts_s = 1700000000
        opts = ExpireOptions.from_timestamp(ts_s, unit='s')
        assert opts.at_time is not None
        assert opts.at_time.year == 2023

    def test_from_duration(self):
        """Test creating with duration from now."""
        opts = ExpireOptions.from_duration(seconds=60)
        assert opts.at_time is not None
        # Should be approximately 60 seconds from now
        expected = datetime.now(timezone.utc) + timedelta(seconds=60)
        diff = abs((opts.at_time - expected).total_seconds())
        assert diff < 2  # Allow 2 second tolerance

    def test_from_duration_complex(self):
        """Test creating with complex duration."""
        opts = ExpireOptions.from_duration(days=1, hours=2, minutes=30, seconds=15)
        assert opts.at_time is not None
        expected_seconds = 1 * 86400 + 2 * 3600 + 30 * 60 + 15
        expected = datetime.now(timezone.utc) + timedelta(seconds=expected_seconds)
        diff = abs((opts.at_time - expected).total_seconds())
        assert diff < 2

    def test_to_timestamp_ns(self):
        """Test converting to nanosecond timestamp."""
        ts_s = 1700000000
        dt = datetime.fromtimestamp(ts_s, tz=timezone.utc)
        opts = ExpireOptions(at_time=dt)
        ts_ns = opts.to_timestamp_ns()
        assert ts_ns == ts_s * 10**9

    def test_is_expired_future(self):
        """Test is_expired for future time."""
        future = datetime.now(timezone.utc) + timedelta(hours=1)
        opts = ExpireOptions(at_time=future)
        assert not opts.is_expired()

    def test_is_expired_past(self):
        """Test is_expired for past time."""
        past = datetime.now(timezone.utc) - timedelta(hours=1)
        opts = ExpireOptions(at_time=past)
        assert opts.is_expired()

    def test_parse_iso_string(self):
        """Test parsing ISO format string."""
        opts = ExpireOptions(at_time="2023-11-14T22:13:20+00:00")
        assert opts.at_time is not None
        assert opts.at_time.year == 2023
        assert opts.at_time.month == 11

    def test_parse_datetime_with_z(self):
        """Test parsing datetime with Z suffix."""
        opts = ExpireOptions(at_time="2023-11-14T22:13:20Z")
        assert opts.at_time is not None
        assert opts.at_time.year == 2023

    def test_to_dict_format(self):
        """Test to_dict produces correct format."""
        dt = datetime(2023, 11, 14, 22, 13, 20, tzinfo=timezone.utc)
        opts = ExpireOptions(at_time=dt)
        d = opts.to_dict()
        assert "atTime" in d
        assert "2023-11-14" in d["atTime"]

    def test_json_alias(self):
        """Test that JSON alias works correctly."""
        opts = ExpireOptions(atTime="2023-11-14T22:13:20+00:00")  # Using alias
        assert opts.at_time is not None


class TestHoldUntilOptions:
    """Tests for HoldUntilOptions class."""

    def test_create_empty(self):
        """Test creating HoldUntilOptions with no minor_block."""
        opts = HoldUntilOptions()
        assert opts.minor_block is None
        assert not opts  # Should be falsy when empty
        assert opts.to_dict() == {}

    def test_create_with_block(self):
        """Test creating with minor_block."""
        opts = HoldUntilOptions(minor_block=12345)
        assert opts.minor_block == 12345
        assert opts  # Should be truthy when set
        assert opts.to_dict() == {"minorBlock": 12345}

    def test_at_block_factory(self):
        """Test at_block factory method."""
        opts = HoldUntilOptions.at_block(99999)
        assert opts.minor_block == 99999

    def test_at_block_negative_raises(self):
        """Test that negative block number raises error."""
        with pytest.raises(ValueError):
            HoldUntilOptions.at_block(-1)

    def test_validation_negative_block(self):
        """Test that negative block via validator raises error."""
        with pytest.raises(ValidationError):
            HoldUntilOptions(minor_block=-1)

    def test_validation_string_conversion(self):
        """Test that string is converted to int."""
        opts = HoldUntilOptions(minor_block="12345")
        assert opts.minor_block == 12345

    def test_json_alias(self):
        """Test that JSON alias works correctly."""
        opts = HoldUntilOptions(minorBlock=12345)  # Using alias
        assert opts.minor_block == 12345

    def test_to_dict_uses_alias(self):
        """Test to_dict uses JSON alias."""
        opts = HoldUntilOptions(minor_block=12345)
        d = opts.to_dict()
        assert "minorBlock" in d
        assert d["minorBlock"] == 12345


class TestTransactionHeader:
    """Tests for TransactionHeader class."""

    def test_create_minimal(self):
        """Test creating header with only required fields."""
        header = TransactionHeader(principal="acc://test.acme")
        assert "test.acme" in str(header.principal)

    def test_create_full(self):
        """Test creating header with all fields."""
        header = TransactionHeader.create(
            principal="acc://test.acme",
            memo="Test memo",
            metadata=b"\x01\x02\x03",
            expire=ExpireOptions.from_duration(hours=1),
            hold_until=HoldUntilOptions.at_block(1000),
            authorities=["acc://auth1.acme", "acc://auth2.acme"],
        )
        assert header.memo == "Test memo"
        assert header.metadata == b"\x01\x02\x03"
        assert header.expire is not None
        assert header.hold_until is not None
        assert len(header.authorities) == 2

    def test_timestamp_auto_generated(self):
        """Test that timestamp is auto-generated."""
        header = TransactionHeader.create(principal="acc://test.acme")
        assert header.timestamp is not None
        assert header.timestamp > 0

    def test_to_dict_format(self):
        """Test to_dict produces correct format."""
        header = TransactionHeader.create(
            principal="acc://test.acme",
            memo="Test",
            metadata=b"\xab\xcd",
        )
        d = header.to_dict()
        assert d["principal"] == "acc://test.acme"
        assert d["memo"] == "Test"
        assert d["metadata"] == "abcd"  # Hex encoded

    def test_to_dict_with_expire(self):
        """Test to_dict includes expire options."""
        expire = ExpireOptions.from_duration(hours=1)
        header = TransactionHeader.create(
            principal="acc://test.acme",
            expire=expire,
        )
        d = header.to_dict()
        assert "expire" in d
        assert "atTime" in d["expire"]

    def test_to_dict_with_hold_until(self):
        """Test to_dict includes holdUntil options."""
        hold = HoldUntilOptions.at_block(5000)
        header = TransactionHeader.create(
            principal="acc://test.acme",
            hold_until=hold,
        )
        d = header.to_dict()
        assert "holdUntil" in d
        assert d["holdUntil"]["minorBlock"] == 5000

    def test_to_dict_with_authorities(self):
        """Test to_dict includes authorities."""
        header = TransactionHeader.create(
            principal="acc://test.acme",
            authorities=["acc://auth1.acme", "acc://auth2.acme"],
        )
        d = header.to_dict()
        assert "authorities" in d
        assert len(d["authorities"]) == 2

    def test_with_memo(self):
        """Test with_memo returns new header."""
        header = TransactionHeader.create(principal="acc://test.acme")
        new_header = header.with_memo("New memo")
        assert header.memo is None
        assert new_header.memo == "New memo"

    def test_with_expire(self):
        """Test with_expire returns new header."""
        header = TransactionHeader.create(principal="acc://test.acme")
        expire = ExpireOptions.from_duration(hours=2)
        new_header = header.with_expire(expire)
        assert header.expire is None
        assert new_header.expire is not None

    def test_with_hold_until(self):
        """Test with_hold_until returns new header."""
        header = TransactionHeader.create(principal="acc://test.acme")
        hold = HoldUntilOptions.at_block(1000)
        new_header = header.with_hold_until(hold)
        assert header.hold_until is None
        assert new_header.hold_until is not None

    def test_with_authorities(self):
        """Test with_authorities returns new header."""
        header = TransactionHeader.create(principal="acc://test.acme")
        new_header = header.with_authorities(["acc://auth.acme"])
        assert header.authorities is None
        assert len(new_header.authorities) == 1

    def test_add_authority(self):
        """Test add_authority appends to list."""
        header = TransactionHeader.create(
            principal="acc://test.acme",
            authorities=["acc://auth1.acme"],
        )
        new_header = header.add_authority("acc://auth2.acme")
        assert len(header.authorities) == 1
        assert len(new_header.authorities) == 2

    def test_initiator_validation(self):
        """Test initiator must be 32 bytes."""
        header = TransactionHeader(
            principal="acc://test.acme",
            initiator=bytes(32),  # Valid 32 bytes
        )
        assert len(header.initiator) == 32

    def test_initiator_hex_string(self):
        """Test initiator can be provided as hex string."""
        hex_str = "ab" * 32  # 64 hex chars = 32 bytes
        header = TransactionHeader(
            principal="acc://test.acme",
            initiator=hex_str,
        )
        assert len(header.initiator) == 32

    def test_principal_auto_prefix(self):
        """Test principal gets acc:// prefix if missing."""
        header = TransactionHeader(principal="test.acme")
        assert "acc://" in str(header.principal)

    def test_memo_max_length(self):
        """Test memo field accepts up to 256 chars."""
        memo = "x" * 256
        header = TransactionHeader(principal="acc://test.acme", memo=memo)
        assert len(header.memo) == 256


class TestTransactionEnvelope:
    """Tests for TransactionEnvelope class."""

    def test_create_basic(self):
        """Test creating basic envelope."""
        header = TransactionHeader.create(principal="acc://test.acme")
        body = {"type": "sendTokens", "to": [{"url": "acc://recipient.acme", "amount": 1000}]}
        envelope = TransactionEnvelope.create(header=header, body=body)
        assert envelope.header == header
        assert envelope.body == body
        assert envelope.signatures is None

    def test_to_dict(self):
        """Test envelope to_dict."""
        header = TransactionHeader.create(principal="acc://test.acme")
        body = {"type": "sendTokens"}
        envelope = TransactionEnvelope.create(header=header, body=body)
        d = envelope.to_dict()
        assert "header" in d
        assert "body" in d
        assert d["body"]["type"] == "sendTokens"

    def test_add_signature(self):
        """Test adding signature to envelope."""
        header = TransactionHeader.create(principal="acc://test.acme")
        body = {"type": "sendTokens"}
        envelope = TransactionEnvelope.create(header=header, body=body)
        sig = {"type": "ed25519", "signature": "abc123"}
        new_envelope = envelope.add_signature(sig)
        assert envelope.signatures is None
        assert len(new_envelope.signatures) == 1


class TestHelperFunctions:
    """Tests for header helper functions."""

    def test_create_simple_header(self):
        """Test create_simple_header."""
        header = create_simple_header("acc://test.acme", memo="Test")
        assert header["principal"] == "acc://test.acme"
        assert header["memo"] == "Test"
        assert "timestamp" in header

    def test_create_simple_header_timestamp(self):
        """Test create_simple_header with explicit timestamp."""
        ts = 1234567890000000000
        header = create_simple_header("acc://test.acme", timestamp=ts)
        assert header["timestamp"] == ts

    def test_create_expiring_header(self):
        """Test create_expiring_header."""
        header = create_expiring_header("acc://test.acme", expire_in_seconds=3600)
        assert "expire" in header
        assert "atTime" in header["expire"]

    def test_create_scheduled_header(self):
        """Test create_scheduled_header."""
        header = create_scheduled_header("acc://test.acme", execute_at_block=10000)
        assert "holdUntil" in header
        assert header["holdUntil"]["minorBlock"] == 10000

    def test_create_multisig_header(self):
        """Test create_multisig_header."""
        header = create_multisig_header(
            "acc://test.acme",
            additional_authorities=["acc://auth1.acme", "acc://auth2.acme"],
        )
        assert "authorities" in header
        assert len(header["authorities"]) == 2


class TestBuilderIntegration:
    """Tests for integration with transaction builders."""

    def test_build_envelope_with_expire(self):
        """Test build_envelope accepts ExpireOptions."""
        from accumulate_client.tx.builders.base import BaseTxBuilder
        from pydantic import BaseModel

        # Create a minimal concrete builder for testing
        class TestBody(BaseModel):
            type: str = "test"

        class TestBuilder(BaseTxBuilder[TestBody]):
            @property
            def tx_type(self) -> str:
                return "test"

            @property
            def body_cls(self):
                return TestBody

        builder = TestBuilder()
        expire = ExpireOptions.from_duration(hours=1)
        envelope = builder.build_envelope(
            origin="acc://test.acme",
            expire=expire,
        )
        assert "expire" in envelope["header"]
        assert "atTime" in envelope["header"]["expire"]

    def test_build_envelope_with_hold_until(self):
        """Test build_envelope accepts HoldUntilOptions."""
        from accumulate_client.tx.builders.base import BaseTxBuilder
        from pydantic import BaseModel

        class TestBody(BaseModel):
            type: str = "test"

        class TestBuilder(BaseTxBuilder[TestBody]):
            @property
            def tx_type(self) -> str:
                return "test"

            @property
            def body_cls(self):
                return TestBody

        builder = TestBuilder()
        hold = HoldUntilOptions.at_block(5000)
        envelope = builder.build_envelope(
            origin="acc://test.acme",
            hold_until=hold,
        )
        assert "holdUntil" in envelope["header"]
        assert envelope["header"]["holdUntil"]["minorBlock"] == 5000

    def test_build_envelope_with_authorities(self):
        """Test build_envelope accepts authorities list."""
        from accumulate_client.tx.builders.base import BaseTxBuilder
        from pydantic import BaseModel

        class TestBody(BaseModel):
            type: str = "test"

        class TestBuilder(BaseTxBuilder[TestBody]):
            @property
            def tx_type(self) -> str:
                return "test"

            @property
            def body_cls(self):
                return TestBody

        builder = TestBuilder()
        envelope = builder.build_envelope(
            origin="acc://test.acme",
            authorities=["acc://auth1.acme", "acc://auth2.acme"],
        )
        assert "authorities" in envelope["header"]
        assert len(envelope["header"]["authorities"]) == 2

    def test_build_envelope_with_metadata(self):
        """Test build_envelope accepts metadata."""
        from accumulate_client.tx.builders.base import BaseTxBuilder
        from pydantic import BaseModel

        class TestBody(BaseModel):
            type: str = "test"

        class TestBuilder(BaseTxBuilder[TestBody]):
            @property
            def tx_type(self) -> str:
                return "test"

            @property
            def body_cls(self):
                return TestBody

        builder = TestBuilder()
        envelope = builder.build_envelope(
            origin="acc://test.acme",
            metadata=b"\xab\xcd\xef",
        )
        assert "metadata" in envelope["header"]
        assert envelope["header"]["metadata"] == "abcdef"

    def test_build_envelope_with_header_object(self):
        """Test build_envelope_with_header accepts TransactionHeader."""
        from accumulate_client.tx.builders.base import BaseTxBuilder
        from pydantic import BaseModel

        class TestBody(BaseModel):
            type: str = "test"

        class TestBuilder(BaseTxBuilder[TestBody]):
            @property
            def tx_type(self) -> str:
                return "test"

            @property
            def body_cls(self):
                return TestBody

        builder = TestBuilder()
        header = TransactionHeader.create(
            principal="acc://test.acme",
            memo="Test memo",
            expire=ExpireOptions.from_duration(hours=1),
        )
        envelope = builder.build_envelope_with_header(header)
        assert envelope["header"]["memo"] == "Test memo"
        assert "expire" in envelope["header"]


class TestGoParity:
    """Tests to verify Go protocol parity."""

    def test_expire_options_go_json_format(self):
        """Test ExpireOptions JSON matches Go format."""
        dt = datetime(2023, 11, 14, 22, 13, 20, tzinfo=timezone.utc)
        opts = ExpireOptions(at_time=dt)
        d = opts.to_dict()
        # Go uses "atTime" field name
        assert "atTime" in d
        # Go uses ISO 8601 format
        assert "2023-11-14" in d["atTime"]

    def test_hold_until_options_go_json_format(self):
        """Test HoldUntilOptions JSON matches Go format."""
        opts = HoldUntilOptions(minor_block=12345)
        d = opts.to_dict()
        # Go uses "minorBlock" field name
        assert "minorBlock" in d
        # Go uses uint64 as integer
        assert isinstance(d["minorBlock"], int)

    def test_header_go_field_names(self):
        """Test TransactionHeader uses Go field names."""
        header = TransactionHeader.create(
            principal="acc://test.acme",
            hold_until=HoldUntilOptions.at_block(1000),
        )
        d = header.to_dict()
        # Go uses "principal" not "origin"
        assert "principal" in d
        # Go uses "holdUntil" (camelCase)
        assert "holdUntil" in d

    def test_header_initiator_format(self):
        """Test initiator is hex encoded like Go."""
        header = TransactionHeader(
            principal="acc://test.acme",
            initiator=bytes(32),
        )
        d = header.to_dict()
        # Go encodes as hex string
        assert "initiator" in d
        assert d["initiator"] == "00" * 32

    def test_header_metadata_format(self):
        """Test metadata is hex encoded like Go."""
        header = TransactionHeader.create(
            principal="acc://test.acme",
            metadata=b"\x01\x02\x03",
        )
        d = header.to_dict()
        # Go encodes as hex string
        assert d["metadata"] == "010203"
