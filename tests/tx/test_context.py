"""
Unit tests for transaction build context (Phase 6).

Tests BuildContext, TransactionContext, and helper functions for
transaction construction with proper defaults matching Go/Dart SDK parity.
"""

import pytest
from datetime import datetime, timezone, timedelta
from pydantic import ValidationError

from accumulate_client.tx.context import (
    BuildContext,
    TransactionContext,
    create_context,
    context_for_identity,
    context_for_lite_account,
)
from accumulate_client.tx.header import ExpireOptions, HoldUntilOptions
from accumulate_client.runtime.url import AccountUrl


class TestBuildContextCreation:
    """Tests for BuildContext creation and initialization."""

    def test_create_minimal(self):
        """Test creating context with only principal."""
        ctx = BuildContext(principal="acc://test.acme")
        assert "test.acme" in ctx.principal
        assert ctx.timestamp is not None
        assert ctx.timestamp > 0
        assert ctx.memo is None
        assert ctx.metadata is None
        assert ctx.expire is None
        assert ctx.hold_until is None
        assert ctx.authorities is None
        assert ctx.initiator is None

    def test_create_with_all_fields(self):
        """Test creating context with all optional fields."""
        expire = ExpireOptions.from_duration(hours=1)
        hold_until = HoldUntilOptions.at_block(1000)
        ctx = BuildContext(
            principal="acc://test.acme",
            memo="Test memo",
            metadata=b"\x01\x02\x03",
            expire=expire,
            hold_until=hold_until,
            authorities=["acc://auth1.acme", "acc://auth2.acme"],
            initiator=bytes(32),
        )
        assert ctx.memo == "Test memo"
        assert ctx.metadata == b"\x01\x02\x03"
        assert ctx.expire is not None
        assert ctx.hold_until is not None
        assert len(ctx.authorities) == 2
        assert ctx.initiator == bytes(32)

    def test_principal_auto_prefix(self):
        """Test principal gets acc:// prefix if missing."""
        ctx = BuildContext(principal="test.acme")
        assert ctx.principal == "acc://test.acme"

    def test_principal_account_url(self):
        """Test principal accepts AccountUrl."""
        url = AccountUrl("acc://test.acme")
        ctx = BuildContext(principal=url)
        assert ctx.principal == "acc://test.acme"

    def test_timestamp_auto_generated(self):
        """Test timestamp is automatically generated in nanoseconds."""
        before = int(datetime.now(timezone.utc).timestamp() * 1_000_000_000)
        ctx = BuildContext(principal="acc://test.acme")
        after = int(datetime.now(timezone.utc).timestamp() * 1_000_000_000)
        assert before <= ctx.timestamp <= after

    def test_timestamp_explicit(self):
        """Test explicit timestamp is used."""
        ts = 1700000000 * 10**9
        ctx = BuildContext(principal="acc://test.acme", timestamp=ts)
        assert ctx.timestamp == ts

    def test_memo_max_length(self):
        """Test memo field allows up to 256 chars."""
        memo = "x" * 256
        ctx = BuildContext(principal="acc://test.acme", memo=memo)
        assert len(ctx.memo) == 256

    def test_metadata_bytes(self):
        """Test metadata accepts bytes."""
        ctx = BuildContext(principal="acc://test.acme", metadata=b"\xab\xcd\xef")
        assert ctx.metadata == b"\xab\xcd\xef"

    def test_metadata_hex_string(self):
        """Test metadata accepts hex string."""
        ctx = BuildContext(principal="acc://test.acme", metadata="abcdef")
        assert ctx.metadata == b"\xab\xcd\xef"

    def test_initiator_bytes(self):
        """Test initiator accepts 32-byte bytes."""
        initiator = bytes(32)
        ctx = BuildContext(principal="acc://test.acme", initiator=initiator)
        assert ctx.initiator == initiator
        assert len(ctx.initiator) == 32

    def test_initiator_hex_string(self):
        """Test initiator accepts 64-char hex string."""
        hex_str = "ab" * 32
        ctx = BuildContext(principal="acc://test.acme", initiator=hex_str)
        assert len(ctx.initiator) == 32

    def test_initiator_invalid_length(self):
        """Test initiator rejects invalid length."""
        with pytest.raises(ValueError, match="32 bytes"):
            BuildContext(principal="acc://test.acme", initiator=b"\x01\x02\x03")

    def test_authorities_list(self):
        """Test authorities accepts list of strings."""
        ctx = BuildContext(
            principal="acc://test.acme",
            authorities=["acc://auth1.acme", "acc://auth2.acme"]
        )
        assert len(ctx.authorities) == 2
        assert "acc://auth1.acme" in ctx.authorities

    def test_authorities_with_account_url(self):
        """Test authorities accepts AccountUrl objects."""
        ctx = BuildContext(
            principal="acc://test.acme",
            authorities=[AccountUrl("acc://auth.acme")]
        )
        assert len(ctx.authorities) == 1

    def test_authorities_auto_prefix(self):
        """Test authorities get acc:// prefix."""
        ctx = BuildContext(
            principal="acc://test.acme",
            authorities=["auth.acme"]
        )
        assert ctx.authorities[0] == "acc://auth.acme"


class TestBuildContextFactoryMethods:
    """Tests for BuildContext factory methods."""

    def test_now(self):
        """Test now() factory creates context with current timestamp."""
        before = int(datetime.now(timezone.utc).timestamp() * 1_000_000_000)
        ctx = BuildContext.now("acc://test.acme")
        after = int(datetime.now(timezone.utc).timestamp() * 1_000_000_000)
        assert before <= ctx.timestamp <= after

    def test_now_with_options(self):
        """Test now() factory with all options."""
        expire = ExpireOptions.from_duration(hours=1)
        hold_until = HoldUntilOptions.at_block(1000)
        ctx = BuildContext.now(
            "acc://test.acme",
            memo="Test",
            metadata=b"\x01\x02",
            expire=expire,
            hold_until=hold_until,
            authorities=["acc://auth.acme"]
        )
        assert ctx.memo == "Test"
        assert ctx.metadata == b"\x01\x02"
        assert ctx.expire is not None
        assert ctx.hold_until is not None
        assert len(ctx.authorities) == 1

    def test_at_timestamp(self):
        """Test at_timestamp() factory with specific timestamp."""
        ts = 1700000000 * 10**9
        ctx = BuildContext.at_timestamp("acc://test.acme", ts)
        assert ctx.timestamp == ts

    def test_at_timestamp_with_options(self):
        """Test at_timestamp() factory with options."""
        ts = 1700000000 * 10**9
        ctx = BuildContext.at_timestamp(
            "acc://test.acme",
            ts,
            memo="Test memo",
            metadata=b"\xab"
        )
        assert ctx.timestamp == ts
        assert ctx.memo == "Test memo"
        assert ctx.metadata == b"\xab"

    def test_expiring(self):
        """Test expiring() factory creates context with expiration."""
        ctx = BuildContext.expiring("acc://test.acme", expire_in_seconds=3600)
        assert ctx.expire is not None
        assert ctx.expire.at_time is not None
        # Should expire approximately 1 hour from now
        expected = datetime.now(timezone.utc) + timedelta(hours=1)
        diff = abs((ctx.expire.at_time - expected).total_seconds())
        assert diff < 5  # 5 second tolerance

    def test_expiring_with_memo(self):
        """Test expiring() factory with memo."""
        ctx = BuildContext.expiring("acc://test.acme", expire_in_seconds=60, memo="Quick tx")
        assert ctx.memo == "Quick tx"
        assert ctx.expire is not None

    def test_scheduled(self):
        """Test scheduled() factory creates context with hold_until."""
        ctx = BuildContext.scheduled("acc://test.acme", execute_at_block=10000)
        assert ctx.hold_until is not None
        assert ctx.hold_until.minor_block == 10000

    def test_scheduled_with_memo(self):
        """Test scheduled() factory with memo."""
        ctx = BuildContext.scheduled("acc://test.acme", execute_at_block=5000, memo="Scheduled tx")
        assert ctx.memo == "Scheduled tx"
        assert ctx.hold_until.minor_block == 5000

    def test_requiring_authorities_factory(self):
        """Test requiring_authorities() factory method."""
        ctx = BuildContext.requiring_authorities(
            "acc://test.acme",
            authorities=["acc://auth1.acme", "acc://auth2.acme"]
        )
        assert len(ctx.authorities) == 2

    def test_requiring_authorities_memo(self):
        """Test requiring_authorities() factory with memo."""
        ctx = BuildContext.requiring_authorities(
            "acc://test.acme",
            authorities=["acc://auth.acme"],
            memo="Multi-sig tx"
        )
        assert ctx.memo == "Multi-sig tx"
        assert len(ctx.authorities) == 1


class TestBuildContextMutators:
    """Tests for BuildContext immutable mutator methods."""

    def test_refresh_timestamp(self):
        """Test refresh_timestamp() creates new context with updated timestamp."""
        ctx = BuildContext(principal="acc://test.acme", timestamp=1000)
        before = int(datetime.now(timezone.utc).timestamp() * 1_000_000_000)
        new_ctx = ctx.refresh_timestamp()
        after = int(datetime.now(timezone.utc).timestamp() * 1_000_000_000)

        # Original unchanged
        assert ctx.timestamp == 1000
        # New context has fresh timestamp
        assert before <= new_ctx.timestamp <= after
        # Other fields preserved
        assert new_ctx.principal == ctx.principal

    def test_with_memo(self):
        """Test with_memo() returns copy with new memo."""
        ctx = BuildContext(principal="acc://test.acme")
        new_ctx = ctx.with_memo("New memo")
        assert ctx.memo is None
        assert new_ctx.memo == "New memo"

    def test_with_metadata(self):
        """Test with_metadata() returns copy with new metadata."""
        ctx = BuildContext(principal="acc://test.acme")
        new_ctx = ctx.with_metadata(b"\x01\x02")
        assert ctx.metadata is None
        assert new_ctx.metadata == b"\x01\x02"

    def test_with_expire(self):
        """Test with_expire() returns copy with new expire."""
        ctx = BuildContext(principal="acc://test.acme")
        expire = ExpireOptions.from_duration(hours=1)
        new_ctx = ctx.with_expire(expire)
        assert ctx.expire is None
        assert new_ctx.expire is not None

    def test_with_hold_until(self):
        """Test with_hold_until() returns copy with new hold_until."""
        ctx = BuildContext(principal="acc://test.acme")
        hold = HoldUntilOptions.at_block(1000)
        new_ctx = ctx.with_hold_until(hold)
        assert ctx.hold_until is None
        assert new_ctx.hold_until.minor_block == 1000

    def test_with_authorities(self):
        """Test with_authorities() returns copy with new authorities."""
        ctx = BuildContext(principal="acc://test.acme")
        new_ctx = ctx.with_authorities(["acc://auth.acme"])
        assert ctx.authorities is None
        assert len(new_ctx.authorities) == 1

    def test_add_authority(self):
        """Test add_authority() appends to authorities list."""
        ctx = BuildContext(
            principal="acc://test.acme",
            authorities=["acc://auth1.acme"]
        )
        new_ctx = ctx.add_authority("acc://auth2.acme")
        assert len(ctx.authorities) == 1
        assert len(new_ctx.authorities) == 2

    def test_add_authority_to_empty(self):
        """Test add_authority() when no authorities exist."""
        ctx = BuildContext(principal="acc://test.acme")
        new_ctx = ctx.add_authority("acc://auth.acme")
        assert ctx.authorities is None
        assert len(new_ctx.authorities) == 1

    def test_with_initiator(self):
        """Test with_initiator() returns copy with new initiator."""
        ctx = BuildContext(principal="acc://test.acme")
        initiator = bytes(32)
        new_ctx = ctx.with_initiator(initiator)
        assert ctx.initiator is None
        assert new_ctx.initiator == initiator


class TestBuildContextOutput:
    """Tests for BuildContext output methods."""

    def test_to_header_dict_minimal(self):
        """Test to_header_dict with minimal fields."""
        ctx = BuildContext(
            principal="acc://test.acme",
            timestamp=1700000000000000000
        )
        d = ctx.to_header_dict()
        assert d["principal"] == "acc://test.acme"
        assert d["timestamp"] == 1700000000000000000
        assert "memo" not in d
        assert "metadata" not in d
        assert "expire" not in d
        assert "holdUntil" not in d
        assert "authorities" not in d
        assert "initiator" not in d

    def test_to_header_dict_full(self):
        """Test to_header_dict with all fields."""
        ctx = BuildContext(
            principal="acc://test.acme",
            timestamp=1700000000000000000,
            memo="Test memo",
            metadata=b"\xab\xcd",
            expire=ExpireOptions.from_duration(hours=1),
            hold_until=HoldUntilOptions.at_block(1000),
            authorities=["acc://auth1.acme", "acc://auth2.acme"],
            initiator=bytes(32),
        )
        d = ctx.to_header_dict()
        assert d["principal"] == "acc://test.acme"
        assert d["timestamp"] == 1700000000000000000
        assert d["memo"] == "Test memo"
        assert d["metadata"] == "abcd"  # Hex encoded
        assert "expire" in d
        assert "holdUntil" in d
        assert d["holdUntil"]["minorBlock"] == 1000
        assert len(d["authorities"]) == 2
        assert d["initiator"] == "00" * 32

    def test_to_header(self):
        """Test to_header() creates TransactionHeader."""
        ctx = BuildContext(
            principal="acc://test.acme",
            memo="Test",
            metadata=b"\x01",
        )
        header = ctx.to_header()
        assert "test.acme" in str(header.principal)
        assert header.memo == "Test"
        assert header.metadata == b"\x01"

    def test_build_envelope(self):
        """Test build_envelope() creates complete envelope."""
        ctx = BuildContext(
            principal="acc://test.acme",
            timestamp=1700000000000000000,
            memo="Test"
        )
        body = {"type": "sendTokens", "to": [{"url": "acc://recipient.acme", "amount": 100}]}
        envelope = ctx.build_envelope(body)

        assert "header" in envelope
        assert "body" in envelope
        assert envelope["header"]["principal"] == "acc://test.acme"
        assert envelope["header"]["memo"] == "Test"
        assert envelope["body"]["type"] == "sendTokens"

    def test_build_signed_envelope(self):
        """Test build_signed_envelope() creates envelope with signature."""
        ctx = BuildContext(principal="acc://test.acme")
        body = {"type": "sendTokens"}
        signature = {"type": "ed25519", "signature": "abc123"}
        envelope = ctx.build_signed_envelope(body, signature)

        assert "transaction" in envelope
        assert "signatures" in envelope
        assert len(envelope["signatures"]) == 1
        assert envelope["signatures"][0]["type"] == "ed25519"


class TestBuildContextTimeUtils:
    """Tests for BuildContext time utility methods."""

    def test_get_timestamp_datetime(self):
        """Test get_timestamp_datetime() conversion."""
        ts = 1700000000000000000  # 1700000000 seconds in nanoseconds
        ctx = BuildContext(principal="acc://test.acme", timestamp=ts)
        dt = ctx.get_timestamp_datetime()
        assert dt.year == 2023
        assert dt.month == 11

    def test_is_expired_false(self):
        """Test is_expired() when not expired."""
        ctx = BuildContext(
            principal="acc://test.acme",
            expire=ExpireOptions.from_duration(hours=1)
        )
        assert not ctx.is_expired()

    def test_is_expired_true(self):
        """Test is_expired() when expired."""
        past = datetime.now(timezone.utc) - timedelta(hours=1)
        ctx = BuildContext(
            principal="acc://test.acme",
            expire=ExpireOptions(at_time=past)
        )
        assert ctx.is_expired()

    def test_is_expired_no_expire(self):
        """Test is_expired() when no expiration set."""
        ctx = BuildContext(principal="acc://test.acme")
        assert not ctx.is_expired()

    def test_time_until_expiry(self):
        """Test time_until_expiry() returns timedelta."""
        ctx = BuildContext(
            principal="acc://test.acme",
            expire=ExpireOptions.from_duration(hours=1)
        )
        remaining = ctx.time_until_expiry()
        assert remaining is not None
        assert 3500 <= remaining.total_seconds() <= 3700  # ~1 hour

    def test_time_until_expiry_none(self):
        """Test time_until_expiry() returns None when no expiration."""
        ctx = BuildContext(principal="acc://test.acme")
        assert ctx.time_until_expiry() is None


class TestTransactionContext:
    """Tests for TransactionContext (extended BuildContext with body)."""

    def test_create(self):
        """Test TransactionContext.create() factory."""
        body = {"type": "sendTokens", "to": []}
        ctx = TransactionContext.create(
            principal="acc://test.acme",
            body=body,
            memo="Test"
        )
        assert ctx.body == body
        assert ctx.memo == "Test"

    def test_create_with_all_options(self):
        """Test TransactionContext.create() with all options."""
        body = {"type": "sendTokens"}
        ctx = TransactionContext.create(
            principal="acc://test.acme",
            body=body,
            memo="Test",
            expire=ExpireOptions.from_duration(hours=1),
            hold_until=HoldUntilOptions.at_block(1000),
            authorities=["acc://auth.acme"]
        )
        assert ctx.body == body
        assert ctx.expire is not None
        assert ctx.hold_until is not None
        assert len(ctx.authorities) == 1

    def test_to_envelope(self):
        """Test to_envelope() creates complete envelope."""
        body = {"type": "sendTokens", "to": []}
        ctx = TransactionContext.create(
            principal="acc://test.acme",
            body=body
        )
        envelope = ctx.to_envelope()
        assert "header" in envelope
        assert "body" in envelope
        assert envelope["body"]["type"] == "sendTokens"

    def test_to_envelope_no_body_raises(self):
        """Test to_envelope() raises when body not set."""
        ctx = TransactionContext(principal="acc://test.acme")
        with pytest.raises(ValueError, match="body is not set"):
            ctx.to_envelope()

    def test_with_body(self):
        """Test with_body() returns copy with new body."""
        ctx = TransactionContext(principal="acc://test.acme")
        body = {"type": "sendTokens"}
        new_ctx = ctx.with_body(body)
        assert ctx.body is None
        assert new_ctx.body == body


class TestHelperFunctions:
    """Tests for module helper functions."""

    def test_create_context(self):
        """Test create_context() helper."""
        ctx = create_context("acc://test.acme", memo="Test")
        assert "test.acme" in ctx.principal
        assert ctx.memo == "Test"

    def test_create_context_with_kwargs(self):
        """Test create_context() with various kwargs."""
        ctx = create_context(
            "acc://test.acme",
            timestamp=1700000000000000000,
            memo="Test",
            metadata=b"\x01"
        )
        assert ctx.timestamp == 1700000000000000000
        assert ctx.memo == "Test"
        assert ctx.metadata == b"\x01"

    def test_context_for_identity(self):
        """Test context_for_identity() helper."""
        ctx = context_for_identity("my-adi.acme", memo="Identity op")
        assert "my-adi.acme" in ctx.principal
        assert ctx.memo == "Identity op"

    def test_context_for_identity_with_url_prefix(self):
        """Test context_for_identity() adds acc:// prefix."""
        ctx = context_for_identity("my-adi.acme")
        assert ctx.principal == "acc://my-adi.acme"

    def test_context_for_identity_account_url(self):
        """Test context_for_identity() accepts AccountUrl."""
        url = AccountUrl("acc://my-adi.acme")
        ctx = context_for_identity(url)
        assert "my-adi.acme" in ctx.principal

    def test_context_for_lite_account(self):
        """Test context_for_lite_account() helper."""
        ctx = context_for_lite_account("acc://1234567890abcdef/ACME", memo="Lite op")
        assert ctx.memo == "Lite op"

    def test_context_for_lite_account_accepts_url(self):
        """Test context_for_lite_account() accepts AccountUrl."""
        url = AccountUrl("acc://1234567890abcdef/ACME")
        ctx = context_for_lite_account(url)
        assert "/ACME" in ctx.principal or "ACME" in ctx.principal


class TestGoParity:
    """Tests to verify Go protocol parity."""

    def test_header_dict_go_field_names(self):
        """Test to_header_dict uses Go camelCase field names."""
        ctx = BuildContext(
            principal="acc://test.acme",
            hold_until=HoldUntilOptions.at_block(1000)
        )
        d = ctx.to_header_dict()
        # Go uses "holdUntil" not "hold_until"
        assert "holdUntil" in d
        # Go uses "minorBlock" in HoldUntilOptions
        assert "minorBlock" in d["holdUntil"]

    def test_envelope_structure_go_compatible(self):
        """Test envelope structure matches Go format."""
        ctx = BuildContext(
            principal="acc://test.acme",
            timestamp=1700000000000000000
        )
        body = {"type": "sendTokens"}
        envelope = ctx.build_envelope(body)

        # Go envelope has "header" and "body" top-level keys
        assert "header" in envelope
        assert "body" in envelope
        # Go header has "principal" not "origin"
        assert "principal" in envelope["header"]

    def test_signed_envelope_structure_go_compatible(self):
        """Test signed envelope structure matches Go format."""
        ctx = BuildContext(principal="acc://test.acme")
        body = {"type": "sendTokens"}
        sig = {"type": "ed25519", "signature": "abc"}
        envelope = ctx.build_signed_envelope(body, sig)

        # Go signed envelope has "transaction" and "signatures"
        assert "transaction" in envelope
        assert "signatures" in envelope
        assert isinstance(envelope["signatures"], list)

    def test_metadata_hex_encoding(self):
        """Test metadata is hex encoded like Go."""
        ctx = BuildContext(
            principal="acc://test.acme",
            metadata=b"\x01\x02\x03"
        )
        d = ctx.to_header_dict()
        assert d["metadata"] == "010203"

    def test_initiator_hex_encoding(self):
        """Test initiator is hex encoded like Go."""
        ctx = BuildContext(
            principal="acc://test.acme",
            initiator=bytes(32)
        )
        d = ctx.to_header_dict()
        assert d["initiator"] == "00" * 32

    def test_timestamp_nanoseconds(self):
        """Test timestamp is in nanoseconds like Go."""
        ctx = BuildContext(principal="acc://test.acme")
        # Go uses uint64 nanoseconds since epoch
        # Should be approximately current time in nanoseconds
        assert ctx.timestamp > 1700000000000000000  # After 2023-11-14


class TestChainedOperations:
    """Tests for fluent/chained operations."""

    def test_chained_with_methods(self):
        """Test chaining multiple with_* methods."""
        ctx = (BuildContext.now("acc://test.acme")
               .with_memo("Test")
               .with_expire(ExpireOptions.from_duration(hours=1))
               .with_hold_until(HoldUntilOptions.at_block(1000))
               .add_authority("acc://auth1.acme")
               .add_authority("acc://auth2.acme"))

        assert ctx.memo == "Test"
        assert ctx.expire is not None
        assert ctx.hold_until.minor_block == 1000
        assert len(ctx.authorities) == 2

    def test_original_unchanged_after_chain(self):
        """Test original context unchanged after chain operations."""
        original = BuildContext.now("acc://test.acme")
        modified = original.with_memo("Test").with_metadata(b"\x01")

        assert original.memo is None
        assert original.metadata is None
        assert modified.memo == "Test"
        assert modified.metadata == b"\x01"
