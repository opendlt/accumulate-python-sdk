"""
Unit tests for voting helpers (Phase 6).

Tests build_vote functions, VoteCollector, and vote analysis helpers
for multi-signature transaction support with Go/Dart SDK parity.
"""

import pytest
import json
from hashlib import sha256
from unittest.mock import Mock, MagicMock

from accumulate_client.tx.voting import (
    canonical_json,
    compute_transaction_hash,
    build_vote,
    build_accept_vote,
    build_reject_vote,
    build_abstain_vote,
    build_suggest_vote,
    VoteCollector,
    is_accepting_vote,
    is_rejecting_vote,
    parse_vote_type,
    check_threshold,
    check_rejection_threshold,
    extract_vote_from_signature,
    get_signature_signer,
    analyze_signatures,
)
from accumulate_client.tx.context import BuildContext
from accumulate_client.enums import VoteType


# =============================================================================
# Test Fixtures
# =============================================================================

class MockSigner:
    """Mock signer for testing without real crypto."""

    def __init__(self, url="acc://test.acme/page", public_key=None):
        self._url = url
        self._public_key = public_key or b"\x01" * 32
        self._signer_version = 1

    def get_signer_url(self):
        return self._url

    def get_public_key(self):
        return self._public_key

    def get_signer_version(self):
        return self._signer_version

    def sign(self, digest):
        # Return mock signature
        return b"\xab" * 64

    def to_accumulate_signature(self, digest, **kwargs):
        # Use provided signer_url if given, otherwise use default
        effective_signer_url = kwargs.get("signer_url", self._url)
        vote = kwargs.get("vote", VoteType.ACCEPT)
        vote_str = vote.name.lower() if hasattr(vote, "name") else str(vote).lower()
        return {
            "type": "ed25519",
            "publicKey": self._public_key.hex(),
            "signature": self.sign(digest).hex(),
            "signer": effective_signer_url,
            "signerVersion": kwargs.get("signer_version", 1),
            "timestamp": kwargs.get("timestamp", 1700000000000000000),
            "vote": vote_str,
        }


@pytest.fixture
def mock_signer():
    """Create a mock signer."""
    return MockSigner()


@pytest.fixture
def mock_signers():
    """Create multiple mock signers."""
    return [
        MockSigner(url="acc://test.acme/page1", public_key=b"\x01" * 32),
        MockSigner(url="acc://test.acme/page2", public_key=b"\x02" * 32),
        MockSigner(url="acc://test.acme/page3", public_key=b"\x03" * 32),
    ]


@pytest.fixture
def build_ctx():
    """Create a BuildContext for testing."""
    return BuildContext(
        principal="acc://test.acme",
        timestamp=1700000000000000000
    )


@pytest.fixture
def sample_body():
    """Create a sample transaction body."""
    return {
        "type": "sendTokens",
        "to": [{"url": "acc://recipient.acme", "amount": 100}]
    }


# =============================================================================
# Test canonical_json
# =============================================================================

class TestCanonicalJson:
    """Tests for canonical_json function."""

    def test_simple_object(self):
        """Test encoding simple object."""
        obj = {"b": 2, "a": 1}
        result = canonical_json(obj)
        # Keys should be sorted
        assert result == b'{"a":1,"b":2}'

    def test_nested_object(self):
        """Test encoding nested object."""
        obj = {"outer": {"z": 3, "a": 1}}
        result = canonical_json(obj)
        assert b'"outer"' in result
        assert b'"a":1' in result

    def test_no_whitespace(self):
        """Test no whitespace in output."""
        obj = {"key": "value", "list": [1, 2, 3]}
        result = canonical_json(obj)
        assert b" " not in result
        assert b"\n" not in result

    def test_utf8_encoding(self):
        """Test result is UTF-8 encoded."""
        obj = {"key": "value"}
        result = canonical_json(obj)
        assert isinstance(result, bytes)
        assert result.decode("utf-8") == '{"key":"value"}'

    def test_deterministic(self):
        """Test result is deterministic."""
        obj = {"z": 1, "a": 2, "m": 3}
        result1 = canonical_json(obj)
        result2 = canonical_json(obj)
        assert result1 == result2


class TestComputeTransactionHash:
    """Tests for compute_transaction_hash function."""

    def test_basic_hash(self):
        """Test computing hash of transaction."""
        transaction = {
            "header": {"principal": "acc://test.acme", "timestamp": 1700000000000000000},
            "body": {"type": "sendTokens"}
        }
        result = compute_transaction_hash(transaction)
        assert isinstance(result, bytes)
        assert len(result) == 32  # SHA-256 produces 32 bytes

    def test_deterministic(self):
        """Test hash is deterministic."""
        transaction = {"header": {"principal": "acc://test.acme"}, "body": {"type": "test"}}
        hash1 = compute_transaction_hash(transaction)
        hash2 = compute_transaction_hash(transaction)
        assert hash1 == hash2

    def test_different_transactions(self):
        """Test different transactions produce different hashes."""
        tx1 = {"header": {"principal": "acc://test1.acme"}, "body": {"type": "test"}}
        tx2 = {"header": {"principal": "acc://test2.acme"}, "body": {"type": "test"}}
        assert compute_transaction_hash(tx1) != compute_transaction_hash(tx2)

    def test_hash_matches_manual(self):
        """Test hash matches manual SHA-256 computation."""
        transaction = {"a": 1}
        expected = sha256(b'{"a":1}').digest()
        assert compute_transaction_hash(transaction) == expected


# =============================================================================
# Test build_vote functions
# =============================================================================

class TestBuildVote:
    """Tests for build_vote function."""

    def test_basic_vote(self, build_ctx, sample_body, mock_signer):
        """Test building a basic vote."""
        envelope = build_vote(build_ctx, sample_body, mock_signer, VoteType.ACCEPT)

        assert "transaction" in envelope
        assert "signatures" in envelope
        assert len(envelope["signatures"]) == 1
        assert envelope["signatures"][0]["vote"] == "accept"

    def test_vote_accept(self, build_ctx, sample_body, mock_signer):
        """Test ACCEPT vote."""
        envelope = build_vote(build_ctx, sample_body, mock_signer, VoteType.ACCEPT)
        assert envelope["signatures"][0]["vote"] == "accept"

    def test_vote_reject(self, build_ctx, sample_body, mock_signer):
        """Test REJECT vote."""
        envelope = build_vote(build_ctx, sample_body, mock_signer, VoteType.REJECT)
        assert envelope["signatures"][0]["vote"] == "reject"

    def test_vote_abstain(self, build_ctx, sample_body, mock_signer):
        """Test ABSTAIN vote."""
        envelope = build_vote(build_ctx, sample_body, mock_signer, VoteType.ABSTAIN)
        assert envelope["signatures"][0]["vote"] == "abstain"

    def test_vote_suggest(self, build_ctx, sample_body, mock_signer):
        """Test SUGGEST vote."""
        envelope = build_vote(build_ctx, sample_body, mock_signer, VoteType.SUGGEST)
        assert envelope["signatures"][0]["vote"] == "suggest"

    def test_with_signer_url(self, build_ctx, sample_body, mock_signer):
        """Test providing custom signer URL."""
        envelope = build_vote(
            build_ctx, sample_body, mock_signer, VoteType.ACCEPT,
            signer_url="acc://custom.acme/page"
        )
        assert envelope["signatures"][0]["signer"] == "acc://custom.acme/page"

    def test_with_signer_version(self, build_ctx, sample_body, mock_signer):
        """Test providing signer version."""
        envelope = build_vote(
            build_ctx, sample_body, mock_signer, VoteType.ACCEPT,
            signer_version=2
        )
        assert envelope["signatures"][0]["signerVersion"] == 2

    def test_with_memo(self, build_ctx, sample_body, mock_signer):
        """Test providing signature memo."""
        envelope = build_vote(
            build_ctx, sample_body, mock_signer, VoteType.REJECT,
            memo="Insufficient funds"
        )
        # Memo should be in signature if signer supports it
        # Note: Mock signer may or may not include memo
        assert "transaction" in envelope

    def test_transaction_structure(self, build_ctx, sample_body, mock_signer):
        """Test transaction structure is correct."""
        envelope = build_vote(build_ctx, sample_body, mock_signer, VoteType.ACCEPT)

        tx = envelope["transaction"]
        assert "header" in tx
        assert "body" in tx
        assert tx["header"]["principal"] == "acc://test.acme"
        assert tx["body"]["type"] == "sendTokens"


class TestBuildAcceptVote:
    """Tests for build_accept_vote convenience function."""

    def test_basic(self, build_ctx, sample_body, mock_signer):
        """Test build_accept_vote creates ACCEPT vote."""
        envelope = build_accept_vote(build_ctx, sample_body, mock_signer)
        assert envelope["signatures"][0]["vote"] == "accept"

    def test_with_options(self, build_ctx, sample_body, mock_signer):
        """Test build_accept_vote with options."""
        envelope = build_accept_vote(
            build_ctx, sample_body, mock_signer,
            signer_url="acc://custom.acme",
            signer_version=2,
            memo="Approved"
        )
        assert envelope["signatures"][0]["signer"] == "acc://custom.acme"


class TestBuildRejectVote:
    """Tests for build_reject_vote convenience function."""

    def test_basic(self, build_ctx, sample_body, mock_signer):
        """Test build_reject_vote creates REJECT vote."""
        envelope = build_reject_vote(build_ctx, sample_body, mock_signer)
        assert envelope["signatures"][0]["vote"] == "reject"


class TestBuildAbstainVote:
    """Tests for build_abstain_vote convenience function."""

    def test_basic(self, build_ctx, sample_body, mock_signer):
        """Test build_abstain_vote creates ABSTAIN vote."""
        envelope = build_abstain_vote(build_ctx, sample_body, mock_signer)
        assert envelope["signatures"][0]["vote"] == "abstain"


class TestBuildSuggestVote:
    """Tests for build_suggest_vote convenience function."""

    def test_basic(self, build_ctx, sample_body, mock_signer):
        """Test build_suggest_vote creates SUGGEST vote."""
        envelope = build_suggest_vote(build_ctx, sample_body, mock_signer)
        assert envelope["signatures"][0]["vote"] == "suggest"


# =============================================================================
# Test VoteCollector
# =============================================================================

class TestVoteCollector:
    """Tests for VoteCollector class."""

    def test_init(self, build_ctx, sample_body):
        """Test VoteCollector initialization."""
        collector = VoteCollector(build_ctx, sample_body)

        assert collector.ctx == build_ctx
        assert collector.body == sample_body
        assert collector.transaction is not None
        assert len(collector.transaction_hash) == 32
        assert len(collector.signatures) == 0

    def test_init_with_hash(self, build_ctx, sample_body):
        """Test VoteCollector with pre-computed hash."""
        custom_hash = bytes(32)
        collector = VoteCollector(build_ctx, sample_body, transaction_hash=custom_hash)
        assert collector.transaction_hash == custom_hash

    def test_add_vote(self, build_ctx, sample_body, mock_signer):
        """Test adding a vote."""
        collector = VoteCollector(build_ctx, sample_body)
        collector.add_vote(mock_signer, VoteType.ACCEPT)

        assert len(collector.signatures) == 1
        assert collector.signatures[0]["vote"] == "accept"

    def test_add_accept(self, build_ctx, sample_body, mock_signer):
        """Test add_accept convenience method."""
        collector = VoteCollector(build_ctx, sample_body)
        collector.add_accept(mock_signer)

        assert len(collector.signatures) == 1
        assert collector.signatures[0]["vote"] == "accept"

    def test_add_reject(self, build_ctx, sample_body, mock_signer):
        """Test add_reject convenience method."""
        collector = VoteCollector(build_ctx, sample_body)
        collector.add_reject(mock_signer)

        assert collector.signatures[0]["vote"] == "reject"

    def test_add_abstain(self, build_ctx, sample_body, mock_signer):
        """Test add_abstain convenience method."""
        collector = VoteCollector(build_ctx, sample_body)
        collector.add_abstain(mock_signer)

        assert collector.signatures[0]["vote"] == "abstain"

    def test_add_suggest(self, build_ctx, sample_body, mock_signer):
        """Test add_suggest convenience method."""
        collector = VoteCollector(build_ctx, sample_body)
        collector.add_suggest(mock_signer)

        assert collector.signatures[0]["vote"] == "suggest"

    def test_chaining(self, build_ctx, sample_body, mock_signers):
        """Test method chaining."""
        collector = VoteCollector(build_ctx, sample_body)
        result = (collector
                  .add_accept(mock_signers[0])
                  .add_accept(mock_signers[1])
                  .add_reject(mock_signers[2]))

        assert result is collector
        assert len(collector.signatures) == 3

    def test_accept_count(self, build_ctx, sample_body, mock_signers):
        """Test accept_count property."""
        collector = VoteCollector(build_ctx, sample_body)
        collector.add_accept(mock_signers[0])
        collector.add_accept(mock_signers[1])
        collector.add_reject(mock_signers[2])

        assert collector.accept_count == 2

    def test_reject_count(self, build_ctx, sample_body, mock_signers):
        """Test reject_count property."""
        collector = VoteCollector(build_ctx, sample_body)
        collector.add_accept(mock_signers[0])
        collector.add_reject(mock_signers[1])
        collector.add_reject(mock_signers[2])

        assert collector.reject_count == 2

    def test_abstain_count(self, build_ctx, sample_body, mock_signers):
        """Test abstain_count property."""
        collector = VoteCollector(build_ctx, sample_body)
        collector.add_abstain(mock_signers[0])
        collector.add_abstain(mock_signers[1])

        assert collector.abstain_count == 2

    def test_suggest_count(self, build_ctx, sample_body, mock_signers):
        """Test suggest_count property."""
        collector = VoteCollector(build_ctx, sample_body)
        collector.add_suggest(mock_signers[0])

        assert collector.suggest_count == 1

    def test_total_votes(self, build_ctx, sample_body, mock_signers):
        """Test total_votes property."""
        collector = VoteCollector(build_ctx, sample_body)
        collector.add_accept(mock_signers[0])
        collector.add_reject(mock_signers[1])
        collector.add_abstain(mock_signers[2])

        assert collector.total_votes == 3

    def test_get_vote(self, build_ctx, sample_body, mock_signer):
        """Test get_vote method."""
        collector = VoteCollector(build_ctx, sample_body)
        collector.add_accept(mock_signer)

        vote = collector.get_vote(mock_signer.get_signer_url())
        assert vote == VoteType.ACCEPT

    def test_get_vote_not_found(self, build_ctx, sample_body):
        """Test get_vote returns None for unknown signer."""
        collector = VoteCollector(build_ctx, sample_body)
        vote = collector.get_vote("acc://unknown.acme")
        assert vote is None

    def test_has_voted(self, build_ctx, sample_body, mock_signer):
        """Test has_voted method."""
        collector = VoteCollector(build_ctx, sample_body)
        assert not collector.has_voted(mock_signer.get_signer_url())

        collector.add_accept(mock_signer)
        assert collector.has_voted(mock_signer.get_signer_url())

    def test_clear_votes(self, build_ctx, sample_body, mock_signers):
        """Test clear_votes method."""
        collector = VoteCollector(build_ctx, sample_body)
        collector.add_accept(mock_signers[0])
        collector.add_accept(mock_signers[1])

        result = collector.clear_votes()
        assert result is collector
        assert len(collector.signatures) == 0
        assert collector.total_votes == 0

    def test_build_envelope(self, build_ctx, sample_body, mock_signers):
        """Test build_envelope method."""
        collector = VoteCollector(build_ctx, sample_body)
        collector.add_accept(mock_signers[0])
        collector.add_accept(mock_signers[1])

        envelope = collector.build_envelope()
        assert "transaction" in envelope
        assert "signatures" in envelope
        assert len(envelope["signatures"]) == 2

    def test_get_vote_summary(self, build_ctx, sample_body, mock_signers):
        """Test get_vote_summary method."""
        collector = VoteCollector(build_ctx, sample_body)
        collector.add_accept(mock_signers[0])
        collector.add_accept(mock_signers[1])
        collector.add_reject(mock_signers[2])

        summary = collector.get_vote_summary()
        assert summary["total"] == 3
        assert summary["accept"] == 2
        assert summary["reject"] == 1
        assert summary["abstain"] == 0
        assert summary["suggest"] == 0
        assert len(summary["voters"]) == 3

    def test_transaction_hash_in_signature(self, build_ctx, sample_body, mock_signer):
        """Test transaction hash is included in signature."""
        collector = VoteCollector(build_ctx, sample_body)
        collector.add_accept(mock_signer)

        assert "transactionHash" in collector.signatures[0]
        assert collector.signatures[0]["transactionHash"] == collector.transaction_hash.hex()


# =============================================================================
# Test vote validation helpers
# =============================================================================

class TestIsAcceptingVote:
    """Tests for is_accepting_vote function."""

    def test_vote_type_accept(self):
        """Test with VoteType.ACCEPT."""
        assert is_accepting_vote(VoteType.ACCEPT) is True

    def test_vote_type_reject(self):
        """Test with VoteType.REJECT."""
        assert is_accepting_vote(VoteType.REJECT) is False

    def test_string_accept(self):
        """Test with string 'accept'."""
        assert is_accepting_vote("accept") is True
        assert is_accepting_vote("ACCEPT") is True

    def test_string_reject(self):
        """Test with string 'reject'."""
        assert is_accepting_vote("reject") is False

    def test_int_accept(self):
        """Test with integer 0 (ACCEPT)."""
        assert is_accepting_vote(0) is True

    def test_int_reject(self):
        """Test with integer 1 (REJECT)."""
        assert is_accepting_vote(1) is False


class TestIsRejectingVote:
    """Tests for is_rejecting_vote function."""

    def test_vote_type_reject(self):
        """Test with VoteType.REJECT."""
        assert is_rejecting_vote(VoteType.REJECT) is True

    def test_vote_type_accept(self):
        """Test with VoteType.ACCEPT."""
        assert is_rejecting_vote(VoteType.ACCEPT) is False

    def test_string_reject(self):
        """Test with string 'reject'."""
        assert is_rejecting_vote("reject") is True
        assert is_rejecting_vote("REJECT") is True

    def test_int_reject(self):
        """Test with integer 1 (REJECT)."""
        assert is_rejecting_vote(1) is True


class TestParseVoteType:
    """Tests for parse_vote_type function."""

    def test_parse_vote_type(self):
        """Test parsing VoteType enum."""
        assert parse_vote_type(VoteType.ACCEPT) == VoteType.ACCEPT
        assert parse_vote_type(VoteType.REJECT) == VoteType.REJECT

    def test_parse_string(self):
        """Test parsing string."""
        assert parse_vote_type("accept") == VoteType.ACCEPT
        assert parse_vote_type("REJECT") == VoteType.REJECT
        assert parse_vote_type("Abstain") == VoteType.ABSTAIN
        assert parse_vote_type("suggest") == VoteType.SUGGEST

    def test_parse_int(self):
        """Test parsing integer."""
        assert parse_vote_type(0) == VoteType.ACCEPT
        assert parse_vote_type(1) == VoteType.REJECT
        assert parse_vote_type(2) == VoteType.ABSTAIN
        assert parse_vote_type(3) == VoteType.SUGGEST

    def test_parse_invalid_string(self):
        """Test parsing invalid string raises ValueError."""
        with pytest.raises(ValueError, match="Unknown vote type"):
            parse_vote_type("invalid")

    def test_parse_invalid_type(self):
        """Test parsing invalid type raises ValueError."""
        with pytest.raises(ValueError):
            parse_vote_type([])


class TestCheckThreshold:
    """Tests for check_threshold function."""

    def test_threshold_met(self):
        """Test threshold is met."""
        assert check_threshold(accept_count=2, total_keys=3, threshold=2) is True

    def test_threshold_not_met(self):
        """Test threshold is not met."""
        assert check_threshold(accept_count=1, total_keys=3, threshold=2) is False

    def test_threshold_exact(self):
        """Test exact threshold match."""
        assert check_threshold(accept_count=2, total_keys=3, threshold=2) is True

    def test_threshold_exceeded(self):
        """Test threshold exceeded."""
        assert check_threshold(accept_count=3, total_keys=3, threshold=2) is True


class TestCheckRejectionThreshold:
    """Tests for check_rejection_threshold function."""

    def test_rejection_threshold_met(self):
        """Test rejection threshold is met."""
        assert check_rejection_threshold(reject_count=2, total_keys=3, threshold=2) is True

    def test_rejection_threshold_not_met(self):
        """Test rejection threshold is not met."""
        assert check_rejection_threshold(reject_count=1, total_keys=3, threshold=2) is False


# =============================================================================
# Test signature analysis
# =============================================================================

class TestExtractVoteFromSignature:
    """Tests for extract_vote_from_signature function."""

    def test_extract_accept(self):
        """Test extracting ACCEPT vote."""
        sig = {"vote": "accept", "signer": "acc://test.acme"}
        assert extract_vote_from_signature(sig) == VoteType.ACCEPT

    def test_extract_reject(self):
        """Test extracting REJECT vote."""
        sig = {"vote": "reject", "signer": "acc://test.acme"}
        assert extract_vote_from_signature(sig) == VoteType.REJECT

    def test_extract_int_vote(self):
        """Test extracting integer vote."""
        sig = {"vote": 0, "signer": "acc://test.acme"}
        assert extract_vote_from_signature(sig) == VoteType.ACCEPT

    def test_no_vote_field(self):
        """Test when vote field is missing."""
        sig = {"signer": "acc://test.acme"}
        assert extract_vote_from_signature(sig) is None

    def test_invalid_vote(self):
        """Test with invalid vote value."""
        sig = {"vote": "invalid", "signer": "acc://test.acme"}
        assert extract_vote_from_signature(sig) is None


class TestGetSignatureSigner:
    """Tests for get_signature_signer function."""

    def test_get_signer(self):
        """Test getting signer URL."""
        sig = {"signer": "acc://test.acme/page"}
        assert get_signature_signer(sig) == "acc://test.acme/page"

    def test_no_signer(self):
        """Test when signer field is missing."""
        sig = {"vote": "accept"}
        assert get_signature_signer(sig) is None


class TestAnalyzeSignatures:
    """Tests for analyze_signatures function."""

    def test_analyze_mixed(self):
        """Test analyzing mixed votes."""
        signatures = [
            {"vote": "accept", "signer": "acc://signer1.acme"},
            {"vote": "accept", "signer": "acc://signer2.acme"},
            {"vote": "reject", "signer": "acc://signer3.acme"},
            {"vote": "abstain", "signer": "acc://signer4.acme"},
        ]
        result = analyze_signatures(signatures)

        assert result["accept"]["count"] == 2
        assert result["reject"]["count"] == 1
        assert result["abstain"]["count"] == 1
        assert result["suggest"]["count"] == 0
        assert result["total"] == 4

    def test_analyze_signers(self):
        """Test signers are included in analysis."""
        signatures = [
            {"vote": "accept", "signer": "acc://signer1.acme"},
            {"vote": "accept", "signer": "acc://signer2.acme"},
        ]
        result = analyze_signatures(signatures)

        assert "acc://signer1.acme" in result["accept"]["signers"]
        assert "acc://signer2.acme" in result["accept"]["signers"]

    def test_analyze_unknown_votes(self):
        """Test signatures without vote are tracked as unknown."""
        signatures = [
            {"vote": "accept", "signer": "acc://signer1.acme"},
            {"signer": "acc://signer2.acme"},  # No vote field
        ]
        result = analyze_signatures(signatures)

        assert result["accept"]["count"] == 1
        assert result["unknown"]["count"] == 1

    def test_analyze_empty(self):
        """Test analyzing empty list."""
        result = analyze_signatures([])

        assert result["total"] == 0
        assert result["accept"]["count"] == 0


# =============================================================================
# Test Go/Dart parity
# =============================================================================

class TestGoParity:
    """Tests to verify Go protocol parity."""

    def test_vote_type_values(self):
        """Test VoteType enum values match Go."""
        # Go: VoteTypeAccept = 0, VoteTypeReject = 1, VoteTypeAbstain = 2, VoteTypeSuggest = 3
        assert VoteType.ACCEPT.value == 0
        assert VoteType.REJECT.value == 1
        assert VoteType.ABSTAIN.value == 2
        assert VoteType.SUGGEST.value == 3

    def test_vote_lowercase_in_json(self, build_ctx, sample_body, mock_signer):
        """Test votes are lowercase in JSON like Go."""
        envelope = build_vote(build_ctx, sample_body, mock_signer, VoteType.ACCEPT)
        # Go serializes as lowercase: "accept", "reject", etc.
        assert envelope["signatures"][0]["vote"] == "accept"

    def test_envelope_structure(self, build_ctx, sample_body, mock_signer):
        """Test envelope structure matches Go format."""
        envelope = build_vote(build_ctx, sample_body, mock_signer, VoteType.ACCEPT)

        # Go envelope has "transaction" and "signatures"
        assert "transaction" in envelope
        assert "signatures" in envelope
        assert isinstance(envelope["signatures"], list)

    def test_transaction_hash_hex(self, build_ctx, sample_body, mock_signer):
        """Test transaction hash is hex encoded like Go."""
        collector = VoteCollector(build_ctx, sample_body)
        collector.add_accept(mock_signer)

        tx_hash = collector.signatures[0].get("transactionHash")
        # Go encodes as hex string
        assert isinstance(tx_hash, str)
        assert len(tx_hash) == 64  # 32 bytes * 2 hex chars


class TestMultiSigScenarios:
    """Integration tests for multi-signature scenarios."""

    def test_2_of_3_approval(self, build_ctx, sample_body, mock_signers):
        """Test 2-of-3 approval scenario."""
        collector = VoteCollector(build_ctx, sample_body)
        collector.add_accept(mock_signers[0])
        collector.add_accept(mock_signers[1])
        collector.add_reject(mock_signers[2])

        # Check threshold met (2 of 3)
        assert check_threshold(collector.accept_count, total_keys=3, threshold=2)
        # Check not rejected (would need 2 rejects for rejection threshold of 2)
        assert not check_rejection_threshold(collector.reject_count, total_keys=3, threshold=2)

    def test_unanimous_approval(self, build_ctx, sample_body, mock_signers):
        """Test unanimous approval scenario."""
        collector = VoteCollector(build_ctx, sample_body)
        for signer in mock_signers:
            collector.add_accept(signer)

        assert collector.accept_count == 3
        assert collector.reject_count == 0
        assert check_threshold(collector.accept_count, total_keys=3, threshold=3)

    def test_unanimous_rejection(self, build_ctx, sample_body, mock_signers):
        """Test unanimous rejection scenario."""
        collector = VoteCollector(build_ctx, sample_body)
        for signer in mock_signers:
            collector.add_reject(signer)

        assert collector.accept_count == 0
        assert collector.reject_count == 3
        assert check_rejection_threshold(collector.reject_count, total_keys=3, threshold=2)

    def test_mixed_votes_no_consensus(self, build_ctx, sample_body, mock_signers):
        """Test mixed votes with no consensus."""
        collector = VoteCollector(build_ctx, sample_body)
        collector.add_accept(mock_signers[0])
        collector.add_reject(mock_signers[1])
        collector.add_abstain(mock_signers[2])

        # Neither threshold met with threshold=2
        assert not check_threshold(collector.accept_count, total_keys=3, threshold=2)
        assert not check_rejection_threshold(collector.reject_count, total_keys=3, threshold=2)
