"""
Unit tests for V3 API options classes.

Tests all option types and query types for correct serialization
and validation matching Go API v3 specifications.
"""

import pytest
from pydantic import ValidationError

from accumulate_client.v3.options import (
    # Base options
    RangeOptions,
    ReceiptOptions,
    # Submit/validate/faucet options
    SubmitOptions,
    ValidateOptions,
    FaucetOptions,
    # Query options
    QueryOptions,
    # Query types
    DefaultQuery,
    ChainQuery,
    DataQuery,
    DirectoryQuery,
    PendingQuery,
    BlockQuery,
    AnchorSearchQuery,
    PublicKeySearchQuery,
    PublicKeyHashSearchQuery,
    DelegateSearchQuery,
    MessageHashSearchQuery,
    # Service options
    NodeInfoOptions,
    ServiceAddress,
    FindServiceOptions,
    ConsensusStatusOptions,
    NetworkStatusOptions,
    MetricsOptions,
)


# =============================================================================
# RangeOptions Tests
# =============================================================================

class TestRangeOptions:
    """Tests for RangeOptions class."""

    def test_default_values(self):
        """Test default RangeOptions values."""
        opts = RangeOptions()
        assert opts.start == 0
        assert opts.count is None
        assert opts.expand is None
        assert opts.from_end is False

    def test_with_values(self):
        """Test RangeOptions with all values."""
        opts = RangeOptions(start=10, count=20, expand=True, from_end=True)
        assert opts.start == 10
        assert opts.count == 20
        assert opts.expand is True
        assert opts.from_end is True

    def test_to_dict_minimal(self):
        """Test to_dict with minimal values."""
        opts = RangeOptions()
        d = opts.to_dict()
        assert d == {"start": 0}

    def test_to_dict_full(self):
        """Test to_dict with all values."""
        opts = RangeOptions(start=5, count=10, expand=True, from_end=True)
        d = opts.to_dict()
        assert d["start"] == 5
        assert d["count"] == 10
        assert d["expand"] is True
        assert d["fromEnd"] is True

    def test_alias_from_end(self):
        """Test fromEnd alias works."""
        opts = RangeOptions(fromEnd=True)
        assert opts.from_end is True

    def test_validation_negative_start(self):
        """Test validation rejects negative start."""
        with pytest.raises(ValidationError):
            RangeOptions(start=-1)

    def test_validation_zero_count(self):
        """Test validation rejects zero count."""
        with pytest.raises(ValidationError):
            RangeOptions(count=0)


# =============================================================================
# ReceiptOptions Tests
# =============================================================================

class TestReceiptOptions:
    """Tests for ReceiptOptions class."""

    def test_default_values(self):
        """Test default ReceiptOptions values."""
        opts = ReceiptOptions()
        assert opts.for_any is False
        assert opts.for_height is None

    def test_for_any(self):
        """Test for_any option."""
        opts = ReceiptOptions(for_any=True)
        d = opts.to_dict()
        assert d["forAny"] is True

    def test_for_height(self):
        """Test for_height option."""
        opts = ReceiptOptions(for_height=1000)
        d = opts.to_dict()
        assert d["forHeight"] == 1000

    def test_aliases(self):
        """Test JSON aliases work."""
        opts = ReceiptOptions(forAny=True, forHeight=500)
        assert opts.for_any is True
        assert opts.for_height == 500


# =============================================================================
# Submit/Validate/Faucet Options Tests
# =============================================================================

class TestSubmitOptions:
    """Tests for SubmitOptions class."""

    def test_default_values(self):
        """Test default SubmitOptions values."""
        opts = SubmitOptions()
        assert opts.verify is None
        assert opts.wait is None

    def test_with_values(self):
        """Test SubmitOptions with values."""
        opts = SubmitOptions(verify=True, wait=False)
        assert opts.verify is True
        assert opts.wait is False

    def test_to_dict(self):
        """Test to_dict output."""
        opts = SubmitOptions(verify=True, wait=True)
        d = opts.to_dict()
        assert d["verify"] is True
        assert d["wait"] is True

    def test_to_dict_empty(self):
        """Test to_dict with no values."""
        opts = SubmitOptions()
        d = opts.to_dict()
        assert d == {}


class TestValidateOptions:
    """Tests for ValidateOptions class."""

    def test_default_values(self):
        """Test default ValidateOptions values."""
        opts = ValidateOptions()
        assert opts.full is None

    def test_to_dict(self):
        """Test to_dict output."""
        opts = ValidateOptions(full=True)
        d = opts.to_dict()
        assert d["full"] is True


class TestFaucetOptions:
    """Tests for FaucetOptions class."""

    def test_default_values(self):
        """Test default FaucetOptions values."""
        opts = FaucetOptions()
        assert opts.token is None

    def test_to_dict(self):
        """Test to_dict output."""
        opts = FaucetOptions(token="acc://ACME")
        d = opts.to_dict()
        assert d["token"] == "acc://ACME"


# =============================================================================
# QueryOptions Tests
# =============================================================================

class TestQueryOptions:
    """Tests for QueryOptions class."""

    def test_default_values(self):
        """Test default QueryOptions values."""
        opts = QueryOptions()
        assert opts.expand is None
        assert opts.height is None
        assert opts.include_remote is None
        assert opts.prove is None
        assert opts.scratch is None

    def test_with_values(self):
        """Test QueryOptions with all values."""
        opts = QueryOptions(
            expand=True,
            height=1000,
            include_remote=True,
            prove=True,
            scratch=False
        )
        assert opts.expand is True
        assert opts.height == 1000
        assert opts.include_remote is True
        assert opts.prove is True
        assert opts.scratch is False

    def test_to_dict(self):
        """Test to_dict output."""
        opts = QueryOptions(expand=True, prove=True)
        d = opts.to_dict()
        assert d["expand"] is True
        assert d["prove"] is True
        assert "height" not in d

    def test_alias_include_remote(self):
        """Test includeRemote alias."""
        opts = QueryOptions(includeRemote=True)
        assert opts.include_remote is True
        d = opts.to_dict()
        assert d["includeRemote"] is True


# =============================================================================
# Query Types Tests
# =============================================================================

class TestDefaultQuery:
    """Tests for DefaultQuery class."""

    def test_basic(self):
        """Test basic DefaultQuery."""
        query = DefaultQuery()
        d = query.to_dict()
        assert d["queryType"] == "default"

    def test_with_receipt(self):
        """Test with receipt options."""
        query = DefaultQuery(include_receipt=ReceiptOptions(for_any=True))
        d = query.to_dict()
        assert d["queryType"] == "default"
        assert d["includeReceipt"]["forAny"] is True


class TestChainQuery:
    """Tests for ChainQuery class."""

    def test_basic(self):
        """Test basic ChainQuery."""
        query = ChainQuery()
        d = query.to_dict()
        assert d["queryType"] == "chain"

    def test_with_name(self):
        """Test with chain name."""
        query = ChainQuery(name="main")
        d = query.to_dict()
        assert d["name"] == "main"

    def test_with_index(self):
        """Test with specific index."""
        query = ChainQuery(index=100)
        d = query.to_dict()
        assert d["index"] == 100

    def test_with_entry_bytes(self):
        """Test with entry as bytes."""
        entry = bytes(32)
        query = ChainQuery(entry=entry)
        d = query.to_dict()
        assert d["entry"] == "00" * 32

    def test_with_entry_hex(self):
        """Test with entry as hex string."""
        query = ChainQuery(entry="ab" * 32)
        d = query.to_dict()
        assert d["entry"] == "ab" * 32

    def test_with_range(self):
        """Test with range options."""
        query = ChainQuery(range=RangeOptions(start=0, count=10))
        d = query.to_dict()
        assert d["range"]["start"] == 0
        assert d["range"]["count"] == 10


class TestDataQuery:
    """Tests for DataQuery class."""

    def test_basic(self):
        """Test basic DataQuery."""
        query = DataQuery()
        d = query.to_dict()
        assert d["queryType"] == "data"

    def test_with_index(self):
        """Test with index."""
        query = DataQuery(index=5)
        d = query.to_dict()
        assert d["index"] == 5

    def test_with_entry(self):
        """Test with entry hash."""
        query = DataQuery(entry="ab" * 32)
        d = query.to_dict()
        assert d["entry"] == "ab" * 32


class TestDirectoryQuery:
    """Tests for DirectoryQuery class."""

    def test_basic(self):
        """Test basic DirectoryQuery."""
        query = DirectoryQuery()
        d = query.to_dict()
        assert d["queryType"] == "directory"

    def test_with_range(self):
        """Test with range."""
        query = DirectoryQuery(range=RangeOptions(start=0, count=20))
        d = query.to_dict()
        assert d["range"]["count"] == 20


class TestPendingQuery:
    """Tests for PendingQuery class."""

    def test_basic(self):
        """Test basic PendingQuery."""
        query = PendingQuery()
        d = query.to_dict()
        assert d["queryType"] == "pending"


class TestBlockQuery:
    """Tests for BlockQuery class."""

    def test_basic(self):
        """Test basic BlockQuery."""
        query = BlockQuery()
        d = query.to_dict()
        assert d["queryType"] == "block"

    def test_minor_block(self):
        """Test minor block query."""
        query = BlockQuery(minor=100)
        d = query.to_dict()
        assert d["minor"] == 100

    def test_major_block(self):
        """Test major block query."""
        query = BlockQuery(major=50)
        d = query.to_dict()
        assert d["major"] == 50

    def test_minor_range(self):
        """Test minor block range."""
        query = BlockQuery(minor_range=RangeOptions(start=0, count=10))
        d = query.to_dict()
        assert "minorRange" in d

    def test_omit_empty(self):
        """Test omit_empty flag."""
        query = BlockQuery(omit_empty=True)
        d = query.to_dict()
        assert d["omitEmpty"] is True


class TestAnchorSearchQuery:
    """Tests for AnchorSearchQuery class."""

    def test_with_bytes(self):
        """Test with anchor as bytes."""
        anchor = bytes(32)
        query = AnchorSearchQuery(anchor=anchor)
        d = query.to_dict()
        assert d["queryType"] == "anchor"
        assert d["anchor"] == "00" * 32

    def test_with_hex(self):
        """Test with anchor as hex."""
        query = AnchorSearchQuery(anchor="ab" * 32)
        d = query.to_dict()
        assert d["anchor"] == "ab" * 32


class TestPublicKeySearchQuery:
    """Tests for PublicKeySearchQuery class."""

    def test_basic(self):
        """Test basic public key search."""
        query = PublicKeySearchQuery(public_key=bytes(32), type="ed25519")
        d = query.to_dict()
        assert d["queryType"] == "publicKey"
        assert d["publicKey"] == "00" * 32
        assert d["type"] == "ed25519"

    def test_alias(self):
        """Test publicKey alias."""
        query = PublicKeySearchQuery(publicKey=bytes(32), type="rcd1")
        assert query.public_key == bytes(32)


class TestPublicKeyHashSearchQuery:
    """Tests for PublicKeyHashSearchQuery class."""

    def test_basic(self):
        """Test basic key hash search."""
        query = PublicKeyHashSearchQuery(public_key_hash=bytes(32))
        d = query.to_dict()
        assert d["queryType"] == "publicKeyHash"
        assert d["publicKeyHash"] == "00" * 32


class TestDelegateSearchQuery:
    """Tests for DelegateSearchQuery class."""

    def test_basic(self):
        """Test basic delegate search."""
        query = DelegateSearchQuery(delegate="acc://delegate.acme")
        d = query.to_dict()
        assert d["queryType"] == "delegate"
        assert d["delegate"] == "acc://delegate.acme"


class TestMessageHashSearchQuery:
    """Tests for MessageHashSearchQuery class."""

    def test_with_bytes(self):
        """Test with hash as bytes."""
        query = MessageHashSearchQuery(hash=bytes(32))
        d = query.to_dict()
        assert d["queryType"] == "messageHash"
        assert d["hash"] == "00" * 32

    def test_with_hex(self):
        """Test with hash as hex."""
        query = MessageHashSearchQuery(hash="ab" * 32)
        d = query.to_dict()
        assert d["hash"] == "ab" * 32

    def test_invalid_length(self):
        """Test validation rejects invalid length."""
        with pytest.raises(ValueError, match="32 bytes"):
            MessageHashSearchQuery(hash=bytes(16))


# =============================================================================
# Service Options Tests
# =============================================================================

class TestNodeInfoOptions:
    """Tests for NodeInfoOptions class."""

    def test_default(self):
        """Test default values."""
        opts = NodeInfoOptions()
        assert opts.peer_id is None

    def test_with_peer_id(self):
        """Test with peer ID."""
        opts = NodeInfoOptions(peer_id="12D3KooW...")
        d = opts.to_dict()
        assert d["peerID"] == "12D3KooW..."

    def test_alias(self):
        """Test peerID alias."""
        opts = NodeInfoOptions(peerID="test")
        assert opts.peer_id == "test"


class TestServiceAddress:
    """Tests for ServiceAddress class."""

    def test_basic(self):
        """Test basic service address."""
        addr = ServiceAddress(type="node")
        d = addr.to_dict()
        assert d["type"] == "node"

    def test_with_argument(self):
        """Test with argument."""
        addr = ServiceAddress(type="query", argument="Directory")
        d = addr.to_dict()
        assert d["type"] == "query"
        assert d["argument"] == "Directory"


class TestFindServiceOptions:
    """Tests for FindServiceOptions class."""

    def test_default(self):
        """Test default values."""
        opts = FindServiceOptions()
        d = opts.to_dict()
        assert d == {}

    def test_with_network(self):
        """Test with network."""
        opts = FindServiceOptions(network="MainNet")
        d = opts.to_dict()
        assert d["network"] == "MainNet"

    def test_with_service(self):
        """Test with service address."""
        service = ServiceAddress(type="node")
        opts = FindServiceOptions(service=service)
        d = opts.to_dict()
        assert d["service"]["type"] == "node"

    def test_with_timeout(self):
        """Test with timeout."""
        opts = FindServiceOptions(timeout=5.0)
        d = opts.to_dict()
        assert d["timeout"] == 5.0


class TestConsensusStatusOptions:
    """Tests for ConsensusStatusOptions class."""

    def test_required_fields(self):
        """Test required fields."""
        opts = ConsensusStatusOptions(node_id="node1", partition="Directory")
        d = opts.to_dict()
        assert d["nodeID"] == "node1"
        assert d["partition"] == "Directory"

    def test_with_includes(self):
        """Test with include flags."""
        opts = ConsensusStatusOptions(
            node_id="node1",
            partition="Directory",
            include_peers=True,
            include_accumulate=True
        )
        d = opts.to_dict()
        assert d["includePeers"] is True
        assert d["includeAccumulate"] is True


class TestNetworkStatusOptions:
    """Tests for NetworkStatusOptions class."""

    def test_basic(self):
        """Test basic network status options."""
        opts = NetworkStatusOptions(partition="Directory")
        d = opts.to_dict()
        assert d["partition"] == "Directory"


class TestMetricsOptions:
    """Tests for MetricsOptions class."""

    def test_basic(self):
        """Test basic metrics options."""
        opts = MetricsOptions(partition="Directory")
        d = opts.to_dict()
        assert d["partition"] == "Directory"

    def test_with_span(self):
        """Test with span."""
        opts = MetricsOptions(partition="Directory", span=100)
        d = opts.to_dict()
        assert d["span"] == 100


class TestListSnapshotsOptions:
    """Tests for ListSnapshotsOptions class."""

    def test_basic(self):
        """Test basic list snapshots options."""
        from accumulate_client.v3.options import ListSnapshotsOptions
        opts = ListSnapshotsOptions(node_id="node123", partition="Directory")
        d = opts.to_dict()
        assert d["nodeID"] == "node123"
        assert d["partition"] == "Directory"

    def test_alias(self):
        """Test nodeID alias."""
        from accumulate_client.v3.options import ListSnapshotsOptions
        opts = ListSnapshotsOptions(nodeID="node456", partition="BVN0")
        assert opts.node_id == "node456"
        d = opts.to_dict()
        assert d["nodeID"] == "node456"
        assert d["partition"] == "BVN0"

    def test_required_fields(self):
        """Test that both fields are required."""
        from accumulate_client.v3.options import ListSnapshotsOptions
        import pydantic
        with pytest.raises(pydantic.ValidationError):
            ListSnapshotsOptions(node_id="node123")  # Missing partition
        with pytest.raises(pydantic.ValidationError):
            ListSnapshotsOptions(partition="Directory")  # Missing node_id


class TestSubscribeOptions:
    """Tests for SubscribeOptions class."""

    def test_default(self):
        """Test default values."""
        from accumulate_client.v3.options import SubscribeOptions
        opts = SubscribeOptions()
        d = opts.to_dict()
        assert d == {}

    def test_with_partition(self):
        """Test with partition."""
        from accumulate_client.v3.options import SubscribeOptions
        opts = SubscribeOptions(partition="Directory")
        d = opts.to_dict()
        assert d["partition"] == "Directory"

    def test_with_account(self):
        """Test with account."""
        from accumulate_client.v3.options import SubscribeOptions
        opts = SubscribeOptions(account="acc://test.acme")
        d = opts.to_dict()
        assert d["account"] == "acc://test.acme"

    def test_with_both(self):
        """Test with both partition and account."""
        from accumulate_client.v3.options import SubscribeOptions
        opts = SubscribeOptions(partition="Directory", account="acc://test.acme")
        d = opts.to_dict()
        assert d["partition"] == "Directory"
        assert d["account"] == "acc://test.acme"


# =============================================================================
# Go Parity Tests
# =============================================================================

class TestGoParity:
    """Tests to verify Go API v3 field name parity."""

    def test_query_options_field_names(self):
        """Test QueryOptions uses Go field names."""
        opts = QueryOptions(include_remote=True)
        d = opts.to_dict()
        # Go uses camelCase: includeRemote
        assert "includeRemote" in d

    def test_range_options_field_names(self):
        """Test RangeOptions uses Go field names."""
        opts = RangeOptions(from_end=True)
        d = opts.to_dict()
        # Go uses camelCase: fromEnd
        assert "fromEnd" in d

    def test_consensus_status_field_names(self):
        """Test ConsensusStatusOptions uses Go field names."""
        opts = ConsensusStatusOptions(
            node_id="test",
            partition="Directory",
            include_peers=True,
            include_accumulate=True
        )
        d = opts.to_dict()
        # Go uses camelCase
        assert "nodeID" in d
        assert "includePeers" in d
        assert "includeAccumulate" in d

    def test_query_type_values(self):
        """Test queryType values match Go."""
        assert DefaultQuery().to_dict()["queryType"] == "default"
        assert ChainQuery().to_dict()["queryType"] == "chain"
        assert DataQuery().to_dict()["queryType"] == "data"
        assert DirectoryQuery().to_dict()["queryType"] == "directory"
        assert PendingQuery().to_dict()["queryType"] == "pending"
        assert BlockQuery().to_dict()["queryType"] == "block"
        assert AnchorSearchQuery(anchor=bytes(32)).to_dict()["queryType"] == "anchor"
        assert PublicKeySearchQuery(public_key=bytes(32), type="ed25519").to_dict()["queryType"] == "publicKey"
        assert PublicKeyHashSearchQuery(public_key_hash=bytes(32)).to_dict()["queryType"] == "publicKeyHash"
        assert DelegateSearchQuery(delegate="acc://test").to_dict()["queryType"] == "delegate"
        assert MessageHashSearchQuery(hash=bytes(32)).to_dict()["queryType"] == "messageHash"
