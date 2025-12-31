"""
V3 API option and query classes.

Provides typed options for all V3 API methods matching Go pkg/api/v3
and Dart SDK patterns for full API parity.

Reference: C:/Accumulate_Stuff/accumulate/pkg/api/v3/options.yml
Reference: C:/Accumulate_Stuff/accumulate/pkg/api/v3/queries.yml
"""

from __future__ import annotations
from typing import Optional, List, Union, Any, Dict
from pydantic import BaseModel, Field, field_validator
from enum import IntEnum


# =============================================================================
# Base Options Classes
# =============================================================================

class RangeOptions(BaseModel):
    """
    Options for paginated range queries.

    Used across multiple query types for specifying result ranges.
    Matches Go RangeOptions struct.
    """
    start: int = Field(default=0, ge=0, description="Starting index")
    count: Optional[int] = Field(default=None, ge=1, description="Number of results to return")
    expand: Optional[bool] = Field(default=None, description="Request expanded results")
    from_end: bool = Field(default=False, alias="fromEnd", description="Count from end instead of start")

    model_config = {"populate_by_name": True}

    def to_dict(self) -> Dict[str, Any]:
        """Convert to API-compatible dictionary."""
        result: Dict[str, Any] = {"start": self.start}
        if self.count is not None:
            result["count"] = self.count
        if self.expand is not None:
            result["expand"] = self.expand
        if self.from_end:
            result["fromEnd"] = self.from_end
        return result


class ReceiptOptions(BaseModel):
    """
    Options for including receipts in query results.

    Matches Go ReceiptOptions struct.
    """
    for_any: bool = Field(default=False, alias="forAny", description="Include receipt for any anchor")
    for_height: Optional[int] = Field(default=None, alias="forHeight", ge=0, description="Include receipt for specific height")

    model_config = {"populate_by_name": True}

    def to_dict(self) -> Dict[str, Any]:
        """Convert to API-compatible dictionary."""
        result: Dict[str, Any] = {}
        if self.for_any:
            result["forAny"] = self.for_any
        if self.for_height is not None:
            result["forHeight"] = self.for_height
        return result


# =============================================================================
# Submit/Validate/Faucet Options
# =============================================================================

class SubmitOptions(BaseModel):
    """
    Options for submit requests.

    Controls transaction submission behavior.
    Matches Go SubmitOptions struct.
    """
    verify: Optional[bool] = Field(
        default=None,
        description="Verify transaction before submitting (default: true)"
    )
    wait: Optional[bool] = Field(
        default=None,
        description="Wait for block acceptance or rejection (default: true)"
    )

    model_config = {"populate_by_name": True}

    def to_dict(self) -> Dict[str, Any]:
        """Convert to API-compatible dictionary."""
        result: Dict[str, Any] = {}
        if self.verify is not None:
            result["verify"] = self.verify
        if self.wait is not None:
            result["wait"] = self.wait
        return result


class ValidateOptions(BaseModel):
    """
    Options for validate requests.

    Controls transaction validation behavior.
    Matches Go ValidateOptions struct.
    """
    full: Optional[bool] = Field(
        default=None,
        description="Fully validate signatures and transactions (default: true)"
    )

    model_config = {"populate_by_name": True}

    def to_dict(self) -> Dict[str, Any]:
        """Convert to API-compatible dictionary."""
        result: Dict[str, Any] = {}
        if self.full is not None:
            result["full"] = self.full
        return result


class FaucetOptions(BaseModel):
    """
    Options for faucet requests.

    Controls faucet token distribution.
    Matches Go FaucetOptions struct.
    """
    token: Optional[str] = Field(
        default=None,
        description="Token URL to use (default: ACME)"
    )

    model_config = {"populate_by_name": True}

    def to_dict(self) -> Dict[str, Any]:
        """Convert to API-compatible dictionary."""
        result: Dict[str, Any] = {}
        if self.token is not None:
            result["token"] = self.token
        return result


# =============================================================================
# Query Options
# =============================================================================

class QueryOptions(BaseModel):
    """
    General options for query requests.

    Provides common query parameters across query types.
    """
    expand: Optional[bool] = Field(
        default=None,
        description="Request expanded results with full record details"
    )
    height: Optional[int] = Field(
        default=None,
        ge=0,
        description="Query at specific block height"
    )
    include_remote: Optional[bool] = Field(
        default=None,
        alias="includeRemote",
        description="Include results from remote partitions"
    )
    prove: Optional[bool] = Field(
        default=None,
        description="Include Merkle proofs in response"
    )
    scratch: Optional[bool] = Field(
        default=None,
        description="Query scratch space instead of main state"
    )

    model_config = {"populate_by_name": True}

    def to_dict(self) -> Dict[str, Any]:
        """Convert to API-compatible dictionary."""
        result: Dict[str, Any] = {}
        if self.expand is not None:
            result["expand"] = self.expand
        if self.height is not None:
            result["height"] = self.height
        if self.include_remote is not None:
            result["includeRemote"] = self.include_remote
        if self.prove is not None:
            result["prove"] = self.prove
        if self.scratch is not None:
            result["scratch"] = self.scratch
        return result


# =============================================================================
# Query Types (for specific query operations)
# =============================================================================

class DefaultQuery(BaseModel):
    """
    Default query for account information.

    Queries basic account state.
    """
    include_receipt: Optional[ReceiptOptions] = Field(
        default=None,
        alias="includeReceipt",
        description="Options for including receipt"
    )

    model_config = {"populate_by_name": True}

    def to_dict(self) -> Dict[str, Any]:
        """Convert to API-compatible dictionary."""
        result: Dict[str, Any] = {"queryType": "default"}
        if self.include_receipt is not None:
            result["includeReceipt"] = self.include_receipt.to_dict()
        return result


class ChainQuery(BaseModel):
    """
    Query for chain entries.

    Queries entries on a specific chain (main, scratch, signature, etc.).
    Matches Go ChainQuery struct.
    """
    name: Optional[str] = Field(
        default=None,
        description="Chain name (e.g., 'main', 'scratch', 'signature')"
    )
    index: Optional[int] = Field(
        default=None,
        ge=0,
        description="Specific entry index"
    )
    entry: Optional[bytes] = Field(
        default=None,
        description="Specific entry hash (32 bytes)"
    )
    range: Optional[RangeOptions] = Field(
        default=None,
        description="Range options for multiple entries"
    )
    include_receipt: Optional[ReceiptOptions] = Field(
        default=None,
        alias="includeReceipt",
        description="Options for including receipt"
    )

    model_config = {"populate_by_name": True}

    @field_validator('entry', mode='before')
    @classmethod
    def validate_entry(cls, v: Any) -> Optional[bytes]:
        """Validate and convert entry to bytes."""
        if v is None:
            return None
        if isinstance(v, bytes):
            return v
        if isinstance(v, str):
            return bytes.fromhex(v)
        raise ValueError(f"entry must be bytes or hex string, got {type(v)}")

    def to_dict(self) -> Dict[str, Any]:
        """Convert to API-compatible dictionary."""
        result: Dict[str, Any] = {"queryType": "chain"}
        if self.name is not None:
            result["name"] = self.name
        if self.index is not None:
            result["index"] = self.index
        if self.entry is not None:
            result["entry"] = self.entry.hex()
        if self.range is not None:
            result["range"] = self.range.to_dict()
        if self.include_receipt is not None:
            result["includeReceipt"] = self.include_receipt.to_dict()
        return result


class DataQuery(BaseModel):
    """
    Query for data chain entries.

    Queries entries on an account's data chain.
    Matches Go DataQuery struct.
    """
    index: Optional[int] = Field(
        default=None,
        ge=0,
        description="Specific data entry index"
    )
    entry: Optional[bytes] = Field(
        default=None,
        description="Specific entry hash (32 bytes)"
    )
    range: Optional[RangeOptions] = Field(
        default=None,
        description="Range options for multiple entries"
    )

    model_config = {"populate_by_name": True}

    @field_validator('entry', mode='before')
    @classmethod
    def validate_entry(cls, v: Any) -> Optional[bytes]:
        """Validate and convert entry to bytes."""
        if v is None:
            return None
        if isinstance(v, bytes):
            return v
        if isinstance(v, str):
            return bytes.fromhex(v)
        raise ValueError(f"entry must be bytes or hex string, got {type(v)}")

    def to_dict(self) -> Dict[str, Any]:
        """Convert to API-compatible dictionary."""
        result: Dict[str, Any] = {"queryType": "data"}
        if self.index is not None:
            result["index"] = self.index
        if self.entry is not None:
            result["entry"] = self.entry.hex()
        if self.range is not None:
            result["range"] = self.range.to_dict()
        return result


class DirectoryQuery(BaseModel):
    """
    Query for account directory entries.

    Lists sub-accounts of an identity or directory.
    Matches Go DirectoryQuery struct.
    """
    range: Optional[RangeOptions] = Field(
        default=None,
        description="Range options for pagination"
    )

    model_config = {"populate_by_name": True}

    def to_dict(self) -> Dict[str, Any]:
        """Convert to API-compatible dictionary."""
        result: Dict[str, Any] = {"queryType": "directory"}
        if self.range is not None:
            result["range"] = self.range.to_dict()
        return result


class PendingQuery(BaseModel):
    """
    Query for pending transactions.

    Lists pending transactions for an account.
    Matches Go PendingQuery struct.
    """
    range: Optional[RangeOptions] = Field(
        default=None,
        description="Range options for pagination"
    )

    model_config = {"populate_by_name": True}

    def to_dict(self) -> Dict[str, Any]:
        """Convert to API-compatible dictionary."""
        result: Dict[str, Any] = {"queryType": "pending"}
        if self.range is not None:
            result["range"] = self.range.to_dict()
        return result


class BlockQuery(BaseModel):
    """
    Query for block information.

    Queries minor or major blocks.
    Matches Go BlockQuery struct.
    """
    minor: Optional[int] = Field(
        default=None,
        ge=0,
        description="Specific minor block index"
    )
    major: Optional[int] = Field(
        default=None,
        ge=0,
        description="Specific major block index"
    )
    minor_range: Optional[RangeOptions] = Field(
        default=None,
        alias="minorRange",
        description="Range of minor blocks"
    )
    major_range: Optional[RangeOptions] = Field(
        default=None,
        alias="majorRange",
        description="Range of major blocks"
    )
    entry_range: Optional[RangeOptions] = Field(
        default=None,
        alias="entryRange",
        description="Range of entries within block"
    )
    omit_empty: bool = Field(
        default=False,
        alias="omitEmpty",
        description="Omit unrecorded/empty blocks"
    )

    model_config = {"populate_by_name": True}

    def to_dict(self) -> Dict[str, Any]:
        """Convert to API-compatible dictionary."""
        result: Dict[str, Any] = {"queryType": "block"}
        if self.minor is not None:
            result["minor"] = self.minor
        if self.major is not None:
            result["major"] = self.major
        if self.minor_range is not None:
            result["minorRange"] = self.minor_range.to_dict()
        if self.major_range is not None:
            result["majorRange"] = self.major_range.to_dict()
        if self.entry_range is not None:
            result["entryRange"] = self.entry_range.to_dict()
        if self.omit_empty:
            result["omitEmpty"] = self.omit_empty
        return result


class AnchorSearchQuery(BaseModel):
    """
    Search query by anchor hash.

    Searches for transactions by anchor.
    Matches Go AnchorSearchQuery struct.
    """
    anchor: bytes = Field(
        ...,
        description="Anchor hash to search for (32 bytes)"
    )
    include_receipt: Optional[ReceiptOptions] = Field(
        default=None,
        alias="includeReceipt",
        description="Options for including receipt"
    )

    model_config = {"populate_by_name": True}

    @field_validator('anchor', mode='before')
    @classmethod
    def validate_anchor(cls, v: Any) -> bytes:
        """Validate and convert anchor to bytes."""
        if isinstance(v, bytes):
            return v
        if isinstance(v, str):
            return bytes.fromhex(v)
        raise ValueError(f"anchor must be bytes or hex string, got {type(v)}")

    def to_dict(self) -> Dict[str, Any]:
        """Convert to API-compatible dictionary."""
        result: Dict[str, Any] = {
            "queryType": "anchor",
            "anchor": self.anchor.hex()
        }
        if self.include_receipt is not None:
            result["includeReceipt"] = self.include_receipt.to_dict()
        return result


class PublicKeySearchQuery(BaseModel):
    """
    Search query by public key.

    Searches for accounts associated with a public key.
    Matches Go PublicKeySearchQuery struct.
    """
    public_key: bytes = Field(
        ...,
        alias="publicKey",
        description="Public key bytes to search for"
    )
    signature_type: str = Field(
        ...,
        alias="type",
        description="Signature type (e.g., 'ed25519', 'rcd1', 'btc')"
    )

    model_config = {"populate_by_name": True}

    @field_validator('public_key', mode='before')
    @classmethod
    def validate_public_key(cls, v: Any) -> bytes:
        """Validate and convert public key to bytes."""
        if isinstance(v, bytes):
            return v
        if isinstance(v, str):
            return bytes.fromhex(v)
        raise ValueError(f"public_key must be bytes or hex string, got {type(v)}")

    def to_dict(self) -> Dict[str, Any]:
        """Convert to API-compatible dictionary."""
        return {
            "queryType": "publicKey",
            "publicKey": self.public_key.hex(),
            "type": self.signature_type
        }


class PublicKeyHashSearchQuery(BaseModel):
    """
    Search query by public key hash.

    Searches for accounts by key hash.
    Matches Go PublicKeyHashSearchQuery struct.
    """
    public_key_hash: bytes = Field(
        ...,
        alias="publicKeyHash",
        description="Public key hash (32 bytes)"
    )

    model_config = {"populate_by_name": True}

    @field_validator('public_key_hash', mode='before')
    @classmethod
    def validate_public_key_hash(cls, v: Any) -> bytes:
        """Validate and convert public key hash to bytes."""
        if isinstance(v, bytes):
            return v
        if isinstance(v, str):
            return bytes.fromhex(v)
        raise ValueError(f"public_key_hash must be bytes or hex string, got {type(v)}")

    def to_dict(self) -> Dict[str, Any]:
        """Convert to API-compatible dictionary."""
        return {
            "queryType": "publicKeyHash",
            "publicKeyHash": self.public_key_hash.hex()
        }


class DelegateSearchQuery(BaseModel):
    """
    Search query by delegate.

    Searches for accounts delegated to a URL.
    Matches Go DelegateSearchQuery struct.
    """
    delegate: str = Field(
        ...,
        description="Delegate URL to search for"
    )

    model_config = {"populate_by_name": True}

    def to_dict(self) -> Dict[str, Any]:
        """Convert to API-compatible dictionary."""
        return {
            "queryType": "delegate",
            "delegate": self.delegate
        }


class MessageHashSearchQuery(BaseModel):
    """
    Search query by message hash.

    Searches for transactions by message hash.
    Matches Go MessageHashSearchQuery struct.
    """
    hash: bytes = Field(
        ...,
        description="Message hash (32 bytes)"
    )

    model_config = {"populate_by_name": True}

    @field_validator('hash', mode='before')
    @classmethod
    def validate_hash(cls, v: Any) -> bytes:
        """Validate and convert hash to bytes."""
        if isinstance(v, bytes):
            if len(v) != 32:
                raise ValueError(f"hash must be 32 bytes, got {len(v)}")
            return v
        if isinstance(v, str):
            b = bytes.fromhex(v)
            if len(b) != 32:
                raise ValueError(f"hash must be 32 bytes, got {len(b)}")
            return b
        raise ValueError(f"hash must be bytes or hex string, got {type(v)}")

    def to_dict(self) -> Dict[str, Any]:
        """Convert to API-compatible dictionary."""
        return {
            "queryType": "messageHash",
            "hash": self.hash.hex()
        }


# =============================================================================
# Service-Specific Options
# =============================================================================

class NodeInfoOptions(BaseModel):
    """
    Options for node-info requests.

    Matches Go NodeInfoOptions struct.
    """
    peer_id: Optional[str] = Field(
        default=None,
        alias="peerID",
        description="Specific peer ID to query"
    )

    model_config = {"populate_by_name": True}

    def to_dict(self) -> Dict[str, Any]:
        """Convert to API-compatible dictionary."""
        result: Dict[str, Any] = {}
        if self.peer_id is not None:
            result["peerID"] = self.peer_id
        return result


class ServiceAddress(BaseModel):
    """
    Service address specification.

    Identifies a specific service type and optional argument.
    Matches Go ServiceAddress struct.
    """
    type: str = Field(
        ...,
        description="Service type (e.g., 'node', 'query', 'submit')"
    )
    argument: Optional[str] = Field(
        default=None,
        description="Optional service argument (e.g., partition name)"
    )

    model_config = {"populate_by_name": True}

    def to_dict(self) -> Dict[str, Any]:
        """Convert to API-compatible dictionary."""
        result: Dict[str, Any] = {"type": self.type}
        if self.argument is not None:
            result["argument"] = self.argument
        return result


class FindServiceOptions(BaseModel):
    """
    Options for find-service requests.

    Used to discover services on the network.
    Matches Go FindServiceOptions struct.
    """
    network: Optional[str] = Field(
        default=None,
        description="Network name to search"
    )
    service: Optional[ServiceAddress] = Field(
        default=None,
        description="Service address to find"
    )
    known: Optional[bool] = Field(
        default=None,
        description="Restrict results to known peers"
    )
    timeout: Optional[float] = Field(
        default=None,
        ge=0,
        description="Wait time before stopping DHT query (seconds)"
    )

    model_config = {"populate_by_name": True}

    def to_dict(self) -> Dict[str, Any]:
        """Convert to API-compatible dictionary."""
        result: Dict[str, Any] = {}
        if self.network is not None:
            result["network"] = self.network
        if self.service is not None:
            result["service"] = self.service.to_dict()
        if self.known is not None:
            result["known"] = self.known
        if self.timeout is not None:
            result["timeout"] = self.timeout
        return result


class ConsensusStatusOptions(BaseModel):
    """
    Options for consensus-status requests.

    Queries consensus state for a specific node and partition.
    Matches Go ConsensusStatusOptions struct.
    """
    node_id: str = Field(
        ...,
        alias="nodeID",
        description="Node ID to query"
    )
    partition: str = Field(
        ...,
        description="Partition name"
    )
    include_peers: Optional[bool] = Field(
        default=None,
        alias="includePeers",
        description="Include peer information"
    )
    include_accumulate: Optional[bool] = Field(
        default=None,
        alias="includeAccumulate",
        description="Include Accumulate-specific information"
    )

    model_config = {"populate_by_name": True}

    def to_dict(self) -> Dict[str, Any]:
        """Convert to API-compatible dictionary."""
        result: Dict[str, Any] = {
            "nodeID": self.node_id,
            "partition": self.partition
        }
        if self.include_peers is not None:
            result["includePeers"] = self.include_peers
        if self.include_accumulate is not None:
            result["includeAccumulate"] = self.include_accumulate
        return result


class NetworkStatusOptions(BaseModel):
    """
    Options for network-status requests.

    Queries network status for a partition.
    Matches Go NetworkStatusOptions struct.
    """
    partition: str = Field(
        ...,
        description="Partition name"
    )

    model_config = {"populate_by_name": True}

    def to_dict(self) -> Dict[str, Any]:
        """Convert to API-compatible dictionary."""
        return {"partition": self.partition}


class MetricsOptions(BaseModel):
    """
    Options for metrics requests.

    Queries network metrics.
    Matches Go MetricsOptions struct.
    """
    partition: str = Field(
        ...,
        description="Partition name"
    )
    span: Optional[int] = Field(
        default=None,
        ge=1,
        description="Width of the window in blocks"
    )

    model_config = {"populate_by_name": True}

    def to_dict(self) -> Dict[str, Any]:
        """Convert to API-compatible dictionary."""
        result: Dict[str, Any] = {"partition": self.partition}
        if self.span is not None:
            result["span"] = self.span
        return result


class ListSnapshotsOptions(BaseModel):
    """
    Options for list-snapshots requests.

    Queries available snapshots from a node.
    Matches Go ListSnapshotsOptions struct.
    """
    node_id: str = Field(
        ...,
        alias="nodeID",
        description="Node ID to query"
    )
    partition: str = Field(
        ...,
        description="Partition name"
    )

    model_config = {"populate_by_name": True}

    def to_dict(self) -> Dict[str, Any]:
        """Convert to API-compatible dictionary."""
        return {
            "nodeID": self.node_id,
            "partition": self.partition
        }


class SubscribeOptions(BaseModel):
    """
    Options for subscribe requests.

    Used for event streaming subscriptions.
    Matches Go SubscribeOptions struct.
    """
    partition: Optional[str] = Field(
        default=None,
        description="Partition to subscribe to events from"
    )
    account: Optional[str] = Field(
        default=None,
        description="Account URL to subscribe to events for"
    )

    model_config = {"populate_by_name": True}

    def to_dict(self) -> Dict[str, Any]:
        """Convert to API-compatible dictionary."""
        result: Dict[str, Any] = {}
        if self.partition is not None:
            result["partition"] = self.partition
        if self.account is not None:
            result["account"] = self.account
        return result


# =============================================================================
# Query Type Union for type hints
# =============================================================================

QueryType = Union[
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
]


__all__ = [
    # Base options
    "RangeOptions",
    "ReceiptOptions",
    # Submit/validate/faucet options
    "SubmitOptions",
    "ValidateOptions",
    "FaucetOptions",
    # Query options
    "QueryOptions",
    # Query types
    "DefaultQuery",
    "ChainQuery",
    "DataQuery",
    "DirectoryQuery",
    "PendingQuery",
    "BlockQuery",
    "AnchorSearchQuery",
    "PublicKeySearchQuery",
    "PublicKeyHashSearchQuery",
    "DelegateSearchQuery",
    "MessageHashSearchQuery",
    "QueryType",
    # Service options
    "NodeInfoOptions",
    "ServiceAddress",
    "FindServiceOptions",
    "ConsensusStatusOptions",
    "NetworkStatusOptions",
    "MetricsOptions",
    "ListSnapshotsOptions",
    "SubscribeOptions",
]
