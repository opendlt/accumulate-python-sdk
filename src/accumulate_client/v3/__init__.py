"""
Accumulate V3 API client and options.

Provides dedicated V3 API client with full options support matching
Go pkg/api/v3 and Dart SDK patterns.
"""

from .options import (
    # Submit and validation options
    SubmitOptions,
    ValidateOptions,
    FaucetOptions,
    # Query options
    QueryOptions,
    RangeOptions,
    ReceiptOptions,
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
    ListSnapshotsOptions,
    SubscribeOptions,
)

from .client import AccumulateV3Client, V3ApiError

__all__ = [
    # Client
    "AccumulateV3Client",
    "V3ApiError",
    # Submit and validation options
    "SubmitOptions",
    "ValidateOptions",
    "FaucetOptions",
    # Query options
    "QueryOptions",
    "RangeOptions",
    "ReceiptOptions",
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
