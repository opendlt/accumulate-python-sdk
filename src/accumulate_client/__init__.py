"""
Accumulate Python SDK - Unified Client

This package provides a comprehensive Python SDK for interacting with the Accumulate protocol.
Includes both generated and enhanced client implementations.

Main entry points:
    - Accumulate: Unified facade with V2/V3 access (recommended)
    - AccumulateV2Client: Direct V2 API access
    - AccumulateV3Client: Direct V3 API access

Example:
    ```python
    from accumulate_client import Accumulate

    # Connect to testnet
    acc = Accumulate.testnet()

    # Query an account
    result = acc.query("acc://my-adi.acme")

    # Submit a transaction
    result = acc.submit(envelope)
    ```
"""

# Core generated types and components
from .enums import *
from .types import *
from .signatures import *
from .transactions import *

# Enhanced runtime components
from .runtime.errors import *
from .runtime.codec import *
from .runtime.url import AccountUrl

# V2/V3 client separation (Phase 7)
from .v2 import AccumulateV2Client, V2ApiError
from .v3 import AccumulateV3Client, V3ApiError
from .v3.options import (
    # Submit/validate/faucet options
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

# Unified facade (primary entry point)
from .facade import Accumulate, AccumulateClient

# Factory helpers (delegates to Accumulate facade)
def mainnet_client(**kwargs): return Accumulate.mainnet(**kwargs)
def testnet_client(**kwargs): return Accumulate.testnet(**kwargs)
def local_client(**kwargs): return Accumulate.local(**kwargs)

# Streaming client
from .client import StreamingAccumulateClient

# Performance optimization
from .performance import (
    HttpConnectionPool, PoolConfig,
    BatchClient, BatchRequest, BatchResponse,
    PipelineClient, PipelineConfig, SubmissionResult
)

# Error recovery
from .recovery import (
    RetryPolicy, ExponentialBackoff, LinearBackoff, FixedBackoff,
    CircuitBreaker, CircuitBreakerConfig, CircuitState,
    TransactionReplay, ReplayConfig, ReplayStore, InMemoryReplayStore
)

# Monitoring and telemetry
from .monitoring import (
    MetricsRegistry, Counter, Gauge, Histogram, Timer,
    Metric, MetricType, get_registry,
    MetricsExporter, JsonExporter, PrometheusExporter, LoggingExporter,
    instrument_client, instrument_function, collect_system_metrics,
    ClientInstrumentation
)

# Signing and transaction infrastructure
from .signers import *
from .keys import *
from .crypto import *
from .tx import *

# Operations (Phase 5 - Key page and account auth operations)
from .operations import *

# Convenience utilities (Dart SDK parity)
from .convenience import (
    # Data classes
    SubmitResult as TxSubmitResult,
    Wallet,
    ADI,
    KeyPageInfo,
    # Main classes
    TxBody,
    SmartSigner,
    KeyManager,
    QuickStart,
)

# Compatibility imports for tests
from .compat import Ed25519KeyPair, TransactionCodec, dumps_canonical, sha256_bytes, sha256_hex

__version__ = "2.0.4"
__all__ = [
    # Primary entry point (Phase 7)
    "Accumulate",
    "AccumulateClient",

    # V2/V3 clients (Phase 7)
    "AccumulateV2Client",
    "AccumulateV3Client",
    "V2ApiError",
    "V3ApiError",

    # V3 options (Phase 7 & 8)
    "SubmitOptions",
    "ValidateOptions",
    "FaucetOptions",
    "QueryOptions",
    "RangeOptions",
    "ReceiptOptions",
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
    "NodeInfoOptions",
    "ServiceAddress",
    "FindServiceOptions",
    "ConsensusStatusOptions",
    "NetworkStatusOptions",
    "MetricsOptions",
    "ListSnapshotsOptions",
    "SubscribeOptions",

    # Streaming
    "StreamingAccumulateClient",

    # Client factories
    "mainnet_client",
    "testnet_client",
    "local_client",

    # Performance optimization
    "HttpConnectionPool",
    "PoolConfig",
    "BatchClient",
    "BatchRequest",
    "BatchResponse",
    "PipelineClient",
    "PipelineConfig",
    "SubmissionResult",

    # Error recovery
    "RetryPolicy",
    "ExponentialBackoff",
    "LinearBackoff",
    "FixedBackoff",
    "CircuitBreaker",
    "CircuitBreakerConfig",
    "CircuitState",
    "TransactionReplay",
    "ReplayConfig",
    "ReplayStore",
    "InMemoryReplayStore",

    # Monitoring and telemetry
    "MetricsRegistry",
    "Counter",
    "Gauge",
    "Histogram",
    "Timer",
    "Metric",
    "MetricType",
    "get_registry",
    "MetricsExporter",
    "JsonExporter",
    "PrometheusExporter",
    "LoggingExporter",
    "instrument_client",
    "instrument_function",
    "collect_system_metrics",
    "ClientInstrumentation",

    # Core types
    "AccountUrl",

    # Convenience utilities (Dart SDK parity)
    "TxBody",
    "SmartSigner",
    "KeyManager",
    "QuickStart",
    "TxSubmitResult",
    "Wallet",
    "ADI",
    "KeyPageInfo",

    # All enums, types, signatures, transactions are included via *
]