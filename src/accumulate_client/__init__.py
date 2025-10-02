"""
Accumulate Python SDK - Unified Client

This package provides a comprehensive Python SDK for interacting with the Accumulate protocol.
Includes both generated and enhanced client implementations.
"""

# Core generated types and components
from .enums import *
from .types import *
from .signatures import *
from .transactions import *
from .json_rpc_client import JsonRpcClient

# Enhanced runtime components
from .api_client import AccumulateClient, mainnet_client, testnet_client, local_client
from .runtime.errors import *
from .runtime.codec import *
from .runtime.url import AccountUrl

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

# Generated client (for compatibility)
from .generated_client import AccumulateClient as GeneratedAccumulateClient

# Signing and transaction infrastructure
from .signers import *
from .keys import *
from .crypto import *
from .tx import *

# Compatibility imports for tests
from .compat import Ed25519KeyPair, TransactionCodec, dumps_canonical, sha256_bytes, sha256_hex

__version__ = "2.3.0"
__all__ = [
    # JSON RPC clients
    "JsonRpcClient",
    "AccumulateClient",
    "GeneratedAccumulateClient",
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

    # All enums, types, signatures, transactions are included via *
]