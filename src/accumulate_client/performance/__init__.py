"""
Performance optimization components for Accumulate SDK.

Provides HTTP connection pooling, request batching, and pipeline functionality
for high-performance transaction submission and data retrieval.
"""

from .pool import HttpConnectionPool, PoolConfig
from .batch import BatchClient, BatchRequest, BatchResponse
from .pipeline import PipelineClient, PipelineConfig, SubmissionResult

__all__ = [
    "HttpConnectionPool",
    "PoolConfig",
    "BatchClient",
    "BatchRequest",
    "BatchResponse",
    "PipelineClient",
    "PipelineConfig",
    "SubmissionResult"
]