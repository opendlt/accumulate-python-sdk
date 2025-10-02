"""
Extension module for batch.py to support test requirements.

Provides additional classes needed by test_batcher_pipeline_shapes.py
without modifying the core batch.py implementation.
"""

import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Callable

from .batch import BatchRequest as BaseBatchRequest, BatchResponse as BaseBatchResponse


@dataclass
class BatchConfig:
    """Configuration for request batching."""
    max_batch_size: int = 100
    max_wait_time: float = 0.1  # seconds
    max_concurrent_batches: int = 10
    enable_deduplication: bool = True


class RequestBatcher:
    """Request batcher for accumulating and flushing requests."""

    def __init__(self, config: BatchConfig):
        """Initialize with batch configuration."""
        self.config = config
        self.pending_requests: List[BaseBatchRequest] = []
        self.flush_callback: Optional[Callable] = None
        self.last_flush_time = time.time()

    def set_flush_callback(self, callback: Callable):
        """Set callback function to be called when batch is flushed."""
        self.flush_callback = callback

    def add_request(self, request: BaseBatchRequest):
        """Add request to batch, triggering flush if needed."""
        self.pending_requests.append(request)

        # Check size-based flush
        if len(self.pending_requests) >= self.config.max_batch_size:
            self._flush_batch()

    def _check_time_flush(self):
        """Check if time-based flush is needed."""
        if self.pending_requests and time.time() - self.last_flush_time >= self.config.max_wait_time:
            self._flush_batch()

    def _flush_batch(self):
        """Flush current batch."""
        if not self.pending_requests:
            return

        if self.flush_callback:
            # Create batch object similar to what tests expect
            batch = type('Batch', (), {
                'requests': self.pending_requests.copy(),
                'batch_id': f"batch_{int(time.time() * 1000)}"
            })()
            self.flush_callback(batch)

        self.pending_requests.clear()
        self.last_flush_time = time.time()

    def pending_count(self) -> int:
        """Get number of pending requests."""
        return len(self.pending_requests)


@dataclass
class BatchRequest(BaseBatchRequest):
    """Enhanced BatchRequest with metadata support for testing."""
    metadata: Optional[Dict[str, Any]] = None

    def __init__(self, id: str, method: str, params: Dict[str, Any],
                 created_at: float = None, priority: int = 0, metadata: Dict[str, Any] = None):
        """Initialize with optional metadata."""
        if created_at is None:
            created_at = time.time()
        super().__init__(id, method, params, created_at, priority)
        self.metadata = metadata


@dataclass
class BatchResponse:
    """Enhanced BatchResponse for testing."""
    batch_id: str
    requests: List[BatchRequest]
    responses: List[Dict[str, Any]]
    metadata: Optional[Dict[str, Any]] = None

    def __init__(self, batch_id: str, requests: List[BatchRequest],
                 responses: List[Dict[str, Any]], metadata: Dict[str, Any] = None):
        """Initialize with test-compatible signature."""
        self.batch_id = batch_id
        self.requests = requests
        self.responses = responses
        self.metadata = metadata


__all__ = [
    "BatchConfig",
    "RequestBatcher",
    "BatchRequest",
    "BatchResponse"
]