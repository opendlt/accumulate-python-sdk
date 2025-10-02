"""
Test request batching and transaction pipeline functionality.

Verifies that requests are batched correctly and that transaction
pipelines handle concurrent operations properly.
"""

import pytest
import asyncio
import time
from unittest.mock import AsyncMock, Mock

from accumulate_client.performance.batch import (
    BatchClient, BatchRequest, BatchResponse, BatchConfig, RequestBatcher
)


class MockPipelineClient:
    """Mock pipeline client for testing."""

    def __init__(self):
        self.submitted_transactions = []
        self.submission_results = {}
        self.workers_active = 0
        self.max_workers_seen = 0

    async def submit_transaction(self, transaction):
        """Mock transaction submission."""
        self.workers_active += 1
        self.max_workers_seen = max(self.max_workers_seen, self.workers_active)

        submission_id = f"tx_{len(self.submitted_transactions)}"
        self.submitted_transactions.append({
            'id': submission_id,
            'transaction': transaction,
            'timestamp': time.time()
        })

        # Simulate async work
        await asyncio.sleep(0.01)

        # Simulate success/failure based on transaction content
        if 'fail' in str(transaction):
            result = {'status': 'failed', 'error': 'Simulated failure'}
        else:
            result = {'status': 'success', 'hash': f"hash_{submission_id}"}

        self.submission_results[submission_id] = result
        self.workers_active -= 1

        return submission_id

    async def wait_for_result(self, submission_id):
        """Wait for transaction result."""
        # Simulate waiting
        while submission_id not in self.submission_results:
            await asyncio.sleep(0.001)

        return self.submission_results[submission_id]


@pytest.mark.performance
@pytest.mark.unit
def test_request_batcher_size_based_flush():
    """Test that batcher flushes when size limit is reached."""

    config = BatchConfig(max_batch_size=3, max_wait_time=10.0)  # Long wait time
    batcher = RequestBatcher(config)

    requests = [
        BatchRequest(id="1", method="query", params={"url": "acc://test1"}),
        BatchRequest(id="2", method="query", params={"url": "acc://test2"}),
        BatchRequest(id="3", method="query", params={"url": "acc://test3"}),
    ]

    # Add requests one by one
    batches_flushed = []

    def mock_flush_callback(batch):
        batches_flushed.append(batch)

    batcher.set_flush_callback(mock_flush_callback)

    for request in requests:
        batcher.add_request(request)

    # Should have flushed when we hit size limit
    assert len(batches_flushed) == 1
    batch = batches_flushed[0]
    assert len(batch.requests) == 3
    assert [r.id for r in batch.requests] == ["1", "2", "3"]


@pytest.mark.performance
@pytest.mark.unit
def test_request_batcher_time_based_flush():
    """Test that batcher flushes when time limit is reached."""

    config = BatchConfig(max_batch_size=10, max_wait_time=0.05)  # 50ms wait
    batcher = RequestBatcher(config)

    batches_flushed = []

    def mock_flush_callback(batch):
        batches_flushed.append(batch)

    batcher.set_flush_callback(mock_flush_callback)

    # Add one request
    request = BatchRequest(id="1", method="query", params={"url": "acc://test1"})
    batcher.add_request(request)

    # Should not flush immediately
    assert len(batches_flushed) == 0

    # Wait for time-based flush
    time.sleep(0.1)
    batcher._check_time_flush()

    # Should have flushed due to time
    assert len(batches_flushed) == 1
    batch = batches_flushed[0]
    assert len(batch.requests) == 1
    assert batch.requests[0].id == "1"


@pytest.mark.performance
@pytest.mark.unit
def test_request_batcher_preserves_order():
    """Test that batcher preserves request order within batches."""

    config = BatchConfig(max_batch_size=5, max_wait_time=1.0)
    batcher = RequestBatcher(config)

    batches_flushed = []

    def mock_flush_callback(batch):
        batches_flushed.append(batch)

    batcher.set_flush_callback(mock_flush_callback)

    # Add requests with specific order
    request_ids = ["A", "B", "C", "D", "E"]
    for req_id in request_ids:
        request = BatchRequest(id=req_id, method="query", params={"url": f"acc://test{req_id}"})
        batcher.add_request(request)

    # Should flush when batch is full
    assert len(batches_flushed) == 1
    batch = batches_flushed[0]

    # Order should be preserved
    actual_ids = [r.id for r in batch.requests]
    assert actual_ids == request_ids


@pytest.mark.performance
@pytest.mark.unit
def test_request_batcher_multiple_batches():
    """Test that batcher handles multiple batches correctly."""

    config = BatchConfig(max_batch_size=2, max_wait_time=1.0)
    batcher = RequestBatcher(config)

    batches_flushed = []

    def mock_flush_callback(batch):
        batches_flushed.append(batch)

    batcher.set_flush_callback(mock_flush_callback)

    # Add 5 requests (should create 2 full batches + 1 partial)
    for i in range(5):
        request = BatchRequest(id=str(i), method="query", params={"url": f"acc://test{i}"})
        batcher.add_request(request)

    # Should have 2 completed batches
    assert len(batches_flushed) == 2

    # Check first batch
    assert len(batches_flushed[0].requests) == 2
    assert [r.id for r in batches_flushed[0].requests] == ["0", "1"]

    # Check second batch
    assert len(batches_flushed[1].requests) == 2
    assert [r.id for r in batches_flushed[1].requests] == ["2", "3"]

    # One request should still be pending
    assert batcher.pending_count() == 1


@pytest.mark.performance
@pytest.mark.unit
@pytest.mark.asyncio
async def test_pipeline_concurrent_workers():
    """Test that pipeline handles concurrent transaction submissions."""

    pipeline = MockPipelineClient()

    # Submit multiple transactions concurrently
    transactions = [
        {"type": "WriteData", "data": f"test{i}"}
        for i in range(5)
    ]

    # Submit all transactions concurrently
    submission_tasks = [
        pipeline.submit_transaction(tx) for tx in transactions
    ]

    submission_ids = await asyncio.gather(*submission_tasks)

    # All should have unique IDs
    assert len(set(submission_ids)) == len(submission_ids)

    # All transactions should be recorded
    assert len(pipeline.submitted_transactions) == 5

    # Should have seen some concurrency
    assert pipeline.max_workers_seen > 1


@pytest.mark.performance
@pytest.mark.unit
@pytest.mark.asyncio
async def test_pipeline_success_error_lanes():
    """Test that pipeline handles both success and error cases."""

    pipeline = MockPipelineClient()

    # Mix of successful and failing transactions
    transactions = [
        {"type": "WriteData", "data": "success1"},
        {"type": "WriteData", "data": "fail1"},
        {"type": "WriteData", "data": "success2"},
        {"type": "WriteData", "data": "fail2"},
    ]

    submission_ids = []
    for tx in transactions:
        submission_id = await pipeline.submit_transaction(tx)
        submission_ids.append(submission_id)

    # Wait for all results
    results = []
    for submission_id in submission_ids:
        result = await pipeline.wait_for_result(submission_id)
        results.append(result)

    # Check success/failure pattern
    assert results[0]['status'] == 'success'
    assert results[1]['status'] == 'failed'
    assert results[2]['status'] == 'success'
    assert results[3]['status'] == 'failed'

    # Successful transactions should have hashes
    assert 'hash' in results[0]
    assert 'hash' in results[2]

    # Failed transactions should have errors
    assert 'error' in results[1]
    assert 'error' in results[3]


@pytest.mark.performance
@pytest.mark.unit
def test_batch_request_creation():
    """Test BatchRequest creation and properties."""

    request = BatchRequest(
        id="test123",
        method="submit",
        params={"transaction": {"type": "WriteData"}},
        metadata={"priority": "high"}
    )

    assert request.id == "test123"
    assert request.method == "submit"
    assert request.params["transaction"]["type"] == "WriteData"
    assert request.metadata["priority"] == "high"


@pytest.mark.performance
@pytest.mark.unit
def test_batch_response_creation():
    """Test BatchResponse creation and properties."""

    requests = [
        BatchRequest(id="1", method="query", params={}),
        BatchRequest(id="2", method="query", params={}),
    ]

    responses = [
        {"id": "1", "result": {"status": "success"}},
        {"id": "2", "error": {"code": -1, "message": "Not found"}},
    ]

    batch_response = BatchResponse(
        batch_id="batch_001",
        requests=requests,
        responses=responses,
        metadata={"processing_time": 0.125}
    )

    assert batch_response.batch_id == "batch_001"
    assert len(batch_response.requests) == 2
    assert len(batch_response.responses) == 2
    assert batch_response.metadata["processing_time"] == 0.125


@pytest.mark.performance
@pytest.mark.unit
def test_batch_config_validation():
    """Test BatchConfig validates parameters correctly."""

    # Valid config
    config = BatchConfig(max_batch_size=100, max_wait_time=0.5)
    assert config.max_batch_size == 100
    assert config.max_wait_time == 0.5

    # Test defaults
    default_config = BatchConfig()
    assert default_config.max_batch_size > 0
    assert default_config.max_wait_time > 0


@pytest.mark.performance
@pytest.mark.unit
@pytest.mark.asyncio
async def test_pipeline_queue_management():
    """Test that pipeline manages submission queue properly."""

    pipeline = MockPipelineClient()

    # Submit transactions in rapid succession
    submission_tasks = []
    for i in range(10):
        task = asyncio.create_task(
            pipeline.submit_transaction({"type": "WriteData", "data": f"batch{i}"})
        )
        submission_tasks.append(task)

    # Wait for all submissions to complete
    submission_ids = await asyncio.gather(*submission_tasks)

    # All should have completed
    assert len(submission_ids) == 10
    assert len(pipeline.submitted_transactions) == 10

    # Timestamps should show they were processed concurrently
    timestamps = [tx['timestamp'] for tx in pipeline.submitted_transactions]
    time_span = max(timestamps) - min(timestamps)

    # Should complete within reasonable time (concurrent processing)
    assert time_span < 1.0  # All within 1 second despite 0.01s each
