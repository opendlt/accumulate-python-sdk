"""
Tests for HTTP connection pooling and request batching.

Comprehensive test suite covering pool management, batch processing,
and performance optimization features.
"""

import asyncio
import json
import pytest
import time
from unittest.mock import Mock, AsyncMock, patch, MagicMock

from accumulate_client.performance.pool import (
    HttpConnectionPool, PoolConfig, PoolError, PoolExhausted, PoolClosed
)
from accumulate_client.performance.batch import (
    BatchClient, BatchRequest, BatchResponse, BatchError, BatchTimeout
)


@pytest.fixture
def pool_config():
    """Default pool configuration for tests."""
    return PoolConfig(
        max_connections=10,
        max_connections_per_host=5,
        connection_timeout=1.0,
        request_timeout=2.0,
        max_retries=2,
        health_check_interval=0.1
    )


@pytest.fixture
def mock_aiohttp_session():
    """Mock aiohttp session."""
    session = AsyncMock()
    session.request = AsyncMock()
    session.get = AsyncMock()
    session.post = AsyncMock()
    session.close = AsyncMock()
    return session


class TestPoolConfig:
    """Test pool configuration."""

    def test_default_config(self):
        config = PoolConfig()
        assert config.max_connections == 100
        assert config.max_connections_per_host == 30
        assert config.connection_timeout == 10.0
        assert config.request_timeout == 30.0
        assert config.max_retries == 3

    def test_custom_config(self):
        config = PoolConfig(
            max_connections=50,
            connection_timeout=5.0,
            enable_compression=False
        )
        assert config.max_connections == 50
        assert config.connection_timeout == 5.0
        assert config.enable_compression is False


class TestHttpConnectionPool:
    """Test HTTP connection pool."""

    @pytest.mark.asyncio
    async def test_no_aiohttp_library(self, pool_config):
        """Test graceful handling when aiohttp is missing."""
        with patch('accumulate_client.performance.pool.HAS_AIOHTTP', False):
            with pytest.raises(ImportError, match="aiohttp"):
                HttpConnectionPool(pool_config)

    @pytest.mark.asyncio
    async def test_pool_initialization(self, pool_config):
        """Test pool initialization."""
        with patch('accumulate_client.performance.pool.HAS_AIOHTTP', True):
            pool = HttpConnectionPool(pool_config)
            assert pool.config == pool_config
            assert pool.closed is False
            assert len(pool.sessions) == 0

    @pytest.mark.asyncio
    async def test_context_manager(self, pool_config):
        """Test pool as async context manager."""
        with patch('accumulate_client.performance.pool.HAS_AIOHTTP', True):
            pool = HttpConnectionPool(pool_config)

            async with pool as p:
                assert p == pool
                assert pool.health_check_task is not None

            assert pool.closed is True

    @pytest.mark.asyncio
    async def test_session_creation(self, pool_config, mock_aiohttp_session):
        """Test session creation and reuse."""
        with patch('accumulate_client.performance.pool.HAS_AIOHTTP', True):
            with patch('accumulate_client.performance.pool.aiohttp.ClientSession',
                      return_value=mock_aiohttp_session):
                pool = HttpConnectionPool(pool_config)

                # First request should create session
                session1 = await pool._get_session("https://example.com/api")
                assert session1 == mock_aiohttp_session
                assert len(pool.sessions) == 1

                # Second request to same host should reuse session
                session2 = await pool._get_session("https://example.com/other")
                assert session2 == mock_aiohttp_session
                assert len(pool.sessions) == 1

                # Different host should create new session
                session3 = await pool._get_session("https://other.com/api")
                assert len(pool.sessions) == 2

    @pytest.mark.asyncio
    async def test_request_with_retries(self, pool_config, mock_aiohttp_session):
        """Test request with retry logic."""
        with patch('accumulate_client.performance.pool.HAS_AIOHTTP', True):
            with patch('accumulate_client.performance.pool.aiohttp.ClientSession',
                      return_value=mock_aiohttp_session):
                pool = HttpConnectionPool(pool_config)

                # Mock response
                mock_response = AsyncMock()
                mock_response.content_length = 100

                # First call fails, second succeeds
                mock_aiohttp_session.request.side_effect = [
                    asyncio.TimeoutError("Timeout"),
                    mock_response
                ]

                with patch('asyncio.sleep'):  # Skip actual sleep in tests
                    response = await pool.request("GET", "https://example.com")

                assert response == mock_response
                assert mock_aiohttp_session.request.call_count == 2

    @pytest.mark.asyncio
    async def test_request_max_retries_exceeded(self, pool_config, mock_aiohttp_session):
        """Test behavior when max retries are exceeded."""
        with patch('accumulate_client.performance.pool.HAS_AIOHTTP', True):
            with patch('accumulate_client.performance.pool.aiohttp.ClientSession',
                      return_value=mock_aiohttp_session):
                pool = HttpConnectionPool(pool_config)

                # All calls fail
                mock_aiohttp_session.request.side_effect = asyncio.TimeoutError("Timeout")

                with patch('asyncio.sleep'):  # Skip actual sleep in tests
                    with pytest.raises(PoolError, match="Request failed"):
                        await pool.request("GET", "https://example.com")

                # Should have tried max_retries + 1 times
                assert mock_aiohttp_session.request.call_count == pool_config.max_retries + 1

    @pytest.mark.asyncio
    async def test_pool_closed_error(self, pool_config):
        """Test operations on closed pool."""
        with patch('accumulate_client.performance.pool.HAS_AIOHTTP', True):
            pool = HttpConnectionPool(pool_config)
            pool.closed = True

            with pytest.raises(PoolClosed):
                await pool._get_session("https://example.com")

            with pytest.raises(PoolClosed):
                await pool.request("GET", "https://example.com")

    @pytest.mark.asyncio
    async def test_cleanup_stale_connections(self, pool_config, mock_aiohttp_session):
        """Test cleanup of stale connections."""
        with patch('accumulate_client.performance.pool.HAS_AIOHTTP', True):
            with patch('accumulate_client.performance.pool.aiohttp.ClientSession',
                      return_value=mock_aiohttp_session):
                pool = HttpConnectionPool(pool_config)

                # Create session and make it stale
                await pool._get_session("https://example.com")
                stats = pool.session_stats["https://example.com"]
                stats.last_used = time.time() - pool_config.max_idle_time - 1

                # Run cleanup
                await pool._cleanup_stale_connections()

                # Session should be removed
                assert len(pool.sessions) == 0
                assert len(pool.session_stats) == 0
                mock_aiohttp_session.close.assert_called_once()

    @pytest.mark.asyncio
    async def test_get_stats(self, pool_config, mock_aiohttp_session):
        """Test statistics collection."""
        with patch('accumulate_client.performance.pool.HAS_AIOHTTP', True):
            with patch('accumulate_client.performance.pool.aiohttp.ClientSession',
                      return_value=mock_aiohttp_session):
                pool = HttpConnectionPool(pool_config)

                # Create session and update stats
                await pool._get_session("https://example.com")
                stats = pool.session_stats["https://example.com"]
                stats.request_count = 10
                stats.error_count = 1

                pool_stats = pool.get_stats()

                assert pool_stats["pool"]["total_hosts"] == 1
                assert pool_stats["pool"]["total_requests"] == 10
                assert pool_stats["pool"]["total_errors"] == 1
                assert "https://example.com" in pool_stats["hosts"]


class TestBatchClient:
    """Test batch client."""

    @pytest.fixture
    def mock_http_client(self):
        """Mock HTTP client."""
        client = AsyncMock()
        client.call = AsyncMock()
        client.batch_call = AsyncMock()
        return client

    @pytest.fixture
    def batch_client(self, mock_http_client):
        """Batch client with mocked dependencies."""
        return BatchClient(
            config_or_endpoint="https://example.com/rpc",
            max_batch_size=5,
            max_wait_time=0.01,
            max_concurrent_batches=2
        )

    @pytest.mark.asyncio
    async def test_initialization(self):
        """Test batch client initialization."""
        client = BatchClient("https://example.com/rpc")
        assert client.endpoint == "https://example.com/rpc"
        assert client.max_batch_size == 100
        assert client.max_wait_time == 0.1
        assert len(client.pending_requests) == 0

    @pytest.mark.asyncio
    async def test_context_manager(self, batch_client):
        """Test batch client as context manager."""
        async with batch_client as client:
            assert client == batch_client
            assert batch_client.batch_task is not None

        assert batch_client.batch_task is None

    @pytest.mark.asyncio
    async def test_single_request_submission(self, batch_client):
        """Test submitting single request."""
        # Mock the execution
        with patch.object(batch_client, '_execute_single_request') as mock_exec:
            mock_exec.return_value = None

            # Set up future result
            async def setup_result():
                await asyncio.sleep(0.01)
                future = batch_client.request_futures.get("test-id")
                if future:
                    future.set_result({"success": True})

            asyncio.create_task(setup_result())

            async with batch_client:
                # Patch uuid4 to return predictable ID
                with patch('accumulate_client.performance.batch.uuid4',
                          return_value="test-id"):
                    result = await batch_client.submit(
                        "test_method",
                        {"param": "value"}
                    )

            assert result == {"success": True}

    @pytest.mark.asyncio
    async def test_request_timeout(self, batch_client):
        """Test request timeout."""
        async with batch_client:
            with pytest.raises(BatchTimeout):
                await batch_client.submit(
                    "test_method",
                    {"param": "value"},
                    timeout=0.01
                )

    @pytest.mark.asyncio
    async def test_deduplication(self, batch_client):
        """Test request deduplication."""
        batch_client.enable_deduplication = True

        # Mock execution to never complete first request
        with patch.object(batch_client, '_execute_single_request'):
            async with batch_client:
                # Submit same request twice
                task1 = asyncio.create_task(
                    batch_client.submit("test", {"param": "value"})
                )
                # Allow first task to start and create dedup entry
                await asyncio.sleep(0.01)

                task2 = asyncio.create_task(
                    batch_client.submit("test", {"param": "value"})
                )
                # Allow second task to run and hit deduplication
                await asyncio.sleep(0.01)

                # Cancel tasks to avoid indefinite wait
                task1.cancel()
                task2.cancel()

                try:
                    await task1
                except asyncio.CancelledError:
                    pass

                try:
                    await task2
                except asyncio.CancelledError:
                    pass

            # Should have hit deduplication
            assert batch_client.stats["deduplication_hits"] > 0

    @pytest.mark.asyncio
    async def test_batch_processing(self, batch_client):
        """Test batch processing with multiple requests."""
        # Mock batch execution
        with patch.object(batch_client, '_execute_batch_request') as mock_exec:
            mock_exec.return_value = None

            # Set up to complete requests
            async def complete_requests():
                await asyncio.sleep(0.02)  # Wait for requests to queue
                for req_id, future in batch_client.request_futures.items():
                    if not future.done():
                        future.set_result(f"result-{req_id}")

            asyncio.create_task(complete_requests())

            async with batch_client:
                # Submit multiple requests quickly
                tasks = []
                for i in range(3):
                    task = asyncio.create_task(
                        batch_client.submit(f"method_{i}", {"param": i})
                    )
                    tasks.append(task)

                results = await asyncio.gather(*tasks)

            assert len(results) == 3
            assert all("result-" in str(r) for r in results)

    @pytest.mark.asyncio
    async def test_submit_many(self, batch_client):
        """Test submitting many requests at once."""
        requests = [
            {"method": "test1", "params": {"a": 1}},
            {"method": "test2", "params": {"b": 2}},
            {"method": "test3", "params": {"c": 3}}
        ]

        # Mock execution
        with patch.object(batch_client, '_execute_batch_request') as mock_exec:
            mock_exec.return_value = None

            # Complete all requests
            async def complete_all():
                await asyncio.sleep(0.01)
                for future in batch_client.request_futures.values():
                    if not future.done():
                        future.set_result("success")

            asyncio.create_task(complete_all())

            async with batch_client:
                results = await batch_client.submit_many(requests)

            assert len(results) == 3
            assert all(r == "success" for r in results)

    @pytest.mark.asyncio
    async def test_get_stats(self, batch_client):
        """Test statistics collection."""
        batch_client.stats["requests_submitted"] = 10
        batch_client.stats["requests_completed"] = 8
        batch_client.stats["batches_sent"] = 2

        stats = batch_client.get_stats()

        assert stats["requests_submitted"] == 10
        assert stats["requests_completed"] == 8
        assert stats["success_rate"] == 0.8
        assert "pending_requests" in stats

    def test_dedup_key_generation(self, batch_client):
        """Test deduplication key generation."""
        key1 = batch_client._get_dedup_key("test", {"a": 1, "b": 2})
        key2 = batch_client._get_dedup_key("test", {"b": 2, "a": 1})  # Different order
        key3 = batch_client._get_dedup_key("test", {"a": 1, "b": 3})  # Different value

        assert key1 == key2  # Should be same despite parameter order
        assert key1 != key3  # Should be different for different values


class TestBatchRequest:
    """Test batch request data class."""

    def test_batch_request_creation(self):
        request = BatchRequest(
            id="test-id",
            method="test_method",
            params={"key": "value"},
            priority=5
        )

        assert request.id == "test-id"
        assert request.method == "test_method"
        assert request.params == {"key": "value"}
        assert request.priority == 5
        assert isinstance(request.created_at, float)


class TestBatchResponse:
    """Test batch response data class."""

    def test_successful_response(self):
        response = BatchResponse(
            id="test-id",
            success=True,
            result={"data": "value"},
            duration_ms=150.0
        )

        assert response.id == "test-id"
        assert response.success is True
        assert response.failed is False
        assert response.result == {"data": "value"}
        assert response.duration_ms == 150.0

    def test_failed_response(self):
        response = BatchResponse(
            id="test-id",
            success=False,
            error={"code": -1, "message": "Error"}
        )

        assert response.success is False
        assert response.failed is True
        assert response.error == {"code": -1, "message": "Error"}


if __name__ == "__main__":
    pytest.main([__file__])
