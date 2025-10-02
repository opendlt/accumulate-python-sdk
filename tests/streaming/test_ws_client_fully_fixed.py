"""
Tests for WebSocket client and streaming functionality.

Comprehensive test suite covering connection management, event handling,
reconnection logic, and backpressure scenarios.
"""

import asyncio
import json
import pytest
import time
from unittest.mock import Mock, AsyncMock, patch, MagicMock
from typing import AsyncIterator, Dict, Any

from accumulate_client.transport.ws import (
    WebSocketClient, WebSocketConfig, WebSocketError, ReconnectExceeded,
    Event, BlockEvent, TxStatusEvent, AnchorEvent, LogEvent,
    ws_url_from_http
)
from accumulate_client.client.streaming import StreamingAccumulateClient


@pytest.fixture
def ws_config():
    """Default WebSocket configuration for tests."""
    return WebSocketConfig(
        url="ws://localhost:8080/v3/ws",
        ping_interval=1.0,
        ping_timeout=0.5,
        max_retries=2,
        backoff_base=0.1,
        max_queue_size=10
    )


@pytest.fixture
def mock_websocket():
    """Mock websocket connection."""
    mock_ws = AsyncMock()
    mock_ws.recv = AsyncMock()
    mock_ws.send = AsyncMock()
    mock_ws.ping = AsyncMock()
    mock_ws.close = AsyncMock()
    return mock_ws


class TestWebSocketConfig:
    """Test WebSocket configuration."""

    def test_default_config(self):
        config = WebSocketConfig(url="ws://test.com")
        assert config.url == "ws://test.com"
        assert config.ping_interval == 30.0
        assert config.ping_timeout == 10.0
        assert config.max_retries == 5
        assert config.backoff_base == 1.0
        assert config.max_queue_size == 1000
        assert config.queue_behavior == "drop_oldest"

    def test_custom_config(self):
        config = WebSocketConfig(
            url="wss://secure.test.com",
            ping_interval=15.0,
            max_retries=3,
            queue_behavior="block"
        )
        assert config.url == "wss://secure.test.com"
        assert config.ping_interval == 15.0
        assert config.max_retries == 3
        assert config.queue_behavior == "block"


class TestEvent:
    """Test event classes."""

    def test_base_event(self):
        event_data = {"key": "value"}
        event = Event(type="test", data=event_data)

        assert event.type == "test"
        assert event.data == event_data
        assert event.stream is None
        assert isinstance(event.timestamp, float)

    def test_block_event(self):
        block_data = {"height": 12345, "hash": "abc123"}
        event = BlockEvent(type="block", data=block_data)

        assert event.type == "block"
        assert event.block_height == 12345
        assert event.block_hash == "abc123"

    def test_tx_status_event(self):
        tx_data = {"txId": "tx123", "status": "delivered"}
        event = TxStatusEvent(type="tx_status", data=tx_data)

        assert event.type == "tx_status"
        assert event.tx_id == "tx123"
        assert event.status == "delivered"

    def test_anchor_event(self):
        anchor_data = {"anchorHash": "anchor123", "sourceChain": "dn.acme"}
        event = AnchorEvent(type="anchor", data=anchor_data)

        assert event.type == "anchor"
        assert event.anchor_hash == "anchor123"
        assert event.source_chain == "dn.acme"

    def test_log_event(self):
        log_data = {"level": "info", "message": "Test message"}
        event = LogEvent(type="log", data=log_data)

        assert event.type == "log"
        assert event.level == "info"
        assert event.message == "Test message"


class TestWebSocketClient:
    """Test WebSocket client functionality."""

    @pytest.mark.asyncio
    async def test_no_websockets_library(self, ws_config):
        """Test graceful handling when websockets library is missing."""
        with patch('accumulate_client.transport.ws.HAS_WEBSOCKETS', False):
            with pytest.raises(ImportError, match="websockets"):
                WebSocketClient(ws_config)

    @pytest.mark.asyncio
    async def test_basic_connection(self, ws_config, mock_websocket):
        """Test basic WebSocket connection."""
        client = WebSocketClient(ws_config)

        # Create proper async mock for websockets.connect
        async def mock_connect(*args, **kwargs):
            return mock_websocket

        # Mock the background tasks to prevent infinite loops
        mock_reader_task = AsyncMock()
        mock_ping_task = AsyncMock()

        with patch('accumulate_client.transport.ws.websockets.connect', side_effect=mock_connect):
            with patch('asyncio.create_task', side_effect=[mock_reader_task, mock_ping_task]):
                await client.connect()

                assert client.connected is True
                assert client.retry_count == 0
                assert client.reader_task == mock_reader_task
                assert client.ping_task == mock_ping_task

    @pytest.mark.asyncio
    async def test_connection_already_connected(self, ws_config, mock_websocket):
        """Test connecting when already connected."""
        client = WebSocketClient(ws_config)
        client.connected = True

        await client.connect()  # Should return early
        assert client.websocket is None  # No new connection created

    @pytest.mark.asyncio
    async def test_disconnect(self, ws_config, mock_websocket):
        """Test WebSocket disconnection."""
        client = WebSocketClient(ws_config)

        # Create proper async mock for websockets.connect
        async def mock_connect(*args, **kwargs):
            return mock_websocket

        # Create mock tasks that can be awaited
        async def mock_task():
            pass

        mock_reader_task = asyncio.create_task(mock_task())
        mock_ping_task = asyncio.create_task(mock_task())

        with patch('accumulate_client.transport.ws.websockets.connect', side_effect=mock_connect):
            with patch('asyncio.create_task', side_effect=[mock_reader_task, mock_ping_task]):
                await client.connect()
                await client.disconnect()

                assert client.connected is False
                assert client.running is False
                assert client.websocket is None
                mock_websocket.close.assert_called_once()

    @pytest.mark.asyncio
    async def test_subscribe_auto_connect(self, ws_config, mock_websocket):
        """Test subscription with automatic connection."""
        client = WebSocketClient(ws_config)

        # Mock the message queue
        test_event = Event(type="test", data={"value": 1}, stream="test_stream")
        client.event_queue = AsyncMock()
        client.event_queue.get = AsyncMock(side_effect=[test_event, asyncio.TimeoutError()])

        # Create proper async mock for websockets.connect
        async def mock_connect(*args, **kwargs):
            return mock_websocket

        # Mock the background tasks to prevent infinite loops
        mock_reader_task = AsyncMock()
        mock_ping_task = AsyncMock()

        with patch('accumulate_client.transport.ws.websockets.connect', side_effect=mock_connect):
            with patch('asyncio.create_task', side_effect=[mock_reader_task, mock_ping_task]):
                subscription = client.subscribe("test_stream")
                events = []

                async for event in subscription:
                    events.append(event)
                    break  # Just get one event

                assert len(events) == 1
                assert events[0].stream == "test_stream"
                mock_websocket.send.assert_called()

    @pytest.mark.asyncio
    async def test_send_message(self, ws_config, mock_websocket):
        """Test sending messages."""
        client = WebSocketClient(ws_config)

        # Create proper async mock for websockets.connect
        async def mock_connect(*args, **kwargs):
            return mock_websocket

        # Mock the background tasks to prevent infinite loops
        mock_reader_task = AsyncMock()
        mock_ping_task = AsyncMock()

        with patch('accumulate_client.transport.ws.websockets.connect', side_effect=mock_connect):
            with patch('asyncio.create_task', side_effect=[mock_reader_task, mock_ping_task]):
                await client.send("test_method", {"param": "value"})

                mock_websocket.send.assert_called()
                call_args = mock_websocket.send.call_args[0][0]
                message = json.loads(call_args)

                assert message["method"] == "test_method"
                assert message["params"]["param"] == "value"
                assert "id" in message

    @pytest.mark.asyncio
    async def test_event_hooks(self, ws_config):
        """Test event hooks for metrics/logging."""
        client = WebSocketClient(ws_config)
        hook_calls = []

        def test_hook(event):
            hook_calls.append(event)

        client.add_event_hook(test_hook)

        # Simulate event handling
        test_data = {"method": "test", "params": {"data": "value"}}
        await client._handle_event(test_data)

        assert len(hook_calls) == 1
        assert hook_calls[0].type == "test"

    @pytest.mark.asyncio
    async def test_backpressure_drop_oldest(self, ws_config):
        """Test backpressure handling with drop_oldest policy."""
        ws_config.max_queue_size = 2
        ws_config.queue_behavior = "drop_oldest"
        client = WebSocketClient(ws_config)

        # Fill queue beyond capacity
        event1 = Event(type="test1", data={})
        event2 = Event(type="test2", data={})
        event3 = Event(type="test3", data={})

        await client._enqueue_event(event1)
        await client._enqueue_event(event2)
        await client._enqueue_event(event3)  # Should drop oldest

        # Queue should contain event2 and event3
        queued_events = []
        try:
            while True:
                event = client.event_queue.get_nowait()
                queued_events.append(event)
        except asyncio.QueueEmpty:
            pass

        assert len(queued_events) == 2
        assert queued_events[0].type == "test2"
        assert queued_events[1].type == "test3"

    @pytest.mark.asyncio
    async def test_backpressure_drop_newest(self, ws_config):
        """Test backpressure handling with drop_newest policy."""
        ws_config.max_queue_size = 2
        ws_config.queue_behavior = "drop_newest"
        client = WebSocketClient(ws_config)

        # Fill queue beyond capacity
        event1 = Event(type="test1", data={})
        event2 = Event(type="test2", data={})
        event3 = Event(type="test3", data={})

        await client._enqueue_event(event1)
        await client._enqueue_event(event2)
        await client._enqueue_event(event3)  # Should be dropped

        # Queue should contain event1 and event2
        queued_events = []
        try:
            while True:
                event = client.event_queue.get_nowait()
                queued_events.append(event)
        except asyncio.QueueEmpty:
            pass

        assert len(queued_events) == 2
        assert queued_events[0].type == "test1"
        assert queued_events[1].type == "test2"

    @pytest.mark.asyncio
    async def test_reconnection_logic(self, ws_config, mock_websocket):
        """Test reconnection with exponential backoff."""
        client = WebSocketClient(ws_config)

        connection_attempts = []

        async def mock_connect(*args, **kwargs):
            connection_attempts.append(time.time())
            if len(connection_attempts) < 3:
                raise ConnectionError("Simulated failure")
            return mock_websocket

        with patch('accumulate_client.transport.ws.websockets.connect', side_effect=mock_connect):
            with patch('asyncio.sleep') as mock_sleep:
                # First attempt should fail and trigger reconnection
                await client._handle_connection_error(ConnectionError("Test"))

                # Should have attempted backoff sleep
                assert mock_sleep.called

                # Backoff time should be calculated correctly
                expected_backoff = ws_config.backoff_base * (ws_config.backoff_factor ** 0)
                actual_backoff = mock_sleep.call_args[0][0]
                assert 0 <= actual_backoff <= expected_backoff * 1.2  # Allow for jitter

    @pytest.mark.asyncio
    async def test_max_retries_exceeded(self, ws_config):
        """Test behavior when max retries are exceeded."""
        client = WebSocketClient(ws_config)
        client.retry_count = ws_config.max_retries

        with pytest.raises(ReconnectExceeded):
            await client._handle_connection_error(ConnectionError("Test"))

    @pytest.mark.asyncio
    async def test_message_handling_event(self, ws_config):
        """Test handling of event messages."""
        client = WebSocketClient(ws_config)

        event_message = {
            "method": "block_notification",
            "params": {"height": 100, "hash": "abc123"}
        }

        await client._handle_message(json.dumps(event_message))

        # Event should be queued
        event = client.event_queue.get_nowait()
        assert isinstance(event, BlockEvent)
        assert event.block_height == 100

    @pytest.mark.asyncio
    async def test_message_handling_response(self, ws_config):
        """Test handling of response messages."""
        client = WebSocketClient(ws_config)

        response_message = {
            "id": "test_id",
            "result": {"success": True}
        }

        # Should not raise exception
        await client._handle_message(json.dumps(response_message))

    @pytest.mark.asyncio
    async def test_message_handling_error_response(self, ws_config):
        """Test handling of error response messages."""
        client = WebSocketClient(ws_config)

        error_message = {
            "id": "test_id",
            "error": {"code": -1, "message": "Test error"}
        }

        # Should not raise exception but log error
        await client._handle_message(json.dumps(error_message))

    @pytest.mark.asyncio
    async def test_invalid_json_handling(self, ws_config):
        """Test handling of invalid JSON messages."""
        client = WebSocketClient(ws_config)

        # Should not raise exception
        await client._handle_message("invalid json {")


class TestStreamingClient:
    """Test high-level streaming client."""

    @pytest.fixture
    def mock_http_client(self):
        """Mock HTTP client."""
        mock_client = Mock()
        mock_client.config.endpoint = "https://testnet.accumulatenetwork.io/v3"
        return mock_client

    @pytest.fixture
    def streaming_client(self, mock_http_client):
        """Streaming client with mocked dependencies."""
        # Create proper async mock for WebSocketClient
        mock_ws_client = AsyncMock()
        mock_ws_client.connect = AsyncMock()
        mock_ws_client.disconnect = AsyncMock()
        mock_ws_client.subscribe = AsyncMock()
        mock_ws_client.add_event_hook = Mock()

        with patch('accumulate_client.client.streaming.WebSocketClient', return_value=mock_ws_client):
            return StreamingAccumulateClient(mock_http_client)

    @pytest.mark.asyncio
    async def test_initialization(self, mock_http_client):
        """Test streaming client initialization."""
        with patch('accumulate_client.client.streaming.WebSocketClient') as mock_ws_class:
            client = StreamingAccumulateClient(mock_http_client)

            assert client.http_client == mock_http_client
            mock_ws_class.assert_called_once()

    @pytest.mark.asyncio
    async def test_initialization_with_ws_config(self, mock_http_client):
        """Test initialization with custom WebSocket config."""
        ws_config = WebSocketConfig(url="ws://custom.url")

        with patch('accumulate_client.client.streaming.WebSocketClient') as mock_ws_class:
            client = StreamingAccumulateClient(mock_http_client, ws_config)

            mock_ws_class.assert_called_once_with(ws_config)

    @pytest.mark.asyncio
    async def test_connect_disconnect(self, streaming_client):
        """Test connection management."""
        await streaming_client.connect()
        streaming_client.ws_client.connect.assert_called_once()

        await streaming_client.disconnect()
        streaming_client.ws_client.disconnect.assert_called_once()

    @pytest.mark.asyncio
    async def test_context_manager(self, streaming_client):
        """Test async context manager."""
        async with streaming_client as client:
            assert client == streaming_client
            streaming_client.ws_client.connect.assert_called_once()

        streaming_client.ws_client.disconnect.assert_called_once()

    @pytest.mark.asyncio
    async def test_stream_blocks(self, streaming_client):
        """Test block streaming."""
        mock_events = [
            BlockEvent(type="block", data={"height": 100}),
            BlockEvent(type="block", data={"height": 101})
        ]

        async def mock_subscribe(stream, params):
            for event in mock_events:
                yield event

        streaming_client.ws_client.subscribe = mock_subscribe
        events = []
        async for event in streaming_client.stream_blocks(start_height=100):
            events.append(event)
            if len(events) >= 2:
                break

        assert len(events) == 2
        assert all(isinstance(e, BlockEvent) for e in events)

    @pytest.mark.asyncio
    async def test_stream_tx_status_single(self, streaming_client):
        """Test transaction status streaming for single transaction."""
        mock_events = [
            TxStatusEvent(type="tx_status", data={"txId": "tx123", "status": "pending"}),
            TxStatusEvent(type="tx_status", data={"txId": "tx123", "status": "delivered"})
        ]

        async def mock_subscribe(stream, params):
            assert params["transaction"] == "tx123"
            for event in mock_events:
                yield event

        streaming_client.ws_client.subscribe = mock_subscribe
        events = []
        async for event in streaming_client.stream_tx_status("tx123"):
            events.append(event)
            if len(events) >= 2:
                break

        assert len(events) == 2
        assert events[0].status == "pending"
        assert events[1].status == "delivered"

    @pytest.mark.asyncio
    async def test_stream_tx_status_multiple(self, streaming_client):
        """Test transaction status streaming for multiple transactions."""
        tx_ids = ["tx123", "tx456"]

        async def mock_subscribe(stream, params):
            assert params["transactions"] == tx_ids
            yield TxStatusEvent(type="tx_status", data={"txId": "tx123", "status": "delivered"})

        streaming_client.ws_client.subscribe = mock_subscribe
        events = []
        async for event in streaming_client.stream_tx_status(tx_ids):
            events.append(event)
            break
        assert len(events) == 1
        assert events[0].tx_id == "tx123"

    @pytest.mark.asyncio
    async def test_wait_for_tx_completion(self, streaming_client):
        """Test waiting for transaction completion."""
        mock_events = [
            TxStatusEvent(type="tx_status", data={"txId": "tx123", "status": "pending"}),
            TxStatusEvent(type="tx_status", data={"txId": "tx123", "status": "delivered"})
        ]

        async def mock_stream_tx_status(tx_id):
            for event in mock_events:
                yield event

        streaming_client.stream_tx_status = mock_stream_tx_status

        result = await streaming_client.wait_for_tx_completion("tx123", timeout=1.0)

        assert result.status == "delivered"
        assert result.tx_id == "tx123"

    @pytest.mark.asyncio
    async def test_wait_for_tx_completion_timeout(self, streaming_client):
        """Test transaction completion timeout."""
        async def mock_stream_tx_status(tx_id):
            yield TxStatusEvent(type="tx_status", data={"txId": "tx123", "status": "pending"})
            await asyncio.sleep(2.0)  # Longer than timeout

        streaming_client.stream_tx_status = mock_stream_tx_status

        with pytest.raises(asyncio.TimeoutError):
            await streaming_client.wait_for_tx_completion("tx123", timeout=0.1)

    @pytest.mark.asyncio
    async def test_track_multiple_txs(self, streaming_client):
        """Test tracking multiple transactions."""
        tx_ids = ["tx123", "tx456"]
        mock_events = [
            TxStatusEvent(type="tx_status", data={"txId": "tx123", "status": "delivered"}),
            TxStatusEvent(type="tx_status", data={"txId": "tx456", "status": "failed"})
        ]

        async def mock_stream_tx_status(tx_list):
            for event in mock_events:
                yield event

        streaming_client.stream_tx_status = mock_stream_tx_status

        results = await streaming_client.track_multiple_txs(tx_ids, timeout=1.0)

        assert len(results) == 2
        assert results["tx123"].status == "delivered"
        assert results["tx456"].status == "failed"

    @pytest.mark.asyncio
    async def test_snapshot_then_stream(self, streaming_client):
        """Test snapshot-then-stream pattern."""
        mock_snapshot = {"height": 100, "data": "snapshot"}
        mock_stream_events = [
            Event(type="stream", data={"height": 101}),
            Event(type="stream", data={"height": 102})
        ]

        def mock_query_fn():
            return mock_snapshot

        async def mock_stream_fn():
            for event in mock_stream_events:
                yield event
        events = []
        async for event in streaming_client.snapshot_then_stream(
            mock_query_fn, mock_stream_fn, "height"
        ):
            events.append(event)
            if len(events) >= 3:  # 1 snapshot + 2 stream events
                break

        assert len(events) == 3
        assert events[0].type == "snapshot"
        assert events[0].data == mock_snapshot
        assert events[1].type == "stream"
        assert events[2].type == "stream"

    @pytest.mark.asyncio
    async def test_add_metrics_hook(self, streaming_client):
        """Test adding metrics hooks."""
        def test_hook(event):
            pass

        streaming_client.add_metrics_hook(test_hook)
        streaming_client.ws_client.add_event_hook.assert_called_once_with(test_hook)


class TestUtilityFunctions:
    """Test utility functions."""

    def test_ws_url_from_http_https(self):
        """Test WebSocket URL conversion from HTTPS."""
        result = ws_url_from_http("https://example.com/v3")
        assert result == "wss://example.com/v3/ws"

    def test_ws_url_from_http_http(self):
        """Test WebSocket URL conversion from HTTP."""
        result = ws_url_from_http("http://localhost:8080")
        assert result == "ws://localhost:8080/v3/ws"

    def test_ws_url_from_http_custom_path(self):
        """Test WebSocket URL conversion with custom path."""
        result = ws_url_from_http("https://example.com", "/custom/ws")
        assert result == "wss://example.com/custom/ws"

    def test_ws_url_from_http_invalid_scheme(self):
        """Test WebSocket URL conversion with invalid scheme."""
        with pytest.raises(ValueError, match="Invalid HTTP scheme"):
            ws_url_from_http("ftp://example.com")


if __name__ == "__main__":
    pytest.main([__file__])
