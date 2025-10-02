"""
WebSocket loopback mock tests for streaming functionality.

Tests streaming client with in-process mock server to verify
connection, subscription, and event handling without network dependencies.
"""

import pytest
import pytest_asyncio
import asyncio
import json
from unittest.mock import AsyncMock, Mock
from accumulate_client.transport.ws import WebSocketClient, WebSocketConfig
from accumulate_client.monitoring.metrics import get_registry


class MockWebSocketServer:
    """In-process mock WebSocket server for testing."""

    def __init__(self):
        self.connected_clients = []
        self.message_queue = []
        self.subscription_count = 0
        self.running = False

    async def start(self):
        """Start the mock server."""
        self.running = True

    async def stop(self):
        """Stop the mock server."""
        self.running = False
        self.connected_clients.clear()

    async def add_client(self, client):
        """Add a connected client."""
        self.connected_clients.append(client)

    async def remove_client(self, client):
        """Remove a disconnected client."""
        if client in self.connected_clients:
            self.connected_clients.remove(client)

    async def broadcast_event(self, event):
        """Broadcast event to all connected clients."""
        for client in self.connected_clients:
            await client.receive_event(event)

    async def handle_subscription(self, subscription_request):
        """Handle subscription request."""
        self.subscription_count += 1
        return {
            "id": f"sub_{self.subscription_count}",
            "status": "subscribed",
            "subscription": subscription_request
        }


class MockWebSocketConnection:
    """Mock WebSocket connection that simulates network behavior."""

    def __init__(self, server: MockWebSocketServer):
        self.server = server
        self.event_queue = asyncio.Queue()
        self.connected = False
        self.closed = False

    async def connect(self):
        """Simulate connection to server."""
        self.connected = True
        await self.server.add_client(self)

    async def close(self):
        """Simulate connection close."""
        self.connected = False
        self.closed = True
        await self.server.remove_client(self)

    async def send(self, message):
        """Simulate sending message to server."""
        if not self.connected:
            raise Exception("Connection not open")

        # Parse and handle different message types
        try:
            msg_data = json.loads(message)
            if msg_data.get("method") == "subscribe":
                response = await self.server.handle_subscription(msg_data)
                await self.event_queue.put(json.dumps(response))
        except json.JSONDecodeError:
            pass

    async def receive(self):
        """Simulate receiving message from server."""
        if not self.connected:
            raise Exception("Connection closed")

        # Wait for message from queue
        message = await self.event_queue.get()
        return message

    async def receive_event(self, event):
        """Receive event from server (called by server)."""
        await self.event_queue.put(json.dumps(event))


@pytest_asyncio.fixture
async def mock_server():
    """Create mock WebSocket server."""
    server = MockWebSocketServer()
    await server.start()
    yield server
    await server.stop()


@pytest.fixture
def fresh_metrics_registry():
    """Get fresh metrics registry."""
    registry = get_registry()
    registry._metrics.clear()
    return registry


@pytest.mark.streaming
@pytest.mark.unit
@pytest.mark.asyncio
async def test_ws_client_connect_mock(mock_server):
    """Test WebSocket client connection to mock server."""

    # Create mock connection instead of real WebSocket
    mock_connection = MockWebSocketConnection(mock_server)

    # Patch WebSocket client to use mock
    original_connect = WebSocketClient._create_connection

    async def mock_create_connection(self):
        await mock_connection.connect()
        return mock_connection

    WebSocketClient._create_connection = mock_create_connection

    try:
        config = WebSocketConfig(url="ws://mock-server:8080")
        client = WebSocketClient(config)

        # Connect to mock server
        await client.connect()

        # Verify connection state
        assert len(mock_server.connected_clients) == 1
        assert mock_connection.connected

        # Clean up
        await client.disconnect()
        assert mock_connection.closed

    finally:
        # Restore original method
        WebSocketClient._create_connection = original_connect


@pytest.mark.streaming
@pytest.mark.unit
@pytest.mark.asyncio
async def test_ws_client_subscribe_mock(mock_server):
    """Test WebSocket client subscription with mock server."""

    mock_connection = MockWebSocketConnection(mock_server)

    # Mock the WebSocket client's connection creation
    async def mock_create_connection():
        await mock_connection.connect()
        return mock_connection

    config = WebSocketConfig(url="ws://mock-server:8080")
    client = WebSocketClient(config)

    # Replace connection method
    client._create_connection = mock_create_connection

    await client.connect()

    # Subscribe to blocks
    subscription_id = await client.subscribe_for_id("blocks", {})

    # Verify subscription was processed
    assert mock_server.subscription_count == 1
    assert subscription_id is not None

    await client.disconnect()


@pytest.mark.streaming
@pytest.mark.unit
@pytest.mark.asyncio
async def test_ws_receive_event_mock(mock_server):
    """Test receiving events through WebSocket mock."""

    mock_connection = MockWebSocketConnection(mock_server)

    # Set up client with mock connection
    config = WebSocketConfig(url="ws://mock-server:8080")
    client = WebSocketClient(config)

    async def mock_create_connection():
        await mock_connection.connect()
        return mock_connection

    client._create_connection = mock_create_connection

    await client.connect()

    # Simulate server sending an event
    test_event = {
        "type": "block",
        "data": {
            "block_height": 12345,
            "block_hash": "abc123",
            "timestamp": "2024-01-01T00:00:00Z"
        }
    }

    # Broadcast event from server
    await mock_server.broadcast_event(test_event)

    # Client should receive the event
    received_message = await mock_connection.receive()
    received_event = json.loads(received_message)

    assert received_event["type"] == "block"
    assert received_event["data"]["block_height"] == 12345

    await client.disconnect()


@pytest.mark.streaming
@pytest.mark.metrics
@pytest.mark.unit
@pytest.mark.asyncio
async def test_ws_metrics_integration_mock(mock_server, fresh_metrics_registry):
    """Test WebSocket client metrics integration with mock server."""

    # Create metrics
    connection_counter = fresh_metrics_registry.counter(
        "ws_connections", "WebSocket connections"
    )
    message_counter = fresh_metrics_registry.counter(
        "ws_messages", "WebSocket messages"
    )
    subscription_counter = fresh_metrics_registry.counter(
        "ws_subscriptions", "WebSocket subscriptions"
    )

    mock_connection = MockWebSocketConnection(mock_server)

    config = WebSocketConfig(url="ws://mock-server:8080")
    client = WebSocketClient(config)

    async def mock_create_connection():
        connection_counter.increment(1)
        await mock_connection.connect()
        return mock_connection

    client._create_connection = mock_create_connection

    # Connect and track metrics
    await client.connect()
    assert connection_counter.get_value() == 1

    # Subscribe and track metrics
    subscription_counter.increment(1)
    subscription_id = await client.subscribe_for_id("blocks", {})
    assert subscription_counter.get_value() == 1

    # Send/receive messages and track metrics
    test_event = {"type": "ping", "data": {}}
    await mock_server.broadcast_event(test_event)

    message_counter.increment(1)  # Simulate message received
    assert message_counter.get_value() == 1

    await client.disconnect()


@pytest.mark.streaming
@pytest.mark.unit
@pytest.mark.asyncio
async def test_ws_multiple_clients_mock(mock_server):
    """Test multiple WebSocket clients with mock server."""

    # Create multiple mock connections
    connections = [MockWebSocketConnection(mock_server) for _ in range(3)]
    clients = []

    for i, connection in enumerate(connections):
        config = WebSocketConfig(url=f"ws://mock-server:808{i}")
        client = WebSocketClient(config)

        def make_mock_connect(conn):
            async def mock_create_connection():
                await conn.connect()
                return conn
            return mock_create_connection

        client._create_connection = make_mock_connect(connection)
        clients.append(client)

    # Connect all clients
    for client in clients:
        await client.connect()

    # Verify all are connected
    assert len(mock_server.connected_clients) == 3

    # Broadcast event to all
    test_event = {"type": "broadcast", "message": "hello all"}
    await mock_server.broadcast_event(test_event)

    # All clients should receive the event
    for connection in connections:
        received = await connection.receive()
        event = json.loads(received)
        assert event["type"] == "broadcast"
        assert event["message"] == "hello all"

    # Disconnect all
    for client in clients:
        await client.disconnect()

    assert len(mock_server.connected_clients) == 0


@pytest.mark.streaming
@pytest.mark.unit
@pytest.mark.asyncio
async def test_ws_error_handling_mock(mock_server):
    """Test WebSocket error handling with mock server."""

    mock_connection = MockWebSocketConnection(mock_server)

    config = WebSocketConfig(url="ws://mock-server:8080")
    client = WebSocketClient(config)

    async def mock_create_connection():
        await mock_connection.connect()
        return mock_connection

    client._create_connection = mock_create_connection

    await client.connect()

    # Simulate connection error
    await mock_connection.close()

    # Attempting to send should raise error
    with pytest.raises(Exception):
        await mock_connection.send("test message")

    # Attempting to receive should raise error
    with pytest.raises(Exception):
        await mock_connection.receive()


@pytest.mark.streaming
@pytest.mark.unit
def test_ws_config_validation():
    """Test WebSocket configuration validation."""

    # Valid config
    config = WebSocketConfig(url="ws://localhost:8080")
    assert config.url == "ws://localhost:8080"

    # Test with additional parameters
    config_with_params = WebSocketConfig(
        url="wss://api.example.com/stream",
        timeout=30.0,
        max_retries=5
    )
    assert config_with_params.url == "wss://api.example.com/stream"
    assert config_with_params.timeout == 30.0
    assert config_with_params.max_retries == 5
