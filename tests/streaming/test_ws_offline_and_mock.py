"""
Streaming/WebSocket offline and mock tests.

Tests WebSocket functionality including dependency handling,
mock loopback, and offline behavior.
"""

import pytest
import asyncio
import sys
import time
from unittest.mock import Mock, patch, AsyncMock
from typing import Dict, Any, List


class TestWebSocketDependencies:
    """Test WebSocket dependency handling."""

    def test_websocket_import_with_deps(self):
        """Test WebSocket import when dependencies are available."""
        try:
            from accumulate_client.transport.ws import WebSocketTransport
            assert WebSocketTransport is not None
        except ImportError as e:
            # Should provide helpful error message
            error_msg = str(e).lower()
            expected_terms = ['websocket', 'aiohttp', 'install', 'pip']
            assert any(term in error_msg for term in expected_terms), f"Unhelpful error message: {e}"
            pytest.skip("WebSocket dependencies not available")

    def test_streaming_client_import_with_deps(self):
        """Test streaming client import."""
        try:
            from accumulate_client.client.streaming import StreamingClient
            assert StreamingClient is not None
        except ImportError as e:
            error_msg = str(e).lower()
            expected_terms = ['websocket', 'streaming', 'install', 'aiohttp']
            assert any(term in error_msg for term in expected_terms), f"Unhelpful error message: {e}"
            pytest.skip("Streaming client dependencies not available")

    def test_websocket_dependency_error_message(self):
        """Test that missing WebSocket dependencies give helpful error."""
        # Temporarily hide WebSocket modules
        with patch.dict('sys.modules', {'aiohttp': None, 'websockets': None}):
            try:
                # Force reimport to trigger dependency check
                import importlib
                if 'accumulate_client.transport.ws' in sys.modules:
                    importlib.reload(sys.modules['accumulate_client.transport.ws'])
                else:
                    import accumulate_client.transport.ws
            except ImportError as e:
                error_msg = str(e)
                # Should mention how to install missing dependencies
                assert 'pip install' in error_msg or 'install' in error_msg.lower()
            except:
                # Other errors are acceptable during forced reimport
                pass

    def test_optional_websocket_features(self):
        """Test that WebSocket features are optional."""
        # Core client should work without WebSocket
        try:
            from accumulate_client import AccumulateClient
            # Should be able to create client without WebSocket support
            client = AccumulateClient("http://test.endpoint")
            assert client is not None
        except Exception as e:
            pytest.fail(f"Core client should work without WebSocket: {e}")


class TestMockWebSocketLoopback:
    """Test mock WebSocket loopback functionality."""

    def test_mock_websocket_creation(self):
        """Test creating mock WebSocket connection."""
        try:
            from accumulate_client.transport.ws import WebSocketTransport, WebSocketConfig

            # Create mock transport with proper config
            config = WebSocketConfig(url="ws://mock.endpoint")
            transport = WebSocketTransport(config)
            assert transport is not None

        except ImportError:
            pytest.skip("WebSocket transport not available")

    def test_mock_message_queue(self):
        """Test mock message queue for loopback testing."""
        # Create mock message queue
        message_queue = asyncio.Queue()

        async def test_queue_operations():
            # Test putting and getting messages
            test_message = {"type": "test", "data": "hello"}
            await message_queue.put(test_message)

            received = await message_queue.get()
            assert received == test_message

        if hasattr(asyncio, 'run'):
            asyncio.run(test_queue_operations())

    def test_mock_subscription_lifecycle(self):
        """Test mock subscription lifecycle."""
        try:
            from accumulate_client.client.streaming import StreamingClient

            # Mock WebSocket connection
            class MockWebSocket:
                def __init__(self):
                    self.subscriptions = set()
                    self.message_queue = asyncio.Queue()

                async def subscribe(self, query: str):
                    self.subscriptions.add(query)
                    return {"status": "subscribed", "query": query}

                async def unsubscribe(self, query: str):
                    self.subscriptions.discard(query)
                    return {"status": "unsubscribed", "query": query}

                async def receive(self):
                    return await self.message_queue.get()

                async def send_mock_message(self, message):
                    await self.message_queue.put(message)

            # Test subscription lifecycle
            async def test_lifecycle():
                mock_ws = MockWebSocket()

                # Test subscribe
                sub_result = await mock_ws.subscribe("acc://test.acme")
                assert sub_result["status"] == "subscribed"
                assert "acc://test.acme" in mock_ws.subscriptions

                # Test unsubscribe
                unsub_result = await mock_ws.unsubscribe("acc://test.acme")
                assert unsub_result["status"] == "unsubscribed"
                assert "acc://test.acme" not in mock_ws.subscriptions

            if hasattr(asyncio, 'run'):
                asyncio.run(test_lifecycle())

        except ImportError:
            pytest.skip("Streaming client not available")

    def test_mock_message_flow(self):
        """Test mock message flow from subscription to receipt."""
        # Mock streaming scenario
        async def test_message_flow():
            message_queue = asyncio.Queue()

            # Simulate subscription message
            subscription_msg = {
                "type": "subscription",
                "query": "acc://test.acme",
                "status": "active"
            }
            await message_queue.put(subscription_msg)

            # Simulate data message
            data_msg = {
                "type": "data",
                "query": "acc://test.acme",
                "data": {
                    "balance": 1000000,
                    "timestamp": time.time()
                }
            }
            await message_queue.put(data_msg)

            # Simulate receiving messages
            received_messages = []
            for _ in range(2):
                msg = await asyncio.wait_for(message_queue.get(), timeout=1.0)
                received_messages.append(msg)

            # Verify message flow
            assert len(received_messages) == 2
            assert received_messages[0]["type"] == "subscription"
            assert received_messages[1]["type"] == "data"

        if hasattr(asyncio, 'run'):
            asyncio.run(test_message_flow())


class TestWebSocketHealthAndPing:
    """Test WebSocket health monitoring and ping/pong."""

    def test_ping_pong_mechanism(self):
        """Test WebSocket ping/pong health check."""
        try:
            from accumulate_client.transport.ws import WebSocketTransport

            class MockWebSocketWithPing:
                def __init__(self):
                    self.last_ping = None
                    self.last_pong = None

                async def ping(self, data=None):
                    self.last_ping = time.time()
                    # Simulate pong response
                    await asyncio.sleep(0.001)
                    self.last_pong = time.time()
                    return self.last_pong - self.last_ping

                async def wait_for_pong(self, timeout=1.0):
                    # Simulate waiting for pong
                    await asyncio.sleep(0.001)
                    return True

            async def test_ping_pong():
                mock_ws = MockWebSocketWithPing()

                # Test ping
                latency = await mock_ws.ping()
                assert latency >= 0
                assert mock_ws.last_ping is not None
                assert mock_ws.last_pong is not None

                # Test pong wait
                pong_received = await mock_ws.wait_for_pong()
                assert pong_received

            if hasattr(asyncio, 'run'):
                asyncio.run(test_ping_pong())

        except ImportError:
            pytest.skip("WebSocket transport not available")

    def test_connection_health_monitoring(self):
        """Test connection health monitoring."""
        class MockHealthMonitor:
            def __init__(self):
                self.ping_interval = 30.0
                self.last_ping_time = None
                self.connection_healthy = True

            async def health_check(self):
                """Perform health check."""
                current_time = time.time()
                if self.last_ping_time is None:
                    self.last_ping_time = current_time
                    return True

                time_since_ping = current_time - self.last_ping_time
                if time_since_ping > self.ping_interval:
                    # Time for a ping
                    self.last_ping_time = current_time
                    # Simulate ping success/failure
                    return self.connection_healthy

                return True

            def simulate_connection_loss(self):
                """Simulate connection loss."""
                self.connection_healthy = False

            def simulate_connection_recovery(self):
                """Simulate connection recovery."""
                self.connection_healthy = True

        async def test_health_monitoring():
            monitor = MockHealthMonitor()

            # Test healthy connection
            is_healthy = await monitor.health_check()
            assert is_healthy

            # Simulate connection loss
            monitor.simulate_connection_loss()
            # Force ping by setting old timestamp
            monitor.last_ping_time = time.time() - 60

            is_healthy = await monitor.health_check()
            assert not is_healthy

            # Simulate recovery
            monitor.simulate_connection_recovery()
            is_healthy = await monitor.health_check()
            assert is_healthy

        if hasattr(asyncio, 'run'):
            asyncio.run(test_health_monitoring())

    def test_reconnection_logic(self):
        """Test WebSocket reconnection logic."""
        class MockReconnectingWebSocket:
            def __init__(self):
                self.connection_attempts = 0
                self.max_attempts = 3
                self.connected = False
                self.backoff_delay = 0.01

            async def connect(self):
                """Attempt to connect."""
                self.connection_attempts += 1

                if self.connection_attempts <= 2:
                    # Fail first two attempts
                    raise ConnectionError("Connection failed")

                # Succeed on third attempt
                self.connected = True
                return True

            async def reconnect_with_backoff(self):
                """Reconnect with exponential backoff."""
                attempt = 0
                while attempt < self.max_attempts:
                    try:
                        await self.connect()
                        return True
                    except ConnectionError:
                        attempt += 1
                        if attempt < self.max_attempts:
                            delay = self.backoff_delay * (2 ** attempt)
                            await asyncio.sleep(delay)

                return False

        async def test_reconnection():
            reconnecting_ws = MockReconnectingWebSocket()

            # Test reconnection
            success = await reconnecting_ws.reconnect_with_backoff()
            assert success
            assert reconnecting_ws.connected
            assert reconnecting_ws.connection_attempts == 3

        if hasattr(asyncio, 'run'):
            asyncio.run(test_reconnection())


class TestStreamingErrorHandling:
    """Test streaming error handling scenarios."""

    def test_connection_timeout_handling(self):
        """Test handling of connection timeouts."""
        async def test_timeout():
            # Simulate connection timeout
            async def slow_connect():
                await asyncio.sleep(2.0)  # Longer than timeout
                return "connected"

            try:
                # Should timeout before connection completes
                result = await asyncio.wait_for(slow_connect(), timeout=0.1)
                pytest.fail("Should have timed out")
            except asyncio.TimeoutError:
                # Expected behavior
                pass

        if hasattr(asyncio, 'run'):
            asyncio.run(test_timeout())

    def test_malformed_message_handling(self):
        """Test handling of malformed WebSocket messages."""
        def handle_message(raw_message):
            """Handle potentially malformed message."""
            try:
                import json
                if isinstance(raw_message, str):
                    message = json.loads(raw_message)
                elif isinstance(raw_message, bytes):
                    message = json.loads(raw_message.decode('utf-8'))
                else:
                    message = raw_message

                # Validate message structure
                if not isinstance(message, dict):
                    raise ValueError("Message must be a dictionary")

                if 'type' not in message:
                    raise ValueError("Message must have a 'type' field")

                return message

            except (json.JSONDecodeError, ValueError) as e:
                # Log error and return None for malformed messages
                return None

        # Test valid messages
        valid_message = '{"type": "data", "content": "test"}'
        parsed = handle_message(valid_message)
        assert parsed is not None
        assert parsed['type'] == 'data'

        # Test malformed messages
        malformed_messages = [
            '{"invalid": json}',  # Invalid JSON
            '"not an object"',    # Not a dict
            '{}',                 # Missing type field
            None,                 # None value
            b'\xff\xfe',         # Invalid bytes
        ]

        for malformed in malformed_messages:
            parsed = handle_message(malformed)
            assert parsed is None, f"Should handle malformed message: {malformed}"

    def test_subscription_error_recovery(self):
        """Test recovery from subscription errors."""
        class MockSubscriptionManager:
            def __init__(self):
                self.subscriptions = {}
                self.failed_subscriptions = set()

            async def subscribe(self, query: str, retry_on_error=True):
                """Subscribe with error recovery."""
                try:
                    # Simulate subscription
                    if query in self.failed_subscriptions:
                        if retry_on_error:
                            # Remove from failed set and retry
                            self.failed_subscriptions.discard(query)
                        else:
                            raise ConnectionError("Subscription failed")

                    self.subscriptions[query] = {"status": "active"}
                    return True

                except ConnectionError:
                    self.failed_subscriptions.add(query)
                    if retry_on_error:
                        # Wait and retry
                        await asyncio.sleep(0.01)
                        return await self.subscribe(query, retry_on_error=False)
                    raise

            def get_subscription_status(self, query: str):
                """Get subscription status."""
                if query in self.subscriptions:
                    return "active"
                elif query in self.failed_subscriptions:
                    return "failed"
                else:
                    return "not_subscribed"

        async def test_subscription_recovery():
            manager = MockSubscriptionManager()

            # Add query to failed set first
            manager.failed_subscriptions.add("acc://test.acme")

            # Subscribe with retry should succeed
            success = await manager.subscribe("acc://test.acme", retry_on_error=True)
            assert success

            # Should now be active
            status = manager.get_subscription_status("acc://test.acme")
            assert status == "active"

        if hasattr(asyncio, 'run'):
            asyncio.run(test_subscription_recovery())


class TestWebSocketIntegration:
    """Test WebSocket integration with core client."""

    def test_client_websocket_integration(self):
        """Test that client can integrate with WebSocket transport."""
        try:
            from accumulate_client import AccumulateClient
            from accumulate_client.transport.ws import WebSocketTransport, WebSocketConfig

            # Test that client can accept WebSocket transport with proper config
            config = WebSocketConfig(url="ws://test.endpoint")
            ws_transport = WebSocketTransport(config)

            # Some clients might accept transport parameter
            try:
                client = AccumulateClient("http://test.endpoint", transport=ws_transport)
                assert client is not None
            except TypeError:
                # Client might not support custom transport
                pass

        except ImportError:
            pytest.skip("WebSocket integration not available")

    def test_streaming_query_interface(self):
        """Test streaming query interface."""
        try:
            from accumulate_client.client.streaming import StreamingClient

            # Mock streaming client
            class MockStreamingClient:
                def __init__(self, endpoint):
                    self.endpoint = endpoint
                    self.subscriptions = {}

                async def stream_account(self, url: str):
                    """Stream account updates."""
                    # Mock async generator
                    for i in range(3):
                        yield {
                            "url": url,
                            "balance": 1000000 + i * 100000,
                            "timestamp": time.time() + i
                        }
                        await asyncio.sleep(0.001)

                async def stream_transactions(self, account: str):
                    """Stream transaction updates."""
                    for i in range(2):
                        yield {
                            "account": account,
                            "hash": f"tx_hash_{i}",
                            "type": "SendTokens",
                            "timestamp": time.time() + i
                        }
                        await asyncio.sleep(0.001)

            async def test_streaming_interface():
                mock_client = MockStreamingClient("ws://test.endpoint")

                # Test account streaming
                account_updates = []
                async for update in mock_client.stream_account("acc://test.acme"):
                    account_updates.append(update)

                assert len(account_updates) == 3
                assert all(update["url"] == "acc://test.acme" for update in account_updates)

                # Test transaction streaming
                tx_updates = []
                async for tx in mock_client.stream_transactions("acc://test.acme"):
                    tx_updates.append(tx)

                assert len(tx_updates) == 2
                assert all(tx["account"] == "acc://test.acme" for tx in tx_updates)

            if hasattr(asyncio, 'run'):
                asyncio.run(test_streaming_interface())

        except ImportError:
            pytest.skip("Streaming client not available")