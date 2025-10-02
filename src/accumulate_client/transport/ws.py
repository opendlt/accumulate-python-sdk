"""
WebSocket transport for Accumulate streaming APIs.

Provides async WebSocket client with reconnection, ping/pong handling,
and backpressure management for real-time event streaming.
"""

import asyncio
import json
import logging
import random
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, AsyncIterator, Union
from urllib.parse import urlparse

try:
    import websockets
    from websockets.exceptions import ConnectionClosed
    HAS_WEBSOCKETS = True
except ImportError:
    HAS_WEBSOCKETS = False
    websockets = None
    ConnectionClosed = Exception


logger = logging.getLogger(__name__)


class WebSocketError(Exception):
    """Base WebSocket error."""
    pass


class ReconnectExceeded(WebSocketError):
    """Maximum reconnection attempts exceeded."""
    pass


class ProtocolError(WebSocketError):
    """WebSocket protocol violation."""
    pass


@dataclass
class Event:
    """Base event type for WebSocket messages."""
    type: str
    data: Dict[str, Any]
    timestamp: float = field(default_factory=time.time)
    stream: Optional[str] = None


@dataclass
class BlockEvent(Event):
    """Block-related event."""
    block_height: Optional[int] = None
    block_hash: Optional[str] = None

    def __post_init__(self):
        self.type = "block"
        if self.data and "height" in self.data:
            self.block_height = self.data["height"]
        if self.data and "hash" in self.data:
            self.block_hash = self.data["hash"]


@dataclass
class TxStatusEvent(Event):
    """Transaction status event."""
    tx_id: Optional[str] = None
    status: Optional[str] = None

    def __post_init__(self):
        self.type = "tx_status"
        if self.data and "txId" in self.data:
            self.tx_id = self.data["txId"]
        if self.data and "status" in self.data:
            self.status = self.data["status"]


@dataclass
class AnchorEvent(Event):
    """Anchor-related event."""
    anchor_hash: Optional[str] = None
    source_chain: Optional[str] = None

    def __post_init__(self):
        self.type = "anchor"
        if self.data and "anchorHash" in self.data:
            self.anchor_hash = self.data["anchorHash"]
        if self.data and "sourceChain" in self.data:
            self.source_chain = self.data["sourceChain"]


@dataclass
class LogEvent(Event):
    """Log event."""
    level: Optional[str] = None
    message: Optional[str] = None

    def __post_init__(self):
        self.type = "log"
        if self.data and "level" in self.data:
            self.level = self.data["level"]
        if self.data and "message" in self.data:
            self.message = self.data["message"]


@dataclass
class WebSocketConfig:
    """Configuration for WebSocket client."""
    url: str
    headers: Optional[Dict[str, str]] = None
    timeout: float = 30.0  # Connection timeout
    ping_interval: float = 30.0
    ping_timeout: float = 10.0
    max_retries: int = 5
    backoff_base: float = 1.0
    backoff_factor: float = 2.0
    backoff_max: float = 60.0
    backoff_jitter: float = 0.1
    max_queue_size: int = 1000
    queue_behavior: str = "drop_oldest"  # "drop_oldest", "block", "drop_newest"


class WebSocketClient:
    """
    Async WebSocket client with automatic reconnection and event streaming.

    Features:
    - Automatic reconnection with exponential backoff and jitter
    - Ping/pong handling for connection health
    - Backpressure management with configurable queue behavior
    - Event subscription and routing
    - Graceful error handling and recovery
    """

    def __init__(self, config: WebSocketConfig):
        """
        Initialize WebSocket client.

        Args:
            config: WebSocket configuration

        Raises:
            ImportError: If websockets library is not available
        """
        if not HAS_WEBSOCKETS:
            raise ImportError(
                "WebSocket functionality requires 'websockets' library. "
                "Install with: pip install websockets"
            )

        self.config = config
        self.websocket = None
        self.connected = False
        self.running = False
        self.retry_count = 0

        # Event handling
        self.event_queue = asyncio.Queue(maxsize=config.max_queue_size)
        self.subscriptions = {}  # stream_name -> subscription_id
        self.event_hooks = []  # List of callable hooks for metrics/logging

        # Tasks
        self.reader_task = None
        self.ping_task = None

        # Connection state
        self.last_ping = None
        self.last_pong = None

    async def _create_connection(self):
        """Create WebSocket connection."""
        return await websockets.connect(
            self.config.url,
            additional_headers=self.config.headers or {},  # Fixed parameter name
            ping_interval=None,  # We handle ping/pong manually
            ping_timeout=None,
            close_timeout=5.0
        )

    async def connect(self) -> None:
        """Connect to WebSocket server."""
        if self.connected:
            return

        logger.info(f"Connecting to WebSocket: {self.config.url}")

        try:
            self.websocket = await self._create_connection()

            self.connected = True
            self.running = True
            self.retry_count = 0

            # Start background tasks
            self.reader_task = asyncio.create_task(self._reader_loop())
            self.ping_task = asyncio.create_task(self._ping_loop())

            logger.info("WebSocket connected successfully")

        except Exception as e:
            logger.error(f"Failed to connect to WebSocket: {e}")
            await self._handle_connection_error(e)

    async def disconnect(self) -> None:
        """Disconnect from WebSocket server."""
        logger.info("Disconnecting WebSocket")

        self.running = False
        self.connected = False

        # Cancel background tasks
        if self.reader_task:
            self.reader_task.cancel()
            try:
                await self.reader_task
            except asyncio.CancelledError:
                pass

        if self.ping_task:
            self.ping_task.cancel()
            try:
                await self.ping_task
            except asyncio.CancelledError:
                pass

        # Close WebSocket connection
        if self.websocket:
            try:
                await self.websocket.close()
            except Exception as e:
                logger.debug(f"Error closing WebSocket: {e}")
            finally:
                self.websocket = None

    async def subscribe_for_id(self, stream: str, params: Optional[Dict[str, Any]] = None) -> str:
        """
        Subscribe to an event stream and return subscription ID.

        Args:
            stream: Stream name to subscribe to
            params: Optional subscription parameters

        Returns:
            Subscription ID string

        Raises:
            WebSocketError: If subscription fails
        """
        if not self.connected:
            await self.connect()

        # Send subscription request
        subscription_request = {
            "method": "subscribe",
            "params": {
                "stream": stream,
                **(params or {})
            },
            "id": f"sub_{stream}_{int(time.time())}"
        }

        try:
            await self.websocket.send(json.dumps(subscription_request))
            subscription_id = subscription_request["id"]
            self.subscriptions[stream] = subscription_id
            logger.info(f"Subscribed to stream: {stream}")
            return subscription_id

        except Exception as e:
            logger.error(f"Failed to subscribe to {stream}: {e}")
            raise WebSocketError(f"Subscription failed: {e}")

    async def subscribe(self, stream: str, params: Optional[Dict[str, Any]] = None) -> AsyncIterator[Event]:
        """
        Subscribe to an event stream.

        Args:
            stream: Stream name to subscribe to
            params: Optional subscription parameters

        Yields:
            Event objects from the stream

        Raises:
            WebSocketError: If subscription fails
        """
        if not self.connected:
            await self.connect()

        # Send subscription request
        subscription_request = {
            "method": "subscribe",
            "params": {
                "stream": stream,
                **(params or {})
            },
            "id": f"sub_{stream}_{int(time.time())}"
        }

        try:
            await self.websocket.send(json.dumps(subscription_request))
            self.subscriptions[stream] = subscription_request["id"]
            logger.info(f"Subscribed to stream: {stream}")

        except Exception as e:
            logger.error(f"Failed to subscribe to {stream}: {e}")
            raise WebSocketError(f"Subscription failed: {e}")

        # Yield events from the queue
        try:
            while self.running and self.connected:
                try:
                    # Wait for events with timeout to allow graceful shutdown
                    event = await asyncio.wait_for(self.event_queue.get(), timeout=1.0)

                    # Filter events for this stream
                    if event.stream == stream or event.stream is None:
                        yield event

                except asyncio.TimeoutError:
                    # Check if we should continue running
                    if not self.running or not self.connected:
                        break
                    continue
                except Exception as e:
                    logger.error(f"Error receiving event: {e}")
                    break
        except asyncio.CancelledError:
            logger.debug(f"Subscribe loop for {stream} cancelled")
            raise

    async def send(self, method: str, params: Optional[Dict[str, Any]] = None) -> None:
        """
        Send a message to the WebSocket server.

        Args:
            method: RPC method name
            params: Optional parameters
        """
        if not self.connected:
            await self.connect()

        message = {
            "method": method,
            "params": params or {},
            "id": f"req_{int(time.time())}"
        }

        try:
            await self.websocket.send(json.dumps(message))
        except Exception as e:
            logger.error(f"Failed to send message: {e}")
            await self._handle_connection_error(e)

    def add_event_hook(self, hook: callable) -> None:
        """Add an event hook for metrics/logging."""
        self.event_hooks.append(hook)

    async def _reader_loop(self) -> None:
        """Main message reading loop."""
        logger.debug("Starting WebSocket reader loop")

        try:
            while self.running and self.connected and self.websocket:
                try:
                    message = await asyncio.wait_for(
                        self.websocket.recv(),
                        timeout=self.config.ping_timeout + 5.0
                    )

                    await self._handle_message(message)

                except asyncio.TimeoutError:
                    logger.warning("WebSocket read timeout")
                    await self._handle_connection_error(TimeoutError("Read timeout"))
                    break

                except ConnectionClosed as e:
                    logger.info(f"WebSocket connection closed: {e}")
                    await self._handle_connection_error(e)
                    break

                except Exception as e:
                    logger.error(f"Error in reader loop: {e}")
                    await self._handle_connection_error(e)
                    break
        except asyncio.CancelledError:
            logger.debug("Reader loop cancelled")
            raise
        finally:
            logger.debug("Reader loop exiting")

    async def _ping_loop(self) -> None:
        """Ping/pong health check loop."""
        logger.debug("Starting WebSocket ping loop")

        try:
            while self.running and self.connected and self.websocket:
                try:
                    await asyncio.sleep(self.config.ping_interval)

                    if not self.running or not self.connected or not self.websocket:
                        break

                    # Send ping
                    self.last_ping = time.time()
                    await self.websocket.ping()
                    logger.debug("Sent WebSocket ping")

                    # Wait for pong with timeout
                    try:
                        pong_waiter = await asyncio.wait_for(
                            self.websocket.ping(),
                            timeout=self.config.ping_timeout
                        )
                        self.last_pong = time.time()
                        logger.debug("Received WebSocket pong")

                    except asyncio.TimeoutError:
                        logger.warning("WebSocket ping timeout")
                        await self._handle_connection_error(TimeoutError("Ping timeout"))
                        break

                except Exception as e:
                    logger.error(f"Error in ping loop: {e}")
                    await self._handle_connection_error(e)
                    break
        except asyncio.CancelledError:
            logger.debug("Ping loop cancelled")
            raise
        finally:
            logger.debug("Ping loop exiting")

    async def _handle_message(self, message: str) -> None:
        """Handle incoming WebSocket message."""
        try:
            data = json.loads(message)

            # Handle different message types
            if "method" in data:
                # This is an event/notification
                await self._handle_event(data)
            elif "result" in data or "error" in data:
                # This is a response to our request
                await self._handle_response(data)
            else:
                logger.debug(f"Unknown message format: {data}")

        except json.JSONDecodeError as e:
            logger.error(f"Invalid JSON message: {e}")
        except Exception as e:
            logger.error(f"Error handling message: {e}")

    async def _handle_event(self, data: Dict[str, Any]) -> None:
        """Handle event message and route to appropriate event type."""
        try:
            # Determine event type and create appropriate event object
            method = data.get("method", "")
            params = data.get("params", {})

            if "block" in method.lower():
                event = BlockEvent(type="block", data=params)
            elif "tx" in method.lower() or "transaction" in method.lower():
                event = TxStatusEvent(type="tx_status", data=params)
            elif "anchor" in method.lower():
                event = AnchorEvent(type="anchor", data=params)
            elif "log" in method.lower():
                event = LogEvent(type="log", data=params)
            else:
                event = Event(type=method, data=params)

            # Determine stream from subscription context
            event.stream = params.get("stream")

            # Call event hooks for metrics/logging
            for hook in self.event_hooks:
                try:
                    hook(event)
                except Exception as e:
                    logger.debug(f"Event hook error: {e}")

            # Add to queue with backpressure handling
            await self._enqueue_event(event)

        except Exception as e:
            logger.error(f"Error handling event: {e}")

    async def _handle_response(self, data: Dict[str, Any]) -> None:
        """Handle response message."""
        if "error" in data:
            error = data["error"]
            logger.error(f"WebSocket RPC error: {error}")
        else:
            logger.debug(f"WebSocket RPC response: {data}")

    async def _enqueue_event(self, event: Event) -> None:
        """Enqueue event with backpressure handling."""
        try:
            if self.config.queue_behavior == "block":
                await self.event_queue.put(event)
            else:
                # Non-blocking put
                self.event_queue.put_nowait(event)

        except asyncio.QueueFull:
            if self.config.queue_behavior == "drop_oldest":
                # Remove oldest event and add new one
                try:
                    self.event_queue.get_nowait()
                    self.event_queue.put_nowait(event)
                    logger.warning("Dropped oldest event due to queue full")
                except asyncio.QueueEmpty:
                    pass
            elif self.config.queue_behavior == "drop_newest":
                # Drop the new event
                logger.warning("Dropped newest event due to queue full")
            else:
                logger.error(f"Unknown queue behavior: {self.config.queue_behavior}")

    async def _handle_connection_error(self, error: Exception) -> None:
        """Handle connection errors and attempt reconnection."""
        self.connected = False

        if self.retry_count >= self.config.max_retries:
            logger.error(f"Max retries ({self.config.max_retries}) exceeded")
            self.running = False
            raise ReconnectExceeded(f"Failed to reconnect after {self.config.max_retries} attempts")

        # Calculate backoff with jitter
        backoff = min(
            self.config.backoff_base * (self.config.backoff_factor ** self.retry_count),
            self.config.backoff_max
        )
        jitter = backoff * self.config.backoff_jitter * (random.random() - 0.5)
        backoff_with_jitter = max(0, backoff + jitter)

        self.retry_count += 1
        logger.info(f"Reconnecting in {backoff_with_jitter:.1f}s (attempt {self.retry_count}/{self.config.max_retries})")

        await asyncio.sleep(backoff_with_jitter)

        if self.running:
            await self.connect()


def ws_url_from_http(http_url: str, ws_path: str = "/v3/ws") -> str:
    """
    Convert HTTP URL to WebSocket URL.

    Args:
        http_url: HTTP endpoint URL
        ws_path: WebSocket path to append

    Returns:
        WebSocket URL
    """
    parsed = urlparse(http_url)

    # Convert scheme
    if parsed.scheme == "https":
        ws_scheme = "wss"
    elif parsed.scheme == "http":
        ws_scheme = "ws"
    else:
        raise ValueError(f"Invalid HTTP scheme: {parsed.scheme}")

    # Build WebSocket URL
    ws_url = f"{ws_scheme}://{parsed.netloc}{ws_path}"

    return ws_url


# Backward compatibility aliases
WebSocketTransport = WebSocketClient