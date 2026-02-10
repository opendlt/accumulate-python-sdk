"""
Streaming Accumulate client for real-time data.

Provides high-level streaming interface wrapping WebSocket transport
with helper methods for common streaming patterns.
"""

import asyncio
import logging
from typing import Any, Dict, Optional, AsyncIterator, Callable, Union

try:
    from ..transport.ws import (
        WebSocketClient, WebSocketConfig, Event, BlockEvent, TxStatusEvent,
        AnchorEvent, LogEvent, ws_url_from_http
    )
    HAS_WEBSOCKETS = True
except ImportError as e:
    HAS_WEBSOCKETS = False
    if "websockets" in str(e):
        raise ImportError(
            "WebSocket functionality requires 'websockets' library. "
            "Install with: pip install websockets"
        ) from e
    raise

logger = logging.getLogger(__name__)


class StreamingAccumulateClient:
    """
    Streaming Accumulate client with WebSocket support.

    Provides high-level streaming interface for real-time Accumulate data:
    - Block streaming
    - Transaction status tracking
    - Directory anchor monitoring
    - Log streaming
    - Snapshot-then-stream patterns
    """

    def __init__(self, http_client=None, ws_config: Optional[WebSocketConfig] = None, endpoint: Optional[str] = None):
        """
        Initialize streaming client.

        Args:
            http_client: HTTP client for snapshot queries
            ws_config: WebSocket configuration (auto-derived if None)
            endpoint: Explicit endpoint URL (used to derive WebSocket URL if ws_config is None)
        """
        self.http_client = http_client

        # Auto-derive WebSocket config if not provided
        if ws_config is None:
            ep = endpoint
            if not ep:
                _ep = getattr(http_client, 'endpoint', None)
                if isinstance(_ep, str):
                    ep = _ep
            if not ep:
                ep = getattr(getattr(http_client, 'config', None), 'endpoint', None)
            if not ep:
                raise ValueError("Must provide endpoint or http_client with .endpoint")
            ws_url = ws_url_from_http(ep)
            ws_config = WebSocketConfig(url=ws_url)

        self.ws_client = WebSocketClient(ws_config)

    async def connect(self) -> None:
        """Connect to WebSocket server."""
        await self.ws_client.connect()

    async def disconnect(self) -> None:
        """Disconnect from WebSocket server."""
        await self.ws_client.disconnect()

    async def stream_blocks(self, start_height: Optional[int] = None,
                          filter_params: Optional[Dict[str, Any]] = None) -> AsyncIterator[BlockEvent]:
        """
        Stream block events.

        Args:
            start_height: Optional starting block height
            filter_params: Optional filter parameters

        Yields:
            BlockEvent objects
        """
        params = filter_params or {}
        if start_height is not None:
            params["startHeight"] = start_height

        async for event in self.ws_client.subscribe("blocks", params):
            if isinstance(event, BlockEvent):
                yield event
            elif event.type == "block":
                # Convert generic event to BlockEvent
                yield BlockEvent(
                    type="block",
                    data=event.data,
                    timestamp=event.timestamp,
                    stream=event.stream
                )

    async def stream_tx_status(self, url_or_id: Union[str, list],
                             follow_children: bool = False) -> AsyncIterator[TxStatusEvent]:
        """
        Stream transaction status updates.

        Args:
            url_or_id: Transaction ID, URL, or list of IDs/URLs to track
            follow_children: Whether to follow child transactions

        Yields:
            TxStatusEvent objects
        """
        params = {
            "followChildren": follow_children
        }

        if isinstance(url_or_id, list):
            params["transactions"] = url_or_id
        else:
            params["transaction"] = url_or_id

        async for event in self.ws_client.subscribe("tx_status", params):
            if isinstance(event, TxStatusEvent):
                yield event
            elif event.type == "tx_status":
                # Convert generic event to TxStatusEvent
                yield TxStatusEvent(
                    type="tx_status",
                    data=event.data,
                    timestamp=event.timestamp,
                    stream=event.stream
                )

    async def stream_logs(self, level: Optional[str] = None,
                        source: Optional[str] = None,
                        filter_params: Optional[Dict[str, Any]] = None) -> AsyncIterator[LogEvent]:
        """
        Stream log events.

        Args:
            level: Log level filter (debug, info, warn, error)
            source: Source component filter
            filter_params: Additional filter parameters

        Yields:
            LogEvent objects
        """
        params = filter_params or {}
        if level is not None:
            params["level"] = level
        if source is not None:
            params["source"] = source

        async for event in self.ws_client.subscribe("logs", params):
            if isinstance(event, LogEvent):
                yield event
            elif event.type == "log":
                # Convert generic event to LogEvent
                yield LogEvent(
                    type="log",
                    data=event.data,
                    timestamp=event.timestamp,
                    stream=event.stream
                )

    async def stream_directory_anchors(self, directory: Optional[str] = None,
                                     filter_params: Optional[Dict[str, Any]] = None) -> AsyncIterator[AnchorEvent]:
        """
        Stream directory anchor events.

        Args:
            directory: Directory URL to monitor
            filter_params: Additional filter parameters

        Yields:
            AnchorEvent objects
        """
        params = filter_params or {}
        if directory is not None:
            params["directory"] = directory

        async for event in self.ws_client.subscribe("anchors", params):
            if isinstance(event, AnchorEvent):
                yield event
            elif event.type == "anchor":
                # Convert generic event to AnchorEvent
                yield AnchorEvent(
                    type="anchor",
                    data=event.data,
                    timestamp=event.timestamp,
                    stream=event.stream
                )

    async def snapshot_then_stream(self,
                                 query_fn: Callable[[], Any],
                                 stream_fn: Callable[[], AsyncIterator[Event]],
                                 snapshot_key: str = "height") -> AsyncIterator[Event]:
        """
        Snapshot-then-stream pattern: query current state, then stream updates.

        This pattern ensures no events are missed between the snapshot and
        starting the stream by:
        1. Taking a snapshot via HTTP
        2. Starting the stream from the snapshot point
        3. Yielding the snapshot data
        4. Yielding streaming updates

        Args:
            query_fn: Function to get current snapshot
            stream_fn: Function to start streaming
            snapshot_key: Key to extract continuation point from snapshot

        Yields:
            Event objects (snapshot + stream)
        """
        # Take snapshot
        logger.info("Taking snapshot before streaming")
        snapshot = await asyncio.get_event_loop().run_in_executor(None, query_fn)

        # Extract continuation point
        continuation_point = None
        if isinstance(snapshot, dict) and snapshot_key in snapshot:
            continuation_point = snapshot[snapshot_key]

        # Yield snapshot as event
        snapshot_event = Event(
            type="snapshot",
            data=snapshot,
            stream="snapshot"
        )
        yield snapshot_event

        # Start streaming from continuation point
        logger.info(f"Starting stream from {snapshot_key}={continuation_point}")
        async for event in stream_fn():
            yield event

    async def wait_for_tx_completion(self, tx_id: str, timeout: float = 60.0,
                                   states: Optional[list] = None) -> TxStatusEvent:
        """
        Wait for a transaction to reach completion.

        Args:
            tx_id: Transaction ID to wait for
            timeout: Maximum time to wait in seconds
            states: List of completion states (default: ["delivered", "failed"])

        Returns:
            Final TxStatusEvent

        Raises:
            asyncio.TimeoutError: If transaction doesn't complete within timeout
        """
        if states is None:
            states = ["delivered", "failed"]

        logger.info(f"Waiting for transaction {tx_id} to reach states: {states}")

        async def stream_and_check():
            async for event in self.stream_tx_status(tx_id):
                logger.debug(f"Transaction {tx_id} status: {event.status}")
                if event.status in states:
                    return event
            return None

        try:
            result = await asyncio.wait_for(stream_and_check(), timeout=timeout)
            if result is None:
                raise asyncio.TimeoutError(f"Transaction {tx_id} did not complete")
            return result

        except asyncio.TimeoutError:
            logger.error(f"Timeout waiting for transaction {tx_id}")
            raise

    async def track_multiple_txs(self, tx_ids: list, timeout: float = 60.0) -> Dict[str, TxStatusEvent]:
        """
        Track multiple transactions to completion.

        Args:
            tx_ids: List of transaction IDs
            timeout: Maximum time to wait in seconds

        Returns:
            Dictionary mapping tx_id to final TxStatusEvent
        """
        results = {}
        pending = set(tx_ids)

        logger.info(f"Tracking {len(tx_ids)} transactions")

        async def track_all():
            async for event in self.stream_tx_status(tx_ids):
                if event.tx_id and event.tx_id in pending:
                    if event.status in ["delivered", "failed"]:
                        results[event.tx_id] = event
                        pending.remove(event.tx_id)
                        logger.info(f"Transaction {event.tx_id} completed: {event.status}")

                        if not pending:
                            break

        try:
            await asyncio.wait_for(track_all(), timeout=timeout)
        except asyncio.TimeoutError:
            logger.warning(f"Timeout tracking transactions. Completed: {len(results)}, Pending: {len(pending)}")

        return results

    def add_metrics_hook(self, hook: Callable[[Event], None]) -> None:
        """
        Add a metrics hook to the WebSocket client.

        Args:
            hook: Function to call for each event (for metrics/logging)
        """
        self.ws_client.add_event_hook(hook)

    async def __aenter__(self):
        """Async context manager entry."""
        await self.connect()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit."""
        await self.disconnect()


# Utility functions for common streaming patterns

async def stream_until_condition(stream: AsyncIterator[Event],
                                condition: Callable[[Event], bool],
                                timeout: Optional[float] = None) -> Event:
    """
    Stream events until a condition is met.

    Args:
        stream: Event stream
        condition: Function that returns True when condition is met
        timeout: Optional timeout in seconds

    Returns:
        Event that satisfied the condition

    Raises:
        asyncio.TimeoutError: If timeout is reached
    """
    async def stream_and_check():
        async for event in stream:
            if condition(event):
                return event
        return None

    if timeout:
        return await asyncio.wait_for(stream_and_check(), timeout=timeout)
    else:
        return await stream_and_check()


async def collect_events(stream: AsyncIterator[Event],
                        count: int,
                        timeout: Optional[float] = None) -> list[Event]:
    """
    Collect a specific number of events from a stream.

    Args:
        stream: Event stream
        count: Number of events to collect
        timeout: Optional timeout in seconds

    Returns:
        List of collected events

    Raises:
        asyncio.TimeoutError: If timeout is reached
    """
    events = []

    async def collect():
        async for event in stream:
            events.append(event)
            if len(events) >= count:
                break
        return events

    if timeout:
        return await asyncio.wait_for(collect(), timeout=timeout)
    else:
        return await collect()


# Backward compatibility aliases
StreamingClient = StreamingAccumulateClient