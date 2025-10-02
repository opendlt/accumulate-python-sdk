#!/usr/bin/env python3
"""
Example: Stream blocks and track transaction statuses.

This example demonstrates how to use the StreamingAccumulateClient to:
1. Stream live block events from the Accumulate network
2. Track transaction status updates in real-time
3. Monitor directory anchors and log events
4. Use snapshot-then-stream patterns for reliable data consistency

Requirements:
- pip install websockets
- Access to an Accumulate network endpoint
"""

import asyncio
import logging
import signal
import sys
from typing import Dict, Any

from accumulate_client import AccumulateClient
from accumulate_client.client.streaming import StreamingAccumulateClient
from accumulate_client.transport.ws import WebSocketConfig


# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class StreamingExample:
    """Example streaming client for blocks and transactions."""

    def __init__(self, endpoint: str = "https://testnet.accumulatenetwork.io/v3"):
        """
        Initialize streaming example.

        Args:
            endpoint: Accumulate network endpoint
        """
        self.endpoint = endpoint
        self.http_client = AccumulateClient(endpoint)

        # Configure WebSocket with custom settings
        ws_config = WebSocketConfig(
            url=self._get_ws_url(endpoint),
            ping_interval=20.0,  # Ping every 20 seconds
            ping_timeout=5.0,    # 5 second ping timeout
            max_retries=10,      # Allow more retries for demo
            backoff_base=1.0,    # Start with 1 second backoff
            max_queue_size=100   # Buffer up to 100 events
        )

        self.streaming_client = StreamingAccumulateClient(self.http_client, ws_config)
        self.running = True

        # Track statistics
        self.stats = {
            "blocks_received": 0,
            "tx_updates_received": 0,
            "anchor_events": 0,
            "log_events": 0,
            "errors": 0
        }

    def _get_ws_url(self, http_url: str) -> str:
        """Convert HTTP URL to WebSocket URL."""
        if http_url.startswith("https://"):
            return http_url.replace("https://", "wss://") + "/ws"
        elif http_url.startswith("http://"):
            return http_url.replace("http://", "ws://") + "/ws"
        else:
            raise ValueError(f"Invalid HTTP URL: {http_url}")

    async def setup_signal_handlers(self):
        """Setup signal handlers for graceful shutdown."""
        def signal_handler():
            logger.info("Received shutdown signal")
            self.running = False

        # Setup signal handlers for graceful shutdown
        for sig in [signal.SIGINT, signal.SIGTERM]:
            asyncio.get_event_loop().add_signal_handler(sig, signal_handler)

    async def stream_blocks(self):
        """Stream block events and display information."""
        logger.info("Starting block streaming...")

        try:
            async for block_event in self.streaming_client.stream_blocks():
                if not self.running:
                    break

                self.stats["blocks_received"] += 1

                logger.info(
                    f"📦 Block #{block_event.block_height} "
                    f"(Hash: {block_event.block_hash[:16]}...)"
                )

                # Log additional block data if available
                if block_event.data:
                    tx_count = block_event.data.get("transactionCount", 0)
                    timestamp = block_event.data.get("timestamp")
                    if tx_count > 0:
                        logger.info(f"   └─ {tx_count} transactions, timestamp: {timestamp}")

        except Exception as e:
            logger.error(f"Error in block streaming: {e}")
            self.stats["errors"] += 1

    async def track_transactions(self, tx_ids: list):
        """
        Track specific transactions to completion.

        Args:
            tx_ids: List of transaction IDs to track
        """
        if not tx_ids:
            logger.info("No transaction IDs provided for tracking")
            return

        logger.info(f"Tracking {len(tx_ids)} transactions...")

        try:
            results = await self.streaming_client.track_multiple_txs(
                tx_ids,
                timeout=300.0  # 5 minute timeout
            )

            logger.info("🎯 Transaction tracking results:")
            for tx_id, event in results.items():
                status_emoji = "✅" if event.status == "delivered" else "❌"
                logger.info(f"   {status_emoji} {tx_id}: {event.status}")

        except asyncio.TimeoutError:
            logger.warning("⏰ Transaction tracking timed out")
        except Exception as e:
            logger.error(f"Error tracking transactions: {e}")
            self.stats["errors"] += 1

    async def stream_tx_status_updates(self, tx_id: str):
        """
        Stream real-time status updates for a single transaction.

        Args:
            tx_id: Transaction ID to monitor
        """
        logger.info(f"Monitoring transaction status: {tx_id}")

        try:
            async for tx_event in self.streaming_client.stream_tx_status(tx_id):
                if not self.running:
                    break

                self.stats["tx_updates_received"] += 1

                status_emoji = {
                    "pending": "⏳",
                    "delivered": "✅",
                    "failed": "❌",
                    "unknown": "❓"
                }.get(tx_event.status, "❓")

                logger.info(f"{status_emoji} TX {tx_id}: {tx_event.status}")

                # Stop monitoring if transaction is complete
                if tx_event.status in ["delivered", "failed"]:
                    logger.info(f"🏁 Transaction {tx_id} completed with status: {tx_event.status}")
                    break

        except Exception as e:
            logger.error(f"Error streaming transaction status: {e}")
            self.stats["errors"] += 1

    async def stream_directory_anchors(self, directory: str = None):
        """
        Stream directory anchor events.

        Args:
            directory: Directory URL to monitor (None for all)
        """
        logger.info(f"Streaming anchors for directory: {directory or 'ALL'}")

        try:
            async for anchor_event in self.streaming_client.stream_directory_anchors(directory):
                if not self.running:
                    break

                self.stats["anchor_events"] += 1

                logger.info(
                    f"⚓ Anchor: {anchor_event.anchor_hash[:16]}... "
                    f"from {anchor_event.source_chain}"
                )

        except Exception as e:
            logger.error(f"Error streaming anchors: {e}")
            self.stats["errors"] += 1

    async def stream_logs(self, level: str = "info"):
        """
        Stream log events from the network.

        Args:
            level: Log level to filter (debug, info, warn, error)
        """
        logger.info(f"Streaming logs at level: {level}")

        try:
            async for log_event in self.streaming_client.stream_logs(level=level):
                if not self.running:
                    break

                self.stats["log_events"] += 1

                level_emoji = {
                    "debug": "🐛",
                    "info": "ℹ️",
                    "warn": "⚠️",
                    "error": "🚨"
                }.get(log_event.level, "📝")

                logger.info(f"{level_emoji} LOG: {log_event.message}")

        except Exception as e:
            logger.error(f"Error streaming logs: {e}")
            self.stats["errors"] += 1

    async def snapshot_then_stream_example(self):
        """Demonstrate snapshot-then-stream pattern."""
        logger.info("Demonstrating snapshot-then-stream pattern...")

        def get_current_block():
            """Get current block height via HTTP."""
            # This would typically call self.http_client.get_latest_block()
            # For demo purposes, we'll simulate it
            return {"height": 12345, "hash": "demo_hash"}

        async def stream_from_height():
            """Stream blocks from current height."""
            async for event in self.streaming_client.stream_blocks(start_height=12345):
                yield event

        try:
            event_count = 0
            async for event in self.streaming_client.snapshot_then_stream(
                get_current_block,
                stream_from_height,
                "height"
            ):
                if not self.running:
                    break

                event_count += 1

                if event.type == "snapshot":
                    logger.info(f"📸 Snapshot: Block #{event.data['height']}")
                else:
                    logger.info(f"🔄 Stream event: {event.type}")

                # Limit demo to 5 events
                if event_count >= 5:
                    break

        except Exception as e:
            logger.error(f"Error in snapshot-then-stream: {e}")
            self.stats["errors"] += 1

    def add_metrics_hook(self):
        """Add a metrics hook to track events."""
        def metrics_hook(event):
            """Simple metrics collection hook."""
            event_type = event.type
            logger.debug(f"📊 Metrics: {event_type} event at {event.timestamp}")

        self.streaming_client.add_metrics_hook(metrics_hook)

    async def print_statistics(self):
        """Print periodic statistics."""
        while self.running:
            await asyncio.sleep(30)  # Print stats every 30 seconds

            logger.info("📈 Statistics:")
            for key, value in self.stats.items():
                logger.info(f"   {key}: {value}")

    async def run_basic_demo(self):
        """Run basic streaming demo."""
        logger.info("🚀 Starting basic streaming demo...")

        try:
            async with self.streaming_client:
                # Add metrics hook
                self.add_metrics_hook()

                # Start statistics task
                stats_task = asyncio.create_task(self.print_statistics())

                # Start streaming tasks
                tasks = [
                    asyncio.create_task(self.stream_blocks()),
                    asyncio.create_task(self.stream_directory_anchors()),
                    asyncio.create_task(self.stream_logs("info"))
                ]

                # Wait for tasks or shutdown
                await asyncio.gather(*tasks, stats_task, return_exceptions=True)

        except KeyboardInterrupt:
            logger.info("Demo interrupted by user")
        except Exception as e:
            logger.error(f"Demo error: {e}")
        finally:
            logger.info("🏁 Demo completed")

    async def run_advanced_demo(self, tx_ids: list = None):
        """
        Run advanced demo with transaction tracking.

        Args:
            tx_ids: Optional list of transaction IDs to track
        """
        logger.info("🚀 Starting advanced streaming demo...")

        try:
            async with self.streaming_client:
                # Add metrics hook
                self.add_metrics_hook()

                tasks = []

                # Block streaming
                tasks.append(asyncio.create_task(self.stream_blocks()))

                # Transaction tracking if IDs provided
                if tx_ids:
                    tasks.append(asyncio.create_task(self.track_transactions(tx_ids)))

                    # Individual status monitoring for first TX
                    if tx_ids:
                        tasks.append(asyncio.create_task(
                            self.stream_tx_status_updates(tx_ids[0])
                        ))

                # Anchor streaming
                tasks.append(asyncio.create_task(self.stream_directory_anchors()))

                # Snapshot-then-stream demo
                tasks.append(asyncio.create_task(self.snapshot_then_stream_example()))

                # Statistics
                tasks.append(asyncio.create_task(self.print_statistics()))

                # Wait for completion or shutdown
                await asyncio.gather(*tasks, return_exceptions=True)

        except KeyboardInterrupt:
            logger.info("Demo interrupted by user")
        except Exception as e:
            logger.error(f"Demo error: {e}")
        finally:
            logger.info("🏁 Advanced demo completed")


async def main():
    """Main entry point."""
    import argparse

    parser = argparse.ArgumentParser(description="Accumulate Streaming Demo")
    parser.add_argument(
        "--endpoint",
        default="https://testnet.accumulatenetwork.io/v3",
        help="Accumulate endpoint URL"
    )
    parser.add_argument(
        "--mode",
        choices=["basic", "advanced"],
        default="basic",
        help="Demo mode to run"
    )
    parser.add_argument(
        "--tx-ids",
        nargs="*",
        help="Transaction IDs to track (for advanced mode)"
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Enable verbose logging"
    )

    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    # Create and run demo
    demo = StreamingExample(args.endpoint)

    # Setup signal handlers
    await demo.setup_signal_handlers()

    if args.mode == "basic":
        await demo.run_basic_demo()
    else:
        await demo.run_advanced_demo(args.tx_ids)


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.info("👋 Goodbye!")
        sys.exit(0)
    except Exception as e:
        logger.error(f"Fatal error: {e}")
        sys.exit(1)