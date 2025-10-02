#!/usr/bin/env python3
"""
Example: High-performance transaction submission with pooling and batching.

This example demonstrates how to use the performance optimization features:
1. HTTP connection pooling for efficient network utilization
2. Request batching for improved throughput
3. Pipeline processing for maximum transaction throughput
4. Performance monitoring and metrics collection

Requirements:
- pip install aiohttp
- Access to an Accumulate network endpoint
"""

import asyncio
import logging
import signal
import sys
import time
from typing import List, Dict, Any

from accumulate_client import AccumulateClient
from accumulate_client.performance import (
    HttpConnectionPool, PoolConfig,
    BatchClient, PipelineClient, PipelineConfig
)
from accumulate_client.tx import Transaction
from accumulate_client.types import TokenAccount, SendTokens


# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class PerformanceDemo:
    """High-performance submission demonstration."""

    def __init__(self, endpoint: str = "https://testnet.accumulatenetwork.io/v3"):
        """
        Initialize performance demo.

        Args:
            endpoint: Accumulate network endpoint
        """
        self.endpoint = endpoint
        self.running = True

        # Performance components (will be initialized in setup)
        self.pool = None
        self.batch_client = None
        self.pipeline_client = None
        self.http_client = None

    async def setup(self):
        """Setup performance components."""
        logger.info("Setting up performance components...")

        # Create high-performance connection pool
        pool_config = PoolConfig(
            max_connections=200,
            max_connections_per_host=50,
            connection_timeout=5.0,
            request_timeout=15.0,
            max_retries=3,
            health_check_interval=30.0
        )
        self.pool = HttpConnectionPool(pool_config)

        # Create batch client for request optimization
        self.batch_client = BatchClient(
            endpoint=self.endpoint,
            pool=self.pool,
            max_batch_size=100,
            max_wait_time=0.05,  # 50ms batching window
            max_concurrent_batches=10,
            enable_deduplication=True
        )

        # Create HTTP client
        self.http_client = AccumulateClient(self.endpoint)

        # Create pipeline client for transaction processing
        pipeline_config = PipelineConfig(
            max_concurrent_signing=10,
            max_concurrent_submission=25,
            max_queue_size=1000,
            submission_timeout=20.0,
            status_check_interval=0.5
        )
        self.pipeline_client = PipelineClient(
            client=self.http_client,
            config=pipeline_config,
            batch_client=self.batch_client,
            pool=self.pool
        )

        # Start all components
        await self.pool.start()
        await self.batch_client.start()
        await self.pipeline_client.start()

        logger.info("Performance components ready")

    async def cleanup(self):
        """Cleanup performance components."""
        logger.info("Cleaning up performance components...")

        if self.pipeline_client:
            await self.pipeline_client.stop()

        if self.batch_client:
            await self.batch_client.stop()

        if self.pool:
            await self.pool.close()

        logger.info("Cleanup completed")

    async def setup_signal_handlers(self):
        """Setup signal handlers for graceful shutdown."""
        def signal_handler():
            logger.info("Received shutdown signal")
            self.running = False

        for sig in [signal.SIGINT, signal.SIGTERM]:
            asyncio.get_event_loop().add_signal_handler(sig, signal_handler)

    async def demo_connection_pooling(self):
        """Demonstrate HTTP connection pooling benefits."""
        logger.info("🔌 Demonstrating connection pooling...")

        urls = [
            f"{self.endpoint}/status",
            f"{self.endpoint}/version",
            f"{self.endpoint}/network"
        ]

        # Warm up connections
        await self.pool.warm_up(urls)

        # Make multiple requests to show connection reuse
        start_time = time.time()
        tasks = []

        for i in range(20):
            for url in urls:
                task = asyncio.create_task(self.pool.get(url))
                tasks.append(task)

        responses = await asyncio.gather(*tasks, return_exceptions=True)
        duration = time.time() - start_time

        successful = sum(1 for r in responses if not isinstance(r, Exception))
        failed = len(responses) - successful

        logger.info(f"   └─ Completed {len(responses)} requests in {duration:.2f}s")
        logger.info(f"   └─ Success: {successful}, Failed: {failed}")
        logger.info(f"   └─ Rate: {len(responses)/duration:.1f} req/s")

        # Show pool statistics
        stats = self.pool.get_stats()
        logger.info(f"   └─ Active connections: {stats['pool']['total_hosts']}")
        logger.info(f"   └─ Total requests: {stats['pool']['total_requests']}")

    async def demo_request_batching(self):
        """Demonstrate request batching benefits."""
        logger.info("📦 Demonstrating request batching...")

        # Prepare batch of similar requests
        requests = []
        for i in range(50):
            requests.append({
                "method": "query",
                "params": {"url": f"acc://test-account-{i:03d}"},
                "priority": i % 3  # Vary priorities
            })

        start_time = time.time()

        # Submit all requests (they will be automatically batched)
        try:
            results = await self.batch_client.submit_many(requests, timeout=30.0)
            duration = time.time() - start_time

            logger.info(f"   └─ Processed {len(requests)} requests in {duration:.2f}s")
            logger.info(f"   └─ Rate: {len(requests)/duration:.1f} req/s")

            # Show batch statistics
            stats = self.batch_client.get_stats()
            logger.info(f"   └─ Batches sent: {stats['batches_sent']}")
            logger.info(f"   └─ Success rate: {stats['success_rate']:.1%}")
            logger.info(f"   └─ Deduplication hits: {stats['deduplication_hits']}")

        except Exception as e:
            logger.error(f"Batching demo failed: {e}")

    async def demo_pipeline_processing(self):
        """Demonstrate transaction pipeline processing."""
        logger.info("🚀 Demonstrating pipeline processing...")

        # Create sample transactions
        transactions = self._create_sample_transactions(20)

        start_time = time.time()

        # Submit transactions to pipeline
        submission_ids = []
        for tx in transactions:
            try:
                submission_id = await self.pipeline_client.submit_transaction(
                    tx,
                    priority=1
                )
                submission_ids.append(submission_id)
            except Exception as e:
                logger.warning(f"Failed to submit transaction: {e}")

        logger.info(f"   └─ Submitted {len(submission_ids)} transactions to pipeline")

        # Wait for some completions (with timeout)
        try:
            results = await self.pipeline_client.wait_for_all(
                submission_ids[:5],  # Just wait for first 5
                timeout=30.0
            )

            duration = time.time() - start_time
            completed = sum(1 for r in results.values() if r.is_complete)
            successful = sum(1 for r in results.values() if r.is_successful)

            logger.info(f"   └─ Completed {completed}/{len(results)} in {duration:.2f}s")
            logger.info(f"   └─ Success rate: {successful}/{completed}")

            # Show pipeline statistics
            stats = self.pipeline_client.get_stats()
            logger.info(f"   └─ Queue sizes: signing={stats['signing_queue_size']}, "
                       f"submission={stats['submission_queue_size']}")
            logger.info(f"   └─ Success rate: {stats['success_rate']:.1%}")

        except Exception as e:
            logger.error(f"Pipeline processing failed: {e}")

    def _create_sample_transactions(self, count: int) -> List[Transaction]:
        """Create sample transactions for testing."""
        transactions = []

        for i in range(count):
            # Create a sample token send transaction
            tx_body = SendTokens(
                to=[
                    TokenAccount(
                        url=f"acc://test-recipient-{i:03d}",
                        amount=1000 + i
                    )
                ]
            )

            tx = Transaction(
                header={
                    "principal": f"acc://test-sender-{i:03d}",
                    "memo": f"Performance test transaction {i}"
                },
                body=tx_body
            )

            transactions.append(tx)

        return transactions

    async def demo_performance_monitoring(self):
        """Demonstrate performance monitoring capabilities."""
        logger.info("📊 Performance monitoring summary...")

        # Pool statistics
        if self.pool:
            pool_stats = self.pool.get_stats()
            logger.info("🔌 Connection Pool:")
            logger.info(f"   └─ Active hosts: {pool_stats['pool']['total_hosts']}")
            logger.info(f"   └─ Total requests: {pool_stats['pool']['total_requests']}")
            logger.info(f"   └─ Error rate: {pool_stats['pool']['overall_error_rate']:.1%}")

        # Batch client statistics
        if self.batch_client:
            batch_stats = self.batch_client.get_stats()
            logger.info("📦 Batch Client:")
            logger.info(f"   └─ Requests submitted: {batch_stats['requests_submitted']}")
            logger.info(f"   └─ Batches sent: {batch_stats['batches_sent']}")
            logger.info(f"   └─ Success rate: {batch_stats['success_rate']:.1%}")
            logger.info(f"   └─ Avg batch time: {batch_stats['average_batch_time']:.3f}s")

        # Pipeline statistics
        if self.pipeline_client:
            pipeline_stats = self.pipeline_client.get_stats()
            logger.info("🚀 Pipeline Client:")
            logger.info(f"   └─ Transactions submitted: {pipeline_stats['transactions_submitted']}")
            logger.info(f"   └─ Success rate: {pipeline_stats['success_rate']:.1%}")
            logger.info(f"   └─ Avg signing time: {pipeline_stats['average_signing_time']:.3f}s")
            logger.info(f"   └─ Avg submission time: {pipeline_stats['average_submission_time']:.3f}s")

    async def run_comprehensive_demo(self):
        """Run comprehensive performance demonstration."""
        logger.info("🎯 Starting comprehensive performance demo...")

        try:
            await self.setup()

            # Run individual demos
            await self.demo_connection_pooling()
            await asyncio.sleep(1)

            await self.demo_request_batching()
            await asyncio.sleep(1)

            await self.demo_pipeline_processing()
            await asyncio.sleep(1)

            await self.demo_performance_monitoring()

        except Exception as e:
            logger.error(f"Demo failed: {e}")
        finally:
            await self.cleanup()

    async def run_stress_test(self, duration: int = 60):
        """
        Run stress test for specified duration.

        Args:
            duration: Test duration in seconds
        """
        logger.info(f"🔥 Starting {duration}s stress test...")

        try:
            await self.setup()

            start_time = time.time()
            total_requests = 0

            while time.time() - start_time < duration and self.running:
                # Submit batch of requests
                requests = [
                    {"method": "query", "params": {"url": f"acc://stress-test-{i}"}}
                    for i in range(10)
                ]

                try:
                    await asyncio.wait_for(
                        self.batch_client.submit_many(requests),
                        timeout=5.0
                    )
                    total_requests += len(requests)
                except asyncio.TimeoutError:
                    logger.warning("Request batch timed out")

                # Brief pause to avoid overwhelming
                await asyncio.sleep(0.1)

            actual_duration = time.time() - start_time
            rate = total_requests / actual_duration

            logger.info(f"   └─ Completed {total_requests} requests in {actual_duration:.1f}s")
            logger.info(f"   └─ Average rate: {rate:.1f} req/s")

            # Final statistics
            await self.demo_performance_monitoring()

        except Exception as e:
            logger.error(f"Stress test failed: {e}")
        finally:
            await self.cleanup()


async def main():
    """Main entry point."""
    import argparse

    parser = argparse.ArgumentParser(description="Accumulate Performance Demo")
    parser.add_argument(
        "--endpoint",
        default="https://testnet.accumulatenetwork.io/v3",
        help="Accumulate endpoint URL"
    )
    parser.add_argument(
        "--mode",
        choices=["demo", "stress"],
        default="demo",
        help="Demo mode to run"
    )
    parser.add_argument(
        "--duration",
        type=int,
        default=60,
        help="Stress test duration in seconds"
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
    demo = PerformanceDemo(args.endpoint)

    # Setup signal handlers
    await demo.setup_signal_handlers()

    if args.mode == "demo":
        await demo.run_comprehensive_demo()
    else:
        await demo.run_stress_test(args.duration)


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.info("👋 Demo interrupted by user")
        sys.exit(0)
    except Exception as e:
        logger.error(f"Fatal error: {e}")
        sys.exit(1)