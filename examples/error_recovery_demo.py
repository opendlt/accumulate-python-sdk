#!/usr/bin/env python3
"""
Example: Advanced error recovery with retry policies and circuit breakers.

This example demonstrates how to use the error recovery features:
1. Retry policies with exponential, linear, and fixed backoff
2. Circuit breaker patterns for fault tolerance
3. Transaction replay for reliable delivery
4. Comprehensive error handling and monitoring

Requirements:
- Access to an Accumulate network endpoint
"""

import asyncio
import logging
import random
import signal
import sys
import time
from typing import Dict, Any

from accumulate_client import AccumulateClient
from accumulate_client.recovery import (
    RetryPolicy, ExponentialBackoff, LinearBackoff, FixedBackoff,
    CircuitBreaker, CircuitBreakerConfig, CircuitState,
    TransactionReplay, ReplayConfig, InMemoryReplayStore,
    with_retry, circuit_breaker, get_circuit
)
from accumulate_client.tx import Transaction
from accumulate_client.types import SendTokens, TokenAccount


# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class ErrorRecoveryDemo:
    """Error recovery demonstration."""

    def __init__(self, endpoint: str = "https://testnet.accumulatenetwork.io/v3"):
        """
        Initialize error recovery demo.

        Args:
            endpoint: Accumulate network endpoint
        """
        self.endpoint = endpoint
        self.client = AccumulateClient(endpoint)
        self.running = True

        # Initialize recovery components (will be set up in demo methods)
        self.replay_system = None

    async def setup_signal_handlers(self):
        """Setup signal handlers for graceful shutdown."""
        def signal_handler():
            logger.info("Received shutdown signal")
            self.running = False

        for sig in [signal.SIGINT, signal.SIGTERM]:
            asyncio.get_event_loop().add_signal_handler(sig, signal_handler)

    async def demo_retry_policies(self):
        """Demonstrate different retry policies."""
        logger.info("🔄 Demonstrating retry policies...")

        # Simulate unreliable function
        class UnreliableService:
            def __init__(self, failure_rate: float = 0.7):
                self.failure_rate = failure_rate
                self.call_count = 0

            async def unreliable_call(self, operation: str):
                self.call_count += 1
                if random.random() < self.failure_rate:
                    raise ConnectionError(f"Simulated failure for {operation} (attempt {self.call_count})")
                return f"Success: {operation} completed on attempt {self.call_count}"

        service = UnreliableService()

        # Test exponential backoff
        logger.info("   Testing exponential backoff...")
        exponential_policy = ExponentialBackoff(
            max_attempts=5,
            base_delay=0.1,
            factor=2.0,
            max_delay=2.0
        )

        try:
            start_time = time.time()
            result = await exponential_policy.execute(
                service.unreliable_call, "exponential_test"
            )
            duration = time.time() - start_time
            logger.info(f"   └─ {result} in {duration:.2f}s")

            stats = exponential_policy.get_stats()
            logger.info(f"   └─ Stats: {stats['total_attempts']} attempts, "
                       f"{stats['total_retries']} retries, "
                       f"{stats['success_rate']:.1%} success rate")

        except Exception as e:
            logger.error(f"   └─ Exponential backoff failed: {e}")

        # Test linear backoff
        logger.info("   Testing linear backoff...")
        service.call_count = 0  # Reset counter
        linear_policy = LinearBackoff(
            max_attempts=4,
            base_delay=0.1,
            increment=0.1
        )

        try:
            start_time = time.time()
            result = await linear_policy.execute(
                service.unreliable_call, "linear_test"
            )
            duration = time.time() - start_time
            logger.info(f"   └─ {result} in {duration:.2f}s")

        except Exception as e:
            logger.error(f"   └─ Linear backoff failed: {e}")

        # Test fixed backoff
        logger.info("   Testing fixed backoff...")
        service.call_count = 0  # Reset counter
        fixed_policy = FixedBackoff(
            max_attempts=3,
            delay=0.2
        )

        try:
            start_time = time.time()
            result = await fixed_policy.execute(
                service.unreliable_call, "fixed_test"
            )
            duration = time.time() - start_time
            logger.info(f"   └─ {result} in {duration:.2f}s")

        except Exception as e:
            logger.error(f"   └─ Fixed backoff failed: {e}")

        # Test retry decorator
        logger.info("   Testing retry decorator...")

        @with_retry(max_attempts=3, base_delay=0.1)
        async def decorated_unreliable_call():
            if random.random() < 0.5:
                raise ValueError("Decorated function failure")
            return "Decorated success"

        try:
            result = await decorated_unreliable_call()
            logger.info(f"   └─ {result}")
        except Exception as e:
            logger.error(f"   └─ Decorated retry failed: {e}")

    async def demo_circuit_breaker(self):
        """Demonstrate circuit breaker patterns."""
        logger.info("[FAST] Demonstrating circuit breaker...")

        # Create circuit breaker
        config = CircuitBreakerConfig(
            failure_threshold=3,
            success_threshold=2,
            timeout=2.0,
            window_size=10,
            min_requests=2,
            failure_rate_threshold=0.6
        )
        circuit = CircuitBreaker("demo_service", config)

        # Simulate failing service
        class FailingService:
            def __init__(self):
                self.failure_mode = True
                self.call_count = 0

            async def api_call(self, data: str):
                self.call_count += 1
                if self.failure_mode and self.call_count <= 5:
                    raise ConnectionError(f"Service unavailable (call {self.call_count})")
                return f"API response for: {data}"

            def fix_service(self):
                self.failure_mode = False
                logger.info("   🔧 Service has been 'fixed'")

        service = FailingService()

        # Test circuit opening
        logger.info("   Testing circuit opening on failures...")
        for i in range(6):
            try:
                result = await circuit.call(service.api_call, f"request_{i}")
                logger.info(f"   └─ Success: {result}")
            except ConnectionError as e:
                logger.warning(f"   └─ Call {i+1} failed: {e}")
            except Exception as e:
                logger.error(f"   └─ Circuit error: {e}")

            # Show circuit state
            metrics = circuit.get_metrics()
            logger.info(f"   └─ Circuit state: {metrics['state']}, "
                       f"failures: {metrics['failure_count']}")

        # Wait for circuit to try half-open
        logger.info("   Waiting for circuit timeout...")
        await asyncio.sleep(2.1)

        # Fix the service and test recovery
        service.fix_service()

        logger.info("   Testing circuit recovery...")
        for i in range(3):
            try:
                result = await circuit.call(service.api_call, f"recovery_{i}")
                logger.info(f"   └─ Recovery success: {result}")
            except Exception as e:
                logger.error(f"   └─ Recovery failed: {e}")

            metrics = circuit.get_metrics()
            logger.info(f"   └─ Circuit state: {metrics['state']}")

        # Test circuit breaker decorator
        logger.info("   Testing circuit breaker decorator...")

        @circuit_breaker("decorated_service")
        async def decorated_api_call(should_fail: bool):
            if should_fail:
                raise TimeoutError("Decorated service timeout")
            return "Decorated service success"

        try:
            result = await decorated_api_call(False)
            logger.info(f"   └─ {result}")
        except Exception as e:
            logger.error(f"   └─ Decorated circuit failed: {e}")

    async def demo_transaction_replay(self):
        """Demonstrate transaction replay system."""
        logger.info("🔁 Demonstrating transaction replay...")

        # Configure replay system
        config = ReplayConfig(
            max_attempts=3,
            retry_delay=1.0,
            retry_multiplier=1.5,
            batch_size=5,
            batch_delay=0.5,
            deduplication_window=60.0
        )

        # Use in-memory store for demo
        store = InMemoryReplayStore()
        self.replay_system = TransactionReplay(self.client, config, store)

        # Create sample transactions
        transactions = self._create_sample_transactions(5)

        try:
            async with self.replay_system:
                logger.info("   Submitting transactions for replay...")

                # Submit transactions
                replay_ids = []
                for i, tx in enumerate(transactions):
                    replay_id = await self.replay_system.submit_transaction(
                        tx,
                        metadata={"demo_id": i, "priority": i % 3}
                    )
                    replay_ids.append(replay_id)
                    logger.info(f"   └─ Submitted transaction {i}: {replay_id}")

                # Monitor replay progress
                logger.info("   Monitoring replay progress...")
                for round_num in range(10):  # Monitor for up to 10 rounds
                    await asyncio.sleep(1.0)

                    stats = self.replay_system.get_stats()
                    logger.info(
                        f"   └─ Round {round_num + 1}: "
                        f"Pending: {stats['pending_entries']}, "
                        f"Replaying: {stats['replaying_entries']}, "
                        f"Success rate: {stats['success_rate']:.1%}"
                    )

                    # Check individual statuses
                    completed = 0
                    for replay_id in replay_ids:
                        entry = await self.replay_system.get_status(replay_id)
                        if entry and entry.is_complete:
                            completed += 1

                    if completed == len(replay_ids):
                        logger.info("   └─ All transactions completed!")
                        break

                # Show final statistics
                final_stats = self.replay_system.get_stats()
                logger.info("   Final replay statistics:")
                for key, value in final_stats.items():
                    logger.info(f"      {key}: {value}")

        except Exception as e:
            logger.error(f"   Transaction replay demo failed: {e}")

    def _create_sample_transactions(self, count: int) -> list:
        """Create sample transactions for testing."""
        transactions = []

        for i in range(count):
            # Create a simple send transaction
            tx_body = SendTokens(
                to=[
                    TokenAccount(
                        url=f"acc://demo-recipient-{i:03d}",
                        amount=1000 + i
                    )
                ]
            )

            tx = Transaction(
                header={
                    "principal": f"acc://demo-sender-{i:03d}",
                    "memo": f"Demo transaction {i}"
                },
                body=tx_body
            )

            transactions.append(tx)

        return transactions

    async def demo_combined_recovery(self):
        """Demonstrate combining multiple recovery strategies."""
        logger.info("🛡️ Demonstrating combined recovery strategies...")

        # Create a service that uses all recovery mechanisms
        class RobustService:
            def __init__(self):
                self.call_count = 0
                self.failure_probability = 0.3

            @circuit_breaker("robust_service")
            @with_retry(max_attempts=3, base_delay=0.2)
            async def robust_api_call(self, data: str):
                self.call_count += 1

                # Simulate various failure modes
                if random.random() < self.failure_probability:
                    failure_type = random.choice([
                        ConnectionError("Network issue"),
                        TimeoutError("Request timeout"),
                        ValueError("Invalid response")
                    ])
                    raise failure_type

                return f"Robust API response {self.call_count}: {data}"

        service = RobustService()

        # Test combined recovery
        logger.info("   Testing combined retry + circuit breaker...")
        successful_calls = 0
        failed_calls = 0

        for i in range(10):
            try:
                result = await service.robust_api_call(f"combined_test_{i}")
                logger.info(f"   └─ Success {i+1}: {result}")
                successful_calls += 1
            except Exception as e:
                logger.warning(f"   └─ Failed {i+1}: {e}")
                failed_calls += 1

            # Brief pause between calls
            await asyncio.sleep(0.1)

        logger.info(f"   └─ Combined recovery results: "
                   f"{successful_calls} successes, {failed_calls} failures")

        # Show circuit metrics
        circuit = get_circuit("robust_service")
        metrics = circuit.get_metrics()
        logger.info(f"   └─ Final circuit state: {metrics['state']}")
        logger.info(f"   └─ Circuit failure rate: {metrics.get('failure_rate', 0):.1%}")

    async def demo_error_monitoring(self):
        """Demonstrate error monitoring and metrics collection."""
        logger.info("📊 Demonstrating error monitoring...")

        # Show global circuit breaker registry stats
        from accumulate_client.recovery.circuit_breaker import _global_registry

        circuits = _global_registry.list_circuits()
        logger.info(f"   Active circuits: {len(circuits)}")

        for circuit_name in circuits:
            circuit = _global_registry.get_circuit(circuit_name)
            metrics = circuit.get_metrics()

            logger.info(f"   Circuit '{circuit_name}':")
            logger.info(f"      State: {metrics['state']}")
            logger.info(f"      Total calls: {metrics['total_calls']}")
            logger.info(f"      Failure rate: {metrics.get('failure_rate', 0):.1%}")
            logger.info(f"      Time in state: {metrics['time_in_current_state']:.1f}s")

        # Show health summary
        health = _global_registry.get_health_summary()
        logger.info("   Overall health summary:")
        logger.info(f"      Total circuits: {health['total_circuits']}")
        logger.info(f"      Open circuits: {health['open_circuits']}")
        logger.info(f"      Health percentage: {health['health_percentage']:.1f}%")

        # Show replay system stats if available
        if self.replay_system:
            stats = self.replay_system.get_stats()
            logger.info("   Replay system statistics:")
            for key, value in stats.items():
                logger.info(f"      {key}: {value}")

    async def run_comprehensive_demo(self):
        """Run comprehensive error recovery demonstration."""
        logger.info("🎯 Starting comprehensive error recovery demo...")

        try:
            # Run individual demos
            await self.demo_retry_policies()
            await asyncio.sleep(1)

            await self.demo_circuit_breaker()
            await asyncio.sleep(1)

            await self.demo_transaction_replay()
            await asyncio.sleep(1)

            await self.demo_combined_recovery()
            await asyncio.sleep(1)

            await self.demo_error_monitoring()

            logger.info("[OK] Error recovery demo completed successfully!")

        except Exception as e:
            logger.error(f"Demo failed: {e}")
        finally:
            # Cleanup
            if self.replay_system:
                await self.replay_system.stop()


async def main():
    """Main entry point."""
    import argparse

    parser = argparse.ArgumentParser(description="Accumulate Error Recovery Demo")
    parser.add_argument(
        "--endpoint",
        default="https://testnet.accumulatenetwork.io/v3",
        help="Accumulate endpoint URL"
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
    demo = ErrorRecoveryDemo(args.endpoint)

    # Setup signal handlers
    await demo.setup_signal_handlers()

    await demo.run_comprehensive_demo()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.info("👋 Demo interrupted by user")
        sys.exit(0)
    except Exception as e:
        logger.error(f"Fatal error: {e}")
        sys.exit(1)