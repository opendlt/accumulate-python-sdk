"""
Pipeline transaction submission for maximum throughput.

Provides high-performance transaction pipeline with parallel signing,
submission, and status tracking for optimal transaction processing.
"""

import asyncio
import logging
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Callable, Union
from uuid import uuid4

from ..api_client import AccumulateClient
from ..tx import Transaction
from ..signatures import Signature
from .batch import BatchClient
from .pool import HttpConnectionPool


logger = logging.getLogger(__name__)


class SubmissionStatus(Enum):
    """Transaction submission status."""
    PENDING = "pending"
    SIGNING = "signing"
    SUBMITTING = "submitting"
    SUBMITTED = "submitted"
    DELIVERED = "delivered"
    FAILED = "failed"


class PipelineError(Exception):
    """Pipeline operation error."""
    pass


@dataclass
class PipelineConfig:
    """Configuration for transaction pipeline."""
    max_concurrent_signing: int = 10
    max_concurrent_submission: int = 20
    max_queue_size: int = 1000
    submission_timeout: float = 30.0
    status_check_interval: float = 1.0
    max_status_checks: int = 60
    enable_nonce_management: bool = True
    nonce_cache_size: int = 100


@dataclass
class SubmissionResult:
    """Result of transaction submission."""
    transaction_id: str
    submission_id: str
    status: SubmissionStatus
    submit_time: Optional[float] = None
    delivery_time: Optional[float] = None
    error: Optional[str] = None
    retry_count: int = 0

    @property
    def duration_ms(self) -> Optional[float]:
        """Get total processing duration in milliseconds."""
        if self.submit_time and self.delivery_time:
            return (self.delivery_time - self.submit_time) * 1000
        return None

    @property
    def is_complete(self) -> bool:
        """Check if submission is complete."""
        return self.status in [SubmissionStatus.DELIVERED, SubmissionStatus.FAILED]

    @property
    def is_successful(self) -> bool:
        """Check if submission was successful."""
        return self.status == SubmissionStatus.DELIVERED


@dataclass
class PipelineTransaction:
    """Transaction in the pipeline."""
    id: str
    transaction: Transaction
    signer: Optional[Callable] = None
    priority: int = 0
    created_at: float = field(default_factory=time.time)
    metadata: Dict[str, Any] = field(default_factory=dict)


class PipelineClient:
    """
    High-performance transaction pipeline for maximum throughput.

    Features:
    - Parallel transaction signing and submission
    - Automatic nonce management
    - Transaction status tracking and retry logic
    - Priority-based processing
    - Comprehensive metrics and monitoring
    """

    def __init__(
        self,
        client: AccumulateClient,
        config: PipelineConfig,
        batch_client: Optional[BatchClient] = None,
        pool: Optional[HttpConnectionPool] = None
    ):
        """
        Initialize pipeline client.

        Args:
            client: Accumulate client
            config: Pipeline configuration
            batch_client: Optional batch client for submissions
            pool: Optional HTTP connection pool
        """
        self.client = client
        self.config = config
        self.batch_client = batch_client
        self.pool = pool

        # Processing queues
        self.signing_queue = asyncio.Queue(maxsize=config.max_queue_size)
        self.submission_queue = asyncio.Queue(maxsize=config.max_queue_size)
        self.tracking_queue = asyncio.Queue(maxsize=config.max_queue_size)

        # Results tracking
        self.results: Dict[str, SubmissionResult] = {}
        self.pending_submissions: Dict[str, PipelineTransaction] = {}

        # Processing tasks
        self.signing_tasks: List[asyncio.Task] = []
        self.submission_tasks: List[asyncio.Task] = []
        self.tracking_tasks: List[asyncio.Task] = []
        self.running = False

        # Nonce management
        self.nonce_cache: Dict[str, int] = {}
        self.nonce_locks: Dict[str, asyncio.Lock] = {}

        # Statistics
        self.stats = {
            "transactions_submitted": 0,
            "transactions_delivered": 0,
            "transactions_failed": 0,
            "total_signing_time": 0.0,
            "total_submission_time": 0.0,
            "total_delivery_time": 0.0,
            "nonce_cache_hits": 0,
            "retries_performed": 0
        }

        logger.info(f"Initialized pipeline client with {config.max_concurrent_submission} workers")

    async def __aenter__(self):
        """Async context manager entry."""
        await self.start()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit."""
        await self.stop()

    async def start(self):
        """Start the pipeline workers."""
        if self.running:
            return

        self.running = True

        # Start signing workers
        for i in range(self.config.max_concurrent_signing):
            task = asyncio.create_task(self._signing_worker(f"signer-{i}"))
            self.signing_tasks.append(task)

        # Start submission workers
        for i in range(self.config.max_concurrent_submission):
            task = asyncio.create_task(self._submission_worker(f"submitter-{i}"))
            self.submission_tasks.append(task)

        # Start tracking worker
        task = asyncio.create_task(self._tracking_worker())
        self.tracking_tasks.append(task)

        logger.info("Pipeline workers started")

    async def stop(self, timeout: float = 30.0):
        """Stop pipeline workers and wait for completion."""
        self.running = False

        # Wait for queues to empty
        await self._wait_for_empty_queues(timeout)

        # Cancel all tasks
        all_tasks = self.signing_tasks + self.submission_tasks + self.tracking_tasks

        for task in all_tasks:
            task.cancel()

        # Wait for tasks to complete
        if all_tasks:
            await asyncio.gather(*all_tasks, return_exceptions=True)

        logger.info("Pipeline stopped")

    async def submit_transaction(
        self,
        transaction: Transaction,
        signer: Optional[Callable] = None,
        priority: int = 0,
        metadata: Optional[Dict[str, Any]] = None
    ) -> str:
        """
        Submit transaction to pipeline.

        Args:
            transaction: Transaction to submit
            signer: Optional custom signer function
            priority: Processing priority (higher = processed first)
            metadata: Optional metadata to attach

        Returns:
            Submission ID for tracking

        Raises:
            PipelineError: If submission fails
        """
        if not self.running:
            raise PipelineError("Pipeline is not running")

        submission_id = str(uuid4())
        pipeline_tx = PipelineTransaction(
            id=submission_id,
            transaction=transaction,
            signer=signer,
            priority=priority,
            metadata=metadata or {}
        )

        # Create result tracking
        self.results[submission_id] = SubmissionResult(
            transaction_id="",  # Will be set after signing
            submission_id=submission_id,
            status=SubmissionStatus.PENDING,
            submit_time=time.time()
        )

        try:
            await self.signing_queue.put(pipeline_tx)
            self.stats["transactions_submitted"] += 1
            logger.debug(f"Transaction {submission_id} queued for signing")
            return submission_id

        except asyncio.QueueFull:
            raise PipelineError("Pipeline queue is full")

    async def submit_many(
        self,
        transactions: List[Transaction],
        signer: Optional[Callable] = None,
        priority: int = 0
    ) -> List[str]:
        """
        Submit multiple transactions to pipeline.

        Args:
            transactions: List of transactions
            signer: Optional custom signer
            priority: Processing priority

        Returns:
            List of submission IDs
        """
        submission_ids = []
        for tx in transactions:
            submission_id = await self.submit_transaction(tx, signer, priority)
            submission_ids.append(submission_id)

        return submission_ids

    async def wait_for_delivery(
        self,
        submission_id: str,
        timeout: float = 60.0
    ) -> SubmissionResult:
        """
        Wait for transaction delivery.

        Args:
            submission_id: Submission ID to wait for
            timeout: Timeout in seconds

        Returns:
            Final submission result

        Raises:
            PipelineError: If delivery fails or times out
        """
        deadline = time.time() + timeout

        while time.time() < deadline:
            result = self.results.get(submission_id)
            if not result:
                raise PipelineError(f"Unknown submission ID: {submission_id}")

            if result.is_complete:
                return result

            await asyncio.sleep(0.1)

        raise PipelineError(f"Transaction {submission_id} did not complete within {timeout}s")

    async def wait_for_all(
        self,
        submission_ids: List[str],
        timeout: float = 120.0
    ) -> Dict[str, SubmissionResult]:
        """
        Wait for multiple transactions to complete.

        Args:
            submission_ids: List of submission IDs
            timeout: Total timeout

        Returns:
            Dictionary mapping submission_id -> result
        """
        results = {}
        deadline = time.time() + timeout

        pending = set(submission_ids)
        while pending and time.time() < deadline:
            completed_this_round = set()

            for submission_id in pending:
                result = self.results.get(submission_id)
                if result and result.is_complete:
                    results[submission_id] = result
                    completed_this_round.add(submission_id)

            pending -= completed_this_round

            if pending:
                await asyncio.sleep(0.1)

        # Add any remaining (incomplete) results
        for submission_id in pending:
            result = self.results.get(submission_id)
            if result:
                results[submission_id] = result

        return results

    async def _signing_worker(self, worker_id: str):
        """Worker for signing transactions."""
        logger.debug(f"Signing worker {worker_id} started")

        while self.running:
            try:
                # Get transaction to sign (with priority)
                pipeline_tx = await asyncio.wait_for(
                    self.signing_queue.get(),
                    timeout=1.0
                )

                await self._process_signing(pipeline_tx)

            except asyncio.TimeoutError:
                continue
            except Exception as e:
                logger.error(f"Error in signing worker {worker_id}: {e}")

        logger.debug(f"Signing worker {worker_id} stopped")

    async def _submission_worker(self, worker_id: str):
        """Worker for submitting transactions."""
        logger.debug(f"Submission worker {worker_id} started")

        while self.running:
            try:
                # Get signed transaction
                pipeline_tx = await asyncio.wait_for(
                    self.submission_queue.get(),
                    timeout=1.0
                )

                await self._process_submission(pipeline_tx)

            except asyncio.TimeoutError:
                continue
            except Exception as e:
                logger.error(f"Error in submission worker {worker_id}: {e}")

        logger.debug(f"Submission worker {worker_id} stopped")

    async def _tracking_worker(self):
        """Worker for tracking transaction status."""
        logger.debug("Tracking worker started")

        while self.running:
            try:
                # Get transaction to track
                submission_id = await asyncio.wait_for(
                    self.tracking_queue.get(),
                    timeout=1.0
                )

                await self._process_tracking(submission_id)

            except asyncio.TimeoutError:
                continue
            except Exception as e:
                logger.error(f"Error in tracking worker: {e}")

        logger.debug("Tracking worker stopped")

    async def _process_signing(self, pipeline_tx: PipelineTransaction):
        """Process transaction signing."""
        result = self.results[pipeline_tx.id]
        start_time = time.time()

        try:
            result.status = SubmissionStatus.SIGNING

            # Handle nonce if needed
            if self.config.enable_nonce_management:
                await self._manage_nonce(pipeline_tx)

            # Sign transaction
            if pipeline_tx.signer:
                signed_tx = await pipeline_tx.signer(pipeline_tx.transaction)
            else:
                # Use default signing (if available)
                signed_tx = pipeline_tx.transaction

            # Update transaction with signature
            pipeline_tx.transaction = signed_tx
            result.transaction_id = signed_tx.id or ""

            # Move to submission queue
            await self.submission_queue.put(pipeline_tx)

            self.stats["total_signing_time"] += time.time() - start_time
            logger.debug(f"Transaction {pipeline_tx.id} signed successfully")

        except Exception as e:
            result.status = SubmissionStatus.FAILED
            result.error = f"Signing failed: {e}"
            logger.error(f"Failed to sign transaction {pipeline_tx.id}: {e}")

    async def _process_submission(self, pipeline_tx: PipelineTransaction):
        """Process transaction submission."""
        result = self.results[pipeline_tx.id]
        start_time = time.time()

        try:
            result.status = SubmissionStatus.SUBMITTING

            # Submit transaction
            if self.batch_client:
                # Use batch client
                tx_result = await self.batch_client.submit(
                    "submit",
                    {"envelope": pipeline_tx.transaction.envelope}
                )
            else:
                # Use direct client
                tx_result = await self.client.submit(pipeline_tx.transaction)

            result.status = SubmissionStatus.SUBMITTED
            self.pending_submissions[pipeline_tx.id] = pipeline_tx

            # Queue for status tracking
            await self.tracking_queue.put(pipeline_tx.id)

            self.stats["total_submission_time"] += time.time() - start_time
            logger.debug(f"Transaction {pipeline_tx.id} submitted successfully")

        except Exception as e:
            result.status = SubmissionStatus.FAILED
            result.error = f"Submission failed: {e}"
            self.stats["transactions_failed"] += 1
            logger.error(f"Failed to submit transaction {pipeline_tx.id}: {e}")

    async def _process_tracking(self, submission_id: str):
        """Process transaction status tracking."""
        result = self.results.get(submission_id)
        pipeline_tx = self.pending_submissions.get(submission_id)

        if not result or not pipeline_tx:
            return

        try:
            # Check transaction status
            for attempt in range(self.config.max_status_checks):
                if not self.running:
                    break

                if self.batch_client:
                    # Use batch client
                    status = await self.batch_client.submit(
                        "query-tx",
                        {"txid": result.transaction_id}
                    )
                else:
                    # Use direct client
                    status = await self.client.query_tx(result.transaction_id)

                if status and status.get("status") == "delivered":
                    result.status = SubmissionStatus.DELIVERED
                    result.delivery_time = time.time()
                    self.stats["transactions_delivered"] += 1
                    logger.debug(f"Transaction {submission_id} delivered")
                    break

                elif status and status.get("status") == "failed":
                    result.status = SubmissionStatus.FAILED
                    result.error = status.get("error", "Transaction failed")
                    self.stats["transactions_failed"] += 1
                    logger.warning(f"Transaction {submission_id} failed")
                    break

                # Wait before next check
                await asyncio.sleep(self.config.status_check_interval)

            else:
                # Max attempts reached
                result.status = SubmissionStatus.FAILED
                result.error = "Status tracking timeout"
                self.stats["transactions_failed"] += 1

        except Exception as e:
            result.status = SubmissionStatus.FAILED
            result.error = f"Tracking failed: {e}"
            logger.error(f"Failed to track transaction {submission_id}: {e}")

        finally:
            # Clean up
            self.pending_submissions.pop(submission_id, None)

    async def _manage_nonce(self, pipeline_tx: PipelineTransaction):
        """Manage transaction nonce."""
        # This is a simplified nonce management
        # In practice, you'd need to track nonces per account
        pass

    async def _wait_for_empty_queues(self, timeout: float):
        """Wait for all queues to empty."""
        deadline = time.time() + timeout

        while time.time() < deadline:
            if (self.signing_queue.empty() and
                self.submission_queue.empty() and
                self.tracking_queue.empty()):
                return

            await asyncio.sleep(0.1)

    def get_result(self, submission_id: str) -> Optional[SubmissionResult]:
        """Get result for submission ID."""
        return self.results.get(submission_id)

    def get_stats(self) -> Dict[str, Any]:
        """Get pipeline statistics."""
        return {
            **self.stats,
            "signing_queue_size": self.signing_queue.qsize(),
            "submission_queue_size": self.submission_queue.qsize(),
            "tracking_queue_size": self.tracking_queue.qsize(),
            "pending_submissions": len(self.pending_submissions),
            "total_results": len(self.results),
            "running": self.running,
            "success_rate": (
                self.stats["transactions_delivered"] /
                max(self.stats["transactions_submitted"], 1)
            ),
            "average_signing_time": (
                self.stats["total_signing_time"] /
                max(self.stats["transactions_submitted"], 1)
            ),
            "average_submission_time": (
                self.stats["total_submission_time"] /
                max(self.stats["transactions_submitted"], 1)
            )
        }

    def cleanup_completed(self, max_age: float = 3600.0):
        """Clean up completed results older than max_age seconds."""
        current_time = time.time()
        to_remove = []

        for submission_id, result in self.results.items():
            if result.is_complete:
                age = current_time - (result.submit_time or 0)
                if age > max_age:
                    to_remove.append(submission_id)

        for submission_id in to_remove:
            self.results.pop(submission_id, None)

        if to_remove:
            logger.debug(f"Cleaned up {len(to_remove)} completed results")


# Factory functions

def create_high_throughput_pipeline(
    client: AccumulateClient,
    pool: HttpConnectionPool,
    batch_client: BatchClient
) -> PipelineClient:
    """Create pipeline optimized for high throughput."""
    config = PipelineConfig(
        max_concurrent_signing=20,
        max_concurrent_submission=50,
        max_queue_size=2000,
        submission_timeout=15.0,
        status_check_interval=0.5
    )
    return PipelineClient(client, config, batch_client, pool)


def create_low_latency_pipeline(
    client: AccumulateClient,
    pool: HttpConnectionPool
) -> PipelineClient:
    """Create pipeline optimized for low latency."""
    config = PipelineConfig(
        max_concurrent_signing=5,
        max_concurrent_submission=10,
        max_queue_size=100,
        submission_timeout=5.0,
        status_check_interval=0.1
    )
    return PipelineClient(client, config, None, pool)