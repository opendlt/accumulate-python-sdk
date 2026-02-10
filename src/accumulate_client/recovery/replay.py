"""
Transaction replay mechanism for reliable transaction delivery.

Provides automatic transaction replay with deduplication, ordering,
and recovery strategies for ensuring transaction completion.
"""

import asyncio
import json
import logging
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Callable
from uuid import uuid4

from ..tx import Transaction
from ..facade import Accumulate as AccumulateClient


logger = logging.getLogger(__name__)


class ReplayStatus(Enum):
    """Transaction replay status."""
    PENDING = "pending"
    REPLAYING = "replaying"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class ReplayError(Exception):
    """Transaction replay error."""
    pass


@dataclass
class ReplayConfig:
    """Configuration for transaction replay."""
    max_attempts: int = 5
    retry_delay: float = 2.0
    retry_multiplier: float = 1.5
    max_retry_delay: float = 60.0
    deduplication_window: float = 300.0  # 5 minutes
    batch_size: int = 10
    batch_delay: float = 1.0
    enable_ordering: bool = True
    ordering_timeout: float = 30.0
    persistence: bool = True


@dataclass
class ReplayEntry:
    """Entry in transaction replay system."""
    id: str
    transaction: Transaction
    original_attempt_time: float
    attempt_count: int = 0
    status: ReplayStatus = ReplayStatus.PENDING
    last_attempt_time: Optional[float] = None
    completion_time: Optional[float] = None
    error_message: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    @property
    def is_complete(self) -> bool:
        """Check if replay is complete."""
        return self.status in [ReplayStatus.COMPLETED, ReplayStatus.FAILED, ReplayStatus.CANCELLED]

    @property
    def age_seconds(self) -> float:
        """Get age of entry in seconds."""
        return time.time() - self.original_attempt_time

    @property
    def next_retry_time(self) -> Optional[float]:
        """Calculate next retry time."""
        if not self.last_attempt_time or self.is_complete:
            return None

        # Calculate exponential backoff
        config = self.metadata.get('config', ReplayConfig())
        delay = config.retry_delay * (config.retry_multiplier ** (self.attempt_count - 1))
        delay = min(delay, config.max_retry_delay)

        return self.last_attempt_time + delay


class ReplayStore(ABC):
    """
    Abstract base class for replay persistence.

    Defines interface for storing and retrieving replay entries
    across application restarts.
    """

    @abstractmethod
    async def save_entry(self, entry: ReplayEntry) -> None:
        """Save replay entry."""
        pass

    @abstractmethod
    async def load_entries(self) -> List[ReplayEntry]:
        """Load all replay entries."""
        pass

    @abstractmethod
    async def update_entry(self, entry: ReplayEntry) -> None:
        """Update existing replay entry."""
        pass

    @abstractmethod
    async def remove_entry(self, entry_id: str) -> None:
        """Remove replay entry."""
        pass

    @abstractmethod
    async def cleanup_old_entries(self, max_age: float) -> int:
        """Remove entries older than max_age seconds."""
        pass


class InMemoryReplayStore(ReplayStore):
    """In-memory implementation of replay store."""

    def __init__(self):
        """Initialize in-memory store."""
        self.entries: Dict[str, ReplayEntry] = {}

    async def save_entry(self, entry: ReplayEntry) -> None:
        """Save replay entry."""
        self.entries[entry.id] = entry

    async def load_entries(self) -> List[ReplayEntry]:
        """Load all replay entries."""
        return list(self.entries.values())

    async def update_entry(self, entry: ReplayEntry) -> None:
        """Update existing replay entry."""
        if entry.id in self.entries:
            self.entries[entry.id] = entry

    async def remove_entry(self, entry_id: str) -> None:
        """Remove replay entry."""
        self.entries.pop(entry_id, None)

    async def cleanup_old_entries(self, max_age: float) -> int:
        """Remove entries older than max_age seconds."""
        current_time = time.time()
        to_remove = []

        for entry_id, entry in self.entries.items():
            if current_time - entry.original_attempt_time > max_age:
                to_remove.append(entry_id)

        for entry_id in to_remove:
            del self.entries[entry_id]

        return len(to_remove)


class FileReplayStore(ReplayStore):
    """File-based implementation of replay store."""

    def __init__(self, file_path: str):
        """
        Initialize file-based store.

        Args:
            file_path: Path to persistence file
        """
        self.file_path = file_path
        self.lock = asyncio.Lock()

    async def save_entry(self, entry: ReplayEntry) -> None:
        """Save replay entry."""
        async with self.lock:
            entries = await self._load_from_file()
            entries[entry.id] = self._serialize_entry(entry)
            await self._save_to_file(entries)

    async def load_entries(self) -> List[ReplayEntry]:
        """Load all replay entries."""
        entries_data = await self._load_from_file()
        return [self._deserialize_entry(data) for data in entries_data.values()]

    async def update_entry(self, entry: ReplayEntry) -> None:
        """Update existing replay entry."""
        await self.save_entry(entry)  # Same as save for file store

    async def remove_entry(self, entry_id: str) -> None:
        """Remove replay entry."""
        async with self.lock:
            entries = await self._load_from_file()
            entries.pop(entry_id, None)
            await self._save_to_file(entries)

    async def cleanup_old_entries(self, max_age: float) -> int:
        """Remove entries older than max_age seconds."""
        async with self.lock:
            entries = await self._load_from_file()
            current_time = time.time()
            to_remove = []

            for entry_id, entry_data in entries.items():
                if current_time - entry_data.get('original_attempt_time', 0) > max_age:
                    to_remove.append(entry_id)

            for entry_id in to_remove:
                del entries[entry_id]

            await self._save_to_file(entries)
            return len(to_remove)

    async def _load_from_file(self) -> Dict[str, Dict]:
        """Load entries from file."""
        try:
            with open(self.file_path, 'r') as f:
                return json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            return {}

    async def _save_to_file(self, entries: Dict[str, Dict]) -> None:
        """Save entries to file."""
        with open(self.file_path, 'w') as f:
            json.dump(entries, f, indent=2)

    def _serialize_entry(self, entry: ReplayEntry) -> Dict:
        """Serialize replay entry to dictionary."""
        return {
            'id': entry.id,
            'transaction': entry.transaction.to_dict() if hasattr(entry.transaction, 'to_dict') else str(entry.transaction),
            'original_attempt_time': entry.original_attempt_time,
            'attempt_count': entry.attempt_count,
            'status': entry.status.value,
            'last_attempt_time': entry.last_attempt_time,
            'completion_time': entry.completion_time,
            'error_message': entry.error_message,
            'metadata': entry.metadata
        }

    def _deserialize_entry(self, data: Dict) -> ReplayEntry:
        """Deserialize replay entry from dictionary."""
        # Note: This is simplified - in practice you'd need proper transaction deserialization
        return ReplayEntry(
            id=data['id'],
            transaction=data['transaction'],  # Would need proper Transaction reconstruction
            original_attempt_time=data['original_attempt_time'],
            attempt_count=data['attempt_count'],
            status=ReplayStatus(data['status']),
            last_attempt_time=data.get('last_attempt_time'),
            completion_time=data.get('completion_time'),
            error_message=data.get('error_message'),
            metadata=data.get('metadata', {})
        )


class TransactionReplay:
    """
    Transaction replay system for reliable delivery.

    Provides automatic replay of failed transactions with deduplication,
    ordering, and configurable retry strategies.

    Features:
    - Automatic retry with exponential backoff
    - Transaction deduplication
    - Ordered replay for dependent transactions
    - Persistent storage of replay queue
    - Batch processing for efficiency
    - Comprehensive monitoring and metrics
    """

    def __init__(
        self,
        client: AccumulateClient,
        config: ReplayConfig,
        store: Optional[ReplayStore] = None
    ):
        """
        Initialize transaction replay system.

        Args:
            client: Accumulate client for submissions
            config: Replay configuration
            store: Persistence store (defaults to in-memory)
        """
        self.client = client
        self.config = config
        self.store = store or InMemoryReplayStore()

        # Internal state
        self.entries: Dict[str, ReplayEntry] = {}
        self.deduplication_cache: Set[str] = set()
        self.running = False

        # Processing state
        self.replay_task: Optional[asyncio.Task] = None
        self.cleanup_task: Optional[asyncio.Task] = None

        # Statistics
        self.stats = {
            "total_submissions": 0,
            "successful_replays": 0,
            "failed_replays": 0,
            "duplicate_submissions": 0,
            "total_attempts": 0,
            "current_queue_size": 0
        }

        logger.info(f"Initialized transaction replay with config: {config}")

    async def __aenter__(self):
        """Async context manager entry."""
        await self.start()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit."""
        await self.stop()

    async def start(self):
        """Start the replay system."""
        if self.running:
            return

        self.running = True

        # Load existing entries from store
        await self._load_entries()

        # Start background tasks
        self.replay_task = asyncio.create_task(self._replay_loop())
        self.cleanup_task = asyncio.create_task(self._cleanup_loop())

        logger.info("Transaction replay system started")

    async def stop(self, timeout: float = 30.0):
        """Stop the replay system."""
        if not self.running:
            return

        self.running = False

        # Cancel background tasks
        if self.replay_task:
            self.replay_task.cancel()

        if self.cleanup_task:
            self.cleanup_task.cancel()

        # Wait for tasks to complete
        tasks = [t for t in [self.replay_task, self.cleanup_task] if t]
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)

        # Save final state
        await self._save_all_entries()

        logger.info("Transaction replay system stopped")

    async def submit_transaction(
        self,
        transaction: Transaction,
        metadata: Optional[Dict[str, Any]] = None
    ) -> str:
        """
        Submit transaction for replay.

        Args:
            transaction: Transaction to submit
            metadata: Optional metadata

        Returns:
            Replay entry ID

        Raises:
            ReplayError: If submission fails
        """
        if not self.running:
            raise ReplayError("Replay system is not running")

        # Generate deduplication key
        dedup_key = self._generate_dedup_key(transaction)

        # Check for duplicates
        if dedup_key in self.deduplication_cache:
            self.stats["duplicate_submissions"] += 1
            logger.debug(f"Duplicate transaction submission detected: {dedup_key}")
            # Return existing entry ID if possible
            for entry in self.entries.values():
                if self._generate_dedup_key(entry.transaction) == dedup_key:
                    return entry.id
            # If not found, continue with new submission

        # Create replay entry
        entry = ReplayEntry(
            id=str(uuid4()),
            transaction=transaction,
            original_attempt_time=time.time(),
            metadata=metadata or {}
        )
        entry.metadata['config'] = self.config
        entry.metadata['dedup_key'] = dedup_key

        # Store entry
        self.entries[entry.id] = entry
        self.deduplication_cache.add(dedup_key)
        await self.store.save_entry(entry)

        self.stats["total_submissions"] += 1
        self.stats["current_queue_size"] = len([e for e in self.entries.values() if not e.is_complete])

        logger.info(f"Transaction submitted for replay: {entry.id}")
        return entry.id

    async def get_status(self, entry_id: str) -> Optional[ReplayEntry]:
        """Get status of replay entry."""
        return self.entries.get(entry_id)

    async def cancel_replay(self, entry_id: str) -> bool:
        """
        Cancel replay entry.

        Args:
            entry_id: Entry ID to cancel

        Returns:
            True if cancelled, False if not found or already complete
        """
        entry = self.entries.get(entry_id)
        if not entry or entry.is_complete:
            return False

        entry.status = ReplayStatus.CANCELLED
        entry.completion_time = time.time()
        await self.store.update_entry(entry)

        self.stats["current_queue_size"] = len([e for e in self.entries.values() if not e.is_complete])

        logger.info(f"Replay cancelled: {entry_id}")
        return True

    async def _load_entries(self):
        """Load entries from persistent store."""
        try:
            entries = await self.store.load_entries()
            for entry in entries:
                self.entries[entry.id] = entry

                # Rebuild deduplication cache
                dedup_key = entry.metadata.get('dedup_key')
                if dedup_key:
                    self.deduplication_cache.add(dedup_key)

            logger.info(f"Loaded {len(entries)} replay entries from store")

        except Exception as e:
            logger.error(f"Failed to load replay entries: {e}")

    async def _save_all_entries(self):
        """Save all entries to persistent store."""
        try:
            for entry in self.entries.values():
                await self.store.save_entry(entry)
        except Exception as e:
            logger.error(f"Failed to save replay entries: {e}")

    async def _replay_loop(self):
        """Main replay processing loop."""
        while self.running:
            try:
                await self._process_replay_batch()
                await asyncio.sleep(self.config.batch_delay)
            except Exception as e:
                logger.error(f"Error in replay loop: {e}")
                await asyncio.sleep(1.0)

    async def _cleanup_loop(self):
        """Cleanup old entries loop."""
        while self.running:
            try:
                await asyncio.sleep(60.0)  # Run cleanup every minute
                await self._cleanup_old_entries()
            except Exception as e:
                logger.error(f"Error in cleanup loop: {e}")

    async def _process_replay_batch(self):
        """Process a batch of replay entries."""
        # Get ready entries
        ready_entries = self._get_ready_entries()
        if not ready_entries:
            return

        # Sort by priority if ordering is enabled
        if self.config.enable_ordering:
            ready_entries.sort(key=lambda e: e.original_attempt_time)

        # Process batch
        batch = ready_entries[:self.config.batch_size]

        for entry in batch:
            try:
                await self._attempt_replay(entry)
            except Exception as e:
                logger.error(f"Error replaying entry {entry.id}: {e}")

    def _get_ready_entries(self) -> List[ReplayEntry]:
        """Get entries ready for replay."""
        current_time = time.time()
        ready = []

        for entry in self.entries.values():
            if entry.is_complete:
                continue

            if entry.status == ReplayStatus.PENDING:
                ready.append(entry)
            elif entry.status == ReplayStatus.FAILED:
                # Check if enough time has passed for retry
                next_retry = entry.next_retry_time
                if next_retry and current_time >= next_retry:
                    ready.append(entry)

        return ready

    async def _attempt_replay(self, entry: ReplayEntry):
        """Attempt to replay a single transaction."""
        entry.status = ReplayStatus.REPLAYING
        entry.attempt_count += 1
        entry.last_attempt_time = time.time()
        self.stats["total_attempts"] += 1

        try:
            # Submit transaction
            result = await self.client.submit(entry.transaction)

            # Check result and update status
            if result and result.get('success', True):
                entry.status = ReplayStatus.COMPLETED
                entry.completion_time = time.time()
                self.stats["successful_replays"] += 1
                logger.info(f"Transaction replay successful: {entry.id}")
            else:
                raise ReplayError(f"Submission failed: {result}")

        except Exception as e:
            # Handle failure
            if entry.attempt_count >= self.config.max_attempts:
                entry.status = ReplayStatus.FAILED
                entry.completion_time = time.time()
                entry.error_message = str(e)
                self.stats["failed_replays"] += 1
                logger.error(f"Transaction replay failed permanently: {entry.id} - {e}")
            else:
                entry.status = ReplayStatus.FAILED  # Will retry later
                entry.error_message = str(e)
                logger.warning(f"Transaction replay attempt {entry.attempt_count} failed: {entry.id} - {e}")

        # Update store
        await self.store.update_entry(entry)
        self.stats["current_queue_size"] = len([e for e in self.entries.values() if not e.is_complete])

    async def _cleanup_old_entries(self):
        """Clean up old completed entries."""
        try:
            # Remove old entries from store
            removed_count = await self.store.cleanup_old_entries(self.config.deduplication_window)

            # Clean up in-memory data
            current_time = time.time()
            to_remove = []

            for entry_id, entry in self.entries.items():
                if (entry.is_complete and
                    entry.completion_time and
                    current_time - entry.completion_time > self.config.deduplication_window):
                    to_remove.append(entry_id)

            for entry_id in to_remove:
                entry = self.entries.pop(entry_id)
                # Clean deduplication cache
                dedup_key = entry.metadata.get('dedup_key')
                if dedup_key:
                    self.deduplication_cache.discard(dedup_key)

            if removed_count > 0 or to_remove:
                logger.info(f"Cleaned up {removed_count + len(to_remove)} old replay entries")

        except Exception as e:
            logger.error(f"Error during cleanup: {e}")

    def _generate_dedup_key(self, transaction: Transaction) -> str:
        """Generate deduplication key for transaction."""
        # This is simplified - in practice you'd use transaction hash or unique identifier
        if hasattr(transaction, 'id') and transaction.id:
            return f"tx:{transaction.id}"
        elif hasattr(transaction, 'hash') and transaction.hash:
            return f"hash:{transaction.hash}"
        else:
            # Fallback to content hash
            content = str(transaction)
            return f"content:{hash(content)}"

    def get_stats(self) -> Dict[str, Any]:
        """Get replay system statistics."""
        pending_count = len([e for e in self.entries.values() if e.status == ReplayStatus.PENDING])
        replaying_count = len([e for e in self.entries.values() if e.status == ReplayStatus.REPLAYING])
        failed_count = len([e for e in self.entries.values() if e.status == ReplayStatus.FAILED and not e.is_complete])

        return {
            **self.stats,
            "pending_entries": pending_count,
            "replaying_entries": replaying_count,
            "failed_entries": failed_count,
            "deduplication_cache_size": len(self.deduplication_cache),
            "total_entries": len(self.entries),
            "success_rate": self.stats["successful_replays"] / max(self.stats["total_submissions"], 1)
        }


# Factory functions

def create_reliable_replay_system(
    client: AccumulateClient,
    persistence_file: Optional[str] = None
) -> TransactionReplay:
    """Create replay system optimized for reliability."""
    config = ReplayConfig(
        max_attempts=10,
        retry_delay=5.0,
        retry_multiplier=1.5,
        max_retry_delay=300.0,
        deduplication_window=3600.0,  # 1 hour
        batch_size=5,
        batch_delay=2.0,
        enable_ordering=True,
        persistence=True
    )

    store = FileReplayStore(persistence_file) if persistence_file else InMemoryReplayStore()
    return TransactionReplay(client, config, store)


def create_fast_replay_system(client: AccumulateClient) -> TransactionReplay:
    """Create replay system optimized for speed."""
    config = ReplayConfig(
        max_attempts=3,
        retry_delay=1.0,
        retry_multiplier=2.0,
        max_retry_delay=10.0,
        deduplication_window=300.0,  # 5 minutes
        batch_size=20,
        batch_delay=0.5,
        enable_ordering=False,
        persistence=False
    )

    return TransactionReplay(client, config, InMemoryReplayStore())