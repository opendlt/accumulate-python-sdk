"""
Retry policies for robust error handling.

Provides configurable retry strategies with backoff algorithms,
jitter, and condition-based retry logic for different failure modes.
"""

import asyncio
import logging
import random
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any, Callable, Optional, Union, Type, Tuple
from enum import Enum


logger = logging.getLogger(__name__)


class RetryStrategy(Enum):
    """Retry strategy types."""
    EXPONENTIAL = "exponential"
    LINEAR = "linear"
    FIXED = "fixed"


class RetryError(Exception):
    """Retry operation failed."""
    pass


class MaxRetriesExceeded(RetryError):
    """Maximum retry attempts exceeded."""
    def __init__(self, attempts: int, last_error: Exception):
        self.attempts = attempts
        self.last_error = last_error
        super().__init__(f"Max retries ({attempts}) exceeded. Last error: {last_error}")


@dataclass
class RetryAttempt:
    """Information about a retry attempt."""
    attempt: int
    delay: float
    exception: Optional[Exception] = None
    start_time: float = 0.0
    end_time: float = 0.0

    @property
    def duration(self) -> float:
        """Get attempt duration in seconds."""
        if self.end_time > self.start_time:
            return self.end_time - self.start_time
        return 0.0


class RetryPolicy(ABC):
    """
    Abstract base class for retry policies.

    Defines the interface for retry strategies with configurable
    backoff algorithms and retry conditions.
    """

    def __init__(
        self,
        max_attempts: int = 3,
        base_delay: float = 1.0,
        max_delay: float = 60.0,
        jitter: bool = True,
        jitter_factor: float = 0.1,
        raise_original_exception: bool = False
    ):
        """
        Initialize retry policy.

        Args:
            max_attempts: Maximum number of retry attempts
            base_delay: Base delay between retries in seconds
            max_delay: Maximum delay between retries in seconds
            jitter: Whether to add jitter to delays
            jitter_factor: Jitter factor (0.0 to 1.0)
            raise_original_exception: If True, raise original exception instead of MaxRetriesExceeded
        """
        self.max_attempts = max_attempts
        self.base_delay = base_delay
        self.max_delay = max_delay
        self.jitter = jitter
        self.jitter_factor = jitter_factor
        self.raise_original_exception = raise_original_exception

        # Statistics
        self.total_attempts = 0
        self.total_retries = 0
        self.total_successes = 0
        self.total_failures = 0

    @abstractmethod
    def calculate_delay(self, attempt: int) -> float:
        """
        Calculate delay for given attempt number.

        Args:
            attempt: Attempt number (1-based)

        Returns:
            Delay in seconds
        """
        pass

    def should_retry(self, attempt: int, exception: Exception) -> bool:
        """
        Determine if operation should be retried.

        Args:
            attempt: Current attempt number
            exception: Exception that occurred

        Returns:
            True if should retry, False otherwise
        """
        # Basic checks
        if attempt >= self.max_attempts:
            return False

        # Check for non-retryable exceptions
        if isinstance(exception, (KeyboardInterrupt, SystemExit)):
            return False

        # Add more exception-specific logic as needed
        return True

    def add_jitter(self, delay: float) -> float:
        """
        Add jitter to delay if enabled.

        Args:
            delay: Base delay

        Returns:
            Delay with jitter applied
        """
        if not self.jitter:
            return delay

        jitter_amount = delay * self.jitter_factor * (random.random() - 0.5)
        return max(0, delay + jitter_amount)

    async def execute(
        self,
        func: Callable,
        *args,
        **kwargs
    ) -> Any:
        """
        Execute function with retry policy.

        Args:
            func: Function to execute
            *args: Function arguments
            **kwargs: Function keyword arguments

        Returns:
            Function result

        Raises:
            MaxRetriesExceeded: If max retries exceeded
        """
        attempt = 0
        last_exception = None
        attempts = []

        while attempt < self.max_attempts:
            attempt += 1
            self.total_attempts += 1

            retry_attempt = RetryAttempt(attempt=attempt, delay=0.0)
            retry_attempt.start_time = time.time()

            try:
                if asyncio.iscoroutinefunction(func):
                    result = await func(*args, **kwargs)
                else:
                    result = func(*args, **kwargs)

                retry_attempt.end_time = time.time()
                attempts.append(retry_attempt)

                self.total_successes += 1
                if attempt > 1:
                    logger.info(f"Operation succeeded on attempt {attempt}")

                return result

            except Exception as e:
                retry_attempt.end_time = time.time()
                retry_attempt.exception = e
                attempts.append(retry_attempt)

                last_exception = e

                if not self.should_retry(attempt, e):
                    break

                if attempt < self.max_attempts:
                    delay = self.calculate_delay(attempt)
                    delay = min(delay, self.max_delay)
                    delay = self.add_jitter(delay)

                    retry_attempt.delay = delay
                    self.total_retries += 1

                    logger.warning(
                        f"Attempt {attempt} failed: {e}. "
                        f"Retrying in {delay:.2f}s..."
                    )

                    await asyncio.sleep(delay)

        self.total_failures += 1
        if self.raise_original_exception and last_exception:
            raise last_exception
        else:
            raise MaxRetriesExceeded(attempt, last_exception)

    async def execute_with_retry(self, func: Callable, *args, **kwargs) -> Any:
        """
        Execute function with retry policy (legacy compatibility).

        Args:
            func: Function to execute
            *args: Function arguments
            **kwargs: Function keyword arguments

        Returns:
            Function result

        Raises:
            MaxRetriesExceeded: If max retries exceeded
        """
        return await self.execute(func, *args, **kwargs)

    def get_stats(self) -> dict:
        """Get retry policy statistics."""
        return {
            "total_attempts": self.total_attempts,
            "total_retries": self.total_retries,
            "total_successes": self.total_successes,
            "total_failures": self.total_failures,
            "success_rate": self.total_successes / max(self.total_attempts, 1),
            "retry_rate": self.total_retries / max(self.total_attempts, 1)
        }


class ExponentialBackoff(RetryPolicy):
    """
    Exponential backoff retry policy.

    Delay increases exponentially with each attempt: base_delay * (factor ^ attempt)
    """

    def __init__(
        self,
        max_attempts: int = 5,
        base_delay: float = 1.0,
        max_delay: float = 60.0,
        factor: float = 2.0,
        jitter: bool = True,
        jitter_factor: float = 0.1,
        raise_original_exception: bool = False
    ):
        """
        Initialize exponential backoff policy.

        Args:
            max_attempts: Maximum retry attempts
            base_delay: Base delay in seconds
            max_delay: Maximum delay cap
            factor: Exponential factor
            jitter: Enable jitter
            jitter_factor: Jitter randomization factor
            raise_original_exception: If True, raise original exception instead of MaxRetriesExceeded
        """
        super().__init__(max_attempts, base_delay, max_delay, jitter, jitter_factor, raise_original_exception)
        self.factor = factor

    def calculate_delay(self, attempt: int) -> float:
        """Calculate exponential backoff delay."""
        delay = self.base_delay * (self.factor ** (attempt - 1))
        return min(delay, self.max_delay)


class LinearBackoff(RetryPolicy):
    """
    Linear backoff retry policy.

    Delay increases linearly with each attempt: base_delay + (increment * attempt)
    """

    def __init__(
        self,
        max_attempts: int = 5,
        base_delay: float = 1.0,
        max_delay: float = 60.0,
        increment: float = 1.0,
        jitter: bool = True,
        jitter_factor: float = 0.1
    ):
        """
        Initialize linear backoff policy.

        Args:
            max_attempts: Maximum retry attempts
            base_delay: Base delay in seconds
            max_delay: Maximum delay cap
            increment: Linear increment per attempt
            jitter: Enable jitter
            jitter_factor: Jitter randomization factor
        """
        super().__init__(max_attempts, base_delay, max_delay, jitter, jitter_factor)
        self.increment = increment

    def calculate_delay(self, attempt: int) -> float:
        """Calculate linear backoff delay."""
        delay = self.base_delay + (self.increment * (attempt - 1))
        return min(delay, self.max_delay)


class FixedBackoff(RetryPolicy):
    """
    Fixed delay retry policy.

    Uses constant delay between all retry attempts.
    """

    def __init__(
        self,
        max_attempts: int = 3,
        delay: float = 1.0,
        jitter: bool = True,
        jitter_factor: float = 0.1
    ):
        """
        Initialize fixed backoff policy.

        Args:
            max_attempts: Maximum retry attempts
            delay: Fixed delay in seconds
            jitter: Enable jitter
            jitter_factor: Jitter randomization factor
        """
        super().__init__(max_attempts, delay, delay, jitter, jitter_factor)

    def calculate_delay(self, attempt: int) -> float:
        """Calculate fixed delay."""
        return self.base_delay


class ConditionalRetryPolicy(RetryPolicy):
    """
    Retry policy with custom retry conditions.

    Allows specification of custom conditions for determining
    whether to retry based on exception type and content.
    """

    def __init__(
        self,
        max_attempts: int = 3,
        base_delay: float = 1.0,
        max_delay: float = 60.0,
        retryable_exceptions: Optional[Tuple[Type[Exception], ...]] = None,
        non_retryable_exceptions: Optional[Tuple[Type[Exception], ...]] = None,
        custom_condition: Optional[Callable[[int, Exception], bool]] = None,
        strategy: RetryStrategy = RetryStrategy.EXPONENTIAL,
        **kwargs
    ):
        """
        Initialize conditional retry policy.

        Args:
            max_attempts: Maximum retry attempts
            base_delay: Base delay in seconds
            max_delay: Maximum delay cap
            retryable_exceptions: Tuple of retryable exception types
            non_retryable_exceptions: Tuple of non-retryable exception types
            custom_condition: Custom retry condition function
            strategy: Retry strategy to use
            **kwargs: Additional strategy-specific parameters
        """
        super().__init__(max_attempts, base_delay, max_delay, **kwargs)
        self.retryable_exceptions = retryable_exceptions or ()
        self.non_retryable_exceptions = non_retryable_exceptions or (
            KeyboardInterrupt, SystemExit, MemoryError
        )
        self.custom_condition = custom_condition
        self.strategy = strategy

        # Initialize strategy-specific parameters
        if strategy == RetryStrategy.EXPONENTIAL:
            self.factor = kwargs.get('factor', 2.0)
        elif strategy == RetryStrategy.LINEAR:
            self.increment = kwargs.get('increment', 1.0)

    def calculate_delay(self, attempt: int) -> float:
        """Calculate delay based on strategy."""
        if self.strategy == RetryStrategy.EXPONENTIAL:
            return self.base_delay * (self.factor ** (attempt - 1))
        elif self.strategy == RetryStrategy.LINEAR:
            return self.base_delay + (self.increment * (attempt - 1))
        else:  # FIXED
            return self.base_delay

    def should_retry(self, attempt: int, exception: Exception) -> bool:
        """Enhanced retry condition checking."""
        # Base checks
        if not super().should_retry(attempt, exception):
            return False

        # Check non-retryable exceptions
        if isinstance(exception, self.non_retryable_exceptions):
            return False

        # Check retryable exceptions (if specified)
        if self.retryable_exceptions and not isinstance(exception, self.retryable_exceptions):
            return False

        # Custom condition check
        if self.custom_condition and not self.custom_condition(attempt, exception):
            return False

        return True


# Convenience functions for common retry patterns

def with_retry(
    max_attempts: int = 3,
    base_delay: float = 1.0,
    strategy: RetryStrategy = RetryStrategy.EXPONENTIAL,
    **kwargs
):
    """
    Decorator for adding retry behavior to functions.

    Args:
        max_attempts: Maximum retry attempts
        base_delay: Base delay between retries
        strategy: Retry strategy
        **kwargs: Additional policy parameters

    Returns:
        Decorator function
    """
    def decorator(func):
        if strategy == RetryStrategy.EXPONENTIAL:
            policy = ExponentialBackoff(
                max_attempts=max_attempts,
                base_delay=base_delay,
                **kwargs
            )
        elif strategy == RetryStrategy.LINEAR:
            policy = LinearBackoff(
                max_attempts=max_attempts,
                base_delay=base_delay,
                **kwargs
            )
        else:
            policy = FixedBackoff(
                max_attempts=max_attempts,
                delay=base_delay,
                **kwargs
            )

        async def async_wrapper(*args, **func_kwargs):
            return await policy.execute(func, *args, **func_kwargs)

        def sync_wrapper(*args, **func_kwargs):
            # For sync functions, create event loop if needed
            try:
                loop = asyncio.get_event_loop()
            except RuntimeError:
                return asyncio.run(policy.execute(func, *args, **func_kwargs))
            else:
                if loop.is_running():
                    # Already in async context
                    return asyncio.create_task(policy.execute(func, *args, **func_kwargs))
                else:
                    return loop.run_until_complete(policy.execute(func, *args, **func_kwargs))

        if asyncio.iscoroutinefunction(func):
            return async_wrapper
        else:
            return sync_wrapper

    return decorator


async def retry_on_exception(
    func: Callable,
    exceptions: Tuple[Type[Exception], ...],
    max_attempts: int = 3,
    base_delay: float = 1.0,
    strategy: RetryStrategy = RetryStrategy.EXPONENTIAL,
    *args,
    **kwargs
) -> Any:
    """
    Retry function execution on specific exceptions.

    Args:
        func: Function to execute
        exceptions: Tuple of exception types to retry on
        max_attempts: Maximum retry attempts
        base_delay: Base delay between retries
        strategy: Retry strategy
        *args: Function arguments
        **kwargs: Function keyword arguments

    Returns:
        Function result
    """
    policy = ConditionalRetryPolicy(
        max_attempts=max_attempts,
        base_delay=base_delay,
        retryable_exceptions=exceptions,
        strategy=strategy
    )

    return await policy.execute(func, *args, **kwargs)


# Factory functions for common configurations

def create_network_retry_policy() -> RetryPolicy:
    """Create retry policy optimized for network operations."""
    return ExponentialBackoff(
        max_attempts=5,
        base_delay=1.0,
        max_delay=30.0,
        factor=2.0,
        jitter=True
    )


def create_api_retry_policy() -> RetryPolicy:
    """Create retry policy optimized for API calls."""
    return ConditionalRetryPolicy(
        max_attempts=3,
        base_delay=0.5,
        max_delay=10.0,
        strategy=RetryStrategy.EXPONENTIAL,
        factor=1.5,
        retryable_exceptions=(
            ConnectionError,
            TimeoutError,
            asyncio.TimeoutError
        )
    )


def create_transaction_retry_policy() -> RetryPolicy:
    """Create retry policy optimized for transaction operations."""
    return LinearBackoff(
        max_attempts=3,
        base_delay=2.0,
        max_delay=20.0,
        increment=2.0,
        jitter=True
    )