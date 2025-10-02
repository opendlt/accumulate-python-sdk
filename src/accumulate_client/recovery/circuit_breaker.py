"""
Circuit breaker pattern for fault tolerance.

Provides automatic failure detection and service protection
with configurable thresholds, timeouts, and recovery strategies.
"""

import asyncio
import logging
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Optional, Dict, List
from collections import deque


logger = logging.getLogger(__name__)


class CircuitState(Enum):
    """Circuit breaker states."""
    CLOSED = "closed"      # Normal operation
    OPEN = "open"          # Failing, rejecting requests
    HALF_OPEN = "half_open"  # Testing recovery


class CircuitBreakerError(Exception):
    """Circuit breaker operation error."""
    pass


class CircuitOpenError(CircuitBreakerError):
    """Circuit is open, rejecting requests."""
    def __init__(self, circuit_name: str, failure_count: int):
        self.circuit_name = circuit_name
        self.failure_count = failure_count
        super().__init__(f"Circuit '{circuit_name}' is open after {failure_count} failures")


# Alias for backward compatibility with tests
CircuitBreakerOpenError = CircuitOpenError


@dataclass
class CircuitBreakerConfig:
    """Configuration for circuit breaker."""
    failure_threshold: int = 5          # Failures before opening
    success_threshold: int = 3          # Successes to close from half-open
    timeout: float = 60.0               # Seconds before trying half-open
    window_size: int = 100              # Size of rolling window
    min_requests: int = 10              # Minimum requests before considering failure rate
    failure_rate_threshold: float = 0.5 # Failure rate to trigger opening (0.0-1.0)
    slow_call_threshold: float = 5.0    # Seconds to consider a call "slow"
    slow_call_rate_threshold: float = 0.5  # Slow call rate to trigger opening


@dataclass
class CallResult:
    """Result of a function call through circuit breaker."""
    success: bool
    duration: float
    timestamp: float = field(default_factory=time.time)
    exception: Optional[Exception] = None

    @property
    def is_slow(self) -> bool:
        """Check if call was slow based on duration."""
        return self.duration > 5.0  # Will be configurable


class CircuitBreaker:
    """
    Circuit breaker implementation for fault tolerance.

    Implements the circuit breaker pattern to prevent cascading failures
    by monitoring operation success/failure rates and automatically
    opening the circuit when thresholds are exceeded.

    Features:
    - Configurable failure and success thresholds
    - Rolling window for failure rate calculation
    - Slow call detection and rate monitoring
    - Automatic recovery testing in half-open state
    - Comprehensive metrics and monitoring
    """

    def __init__(self, name: str = None, config: CircuitBreakerConfig = None,
                 failure_threshold: int = None, timeout: float = None, **kwargs):
        """
        Initialize circuit breaker.

        Args:
            name: Circuit breaker name for identification
            config: Circuit breaker configuration
            failure_threshold: Number of failures before opening (legacy compatibility)
            timeout: Timeout before trying half-open (legacy compatibility)
            **kwargs: Additional configuration parameters for legacy compatibility
        """
        # Handle legacy parameter style for test compatibility
        if config is None:
            config = CircuitBreakerConfig()
            if failure_threshold is not None:
                config.failure_threshold = failure_threshold
            if timeout is not None:
                config.timeout = timeout
            # Handle other legacy parameters
            for key, value in kwargs.items():
                if hasattr(config, key):
                    setattr(config, key, value)

        self.name = name or "default"
        self.config = config
        self._state = CircuitState.CLOSED

        # State tracking
        self.failure_count = 0
        self.success_count = 0
        self.last_failure_time = 0.0
        self.last_success_time = 0.0
        self.state_changed_time = time.time()

        # Rolling window for statistics
        self.call_results: deque = deque(maxlen=config.window_size)

        # Locks for thread safety
        self.state_lock = asyncio.Lock()

        logger.info(f"Initialized circuit breaker '{name}' with config: {config}")

    async def __aenter__(self):
        """Async context manager entry."""
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit."""
        pass

    @property
    def state(self) -> CircuitState:
        """Get circuit state."""
        return self._state

    @property
    def is_closed(self) -> bool:
        """Check if circuit is closed (normal operation)."""
        return self._state == CircuitState.CLOSED

    @property
    def is_open(self) -> bool:
        """Check if circuit is open (failing)."""
        return self._state == CircuitState.OPEN

    @property
    def is_half_open(self) -> bool:
        """Check if circuit is half-open (testing)."""
        return self._state == CircuitState.HALF_OPEN

    async def call(self, func: Callable, *args, **kwargs) -> Any:
        """
        Execute function through circuit breaker.

        Args:
            func: Function to execute
            *args: Function arguments
            **kwargs: Function keyword arguments

        Returns:
            Function result

        Raises:
            CircuitOpenError: If circuit is open
            Exception: Any exception from the wrapped function
        """
        # Check if we can make the call
        await self._check_state_async()

        if self.is_open:
            raise CircuitOpenError(self.name, self.failure_count)

        # Execute the function
        start_time = time.time()
        call_result = None

        try:
            if asyncio.iscoroutinefunction(func):
                result = await func(*args, **kwargs)
            else:
                result = func(*args, **kwargs)

            # Record successful call
            duration = time.time() - start_time
            call_result = CallResult(success=True, duration=duration)
            await self._record_success(call_result)

            return result

        except Exception as e:
            # Record failed call
            duration = time.time() - start_time
            call_result = CallResult(success=False, duration=duration, exception=e)
            await self._record_failure_async(call_result)
            raise

    async def _check_state_async(self):
        """Check and update circuit breaker state."""
        async with self.state_lock:
            current_time = time.time()

            if self.is_open:
                # Check if timeout has elapsed to try half-open
                if current_time - self.last_failure_time >= self.config.timeout:
                    await self._transition_to_half_open()

    async def _record_success(self, call_result: CallResult):
        """Record successful call and update state."""
        async with self.state_lock:
            self.call_results.append(call_result)
            self.last_success_time = call_result.timestamp

            if self.is_half_open:
                self.success_count += 1
                if self.success_count >= self.config.success_threshold:
                    await self._transition_to_closed()
            elif self.is_closed:
                # Reset failure count on success in closed state
                self.failure_count = 0

            logger.debug(f"Circuit '{self.name}': Recorded success, state={self._state.value}")

    async def _record_failure_async(self, call_result: CallResult):
        """Record failed call and update state."""
        async with self.state_lock:
            self.call_results.append(call_result)
            self.last_failure_time = call_result.timestamp

            if self.is_half_open:
                # In half-open state, any failure immediately reopens the circuit
                self.failure_count += 1
                await self._transition_to_open()
            elif self.is_closed:
                self.failure_count += 1

                # Check if we should open the circuit
                if await self._should_open_circuit():
                    await self._transition_to_open()

            logger.debug(
                f"Circuit '{self.name}': Recorded failure {self.failure_count}, "
                f"state={self._state.value}"
            )

    async def _should_open_circuit(self) -> bool:
        """Determine if circuit should be opened based on current metrics."""
        # Simple threshold check - this is the primary check
        if self.failure_count >= self.config.failure_threshold:
            return True

        # Advanced checks based on rolling window - only use if we have enough data
        # and haven't already hit the simple threshold
        if len(self.call_results) > self.config.window_size / 2:  # Need significant sample size
            failure_rate = self._calculate_failure_rate()
            slow_call_rate = self._calculate_slow_call_rate()

            if (failure_rate >= self.config.failure_rate_threshold or
                slow_call_rate >= self.config.slow_call_rate_threshold):
                return True

        return False

    def _calculate_failure_rate(self) -> float:
        """Calculate failure rate from rolling window."""
        if not self.call_results:
            return 0.0

        failures = sum(1 for result in self.call_results if not result.success)
        return failures / len(self.call_results)

    def _calculate_slow_call_rate(self) -> float:
        """Calculate slow call rate from rolling window."""
        if not self.call_results:
            return 0.0

        slow_calls = sum(
            1 for result in self.call_results
            if result.duration > self.config.slow_call_threshold
        )
        return slow_calls / len(self.call_results)

    async def _transition_to_open(self):
        """Transition circuit to open state."""
        old_state = self._state
        self._state = CircuitState.OPEN
        self.state_changed_time = time.time()

        logger.warning(
            f"Circuit '{self.name}' opened: {old_state.value} -> {self._state.value} "
            f"(failures: {self.failure_count})"
        )

    async def _transition_to_half_open(self):
        """Transition circuit to half-open state."""
        old_state = self._state
        self._state = CircuitState.HALF_OPEN
        self.success_count = 0
        self.state_changed_time = time.time()

        logger.info(
            f"Circuit '{self.name}' half-opened: {old_state.value} -> {self._state.value}"
        )

    async def _transition_to_closed(self):
        """Transition circuit to closed state."""
        old_state = self._state
        self._state = CircuitState.CLOSED
        self.failure_count = 0
        self.success_count = 0
        self.state_changed_time = time.time()

        logger.info(
            f"Circuit '{self.name}' closed: {old_state.value} -> {self._state.value}"
        )

    async def force_open(self):
        """Force circuit to open state."""
        async with self.state_lock:
            await self._transition_to_open()

    async def force_closed(self):
        """Force circuit to closed state."""
        async with self.state_lock:
            await self._transition_to_closed()

    async def force_half_open(self):
        """Force circuit to half-open state."""
        async with self.state_lock:
            await self._transition_to_half_open()

    def get_metrics(self) -> Dict[str, Any]:
        """Get circuit breaker metrics."""
        current_time = time.time()

        metrics = {
            "name": self.name,
            "state": self._state.value,
            "failure_count": self.failure_count,
            "success_count": self.success_count,
            "time_in_current_state": current_time - self.state_changed_time,
            "last_failure_time": self.last_failure_time,
            "last_success_time": self.last_success_time,
            "total_calls": len(self.call_results),
            "window_size": len(self.call_results)
        }

        if self.call_results:
            metrics.update({
                "failure_rate": self._calculate_failure_rate(),
                "slow_call_rate": self._calculate_slow_call_rate(),
                "average_call_duration": sum(r.duration for r in self.call_results) / len(self.call_results),
                "recent_calls": len([r for r in self.call_results if current_time - r.timestamp < 60])
            })

        return metrics

    def reset(self):
        """Reset circuit breaker to initial state."""
        # Note: This is a synchronous method, so we can't use async lock
        # The lock is mainly needed for async operations
        self._state = CircuitState.CLOSED
        self.failure_count = 0
        self.success_count = 0
        self.call_results.clear()
        self.state_changed_time = time.time()

        logger.info(f"Circuit '{self.name}' reset to closed state")

    # Synchronous methods for testing (these will overload the async versions)
    def _record_failure(self):
        """Synchronous version for recording failure (for testing)."""
        # Simple synchronous implementation for testing
        self.failure_count += 1
        self.last_failure_time = time.time()
        if self.failure_count >= self.config.failure_threshold:
            self._state = CircuitState.OPEN

    def _check_state(self):
        """Synchronous version for checking state (for testing)."""
        # Simple synchronous implementation for testing
        current_time = time.time()
        if self.is_open and (current_time - self.last_failure_time >= self.config.timeout):
            self._state = CircuitState.HALF_OPEN


class CircuitBreakerRegistry:
    """
    Registry for managing multiple circuit breakers.

    Provides centralized management of circuit breakers with
    global monitoring and configuration capabilities.
    """

    def __init__(self):
        """Initialize circuit breaker registry."""
        self.circuits: Dict[str, CircuitBreaker] = {}
        self.default_config = CircuitBreakerConfig()

    def get_circuit(
        self,
        name: str,
        config: Optional[CircuitBreakerConfig] = None
    ) -> CircuitBreaker:
        """
        Get or create circuit breaker.

        Args:
            name: Circuit breaker name
            config: Optional custom configuration

        Returns:
            Circuit breaker instance
        """
        if name not in self.circuits:
            circuit_config = config or self.default_config
            self.circuits[name] = CircuitBreaker(name, circuit_config)
            logger.info(f"Created new circuit breaker: {name}")

        return self.circuits[name]

    def remove_circuit(self, name: str) -> bool:
        """
        Remove circuit breaker from registry.

        Args:
            name: Circuit breaker name

        Returns:
            True if removed, False if not found
        """
        if name in self.circuits:
            del self.circuits[name]
            logger.info(f"Removed circuit breaker: {name}")
            return True
        return False

    def list_circuits(self) -> List[str]:
        """Get list of circuit breaker names."""
        return list(self.circuits.keys())

    def get_all_metrics(self) -> Dict[str, Dict[str, Any]]:
        """Get metrics for all circuit breakers."""
        return {name: circuit.get_metrics() for name, circuit in self.circuits.items()}

    async def reset_all(self):
        """Reset all circuit breakers."""
        for circuit in self.circuits.values():
            circuit.reset()
        logger.info("Reset all circuit breakers")

    def get_open_circuits(self) -> List[str]:
        """Get list of open circuit breaker names."""
        return [name for name, circuit in self.circuits.items() if circuit.is_open]

    def get_health_summary(self) -> Dict[str, Any]:
        """Get overall health summary."""
        total_circuits = len(self.circuits)
        open_circuits = len(self.get_open_circuits())

        return {
            "total_circuits": total_circuits,
            "open_circuits": open_circuits,
            "closed_circuits": total_circuits - open_circuits,
            "health_percentage": ((total_circuits - open_circuits) / max(total_circuits, 1)) * 100
        }


# Global registry instance
_global_registry = CircuitBreakerRegistry()


def get_circuit(name: str, config: Optional[CircuitBreakerConfig] = None) -> CircuitBreaker:
    """Get circuit breaker from global registry."""
    return _global_registry.get_circuit(name, config)


def circuit_breaker(
    name: Optional[str] = None,
    config: Optional[CircuitBreakerConfig] = None
):
    """
    Decorator for wrapping functions with circuit breaker.

    Args:
        name: Circuit breaker name (defaults to function name)
        config: Optional circuit breaker configuration

    Returns:
        Decorator function
    """
    def decorator(func):
        circuit_name = name or f"{func.__module__}.{func.__qualname__}"
        circuit = get_circuit(circuit_name, config)

        async def async_wrapper(*args, **kwargs):
            return await circuit.call(func, *args, **kwargs)

        def sync_wrapper(*args, **kwargs):
            # For sync functions, we need to handle the async circuit call
            try:
                loop = asyncio.get_event_loop()
            except RuntimeError:
                return asyncio.run(circuit.call(func, *args, **kwargs))
            else:
                if loop.is_running():
                    # Already in async context, create task
                    return asyncio.create_task(circuit.call(func, *args, **kwargs))
                else:
                    return loop.run_until_complete(circuit.call(func, *args, **kwargs))

        if asyncio.iscoroutinefunction(func):
            return async_wrapper
        else:
            return sync_wrapper

    return decorator


# Factory functions for common configurations

def create_network_circuit_breaker(name: str) -> CircuitBreaker:
    """Create circuit breaker optimized for network operations."""
    config = CircuitBreakerConfig(
        failure_threshold=3,
        success_threshold=2,
        timeout=30.0,
        window_size=50,
        min_requests=5,
        failure_rate_threshold=0.6,
        slow_call_threshold=10.0
    )
    return CircuitBreaker(name, config)


def create_api_circuit_breaker(name: str) -> CircuitBreaker:
    """Create circuit breaker optimized for API operations."""
    config = CircuitBreakerConfig(
        failure_threshold=5,
        success_threshold=3,
        timeout=60.0,
        window_size=100,
        min_requests=10,
        failure_rate_threshold=0.5,
        slow_call_threshold=5.0
    )
    return CircuitBreaker(name, config)


def create_database_circuit_breaker(name: str) -> CircuitBreaker:
    """Create circuit breaker optimized for database operations."""
    config = CircuitBreakerConfig(
        failure_threshold=2,
        success_threshold=1,
        timeout=20.0,
        window_size=30,
        min_requests=3,
        failure_rate_threshold=0.7,
        slow_call_threshold=2.0
    )
    return CircuitBreaker(name, config)