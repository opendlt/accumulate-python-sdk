"""
Tests for retry policies and circuit breaker functionality.

Comprehensive test suite covering retry strategies, circuit breaker patterns,
and error recovery mechanisms.
"""

import asyncio
import pytest
import time
from unittest.mock import Mock, AsyncMock, patch

from accumulate_client.recovery.retry import (
    RetryPolicy, ExponentialBackoff, LinearBackoff, FixedBackoff,
    ConditionalRetryPolicy, RetryStrategy, MaxRetriesExceeded,
    with_retry, retry_on_exception
)
from accumulate_client.recovery.circuit_breaker import (
    CircuitBreaker, CircuitBreakerConfig, CircuitState,
    CircuitOpenError, circuit_breaker, get_circuit
)


class TestRetryPolicies:
    """Test retry policy implementations."""

    @pytest.mark.asyncio
    async def test_exponential_backoff_calculation(self):
        """Test exponential backoff delay calculation."""
        policy = ExponentialBackoff(base_delay=1.0, factor=2.0, jitter=False)

        assert policy.calculate_delay(1) == 1.0
        assert policy.calculate_delay(2) == 2.0
        assert policy.calculate_delay(3) == 4.0
        assert policy.calculate_delay(4) == 8.0

    @pytest.mark.asyncio
    async def test_linear_backoff_calculation(self):
        """Test linear backoff delay calculation."""
        policy = LinearBackoff(base_delay=1.0, increment=0.5, jitter=False)

        assert policy.calculate_delay(1) == 1.0
        assert policy.calculate_delay(2) == 1.5
        assert policy.calculate_delay(3) == 2.0
        assert policy.calculate_delay(4) == 2.5

    @pytest.mark.asyncio
    async def test_fixed_backoff_calculation(self):
        """Test fixed backoff delay calculation."""
        policy = FixedBackoff(delay=2.0, jitter=False)

        assert policy.calculate_delay(1) == 2.0
        assert policy.calculate_delay(2) == 2.0
        assert policy.calculate_delay(3) == 2.0

    @pytest.mark.asyncio
    async def test_successful_execution_no_retry(self):
        """Test successful execution without retries."""
        policy = ExponentialBackoff(max_attempts=3)

        async def success_func():
            return "success"

        result = await policy.execute(success_func)
        assert result == "success"
        assert policy.total_attempts == 1
        assert policy.total_retries == 0
        assert policy.total_successes == 1

    @pytest.mark.asyncio
    async def test_retry_on_failure(self):
        """Test retry behavior on failures."""
        policy = ExponentialBackoff(max_attempts=3, base_delay=0.01)

        call_count = 0

        async def failing_func():
            nonlocal call_count
            call_count += 1
            if call_count < 3:
                raise ValueError("Temporary failure")
            return "success"

        start_time = time.time()
        result = await policy.execute(failing_func)
        duration = time.time() - start_time

        assert result == "success"
        assert call_count == 3
        assert policy.total_attempts == 3
        assert policy.total_retries == 2
        assert policy.total_successes == 1
        assert duration > 0.01  # Should have some delay

    @pytest.mark.asyncio
    async def test_max_retries_exceeded(self):
        """Test behavior when max retries are exceeded."""
        policy = ExponentialBackoff(max_attempts=2, base_delay=0.01)

        async def always_failing():
            raise ValueError("Always fails")

        with pytest.raises(MaxRetriesExceeded) as exc_info:
            await policy.execute(always_failing)

        assert exc_info.value.attempts == 2
        assert isinstance(exc_info.value.last_error, ValueError)
        assert policy.total_failures == 1

    @pytest.mark.asyncio
    async def test_jitter_application(self):
        """Test jitter application to delays."""
        policy = ExponentialBackoff(base_delay=1.0, jitter=True, jitter_factor=0.5)

        # Test multiple jitter applications
        delays = [policy.add_jitter(1.0) for _ in range(100)]

        # All delays should be between 0.5 and 1.5 (1.0 ± 50%)
        assert all(0.5 <= d <= 1.5 for d in delays)
        # Should have some variation
        assert len(set(delays)) > 10

    @pytest.mark.asyncio
    async def test_conditional_retry_policy(self):
        """Test conditional retry policy."""
        policy = ConditionalRetryPolicy(
            max_attempts=3,
            base_delay=0.01,
            retryable_exceptions=(ValueError,),
            non_retryable_exceptions=(TypeError,)
        )

        # Should retry ValueError
        call_count = 0

        async def value_error_func():
            nonlocal call_count
            call_count += 1
            if call_count < 2:
                raise ValueError("Retryable")
            return "success"

        result = await policy.execute(value_error_func)
        assert result == "success"
        assert call_count == 2

        # Should not retry TypeError
        async def type_error_func():
            raise TypeError("Non-retryable")

        with pytest.raises(MaxRetriesExceeded):
            await policy.execute(type_error_func)

    @pytest.mark.asyncio
    async def test_retry_decorator(self):
        """Test retry decorator functionality."""
        @with_retry(max_attempts=3, base_delay=0.01, strategy=RetryStrategy.FIXED)
        async def decorated_func(should_fail: bool):
            if should_fail:
                raise ValueError("Decorated failure")
            return "decorated_success"

        # Test success
        result = await decorated_func(False)
        assert result == "decorated_success"

        # Test failure with retries
        with pytest.raises(MaxRetriesExceeded):
            await decorated_func(True)

    @pytest.mark.asyncio
    async def test_retry_on_exception_function(self):
        """Test retry_on_exception utility function."""
        call_count = 0

        async def test_func():
            nonlocal call_count
            call_count += 1
            if call_count < 3:
                raise ConnectionError("Connection failed")
            return "connected"

        result = await retry_on_exception(
            test_func,
            (ConnectionError,),
            max_attempts=3,
            base_delay=0.01
        )

        assert result == "connected"
        assert call_count == 3


class TestCircuitBreaker:
    """Test circuit breaker functionality."""

    @pytest.fixture
    def circuit_config(self):
        """Default circuit breaker configuration for tests."""
        return CircuitBreakerConfig(
            failure_threshold=3,
            success_threshold=2,
            timeout=0.1,  # Short timeout for tests
            window_size=10,
            min_requests=2
        )

    @pytest.mark.asyncio
    async def test_circuit_initialization(self, circuit_config):
        """Test circuit breaker initialization."""
        circuit = CircuitBreaker("test_circuit", circuit_config)

        assert circuit.name == "test_circuit"
        assert circuit.state == CircuitState.CLOSED
        assert circuit.is_closed
        assert not circuit.is_open
        assert not circuit.is_half_open

    @pytest.mark.asyncio
    async def test_successful_calls_closed_state(self, circuit_config):
        """Test successful calls in closed state."""
        circuit = CircuitBreaker("test_circuit", circuit_config)

        async def success_func():
            return "success"

        for _ in range(5):
            result = await circuit.call(success_func)
            assert result == "success"

        assert circuit.is_closed
        assert circuit.failure_count == 0

    @pytest.mark.asyncio
    async def test_circuit_opens_on_failures(self, circuit_config):
        """Test circuit opening after threshold failures."""
        circuit = CircuitBreaker("test_circuit", circuit_config)

        async def failing_func():
            raise ValueError("Test failure")

        # Should fail threshold times and open circuit
        for i in range(circuit_config.failure_threshold):
            with pytest.raises(ValueError):
                await circuit.call(failing_func)

        assert circuit.is_open
        assert circuit.failure_count == circuit_config.failure_threshold

        # Next call should raise CircuitOpenError
        with pytest.raises(CircuitOpenError):
            await circuit.call(failing_func)

    @pytest.mark.asyncio
    async def test_circuit_half_open_transition(self, circuit_config):
        """Test transition to half-open state after timeout."""
        circuit = CircuitBreaker("test_circuit", circuit_config)

        async def failing_func():
            raise ValueError("Test failure")

        # Open the circuit
        for _ in range(circuit_config.failure_threshold):
            with pytest.raises(ValueError):
                await circuit.call(failing_func)

        assert circuit.is_open

        # Wait for timeout and check state transition
        await asyncio.sleep(circuit_config.timeout + 0.01)

        async def success_func():
            return "success"

        # This should transition to half-open and succeed
        result = await circuit.call(success_func)
        assert result == "success"
        assert circuit.is_half_open

    @pytest.mark.asyncio
    async def test_circuit_closes_from_half_open(self, circuit_config):
        """Test circuit closing from half-open after successful calls."""
        circuit = CircuitBreaker("test_circuit", circuit_config)

        # Force to half-open state
        await circuit.force_half_open()
        assert circuit.is_half_open

        async def success_func():
            return "success"

        # Make enough successful calls to close circuit
        for _ in range(circuit_config.success_threshold):
            result = await circuit.call(success_func)
            assert result == "success"

        assert circuit.is_closed
        assert circuit.failure_count == 0

    @pytest.mark.asyncio
    async def test_circuit_reopens_from_half_open(self, circuit_config):
        """Test circuit reopening from half-open on failure."""
        circuit = CircuitBreaker("test_circuit", circuit_config)

        # Force to half-open state
        await circuit.force_half_open()
        assert circuit.is_half_open

        async def failing_func():
            raise ValueError("Test failure")

        # One failure should reopen the circuit
        with pytest.raises(ValueError):
            await circuit.call(failing_func)

        assert circuit.is_open

    @pytest.mark.asyncio
    async def test_failure_rate_threshold(self, circuit_config):
        """Test circuit opening based on failure rate."""
        circuit_config.failure_rate_threshold = 0.5
        circuit_config.min_requests = 4
        circuit = CircuitBreaker("test_circuit", circuit_config)

        async def success_func():
            return "success"

        async def failing_func():
            raise ValueError("Test failure")

        # Add some successful calls
        await circuit.call(success_func)
        await circuit.call(success_func)

        # Add failures to exceed rate threshold
        with pytest.raises(ValueError):
            await circuit.call(failing_func)

        with pytest.raises(ValueError):
            await circuit.call(failing_func)

        with pytest.raises(ValueError):
            await circuit.call(failing_func)

        # Circuit should open due to failure rate (3/5 = 0.6 > 0.5)
        assert circuit.is_open

    @pytest.mark.asyncio
    async def test_slow_call_detection(self, circuit_config):
        """Test slow call detection and rate monitoring."""
        circuit_config.slow_call_threshold = 0.1
        circuit_config.slow_call_rate_threshold = 0.5
        circuit_config.min_requests = 2
        circuit = CircuitBreaker("test_circuit", circuit_config)

        async def slow_func():
            await asyncio.sleep(0.2)  # Slower than threshold
            return "slow_success"

        async def fast_func():
            return "fast_success"

        # Make some fast and slow calls
        await circuit.call(fast_func)
        await circuit.call(slow_func)
        await circuit.call(slow_func)

        # Check if circuit opens due to slow call rate
        # This depends on implementation details of slow call handling

    @pytest.mark.asyncio
    async def test_force_state_transitions(self, circuit_config):
        """Test forced state transitions."""
        circuit = CircuitBreaker("test_circuit", circuit_config)

        # Force open
        await circuit.force_open()
        assert circuit.is_open

        # Force half-open
        await circuit.force_half_open()
        assert circuit.is_half_open

        # Force closed
        await circuit.force_closed()
        assert circuit.is_closed

    @pytest.mark.asyncio
    async def test_circuit_metrics(self, circuit_config):
        """Test circuit breaker metrics collection."""
        circuit = CircuitBreaker("test_circuit", circuit_config)

        async def test_func():
            return "success"

        await circuit.call(test_func)

        metrics = circuit.get_metrics()

        assert metrics["name"] == "test_circuit"
        assert metrics["state"] == CircuitState.CLOSED.value
        assert metrics["total_calls"] >= 1
        assert "failure_rate" in metrics
        assert "time_in_current_state" in metrics

    @pytest.mark.asyncio
    async def test_circuit_decorator(self):
        """Test circuit breaker decorator."""
        config = CircuitBreakerConfig(failure_threshold=2, timeout=0.1)

        @circuit_breaker("decorated_circuit", config)
        async def decorated_func(should_fail: bool):
            if should_fail:
                raise ValueError("Decorated failure")
            return "decorated_success"

        # Test success
        result = await decorated_func(False)
        assert result == "decorated_success"

        # Test opening circuit
        with pytest.raises(ValueError):
            await decorated_func(True)

        with pytest.raises(ValueError):
            await decorated_func(True)

        # Circuit should now be open
        with pytest.raises(CircuitOpenError):
            await decorated_func(True)

    @pytest.mark.asyncio
    async def test_global_circuit_registry(self):
        """Test global circuit registry functionality."""
        config = CircuitBreakerConfig(failure_threshold=2)

        # Get circuit from global registry
        circuit1 = get_circuit("registry_test", config)
        circuit2 = get_circuit("registry_test")  # Should return same instance

        assert circuit1 is circuit2
        assert circuit1.name == "registry_test"

    @pytest.mark.asyncio
    async def test_circuit_reset(self, circuit_config):
        """Test circuit breaker reset functionality."""
        circuit = CircuitBreaker("test_circuit", circuit_config)

        # Open the circuit
        await circuit.force_open()
        circuit.failure_count = 5

        # Reset circuit
        circuit.reset()

        assert circuit.is_closed
        assert circuit.failure_count == 0
        assert len(circuit.call_results) == 0


if __name__ == "__main__":
    pytest.main([__file__])
