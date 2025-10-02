"""
Test retry policies, circuit breakers, and metrics integration.

Exercises error recovery components to ensure they handle various
failure scenarios and properly update metrics counters.
"""

import pytest
import asyncio
import time
from unittest.mock import AsyncMock, Mock

from accumulate_client.recovery.retry import (
    RetryPolicy, ExponentialBackoff, LinearBackoff, FixedBackoff
)
from accumulate_client.recovery.circuit_breaker import (
    CircuitBreaker, CircuitBreakerConfig, CircuitState, CircuitBreakerOpenError
)
from accumulate_client.monitoring.metrics import get_registry, Counter, Timer


class TransientError(Exception):
    """Mock transient error that should be retried."""
    pass


class FatalError(Exception):
    """Mock fatal error that should not be retried."""
    pass


@pytest.fixture
def fresh_registry():
    """Get a fresh metrics registry for each test."""
    registry = get_registry()
    registry._metrics.clear()  # Clear previous metrics
    return registry


@pytest.mark.recovery
@pytest.mark.unit
def test_exponential_backoff_retry_success():
    """Test retry policy succeeds after transient failures."""

    retry_policy = ExponentialBackoff(max_attempts=3, base_delay=0.001)

    call_count = 0

    async def flaky_operation():
        nonlocal call_count
        call_count += 1
        if call_count < 3:
            raise TransientError("Temporary failure")
        return "success"

    # Should succeed on third attempt
    result = asyncio.run(retry_policy.execute(flaky_operation))
    assert result == "success"
    assert call_count == 3


@pytest.mark.recovery
@pytest.mark.unit
def test_exponential_backoff_delay_progression():
    """Test that exponential backoff increases delays correctly."""

    retry_policy = ExponentialBackoff(
        max_attempts=4,
        base_delay=0.1,
        factor=2.0,
        max_delay=1.0
    )

    # Test delay calculation
    assert retry_policy.calculate_delay(1) == 0.1
    assert retry_policy.calculate_delay(2) == 0.2
    assert retry_policy.calculate_delay(3) == 0.4
    # Should cap at max_delay
    assert retry_policy.calculate_delay(10) == 1.0


@pytest.mark.recovery
@pytest.mark.unit
def test_linear_backoff_delay_progression():
    """Test that linear backoff increases delays linearly."""

    retry_policy = LinearBackoff(
        max_attempts=4,
        base_delay=0.1,
        increment=0.05,
        max_delay=0.5
    )

    assert retry_policy.calculate_delay(1) == pytest.approx(0.1)
    assert retry_policy.calculate_delay(2) == pytest.approx(0.15)
    assert retry_policy.calculate_delay(3) == pytest.approx(0.20)
    # Should cap at max_delay
    assert retry_policy.calculate_delay(20) == 0.5


@pytest.mark.recovery
@pytest.mark.unit
def test_fixed_backoff_constant_delay():
    """Test that fixed backoff maintains constant delay."""

    retry_policy = FixedBackoff(max_attempts=5, delay=0.2)

    for attempt in range(1, 10):
        assert retry_policy.calculate_delay(attempt) == 0.2


@pytest.mark.recovery
@pytest.mark.unit
def test_retry_policy_max_attempts_exceeded():
    """Test retry policy gives up after max attempts."""

    retry_policy = ExponentialBackoff(max_attempts=2, base_delay=0.001, raise_original_exception=True)

    async def always_fails():
        raise TransientError("Always fails")

    # Should raise after max attempts
    with pytest.raises(TransientError):
        asyncio.run(retry_policy.execute(always_fails))


@pytest.mark.recovery
@pytest.mark.unit
def test_circuit_breaker_state_transitions():
    """Test circuit breaker state transitions."""

    config = CircuitBreakerConfig(
        failure_threshold=2,
        timeout=0.1,
        failure_rate_threshold=0.5
    )

    circuit = CircuitBreaker("test_circuit", config)

    # Initially closed
    assert circuit.state == CircuitState.CLOSED

    # Record failures to trip circuit
    circuit._record_failure()
    assert circuit.state == CircuitState.CLOSED

    circuit._record_failure()
    assert circuit.state == CircuitState.OPEN

    # Wait for timeout and check half-open
    time.sleep(0.15)  # Wait longer than timeout

    # Next call should transition to half-open
    try:
        circuit._check_state()
    except:
        pass

    # Circuit should allow one test call in half-open state
    assert circuit.state in [CircuitState.HALF_OPEN, CircuitState.OPEN]


@pytest.mark.recovery
@pytest.mark.unit
def test_circuit_breaker_prevents_calls_when_open():
    """Test circuit breaker prevents calls when open."""

    config = CircuitBreakerConfig(failure_threshold=1, timeout=1.0)
    circuit = CircuitBreaker("test_circuit", config)

    # Trip the circuit
    circuit._record_failure()
    assert circuit.state == CircuitState.OPEN

    # Should raise CircuitBreakerOpenError when calling
    async def test_operation():
        return "should not execute"

    with pytest.raises(CircuitBreakerOpenError):
        asyncio.run(circuit.call(test_operation))


@pytest.mark.metrics
@pytest.mark.unit
def test_metrics_counter_increment(fresh_registry):
    """Test metrics counter increments correctly."""

    counter = fresh_registry.counter("test_requests", "Test request counter")

    # Initial value should be 0
    assert counter.get_value() == 0

    # Increment and verify
    counter.increment(1)
    assert counter.get_value() == 1

    counter.increment(5)
    assert counter.get_value() == 6

    # Test with labels - labels create separate buckets
    counter.increment(2, {"status": "success"})
    assert counter.get_value() == 6  # Default bucket unchanged
    assert counter.get_value({"status": "success"}) == 2  # Labeled bucket


@pytest.mark.metrics
@pytest.mark.unit
def test_metrics_timer_measurements(fresh_registry):
    """Test metrics timer records durations."""

    timer = fresh_registry.timer("test_duration", "Test duration timer")

    # Record some durations
    timer.observe(0.1)
    timer.observe(0.2)
    timer.observe(0.15)

    # Timer should have recorded observations
    stats = timer.get_stats()
    assert stats['count'] == 3
    assert stats['sum'] == pytest.approx(0.45, rel=1e-2)


@pytest.mark.metrics
@pytest.mark.unit
def test_metrics_with_retry_integration(fresh_registry):
    """Test that retry operations update metrics correctly."""

    # Create metrics
    attempt_counter = fresh_registry.counter("retry_attempts", "Retry attempts")
    success_counter = fresh_registry.counter("retry_success", "Retry successes")
    failure_counter = fresh_registry.counter("retry_failures", "Retry failures")

    retry_policy = ExponentialBackoff(max_attempts=3, base_delay=0.001)

    call_count = 0

    async def operation_with_metrics():
        nonlocal call_count
        call_count += 1
        attempt_counter.increment(1)

        if call_count < 2:
            failure_counter.increment(1)
            raise TransientError("Temporary failure")

        success_counter.increment(1)
        return "success"

    # Execute with retries
    result = asyncio.run(retry_policy.execute(operation_with_metrics))

    assert result == "success"
    assert attempt_counter.get_value() == 2  # Two attempts total
    assert success_counter.get_value() == 1   # One success
    assert failure_counter.get_value() == 1   # One failure


@pytest.mark.recovery
@pytest.mark.metrics
@pytest.mark.unit
def test_circuit_breaker_metrics_integration(fresh_registry):
    """Test circuit breaker updates metrics correctly."""

    # Create metrics
    call_counter = fresh_registry.counter("circuit_calls", "Circuit breaker calls")
    success_counter = fresh_registry.counter("circuit_success", "Circuit breaker successes")
    failure_counter = fresh_registry.counter("circuit_failures", "Circuit breaker failures")

    config = CircuitBreakerConfig(failure_threshold=2, timeout=0.1)
    circuit = CircuitBreaker("test_circuit", config)

    async def operation_with_metrics(should_fail=False):
        call_counter.increment(1)
        if should_fail:
            failure_counter.increment(1)
            raise Exception("Simulated failure")
        success_counter.increment(1)
        return "success"

    # Successful call
    async def success_op():
        return await operation_with_metrics(False)

    result = asyncio.run(circuit.call(success_op))
    assert result == "success"

    # Failed calls to trip circuit
    async def fail_op():
        return await operation_with_metrics(True)

    with pytest.raises(Exception):
        asyncio.run(circuit.call(fail_op))

    with pytest.raises(Exception):
        asyncio.run(circuit.call(fail_op))

    # Verify metrics
    assert call_counter.get_value() >= 2  # At least 2 calls made
    assert failure_counter.get_value() >= 2  # At least 2 failures
    assert success_counter.get_value() == 1   # One success


@pytest.mark.unit
def test_retry_policy_interface_coverage():
    """Test that all retry policy types implement the interface correctly."""

    policies = [
        ExponentialBackoff(max_attempts=3),
        LinearBackoff(max_attempts=3),
        FixedBackoff(max_attempts=3, delay=0.1)
    ]

    for policy in policies:
        # All should implement calculate_delay
        delay = policy.calculate_delay(1)
        assert isinstance(delay, (int, float))
        assert delay >= 0

        # All should have max_attempts
        assert hasattr(policy, 'max_attempts')
        assert policy.max_attempts > 0
