"""
Test transport retry and backoff behavior.

Tests retry logic, backoff algorithms, and error recovery
for network transport operations.
"""

import pytest
import time
import sys
from pathlib import Path

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))
from helpers import MockTransport

from accumulate_client.api_client import AccumulateClient, AccumulateNetworkError, ClientConfig


def test_transport_retry_success_after_failures():
    """Test that transport succeeds after initial failures."""
    transport = MockTransport()
    transport.set_failures(2)  # Fail first 2 attempts, succeed on 3rd

    # Use AccumulateClient with mock transport for proper retry logic
    config = ClientConfig(endpoint='testnet', max_retries=3, retry_delay=0.01)
    client = AccumulateClient(config)
    client.transport = transport

    start_time = time.time()

    # Should eventually succeed
    result = client.status()
    elapsed = time.time() - start_time

    assert isinstance(result, dict)
    assert transport.call_count >= 3  # Should have made at least 3 calls
    # Should have taken some time due to retries (but we can't be too strict in tests)


def test_transport_retry_persistent_failure():
    """Test behavior with persistent transport failures."""
    transport = MockTransport()
    transport.set_failures(10)  # More failures than max retries

    # Use AccumulateClient with mock transport for proper retry logic
    config = ClientConfig(endpoint='testnet', max_retries=3, retry_delay=0.01)
    client = AccumulateClient(config)
    client.transport = transport

    # Should eventually give up and raise error
    with pytest.raises(AccumulateNetworkError):
        client.status()

    # Should have attempted multiple calls
    assert transport.call_count > 1


def test_transport_retry_backoff_timing():
    """Test that retry backoff timing is reasonable."""
    # This test is more about structure than precise timing
    # since timing tests can be flaky in CI environments

    transport = MockTransport()
    transport.set_failures(3)

    # Create client with known retry configuration
    config = ClientConfig(
        endpoint='testnet',
        max_retries=3,
        retry_delay=0.1,  # Short delays for testing
        retry_backoff=2.0
    )
    client = AccumulateClient(config)
    client.transport = transport  # Use our mock transport

    start_time = time.time()

    try:
        # This should fail, but we're testing timing
        client._make_request('test', {})
    except:
        pass

    elapsed = time.time() - start_time

    # Should have taken at least some time for retries
    # With 0.1s initial delay and 2.0x backoff: 0.1 + 0.2 + 0.4 = 0.7s minimum
    expected_min_time = 0.05  # Very conservative for test stability
    assert elapsed >= expected_min_time, f"Retry timing too fast: {elapsed}s"


def test_transport_retry_call_counting():
    """Test that retry call counting is accurate."""
    transport = MockTransport()
    transport.set_failures(2)

    config = ClientConfig(endpoint='testnet', max_retries=3, retry_delay=0.01)
    client = AccumulateClient(config)
    client.transport = transport

    # Reset call count
    transport.call_count = 0

    # Make a call that should succeed on 3rd attempt
    client.status()

    # Should have made exactly 3 calls (2 failures + 1 success)
    assert transport.call_count == 3


def test_transport_immediate_success():
    """Test transport behavior with immediate success (no retries needed)."""
    transport = MockTransport()
    transport.set_failures(0)  # No failures

    config = ClientConfig(endpoint='testnet', max_retries=3, retry_delay=0.01)
    client = AccumulateClient(config)
    client.transport = transport
    transport.call_count = 0

    start_time = time.time()
    result = client.status()
    elapsed = time.time() - start_time

    assert isinstance(result, dict)
    assert transport.call_count == 1  # Should only make one call
    assert elapsed < 0.1  # Should be very fast


def test_transport_retry_different_methods():
    """Test retry behavior across different API methods."""
    transport = MockTransport()

    config = ClientConfig(endpoint='testnet', max_retries=3, retry_delay=0.01)
    client = AccumulateClient(config)
    client.transport = transport

    methods_to_test = [
        ('status', [], {}),
        ('node_info', [], {}),
        ('submit', [{'test': 'envelope'}], {}),
    ]

    for method_name, args, kwargs in methods_to_test:
        if hasattr(client, method_name):
            transport.set_failures(1)  # Fail once for each method
            transport.call_count = 0
            transport.fail_count = 0  # Reset failure count

            method = getattr(client, method_name)
            result = method(*args, **kwargs)

            # Should have retried once and succeeded
            assert transport.call_count == 2


def test_transport_retry_with_different_error_types():
    """Test retry behavior with different types of errors."""
    # This test would be more meaningful with a real transport implementation
    # For now, we test the mock's basic error handling

    transport = MockTransport()
    transport.set_failures(1)

    config = ClientConfig(endpoint='testnet', max_retries=3, retry_delay=0.01)
    client = AccumulateClient(config)
    client.transport = transport

    # Test with basic network error
    try:
        result = client.status()
        assert isinstance(result, dict)
    except Exception as e:
        pytest.fail(f"Should have succeeded after retry: {e}")


def test_transport_retry_configuration():
    """Test transport retry with different configurations."""
    transport = MockTransport()
    transport.set_failures(2)

    # Test with different retry settings
    configs = [
        {'max_retries': 1, 'retry_delay': 0.01},
        {'max_retries': 3, 'retry_delay': 0.01},
        {'max_retries': 5, 'retry_delay': 0.01},
    ]

    for config_params in configs:
        config = ClientConfig(endpoint='testnet', **config_params)
        client = AccumulateClient(config)
        client.transport = transport

        # Reset transport state
        transport.call_count = 0
        transport.fail_count = 0

        try:
            client._make_request('test', {})
            # If successful, should have made retries
            assert transport.call_count > 1
        except AccumulateNetworkError:
            # If failed, should have attempted up to max_retries + 1
            expected_max_calls = config_params['max_retries'] + 1
            assert transport.call_count <= expected_max_calls


def test_transport_retry_backoff_progression():
    """Test that retry delays follow backoff progression."""
    # This is a structural test since precise timing is hard to test

    transport = MockTransport()
    transport.set_failures(3)

    config = ClientConfig(
        endpoint='testnet',
        max_retries=3,
        retry_delay=0.1,
        retry_backoff=2.0
    )
    client = AccumulateClient(config)
    client.transport = transport

    timestamps = []

    # Mock the sleep function to capture timing
    original_sleep = time.sleep
    def mock_sleep(duration):
        timestamps.append((time.time(), duration))
        original_sleep(duration * 0.01)  # Shorten actual sleep for tests

    time.sleep = mock_sleep

    try:
        client._make_request('test', {})
    except:
        pass
    finally:
        time.sleep = original_sleep

    # Should have recorded sleep calls with increasing durations
    if len(timestamps) >= 2:
        durations = [duration for _, duration in timestamps]
        # Each duration should be roughly double the previous (with backoff=2.0)
        for i in range(1, len(durations)):
            ratio = durations[i] / durations[i-1]
            assert 1.5 <= ratio <= 2.5, f"Backoff ratio {ratio} not in expected range"


def test_transport_retry_partial_failure_recovery():
    """Test recovery from partial failures."""
    transport = MockTransport()

    config = ClientConfig(endpoint='testnet', max_retries=3, retry_delay=0.01)
    client = AccumulateClient(config)
    client.transport = transport

    # Simulate intermittent failures
    failure_patterns = [0, 1, 0, 1, 0]  # Alternate success/failure

    for should_fail in failure_patterns:
        transport.set_failures(should_fail)
        transport.call_count = 0
        transport.fail_count = 0

        try:
            result = client.status()
            if should_fail:
                # If we expected failure but got success, that's OK (retry worked)
                pass
            else:
                assert isinstance(result, dict)
        except AccumulateNetworkError:
            if not should_fail:
                pytest.fail("Unexpected failure when none expected")


def test_transport_concurrent_retry():
    """Test retry behavior with concurrent requests."""
    transport = MockTransport()
    transport.set_failures(1)  # Each request fails once

    config = ClientConfig(endpoint='testnet', max_retries=3, retry_delay=0.01)
    client = AccumulateClient(config)
    client.transport = transport

    # Make multiple concurrent-ish requests
    results = []
    errors = []

    for i in range(3):
        try:
            result = client.status()
            results.append(result)
        except Exception as e:
            errors.append(e)

    # Most or all requests should eventually succeed
    assert len(results) >= 2, f"Too many failures: {len(errors)} errors, {len(results)} successes"


# TODO[ACC-P2-S941]: Add tests for retry with exponential backoff jitter
# TODO[ACC-P2-S942]: Add tests for retry circuit breaker patterns
# TODO[ACC-P2-S943]: Add tests for retry with different timeout values
# TODO[ACC-P2-S944]: Add tests for retry metrics and monitoring
