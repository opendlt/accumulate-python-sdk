"""
Test error mapping and handling.

Tests mapping of transport errors to Python exceptions,
error message formatting, and error code handling.
"""

import pytest
import sys
from pathlib import Path

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))
from helpers import MockTransport, MockClient

from accumulate_client.api_client import (
    AccumulateAPIError, AccumulateNetworkError, AccumulateValidationError,
    AccumulateClient, ClientConfig
)


def test_network_error_mapping():
    """Test mapping of network errors to AccumulateNetworkError."""
    transport = MockTransport()
    transport.set_failures(10)  # Force persistent failure

    client = MockClient(transport)

    with pytest.raises(AccumulateNetworkError) as exc_info:
        client.status()

    error = exc_info.value
    assert isinstance(error, AccumulateNetworkError)
    assert isinstance(error, AccumulateAPIError)  # Should inherit from base error
    assert "Mock network error" in str(error)


def test_api_error_with_code():
    """Test API error with error code."""
    transport = MockTransport()

    # Set up transport to return API error
    transport.set_response('test-method', {
        'error': {
            'code': 404,
            'message': 'Not found',
            'data': {'resource': 'transaction'}
        }
    })

    client = MockClient(transport)

    try:
        # Use direct transport call to test error handling
        transport.make_request('test-method', {})
        pytest.fail("Expected API error")
    except AccumulateAPIError as e:
        assert e.code == 404
        assert "Not found" in str(e)
        assert e.data == {'resource': 'transaction'}


def test_validation_error_mapping():
    """Test mapping of validation errors to AccumulateValidationError."""
    transport = MockTransport()

    # Set up validation error response
    validation_error = {
        'error': {
            'code': 400,
            'message': 'Validation failed',
            'data': {
                'errors': ['Field "amount" is required', 'Invalid URL format']
            }
        }
    }
    transport.set_response('validate', validation_error)

    client = MockClient(transport)

    try:
        transport.make_request('validate', {})
        pytest.fail("Expected validation error")
    except AccumulateValidationError as e:
        assert e.code == 400
        assert "Validation failed" in str(e)
        assert e.data is not None


def test_error_message_formatting():
    """Test that error messages are properly formatted."""
    transport = MockTransport()

    error_cases = [
        # Simple string error
        {'error': 'Simple error message'},

        # Error with code and message
        {'error': {'code': 500, 'message': 'Internal server error'}},

        # Error with code, message, and data
        {'error': {
            'code': 422,
            'message': 'Unprocessable entity',
            'data': {'field': 'amount', 'reason': 'negative value'}
        }},

        # Malformed error (just code)
        {'error': {'code': 999}},
    ]

    for i, error_response in enumerate(error_cases):
        transport.set_response(f'test-{i}', error_response)

        try:
            transport.make_request(f'test-{i}', {})
            pytest.fail(f"Expected error for case {i}")
        except AccumulateAPIError as e:
            # Should have reasonable error message
            assert len(str(e)) > 0
            assert str(e) != 'None'

            # Check error properties
            if isinstance(error_response['error'], dict):
                if 'code' in error_response['error']:
                    assert e.code == error_response['error']['code']
                if 'message' in error_response['error']:
                    assert error_response['error']['message'] in str(e)


def test_error_code_categorization():
    """Test that error codes are categorized correctly."""
    transport = MockTransport()
    client = MockClient(transport)

    # Test different error code ranges
    error_cases = [
        (400, AccumulateValidationError, "Bad request"),
        (401, AccumulateValidationError, "Unauthorized"),
        (404, AccumulateValidationError, "Not found"),
        (422, AccumulateValidationError, "Unprocessable entity"),
        (500, AccumulateAPIError, "Internal server error"),
        (-1, AccumulateAPIError, "Custom negative code"),
    ]

    for code, expected_exception, message in error_cases:
        transport.set_response('test', {
            'error': {'code': code, 'message': message}
        })

        with pytest.raises(expected_exception) as exc_info:
            transport.make_request('test', {})

        error = exc_info.value
        assert error.code == code
        assert message in str(error)


def test_error_inheritance_hierarchy():
    """Test that error classes have correct inheritance."""
    # AccumulateNetworkError should inherit from AccumulateAPIError
    assert issubclass(AccumulateNetworkError, AccumulateAPIError)

    # AccumulateValidationError should inherit from AccumulateAPIError
    assert issubclass(AccumulateValidationError, AccumulateAPIError)

    # All should ultimately inherit from Exception
    assert issubclass(AccumulateAPIError, Exception)
    assert issubclass(AccumulateNetworkError, Exception)
    assert issubclass(AccumulateValidationError, Exception)


def test_error_with_none_data():
    """Test error handling when data is None or missing."""
    transport = MockTransport()

    # Error with no data field
    transport.set_response('no-data', {
        'error': {'code': 500, 'message': 'No data error'}
    })

    # Error with explicit None data
    transport.set_response('null-data', {
        'error': {'code': 500, 'message': 'Null data error', 'data': None}
    })

    for method in ['no-data', 'null-data']:
        try:
            transport.make_request(method, {})
            pytest.fail(f"Expected error for {method}")
        except AccumulateAPIError as e:
            # Should handle gracefully
            assert e.data is None or e.data == {}
            assert len(str(e)) > 0


def test_transport_error_context():
    """Test that transport errors include context information."""
    transport = MockTransport()
    transport.set_failures(1)

    client = MockClient(transport)

    try:
        client.status()
    except AccumulateNetworkError as e:
        # Should include context about the operation
        error_msg = str(e).lower()
        assert 'network' in error_msg or 'transport' in error_msg or 'mock' in error_msg


def test_error_retry_vs_no_retry():
    """Test that certain errors are not retried."""
    transport = MockTransport()
    client = MockClient(transport)

    # Validation errors should not be retried
    transport.set_response('validate', {
        'error': {'code': 400, 'message': 'Bad request'}
    })

    start_call_count = transport.call_count

    try:
        transport.make_request('validate', {})
        pytest.fail("Expected validation error")
    except AccumulateValidationError:
        # Should have made only one call (no retries for validation errors)
        assert transport.call_count == start_call_count + 1


def test_error_chaining():
    """Test that errors can be chained properly."""
    transport = MockTransport()

    # Create a nested error scenario
    transport.set_response('chain', {
        'error': {
            'code': 500,
            'message': 'Database connection failed',
            'data': {
                'inner_error': 'Connection timeout after 30s',
                'retry_after': 60
            }
        }
    })

    try:
        transport.make_request('chain', {})
        pytest.fail("Expected chained error")
    except AccumulateAPIError as e:
        # Should preserve error details
        assert e.code == 500
        assert 'Database connection failed' in str(e)
        assert e.data['inner_error'] == 'Connection timeout after 30s'


def test_error_serialization():
    """Test that errors can be serialized/represented properly."""
    transport = MockTransport()

    error_data = {
        'error': {
            'code': 422,
            'message': 'Transaction validation failed',
            'data': {
                'field_errors': ['amount must be positive', 'invalid recipient'],
                'transaction_id': 'abc123'
            }
        }
    }
    transport.set_response('serialize', error_data)

    try:
        transport.make_request('serialize', {})
        pytest.fail("Expected serializable error")
    except AccumulateAPIError as e:
        # Test string representation
        str_repr = str(e)
        assert 'Transaction validation failed' in str_repr
        assert len(str_repr) > 0

        # Test repr
        repr_str = repr(e)
        assert 'AccumulateAPIError' in repr_str or 'AccumulateValidationError' in repr_str

        # Test that error attributes are accessible
        assert e.code == 422
        assert e.data is not None
        assert 'field_errors' in e.data


def test_error_handling_edge_cases():
    """Test error handling edge cases."""
    transport = MockTransport()

    edge_cases = [
        # Empty error object
        {'error': {}},

        # Error as empty string
        {'error': ''},

        # Error as number
        {'error': 404},

        # Malformed nested error
        {'error': {'message': {'nested': 'object'}}},
    ]

    for i, case in enumerate(edge_cases):
        transport.set_response(f'edge-{i}', case)

        try:
            transport.make_request(f'edge-{i}', {})
            pytest.fail(f"Expected error for edge case {i}")
        except AccumulateAPIError as e:
            # Should handle gracefully without crashing
            assert isinstance(e, AccumulateAPIError)
            assert len(str(e)) > 0


# TODO[ACC-P2-S945]: Add tests for error handling with different client configurations
# TODO[ACC-P2-S946]: Add tests for error rate limiting and circuit breaker patterns
# TODO[ACC-P2-S947]: Add tests for error logging and monitoring integration
# TODO[ACC-P2-S948]: Add tests for custom error handlers and callbacks
