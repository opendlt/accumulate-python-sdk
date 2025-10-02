"""
Test API parity and completeness.

Tests that the high-level client exposes all expected API methods
and maintains compatibility with the protocol specification.
"""

import pytest
import inspect
import sys
from pathlib import Path

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))
from helpers import MockClient

from accumulate_client.api_client import AccumulateClient
from accumulate_client.json_rpc_client import JsonRpcClient


def get_api_methods(client_class):
    """Get all public API methods from a client class."""
    methods = []
    for name in dir(client_class):
        if name.startswith('_'):
            continue
        attr = getattr(client_class, name)
        if callable(attr):
            methods.append(name)
    return sorted(methods)


def test_accumulate_client_method_count():
    """Test that AccumulateClient has expected number of methods."""
    methods = get_api_methods(AccumulateClient)

    # Filter out non-API methods (properties, utilities, etc.)
    api_methods = [m for m in methods if not m in {
        'for_network', 'config'  # Utility methods
    }]

    print(f"AccumulateClient has {len(api_methods)} API methods")

    # Should have close to 35 API methods as specified
    assert len(api_methods) >= 30, f"Expected at least 30 API methods, got {len(api_methods)}"

    # Print methods for reference
    print("AccumulateClient API methods:")
    for method in api_methods:
        print(f"  {method}")


def test_json_rpc_client_method_count():
    """Test that JsonRpcClient has expected methods."""
    methods = get_api_methods(JsonRpcClient)

    # Filter out utility methods
    api_methods = [m for m in methods if not m in {'call'}]

    print(f"JsonRpcClient has {len(api_methods)} API methods")

    # Should have a reasonable number of methods
    assert len(api_methods) >= 20, f"Expected at least 20 API methods, got {len(api_methods)}"


def test_client_method_compatibility():
    """Test that both client classes have overlapping method sets."""
    accumulate_methods = set(get_api_methods(AccumulateClient))
    jsonrpc_methods = set(get_api_methods(JsonRpcClient))

    # Remove utility methods for comparison
    accumulate_api = {m for m in accumulate_methods if not m.startswith('for_')}
    jsonrpc_api = {m for m in jsonrpc_methods if m != 'call'}

    # There should be significant overlap
    overlap = accumulate_api & jsonrpc_api
    print(f"Method overlap: {len(overlap)} methods")

    assert len(overlap) >= 10, f"Expected significant method overlap, got {len(overlap)}"


# Core API methods that should be present
EXPECTED_CORE_METHODS = [
    'status',
    'version',
    'describe',
    'metrics',
    'query',
    'submit',
    'faucet'
]

# V2 API methods
EXPECTED_V2_METHODS = [
    'query_tx',
    'query_directory',
    'query_data',
    'execute'
]

# Node service methods
EXPECTED_NODE_METHODS = [
    'node_info',
    'consensus_status',
    'network_status'
]


@pytest.mark.parametrize("method_name", EXPECTED_CORE_METHODS)
def test_accumulate_client_has_core_method(method_name):
    """Test that AccumulateClient has each expected core method."""
    assert hasattr(AccumulateClient, method_name), f"AccumulateClient missing method: {method_name}"

    method = getattr(AccumulateClient, method_name)
    assert callable(method), f"AccumulateClient.{method_name} is not callable"


@pytest.mark.parametrize("method_name", EXPECTED_V2_METHODS)
def test_accumulate_client_has_v2_method(method_name):
    """Test that AccumulateClient has each expected V2 method."""
    assert hasattr(AccumulateClient, method_name), f"AccumulateClient missing V2 method: {method_name}"

    method = getattr(AccumulateClient, method_name)
    assert callable(method), f"AccumulateClient.{method_name} is not callable"


@pytest.mark.parametrize("method_name", EXPECTED_NODE_METHODS)
def test_accumulate_client_has_node_method(method_name):
    """Test that AccumulateClient has each expected node method."""
    assert hasattr(AccumulateClient, method_name), f"AccumulateClient missing node method: {method_name}"

    method = getattr(AccumulateClient, method_name)
    assert callable(method), f"AccumulateClient.{method_name} is not callable"


def test_client_method_signatures():
    """Test that client methods have reasonable signatures."""
    # Test a few key methods for signature compatibility
    methods_to_check = ['query', 'submit', 'query_tx', 'faucet']

    for method_name in methods_to_check:
        if hasattr(AccumulateClient, method_name):
            method = getattr(AccumulateClient, method_name)
            sig = inspect.signature(method)

            # Should have at least one parameter (self)
            assert len(sig.parameters) >= 1, f"{method_name} should have parameters"

            # Parameters should have reasonable names
            param_names = list(sig.parameters.keys())
            assert 'self' in param_names, f"{method_name} should have 'self' parameter"


def test_mock_client_compatibility():
    """Test that MockClient is compatible with real client interface."""
    mock_client = MockClient()

    # Should have key methods
    required_methods = ['submit', 'query_tx', 'status']
    for method_name in required_methods:
        assert hasattr(mock_client, method_name), f"MockClient missing method: {method_name}"
        assert callable(getattr(mock_client, method_name)), f"MockClient.{method_name} not callable"


def test_client_instantiation():
    """Test that clients can be instantiated properly."""
    # Test AccumulateClient
    try:
        client = AccumulateClient('testnet')
        assert client is not None
        assert hasattr(client, 'config')
    except Exception as e:
        pytest.fail(f"Failed to instantiate AccumulateClient: {e}")

    # Test JsonRpcClient
    try:
        client = JsonRpcClient('localhost:26660')
        assert client is not None
        assert hasattr(client, 'host')
    except Exception as e:
        pytest.fail(f"Failed to instantiate JsonRpcClient: {e}")


def test_client_method_smoke_test():
    """Smoke test key client methods with MockClient."""
    mock_client = MockClient()

    # Test status method
    try:
        result = mock_client.status()
        assert isinstance(result, dict)
        assert 'network' in result
    except Exception as e:
        pytest.fail(f"MockClient.status() failed: {e}")

    # Test submit method
    try:
        envelope = {'test': 'envelope'}
        result = mock_client.submit(envelope)
        assert isinstance(result, list)
        assert len(result) > 0
    except Exception as e:
        pytest.fail(f"MockClient.submit() failed: {e}")

    # Test query_tx method
    try:
        # First submit a transaction to get a txid
        envelope = {'test': 'envelope'}
        submit_result = mock_client.submit(envelope)
        txid = submit_result[0]['txid']

        # Then query it
        query_result = mock_client.query_tx(txid)
        assert isinstance(query_result, dict)
        assert 'txid' in query_result
    except Exception as e:
        pytest.fail(f"MockClient.query_tx() failed: {e}")


def test_client_error_handling():
    """Test that clients handle errors appropriately."""
    mock_client = MockClient()

    # Test querying non-existent transaction
    try:
        fake_txid = "0" * 64
        mock_client.query_tx(fake_txid)
    except Exception as e:
        # Should raise an appropriate error
        assert 'not found' in str(e).lower() or 'error' in str(e).lower()


def test_client_configuration():
    """Test client configuration and factory methods."""
    # Test AccumulateClient factory methods
    if hasattr(AccumulateClient, 'for_network'):
        try:
            mainnet_client = AccumulateClient.for_network('mainnet')
            assert mainnet_client is not None

            testnet_client = AccumulateClient.for_network('testnet')
            assert testnet_client is not None

            local_client = AccumulateClient.for_network('local')
            assert local_client is not None

        except Exception as e:
            pytest.fail(f"Client factory methods failed: {e}")


def test_client_method_documentation():
    """Test that client methods have documentation."""
    important_methods = ['query', 'submit', 'query_tx', 'status']

    for method_name in important_methods:
        if hasattr(AccumulateClient, method_name):
            method = getattr(AccumulateClient, method_name)
            assert method.__doc__ is not None, f"{method_name} should have documentation"
            assert len(method.__doc__.strip()) > 0, f"{method_name} documentation should not be empty"


def test_enhanced_client_integration():
    """Test enhanced client with transaction builder integration."""
    try:
        from accumulate_client.tx.client_helpers import EnhancedAccumulateClient

        # Test that enhanced client has builder methods
        enhanced_methods = get_api_methods(EnhancedAccumulateClient)

        # Should have transaction builder methods
        builder_methods = [m for m in enhanced_methods if 'create_' in m or 'send_' in m or 'build_' in m]
        assert len(builder_methods) > 0, "EnhancedAccumulateClient should have builder methods"

        print(f"EnhancedAccumulateClient has {len(builder_methods)} builder methods")

        # Should also have all regular client methods
        regular_methods = get_api_methods(AccumulateClient)
        for method in regular_methods:
            if not method.startswith('for_'):  # Skip factory methods
                assert hasattr(EnhancedAccumulateClient, method), \
                    f"EnhancedAccumulateClient missing regular method: {method}"

    except ImportError:
        pytest.skip("EnhancedAccumulateClient not available")


# TODO[ACC-P2-S937]: Add tests for API method parameter validation
# TODO[ACC-P2-S938]: Add tests for API method return type consistency
# TODO[ACC-P2-S939]: Add tests for API versioning compatibility
# TODO[ACC-P2-S940]: Add tests for API method performance characteristics
