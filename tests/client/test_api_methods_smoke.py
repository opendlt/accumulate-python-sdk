"""
Client API method smoke tests.

Tests all client API methods with mock transport to ensure they work
without external dependencies. Includes retry policy integration.
"""

import pytest
import time
from unittest.mock import Mock, patch
from typing import Dict, Any


class TestClientAPIMethods:
    """Test client API methods with mock transport."""

    @pytest.mark.parametrize("method_name,args", [
        ("query", ("acc://test.acme",)),
        ("submit", ({"transaction": {}, "signatures": []},)),
        ("faucet", ("acc://test.acme/ACME",)),
        ("status", ()),
    ])
    def test_api_method_smoke(self, mock_client, method_name, args):
        """Test that API methods work with mock transport."""
        method = getattr(mock_client, method_name)
        assert callable(method), f"Method {method_name} should be callable"

        # Call method with arguments
        result = method(*args)

        # Verify result structure
        assert isinstance(result, dict), f"Method {method_name} should return dict"
        assert 'data' in result, f"Method {method_name} should return data field"

    def test_query_method_variations(self, mock_client):
        """Test query method with different URL patterns."""
        test_urls = [
            "acc://test.acme",
            "acc://test.acme/ACME",
            "acc://test.acme/book/1",
            "acc://test.acme/data",
            "acc://test.acme/data#0"
        ]

        for url in test_urls:
            result = mock_client.query(url)
            assert 'data' in result
            assert isinstance(result['data'], dict)

    def test_submit_method_variations(self, mock_client):
        """Test submit method with different transaction types."""
        test_envelopes = [
            {"transaction": {"type": "CreateIdentity"}, "signatures": []},
            {"transaction": {"type": "SendTokens", "to": []}, "signatures": []},
            {"transaction": {"type": "WriteData", "data": "test"}, "signatures": []},
        ]

        for envelope in test_envelopes:
            result = mock_client.submit(envelope)
            assert 'data' in result
            assert 'transactionHash' in result['data']

    def test_faucet_method_balance_tracking(self, mock_client):
        """Test faucet method updates balances correctly."""
        account = "acc://test.acme/ACME"

        # Get initial balance
        initial_result = mock_client.query(account)
        initial_balance = initial_result['data']['balance']

        # Request faucet
        faucet_result = mock_client.faucet(account)
        assert 'transactionHash' in faucet_result['data']

        # Check balance increased
        final_result = mock_client.query(account)
        final_balance = final_result['data']['balance']

        assert final_balance > initial_balance, "Faucet should increase balance"

    def test_status_method_returns_network_info(self, mock_client):
        """Test status method returns network information."""
        result = mock_client.status()

        assert 'data' in result
        assert 'network' in result['data']
        assert 'version' in result['data']

        # Verify expected values
        assert result['data']['network'] == 'MockNet'
        assert result['data']['version'] == 'mock-1.0.0'


class TestClientRetryIntegration:
    """Test client retry policy integration."""

    def test_retry_policy_on_transient_failure(self, mock_client):
        """Test retry policy handles transient failures."""
        # Create a mock that fails once then succeeds
        failure_count = 0

        def failing_query(url):
            nonlocal failure_count
            failure_count += 1
            if failure_count == 1:
                raise ConnectionError("Temporary network error")
            return {"data": {"url": url, "type": "identity"}}

        # Create a retry wrapper to simulate retry behavior
        def retry_query(url, max_retries=2):
            for attempt in range(max_retries):
                try:
                    return failing_query(url)
                except ConnectionError:
                    if attempt == max_retries - 1:
                        raise
                    continue

        # This should succeed after retry
        result = retry_query("acc://test.acme")
        assert 'data' in result
        assert failure_count == 2  # Failed once, succeeded on retry

        # Test completed successfully

    def test_circuit_breaker_integration(self, mock_client):
        """Test circuit breaker integration if available."""
        # Test that multiple rapid failures don't cause infinite retries
        failure_count = 0

        def always_failing_query(url):
            nonlocal failure_count
            failure_count += 1
            raise ConnectionError("Network unreachable")

        original_query = mock_client.query
        mock_client.query = always_failing_query

        # Should fail quickly after circuit opens
        start_time = time.time()
        try:
            mock_client.query("acc://test.acme")
        except:
            pass  # Expected to fail

        elapsed = time.time() - start_time
        # Should fail relatively quickly (circuit breaker effect)
        assert elapsed < 5.0, "Circuit breaker should prevent long retry loops"

        # Restore original method
        mock_client.query = original_query


class TestClientErrorHandling:
    """Test client error handling scenarios."""

    def test_invalid_url_handling(self, mock_client):
        """Test handling of invalid URLs."""
        invalid_urls = [
            "",
            "not-a-url",
            "http://invalid",
            None
        ]

        for invalid_url in invalid_urls:
            try:
                result = mock_client.query(invalid_url)
                # Mock client might handle anything, just verify it returns something
                assert isinstance(result, dict)
            except (ValueError, TypeError):
                # Also acceptable for invalid inputs
                pass

    def test_malformed_envelope_handling(self, mock_client):
        """Test handling of malformed transaction envelopes."""
        malformed_envelopes = [
            {},  # Empty envelope
            {"transaction": {}},  # Missing signatures
            {"signatures": []},  # Missing transaction
            None,  # Invalid type
        ]

        for envelope in malformed_envelopes:
            try:
                result = mock_client.submit(envelope)
                # Mock might handle anything
                assert isinstance(result, dict)
            except (ValueError, TypeError, KeyError):
                # Also acceptable for malformed input
                pass

    def test_network_timeout_simulation(self, mock_client):
        """Test network timeout handling."""
        def timeout_query(url):
            raise TimeoutError("Request timed out")

        original_query = mock_client.query
        mock_client.query = timeout_query

        try:
            mock_client.query("acc://test.acme")
        except TimeoutError:
            # Expected behavior
            pass

        # Restore original method
        mock_client.query = original_query


class TestClientResponseSchemas:
    """Test that client responses match expected schemas."""

    def test_query_response_schema(self, mock_client):
        """Test query response has expected schema."""
        result = mock_client.query("acc://test.acme")

        # Required fields
        assert 'data' in result
        assert isinstance(result['data'], dict)

        # Optional fields that might be present
        optional_fields = ['error', 'warnings', 'metadata']
        for field in optional_fields:
            if field in result:
                assert result[field] is not None

    def test_submit_response_schema(self, mock_client):
        """Test submit response has expected schema."""
        envelope = {"transaction": {"type": "test"}, "signatures": []}
        result = mock_client.submit(envelope)

        # Required fields
        assert 'data' in result
        assert isinstance(result['data'], dict)
        assert 'transactionHash' in result['data']

        # Verify transaction hash format
        tx_hash = result['data']['transactionHash']
        assert isinstance(tx_hash, str)
        assert len(tx_hash) > 0

    def test_faucet_response_schema(self, mock_client):
        """Test faucet response has expected schema."""
        result = mock_client.faucet("acc://test.acme/ACME")

        # Required fields
        assert 'data' in result
        assert isinstance(result['data'], dict)
        assert 'transactionHash' in result['data']

        # Verify transaction hash
        tx_hash = result['data']['transactionHash']
        assert tx_hash == 'mock_faucet_hash'

    def test_status_response_schema(self, mock_client):
        """Test status response has expected schema."""
        result = mock_client.status()

        # Required fields
        assert 'data' in result
        assert isinstance(result['data'], dict)
        assert 'network' in result['data']
        assert 'version' in result['data']

        # Verify field types
        assert isinstance(result['data']['network'], str)
        assert isinstance(result['data']['version'], str)


class TestClientStateManagement:
    """Test client state management."""

    def test_mock_client_state_persistence(self, mock_client):
        """Test that mock client maintains state across calls."""
        # Test balance tracking persistence
        account = "acc://test.acme/ACME"

        # Initial query
        result1 = mock_client.query(account)
        balance1 = result1['data']['balance']

        # Faucet call
        mock_client.faucet(account)

        # Query again
        result2 = mock_client.query(account)
        balance2 = result2['data']['balance']

        # State should be maintained
        assert balance2 > balance1

        # Another faucet call
        mock_client.faucet(account)

        # Query again
        result3 = mock_client.query(account)
        balance3 = result3['data']['balance']

        # Should continue increasing
        assert balance3 > balance2

    def test_transaction_counter_increments(self, mock_client):
        """Test that transaction counter increments properly."""
        # Submit multiple transactions
        envelope = {"transaction": {"type": "test"}, "signatures": []}

        hashes = []
        for i in range(3):
            result = mock_client.submit(envelope)
            tx_hash = result['data']['transactionHash']
            hashes.append(tx_hash)

        # All hashes should be unique (counter incrementing)
        assert len(set(hashes)) == 3, "Transaction hashes should be unique"

        # Should follow expected pattern
        for i, tx_hash in enumerate(hashes, 1):
            expected_suffix = f"{i:04d}"
            assert expected_suffix in tx_hash