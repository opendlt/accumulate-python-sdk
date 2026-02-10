"""
Basic functionality tests for the Accumulate Python SDK.

Tests the core runtime components without requiring network access.
"""

import pytest
from datetime import datetime, timezone

from accumulate_client import (
    AccumulateClient,
    AccountUrl,
    hash_sha256_hex,
    encode_json,
    encode_binary,
    decode_binary,
    write_varint,
    read_varint,
)

from accumulate_client.runtime.errors import (
    AccumulateError,
    ValidationError,
    NetworkError,
    ErrorCode,
)


class TestAccountUrl:
    """Test AccountUrl functionality."""

    def test_basic_url_creation(self):
        """Test basic URL creation and validation."""
        url = AccountUrl("acc://example.acme")
        assert str(url) == "acc://example.acme"
        assert url.identity == "example.acme"
        assert url.path == ""

    def test_url_with_path(self):
        """Test URL with path components."""
        url = AccountUrl("acc://example.acme/tokens")
        assert url.identity == "example.acme"
        assert url.path == "tokens"

    def test_url_joining(self):
        """Test URL path joining."""
        base = AccountUrl("acc://example.acme")
        token_url = base.join("tokens")
        data_url = base.join("data", "chain")

        assert str(token_url) == "acc://example.acme/tokens"
        assert str(data_url) == "acc://example.acme/data/chain"

    def test_lite_account_detection(self):
        """Test lite account URL detection."""
        # Regular identity
        regular = AccountUrl("acc://example.acme")
        assert not regular.is_lite

        # Lite account (64 hex chars)
        lite = AccountUrl("acc://" + "a" * 64)
        assert lite.is_lite

    def test_url_parsing_methods(self):
        """Test URL parsing class methods."""
        url1 = AccountUrl.parse("acc://example.acme")
        url2 = AccountUrl.parse("//example.acme")
        url3 = AccountUrl.from_identity("example.acme")

        assert str(url1) == "acc://example.acme"
        assert str(url2) == "acc://example.acme"
        assert str(url3) == "acc://example.acme"

    def test_url_relationships(self):
        """Test URL relationship methods."""
        parent = AccountUrl("acc://example.acme")
        child = AccountUrl("acc://example.acme/tokens")

        assert child.is_child_of(parent)
        assert not parent.is_child_of(child)
        assert parent.is_root()
        assert not child.is_root()

    def test_account_type_hints(self):
        """Test account type hinting."""
        identity = AccountUrl("acc://example.acme")
        tokens = AccountUrl("acc://example.acme/tokens")
        data = AccountUrl("acc://example.acme/data")
        book = AccountUrl("acc://example.acme/book")

        assert identity.account_type_hint() == "identity"
        assert tokens.account_type_hint() == "token_account"
        assert data.account_type_hint() == "data_account"
        assert book.account_type_hint() == "key_book"


class TestEncoding:
    """Test encoding and hashing functionality."""

    def test_varint_encoding(self):
        """Test variable-length integer encoding."""
        # Test small numbers
        assert write_varint(0) == b'\x00'
        assert write_varint(127) == b'\x7f'
        assert write_varint(128) == b'\x80\x01'

        # Test round-trip
        for value in [0, 1, 127, 128, 255, 16383, 16384]:
            encoded = write_varint(value)
            decoded, offset = read_varint(encoded)
            assert decoded == value
            assert offset == len(encoded)

    def test_json_encoding(self):
        """Test canonical JSON encoding."""
        data = {
            "type": "test",
            "number": 42,
            "boolean": True,
            "null": None,
            "array": [1, 2, 3],
            "nested": {"key": "value"}
        }

        json_str = encode_json(data)

        # Should be deterministic (sorted keys, no spaces)
        assert '"array":[1,2,3]' in json_str
        assert '"boolean":true' in json_str
        assert '"null":null' in json_str

    def test_binary_encoding_basic_types(self):
        """Test binary encoding of basic types."""
        # Test string
        encoded = encode_binary("hello")
        decoded = decode_binary(encoded, str)
        # Note: decode_binary currently returns dict, so this test may need adjustment

        # Test integer
        encoded = encode_binary(42)
        # Test would go here once binary encoding is fully implemented

    def test_hashing(self):
        """Test hashing functions."""
        data = "hello world"

        # Test string hashing
        hash_bytes = hash_sha256_hex(data)
        assert len(hash_bytes) == 64  # 32 bytes = 64 hex chars
        assert isinstance(hash_bytes, str)

        # Same input should produce same hash
        hash2 = hash_sha256_hex(data)
        assert hash_bytes == hash2

        # Different input should produce different hash
        hash3 = hash_sha256_hex("different data")
        assert hash_bytes != hash3


class TestErrorHandling:
    """Test error handling functionality."""

    def test_error_creation(self):
        """Test error object creation."""
        error = AccumulateError("Test error", ErrorCode.INVALID_TRANSACTION)
        assert error.message == "Test error"
        assert error.code == ErrorCode.INVALID_TRANSACTION
        assert str(error).startswith("[INVALID_TRANSACTION]")

    def test_specific_error_types(self):
        """Test specific error type creation."""
        validation_error = ValidationError("Invalid signature")
        assert validation_error.code == ErrorCode.INVALID_TRANSACTION

        network_error = NetworkError("Connection failed")
        assert network_error.code == ErrorCode.NETWORK_ERROR

    def test_error_serialization(self):
        """Test error dictionary conversion."""
        error = AccumulateError("Test", ErrorCode.NOT_FOUND, {"detail": "missing"})
        error_dict = error.to_dict()

        assert error_dict["code"] == ErrorCode.NOT_FOUND.value
        assert error_dict["message"] == "Test"
        assert error_dict["details"]["detail"] == "missing"

        # Test round-trip
        recreated = AccumulateError.from_dict(error_dict)
        assert recreated.message == error.message
        assert recreated.code == error.code


class TestClientConfiguration:
    """Test client configuration and creation."""

    def test_client_creation_with_string(self):
        """Test client creation with endpoint string."""
        client = AccumulateClient("https://example.com")
        assert client.endpoint == "https://example.com"

    def test_client_creation_with_config(self):
        """Test client creation with timeout."""
        client = AccumulateClient("http://localhost:8080", timeout=60.0)
        assert client.endpoint == "http://localhost:8080"

    def test_well_known_networks(self):
        """Test well-known network resolution."""
        from accumulate_client import mainnet_client, testnet_client, local_client

        mainnet = mainnet_client()
        testnet = testnet_client()
        local = local_client()

        assert "accumulatenetwork.io" in mainnet.endpoint
        assert "accumulatenetwork.io" in testnet.endpoint
        assert "127.0.0.1" in local.endpoint or "localhost" in local.endpoint

    def test_client_method_existence(self):
        """Test that client has all required API methods."""
        client = AccumulateClient("https://example.com")

        # Facade methods
        assert hasattr(client, 'query')
        assert hasattr(client, 'submit')
        assert hasattr(client, 'faucet')
        assert hasattr(client, 'execute')
        assert hasattr(client, 'execute_direct')
        assert hasattr(client, 'query_chain')
        assert hasattr(client, 'query_data')
        assert hasattr(client, 'query_directory')

        # Sub-clients
        assert hasattr(client, 'v2')
        assert hasattr(client, 'v3')


class TestIntegration:
    """Integration tests combining multiple components."""

    def test_url_encoding_roundtrip(self):
        """Test URL encoding and JSON serialization."""
        url = AccountUrl("acc://example.acme/tokens")

        # Should be able to include in JSON
        data = {"account": url, "amount": 1000}
        json_str = encode_json(data)

        assert "acc://example.acme/tokens" in json_str
        assert "1000" in json_str

    def test_error_handling_with_client(self):
        """Test error handling in client context."""
        client = AccumulateClient("https://invalid-endpoint-that-does-not-exist.com")

        # This should not raise during client creation
        assert client.endpoint == "https://invalid-endpoint-that-does-not-exist.com"

    def test_comprehensive_example(self):
        """Test a comprehensive usage example."""
        # Create client
        client = AccumulateClient("https://testnet.accumulatenetwork.io")

        # Create URLs
        identity = AccountUrl("acc://test.acme")
        tokens = identity.join("tokens")

        # Create transaction-like data
        tx_data = {
            "type": "sendTokens",
            "from": str(identity),
            "to": str(tokens),
            "amount": 1000000,  # 1 ACME
            "timestamp": datetime.now(timezone.utc).isoformat()
        }

        # Encode and hash
        json_str = encode_json(tx_data)
        tx_hash = hash_sha256_hex(json_str)

        # Verify results
        assert len(tx_hash) == 64
        assert "acc://test.acme" in json_str
        assert "sendTokens" in json_str


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
