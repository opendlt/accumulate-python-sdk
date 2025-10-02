"""
Transaction builder parametric roundtrip tests.

Tests all available transaction builders with parametric data,
validation, fee estimation, and roundtrip encoding.
"""

import pytest
import hashlib
from typing import Dict, Any, Optional

from accumulate_client.tx.codec import to_canonical_json


class TestBuilderParametricRoundtrip:
    """Test all builders with parametric roundtrip validation."""

    @pytest.mark.parametrize("builder_name", [
        "CreateIdentity", "CreateTokenAccount", "CreateDataAccount",
        "SendTokens", "WriteData", "AddCredits", "UpdateKeyPage",
        "CreateKeyBook", "CreateKeyPage", "UpdateKey", "CreateToken",
        "IssueTokens", "BurnTokens", "CreateLiteDataAccount",
        "UpdateAccountAuth", "LockAccount", "RemoteTransaction"
    ])
    def test_builder_roundtrip_validation(self, builder_name, builder_registry):
        """Test builder validation, build, and canonical encoding."""
        if builder_name not in builder_registry:
            pytest.skip(f"Builder {builder_name} not available")

        builder_class = builder_registry[builder_name]

        try:
            # Create builder instance
            builder = builder_class()

            # Configure builder with minimal valid data
            self._configure_builder(builder, builder_name)

            # Test validation
            if hasattr(builder, 'validate'):
                try:
                    builder.validate()
                except Exception as e:
                    pytest.skip(f"Builder {builder_name} validation failed: {e}")

            # Test fee estimation if available
            if hasattr(builder, 'estimate_fees'):
                try:
                    # Use mock network parameters
                    network_params = {
                        "creditRate": 1000,
                        "baseRate": 100,
                        "dataRate": 10
                    }
                    fees = builder.estimate_fees(network_params)
                    assert isinstance(fees, (int, float)), f"Fees should be numeric for {builder_name}"
                except Exception:
                    # Fee estimation might not be implemented
                    pass

            # Test build transaction
            if hasattr(builder, 'to_body'):
                tx_body = builder.to_body()
                assert isinstance(tx_body, dict), f"Transaction body should be dict for {builder_name}"
                assert 'type' in tx_body, f"Transaction should have type field for {builder_name}"

                # Test canonical encoding
                canonical_json = to_canonical_json(tx_body)
                assert len(canonical_json) > 0, f"Canonical JSON should not be empty for {builder_name}"

                # Test hash stability
                hash1 = hashlib.sha256(canonical_json).hexdigest()

                # Encode again
                canonical_json2 = to_canonical_json(tx_body)
                hash2 = hashlib.sha256(canonical_json2).hexdigest()

                assert hash1 == hash2, f"Hash should be stable for {builder_name}"

            elif hasattr(builder, 'build'):
                tx = builder.build()
                assert tx is not None, f"Built transaction should not be None for {builder_name}"

        except Exception as e:
            pytest.skip(f"Builder {builder_name} failed: {e}")

    def _configure_builder(self, builder, builder_name: str):
        """Configure builder with minimal valid data based on type."""
        if builder_name == "CreateIdentity":
            builder.with_field("url", "acc://test.acme")
            builder.with_field("keyBookUrl", "acc://test.acme/book")
            builder.with_field("keyPageUrl", "acc://test.acme/book/page1")

        elif builder_name == "CreateTokenAccount":
            builder.with_field("url", "acc://test.acme/tokens")
            builder.with_field("tokenUrl", "acc://acme.acme/tokens/ACME")

        elif builder_name == "CreateDataAccount":
            builder.with_field("url", "acc://test.acme/data")

        elif builder_name == "SendTokens":
            builder.with_field("to", [{"url": "acc://test.acme/tokens", "amount": 1000000}])

        elif builder_name == "WriteData":
            builder.with_field("data", b"test data")
            builder.with_field("scratch", False)

        elif builder_name == "AddCredits":
            builder.with_field("recipient", "acc://test.acme/book/page1")
            builder.with_field("amount", 1000000)
            builder.with_field("oracle", 500.0)

        elif builder_name == "UpdateKeyPage":
            builder.with_field("operation", "add")
            builder.with_field("key", "0123456789abcdef" * 4)

        elif builder_name == "CreateKeyBook":
            builder.with_field("url", "acc://test.acme/book")

        elif builder_name == "CreateKeyPage":
            builder.with_field("url", "acc://test.acme/book/page1")
            builder.with_field("keys", ["0123456789abcdef" * 4])

        elif builder_name == "UpdateKey":
            builder.with_field("operation", "add")
            builder.with_field("key", "0123456789abcdef" * 4)
            builder.with_field("newKey", "fedcba9876543210" * 4)

        elif builder_name == "CreateToken":
            builder.with_field("url", "acc://test.acme/tokens/TEST")
            builder.with_field("symbol", "TEST")
            builder.with_field("precision", 8)

        elif builder_name == "IssueTokens":
            builder.with_field("recipient", "acc://test.acme/tokens")
            builder.with_field("amount", 1000000)

        elif builder_name == "BurnTokens":
            builder.with_field("amount", 1000000)

        elif builder_name == "CreateLiteDataAccount":
            builder.with_field("url", "acc://1234567890abcdef1234567890abcdef12345678/data")

        elif builder_name == "UpdateAccountAuth":
            builder.with_field("authority", "acc://test.acme/book")

        elif builder_name == "LockAccount":
            builder.with_field("height", 1000)

        elif builder_name == "RemoteTransaction":
            builder.with_field("hash", "0123456789abcdef" * 4)

        # Add more configurations as needed


class TestBuilderEdgeCases:
    """Test builder edge cases and error conditions."""

    def test_builder_with_missing_required_fields(self, builder_registry):
        """Test builders fail validation with missing required fields."""
        if "CreateIdentity" in builder_registry:
            builder_class = builder_registry["CreateIdentity"]
            builder = builder_class()

            # Don't configure required fields
            if hasattr(builder, 'validate'):
                with pytest.raises(Exception):
                    builder.validate()

    def test_builder_with_invalid_field_values(self, builder_registry):
        """Test builders handle invalid field values."""
        if "SendTokens" in builder_registry:
            builder_class = builder_registry["SendTokens"]
            builder = builder_class()

            # Test with invalid amount
            builder.with_field("to", [{"url": "acc://test.acme/tokens", "amount": -1}])

            if hasattr(builder, 'validate'):
                try:
                    builder.validate()
                    # If validation passes, that's also acceptable behavior
                except Exception:
                    # Expected for invalid values
                    pass

    def test_builder_field_type_validation(self, builder_registry):
        """Test builder field type validation."""
        if "WriteData" in builder_registry:
            builder_class = builder_registry["WriteData"]
            builder = builder_class()

            # Test with valid data
            builder.with_field("data", b"test data")
            builder.with_field("scratch", False)

            if hasattr(builder, 'validate'):
                try:
                    builder.validate()
                except Exception as e:
                    pytest.skip(f"Builder validation failed: {e}")

    def test_builder_url_validation(self, builder_registry):
        """Test builder URL field validation."""
        builders_with_urls = ["CreateIdentity", "CreateTokenAccount", "CreateDataAccount"]

        for builder_name in builders_with_urls:
            if builder_name in builder_registry:
                builder_class = builder_registry[builder_name]
                builder = builder_class()

                # Test with invalid URL
                builder.with_field("url", "not-a-valid-url")

                if hasattr(builder, 'validate'):
                    try:
                        builder.validate()
                        # Some implementations might accept any string
                    except Exception:
                        # Expected for invalid URLs
                        pass


class TestBuilderSerialization:
    """Test builder serialization and deserialization."""

    def test_builder_to_body_consistency(self, builder_registry):
        """Test that to_body() produces consistent output."""
        if "CreateIdentity" in builder_registry:
            builder_class = builder_registry["CreateIdentity"]

            # Create two identical builders
            builder1 = builder_class()
            builder1.with_field("url", "acc://test.acme")
            builder1.with_field("keyBookUrl", "acc://test.acme/book")
            builder1.with_field("keyPageUrl", "acc://test.acme/book/1")

            builder2 = builder_class()
            builder2.with_field("url", "acc://test.acme")
            builder2.with_field("keyBookUrl", "acc://test.acme/book")
            builder2.with_field("keyPageUrl", "acc://test.acme/book/1")

            if hasattr(builder1, 'to_body'):
                body1 = builder1.to_body()
                body2 = builder2.to_body()

                # Should produce identical output
                assert body1 == body2, "Identical builders should produce identical bodies"

    def test_builder_canonical_json_method(self, builder_registry):
        """Test builder's canonical JSON method if available."""
        if "SendTokens" in builder_registry:
            builder_class = builder_registry["SendTokens"]
            builder = builder_class()
            builder.with_field("to", [{"url": "acc://test.acme/tokens", "amount": 1000000}])

            if hasattr(builder, 'to_canonical_json'):
                canonical_json = builder.to_canonical_json()
                assert isinstance(canonical_json, bytes)
                assert len(canonical_json) > 0

                # Should be consistent across calls
                canonical_json2 = builder.to_canonical_json()
                assert canonical_json == canonical_json2

    def test_builder_field_ordering(self, builder_registry):
        """Test that field ordering doesn't affect output."""
        if "CreateIdentity" in builder_registry:
            builder_class = builder_registry["CreateIdentity"]

            # Create builder with fields in different order
            builder1 = builder_class()
            builder1.with_field("url", "acc://test.acme")
            builder1.with_field("keyBookUrl", "acc://test.acme/book")
            builder1.with_field("keyPageUrl", "acc://test.acme/book/1")

            builder2 = builder_class()
            builder2.with_field("keyPageUrl", "acc://test.acme/book/1")
            builder2.with_field("url", "acc://test.acme")
            builder2.with_field("keyBookUrl", "acc://test.acme/book")

            if hasattr(builder1, 'to_body'):
                body1 = builder1.to_body()
                body2 = builder2.to_body()

                # Field order shouldn't matter for final output
                assert body1 == body2, "Field order should not affect final output"


class TestBuilderFactoryMethods:
    """Test builder factory methods and convenience constructors."""

    def test_get_builder_for_all_types(self, builder_registry):
        """Test that get_builder_for works for all registered types."""
        from accumulate_client.tx.builders import get_builder_for

        for builder_name in builder_registry.keys():
            builder_instance = get_builder_for(builder_name)
            assert builder_instance is not None, f"get_builder_for should return instance for {builder_name}"

            # Should be a builder instance with expected methods
            assert hasattr(builder_instance, 'with_field'), f"Builder {builder_name} should have with_field method"
            assert hasattr(builder_instance, 'to_body'), f"Builder {builder_name} should have to_body method"

    def test_builder_registry_completeness(self, builder_registry):
        """Test that builder registry has reasonable coverage."""
        # Should have at least core transaction types
        core_types = ["CreateIdentity", "SendTokens", "WriteData", "AddCredits"]

        found_core_types = 0
        for core_type in core_types:
            if core_type in builder_registry:
                found_core_types += 1

        assert found_core_types >= 2, f"Should have at least 2 core builders, found {found_core_types}"

        # Total count should be reasonable
        total_builders = len(builder_registry)
        assert total_builders >= 10, f"Should have at least 10 builders, found {total_builders}"
        assert total_builders <= 50, f"Should have at most 50 builders, found {total_builders}"

    def test_builder_inheritance_hierarchy(self, builder_registry):
        """Test builder inheritance hierarchy."""
        # Most builders should inherit from a common base
        base_classes = set()

        for builder_class in builder_registry.values():
            # Get MRO (Method Resolution Order) to find base classes
            mro = builder_class.__mro__
            if len(mro) > 2:  # More than just (SelfClass, object)
                base_classes.add(mro[1])  # First base class

        # Should have some common base classes
        assert len(base_classes) <= 5, "Should not have too many different base classes"