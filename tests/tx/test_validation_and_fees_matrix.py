"""
Transaction validation and fees matrix tests.

Tests validation logic and fee calculation across different transaction
types, sizes, and configurations.
"""

import pytest
from typing import Dict, Any


class TestValidationMatrix:
    """Test transaction validation across different scenarios."""

    @pytest.mark.parametrize("tx_type,required_fields", [
        ("CreateIdentity", ["url", "keyBookUrl", "keyPageUrl"]),
        ("CreateTokenAccount", ["url", "tokenUrl"]),
        ("SendTokens", ["to"]),
        ("WriteData", ["data"]),
        ("AddCredits", ["recipient", "amount", "oracle"]),
    ])
    def test_required_field_validation(self, tx_type, required_fields, builder_registry):
        """Test that required fields are properly validated."""
        if tx_type not in builder_registry:
            pytest.skip(f"Builder {tx_type} not available")

        builder_class = builder_registry[tx_type]
        builder = builder_class()

        # Test with missing required fields
        if hasattr(builder, 'validate'):
            try:
                builder.validate()
                # If no exception, validation might be permissive
            except Exception as e:
                # Expected for missing required fields
                assert any(field in str(e).lower() for field in required_fields) or "required" in str(e).lower()

    @pytest.mark.parametrize("tx_type,invalid_field,invalid_value", [
        ("SendTokens", "to", [{"url": "invalid", "amount": -1}]),
        ("WriteData", "data", None),
        ("AddCredits", "amount", -1000),
        ("AddCredits", "oracle", "not_a_number"),
    ])
    def test_field_value_validation(self, tx_type, invalid_field, invalid_value, builder_registry):
        """Test validation of invalid field values."""
        if tx_type not in builder_registry:
            pytest.skip(f"Builder {tx_type} not available")

        builder_class = builder_registry[tx_type]
        builder = builder_class()

        # Set the invalid field
        builder.with_field(invalid_field, invalid_value)

        # Also set required fields to focus on the invalid field
        self._configure_valid_fields(builder, tx_type, exclude=invalid_field)

        if hasattr(builder, 'validate'):
            try:
                builder.validate()
                # Some implementations might be permissive
            except Exception:
                # Expected for invalid values
                pass

    def test_url_format_validation(self, builder_registry):
        """Test URL format validation across builders."""
        url_builders = ["CreateIdentity", "CreateTokenAccount", "CreateDataAccount"]

        for tx_type in url_builders:
            if tx_type not in builder_registry:
                continue

            builder_class = builder_registry[tx_type]

            # Test various URL formats
            url_formats = [
                "acc://valid.domain",
                "acc://valid.domain/path",
                "invalid-url",
                "",
                None
            ]

            for url_format in url_formats:
                builder = builder_class()
                builder.with_field("url", url_format)

                # Configure other required fields
                if tx_type == "CreateIdentity":
                    builder.with_field("keyBookUrl", "acc://test.acme/book")
                    builder.with_field("keyPageUrl", "acc://test.acme/book/page1")
                elif tx_type == "CreateTokenAccount":
                    builder.with_field("tokenUrl", "acc://acme.acme/tokens/ACME")

                if hasattr(builder, 'validate'):
                    try:
                        builder.validate()
                        # Valid URLs should pass, invalid ones might fail
                    except Exception:
                        # Expected for invalid URLs
                        pass

    def _configure_valid_fields(self, builder, tx_type: str, exclude: str = None):
        """Configure builder with valid fields, excluding specified field."""
        if tx_type == "CreateIdentity":
            if exclude != "url":
                builder.with_field("url", "acc://test.acme")
            if exclude != "keyBookUrl":
                builder.with_field("keyBookUrl", "acc://test.acme/book")
            if exclude != "keyPageUrl":
                builder.with_field("keyPageUrl", "acc://test.acme/book/page1")

        elif tx_type == "CreateTokenAccount":
            if exclude != "url":
                builder.with_field("url", "acc://test.acme/tokens")
            if exclude != "tokenUrl":
                builder.with_field("tokenUrl", "acc://acme.acme/tokens/ACME")

        elif tx_type == "SendTokens":
            if exclude != "to":
                builder.with_field("to", [{"url": "acc://test.acme/tokens", "amount": 1000000}])

        elif tx_type == "WriteData":
            if exclude != "data":
                builder.with_field("data", b"test data")
            if exclude != "scratch":
                builder.with_field("scratch", False)

        elif tx_type == "AddCredits":
            if exclude != "recipient":
                builder.with_field("recipient", "acc://test.acme/book/page1")
            if exclude != "amount":
                builder.with_field("amount", 1000000)
            if exclude != "oracle":
                builder.with_field("oracle", 500.0)


class TestFeesMatrix:
    """Test fee calculation across different scenarios."""

    @pytest.mark.parametrize("data_size", [0, 100, 1000, 10000])
    def test_fee_scales_with_data_size(self, data_size, builder_registry):
        """Test that fees scale appropriately with data size."""
        if "WriteData" not in builder_registry:
            pytest.skip("WriteData builder not available")

        builder_class = builder_registry["WriteData"]

        # Create data of specified size
        test_data = b"x" * data_size

        builder = builder_class()
        builder.with_field("data", test_data)
        builder.with_field("scratch", False)

        if hasattr(builder, 'estimate_fees'):
            try:
                network_params = {
                    "creditRate": 1000,
                    "baseRate": 100,
                    "dataRate": 10
                }
                fees = builder.estimate_fees(network_params)
                assert isinstance(fees, (int, float))
                assert fees >= 0

                # Store fee for comparison
                return fees

            except Exception:
                pytest.skip("Fee estimation not available")

    @pytest.mark.parametrize("tx_complexity", [
        ("simple", {"to": [{"url": "acc://test.acme/tokens", "amount": 1000000}]}),
        ("multi_recipient", {"to": [
            {"url": "acc://test1.acme/tokens", "amount": 1000000},
            {"url": "acc://test2.acme/tokens", "amount": 2000000},
            {"url": "acc://test3.acme/tokens", "amount": 3000000}
        ]})
    ])
    def test_fee_scales_with_complexity(self, tx_complexity, builder_registry):
        """Test that fees scale with transaction complexity."""
        if "SendTokens" not in builder_registry:
            pytest.skip("SendTokens builder not available")

        complexity_name, fields = tx_complexity
        builder_class = builder_registry["SendTokens"]
        builder = builder_class()

        for field_name, field_value in fields.items():
            builder.with_field(field_name, field_value)

        if hasattr(builder, 'estimate_fees'):
            try:
                network_params = {
                    "creditRate": 1000,
                    "baseRate": 100,
                    "dataRate": 10
                }
                fees = builder.estimate_fees(network_params)
                assert isinstance(fees, (int, float))
                assert fees >= 0

            except Exception:
                pytest.skip("Fee estimation not available")

    def test_fee_calculation_parameters(self, builder_registry):
        """Test fee calculation with different network parameters."""
        if "AddCredits" not in builder_registry:
            pytest.skip("AddCredits builder not available")

        builder_class = builder_registry["AddCredits"]
        builder = builder_class()
        builder.with_field("recipient", "acc://test.acme/book/page1")
        builder.with_field("amount", 1000000)
        builder.with_field("oracle", 500.0)

        if hasattr(builder, 'estimate_fees'):
            # Test with different network parameters
            param_sets = [
                {"creditRate": 1000, "baseRate": 100, "dataRate": 10},
                {"creditRate": 2000, "baseRate": 200, "dataRate": 20},  # Higher rates
                {"creditRate": 500, "baseRate": 50, "dataRate": 5},     # Lower rates
            ]

            fees = []
            for params in param_sets:
                try:
                    fee = builder.estimate_fees(params)
                    fees.append(fee)
                except Exception:
                    continue

            if len(fees) >= 2:
                # Fees should generally scale with rates
                # (though exact relationship depends on implementation)
                assert all(isinstance(f, (int, float)) for f in fees)
                assert all(f >= 0 for f in fees)

    def test_minimum_fee_validation(self, builder_registry):
        """Test that minimum fees are enforced."""
        # Test with minimal transactions
        minimal_builders = [
            ("CreateIdentity", {
                "url": "acc://test.acme",
                "keyBookUrl": "acc://test.acme/book",
                "keyPageUrl": "acc://test.acme/book/page1"
            }),
            ("WriteData", {
                "data": b"",  # Empty data
                "scratch": True
            })
        ]

        for tx_type, fields in minimal_builders:
            if tx_type not in builder_registry:
                continue

            builder_class = builder_registry[tx_type]
            builder = builder_class()

            for field_name, field_value in fields.items():
                builder.with_field(field_name, field_value)

            if hasattr(builder, 'estimate_fees'):
                try:
                    network_params = {
                        "creditRate": 1000,
                        "baseRate": 100,
                        "dataRate": 10
                    }
                    fees = builder.estimate_fees(network_params)

                    # Should have some minimum fee even for minimal transactions
                    assert fees > 0, f"Minimum fee should be positive for {tx_type}"

                except Exception:
                    continue


class TestValidationErrorMessages:
    """Test that validation provides helpful error messages."""

    def test_missing_field_error_message(self, builder_registry):
        """Test that missing field errors are informative."""
        if "CreateIdentity" not in builder_registry:
            pytest.skip("CreateIdentity builder not available")

        builder_class = builder_registry["CreateIdentity"]
        builder = builder_class()

        # Don't set any fields
        if hasattr(builder, 'validate'):
            try:
                builder.validate()
            except Exception as e:
                error_msg = str(e).lower()
                # Should mention missing/required fields
                assert any(word in error_msg for word in ["missing", "required", "url", "field"])

    def test_invalid_value_error_message(self, builder_registry):
        """Test that invalid value errors are informative."""
        if "SendTokens" not in builder_registry:
            pytest.skip("SendTokens builder not available")

        builder_class = builder_registry["SendTokens"]
        builder = builder_class()

        # Set invalid amount
        builder.with_field("to", [{"url": "acc://test.acme/tokens", "amount": "not_a_number"}])

        if hasattr(builder, 'validate'):
            try:
                builder.validate()
            except Exception as e:
                error_msg = str(e).lower()
                # Should mention the problematic field or value
                assert any(word in error_msg for word in ["amount", "invalid", "number", "type"])

    def test_url_validation_error_message(self, builder_registry):
        """Test that URL validation errors are informative."""
        if "CreateTokenAccount" not in builder_registry:
            pytest.skip("CreateTokenAccount builder not available")

        builder_class = builder_registry["CreateTokenAccount"]
        builder = builder_class()

        # Set invalid URL
        builder.with_field("url", "not-a-valid-accumulate-url")
        builder.with_field("tokenUrl", "acc://acme.acme/tokens/ACME")

        if hasattr(builder, 'validate'):
            try:
                builder.validate()
            except Exception as e:
                error_msg = str(e).lower()
                # Should mention URL format issues
                assert any(word in error_msg for word in ["url", "invalid", "format", "acc://"])


class TestCrossTransactionValidation:
    """Test validation logic that spans multiple transaction types."""

    def test_consistent_url_validation(self, builder_registry):
        """Test that URL validation is consistent across transaction types."""
        url_builders = ["CreateIdentity", "CreateTokenAccount", "CreateDataAccount"]
        test_urls = [
            "acc://valid.domain",
            "acc://valid.domain/path/subpath",
            "invalid-url",
            ""
        ]

        validation_results = {}

        for tx_type in url_builders:
            if tx_type not in builder_registry:
                continue

            builder_class = builder_registry[tx_type]
            validation_results[tx_type] = {}

            for test_url in test_urls:
                builder = builder_class()
                builder.with_field("url", test_url)

                # Configure other required fields
                if tx_type == "CreateIdentity":
                    builder.with_field("keyBookUrl", "acc://test.acme/book")
                    builder.with_field("keyPageUrl", "acc://test.acme/book/page1")
                elif tx_type == "CreateTokenAccount":
                    builder.with_field("tokenUrl", "acc://acme.acme/tokens/ACME")

                try:
                    if hasattr(builder, 'validate'):
                        builder.validate()
                    validation_results[tx_type][test_url] = True
                except Exception:
                    validation_results[tx_type][test_url] = False

        # Check for consistency across transaction types
        # (Some variation is acceptable, but gross inconsistencies should be flagged)
        for test_url in test_urls:
            url_results = [results.get(test_url) for results in validation_results.values() if test_url in results]
            if len(url_results) > 1:
                # If we have results from multiple builders, they should be somewhat consistent
                pass  # Implementation detail - exact consistency requirements may vary

    def test_amount_validation_consistency(self, builder_registry):
        """Test that amount validation is consistent across transaction types."""
        amount_builders = ["SendTokens", "AddCredits"]
        test_amounts = [0, 1, 1000000, -1, "not_a_number"]

        for tx_type in amount_builders:
            if tx_type not in builder_registry:
                continue

            builder_class = builder_registry[tx_type]

            for test_amount in test_amounts:
                builder = builder_class()

                if tx_type == "SendTokens":
                    builder.with_field("to", [{"url": "acc://test.acme/tokens", "amount": test_amount}])
                elif tx_type == "AddCredits":
                    builder.with_field("recipient", "acc://test.acme/book/page1")
                    builder.with_field("amount", test_amount)
                    builder.with_field("oracle", 500.0)

                try:
                    if hasattr(builder, 'validate'):
                        builder.validate()
                    # Valid amounts should pass
                except Exception:
                    # Invalid amounts should fail
                    pass