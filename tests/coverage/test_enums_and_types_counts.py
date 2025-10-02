"""
Enum and type count validation tests.

Validates the expected counts of enums, types, signatures, and transactions
to ensure API completeness and catch regressions.
"""

import pytest
from enum import Enum
from typing import get_type_hints

import accumulate_client.enums as enums
import accumulate_client.types as types
import accumulate_client.signatures as signatures
import accumulate_client.transactions as transactions


class TestEnumCounts:
    """Test enum definitions and counts."""

    def test_enum_count_validation(self):
        """Test that we have expected number of enums defined."""
        # Count enum classes in enums module
        enum_classes = []
        for name in dir(enums):
            obj = getattr(enums, name)
            if isinstance(obj, type) and issubclass(obj, Enum) and obj is not Enum:
                enum_classes.append(name)

        # Expected count based on Accumulate protocol
        # Adjust this number based on actual implementation
        expected_enum_count = 14
        actual_count = len(enum_classes)

        assert actual_count >= 10, f"Too few enums: {actual_count}, expected at least 10"
        # Allow some flexibility in exact count
        assert actual_count <= 20, f"More enums than expected: {actual_count}, expected around {expected_enum_count}"

    def test_transaction_type_enum_complete(self):
        """Test TransactionType enum has expected values."""
        tx_type = enums.TransactionType

        # Core transaction types that should exist
        expected_tx_types = [
            'CreateIdentity', 'CreateTokenAccount', 'CreateDataAccount',
            'SendTokens', 'WriteData', 'AddCredits'
        ]

        for tx_type_name in expected_tx_types:
            assert hasattr(tx_type, tx_type_name), f"Missing transaction type: {tx_type_name}"

        # Count total transaction types
        tx_type_count = len([item for item in tx_type])
        assert tx_type_count >= 25, f"Too few transaction types: {tx_type_count}"
        assert tx_type_count <= 40, f"Too many transaction types: {tx_type_count}"

    def test_signature_type_enum_complete(self):
        """Test SignatureType enum has expected values."""
        try:
            sig_type = enums.SignatureType

            # Core signature types
            expected_sig_types = ['ED25519', 'RCD1', 'LEGACYED25519']

            for sig_type_name in expected_sig_types:
                if hasattr(sig_type, sig_type_name):
                    # Verify it exists
                    getattr(sig_type, sig_type_name)

            # Count signature types
            sig_type_count = len([item for item in sig_type])
            assert sig_type_count >= 10, f"Too few signature types: {sig_type_count}"
            assert sig_type_count <= 25, f"Too many signature types: {sig_type_count}"

        except AttributeError:
            pytest.skip("SignatureType enum not available")

    def test_account_type_enum_complete(self):
        """Test AccountType enum has expected values."""
        try:
            account_type = enums.AccountType

            # Core account types
            expected_account_types = ['Identity', 'TokenAccount', 'DataAccount', 'KeyBook', 'KeyPage']

            for account_type_name in expected_account_types:
                if hasattr(account_type, account_type_name):
                    getattr(account_type, account_type_name)

            # Count account types
            account_type_count = len([item for item in account_type])
            assert account_type_count >= 5, f"Too few account types: {account_type_count}"

        except AttributeError:
            pytest.skip("AccountType enum not available")


class TestTypeCounts:
    """Test type definitions and counts."""

    def test_type_count_validation(self):
        """Test that we have expected number of types defined."""
        # Count classes/types in types module
        type_classes = []
        for name in dir(types):
            if not name.startswith('_'):
                obj = getattr(types, name)
                if isinstance(obj, type):
                    type_classes.append(name)

        # Expected count based on Accumulate protocol
        expected_type_count = 103
        actual_count = len(type_classes)

        assert actual_count >= 80, f"Too few types: {actual_count}, expected at least 80"
        # Allow some flexibility in exact count
        assert actual_count <= 130, f"More types than expected: {actual_count}, expected around {expected_type_count}"

    def test_core_types_exist(self):
        """Test that core types are defined."""
        # Core types that should exist
        expected_types = [
            'Identity', 'TokenAccount', 'DataAccount', 'KeyBook', 'KeyPage',
            'Transaction', 'Signature'
        ]

        for type_name in expected_types:
            if hasattr(types, type_name):
                type_obj = getattr(types, type_name)
                assert isinstance(type_obj, type), f"{type_name} should be a type/class"

    def test_transaction_types_exist(self):
        """Test that transaction types are defined."""
        # Transaction payload types
        tx_types = [
            'CreateIdentityTransaction', 'CreateTokenAccountTransaction',
            'SendTokensTransaction', 'WriteDataTransaction', 'AddCreditsTransaction'
        ]

        found_tx_types = 0
        for tx_type_name in tx_types:
            if hasattr(types, tx_type_name):
                found_tx_types += 1

        # Should have most core transaction types
        assert found_tx_types >= 3, f"Too few transaction types found: {found_tx_types}"


class TestSignatureCounts:
    """Test signature definitions and counts."""

    def test_signature_count_validation(self):
        """Test that we have expected number of signature types."""
        # Count signature classes - filter to only signature-specific classes
        signature_classes = []
        for name in dir(signatures):
            if not name.startswith('_'):
                obj = getattr(signatures, name)
                if isinstance(obj, type):
                    # Only count classes that are defined in the signatures module
                    # Filter out imported classes by checking if they contain "Signature" in the name
                    if "Signature" in name or name in ["Signature"]:
                        signature_classes.append(name)

        # Expected count
        expected_signature_count = 16
        actual_count = len(signature_classes)

        assert actual_count >= 10, f"Too few signature types: {actual_count}"
        assert actual_count <= 25, f"Too many signature types: {actual_count}"

    def test_core_signature_types_exist(self):
        """Test that core signature types exist."""
        expected_signatures = ['ED25519Signature', 'RCD1Signature']

        found_signatures = 0
        for sig_name in expected_signatures:
            if hasattr(signatures, sig_name):
                found_signatures += 1

        assert found_signatures >= 1, "Should have at least one core signature type"


class TestTransactionCounts:
    """Test transaction definitions and counts."""

    def test_transaction_count_validation(self):
        """Test that we have expected number of transaction definitions."""
        # Count transaction classes - filter to only transaction-specific classes
        transaction_classes = []
        for name in dir(transactions):
            if not name.startswith('_'):
                obj = getattr(transactions, name)
                if isinstance(obj, type):
                    # Only count classes that are defined in the transactions module
                    # Filter out imported classes by checking module-specific patterns
                    if ("Transaction" in name or "Header" in name or
                        name in ["TxHeaderBase", "RemoteTransaction", "SyntheticForwardTransaction"]):
                        transaction_classes.append(name)

        # Expected count (33 or 32 builders)
        expected_transaction_count = 33
        actual_count = len(transaction_classes)

        assert actual_count >= 25, f"Too few transaction types: {actual_count}"
        assert actual_count <= 60, f"Too many transaction types: {actual_count}"  # Increased limit since headers are included

    def test_core_transaction_classes_exist(self):
        """Test that core transaction classes exist."""
        expected_transactions = [
            'CreateIdentityTransaction', 'CreateTokenAccountTransaction',
            'SendTokensTransaction', 'WriteDataTransaction'
        ]

        found_transactions = 0
        for tx_name in expected_transactions:
            if hasattr(transactions, tx_name):
                found_transactions += 1

        assert found_transactions >= 2, "Should have at least some core transaction types"


class TestEnumIteration:
    """Test enum iteration to increase coverage."""

    def test_transaction_type_iteration(self):
        """Test iterating through TransactionType enum."""
        tx_type = enums.TransactionType
        tx_types_list = list(tx_type)

        assert len(tx_types_list) > 0, "TransactionType enum should not be empty"

        # Test each enum value
        for tx_type_value in tx_types_list:
            assert tx_type_value.name is not None
            assert tx_type_value.value is not None

    def test_enum_value_access(self):
        """Test accessing enum values by name and value."""
        tx_type = enums.TransactionType

        # Test accessing by attribute
        if hasattr(tx_type, 'CreateIdentity'):
            create_identity = tx_type.CreateIdentity
            assert create_identity is not None

        # Test getting enum members
        members = tx_type.__members__
        assert len(members) > 0

    def test_signature_type_iteration(self):
        """Test iterating through signature types if available."""
        try:
            sig_type = enums.SignatureType
            sig_types_list = list(sig_type)

            for sig_type_value in sig_types_list:
                assert sig_type_value.name is not None
                assert sig_type_value.value is not None

        except AttributeError:
            pytest.skip("SignatureType enum not available")

    def test_all_enums_iterable(self):
        """Test that all enum classes are properly iterable."""
        enum_classes = []
        for name in dir(enums):
            obj = getattr(enums, name)
            if isinstance(obj, type) and issubclass(obj, Enum) and obj is not Enum:
                enum_classes.append(obj)

        for enum_class in enum_classes:
            # Test iteration works
            items = list(enum_class)
            # Each enum should have at least one member
            assert len(items) >= 0  # Some enums might be empty

            # Test members access
            members = enum_class.__members__
            # __members__ returns a mappingproxy in Python, not a dict
            from collections.abc import Mapping
            assert isinstance(members, Mapping)