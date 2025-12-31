"""
Unit tests for operations module (Phase 5).

Tests key page operations, account auth operations, and helper functions.
"""

import pytest
from pydantic import ValidationError

from accumulate_client.operations import (
    # Key spec types
    KeySpecParams,
    KeySpec,
    # Key page operations
    AddKeyOperation,
    RemoveKeyOperation,
    UpdateKeyOperation,
    SetThresholdKeyPageOperation,
    SetRejectThresholdKeyPageOperation,
    SetResponseThresholdKeyPageOperation,
    UpdateAllowedKeyPageOperation,
    KeyPageOperation,
    # Key page helpers
    create_key_page_operation,
    parse_key_page_operation,
    validate_key_page_operations,
    # Account auth operations
    EnableAccountAuthOperation,
    DisableAccountAuthOperation,
    AddAccountAuthorityOperation,
    RemoveAccountAuthorityOperation,
    AccountAuthOperation,
    # Account auth helpers
    create_account_auth_operation,
    parse_account_auth_operation,
    validate_account_auth_operations,
    # Convenience functions
    enable_authority,
    disable_authority,
    add_authority,
    remove_authority,
    # Network maintenance
    PendingTransactionGCOperation,
)
from accumulate_client.enums import KeyPageOperationType, AccountAuthOperationType, TransactionType


# =============================================================================
# KeySpecParams Tests
# =============================================================================

class TestKeySpecParams:
    """Tests for KeySpecParams class."""

    def test_create_with_key_hash(self):
        """Test creating KeySpecParams with key hash."""
        key_hash = bytes(32)
        params = KeySpecParams(key_hash=key_hash)
        assert params.key_hash == key_hash
        assert params.delegate is None

    def test_create_with_hex_string(self):
        """Test creating KeySpecParams with hex string."""
        hex_str = "ab" * 32
        params = KeySpecParams(key_hash=hex_str)
        assert params.key_hash == bytes.fromhex(hex_str)

    def test_create_with_delegate(self):
        """Test creating KeySpecParams with delegate."""
        params = KeySpecParams(
            key_hash=bytes(32),
            delegate="acc://delegate.acme/book"
        )
        assert params.delegate == "acc://delegate.acme/book"

    def test_delegate_auto_prefix(self):
        """Test delegate gets acc:// prefix."""
        params = KeySpecParams(
            key_hash=bytes(32),
            delegate="delegate.acme/book"
        )
        assert params.delegate == "acc://delegate.acme/book"

    def test_from_key_hash_factory(self):
        """Test from_key_hash factory method."""
        params = KeySpecParams.from_key_hash("ab" * 32, delegate="acc://test.acme")
        assert len(params.key_hash) == 32
        assert params.delegate == "acc://test.acme"

    def test_from_public_key_factory(self):
        """Test from_public_key factory method."""
        public_key = b"test_public_key_32_bytes_exactly"
        params = KeySpecParams.from_public_key(public_key)
        assert params.key_hash is not None
        assert len(params.key_hash) == 32  # SHA-256 hash

    def test_to_dict(self):
        """Test to_dict serialization."""
        params = KeySpecParams(
            key_hash=bytes.fromhex("ab" * 32),
            delegate="acc://test.acme"
        )
        d = params.to_dict()
        assert d["keyHash"] == "ab" * 32
        assert d["delegate"] == "acc://test.acme"

    def test_matches(self):
        """Test matches method."""
        params1 = KeySpecParams(key_hash=bytes(32))
        params2 = KeySpecParams(key_hash=bytes(32))
        params3 = KeySpecParams(key_hash=bytes.fromhex("ab" * 32))

        assert params1.matches(params2)
        assert not params1.matches(params3)

    def test_equality(self):
        """Test equality comparison."""
        params1 = KeySpecParams(key_hash=bytes(32))
        params2 = KeySpecParams(key_hash=bytes(32))
        assert params1 == params2


class TestKeySpec:
    """Tests for KeySpec class."""

    def test_create_basic(self):
        """Test creating KeySpec."""
        spec = KeySpec(public_key_hash=bytes(32))
        assert spec.public_key_hash == bytes(32)
        assert spec.last_used_on == 0

    def test_create_with_last_used(self):
        """Test creating KeySpec with last_used_on."""
        spec = KeySpec(public_key_hash=bytes(32), last_used_on=12345)
        assert spec.last_used_on == 12345

    def test_from_public_key(self):
        """Test from_public_key factory."""
        spec = KeySpec.from_public_key(b"test_key", last_used_on=100)
        assert len(spec.public_key_hash) == 32
        assert spec.last_used_on == 100

    def test_to_params(self):
        """Test conversion to KeySpecParams."""
        spec = KeySpec(public_key_hash=bytes(32), delegate="acc://test.acme")
        params = spec.to_params()
        assert params.key_hash == bytes(32)
        assert params.delegate == "acc://test.acme"

    def test_to_dict(self):
        """Test to_dict serialization."""
        spec = KeySpec(
            public_key_hash=bytes.fromhex("ab" * 32),
            last_used_on=100,
            delegate="acc://test.acme"
        )
        d = spec.to_dict()
        assert d["publicKeyHash"] == "ab" * 32
        assert d["lastUsedOn"] == 100
        assert d["delegate"] == "acc://test.acme"


# =============================================================================
# Key Page Operation Tests
# =============================================================================

class TestAddKeyOperation:
    """Tests for AddKeyOperation."""

    def test_create_basic(self):
        """Test creating AddKeyOperation."""
        op = AddKeyOperation.create(key_hash=bytes(32))
        assert op.type == "add"
        assert op.operation_type == KeyPageOperationType.ADD
        assert op.entry.key_hash == bytes(32)

    def test_create_with_delegate(self):
        """Test creating with delegate."""
        op = AddKeyOperation.create(
            key_hash="ab" * 32,
            delegate="acc://delegate.acme"
        )
        assert op.entry.delegate == "acc://delegate.acme"

    def test_from_public_key(self):
        """Test from_public_key factory."""
        op = AddKeyOperation.from_public_key(b"test_key")
        assert op.entry.key_hash is not None

    def test_to_dict(self):
        """Test to_dict serialization."""
        op = AddKeyOperation.create(key_hash="ab" * 32)
        d = op.to_dict()
        assert d["type"] == "add"
        assert "entry" in d
        assert d["entry"]["keyHash"] == "ab" * 32

    def test_validate_for_submission(self):
        """Test validation."""
        op = AddKeyOperation.create(key_hash=bytes(32))
        errors = op.validate_for_submission()
        assert len(errors) == 0

    def test_validate_missing_key_hash(self):
        """Test validation with missing key hash."""
        op = AddKeyOperation(entry=KeySpecParams())
        errors = op.validate_for_submission()
        assert len(errors) > 0
        assert "key_hash" in errors[0]


class TestRemoveKeyOperation:
    """Tests for RemoveKeyOperation."""

    def test_create_basic(self):
        """Test creating RemoveKeyOperation."""
        op = RemoveKeyOperation.create(key_hash=bytes(32))
        assert op.type == "remove"
        assert op.operation_type == KeyPageOperationType.REMOVE

    def test_to_dict(self):
        """Test to_dict serialization."""
        op = RemoveKeyOperation.create(key_hash="cd" * 32)
        d = op.to_dict()
        assert d["type"] == "remove"
        assert d["entry"]["keyHash"] == "cd" * 32


class TestUpdateKeyOperation:
    """Tests for UpdateKeyOperation."""

    def test_create_basic(self):
        """Test creating UpdateKeyOperation."""
        op = UpdateKeyOperation.create(
            old_key_hash=bytes(32),
            new_key_hash=bytes.fromhex("ab" * 32)
        )
        assert op.type == "update"
        assert op.operation_type == KeyPageOperationType.UPDATE
        assert op.old_entry.key_hash == bytes(32)
        assert op.new_entry.key_hash == bytes.fromhex("ab" * 32)

    def test_from_public_keys(self):
        """Test from_public_keys factory."""
        op = UpdateKeyOperation.from_public_keys(
            old_public_key=b"old_key",
            new_public_key=b"new_key"
        )
        assert op.old_entry.key_hash is not None
        assert op.new_entry.key_hash is not None

    def test_to_dict(self):
        """Test to_dict serialization."""
        op = UpdateKeyOperation.create(
            old_key_hash="00" * 32,
            new_key_hash="ff" * 32
        )
        d = op.to_dict()
        assert d["type"] == "update"
        assert d["oldEntry"]["keyHash"] == "00" * 32
        assert d["newEntry"]["keyHash"] == "ff" * 32


class TestSetThresholdKeyPageOperation:
    """Tests for SetThresholdKeyPageOperation."""

    def test_create_basic(self):
        """Test creating SetThresholdKeyPageOperation."""
        op = SetThresholdKeyPageOperation.create(threshold=2)
        assert op.type == "setThreshold"
        assert op.threshold == 2
        assert op.operation_type == KeyPageOperationType.SETTHRESHOLD

    def test_create_invalid_threshold(self):
        """Test creating with invalid threshold."""
        with pytest.raises(ValueError):
            SetThresholdKeyPageOperation.create(threshold=0)

    def test_to_dict(self):
        """Test to_dict serialization."""
        op = SetThresholdKeyPageOperation.create(threshold=3)
        d = op.to_dict()
        assert d["type"] == "setThreshold"
        assert d["threshold"] == 3


class TestSetRejectThresholdKeyPageOperation:
    """Tests for SetRejectThresholdKeyPageOperation."""

    def test_create_basic(self):
        """Test creating SetRejectThresholdKeyPageOperation."""
        op = SetRejectThresholdKeyPageOperation.create(threshold=1)
        assert op.type == "setRejectThreshold"
        assert op.threshold == 1

    def test_to_dict(self):
        """Test to_dict serialization."""
        op = SetRejectThresholdKeyPageOperation.create(threshold=2)
        d = op.to_dict()
        assert d["type"] == "setRejectThreshold"


class TestSetResponseThresholdKeyPageOperation:
    """Tests for SetResponseThresholdKeyPageOperation."""

    def test_create_basic(self):
        """Test creating SetResponseThresholdKeyPageOperation."""
        op = SetResponseThresholdKeyPageOperation.create(threshold=0)
        assert op.type == "setResponseThreshold"
        assert op.threshold == 0


class TestUpdateAllowedKeyPageOperation:
    """Tests for UpdateAllowedKeyPageOperation."""

    def test_create_with_allow(self):
        """Test creating with allow list."""
        op = UpdateAllowedKeyPageOperation.create(
            allow=[TransactionType.SENDTOKENS, TransactionType.ADDCREDITS]
        )
        assert op.type == "updateAllowed"
        assert len(op.allow) == 2
        assert TransactionType.SENDTOKENS in op.allow

    def test_create_with_deny(self):
        """Test creating with deny list."""
        op = UpdateAllowedKeyPageOperation.create(
            deny=[TransactionType.UPDATEKEYPAGE]
        )
        assert len(op.deny) == 1

    def test_allow_only(self):
        """Test allow_only factory."""
        op = UpdateAllowedKeyPageOperation.allow_only(
            TransactionType.SENDTOKENS,
            TransactionType.ADDCREDITS
        )
        assert len(op.allow) == 2
        assert op.deny is None

    def test_deny_only(self):
        """Test deny_only factory."""
        op = UpdateAllowedKeyPageOperation.deny_only(TransactionType.UPDATEKEYPAGE)
        assert len(op.deny) == 1
        assert op.allow is None

    def test_create_with_int_values(self):
        """Test creating with integer values."""
        op = UpdateAllowedKeyPageOperation.create(allow=[3, 14])  # SENDTOKENS=3, ADDCREDITS=14
        assert TransactionType.SENDTOKENS in op.allow
        assert TransactionType.ADDCREDITS in op.allow

    def test_to_dict(self):
        """Test to_dict serialization."""
        op = UpdateAllowedKeyPageOperation.create(
            allow=[TransactionType.SENDTOKENS]
        )
        d = op.to_dict()
        assert d["type"] == "updateAllowed"
        assert "allow" in d


# =============================================================================
# Key Page Operation Factory/Parser Tests
# =============================================================================

class TestKeyPageOperationFactories:
    """Tests for key page operation factory functions."""

    def test_create_by_enum(self):
        """Test create_key_page_operation with enum."""
        op = create_key_page_operation(
            KeyPageOperationType.ADD,
            entry=KeySpecParams(key_hash=bytes(32))
        )
        assert isinstance(op, AddKeyOperation)

    def test_create_by_string(self):
        """Test create_key_page_operation with string."""
        op = create_key_page_operation(
            "ADD",
            entry=KeySpecParams(key_hash=bytes(32))
        )
        assert isinstance(op, AddKeyOperation)

    def test_create_by_int(self):
        """Test create_key_page_operation with int."""
        op = create_key_page_operation(
            3,  # ADD
            entry=KeySpecParams(key_hash=bytes(32))
        )
        assert isinstance(op, AddKeyOperation)

    def test_parse_add_operation(self):
        """Test parse_key_page_operation for add."""
        data = {
            "type": "add",
            "entry": {"keyHash": "ab" * 32}
        }
        op = parse_key_page_operation(data)
        assert isinstance(op, AddKeyOperation)

    def test_parse_threshold_operation(self):
        """Test parse_key_page_operation for setThreshold."""
        data = {"type": "setThreshold", "threshold": 2}
        op = parse_key_page_operation(data)
        assert isinstance(op, SetThresholdKeyPageOperation)
        assert op.threshold == 2

    def test_validate_operations(self):
        """Test validate_key_page_operations."""
        ops = [
            AddKeyOperation.create(key_hash=bytes(32)),
            SetThresholdKeyPageOperation.create(threshold=2)
        ]
        errors = validate_key_page_operations(ops)
        assert len(errors) == 0


# =============================================================================
# Account Auth Operation Tests
# =============================================================================

class TestEnableAccountAuthOperation:
    """Tests for EnableAccountAuthOperation."""

    def test_create_basic(self):
        """Test creating EnableAccountAuthOperation."""
        op = EnableAccountAuthOperation.create("acc://test.acme/book")
        assert op.type == "enable"
        assert op.authority == "acc://test.acme/book"
        assert op.operation_type == AccountAuthOperationType.ENABLE

    def test_auto_prefix(self):
        """Test authority gets acc:// prefix."""
        op = EnableAccountAuthOperation.create("test.acme/book")
        assert op.authority == "acc://test.acme/book"

    def test_to_dict(self):
        """Test to_dict serialization."""
        op = EnableAccountAuthOperation.create("acc://test.acme/book")
        d = op.to_dict()
        assert d["type"] == "enable"
        assert d["authority"] == "acc://test.acme/book"


class TestDisableAccountAuthOperation:
    """Tests for DisableAccountAuthOperation."""

    def test_create_basic(self):
        """Test creating DisableAccountAuthOperation."""
        op = DisableAccountAuthOperation.create("acc://test.acme/book")
        assert op.type == "disable"
        assert op.operation_type == AccountAuthOperationType.DISABLE


class TestAddAccountAuthorityOperation:
    """Tests for AddAccountAuthorityOperation."""

    def test_create_basic(self):
        """Test creating AddAccountAuthorityOperation."""
        op = AddAccountAuthorityOperation.create("acc://new.acme/book")
        assert op.type == "addAuthority"
        assert op.authority == "acc://new.acme/book"
        assert op.operation_type == AccountAuthOperationType.ADDAUTHORITY


class TestRemoveAccountAuthorityOperation:
    """Tests for RemoveAccountAuthorityOperation."""

    def test_create_basic(self):
        """Test creating RemoveAccountAuthorityOperation."""
        op = RemoveAccountAuthorityOperation.create("acc://old.acme/book")
        assert op.type == "removeAuthority"
        assert op.operation_type == AccountAuthOperationType.REMOVEAUTHORITY


# =============================================================================
# Account Auth Operation Factory/Parser Tests
# =============================================================================

class TestAccountAuthOperationFactories:
    """Tests for account auth operation factory functions."""

    def test_create_by_enum(self):
        """Test create_account_auth_operation with enum."""
        op = create_account_auth_operation(
            AccountAuthOperationType.ENABLE,
            "acc://test.acme/book"
        )
        assert isinstance(op, EnableAccountAuthOperation)

    def test_create_by_string(self):
        """Test create_account_auth_operation with string."""
        op = create_account_auth_operation("ADDAUTHORITY", "acc://test.acme")
        assert isinstance(op, AddAccountAuthorityOperation)

    def test_parse_enable(self):
        """Test parse_account_auth_operation for enable."""
        data = {"type": "enable", "authority": "acc://test.acme"}
        op = parse_account_auth_operation(data)
        assert isinstance(op, EnableAccountAuthOperation)

    def test_validate_operations(self):
        """Test validate_account_auth_operations."""
        ops = [
            EnableAccountAuthOperation.create("acc://test.acme"),
            AddAccountAuthorityOperation.create("acc://new.acme")
        ]
        errors = validate_account_auth_operations(ops)
        assert len(errors) == 0


# =============================================================================
# Convenience Function Tests
# =============================================================================

class TestConvenienceFunctions:
    """Tests for convenience functions."""

    def test_enable_authority(self):
        """Test enable_authority function."""
        op = enable_authority("acc://test.acme/book")
        assert isinstance(op, EnableAccountAuthOperation)

    def test_disable_authority(self):
        """Test disable_authority function."""
        op = disable_authority("acc://test.acme/book")
        assert isinstance(op, DisableAccountAuthOperation)

    def test_add_authority(self):
        """Test add_authority function."""
        op = add_authority("acc://new.acme/book")
        assert isinstance(op, AddAccountAuthorityOperation)

    def test_remove_authority(self):
        """Test remove_authority function."""
        op = remove_authority("acc://old.acme/book")
        assert isinstance(op, RemoveAccountAuthorityOperation)


# =============================================================================
# Network Maintenance Tests
# =============================================================================

class TestPendingTransactionGCOperation:
    """Tests for PendingTransactionGCOperation."""

    def test_create_basic(self):
        """Test creating PendingTransactionGCOperation."""
        op = PendingTransactionGCOperation.create("acc://test.acme")
        assert op.type == "pendingTransactionGC"
        assert op.account == "acc://test.acme"

    def test_auto_prefix(self):
        """Test account gets acc:// prefix."""
        op = PendingTransactionGCOperation.create("test.acme")
        assert op.account == "acc://test.acme"

    def test_to_dict(self):
        """Test to_dict serialization."""
        op = PendingTransactionGCOperation.create("acc://test.acme")
        d = op.to_dict()
        assert d["type"] == "pendingTransactionGC"
        assert d["account"] == "acc://test.acme"


# =============================================================================
# Go Parity Tests
# =============================================================================

class TestGoParity:
    """Tests to verify Go protocol parity."""

    def test_key_page_operation_type_values(self):
        """Test KeyPageOperationType enum values match Go."""
        assert KeyPageOperationType.UNKNOWN == 0
        assert KeyPageOperationType.UPDATE == 1
        assert KeyPageOperationType.REMOVE == 2
        assert KeyPageOperationType.ADD == 3
        assert KeyPageOperationType.SETTHRESHOLD == 4
        assert KeyPageOperationType.UPDATEALLOWED == 5
        assert KeyPageOperationType.SETREJECTTHRESHOLD == 6
        assert KeyPageOperationType.SETRESPONSETHRESHOLD == 7

    def test_account_auth_operation_type_values(self):
        """Test AccountAuthOperationType enum values match Go."""
        assert AccountAuthOperationType.UNKNOWN == 0
        assert AccountAuthOperationType.ENABLE == 1
        assert AccountAuthOperationType.DISABLE == 2
        assert AccountAuthOperationType.ADDAUTHORITY == 3
        assert AccountAuthOperationType.REMOVEAUTHORITY == 4

    def test_add_key_operation_json_format(self):
        """Test AddKeyOperation JSON matches Go format."""
        op = AddKeyOperation.create(key_hash="ab" * 32)
        d = op.to_dict()
        # Go uses "type": "add" and "entry": {...}
        assert d["type"] == "add"
        assert "entry" in d
        assert "keyHash" in d["entry"]  # Go uses camelCase

    def test_update_key_operation_json_format(self):
        """Test UpdateKeyOperation JSON matches Go format."""
        op = UpdateKeyOperation.create(
            old_key_hash="00" * 32,
            new_key_hash="ff" * 32
        )
        d = op.to_dict()
        # Go uses "oldEntry" and "newEntry" (camelCase)
        assert "oldEntry" in d
        assert "newEntry" in d

    def test_threshold_operation_json_format(self):
        """Test threshold operations JSON matches Go format."""
        op = SetThresholdKeyPageOperation.create(threshold=2)
        d = op.to_dict()
        assert d["type"] == "setThreshold"
        assert d["threshold"] == 2

    def test_account_auth_operation_json_format(self):
        """Test account auth operation JSON matches Go format."""
        op = EnableAccountAuthOperation.create("acc://test.acme/book")
        d = op.to_dict()
        assert d["type"] == "enable"
        assert d["authority"] == "acc://test.acme/book"
