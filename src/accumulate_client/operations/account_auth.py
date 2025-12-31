"""
Account auth operation types with full Go parity.

Provides complete implementations of all account authorization operations
matching the Go protocol implementation in protocol/operations.yml.

Reference: C:/Accumulate_Stuff/accumulate/protocol/operations.yml
"""

from __future__ import annotations
from typing import Optional, List, Union, Any, Dict, Type
from pydantic import BaseModel, Field, field_validator
from abc import ABC, abstractmethod

from ..enums import AccountAuthOperationType
from ..runtime.url import AccountUrl


# =============================================================================
# Base Account Auth Operation
# =============================================================================

class BaseAccountAuthOperation(BaseModel, ABC):
    """
    Base class for all account authorization operations.

    Provides common functionality and interface for account auth operations.
    """

    @property
    @abstractmethod
    def operation_type(self) -> AccountAuthOperationType:
        """Get the operation type enum value."""
        pass

    @abstractmethod
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        pass

    def validate_for_submission(self) -> List[str]:
        """
        Validate the operation for submission.

        Returns:
            List of validation error messages (empty if valid)
        """
        return []


# =============================================================================
# Account Auth Operations
# =============================================================================

class EnableAccountAuthOperation(BaseAccountAuthOperation):
    """
    Enable authorization checks for an authority.

    When an authority is enabled, it must approve transactions
    that fall under its authorization scope.

    Matches Go type: protocol.EnableAccountAuthOperation

    Reference: operations.yml lines 1-7:
        EnableAccountAuthOperation:
          union: { type: accountAuthOperation }
          fields:
          - name: Authority
            description: is the authority to enable authorization for
            type: url
            pointer: true
    """
    type: str = Field(default="enable", frozen=True)
    authority: str = Field(
        ...,
        description="The authority URL to enable authorization for"
    )

    model_config = {"populate_by_name": True}

    @property
    def operation_type(self) -> AccountAuthOperationType:
        return AccountAuthOperationType.ENABLE

    @field_validator('authority', mode='before')
    @classmethod
    def validate_authority(cls, v: Any) -> str:
        """Validate and normalize authority URL."""
        if isinstance(v, AccountUrl):
            return str(v)
        if isinstance(v, str):
            if v and not v.startswith('acc://'):
                v = f'acc://{v}'
            return v
        raise ValueError(f"authority must be a string or AccountUrl, got {type(v)}")

    @classmethod
    def create(cls, authority: Union[str, AccountUrl]) -> EnableAccountAuthOperation:
        """
        Create an EnableAccountAuthOperation.

        Args:
            authority: The authority URL to enable

        Returns:
            EnableAccountAuthOperation instance
        """
        return cls(authority=str(authority) if isinstance(authority, AccountUrl) else authority)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "type": self.type,
            "authority": self.authority
        }

    def validate_for_submission(self) -> List[str]:
        errors = []
        if not self.authority:
            errors.append("EnableAccountAuthOperation requires authority")
        if not self.authority.startswith('acc://'):
            errors.append("authority must be a valid Accumulate URL")
        return errors


class DisableAccountAuthOperation(BaseAccountAuthOperation):
    """
    Disable authorization checks for an authority.

    When an authority is disabled, it does not need to approve
    transactions (they are auto-approved for that authority).

    Matches Go type: protocol.DisableAccountAuthOperation

    Reference: operations.yml lines 9-15:
        DisableAccountAuthOperation:
          union: { type: accountAuthOperation }
          fields:
          - name: Authority
            description: is the authority to disable authorization for
            type: url
            pointer: true
    """
    type: str = Field(default="disable", frozen=True)
    authority: str = Field(
        ...,
        description="The authority URL to disable authorization for"
    )

    model_config = {"populate_by_name": True}

    @property
    def operation_type(self) -> AccountAuthOperationType:
        return AccountAuthOperationType.DISABLE

    @field_validator('authority', mode='before')
    @classmethod
    def validate_authority(cls, v: Any) -> str:
        """Validate and normalize authority URL."""
        if isinstance(v, AccountUrl):
            return str(v)
        if isinstance(v, str):
            if v and not v.startswith('acc://'):
                v = f'acc://{v}'
            return v
        raise ValueError(f"authority must be a string or AccountUrl, got {type(v)}")

    @classmethod
    def create(cls, authority: Union[str, AccountUrl]) -> DisableAccountAuthOperation:
        """
        Create a DisableAccountAuthOperation.

        Args:
            authority: The authority URL to disable

        Returns:
            DisableAccountAuthOperation instance
        """
        return cls(authority=str(authority) if isinstance(authority, AccountUrl) else authority)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "type": self.type,
            "authority": self.authority
        }

    def validate_for_submission(self) -> List[str]:
        errors = []
        if not self.authority:
            errors.append("DisableAccountAuthOperation requires authority")
        if not self.authority.startswith('acc://'):
            errors.append("authority must be a valid Accumulate URL")
        return errors


class AddAccountAuthorityOperation(BaseAccountAuthOperation):
    """
    Add an authority to an account.

    The new authority will be able to authorize transactions
    for this account (subject to the key page rules).

    Matches Go type: protocol.AddAccountAuthorityOperation

    Reference: operations.yml lines 17-23:
        AddAccountAuthorityOperation:
          union: { type: accountAuthOperation, value: AddAuthority }
          fields:
          - name: Authority
            description: is the authority to add
            type: url
            pointer: true
    """
    type: str = Field(default="addAuthority", frozen=True)
    authority: str = Field(
        ...,
        description="The authority URL to add"
    )

    model_config = {"populate_by_name": True}

    @property
    def operation_type(self) -> AccountAuthOperationType:
        return AccountAuthOperationType.ADDAUTHORITY

    @field_validator('authority', mode='before')
    @classmethod
    def validate_authority(cls, v: Any) -> str:
        """Validate and normalize authority URL."""
        if isinstance(v, AccountUrl):
            return str(v)
        if isinstance(v, str):
            if v and not v.startswith('acc://'):
                v = f'acc://{v}'
            return v
        raise ValueError(f"authority must be a string or AccountUrl, got {type(v)}")

    @classmethod
    def create(cls, authority: Union[str, AccountUrl]) -> AddAccountAuthorityOperation:
        """
        Create an AddAccountAuthorityOperation.

        Args:
            authority: The authority URL to add

        Returns:
            AddAccountAuthorityOperation instance
        """
        return cls(authority=str(authority) if isinstance(authority, AccountUrl) else authority)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "type": self.type,
            "authority": self.authority
        }

    def validate_for_submission(self) -> List[str]:
        errors = []
        if not self.authority:
            errors.append("AddAccountAuthorityOperation requires authority")
        if not self.authority.startswith('acc://'):
            errors.append("authority must be a valid Accumulate URL")
        return errors


class RemoveAccountAuthorityOperation(BaseAccountAuthOperation):
    """
    Remove an authority from an account.

    The removed authority will no longer be able to authorize
    transactions for this account.

    Matches Go type: protocol.RemoveAccountAuthorityOperation

    Reference: operations.yml lines 25-31:
        RemoveAccountAuthorityOperation:
          union: { type: accountAuthOperation, value: RemoveAuthority }
          fields:
          - name: Authority
            description: is the authority to remove
            type: url
            pointer: true
    """
    type: str = Field(default="removeAuthority", frozen=True)
    authority: str = Field(
        ...,
        description="The authority URL to remove"
    )

    model_config = {"populate_by_name": True}

    @property
    def operation_type(self) -> AccountAuthOperationType:
        return AccountAuthOperationType.REMOVEAUTHORITY

    @field_validator('authority', mode='before')
    @classmethod
    def validate_authority(cls, v: Any) -> str:
        """Validate and normalize authority URL."""
        if isinstance(v, AccountUrl):
            return str(v)
        if isinstance(v, str):
            if v and not v.startswith('acc://'):
                v = f'acc://{v}'
            return v
        raise ValueError(f"authority must be a string or AccountUrl, got {type(v)}")

    @classmethod
    def create(cls, authority: Union[str, AccountUrl]) -> RemoveAccountAuthorityOperation:
        """
        Create a RemoveAccountAuthorityOperation.

        Args:
            authority: The authority URL to remove

        Returns:
            RemoveAccountAuthorityOperation instance
        """
        return cls(authority=str(authority) if isinstance(authority, AccountUrl) else authority)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "type": self.type,
            "authority": self.authority
        }

    def validate_for_submission(self) -> List[str]:
        errors = []
        if not self.authority:
            errors.append("RemoveAccountAuthorityOperation requires authority")
        if not self.authority.startswith('acc://'):
            errors.append("authority must be a valid Accumulate URL")
        return errors


# Type alias for any account auth operation
AccountAuthOperation = Union[
    EnableAccountAuthOperation,
    DisableAccountAuthOperation,
    AddAccountAuthorityOperation,
    RemoveAccountAuthorityOperation,
]


# =============================================================================
# Network Maintenance Operations
# =============================================================================

class PendingTransactionGCOperation(BaseModel):
    """
    Garbage collection operation for pending transactions.

    Used for network maintenance to clean up stale pending transactions.

    Matches Go type: protocol.PendingTransactionGCOperation

    Reference: operations.yml lines 33-39:
        PendingTransactionGCOperation:
          union: { type: networkMaintenanceOperation, value: pendingTransactionGC }
          fields:
          - name: Account
            description: is the account to collect garbage from
            type: url
            pointer: true
    """
    type: str = Field(default="pendingTransactionGC", frozen=True)
    account: str = Field(
        ...,
        description="The account URL to collect garbage from"
    )

    model_config = {"populate_by_name": True}

    @field_validator('account', mode='before')
    @classmethod
    def validate_account(cls, v: Any) -> str:
        """Validate and normalize account URL."""
        if isinstance(v, AccountUrl):
            return str(v)
        if isinstance(v, str):
            if v and not v.startswith('acc://'):
                v = f'acc://{v}'
            return v
        raise ValueError(f"account must be a string or AccountUrl, got {type(v)}")

    @classmethod
    def create(cls, account: Union[str, AccountUrl]) -> PendingTransactionGCOperation:
        """
        Create a PendingTransactionGCOperation.

        Args:
            account: The account URL to garbage collect

        Returns:
            PendingTransactionGCOperation instance
        """
        return cls(account=str(account) if isinstance(account, AccountUrl) else account)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "type": self.type,
            "account": self.account
        }


# Network maintenance operation type alias
NetworkMaintenanceOperation = Union[PendingTransactionGCOperation]


# =============================================================================
# Factory and Helper Functions
# =============================================================================

def create_account_auth_operation(
    operation_type: Union[AccountAuthOperationType, str, int],
    authority: Union[str, AccountUrl]
) -> AccountAuthOperation:
    """
    Factory function to create an account auth operation.

    Args:
        operation_type: The type of operation to create
        authority: The authority URL for the operation

    Returns:
        The appropriate AccountAuthOperation instance
    """
    # Normalize operation_type
    if isinstance(operation_type, str):
        operation_type = operation_type.upper().replace(' ', '').replace('_', '')
        for op_type in AccountAuthOperationType:
            if op_type.name == operation_type:
                operation_type = op_type
                break
        else:
            raise ValueError(f"Unknown operation type: {operation_type}")
    elif isinstance(operation_type, int):
        operation_type = AccountAuthOperationType(operation_type)

    # Create the appropriate operation
    operation_map: Dict[AccountAuthOperationType, Type[BaseAccountAuthOperation]] = {
        AccountAuthOperationType.ENABLE: EnableAccountAuthOperation,
        AccountAuthOperationType.DISABLE: DisableAccountAuthOperation,
        AccountAuthOperationType.ADDAUTHORITY: AddAccountAuthorityOperation,
        AccountAuthOperationType.REMOVEAUTHORITY: RemoveAccountAuthorityOperation,
    }

    op_class = operation_map.get(operation_type)
    if op_class is None:
        raise ValueError(f"Unsupported operation type: {operation_type}")

    return op_class.create(authority)


def parse_account_auth_operation(data: Dict[str, Any]) -> AccountAuthOperation:
    """
    Parse an account auth operation from a dictionary.

    Args:
        data: Dictionary representation of the operation

    Returns:
        The appropriate AccountAuthOperation instance
    """
    op_type = data.get("type", "").lower()

    type_map = {
        "enable": EnableAccountAuthOperation,
        "disable": DisableAccountAuthOperation,
        "addauthority": AddAccountAuthorityOperation,
        "removeauthority": RemoveAccountAuthorityOperation,
    }

    op_class = type_map.get(op_type)
    if op_class is None:
        raise ValueError(f"Unknown operation type: {op_type}")

    return op_class.model_validate(data)


def validate_account_auth_operations(operations: List[AccountAuthOperation]) -> List[str]:
    """
    Validate a list of account auth operations.

    Args:
        operations: List of operations to validate

    Returns:
        List of error messages (empty if all valid)
    """
    errors = []
    for i, op in enumerate(operations):
        op_errors = op.validate_for_submission()
        for error in op_errors:
            errors.append(f"Operation {i} ({op.type}): {error}")
    return errors


# =============================================================================
# Convenience Functions for Common Operations
# =============================================================================

def enable_authority(authority: Union[str, AccountUrl]) -> EnableAccountAuthOperation:
    """Enable authorization for an authority (convenience function)."""
    return EnableAccountAuthOperation.create(authority)


def disable_authority(authority: Union[str, AccountUrl]) -> DisableAccountAuthOperation:
    """Disable authorization for an authority (convenience function)."""
    return DisableAccountAuthOperation.create(authority)


def add_authority(authority: Union[str, AccountUrl]) -> AddAccountAuthorityOperation:
    """Add an authority to an account (convenience function)."""
    return AddAccountAuthorityOperation.create(authority)


def remove_authority(authority: Union[str, AccountUrl]) -> RemoveAccountAuthorityOperation:
    """Remove an authority from an account (convenience function)."""
    return RemoveAccountAuthorityOperation.create(authority)


__all__ = [
    # Base class
    "BaseAccountAuthOperation",
    # Account auth operations
    "EnableAccountAuthOperation",
    "DisableAccountAuthOperation",
    "AddAccountAuthorityOperation",
    "RemoveAccountAuthorityOperation",
    # Union type
    "AccountAuthOperation",
    # Network maintenance
    "PendingTransactionGCOperation",
    "NetworkMaintenanceOperation",
    # Factory/helpers
    "create_account_auth_operation",
    "parse_account_auth_operation",
    "validate_account_auth_operations",
    # Convenience functions
    "enable_authority",
    "disable_authority",
    "add_authority",
    "remove_authority",
]
