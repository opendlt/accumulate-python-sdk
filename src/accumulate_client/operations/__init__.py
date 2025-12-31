"""
Operation types for Accumulate Protocol transactions.

This module provides complete implementations of all operation types
used in Accumulate protocol transactions, including:

- Key Page Operations (UpdateKeyPage transaction)
- Account Auth Operations (UpdateAccountAuth transaction)
- Network Maintenance Operations (NetworkMaintenance transaction)

All implementations have full Go parity with the protocol implementation.

Reference: C:/Accumulate_Stuff/accumulate/protocol/
"""

from .key_page import (
    # Key spec types
    KeySpecParams,
    KeySpec,
    # Base class
    BaseKeyPageOperation,
    # Operations
    AddKeyOperation,
    RemoveKeyOperation,
    UpdateKeyOperation,
    SetThresholdKeyPageOperation,
    SetRejectThresholdKeyPageOperation,
    SetResponseThresholdKeyPageOperation,
    UpdateAllowedKeyPageOperation,
    # Union type
    KeyPageOperation,
    # Factory/helpers
    create_key_page_operation,
    parse_key_page_operation,
    validate_key_page_operations,
)

from .account_auth import (
    # Base class
    BaseAccountAuthOperation,
    # Account auth operations
    EnableAccountAuthOperation,
    DisableAccountAuthOperation,
    AddAccountAuthorityOperation,
    RemoveAccountAuthorityOperation,
    # Union type
    AccountAuthOperation,
    # Network maintenance
    PendingTransactionGCOperation,
    NetworkMaintenanceOperation,
    # Factory/helpers
    create_account_auth_operation,
    parse_account_auth_operation,
    validate_account_auth_operations,
    # Convenience functions
    enable_authority,
    disable_authority,
    add_authority,
    remove_authority,
)


__all__ = [
    # ==========================================================================
    # Key Page Operations
    # ==========================================================================
    # Key spec types
    "KeySpecParams",
    "KeySpec",
    # Base class
    "BaseKeyPageOperation",
    # Individual operations
    "AddKeyOperation",
    "RemoveKeyOperation",
    "UpdateKeyOperation",
    "SetThresholdKeyPageOperation",
    "SetRejectThresholdKeyPageOperation",
    "SetResponseThresholdKeyPageOperation",
    "UpdateAllowedKeyPageOperation",
    # Union type
    "KeyPageOperation",
    # Factory/helpers
    "create_key_page_operation",
    "parse_key_page_operation",
    "validate_key_page_operations",

    # ==========================================================================
    # Account Auth Operations
    # ==========================================================================
    # Base class
    "BaseAccountAuthOperation",
    # Individual operations
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
