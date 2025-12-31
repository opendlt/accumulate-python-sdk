"""
Key page operation types with full Go parity.

Provides complete implementations of all key page operations matching
the Go protocol implementation in protocol/key_page_operations.yml.

Reference: C:/Accumulate_Stuff/accumulate/protocol/key_page_operations.yml
"""

from __future__ import annotations
from typing import Optional, List, Union, Any, Dict, Type
from pydantic import BaseModel, Field, field_validator, model_validator
from abc import ABC, abstractmethod

from ..enums import KeyPageOperationType, TransactionType
from ..runtime.url import AccountUrl


class KeySpecParams(BaseModel):
    """
    Key specification parameters for key pages.

    Matches Go type: protocol.KeySpecParams

    Reference: general.yml lines 156-163:
        KeySpecParams:
          fields:
            - name: KeyHash
              type: bytes
            - name: Delegate
              type: url
              pointer: true
              optional: true
    """
    key_hash: Optional[bytes] = Field(
        default=None,
        alias="keyHash",
        description="SHA-256 hash of the public key (32 bytes)"
    )
    delegate: Optional[str] = Field(
        default=None,
        description="Optional delegate URL for this key"
    )

    model_config = {
        "populate_by_name": True,
        "arbitrary_types_allowed": True
    }

    @field_validator('key_hash', mode='before')
    @classmethod
    def validate_key_hash(cls, v: Any) -> Optional[bytes]:
        """Validate and convert key_hash to bytes."""
        if v is None:
            return None
        if isinstance(v, bytes):
            return v
        if isinstance(v, str):
            return bytes.fromhex(v)
        raise ValueError(f"key_hash must be bytes or hex string, got {type(v)}")

    @field_validator('delegate', mode='before')
    @classmethod
    def validate_delegate(cls, v: Any) -> Optional[str]:
        """Validate delegate URL."""
        if v is None:
            return None
        if isinstance(v, AccountUrl):
            return str(v)
        if isinstance(v, str):
            if v and not v.startswith('acc://'):
                v = f'acc://{v}'
            return v
        raise ValueError(f"delegate must be a string or AccountUrl, got {type(v)}")

    @classmethod
    def from_public_key(cls, public_key: bytes, delegate: Optional[str] = None) -> KeySpecParams:
        """
        Create KeySpecParams from a public key (computes hash).

        Args:
            public_key: Raw public key bytes
            delegate: Optional delegate URL

        Returns:
            KeySpecParams with computed key_hash
        """
        from ..runtime.codec import hash_sha256
        key_hash = hash_sha256(public_key)
        return cls(key_hash=key_hash, delegate=delegate)

    @classmethod
    def from_key_hash(cls, key_hash: Union[bytes, str], delegate: Optional[str] = None) -> KeySpecParams:
        """
        Create KeySpecParams from a key hash.

        Args:
            key_hash: SHA-256 hash of the public key (bytes or hex string)
            delegate: Optional delegate URL

        Returns:
            KeySpecParams instance
        """
        if isinstance(key_hash, str):
            key_hash = bytes.fromhex(key_hash)
        return cls(key_hash=key_hash, delegate=delegate)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        result = {}
        if self.key_hash is not None:
            result["keyHash"] = self.key_hash.hex()
        if self.delegate is not None:
            result["delegate"] = self.delegate
        return result

    def matches(self, other: KeySpecParams) -> bool:
        """Check if this key spec matches another (by key hash)."""
        if self.key_hash is None or other.key_hash is None:
            return False
        return self.key_hash == other.key_hash

    def __hash__(self) -> int:
        return hash(self.key_hash)

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, KeySpecParams):
            return False
        return self.key_hash == other.key_hash


class KeySpec(BaseModel):
    """
    Full key specification with usage tracking.

    Matches Go type: protocol.KeySpec

    Reference: general.yml lines 165-171:
        KeySpec:
          fields:
            - name: PublicKeyHash
              type: bytes
              alternative: PublicKey
            - name: LastUsedOn
              type: uvarint
    """
    public_key_hash: bytes = Field(
        ...,
        alias="publicKeyHash",
        description="SHA-256 hash of the public key"
    )
    last_used_on: int = Field(
        default=0,
        alias="lastUsedOn",
        ge=0,
        description="Block height when this key was last used"
    )
    delegate: Optional[str] = Field(
        default=None,
        description="Optional delegate URL"
    )

    model_config = {
        "populate_by_name": True
    }

    @field_validator('public_key_hash', mode='before')
    @classmethod
    def validate_public_key_hash(cls, v: Any) -> bytes:
        """Validate and convert public_key_hash to bytes."""
        if isinstance(v, bytes):
            return v
        if isinstance(v, str):
            return bytes.fromhex(v)
        raise ValueError(f"public_key_hash must be bytes or hex string, got {type(v)}")

    @classmethod
    def from_public_key(
        cls,
        public_key: bytes,
        last_used_on: int = 0,
        delegate: Optional[str] = None
    ) -> KeySpec:
        """Create KeySpec from a public key (computes hash)."""
        from ..runtime.codec import hash_sha256
        key_hash = hash_sha256(public_key)
        return cls(public_key_hash=key_hash, last_used_on=last_used_on, delegate=delegate)

    def to_params(self) -> KeySpecParams:
        """Convert to KeySpecParams (for use in operations)."""
        return KeySpecParams(key_hash=self.public_key_hash, delegate=self.delegate)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        result = {"publicKeyHash": self.public_key_hash.hex()}
        if self.last_used_on > 0:
            result["lastUsedOn"] = self.last_used_on
        if self.delegate:
            result["delegate"] = self.delegate
        return result


# =============================================================================
# Base Key Page Operation
# =============================================================================

class BaseKeyPageOperation(BaseModel, ABC):
    """
    Base class for all key page operations.

    Provides common functionality and interface for key page operations.
    """

    @property
    @abstractmethod
    def operation_type(self) -> KeyPageOperationType:
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
# Key Page Operations
# =============================================================================

class AddKeyOperation(BaseKeyPageOperation):
    """
    Add a key to a key page.

    Matches Go type: protocol.AddKeyOperation

    Reference: key_page_operations.yml lines 1-6:
        AddKeyOperation:
          union: { type: keyPageOperation, value: Add }
          fields:
            - name: Entry
              type: KeySpecParams
              marshal-as: reference
    """
    type: str = Field(default="add", frozen=True)
    entry: KeySpecParams

    model_config = {"populate_by_name": True}

    @property
    def operation_type(self) -> KeyPageOperationType:
        return KeyPageOperationType.ADD

    @classmethod
    def create(
        cls,
        key_hash: Union[bytes, str],
        delegate: Optional[str] = None
    ) -> AddKeyOperation:
        """
        Create an AddKeyOperation.

        Args:
            key_hash: SHA-256 hash of the public key to add
            delegate: Optional delegate URL for this key

        Returns:
            AddKeyOperation instance
        """
        entry = KeySpecParams.from_key_hash(key_hash, delegate)
        return cls(entry=entry)

    @classmethod
    def from_public_key(
        cls,
        public_key: bytes,
        delegate: Optional[str] = None
    ) -> AddKeyOperation:
        """
        Create an AddKeyOperation from a public key.

        Args:
            public_key: Raw public key bytes (will compute hash)
            delegate: Optional delegate URL

        Returns:
            AddKeyOperation instance
        """
        entry = KeySpecParams.from_public_key(public_key, delegate)
        return cls(entry=entry)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "type": self.type,
            "entry": self.entry.to_dict()
        }

    def validate_for_submission(self) -> List[str]:
        errors = []
        if self.entry.key_hash is None:
            errors.append("AddKeyOperation requires entry.key_hash")
        return errors


class RemoveKeyOperation(BaseKeyPageOperation):
    """
    Remove a key from a key page.

    Matches Go type: protocol.RemoveKeyOperation

    Reference: key_page_operations.yml lines 8-13:
        RemoveKeyOperation:
          union: { type: keyPageOperation, value: Remove }
          fields:
            - name: Entry
              type: KeySpecParams
              marshal-as: reference
    """
    type: str = Field(default="remove", frozen=True)
    entry: KeySpecParams

    model_config = {"populate_by_name": True}

    @property
    def operation_type(self) -> KeyPageOperationType:
        return KeyPageOperationType.REMOVE

    @classmethod
    def create(
        cls,
        key_hash: Union[bytes, str],
        delegate: Optional[str] = None
    ) -> RemoveKeyOperation:
        """
        Create a RemoveKeyOperation.

        Args:
            key_hash: SHA-256 hash of the public key to remove
            delegate: Optional delegate URL (for matching)

        Returns:
            RemoveKeyOperation instance
        """
        entry = KeySpecParams.from_key_hash(key_hash, delegate)
        return cls(entry=entry)

    @classmethod
    def from_public_key(
        cls,
        public_key: bytes,
        delegate: Optional[str] = None
    ) -> RemoveKeyOperation:
        """Create a RemoveKeyOperation from a public key."""
        entry = KeySpecParams.from_public_key(public_key, delegate)
        return cls(entry=entry)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "type": self.type,
            "entry": self.entry.to_dict()
        }

    def validate_for_submission(self) -> List[str]:
        errors = []
        if self.entry.key_hash is None:
            errors.append("RemoveKeyOperation requires entry.key_hash")
        return errors


class UpdateKeyOperation(BaseKeyPageOperation):
    """
    Update (replace) a key on a key page.

    Matches Go type: protocol.UpdateKeyOperation

    Reference: key_page_operations.yml lines 15-23:
        UpdateKeyOperation:
          union: { type: keyPageOperation, value: Update }
          fields:
            - name: OldEntry
              type: KeySpecParams
              marshal-as: reference
            - name: NewEntry
              type: KeySpecParams
              marshal-as: reference
    """
    type: str = Field(default="update", frozen=True)
    old_entry: KeySpecParams = Field(..., alias="oldEntry")
    new_entry: KeySpecParams = Field(..., alias="newEntry")

    model_config = {"populate_by_name": True}

    @property
    def operation_type(self) -> KeyPageOperationType:
        return KeyPageOperationType.UPDATE

    @classmethod
    def create(
        cls,
        old_key_hash: Union[bytes, str],
        new_key_hash: Union[bytes, str],
        old_delegate: Optional[str] = None,
        new_delegate: Optional[str] = None
    ) -> UpdateKeyOperation:
        """
        Create an UpdateKeyOperation.

        Args:
            old_key_hash: Hash of the key to replace
            new_key_hash: Hash of the new key
            old_delegate: Old key's delegate (for matching)
            new_delegate: New key's delegate

        Returns:
            UpdateKeyOperation instance
        """
        old_entry = KeySpecParams.from_key_hash(old_key_hash, old_delegate)
        new_entry = KeySpecParams.from_key_hash(new_key_hash, new_delegate)
        return cls(old_entry=old_entry, new_entry=new_entry)

    @classmethod
    def from_public_keys(
        cls,
        old_public_key: bytes,
        new_public_key: bytes,
        old_delegate: Optional[str] = None,
        new_delegate: Optional[str] = None
    ) -> UpdateKeyOperation:
        """Create an UpdateKeyOperation from public keys."""
        old_entry = KeySpecParams.from_public_key(old_public_key, old_delegate)
        new_entry = KeySpecParams.from_public_key(new_public_key, new_delegate)
        return cls(old_entry=old_entry, new_entry=new_entry)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "type": self.type,
            "oldEntry": self.old_entry.to_dict(),
            "newEntry": self.new_entry.to_dict()
        }

    def validate_for_submission(self) -> List[str]:
        errors = []
        if self.old_entry.key_hash is None:
            errors.append("UpdateKeyOperation requires old_entry.key_hash")
        if self.new_entry.key_hash is None:
            errors.append("UpdateKeyOperation requires new_entry.key_hash")
        return errors


class SetThresholdKeyPageOperation(BaseKeyPageOperation):
    """
    Set the signing threshold for a key page.

    The threshold is the "M" in "M of N" signatures required.

    Matches Go type: protocol.SetThresholdKeyPageOperation

    Reference: key_page_operations.yml lines 25-29:
        SetThresholdKeyPageOperation:
          union: { type: keyPageOperation }
          fields:
            - name: Threshold
              type: uvarint
    """
    type: str = Field(default="setThreshold", frozen=True)
    threshold: int = Field(..., ge=1, description="Required signature threshold (M of N)")

    model_config = {"populate_by_name": True}

    @property
    def operation_type(self) -> KeyPageOperationType:
        return KeyPageOperationType.SETTHRESHOLD

    @classmethod
    def create(cls, threshold: int) -> SetThresholdKeyPageOperation:
        """
        Create a SetThresholdKeyPageOperation.

        Args:
            threshold: Number of signatures required (must be >= 1)

        Returns:
            SetThresholdKeyPageOperation instance
        """
        if threshold < 1:
            raise ValueError("threshold must be at least 1")
        return cls(threshold=threshold)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "type": self.type,
            "threshold": self.threshold
        }

    def validate_for_submission(self) -> List[str]:
        errors = []
        if self.threshold < 1:
            errors.append("threshold must be at least 1")
        return errors


class SetRejectThresholdKeyPageOperation(BaseKeyPageOperation):
    """
    Set the rejection threshold for a key page.

    Matches Go type: protocol.SetRejectThresholdKeyPageOperation

    Reference: key_page_operations.yml lines 31-35:
        SetRejectThresholdKeyPageOperation:
          union: { type: keyPageOperation }
          fields:
            - name: Threshold
              type: uvarint
    """
    type: str = Field(default="setRejectThreshold", frozen=True)
    threshold: int = Field(..., ge=0, description="Rejection threshold")

    model_config = {"populate_by_name": True}

    @property
    def operation_type(self) -> KeyPageOperationType:
        return KeyPageOperationType.SETREJECTTHRESHOLD

    @classmethod
    def create(cls, threshold: int) -> SetRejectThresholdKeyPageOperation:
        """Create a SetRejectThresholdKeyPageOperation."""
        if threshold < 0:
            raise ValueError("threshold must be non-negative")
        return cls(threshold=threshold)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "type": self.type,
            "threshold": self.threshold
        }


class SetResponseThresholdKeyPageOperation(BaseKeyPageOperation):
    """
    Set the response threshold for a key page.

    Matches Go type: protocol.SetResponseThresholdKeyPageOperation

    Reference: key_page_operations.yml lines 37-41:
        SetResponseThresholdKeyPageOperation:
          union: { type: keyPageOperation }
          fields:
            - name: Threshold
              type: uvarint
    """
    type: str = Field(default="setResponseThreshold", frozen=True)
    threshold: int = Field(..., ge=0, description="Response threshold")

    model_config = {"populate_by_name": True}

    @property
    def operation_type(self) -> KeyPageOperationType:
        return KeyPageOperationType.SETRESPONSETHRESHOLD

    @classmethod
    def create(cls, threshold: int) -> SetResponseThresholdKeyPageOperation:
        """Create a SetResponseThresholdKeyPageOperation."""
        if threshold < 0:
            raise ValueError("threshold must be non-negative")
        return cls(threshold=threshold)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "type": self.type,
            "threshold": self.threshold
        }


class UpdateAllowedKeyPageOperation(BaseKeyPageOperation):
    """
    Update allowed/denied transaction types for a key page.

    Matches Go type: protocol.UpdateAllowedKeyPageOperation

    Reference: key_page_operations.yml lines 43-55:
        UpdateAllowedKeyPageOperation:
          union: { type: keyPageOperation }
          fields:
            - name: Allow
              type: TransactionType
              repeatable: true
              marshal-as: enum
              optional: true
            - name: Deny
              type: TransactionType
              repeatable: true
              marshal-as: enum
              optional: true
    """
    type: str = Field(default="updateAllowed", frozen=True)
    allow: Optional[List[TransactionType]] = Field(
        default=None,
        description="Transaction types to allow"
    )
    deny: Optional[List[TransactionType]] = Field(
        default=None,
        description="Transaction types to deny"
    )

    model_config = {"populate_by_name": True}

    @property
    def operation_type(self) -> KeyPageOperationType:
        return KeyPageOperationType.UPDATEALLOWED

    @field_validator('allow', 'deny', mode='before')
    @classmethod
    def convert_to_transaction_types(cls, v: Any) -> Optional[List[TransactionType]]:
        """Convert various inputs to TransactionType list."""
        if v is None:
            return None
        if isinstance(v, list):
            result = []
            for item in v:
                if isinstance(item, TransactionType):
                    result.append(item)
                elif isinstance(item, int):
                    result.append(TransactionType(item))
                elif isinstance(item, str):
                    # Try to match by name
                    item_upper = item.upper().replace('_', '')
                    for tt in TransactionType:
                        if tt.name == item_upper:
                            result.append(tt)
                            break
                    else:
                        raise ValueError(f"Unknown transaction type: {item}")
                else:
                    raise ValueError(f"Cannot convert {type(item)} to TransactionType")
            return result if result else None
        raise ValueError(f"allow/deny must be a list, got {type(v)}")

    @classmethod
    def create(
        cls,
        allow: Optional[List[Union[TransactionType, int, str]]] = None,
        deny: Optional[List[Union[TransactionType, int, str]]] = None
    ) -> UpdateAllowedKeyPageOperation:
        """
        Create an UpdateAllowedKeyPageOperation.

        Args:
            allow: Transaction types to allow (by enum, int, or name)
            deny: Transaction types to deny (by enum, int, or name)

        Returns:
            UpdateAllowedKeyPageOperation instance
        """
        return cls(allow=allow, deny=deny)

    @classmethod
    def allow_only(cls, *tx_types: Union[TransactionType, int, str]) -> UpdateAllowedKeyPageOperation:
        """Create an operation that only allows specific transaction types."""
        return cls(allow=list(tx_types))

    @classmethod
    def deny_only(cls, *tx_types: Union[TransactionType, int, str]) -> UpdateAllowedKeyPageOperation:
        """Create an operation that denies specific transaction types."""
        return cls(deny=list(tx_types))

    def to_dict(self) -> Dict[str, Any]:
        result: Dict[str, Any] = {"type": self.type}
        if self.allow:
            result["allow"] = [t.name.lower() for t in self.allow]
        if self.deny:
            result["deny"] = [t.name.lower() for t in self.deny]
        return result

    def validate_for_submission(self) -> List[str]:
        errors = []
        if self.allow is None and self.deny is None:
            errors.append("UpdateAllowedKeyPageOperation requires at least allow or deny")
        return errors


# Type alias for any key page operation
KeyPageOperation = Union[
    AddKeyOperation,
    RemoveKeyOperation,
    UpdateKeyOperation,
    SetThresholdKeyPageOperation,
    SetRejectThresholdKeyPageOperation,
    SetResponseThresholdKeyPageOperation,
    UpdateAllowedKeyPageOperation,
]


# =============================================================================
# Factory and Helper Functions
# =============================================================================

def create_key_page_operation(
    operation_type: Union[KeyPageOperationType, str, int],
    **kwargs
) -> KeyPageOperation:
    """
    Factory function to create a key page operation.

    Args:
        operation_type: The type of operation to create
        **kwargs: Arguments for the specific operation

    Returns:
        The appropriate KeyPageOperation instance
    """
    # Normalize operation_type
    if isinstance(operation_type, str):
        operation_type = operation_type.upper().replace(' ', '').replace('_', '')
        for op_type in KeyPageOperationType:
            if op_type.name == operation_type:
                operation_type = op_type
                break
        else:
            raise ValueError(f"Unknown operation type: {operation_type}")
    elif isinstance(operation_type, int):
        operation_type = KeyPageOperationType(operation_type)

    # Create the appropriate operation
    operation_map: Dict[KeyPageOperationType, Type[BaseKeyPageOperation]] = {
        KeyPageOperationType.ADD: AddKeyOperation,
        KeyPageOperationType.REMOVE: RemoveKeyOperation,
        KeyPageOperationType.UPDATE: UpdateKeyOperation,
        KeyPageOperationType.SETTHRESHOLD: SetThresholdKeyPageOperation,
        KeyPageOperationType.SETREJECTTHRESHOLD: SetRejectThresholdKeyPageOperation,
        KeyPageOperationType.SETRESPONSETHRESHOLD: SetResponseThresholdKeyPageOperation,
        KeyPageOperationType.UPDATEALLOWED: UpdateAllowedKeyPageOperation,
    }

    op_class = operation_map.get(operation_type)
    if op_class is None:
        raise ValueError(f"Unsupported operation type: {operation_type}")

    return op_class(**kwargs)


def parse_key_page_operation(data: Dict[str, Any]) -> KeyPageOperation:
    """
    Parse a key page operation from a dictionary.

    Args:
        data: Dictionary representation of the operation

    Returns:
        The appropriate KeyPageOperation instance
    """
    op_type = data.get("type", "").lower()

    type_map = {
        "add": AddKeyOperation,
        "remove": RemoveKeyOperation,
        "update": UpdateKeyOperation,
        "setthreshold": SetThresholdKeyPageOperation,
        "setrejectthreshold": SetRejectThresholdKeyPageOperation,
        "setresponsethreshold": SetResponseThresholdKeyPageOperation,
        "updateallowed": UpdateAllowedKeyPageOperation,
    }

    op_class = type_map.get(op_type)
    if op_class is None:
        raise ValueError(f"Unknown operation type: {op_type}")

    return op_class.model_validate(data)


def validate_key_page_operations(operations: List[KeyPageOperation]) -> List[str]:
    """
    Validate a list of key page operations.

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


__all__ = [
    # Key spec types
    "KeySpecParams",
    "KeySpec",
    # Base class
    "BaseKeyPageOperation",
    # Operations
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
]
