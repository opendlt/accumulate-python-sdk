r"""
Transaction field validation and encoding for Accumulate Protocol.

Provides field validation, type checking, and canonical encoding for all
transaction types matching the Go implementation.

Reference: C:/Accumulate_Stuff/accumulate\protocol\transaction.go
"""

from __future__ import annotations
from typing import Any, Dict, List, Optional, Union, Type, Callable
from abc import ABC, abstractmethod
import re
import logging
from decimal import Decimal

from ..runtime.url import AccountUrl
from ..runtime.errors import AccumulateError
from ..enums import TransactionType

logger = logging.getLogger(__name__)


class FieldValidationError(AccumulateError):
    """Field validation specific errors."""
    pass


class TransactionField(ABC):
    """
    Base class for transaction field validation.

    Defines the interface for field validation, type checking, and encoding.
    """

    def __init__(self, name: str, required: bool = True, default: Any = None):
        """
        Initialize transaction field.

        Args:
            name: Field name
            required: Whether field is required
            default: Default value if not required
        """
        self.name = name
        self.required = required
        self.default = default

    @abstractmethod
    def validate(self, value: Any) -> Any:
        """
        Validate and normalize a field value.

        Args:
            value: Raw field value

        Returns:
            Normalized value

        Raises:
            FieldValidationError: If validation fails
        """
        pass

    @abstractmethod
    def encode(self, value: Any) -> Any:
        """
        Encode a field value for protocol transmission.

        Args:
            value: Validated field value

        Returns:
            Encoded value
        """
        pass

    def is_valid(self, value: Any) -> bool:
        """
        Check if a value is valid without raising exceptions.

        Args:
            value: Value to check

        Returns:
            True if valid
        """
        try:
            self.validate(value)
            return True
        except FieldValidationError:
            return False

    def __str__(self) -> str:
        return f"{self.__class__.__name__}({self.name}, required={self.required})"


class StringField(TransactionField):
    """String field with optional length and pattern validation."""

    def __init__(
        self,
        name: str,
        required: bool = True,
        default: Optional[str] = None,
        min_length: Optional[int] = None,
        max_length: Optional[int] = None,
        pattern: Optional[str] = None
    ):
        """
        Initialize string field.

        Args:
            name: Field name
            required: Whether field is required
            default: Default value
            min_length: Minimum length
            max_length: Maximum length
            pattern: Regex pattern to match
        """
        super().__init__(name, required, default)
        self.min_length = min_length
        self.max_length = max_length
        self.pattern = re.compile(pattern) if pattern else None

    def validate(self, value: Any) -> str:
        """Validate string field."""
        if value is None:
            if self.required:
                raise FieldValidationError(f"Field {self.name} is required")
            return self.default

        if not isinstance(value, str):
            raise FieldValidationError(f"Field {self.name} must be a string, got {type(value)}")

        # Length validation
        if self.min_length is not None and len(value) < self.min_length:
            raise FieldValidationError(f"Field {self.name} must be at least {self.min_length} characters")

        if self.max_length is not None and len(value) > self.max_length:
            raise FieldValidationError(f"Field {self.name} must be at most {self.max_length} characters")

        # Pattern validation
        if self.pattern and not self.pattern.match(value):
            raise FieldValidationError(f"Field {self.name} does not match required pattern")

        return value

    def encode(self, value: str) -> str:
        """Encode string field."""
        return value


class IntegerField(TransactionField):
    """Integer field with optional range validation."""

    def __init__(
        self,
        name: str,
        required: bool = True,
        default: Optional[int] = None,
        min_value: Optional[int] = None,
        max_value: Optional[int] = None,
        unsigned: bool = False
    ):
        """
        Initialize integer field.

        Args:
            name: Field name
            required: Whether field is required
            default: Default value
            min_value: Minimum value
            max_value: Maximum value
            unsigned: Whether to enforce unsigned (non-negative)
        """
        super().__init__(name, required, default)
        self.min_value = min_value
        self.max_value = max_value
        self.unsigned = unsigned

    def validate(self, value: Any) -> int:
        """Validate integer field."""
        if value is None:
            if self.required:
                raise FieldValidationError(f"Field {self.name} is required")
            return self.default

        if isinstance(value, str):
            try:
                value = int(value)
            except ValueError:
                raise FieldValidationError(f"Field {self.name} must be a valid integer")

        if not isinstance(value, int):
            raise FieldValidationError(f"Field {self.name} must be an integer, got {type(value)}")

        # Unsigned validation
        if self.unsigned and value < 0:
            raise FieldValidationError(f"Field {self.name} must be non-negative")

        # Range validation
        if self.min_value is not None and value < self.min_value:
            raise FieldValidationError(f"Field {self.name} must be at least {self.min_value}")

        if self.max_value is not None and value > self.max_value:
            raise FieldValidationError(f"Field {self.name} must be at most {self.max_value}")

        return value

    def encode(self, value: int) -> int:
        """Encode integer field."""
        return value


class BooleanField(TransactionField):
    """Boolean field."""

    def __init__(self, name: str, required: bool = True, default: Optional[bool] = None):
        """
        Initialize boolean field.

        Args:
            name: Field name
            required: Whether field is required
            default: Default value
        """
        super().__init__(name, required, default)

    def validate(self, value: Any) -> bool:
        """Validate boolean field."""
        if value is None:
            if self.required:
                raise FieldValidationError(f"Field {self.name} is required")
            return self.default

        if isinstance(value, str):
            value_lower = value.lower()
            if value_lower in ("true", "1", "yes", "on"):
                return True
            elif value_lower in ("false", "0", "no", "off"):
                return False
            else:
                raise FieldValidationError(f"Field {self.name} must be a valid boolean string")

        if not isinstance(value, bool):
            raise FieldValidationError(f"Field {self.name} must be a boolean, got {type(value)}")

        return value

    def encode(self, value: bool) -> bool:
        """Encode boolean field."""
        return value


class URLField(TransactionField):
    """Account URL field."""

    def __init__(self, name: str, required: bool = True, default: Optional[AccountUrl] = None):
        """
        Initialize URL field.

        Args:
            name: Field name
            required: Whether field is required
            default: Default value
        """
        super().__init__(name, required, default)

    def validate(self, value: Any) -> AccountUrl:
        """Validate URL field."""
        if value is None:
            if self.required:
                raise FieldValidationError(f"Field {self.name} is required")
            return self.default

        if isinstance(value, str):
            try:
                value = AccountUrl(value)
            except Exception as e:
                raise FieldValidationError(f"Field {self.name} must be a valid URL: {e}")

        if not isinstance(value, AccountUrl):
            raise FieldValidationError(f"Field {self.name} must be an AccountUrl, got {type(value)}")

        return value

    def encode(self, value: AccountUrl) -> str:
        """Encode URL field."""
        return str(value)


class BytesField(TransactionField):
    """Bytes field with optional length validation."""

    def __init__(
        self,
        name: str,
        required: bool = True,
        default: Optional[bytes] = None,
        min_length: Optional[int] = None,
        max_length: Optional[int] = None,
        fixed_length: Optional[int] = None
    ):
        """
        Initialize bytes field.

        Args:
            name: Field name
            required: Whether field is required
            default: Default value
            min_length: Minimum length
            max_length: Maximum length
            fixed_length: Exact required length
        """
        super().__init__(name, required, default)
        self.min_length = min_length
        self.max_length = max_length
        self.fixed_length = fixed_length

    def validate(self, value: Any) -> bytes:
        """Validate bytes field."""
        if value is None:
            if self.required:
                raise FieldValidationError(f"Field {self.name} is required")
            return self.default

        if isinstance(value, str):
            try:
                value = bytes.fromhex(value)
            except ValueError:
                raise FieldValidationError(f"Field {self.name} must be valid hex string")

        if not isinstance(value, bytes):
            raise FieldValidationError(f"Field {self.name} must be bytes, got {type(value)}")

        # Length validation
        if self.fixed_length is not None and len(value) != self.fixed_length:
            raise FieldValidationError(f"Field {self.name} must be exactly {self.fixed_length} bytes")

        if self.min_length is not None and len(value) < self.min_length:
            raise FieldValidationError(f"Field {self.name} must be at least {self.min_length} bytes")

        if self.max_length is not None and len(value) > self.max_length:
            raise FieldValidationError(f"Field {self.name} must be at most {self.max_length} bytes")

        return value

    def encode(self, value: bytes) -> str:
        """Encode bytes field."""
        return value.hex()


class ListField(TransactionField):
    """List field with element validation."""

    def __init__(
        self,
        name: str,
        element_field: TransactionField,
        required: bool = True,
        default: Optional[List] = None,
        min_length: Optional[int] = None,
        max_length: Optional[int] = None
    ):
        """
        Initialize list field.

        Args:
            name: Field name
            element_field: Field validator for list elements
            required: Whether field is required
            default: Default value
            min_length: Minimum list length
            max_length: Maximum list length
        """
        super().__init__(name, required, default or [])
        self.element_field = element_field
        self.min_length = min_length
        self.max_length = max_length

    def validate(self, value: Any) -> List[Any]:
        """Validate list field."""
        if value is None:
            if self.required:
                raise FieldValidationError(f"Field {self.name} is required")
            return self.default

        if not isinstance(value, list):
            raise FieldValidationError(f"Field {self.name} must be a list, got {type(value)}")

        # Length validation
        if self.min_length is not None and len(value) < self.min_length:
            raise FieldValidationError(f"Field {self.name} must have at least {self.min_length} elements")

        if self.max_length is not None and len(value) > self.max_length:
            raise FieldValidationError(f"Field {self.name} must have at most {self.max_length} elements")

        # Validate each element
        validated_elements = []
        for i, element in enumerate(value):
            try:
                validated_element = self.element_field.validate(element)
                validated_elements.append(validated_element)
            except FieldValidationError as e:
                raise FieldValidationError(f"Field {self.name}[{i}]: {e}")

        return validated_elements

    def encode(self, value: List[Any]) -> List[Any]:
        """Encode list field."""
        return [self.element_field.encode(element) for element in value]


class EnumField(TransactionField):
    """Enum field with value validation."""

    def __init__(
        self,
        name: str,
        enum_class: Type,
        required: bool = True,
        default: Any = None
    ):
        """
        Initialize enum field.

        Args:
            name: Field name
            enum_class: Enum class for validation
            required: Whether field is required
            default: Default value
        """
        super().__init__(name, required, default)
        self.enum_class = enum_class

    def validate(self, value: Any) -> Any:
        """Validate enum field."""
        if value is None:
            if self.required:
                raise FieldValidationError(f"Field {self.name} is required")
            return self.default

        if isinstance(value, str):
            try:
                value = self.enum_class[value.upper()]
            except KeyError:
                valid_values = [e.name for e in self.enum_class]
                raise FieldValidationError(f"Field {self.name} must be one of {valid_values}")

        if not isinstance(value, self.enum_class):
            raise FieldValidationError(f"Field {self.name} must be {self.enum_class.__name__}, got {type(value)}")

        return value

    def encode(self, value: Any) -> str:
        """Encode enum field."""
        return value.name.lower()


class AmountField(TransactionField):
    """Amount field for token values with precision handling."""

    def __init__(
        self,
        name: str,
        required: bool = True,
        default: Optional[int] = None,
        min_value: int = 0
    ):
        """
        Initialize amount field.

        Args:
            name: Field name
            required: Whether field is required
            default: Default value
            min_value: Minimum value (default 0)
        """
        super().__init__(name, required, default)
        self.min_value = min_value

    def validate(self, value: Any) -> int:
        """Validate amount field."""
        if value is None:
            if self.required:
                raise FieldValidationError(f"Field {self.name} is required")
            return self.default

        # Handle string representation
        if isinstance(value, str):
            try:
                # Handle decimal strings
                if '.' in value:
                    decimal_value = Decimal(value)
                    # Convert to integer (assuming 8 decimal places precision)
                    value = int(decimal_value * Decimal('100000000'))
                else:
                    value = int(value)
            except (ValueError, TypeError):
                raise FieldValidationError(f"Field {self.name} must be a valid amount")

        # Handle float (convert to integer with precision)
        if isinstance(value, float):
            value = int(value * 100000000)  # 8 decimal places

        if not isinstance(value, int):
            raise FieldValidationError(f"Field {self.name} must be an amount, got {type(value)}")

        if value < self.min_value:
            raise FieldValidationError(f"Field {self.name} must be at least {self.min_value}")

        return value

    def encode(self, value: int) -> str:
        """Encode amount field as string."""
        return str(value)


# Field validation functions
def validate_field(field: TransactionField, value: Any) -> Any:
    """
    Validate a field value.

    Args:
        field: Field validator
        value: Value to validate

    Returns:
        Validated value

    Raises:
        FieldValidationError: If validation fails
    """
    return field.validate(value)


def validate_transaction_fields(fields: Dict[str, TransactionField], data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Validate all fields in a transaction.

    Args:
        fields: Field validators
        data: Transaction data

    Returns:
        Validated data

    Raises:
        FieldValidationError: If any field validation fails
    """
    validated_data = {}

    # Validate provided fields
    for field_name, field_validator in fields.items():
        field_value = data.get(field_name)
        validated_data[field_name] = field_validator.validate(field_value)

    # Check for unknown fields
    unknown_fields = set(data.keys()) - set(fields.keys())
    if unknown_fields:
        logger.warning(f"Unknown fields in transaction data: {unknown_fields}")

    return validated_data


def encode_transaction_fields(fields: Dict[str, TransactionField], data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Encode all fields in a transaction.

    Args:
        fields: Field validators
        data: Validated transaction data

    Returns:
        Encoded data
    """
    encoded_data = {}

    for field_name, field_validator in fields.items():
        field_value = data.get(field_name)
        if field_value is not None:
            encoded_data[field_name] = field_validator.encode(field_value)

    return encoded_data


# Export main classes and functions
__all__ = [
    "TransactionField",
    "FieldValidationError",
    "StringField",
    "IntegerField",
    "BooleanField",
    "URLField",
    "BytesField",
    "ListField",
    "EnumField",
    "AmountField",
    "validate_field",
    "validate_transaction_fields",
    "encode_transaction_fields"
]