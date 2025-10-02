"""
Transaction builders and execution infrastructure for Accumulate Protocol.

Provides builders for all transaction types with validation, encoding,
execution, and fee estimation for exact parity with the Go implementation.
"""

# Stage 6-8 modules
from . import builders, codec, execute, validation, fees, client_helpers

# Generated types (available after codegen)
try:
    from .types_generated import *  # generated models/enums
    from ._type_index import lookup_tx_model, TX_MODEL_REGISTRY
    HAS_GENERATED_TYPES = True
except ImportError:
    HAS_GENERATED_TYPES = False

# Legacy Phase 2 components (for backward compatibility)
from .builder import (
    TransactionBuilder, BaseTransactionBuilder, Transaction, SignedTransaction,
    TransactionBuilderError, register_builder, get_builder, create_builder
)
from .fields import (
    TransactionField, FieldValidationError,
    StringField, IntegerField, BooleanField, URLField, BytesField,
    ListField, EnumField, AmountField,
    validate_field, validate_transaction_fields, encode_transaction_fields
)

__all__ = [
    # Stage 6-8 modules
    "builders",
    "codec",
    "execute",
    "validation",
    "fees",
    "client_helpers",

    # Generated types (if available)
    "HAS_GENERATED_TYPES",

    # Legacy builder classes
    "TransactionBuilder",
    "BaseTransactionBuilder",
    "Transaction",
    "SignedTransaction",
    "TransactionBuilderError",

    # Legacy builder registry
    "register_builder",
    "get_builder",
    "create_builder",

    # Legacy field types
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

    # Legacy field functions
    "validate_field",
    "validate_transaction_fields",
    "encode_transaction_fields"
]

# Add generated types to __all__ if available
if HAS_GENERATED_TYPES:
    __all__.extend(["lookup_tx_model", "TX_MODEL_REGISTRY"])