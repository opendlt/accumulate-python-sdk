"""
Transaction builders and execution infrastructure for Accumulate Protocol.

Provides builders for all transaction types with validation, encoding,
execution, and fee estimation for exact parity with the Go implementation.
"""

# Stage 6-8 modules
from . import builders, codec, execute, validation, fees, client_helpers

# Header types with full Go parity (Phase 4)
from .header import (
    ExpireOptions,
    HoldUntilOptions,
    TransactionHeader,
    TransactionEnvelope,
    create_simple_header,
    create_expiring_header,
    create_scheduled_header,
    create_multisig_header,
)

# Build context types (Phase 6)
from .context import (
    BuildContext,
    TransactionContext,
    create_context,
    context_for_identity,
    context_for_lite_account,
)

# Voting helpers (Phase 6)
from .voting import (
    # Core functions
    canonical_json,
    compute_transaction_hash,
    # Vote building
    build_vote,
    build_accept_vote,
    build_reject_vote,
    build_abstain_vote,
    build_suggest_vote,
    # Multi-sig collection
    VoteCollector,
    # Validation helpers
    is_accepting_vote,
    is_rejecting_vote,
    parse_vote_type,
    check_threshold,
    check_rejection_threshold,
    # Signature analysis
    extract_vote_from_signature,
    get_signature_signer,
    analyze_signatures,
)

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

    # Transaction header types (Phase 4 - Go parity)
    "ExpireOptions",
    "HoldUntilOptions",
    "TransactionHeader",
    "TransactionEnvelope",
    "create_simple_header",
    "create_expiring_header",
    "create_scheduled_header",
    "create_multisig_header",

    # Build context types (Phase 6 - Go/Dart parity)
    "BuildContext",
    "TransactionContext",
    "create_context",
    "context_for_identity",
    "context_for_lite_account",

    # Voting helpers (Phase 6)
    "canonical_json",
    "compute_transaction_hash",
    "build_vote",
    "build_accept_vote",
    "build_reject_vote",
    "build_abstain_vote",
    "build_suggest_vote",
    "VoteCollector",
    "is_accepting_vote",
    "is_rejecting_vote",
    "parse_vote_type",
    "check_threshold",
    "check_rejection_threshold",
    "extract_vote_from_signature",
    "get_signature_signer",
    "analyze_signatures",

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