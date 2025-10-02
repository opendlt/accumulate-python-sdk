"""
Transaction builder base classes for Accumulate Protocol.

Provides the foundation for building all 33 transaction types with validation,
encoding, and signature management.

Reference: C:/Accumulate_Stuff/accumulate/protocol/transaction.go
"""

from __future__ import annotations
from abc import ABC, abstractmethod
from typing import Dict, List, Any, Optional, Union, Type
import logging
from datetime import datetime, timezone

from ..runtime.url import AccountUrl
from ..runtime.errors import AccumulateError
from ..enums import TransactionType
from ..signers.signer import Signer
from .fields import (
    TransactionField, FieldValidationError,
    validate_transaction_fields, encode_transaction_fields
)

logger = logging.getLogger(__name__)


class TransactionBuilderError(AccumulateError):
    """Transaction builder specific errors."""
    pass


class Transaction:
    """
    Immutable transaction representation.

    Contains validated transaction data ready for submission.
    """

    def __init__(
        self,
        transaction_type: TransactionType,
        principal: AccountUrl,
        data: Dict[str, Any],
        metadata: Optional[Dict[str, Any]] = None
    ):
        """
        Initialize transaction.

        Args:
            transaction_type: Type of transaction
            principal: Principal account URL
            data: Validated transaction data
            metadata: Optional metadata
        """
        self.transaction_type = transaction_type
        self.principal = principal
        self.data = data.copy()
        self.metadata = metadata or {}
        self.created_at = int(datetime.now(timezone.utc).timestamp() * 1_000_000_000)

    def to_dict(self) -> Dict[str, Any]:
        """
        Convert to dictionary representation.

        Returns:
            Dictionary matching Accumulate transaction format
        """
        result = {
            "type": self.transaction_type.name.lower(),
            "principal": str(self.principal),
            "data": self.data.copy(),
            "metadata": self.metadata.copy()
        }
        return result

    def get_hash(self) -> bytes:
        """
        Calculate transaction hash.

        Returns:
            32-byte transaction hash
        """
        from ..runtime.codec import hash_sha256, encode_json
        tx_data = self.to_dict()
        canonical_json = encode_json(tx_data)
        return hash_sha256(canonical_json.encode('utf-8'))

    def get_routing_location(self) -> AccountUrl:
        """
        Get the routing location for this transaction.

        Returns:
            Account URL for routing
        """
        return self.principal

    def requires_signature(self) -> bool:
        """
        Check if transaction requires signature.

        Returns:
            True if signature is required
        """
        # Most transactions require signatures
        return True

    def __str__(self) -> str:
        return f"Transaction({self.transaction_type.name}, {self.principal})"

    def __repr__(self) -> str:
        return f"Transaction(type={self.transaction_type}, principal='{self.principal}')"


class SignedTransaction:
    """
    Signed transaction with signature information.

    Contains transaction data and associated signatures.
    """

    def __init__(self, transaction: Transaction, signatures: List[Dict[str, Any]]):
        """
        Initialize signed transaction.

        Args:
            transaction: Base transaction
            signatures: List of signature data
        """
        self.transaction = transaction
        self.signatures = signatures.copy()

    def add_signature(self, signature_data: Dict[str, Any]):
        """Add a signature to the transaction."""
        self.signatures.append(signature_data.copy())

    def get_signature_count(self) -> int:
        """Get number of signatures."""
        return len(self.signatures)

    def to_dict(self) -> Dict[str, Any]:
        """
        Convert to dictionary representation.

        Returns:
            Dictionary matching Accumulate signed transaction format
        """
        result = self.transaction.to_dict()
        result["signatures"] = self.signatures.copy()
        return result

    def get_hash(self) -> bytes:
        """Get the hash of the underlying transaction."""
        return self.transaction.get_hash()

    def __str__(self) -> str:
        return f"SignedTransaction({self.transaction.transaction_type.name}, {len(self.signatures)} signatures)"

    def __repr__(self) -> str:
        return f"SignedTransaction(type={self.transaction.transaction_type}, signatures={len(self.signatures)})"


class TransactionBuilder(ABC):
    """
    Abstract base class for transaction builders.

    Provides the foundation for building specific transaction types.
    """

    def __init__(self, transaction_type: TransactionType):
        """
        Initialize transaction builder.

        Args:
            transaction_type: Type of transaction this builder creates
        """
        self.transaction_type = transaction_type
        self._data: Dict[str, Any] = {}
        self._metadata: Dict[str, Any] = {}
        self._signers: List[Signer] = []

    @abstractmethod
    def get_fields(self) -> Dict[str, TransactionField]:
        """
        Get field validators for this transaction type.

        Returns:
            Dictionary mapping field names to validators
        """
        pass

    @abstractmethod
    def get_principal(self) -> AccountUrl:
        """
        Get the principal account URL for this transaction.

        Returns:
            Principal account URL
        """
        pass

    def set_field(self, name: str, value: Any) -> TransactionBuilder:
        """
        Set a transaction field.

        Args:
            name: Field name
            value: Field value

        Returns:
            Self for method chaining
        """
        self._data[name] = value
        return self

    def get_field(self, name: str, default: Any = None) -> Any:
        """
        Get a transaction field value.

        Args:
            name: Field name
            default: Default value if not set

        Returns:
            Field value
        """
        return self._data.get(name, default)

    def has_field(self, name: str) -> bool:
        """
        Check if a field is set.

        Args:
            name: Field name

        Returns:
            True if field is set
        """
        return name in self._data

    def remove_field(self, name: str) -> bool:
        """
        Remove a field.

        Args:
            name: Field name

        Returns:
            True if field was removed
        """
        if name in self._data:
            del self._data[name]
            return True
        return False

    def set_metadata(self, key: str, value: Any) -> TransactionBuilder:
        """
        Set metadata.

        Args:
            key: Metadata key
            value: Metadata value

        Returns:
            Self for method chaining
        """
        self._metadata[key] = value
        return self

    def get_metadata(self, key: str, default: Any = None) -> Any:
        """
        Get metadata value.

        Args:
            key: Metadata key
            default: Default value

        Returns:
            Metadata value
        """
        return self._metadata.get(key, default)

    def add_signer(self, signer: Signer) -> TransactionBuilder:
        """
        Add a signer for this transaction.

        Args:
            signer: Signer to add

        Returns:
            Self for method chaining
        """
        self._signers.append(signer)
        return self

    def remove_signer(self, signer: Signer) -> bool:
        """
        Remove a signer.

        Args:
            signer: Signer to remove

        Returns:
            True if signer was removed
        """
        if signer in self._signers:
            self._signers.remove(signer)
            return True
        return False

    def get_signers(self) -> List[Signer]:
        """Get list of signers."""
        return self._signers.copy()

    def get_signer_count(self) -> int:
        """Get number of signers."""
        return len(self._signers)

    def validate(self) -> Dict[str, Any]:
        """
        Validate transaction data.

        Returns:
            Validated transaction data

        Raises:
            TransactionBuilderError: If validation fails
        """
        try:
            fields = self.get_fields()
            validated_data = validate_transaction_fields(fields, self._data)
            return validated_data
        except FieldValidationError as e:
            raise TransactionBuilderError(f"Transaction validation failed: {e}")

    def build(self) -> Transaction:
        """
        Build an unsigned transaction.

        Returns:
            Transaction ready for signing

        Raises:
            TransactionBuilderError: If validation fails
        """
        validated_data = self.validate()
        principal = self.get_principal()

        if not principal:
            raise TransactionBuilderError("Principal account URL is required")

        return Transaction(
            transaction_type=self.transaction_type,
            principal=principal,
            data=validated_data,
            metadata=self._metadata.copy()
        )

    def sign(self, additional_signers: Optional[List[Signer]] = None) -> SignedTransaction:
        """
        Build and sign the transaction.

        Args:
            additional_signers: Additional signers to use

        Returns:
            Signed transaction

        Raises:
            TransactionBuilderError: If signing fails
        """
        transaction = self.build()

        # Combine signers
        all_signers = self._signers.copy()
        if additional_signers:
            all_signers.extend(additional_signers)

        if not all_signers:
            raise TransactionBuilderError("No signers available for signing")

        # Calculate transaction hash for signing
        tx_hash = transaction.get_hash()

        # Create signatures
        signatures = []
        for signer in all_signers:
            try:
                signature_data = signer.to_accumulate_signature(
                    tx_hash,
                    transaction_hash=tx_hash.hex()
                )
                signatures.append(signature_data)
            except Exception as e:
                logger.warning(f"Failed to sign with {signer}: {e}")

        if not signatures:
            raise TransactionBuilderError("Failed to create any signatures")

        return SignedTransaction(transaction, signatures)

    def to_dict(self) -> Dict[str, Any]:
        """
        Convert builder state to dictionary.

        Returns:
            Dictionary representation of builder state
        """
        return {
            "type": self.transaction_type.name,
            "data": self._data.copy(),
            "metadata": self._metadata.copy(),
            "signers": [str(signer.get_signer_url()) for signer in self._signers]
        }

    @abstractmethod
    def clone(self) -> TransactionBuilder:
        """
        Create a copy of this builder.

        Returns:
            New builder instance with same state
        """
        pass

    def reset(self) -> TransactionBuilder:
        """
        Reset builder to initial state.

        Returns:
            Self for method chaining
        """
        self._data.clear()
        self._metadata.clear()
        self._signers.clear()
        return self

    def __str__(self) -> str:
        return f"{self.__class__.__name__}({self.transaction_type.name})"

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}(type={self.transaction_type}, fields={len(self._data)})"


class BaseTransactionBuilder(TransactionBuilder):
    """
    Base implementation with common functionality.

    Provides default implementations for common transaction patterns.
    """

    def __init__(self, transaction_type: TransactionType, principal: Optional[AccountUrl] = None):
        """
        Initialize base transaction builder.

        Args:
            transaction_type: Type of transaction
            principal: Optional principal account URL
        """
        super().__init__(transaction_type)
        self._principal = principal

    def set_principal(self, principal: AccountUrl) -> BaseTransactionBuilder:
        """
        Set the principal account URL.

        Args:
            principal: Principal account URL

        Returns:
            Self for method chaining
        """
        self._principal = principal
        return self

    def get_principal(self) -> AccountUrl:
        """Get the principal account URL."""
        if not self._principal:
            raise TransactionBuilderError("Principal account URL not set")
        return self._principal

    def clone(self) -> BaseTransactionBuilder:
        """Create a copy of this builder."""
        cloned = self.__class__(self.transaction_type, self._principal)
        cloned._data = self._data.copy()
        cloned._metadata = self._metadata.copy()
        cloned._signers = self._signers.copy()
        return cloned


# Registry for transaction builders
_BUILDER_REGISTRY: Dict[TransactionType, Type[TransactionBuilder]] = {}


def register_builder(transaction_type: TransactionType, builder_class: Type[TransactionBuilder]):
    """
    Register a transaction builder class.

    Args:
        transaction_type: Transaction type
        builder_class: Builder class
    """
    _BUILDER_REGISTRY[transaction_type] = builder_class
    logger.debug(f"Registered builder {builder_class.__name__} for {transaction_type.name}")


def get_builder(transaction_type: TransactionType) -> Optional[Type[TransactionBuilder]]:
    """
    Get a transaction builder class.

    Args:
        transaction_type: Transaction type

    Returns:
        Builder class if registered
    """
    return _BUILDER_REGISTRY.get(transaction_type)


def create_builder(transaction_type: TransactionType, **kwargs) -> TransactionBuilder:
    """
    Create a transaction builder instance.

    Args:
        transaction_type: Transaction type
        **kwargs: Builder initialization arguments

    Returns:
        Builder instance

    Raises:
        TransactionBuilderError: If builder not found
    """
    builder_class = get_builder(transaction_type)
    if not builder_class:
        raise TransactionBuilderError(f"No builder registered for transaction type: {transaction_type}")

    return builder_class(**kwargs)


def list_registered_builders() -> List[TransactionType]:
    """
    List all registered builder types.

    Returns:
        List of transaction types with registered builders
    """
    return list(_BUILDER_REGISTRY.keys())


# Export main classes and functions
__all__ = [
    "TransactionBuilder",
    "BaseTransactionBuilder",
    "Transaction",
    "SignedTransaction",
    "TransactionBuilderError",
    "register_builder",
    "get_builder",
    "create_builder",
    "list_registered_builders"
]