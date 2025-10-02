"""
Transaction builder registry for Accumulate Protocol.

Provides factory functions and registry for transaction builders.
Enhanced to work with generated transaction models.
"""

from typing import Dict, Type, Optional, Any
from .base import BaseTxBuilder

# Try to import generated types
try:
    from accumulate_client.tx._type_index import lookup_tx_model, TX_MODEL_REGISTRY
    HAS_GENERATED_TYPES = True
except ImportError:
    HAS_GENERATED_TYPES = False
    TX_MODEL_REGISTRY = {}

# Import existing builders from category modules
try:
    from .identity import CreateIdentityBuilder
except ImportError:
    CreateIdentityBuilder = None

try:
    from .tokens import SendTokensBuilder
except ImportError:
    SendTokensBuilder = None

try:
    from .data import CreateDataAccountBuilder, WriteDataBuilder, WriteDataToBuilder, CreateLiteDataAccountBuilder
except ImportError:
    CreateDataAccountBuilder = None
    WriteDataBuilder = None
    WriteDataToBuilder = None
    CreateLiteDataAccountBuilder = None

try:
    from .accounts import AddCreditsBuilder
    from .identity import UpdateKeyPageBuilder, CreateKeyBookBuilder
except ImportError:
    AddCreditsBuilder = None
    UpdateKeyPageBuilder = None
    CreateKeyBookBuilder = None

# Builder registry - maps transaction type names to builder classes
BUILDER_REGISTRY: Dict[str, Type[BaseTxBuilder]] = {}

# Add builders that are available
if CreateIdentityBuilder:
    BUILDER_REGISTRY['CreateIdentity'] = CreateIdentityBuilder
if SendTokensBuilder:
    BUILDER_REGISTRY['SendTokens'] = SendTokensBuilder
if CreateDataAccountBuilder:
    BUILDER_REGISTRY['CreateDataAccount'] = CreateDataAccountBuilder
if WriteDataBuilder:
    BUILDER_REGISTRY['WriteData'] = WriteDataBuilder
if WriteDataToBuilder:
    BUILDER_REGISTRY['WriteDataTo'] = WriteDataToBuilder
if CreateLiteDataAccountBuilder:
    BUILDER_REGISTRY['CreateLiteDataAccount'] = CreateLiteDataAccountBuilder
if AddCreditsBuilder:
    BUILDER_REGISTRY['AddCredits'] = AddCreditsBuilder
if UpdateKeyPageBuilder:
    BUILDER_REGISTRY['UpdateKeyPage'] = UpdateKeyPageBuilder
if CreateKeyBookBuilder:
    BUILDER_REGISTRY['CreateKeyBook'] = CreateKeyBookBuilder

# Auto-discover builders for any transaction types that have generated models
if HAS_GENERATED_TYPES:
    class GeneratedModelBuilder(BaseTxBuilder):
        """Generic builder that works with generated transaction models."""

        def __init__(self, tx_type: str):
            self._tx_type = tx_type
            # Get the generated model class
            self._model_cls = lookup_tx_model(tx_type)
            if not self._model_cls:
                raise ValueError(f"No model found for transaction type: {tx_type}")

            super().__init__()

        @property
        def tx_type(self) -> str:
            """Get the transaction type name."""
            return self._tx_type

        @property
        def body_cls(self):
            """Get the transaction body class."""
            return self._model_cls

        def to_body(self) -> Dict[str, Any]:
            """Create transaction body using generated model."""
            try:
                # Create model instance with current fields (without type - model doesn't define it)
                model_instance = self.body_cls.model_validate(self._fields)

                # Convert to dict for JSON serialization
                body_dict = model_instance.model_dump(exclude_none=True, by_alias=True)

                # Add the type field after model dump (since model doesn't include it)
                body_dict['type'] = self.tx_type

                # Normalize bytes fields to hex strings for JSON
                return self._normalize_bytes_to_hex(body_dict)

            except Exception as e:
                # Fall back to basic dict if model validation fails - include type field
                return {'type': self.tx_type, **self._fields}

        def _normalize_bytes_to_hex(self, data: Any) -> Any:
            """Recursively convert bytes to hex strings for JSON serialization."""
            if isinstance(data, bytes):
                return data.hex()
            elif isinstance(data, dict):
                return {k: self._normalize_bytes_to_hex(v) for k, v in data.items()}
            elif isinstance(data, list):
                return [self._normalize_bytes_to_hex(item) for item in data]
            return data

    # Add generated model builders for transaction types not in manual registry
    for tx_type in TX_MODEL_REGISTRY:
        if tx_type not in BUILDER_REGISTRY:
            # Create a closure to capture tx_type
            def make_builder_class(captured_tx_type: str):
                class DynamicBuilder(GeneratedModelBuilder):
                    def __init__(self):
                        super().__init__(captured_tx_type)
                return DynamicBuilder

            BUILDER_REGISTRY[tx_type] = make_builder_class(tx_type)


def get_builder_for(tx_type: str) -> BaseTxBuilder:
    """
    Get a transaction builder for the specified transaction type.

    Args:
        tx_type: Transaction type name (e.g., 'CreateIdentity', 'SendTokens')

    Returns:
        Transaction builder instance

    Raises:
        ValueError: If transaction type is not supported
    """
    builder_cls = BUILDER_REGISTRY.get(tx_type)
    if not builder_cls:
        raise ValueError(f"Unsupported transaction type: {tx_type}")

    return builder_cls()


def list_transaction_types() -> list[str]:
    """
    Get list of all supported transaction types.

    Returns:
        List of transaction type names
    """
    return list(BUILDER_REGISTRY.keys())


def register_builder(tx_type: str, builder_cls: Type[BaseTxBuilder]) -> None:
    """
    Register a custom transaction builder.

    Args:
        tx_type: Transaction type name
        builder_cls: Builder class
    """
    BUILDER_REGISTRY[tx_type] = builder_cls


__all__ = [
    'BUILDER_REGISTRY',
    'get_builder_for',
    'list_transaction_types',
    'register_builder',
]