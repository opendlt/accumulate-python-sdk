"""
Base transaction builder for Accumulate Protocol.

Provides the foundation for all transaction builders with exact parity
to the Go implementation.

Reference: C:/Accumulate_Stuff/accumulate/protocol/transaction.go
"""

from __future__ import annotations
from typing import TypeVar, Generic, Type, Dict, Any, Optional, List, Union
from abc import ABC, abstractmethod
from datetime import datetime, timezone

from ...runtime.url import AccountUrl
from ...runtime.errors import AccumulateError
from ..codec import to_canonical_json, to_binary, hash_transaction
from ..validation import validate_tx_body, ValidationError
from ..fees import estimate_for_body, NetworkParams
from ..header import ExpireOptions, HoldUntilOptions, TransactionHeader

BodyT = TypeVar('BodyT')


class BuilderError(AccumulateError):
    """Transaction builder specific errors."""
    pass


class BaseTxBuilder(Generic[BodyT], ABC):
    """
    Base class for all transaction builders.

    Generic over BodyT = the generated transaction body type.
    """

    def __init__(self):
        """Initialize the builder."""
        self._fields: Dict[str, Any] = {}

    @property
    @abstractmethod
    def tx_type(self) -> str:
        """Get the transaction type name."""
        pass

    @property
    @abstractmethod
    def body_cls(self) -> Type[BodyT]:
        """Get the transaction body class."""
        pass

    def with_field(self, name: str, value: Any) -> BaseTxBuilder[BodyT]:
        """
        Set a field value (chainable).

        Args:
            name: Field name
            value: Field value

        Returns:
            Self for chaining
        """
        self._fields[name] = value
        return self

    def get_field(self, name: str, default: Any = None) -> Any:
        """
        Get a field value.

        Args:
            name: Field name
            default: Default value if not set

        Returns:
            Field value
        """
        return self._fields.get(name, default)

    def validate(self) -> None:
        """
        Validate the current transaction body.

        Raises:
            ValidationError: If validation fails with precise message list
        """
        # For generated models, use enhanced builder validation which handles both
        # builder fields and generated model validation properly
        if hasattr(self.body_cls, 'model_fields') and self.body_cls.model_fields:
            from accumulate_client.tx.validation import validate_builder_fields
            validate_builder_fields(self)
        else:
            # For legacy builders with no schema, also use enhanced validation
            from accumulate_client.tx.validation import validate_builder_fields
            validate_builder_fields(self)

    def to_body(self) -> BodyT:
        """
        Create the transaction body instance.

        Returns:
            Generated body instance or dict for JSON serialization

        Raises:
            BuilderError: If body creation fails
        """
        try:
            # Add the transaction type to fields
            fields_with_type = {'type': self.tx_type, **self._fields}

            # If body class has model fields (generated model), create instance
            if hasattr(self.body_cls, 'model_fields') and self.body_cls.model_fields:
                # Generated model with actual fields
                if hasattr(self.body_cls, 'model_validate'):
                    # Pydantic v2
                    model_instance = self.body_cls.model_validate(fields_with_type)
                    # Return dict for JSON serialization
                    body_dict = model_instance.model_dump(exclude_none=True, by_alias=True)
                    return self._normalize_bytes_to_hex(body_dict)
                elif hasattr(self.body_cls, 'parse_obj'):
                    # Pydantic v1
                    model_instance = self.body_cls.parse_obj(fields_with_type)
                    body_dict = model_instance.dict(exclude_none=True)
                    return self._normalize_bytes_to_hex(body_dict)
                else:
                    # Plain class
                    return self.body_cls(**fields_with_type)
            else:
                # Empty body class or legacy - return dict with type
                return dict(fields_with_type)

        except Exception as e:
            raise BuilderError(f"Failed to create {self.tx_type} body: {e}")

    def _normalize_bytes_to_hex(self, data: Any) -> Any:
        """Recursively convert bytes to hex strings for JSON serialization."""
        if isinstance(data, bytes):
            return data.hex()
        elif isinstance(data, dict):
            return {k: self._normalize_bytes_to_hex(v) for k, v in data.items()}
        elif isinstance(data, list):
            return [self._normalize_bytes_to_hex(item) for item in data]
        return data

    def estimate_fees(self, network_params: Optional[Dict[str, Any]] = None) -> int:
        """
        Estimate fees for this transaction.

        Args:
            network_params: Network parameters (optional)

        Returns:
            Estimated total fee in credits
        """
        try:
            # Try the new fee calculation system first
            from ...utils.fees import estimate_fees
            tx_body = self.to_body()
            fee_breakdown = estimate_fees(self.tx_type, tx_body, network_params)

            # Always return just the total fee as int for compatibility
            return fee_breakdown.get("total", fee_breakdown.get("transaction", 100))

        except (ImportError, AttributeError):
            try:
                # Fall back to the existing fee system
                from ..fees import estimate_for_body, NetworkParams
                if network_params:
                    # Convert dict to NetworkParams object
                    params = NetworkParams(
                        base_fee=network_params.get('baseRate', 100),
                        data_entry_fee=network_params.get('dataRate', 10),
                        signature_fee=network_params.get('creditRate', 1000)
                    )
                else:
                    params = NetworkParams()

                tx_body = self.to_body()
                total_fee = estimate_for_body(tx_body, params)
                return total_fee
            except Exception:
                # Ultimate fallback
                return 101

    def estimate_fees_detailed(self, network_params: Optional[Dict[str, Any]] = None) -> Dict[str, int]:
        """
        Estimate fees for this transaction with detailed breakdown.

        Args:
            network_params: Network parameters (optional)

        Returns:
            Dictionary with fee breakdown including transaction and signature fees
        """
        try:
            # Try the new fee calculation system first
            from ...utils.fees import estimate_fees
            tx_body = self.to_body()
            return estimate_fees(self.tx_type, tx_body, network_params)
        except (ImportError, AttributeError):
            try:
                # Fall back to the existing fee system
                from ..fees import estimate_for_body, NetworkParams
                if network_params:
                    # Convert dict to NetworkParams object
                    params = NetworkParams(
                        base_fee=network_params.get('baseRate', 100),
                        data_entry_fee=network_params.get('dataRate', 10),
                        signature_fee=network_params.get('creditRate', 1000)
                    )
                else:
                    params = NetworkParams()

                tx_body = self.to_body()
                total_fee = estimate_for_body(tx_body, params)
                return {"transaction": total_fee, "signature": 1, "total": total_fee + 1}
            except Exception:
                # Ultimate fallback
                return {"transaction": 100, "signature": 1, "total": 101}

    def _restore_field_types(self, fields: Dict[str, Any]) -> Dict[str, Any]:
        """Restore correct field types based on model schema when loading from dict."""
        # If body class has model fields (generated model), use schema to restore types
        if hasattr(self.body_cls, 'model_fields') and self.body_cls.model_fields:
            restored_fields = {}
            for field_name, field_value in fields.items():
                field_info = self.body_cls.model_fields.get(field_name)
                if field_info and field_info.annotation:
                    # Check if this should be bytes but is currently a hex string
                    is_bytes_field = field_info.annotation == bytes
                    is_list_of_bytes = (hasattr(field_info.annotation, '__origin__') and
                                       field_info.annotation.__origin__ == list and
                                       len(field_info.annotation.__args__) > 0 and
                                       field_info.annotation.__args__[0] == bytes)

                    if is_bytes_field or is_list_of_bytes:
                        try:
                            if is_bytes_field and isinstance(field_value, str) and len(field_value) % 2 == 0:
                                # Single bytes field - convert hex string back to bytes
                                restored_fields[field_name] = bytes.fromhex(field_value)
                                continue
                            elif is_list_of_bytes and isinstance(field_value, list):
                                # List of bytes - convert each hex string back to bytes
                                restored_list = []
                                for item in field_value:
                                    if isinstance(item, str) and len(item) % 2 == 0:
                                        restored_list.append(bytes.fromhex(item))
                                    else:
                                        restored_list.append(item)
                                restored_fields[field_name] = restored_list
                                continue
                        except ValueError:
                            # Not a valid hex string, keep as is
                            pass

                # Keep original value if no conversion needed
                restored_fields[field_name] = field_value
            return restored_fields

        # No schema available, return as-is
        return fields

    def to_canonical_json(self) -> bytes:
        """
        Convert to canonical JSON bytes.

        Returns:
            Canonical JSON representation
        """
        body = self.to_body()
        return to_canonical_json(body)

    def to_binary(self) -> bytes:
        """
        Convert to binary bytes.

        Returns:
            Binary representation
        """
        body = self.to_body()
        return to_binary(body)


    def build_envelope(
        self,
        origin: Union[str, AccountUrl],
        timestamp: Optional[int] = None,
        memo: Optional[str] = None,
        metadata: Optional[bytes] = None,
        expire: Optional[ExpireOptions] = None,
        hold_until: Optional[HoldUntilOptions] = None,
        authorities: Optional[List[Union[str, AccountUrl]]] = None,
        signer_hint: Optional[str] = None,
        initiator: Optional[bytes] = None,
        **header_kwargs
    ) -> Any:
        """
        Build a complete transaction envelope with full header support.

        Matches Go protocol.TransactionHeader with all fields:
        - principal (origin)
        - initiator
        - memo
        - metadata
        - expire (ExpireOptions)
        - holdUntil (HoldUntilOptions)
        - authorities

        Args:
            origin: Origin/principal account URL
            timestamp: Transaction timestamp (UTC nanoseconds, defaults to now)
            memo: Optional transaction memo (max 256 characters)
            metadata: Optional binary metadata
            expire: Expiration options (ExpireOptions) - expires transaction when conditions met
            hold_until: Hold options (HoldUntilOptions) - holds transaction until conditions met
            authorities: Additional authorities that must approve the transaction
            signer_hint: Optional signer hint
            initiator: Optional 32-byte initiator hash
            **header_kwargs: Additional header fields

        Returns:
            Generated transaction envelope/header object matching Go protocol.Transaction

        Raises:
            BuilderError: If envelope creation fails
        """
        # Default timestamp to current time (nanoseconds since Unix epoch)
        if timestamp is None:
            timestamp = int(datetime.now(timezone.utc).timestamp() * 1_000_000_000)

        # Normalize origin to string
        if isinstance(origin, AccountUrl):
            principal_str = str(origin)
        else:
            principal_str = origin

        # Create header fields with principal as the primary field name (Go parity)
        header_fields = {
            'principal': principal_str,
            'timestamp': timestamp,
            **header_kwargs
        }

        # Add optional fields if provided

        # Memo - string, max 256 chars
        if memo is not None:
            if len(memo) > 256:
                raise BuilderError(f"Memo exceeds maximum length of 256 characters: {len(memo)}")
            header_fields['memo'] = memo

        # Metadata - binary data as hex string
        if metadata is not None:
            header_fields['metadata'] = metadata.hex() if isinstance(metadata, bytes) else metadata

        # Expire options - for transaction expiration
        if expire is not None:
            if isinstance(expire, ExpireOptions):
                expire_dict = expire.to_dict()
                if expire_dict:  # Only add if not empty
                    header_fields['expire'] = expire_dict
            elif isinstance(expire, dict):
                header_fields['expire'] = expire
            else:
                raise BuilderError(f"expire must be ExpireOptions or dict, got {type(expire)}")

        # HoldUntil options - for holding transaction until conditions met
        if hold_until is not None:
            if isinstance(hold_until, HoldUntilOptions):
                hold_dict = hold_until.to_dict()
                if hold_dict:  # Only add if not empty
                    header_fields['holdUntil'] = hold_dict
            elif isinstance(hold_until, dict):
                header_fields['holdUntil'] = hold_until
            else:
                raise BuilderError(f"hold_until must be HoldUntilOptions or dict, got {type(hold_until)}")

        # Authorities - list of additional required authorities
        if authorities is not None:
            auth_list = []
            for auth in authorities:
                if isinstance(auth, AccountUrl):
                    auth_list.append(str(auth))
                else:
                    auth_list.append(auth)
            if auth_list:
                header_fields['authorities'] = auth_list

        # Signer hint - optional hint for signature routing
        if signer_hint is not None:
            header_fields['signerHint'] = signer_hint

        # Initiator - 32-byte hash (typically public key hash)
        if initiator is not None:
            if isinstance(initiator, bytes):
                if len(initiator) != 32:
                    raise BuilderError(f"initiator must be 32 bytes, got {len(initiator)}")
                header_fields['initiator'] = initiator.hex()
            else:
                header_fields['initiator'] = initiator

        # Create body
        body = self.to_body()

        # Create transaction structure matching Go protocol.Transaction
        # The Transaction struct contains header and body, signatures are handled separately
        transaction = {
            'header': header_fields,
            'body': body
        }

        return transaction

    def build_envelope_with_header(
        self,
        header: TransactionHeader
    ) -> Any:
        """
        Build a complete transaction envelope using a TransactionHeader object.

        This provides a more structured approach to building envelopes.

        Args:
            header: TransactionHeader object with all header fields configured

        Returns:
            Generated transaction envelope matching Go protocol.Transaction

        Raises:
            BuilderError: If envelope creation fails
        """
        # Convert header to dict format
        header_dict = header.to_dict(by_alias=True, exclude_none=True)

        # Create body
        body = self.to_body()

        # Create transaction structure
        transaction = {
            'header': header_dict,
            'body': body
        }

        return transaction

    @classmethod
    def from_model(cls, body: BodyT) -> BaseTxBuilder[BodyT]:
        """
        Create a builder from an existing body model.

        Args:
            body: Existing transaction body

        Returns:
            Builder instance

        Raises:
            BuilderError: If conversion fails
        """
        builder = cls()

        try:
            # Extract fields from body
            if isinstance(body, dict):
                # Already a dict (from to_body() output)
                fields = body
                # Need to restore correct types based on model schema
                fields = builder._restore_field_types(fields)
            elif hasattr(body, 'model_dump'):
                # Pydantic v2
                fields = body.model_dump(exclude_none=True)
            elif hasattr(body, 'dict'):
                # Pydantic v1
                fields = body.dict(exclude_none=True)
            elif hasattr(body, '__dict__'):
                # Try to get fields from __dict__
                fields = {k: v for k, v in body.__dict__.items() if not k.startswith('_')}
            else:
                # Unknown body type
                raise BuilderError(f"Unsupported body type: {type(body)}")

            # Set fields in builder
            for name, value in fields.items():
                builder.with_field(name, value)

            return builder

        except Exception as e:
            raise BuilderError(f"Failed to create builder from model: {e}")

    def clone(self) -> BaseTxBuilder[BodyT]:
        """
        Create a copy of this builder.

        Returns:
            New builder instance with same state
        """
        cloned = self.__class__()
        cloned._fields = self._fields.copy()
        return cloned

    def reset(self) -> BaseTxBuilder[BodyT]:
        """
        Reset builder to initial state.

        Returns:
            Self for chaining
        """
        self._fields.clear()
        return self

    def __str__(self) -> str:
        return f"{self.__class__.__name__}({self.tx_type}, {len(self._fields)} fields)"

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}(type='{self.tx_type}', fields={list(self._fields.keys())})"


__all__ = [
    "BaseTxBuilder",
    "BuilderError",
    # Re-exported from header module for convenience
    "ExpireOptions",
    "HoldUntilOptions",
    "TransactionHeader",
]