"""
Transaction header types with full Go parity.

Provides ExpireOptions, HoldUntilOptions, and TransactionHeader classes
matching the Go implementation in protocol/types_gen.go.

Reference: C:/Accumulate_Stuff/accumulate/protocol/types_gen.go (lines 980-993)
"""

from __future__ import annotations
from typing import Optional, List, Union, Any, Dict
from datetime import datetime, timezone
from pydantic import BaseModel, Field, field_validator, model_validator

from ..runtime.url import AccountUrl


class ExpireOptions(BaseModel):
    """
    Options for transaction expiration.

    Expires the transaction as pending once the condition(s) are met.
    Matches Go type: protocol.ExpireOptions

    Reference: types_gen.go lines 401-405:
        type ExpireOptions struct {
            AtTime    *time.Time `json:"atTime,omitempty"`
        }
    """
    at_time: Optional[datetime] = Field(
        default=None,
        alias="atTime",
        description="Time at which the transaction expires"
    )

    model_config = {
        "populate_by_name": True,
        "json_encoders": {
            datetime: lambda v: v.isoformat() if v else None
        }
    }

    @field_validator('at_time', mode='before')
    @classmethod
    def parse_datetime(cls, v: Any) -> Optional[datetime]:
        """Parse datetime from various formats."""
        if v is None:
            return None
        if isinstance(v, datetime):
            return v
        if isinstance(v, str):
            # Handle ISO format strings
            try:
                # Try standard ISO format
                return datetime.fromisoformat(v.replace('Z', '+00:00'))
            except ValueError:
                pass
            # Try other common formats
            for fmt in ['%Y-%m-%dT%H:%M:%S', '%Y-%m-%d %H:%M:%S', '%Y-%m-%d']:
                try:
                    return datetime.strptime(v, fmt).replace(tzinfo=timezone.utc)
                except ValueError:
                    continue
            raise ValueError(f"Cannot parse datetime from: {v}")
        if isinstance(v, (int, float)):
            # Unix timestamp (seconds or nanoseconds)
            if v > 1e12:  # Likely nanoseconds
                return datetime.fromtimestamp(v / 1e9, tz=timezone.utc)
            return datetime.fromtimestamp(v, tz=timezone.utc)
        raise ValueError(f"Cannot parse datetime from type: {type(v)}")

    @classmethod
    def from_timestamp(cls, timestamp: Union[int, float], unit: str = 'ns') -> ExpireOptions:
        """
        Create ExpireOptions from a Unix timestamp.

        Args:
            timestamp: Unix timestamp value
            unit: Time unit - 's' for seconds, 'ms' for milliseconds, 'ns' for nanoseconds

        Returns:
            ExpireOptions with at_time set
        """
        if unit == 'ns':
            ts_seconds = timestamp / 1e9
        elif unit == 'ms':
            ts_seconds = timestamp / 1e3
        else:  # seconds
            ts_seconds = timestamp

        dt = datetime.fromtimestamp(ts_seconds, tz=timezone.utc)
        return cls(at_time=dt)

    @classmethod
    def from_duration(cls, seconds: int = 0, minutes: int = 0, hours: int = 0, days: int = 0) -> ExpireOptions:
        """
        Create ExpireOptions that expires after a duration from now.

        Args:
            seconds: Number of seconds
            minutes: Number of minutes
            hours: Number of hours
            days: Number of days

        Returns:
            ExpireOptions with at_time set to now + duration
        """
        from datetime import timedelta
        total_seconds = seconds + (minutes * 60) + (hours * 3600) + (days * 86400)
        expire_time = datetime.now(timezone.utc) + timedelta(seconds=total_seconds)
        return cls(at_time=expire_time)

    def to_timestamp_ns(self) -> Optional[int]:
        """Convert at_time to nanosecond timestamp."""
        if self.at_time is None:
            return None
        return int(self.at_time.timestamp() * 1e9)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        if self.at_time is None:
            return {}
        return {"atTime": self.at_time.isoformat()}

    def is_expired(self) -> bool:
        """Check if the expiration time has passed."""
        if self.at_time is None:
            return False
        return datetime.now(timezone.utc) >= self.at_time

    def __bool__(self) -> bool:
        """Returns True if at_time is set."""
        return self.at_time is not None


class HoldUntilOptions(BaseModel):
    """
    Options for holding transaction until conditions met.

    Holds the transaction as pending until the condition(s) are met.
    Matches Go type: protocol.HoldUntilOptions

    Reference: types_gen.go lines 430-434:
        type HoldUntilOptions struct {
            MinorBlock uint64 `json:"minorBlock,omitempty"`
        }
    """
    minor_block: Optional[int] = Field(
        default=None,
        alias="minorBlock",
        ge=0,
        description="Minor block number to hold transaction until"
    )

    model_config = {
        "populate_by_name": True
    }

    @field_validator('minor_block', mode='before')
    @classmethod
    def validate_minor_block(cls, v: Any) -> Optional[int]:
        """Validate minor_block as non-negative integer."""
        if v is None:
            return None
        if isinstance(v, str):
            v = int(v)
        if not isinstance(v, int):
            raise ValueError(f"minor_block must be an integer, got {type(v)}")
        if v < 0:
            raise ValueError(f"minor_block must be non-negative, got {v}")
        return v

    @classmethod
    def at_block(cls, block_number: int) -> HoldUntilOptions:
        """
        Create HoldUntilOptions for a specific block number.

        Args:
            block_number: The minor block number to hold until

        Returns:
            HoldUntilOptions configured for the block
        """
        if block_number < 0:
            raise ValueError("block_number must be non-negative")
        return cls(minor_block=block_number)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        if self.minor_block is None:
            return {}
        return {"minorBlock": self.minor_block}

    def __bool__(self) -> bool:
        """Returns True if minor_block is set."""
        return self.minor_block is not None


class TransactionHeader(BaseModel):
    """
    Complete transaction header matching Go implementation.

    Contains all header fields for Accumulate protocol transactions.
    Matches Go type: protocol.TransactionHeader

    Reference: types_gen.go lines 980-993:
        type TransactionHeader struct {
            Principal   *url.URL         `json:"principal,omitempty" validate:"required"`
            Initiator   [32]byte         `json:"initiator,omitempty" validate:"required"`
            Memo        string           `json:"memo,omitempty"`
            Metadata    []byte           `json:"metadata,omitempty"`
            Expire      *ExpireOptions   `json:"expire,omitempty"`
            HoldUntil   *HoldUntilOptions `json:"holdUntil,omitempty"`
            Authorities []*url.URL       `json:"authorities,omitempty"`
        }
    """
    principal: Union[str, AccountUrl] = Field(
        ...,
        description="Principal account URL (origin of the transaction)"
    )
    initiator: Optional[bytes] = Field(
        default=None,
        description="32-byte initiator hash (typically public key hash)"
    )
    memo: Optional[str] = Field(
        default=None,
        max_length=256,
        description="Optional transaction memo (max 256 characters)"
    )
    metadata: Optional[bytes] = Field(
        default=None,
        description="Optional binary metadata"
    )
    expire: Optional[ExpireOptions] = Field(
        default=None,
        description="Expires the transaction as pending once conditions are met"
    )
    hold_until: Optional[HoldUntilOptions] = Field(
        default=None,
        alias="holdUntil",
        description="Holds the transaction as pending until conditions are met"
    )
    authorities: Optional[List[Union[str, AccountUrl]]] = Field(
        default=None,
        description="Additional authorities that must approve the transaction"
    )
    # Additional envelope-level fields
    timestamp: Optional[int] = Field(
        default=None,
        description="Transaction timestamp in nanoseconds since Unix epoch"
    )

    model_config = {
        "populate_by_name": True,
        "arbitrary_types_allowed": True
    }

    @field_validator('principal', mode='before')
    @classmethod
    def validate_principal(cls, v: Any) -> Union[str, AccountUrl]:
        """Validate and parse principal URL."""
        if isinstance(v, AccountUrl):
            return v
        if isinstance(v, str):
            # Validate it's a proper Accumulate URL
            if not v.startswith('acc://'):
                v = f'acc://{v}'
            return v
        raise ValueError(f"principal must be a string or AccountUrl, got {type(v)}")

    @field_validator('initiator', mode='before')
    @classmethod
    def validate_initiator(cls, v: Any) -> Optional[bytes]:
        """Validate initiator is 32 bytes."""
        if v is None:
            return None
        if isinstance(v, str):
            v = bytes.fromhex(v)
        if isinstance(v, bytes):
            if len(v) != 0 and len(v) != 32:
                raise ValueError(f"initiator must be 32 bytes, got {len(v)}")
            return v if len(v) == 32 else None
        raise ValueError(f"initiator must be bytes or hex string, got {type(v)}")

    @field_validator('metadata', mode='before')
    @classmethod
    def validate_metadata(cls, v: Any) -> Optional[bytes]:
        """Validate and convert metadata to bytes."""
        if v is None:
            return None
        if isinstance(v, str):
            return bytes.fromhex(v)
        if isinstance(v, bytes):
            return v
        raise ValueError(f"metadata must be bytes or hex string, got {type(v)}")

    @field_validator('authorities', mode='before')
    @classmethod
    def validate_authorities(cls, v: Any) -> Optional[List[Union[str, AccountUrl]]]:
        """Validate authorities list."""
        if v is None:
            return None
        if not isinstance(v, list):
            raise ValueError(f"authorities must be a list, got {type(v)}")
        validated = []
        for auth in v:
            if isinstance(auth, AccountUrl):
                validated.append(auth)
            elif isinstance(auth, str):
                if not auth.startswith('acc://'):
                    auth = f'acc://{auth}'
                validated.append(auth)
            else:
                raise ValueError(f"authority must be string or AccountUrl, got {type(auth)}")
        return validated if validated else None

    @classmethod
    def create(
        cls,
        principal: Union[str, AccountUrl],
        initiator: Optional[bytes] = None,
        memo: Optional[str] = None,
        metadata: Optional[bytes] = None,
        expire: Optional[ExpireOptions] = None,
        hold_until: Optional[HoldUntilOptions] = None,
        authorities: Optional[List[Union[str, AccountUrl]]] = None,
        timestamp: Optional[int] = None
    ) -> TransactionHeader:
        """
        Factory method for creating a TransactionHeader.

        Args:
            principal: Principal account URL
            initiator: 32-byte initiator hash
            memo: Optional memo string
            metadata: Optional binary metadata
            expire: Expiration options
            hold_until: Hold until options
            authorities: Additional required authorities
            timestamp: Transaction timestamp (nanoseconds)

        Returns:
            Configured TransactionHeader instance
        """
        if timestamp is None:
            timestamp = int(datetime.now(timezone.utc).timestamp() * 1e9)

        return cls(
            principal=principal,
            initiator=initiator,
            memo=memo,
            metadata=metadata,
            expire=expire,
            hold_until=hold_until,
            authorities=authorities,
            timestamp=timestamp
        )

    def to_dict(self, by_alias: bool = True, exclude_none: bool = True) -> Dict[str, Any]:
        """
        Convert to dictionary for JSON serialization.

        Args:
            by_alias: Use JSON aliases (camelCase)
            exclude_none: Exclude None values

        Returns:
            Dictionary representation
        """
        result = {}

        # Principal - always include
        if isinstance(self.principal, AccountUrl):
            result['principal'] = str(self.principal)
        else:
            result['principal'] = self.principal

        # Timestamp
        if self.timestamp is not None:
            result['timestamp'] = self.timestamp

        # Initiator
        if self.initiator is not None:
            result['initiator'] = self.initiator.hex()

        # Memo
        if self.memo is not None:
            result['memo'] = self.memo

        # Metadata
        if self.metadata is not None:
            result['metadata'] = self.metadata.hex()

        # Expire
        if self.expire is not None and self.expire:
            expire_dict = self.expire.to_dict()
            if expire_dict:
                result['expire'] = expire_dict

        # HoldUntil
        if self.hold_until is not None and self.hold_until:
            key = 'holdUntil' if by_alias else 'hold_until'
            hold_dict = self.hold_until.to_dict()
            if hold_dict:
                result[key] = hold_dict

        # Authorities
        if self.authorities is not None and self.authorities:
            result['authorities'] = [
                str(auth) if isinstance(auth, AccountUrl) else auth
                for auth in self.authorities
            ]

        return result

    def with_expire(self, expire: ExpireOptions) -> TransactionHeader:
        """Return a copy with new expire options."""
        data = self.model_dump(exclude_none=True)
        data['expire'] = expire
        return TransactionHeader(**data)

    def with_hold_until(self, hold_until: HoldUntilOptions) -> TransactionHeader:
        """Return a copy with new hold_until options."""
        data = self.model_dump(exclude_none=True)
        data['hold_until'] = hold_until
        return TransactionHeader(**data)

    def with_memo(self, memo: str) -> TransactionHeader:
        """Return a copy with new memo."""
        data = self.model_dump(exclude_none=True)
        data['memo'] = memo
        return TransactionHeader(**data)

    def with_metadata(self, metadata: bytes) -> TransactionHeader:
        """Return a copy with new metadata."""
        data = self.model_dump(exclude_none=True)
        data['metadata'] = metadata
        return TransactionHeader(**data)

    def with_authorities(self, authorities: List[Union[str, AccountUrl]]) -> TransactionHeader:
        """Return a copy with new authorities list."""
        data = self.model_dump(exclude_none=True)
        data['authorities'] = authorities
        return TransactionHeader(**data)

    def add_authority(self, authority: Union[str, AccountUrl]) -> TransactionHeader:
        """Return a copy with an additional authority."""
        current = list(self.authorities) if self.authorities else []
        current.append(authority)
        return self.with_authorities(current)


class TransactionEnvelope(BaseModel):
    """
    Complete transaction envelope containing header, body, and signatures.

    This is the top-level structure for a signed Accumulate transaction.
    """
    header: TransactionHeader = Field(
        ...,
        description="Transaction header"
    )
    body: Dict[str, Any] = Field(
        ...,
        description="Transaction body"
    )
    signatures: Optional[List[Dict[str, Any]]] = Field(
        default=None,
        description="List of signatures"
    )

    model_config = {
        "populate_by_name": True,
        "arbitrary_types_allowed": True
    }

    @classmethod
    def create(
        cls,
        header: TransactionHeader,
        body: Dict[str, Any],
        signatures: Optional[List[Dict[str, Any]]] = None
    ) -> TransactionEnvelope:
        """Factory method for creating a TransactionEnvelope."""
        return cls(header=header, body=body, signatures=signatures)

    def to_dict(self, by_alias: bool = True, exclude_none: bool = True) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        result = {
            'header': self.header.to_dict(by_alias=by_alias, exclude_none=exclude_none),
            'body': self.body
        }
        if self.signatures:
            result['signatures'] = self.signatures
        return result

    def add_signature(self, signature: Dict[str, Any]) -> TransactionEnvelope:
        """Return a copy with an additional signature."""
        current = list(self.signatures) if self.signatures else []
        current.append(signature)
        return TransactionEnvelope(
            header=self.header,
            body=self.body,
            signatures=current
        )


# Helper functions for common header creation patterns

def create_simple_header(
    principal: Union[str, AccountUrl],
    memo: Optional[str] = None,
    timestamp: Optional[int] = None
) -> Dict[str, Any]:
    """
    Create a simple transaction header dict for basic transactions.

    Args:
        principal: Principal account URL
        memo: Optional memo
        timestamp: Optional timestamp (nanoseconds)

    Returns:
        Header dictionary
    """
    if timestamp is None:
        timestamp = int(datetime.now(timezone.utc).timestamp() * 1e9)

    header = {
        'principal': str(principal) if isinstance(principal, AccountUrl) else principal,
        'timestamp': timestamp
    }

    if memo:
        header['memo'] = memo

    return header


def create_expiring_header(
    principal: Union[str, AccountUrl],
    expire_in_seconds: int,
    memo: Optional[str] = None,
    timestamp: Optional[int] = None
) -> Dict[str, Any]:
    """
    Create a transaction header that expires after a duration.

    Args:
        principal: Principal account URL
        expire_in_seconds: Number of seconds until expiration
        memo: Optional memo
        timestamp: Optional timestamp (nanoseconds)

    Returns:
        Header dictionary with expire options
    """
    header = create_simple_header(principal, memo, timestamp)
    header['expire'] = ExpireOptions.from_duration(seconds=expire_in_seconds).to_dict()
    return header


def create_scheduled_header(
    principal: Union[str, AccountUrl],
    execute_at_block: int,
    memo: Optional[str] = None,
    timestamp: Optional[int] = None
) -> Dict[str, Any]:
    """
    Create a transaction header that executes at a specific block.

    Args:
        principal: Principal account URL
        execute_at_block: Minor block number to execute at
        memo: Optional memo
        timestamp: Optional timestamp (nanoseconds)

    Returns:
        Header dictionary with holdUntil options
    """
    header = create_simple_header(principal, memo, timestamp)
    header['holdUntil'] = HoldUntilOptions.at_block(execute_at_block).to_dict()
    return header


def create_multisig_header(
    principal: Union[str, AccountUrl],
    additional_authorities: List[Union[str, AccountUrl]],
    memo: Optional[str] = None,
    timestamp: Optional[int] = None
) -> Dict[str, Any]:
    """
    Create a transaction header requiring multiple authorities.

    Args:
        principal: Principal account URL
        additional_authorities: List of additional authority URLs
        memo: Optional memo
        timestamp: Optional timestamp (nanoseconds)

    Returns:
        Header dictionary with authorities
    """
    header = create_simple_header(principal, memo, timestamp)
    header['authorities'] = [
        str(auth) if isinstance(auth, AccountUrl) else auth
        for auth in additional_authorities
    ]
    return header


__all__ = [
    # Core classes
    "ExpireOptions",
    "HoldUntilOptions",
    "TransactionHeader",
    "TransactionEnvelope",
    # Helper functions
    "create_simple_header",
    "create_expiring_header",
    "create_scheduled_header",
    "create_multisig_header",
]
