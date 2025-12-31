"""
Build context for transaction construction.

Provides BuildContext class for structured transaction building with
proper defaults, matching patterns from the Dart SDK and Go implementation.

The BuildContext encapsulates all header fields needed for building
transaction envelopes, making it easy to construct transactions with
consistent settings.
"""

from __future__ import annotations
from typing import Optional, List, Union, Any, Dict, TYPE_CHECKING
from datetime import datetime, timezone, timedelta
from pydantic import BaseModel, Field, field_validator, model_validator
from copy import deepcopy

from .header import ExpireOptions, HoldUntilOptions, TransactionHeader
from ..runtime.url import AccountUrl

if TYPE_CHECKING:
    from ..signers.signer import Signer


class BuildContext(BaseModel):
    """
    Context for building transactions with proper defaults.

    BuildContext encapsulates all the header fields needed for transaction
    construction, providing a convenient way to build multiple transactions
    with consistent settings.

    Example usage:
        ```python
        # Create a context for an identity
        ctx = BuildContext.now("acc://my-adi.acme")

        # Build a transaction
        envelope = builder.build_envelope(
            origin=ctx.principal,
            timestamp=ctx.timestamp,
            memo=ctx.memo,
            expire=ctx.expire,
            hold_until=ctx.hold_until,
            authorities=ctx.authorities
        )

        # Or use the context directly
        envelope = ctx.build_envelope(body)
        ```
    """

    principal: str = Field(
        ...,
        description="Principal account URL (origin of the transaction)"
    )
    timestamp: int = Field(
        default_factory=lambda: int(datetime.now(timezone.utc).timestamp() * 1_000_000_000),
        description="Transaction timestamp in nanoseconds since Unix epoch"
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
        description="Expiration options"
    )
    hold_until: Optional[HoldUntilOptions] = Field(
        default=None,
        alias="holdUntil",
        description="Hold until options"
    )
    authorities: Optional[List[str]] = Field(
        default=None,
        description="Additional authorities that must approve"
    )
    initiator: Optional[bytes] = Field(
        default=None,
        description="32-byte initiator hash"
    )

    model_config = {
        "populate_by_name": True,
        "arbitrary_types_allowed": True
    }

    @field_validator('principal', mode='before')
    @classmethod
    def validate_principal(cls, v: Any) -> str:
        """Validate and normalize principal URL."""
        if isinstance(v, AccountUrl):
            return str(v)
        if isinstance(v, str):
            if v and not v.startswith('acc://'):
                v = f'acc://{v}'
            return v
        raise ValueError(f"principal must be a string or AccountUrl, got {type(v)}")

    @field_validator('metadata', mode='before')
    @classmethod
    def validate_metadata(cls, v: Any) -> Optional[bytes]:
        """Validate and convert metadata to bytes."""
        if v is None:
            return None
        if isinstance(v, bytes):
            return v
        if isinstance(v, str):
            return bytes.fromhex(v)
        raise ValueError(f"metadata must be bytes or hex string, got {type(v)}")

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

    @field_validator('authorities', mode='before')
    @classmethod
    def validate_authorities(cls, v: Any) -> Optional[List[str]]:
        """Validate and normalize authorities list."""
        if v is None:
            return None
        if not isinstance(v, list):
            raise ValueError(f"authorities must be a list, got {type(v)}")
        result = []
        for auth in v:
            if isinstance(auth, AccountUrl):
                result.append(str(auth))
            elif isinstance(auth, str):
                if not auth.startswith('acc://'):
                    auth = f'acc://{auth}'
                result.append(auth)
            else:
                raise ValueError(f"authority must be string or AccountUrl, got {type(auth)}")
        return result if result else None

    # =========================================================================
    # Factory Methods
    # =========================================================================

    @classmethod
    def now(
        cls,
        principal: Union[str, AccountUrl],
        memo: Optional[str] = None,
        metadata: Optional[bytes] = None,
        expire: Optional[ExpireOptions] = None,
        hold_until: Optional[HoldUntilOptions] = None,
        authorities: Optional[List[Union[str, AccountUrl]]] = None
    ) -> BuildContext:
        """
        Create a BuildContext with current timestamp.

        Args:
            principal: Principal account URL
            memo: Optional transaction memo
            metadata: Optional binary metadata
            expire: Expiration options
            hold_until: Hold until options
            authorities: Additional required authorities

        Returns:
            BuildContext with current timestamp
        """
        return cls(
            principal=principal,
            memo=memo,
            metadata=metadata,
            expire=expire,
            hold_until=hold_until,
            authorities=authorities
        )

    @classmethod
    def at_timestamp(
        cls,
        principal: Union[str, AccountUrl],
        timestamp: int,
        memo: Optional[str] = None,
        metadata: Optional[bytes] = None
    ) -> BuildContext:
        """
        Create a BuildContext with a specific timestamp.

        Args:
            principal: Principal account URL
            timestamp: Timestamp in nanoseconds since Unix epoch
            memo: Optional transaction memo
            metadata: Optional binary metadata

        Returns:
            BuildContext with specified timestamp
        """
        return cls(
            principal=principal,
            timestamp=timestamp,
            memo=memo,
            metadata=metadata
        )

    @classmethod
    def expiring(
        cls,
        principal: Union[str, AccountUrl],
        expire_in_seconds: int,
        memo: Optional[str] = None
    ) -> BuildContext:
        """
        Create a BuildContext that expires after a duration.

        Args:
            principal: Principal account URL
            expire_in_seconds: Seconds until expiration
            memo: Optional transaction memo

        Returns:
            BuildContext with expiration set
        """
        expire = ExpireOptions.from_duration(seconds=expire_in_seconds)
        return cls(
            principal=principal,
            memo=memo,
            expire=expire
        )

    @classmethod
    def scheduled(
        cls,
        principal: Union[str, AccountUrl],
        execute_at_block: int,
        memo: Optional[str] = None
    ) -> BuildContext:
        """
        Create a BuildContext that executes at a specific block.

        Args:
            principal: Principal account URL
            execute_at_block: Minor block number to execute at
            memo: Optional transaction memo

        Returns:
            BuildContext with holdUntil set
        """
        hold_until = HoldUntilOptions.at_block(execute_at_block)
        return cls(
            principal=principal,
            memo=memo,
            hold_until=hold_until
        )

    @classmethod
    def requiring_authorities(
        cls,
        principal: Union[str, AccountUrl],
        authorities: List[Union[str, AccountUrl]],
        memo: Optional[str] = None
    ) -> BuildContext:
        """
        Create a BuildContext requiring additional authorities.

        This is a factory method for creating a context with pre-set authorities.
        For modifying an existing context, use the instance method with_authorities().

        Args:
            principal: Principal account URL
            authorities: List of additional authority URLs
            memo: Optional transaction memo

        Returns:
            BuildContext with authorities set
        """
        return cls(
            principal=principal,
            memo=memo,
            authorities=authorities
        )

    @classmethod
    def from_signer(
        cls,
        signer: Signer,
        memo: Optional[str] = None
    ) -> BuildContext:
        """
        Create a BuildContext from a signer.

        Uses the signer's URL as the principal and sets the initiator
        from the signer's public key hash.

        Args:
            signer: Signer to use
            memo: Optional transaction memo

        Returns:
            BuildContext configured from signer
        """
        return cls(
            principal=str(signer.get_signer_url()),
            memo=memo,
            initiator=signer.get_public_key_hash()
        )

    # =========================================================================
    # Instance Methods
    # =========================================================================

    def to_header_dict(self) -> Dict[str, Any]:
        """
        Convert to header dictionary for envelope construction.

        Returns:
            Dictionary with header fields for transaction envelope
        """
        result: Dict[str, Any] = {
            "principal": self.principal,
            "timestamp": self.timestamp
        }

        if self.memo:
            result["memo"] = self.memo

        if self.metadata:
            result["metadata"] = self.metadata.hex()

        if self.initiator:
            result["initiator"] = self.initiator.hex()

        if self.expire and self.expire.at_time:
            result["expire"] = self.expire.to_dict()

        if self.hold_until and self.hold_until.minor_block is not None:
            result["holdUntil"] = self.hold_until.to_dict()

        if self.authorities:
            result["authorities"] = self.authorities

        return result

    def to_header(self) -> TransactionHeader:
        """
        Convert to a TransactionHeader object.

        Returns:
            TransactionHeader instance
        """
        return TransactionHeader(
            principal=self.principal,
            initiator=self.initiator,
            memo=self.memo,
            metadata=self.metadata,
            expire=self.expire,
            hold_until=self.hold_until,
            authorities=self.authorities,
            timestamp=self.timestamp
        )

    def build_envelope(self, body: Dict[str, Any]) -> Dict[str, Any]:
        """
        Build a complete transaction envelope.

        Args:
            body: Transaction body dictionary

        Returns:
            Complete transaction envelope with header and body
        """
        return {
            "header": self.to_header_dict(),
            "body": body
        }

    def build_signed_envelope(
        self,
        body: Dict[str, Any],
        signature: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Build a signed transaction envelope.

        Args:
            body: Transaction body dictionary
            signature: Signature dictionary

        Returns:
            Complete envelope with transaction and signature
        """
        transaction = self.build_envelope(body)
        return {
            "transaction": transaction,
            "signatures": [signature]
        }

    def refresh_timestamp(self) -> BuildContext:
        """
        Return a copy with refreshed timestamp.

        Returns:
            New BuildContext with current timestamp
        """
        return self.model_copy(update={
            "timestamp": int(datetime.now(timezone.utc).timestamp() * 1_000_000_000)
        })

    def with_memo(self, memo: str) -> BuildContext:
        """Return a copy with new memo."""
        return self.model_copy(update={"memo": memo})

    def with_metadata(self, metadata: bytes) -> BuildContext:
        """Return a copy with new metadata."""
        return self.model_copy(update={"metadata": metadata})

    def with_expire(self, expire: ExpireOptions) -> BuildContext:
        """Return a copy with new expire options."""
        return self.model_copy(update={"expire": expire})

    def with_hold_until(self, hold_until: HoldUntilOptions) -> BuildContext:
        """Return a copy with new hold_until options."""
        return self.model_copy(update={"hold_until": hold_until})

    def with_authorities(self, authorities: List[Union[str, AccountUrl]]) -> BuildContext:
        """Return a copy with new authorities list."""
        auth_strs = [str(a) if isinstance(a, AccountUrl) else a for a in authorities]
        return self.model_copy(update={"authorities": auth_strs})

    def add_authority(self, authority: Union[str, AccountUrl]) -> BuildContext:
        """Return a copy with an additional authority."""
        current = list(self.authorities) if self.authorities else []
        auth_str = str(authority) if isinstance(authority, AccountUrl) else authority
        current.append(auth_str)
        return self.model_copy(update={"authorities": current})

    def with_initiator(self, initiator: bytes) -> BuildContext:
        """Return a copy with new initiator."""
        return self.model_copy(update={"initiator": initiator})

    def get_timestamp_datetime(self) -> datetime:
        """Get timestamp as datetime object."""
        return datetime.fromtimestamp(self.timestamp / 1e9, tz=timezone.utc)

    def is_expired(self) -> bool:
        """Check if the context's expiration has passed."""
        if self.expire is None or self.expire.at_time is None:
            return False
        return self.expire.is_expired()

    def time_until_expiry(self) -> Optional[timedelta]:
        """Get time remaining until expiration."""
        if self.expire is None or self.expire.at_time is None:
            return None
        now = datetime.now(timezone.utc)
        return self.expire.at_time - now


class TransactionContext(BuildContext):
    """
    Extended BuildContext with transaction body support.

    Adds the ability to store the transaction body along with header fields,
    providing a complete transaction context.
    """

    body: Optional[Dict[str, Any]] = Field(
        default=None,
        description="Transaction body"
    )

    @classmethod
    def create(
        cls,
        principal: Union[str, AccountUrl],
        body: Dict[str, Any],
        memo: Optional[str] = None,
        expire: Optional[ExpireOptions] = None,
        hold_until: Optional[HoldUntilOptions] = None,
        authorities: Optional[List[Union[str, AccountUrl]]] = None
    ) -> TransactionContext:
        """
        Create a TransactionContext with body.

        Args:
            principal: Principal account URL
            body: Transaction body
            memo: Optional memo
            expire: Expiration options
            hold_until: Hold until options
            authorities: Additional authorities

        Returns:
            TransactionContext instance
        """
        return cls(
            principal=principal,
            body=body,
            memo=memo,
            expire=expire,
            hold_until=hold_until,
            authorities=authorities
        )

    def to_envelope(self) -> Dict[str, Any]:
        """
        Convert to complete transaction envelope.

        Returns:
            Transaction envelope with header and body

        Raises:
            ValueError: If body is not set
        """
        if self.body is None:
            raise ValueError("Transaction body is not set")
        return self.build_envelope(self.body)

    def with_body(self, body: Dict[str, Any]) -> TransactionContext:
        """Return a copy with new body."""
        return self.model_copy(update={"body": body})


# =============================================================================
# Helper Functions
# =============================================================================

def create_context(
    principal: Union[str, AccountUrl],
    **kwargs
) -> BuildContext:
    """
    Create a BuildContext with optional parameters.

    Args:
        principal: Principal account URL
        **kwargs: Additional context parameters

    Returns:
        BuildContext instance
    """
    return BuildContext(principal=principal, **kwargs)


def context_for_identity(
    identity: Union[str, AccountUrl],
    key_book: Optional[str] = None,
    memo: Optional[str] = None
) -> BuildContext:
    """
    Create a BuildContext for an identity.

    Args:
        identity: Identity URL
        key_book: Optional key book path (defaults to /book)
        memo: Optional memo

    Returns:
        BuildContext for the identity
    """
    identity_str = str(identity) if isinstance(identity, AccountUrl) else identity
    if not identity_str.startswith('acc://'):
        identity_str = f'acc://{identity_str}'

    return BuildContext(
        principal=identity_str,
        memo=memo
    )


def context_for_lite_account(
    lite_url: Union[str, AccountUrl],
    memo: Optional[str] = None
) -> BuildContext:
    """
    Create a BuildContext for a lite account.

    Args:
        lite_url: Lite account URL
        memo: Optional memo

    Returns:
        BuildContext for the lite account
    """
    return BuildContext(
        principal=str(lite_url) if isinstance(lite_url, AccountUrl) else lite_url,
        memo=memo
    )


__all__ = [
    # Main classes
    "BuildContext",
    "TransactionContext",
    # Factory functions
    "create_context",
    "context_for_identity",
    "context_for_lite_account",
]
