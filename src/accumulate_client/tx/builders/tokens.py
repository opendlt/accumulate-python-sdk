"""
Token transaction builders for Accumulate Protocol.

Provides builders for token-related transactions with ergonomic interfaces
and exact parity to the Go implementation.

Reference: C:/Accumulate_Stuff/accumulate/protocol/token.go
"""

from __future__ import annotations
from typing import Optional, Union

from ...runtime.url import AccountUrl
from ...transactions import (
    CreateTokenBody, CreateTokenAccountBody, CreateLiteTokenAccountBody,
    SendTokensBody, IssueTokensBody, BurnTokensBody
)
from .base import BaseTxBuilder


class CreateTokenBuilder(BaseTxBuilder[CreateTokenBody]):
    """Builder for CreateToken transactions."""

    @property
    def tx_type(self) -> str:
        return "CreateToken"

    @property
    def body_cls(self):
        return CreateTokenBody

    def url(self, url: Union[str, AccountUrl]) -> CreateTokenBuilder:
        """Set the token URL to create."""
        return self.with_field('url', url)

    def symbol(self, symbol: str) -> CreateTokenBuilder:
        """Set the token symbol."""
        return self.with_field('symbol', symbol)

    def precision(self, precision: int) -> CreateTokenBuilder:
        """Set the token precision (decimal places)."""
        return self.with_field('precision', precision)

    def properties(self, properties: str) -> CreateTokenBuilder:
        """Set token properties URL or metadata."""
        return self.with_field('properties', properties)

    def supply_limit(self, limit: Optional[int]) -> CreateTokenBuilder:
        """Set the maximum token supply limit (None for unlimited)."""
        return self.with_field('supplyLimit', limit)


class CreateTokenAccountBuilder(BaseTxBuilder[CreateTokenAccountBody]):
    """Builder for CreateTokenAccount transactions."""

    @property
    def tx_type(self) -> str:
        return "CreateTokenAccount"

    @property
    def body_cls(self):
        return CreateTokenAccountBody

    def url(self, url: Union[str, AccountUrl]) -> CreateTokenAccountBuilder:
        """Set the token account URL to create."""
        return self.with_field('url', url)

    def token_url(self, url: Union[str, AccountUrl]) -> CreateTokenAccountBuilder:
        """Set the token URL this account will hold."""
        return self.with_field('tokenUrl', url)

    def key_book_url(self, url: Union[str, AccountUrl]) -> CreateTokenAccountBuilder:
        """Set the key book URL for the token account."""
        return self.with_field('keyBookUrl', url)

    def scratch(self, scratch: bool = True) -> CreateTokenAccountBuilder:
        """Set whether this is a scratch account."""
        return self.with_field('scratch', scratch)


class CreateLiteTokenAccountBuilder(BaseTxBuilder[CreateLiteTokenAccountBody]):
    """Builder for CreateLiteTokenAccount transactions."""

    @property
    def tx_type(self) -> str:
        return "CreateLiteTokenAccount"

    @property
    def body_cls(self):
        return CreateLiteTokenAccountBody


class SendTokensBuilder(BaseTxBuilder[SendTokensBody]):
    """Builder for SendTokens transactions."""

    @property
    def tx_type(self) -> str:
        return "SendTokens"

    @property
    def body_cls(self):
        return SendTokensBody

    def to(self, to_url: Union[str, AccountUrl]) -> SendTokensBuilder:
        """Set the recipient account URL."""
        return self.with_field('to', to_url)

    def amount(self, amount: int) -> SendTokensBuilder:
        """Set the amount to send (in token base units)."""
        return self.with_field('amount', amount)

    def meta(self, meta: bytes) -> SendTokensBuilder:
        """Set transaction metadata."""
        return self.with_field('meta', meta)

    def hash(self, hash_value: bytes) -> SendTokensBuilder:
        """Set transaction hash."""
        return self.with_field('hash', hash_value)


class IssueTokensBuilder(BaseTxBuilder[IssueTokensBody]):
    """Builder for IssueTokens transactions."""

    @property
    def tx_type(self) -> str:
        return "IssueTokens"

    @property
    def body_cls(self):
        return IssueTokensBody

    def recipient(self, recipient_url: Union[str, AccountUrl]) -> IssueTokensBuilder:
        """Set the recipient account URL."""
        return self.with_field('recipient', recipient_url)

    def amount(self, amount: int) -> IssueTokensBuilder:
        """Set the amount to issue (in token base units)."""
        return self.with_field('amount', amount)


class BurnTokensBuilder(BaseTxBuilder[BurnTokensBody]):
    """Builder for BurnTokens transactions."""

    @property
    def tx_type(self) -> str:
        return "BurnTokens"

    @property
    def body_cls(self):
        return BurnTokensBody

    def amount(self, amount: int) -> BurnTokensBuilder:
        """Set the amount to burn (in token base units)."""
        return self.with_field('amount', amount)


__all__ = [
    "CreateTokenBuilder",
    "CreateTokenAccountBuilder",
    "CreateLiteTokenAccountBuilder",
    "SendTokensBuilder",
    "IssueTokensBuilder",
    "BurnTokensBuilder"
]