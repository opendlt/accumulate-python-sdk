"""
Synthetic transaction builders for Accumulate Protocol.

Provides builders for synthetic transactions with ergonomic interfaces
and exact parity to the Go implementation.

Reference: C:/Accumulate_Stuff/accumulate/protocol/synthetic.go
"""

from __future__ import annotations
from typing import Union, Any

from ...runtime.url import AccountUrl
from ...transactions import (
    SyntheticCreateIdentityBody, SyntheticWriteDataBody,
    SyntheticDepositTokensBody, SyntheticDepositCreditsBody,
    SyntheticBurnTokensBody, SyntheticForwardTransactionBody,
    RemoteTransactionBody
)
from .base import BaseTxBuilder


class SyntheticCreateIdentityBuilder(BaseTxBuilder[SyntheticCreateIdentityBody]):
    """Builder for SyntheticCreateIdentity transactions."""

    @property
    def tx_type(self) -> str:
        return "SyntheticCreateIdentity"

    @property
    def body_cls(self):
        return SyntheticCreateIdentityBody

    def url(self, url: Union[str, AccountUrl]) -> SyntheticCreateIdentityBuilder:
        """Set the identity URL to create."""
        return self.with_field('url', url)

    def cause(self, cause: bytes) -> SyntheticCreateIdentityBuilder:
        """Set the transaction hash that caused this synthetic transaction."""
        return self.with_field('cause', cause)


class SyntheticWriteDataBuilder(BaseTxBuilder[SyntheticWriteDataBody]):
    """Builder for SyntheticWriteData transactions."""

    @property
    def tx_type(self) -> str:
        return "SyntheticWriteData"

    @property
    def body_cls(self):
        return SyntheticWriteDataBody

    def data(self, data: bytes) -> SyntheticWriteDataBuilder:
        """Set the data to write."""
        return self.with_field('data', data)

    def cause(self, cause: bytes) -> SyntheticWriteDataBuilder:
        """Set the transaction hash that caused this synthetic transaction."""
        return self.with_field('cause', cause)


class SyntheticDepositTokensBuilder(BaseTxBuilder[SyntheticDepositTokensBody]):
    """Builder for SyntheticDepositTokens transactions."""

    @property
    def tx_type(self) -> str:
        return "SyntheticDepositTokens"

    @property
    def body_cls(self):
        return SyntheticDepositTokensBody

    def token(self, token_url: Union[str, AccountUrl]) -> SyntheticDepositTokensBuilder:
        """Set the token URL being deposited."""
        return self.with_field('token', token_url)

    def amount(self, amount: int) -> SyntheticDepositTokensBuilder:
        """Set the amount being deposited."""
        return self.with_field('amount', amount)

    def cause(self, cause: bytes) -> SyntheticDepositTokensBuilder:
        """Set the transaction hash that caused this synthetic transaction."""
        return self.with_field('cause', cause)


class SyntheticDepositCreditsBuilder(BaseTxBuilder[SyntheticDepositCreditsBody]):
    """Builder for SyntheticDepositCredits transactions."""

    @property
    def tx_type(self) -> str:
        return "SyntheticDepositCredits"

    @property
    def body_cls(self):
        return SyntheticDepositCreditsBody

    def amount(self, amount: int) -> SyntheticDepositCreditsBuilder:
        """Set the amount of credits being deposited."""
        return self.with_field('amount', amount)

    def cause(self, cause: bytes) -> SyntheticDepositCreditsBuilder:
        """Set the transaction hash that caused this synthetic transaction."""
        return self.with_field('cause', cause)


class SyntheticBurnTokensBuilder(BaseTxBuilder[SyntheticBurnTokensBody]):
    """Builder for SyntheticBurnTokens transactions."""

    @property
    def tx_type(self) -> str:
        return "SyntheticBurnTokens"

    @property
    def body_cls(self):
        return SyntheticBurnTokensBody

    def amount(self, amount: int) -> SyntheticBurnTokensBuilder:
        """Set the amount being burned."""
        return self.with_field('amount', amount)

    def cause(self, cause: bytes) -> SyntheticBurnTokensBuilder:
        """Set the transaction hash that caused this synthetic transaction."""
        return self.with_field('cause', cause)


class SyntheticForwardTransactionBuilder(BaseTxBuilder[SyntheticForwardTransactionBody]):
    """Builder for SyntheticForwardTransaction transactions."""

    @property
    def tx_type(self) -> str:
        return "SyntheticForwardTransaction"

    @property
    def body_cls(self):
        return SyntheticForwardTransactionBody

    def envelope(self, envelope: Any) -> SyntheticForwardTransactionBuilder:
        """Set the transaction envelope being forwarded."""
        return self.with_field('envelope', envelope)

    def cause(self, cause: bytes) -> SyntheticForwardTransactionBuilder:
        """Set the transaction hash that caused this synthetic transaction."""
        return self.with_field('cause', cause)


class RemoteTransactionBuilder(BaseTxBuilder[RemoteTransactionBody]):
    """Builder for RemoteTransaction transactions."""

    @property
    def tx_type(self) -> str:
        return "RemoteTransaction"

    @property
    def body_cls(self):
        return RemoteTransactionBody

    def hash(self, hash_value: bytes) -> RemoteTransactionBuilder:
        """Set the remote transaction hash."""
        return self.with_field('hash', hash_value)


__all__ = [
    "SyntheticCreateIdentityBuilder",
    "SyntheticWriteDataBuilder",
    "SyntheticDepositTokensBuilder",
    "SyntheticDepositCreditsBuilder",
    "SyntheticBurnTokensBuilder",
    "SyntheticForwardTransactionBuilder",
    "RemoteTransactionBuilder"
]