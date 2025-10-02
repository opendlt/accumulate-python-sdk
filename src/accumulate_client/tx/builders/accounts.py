"""
Account transaction builders for Accumulate Protocol.

Provides builders for account management transactions with ergonomic interfaces
and exact parity to the Go implementation.

Reference: C:/Accumulate_Stuff/accumulate/protocol/account.go
"""

from __future__ import annotations
from typing import Union, List, Optional

from ...runtime.url import AccountUrl
from ...transactions import (
    AddCreditsBody, BurnCreditsBody, TransferCreditsBody,
    UpdateAccountAuthBody, LockAccountBody, AcmeFaucetBody
)
from .base import BaseTxBuilder


class AddCreditsBuilder(BaseTxBuilder[AddCreditsBody]):
    """Builder for AddCredits transactions."""

    @property
    def tx_type(self) -> str:
        return "AddCredits"

    @property
    def body_cls(self):
        return AddCreditsBody

    def recipient(self, recipient_url: Union[str, AccountUrl]) -> AddCreditsBuilder:
        """Set the recipient account URL."""
        return self.with_field('recipient', recipient_url)

    def amount(self, amount: int) -> AddCreditsBuilder:
        """Set the amount of credits to add."""
        return self.with_field('amount', amount)

    def oracle(self, oracle: float) -> AddCreditsBuilder:
        """Set the oracle price for ACME to credits conversion."""
        return self.with_field('oracle', oracle)


class BurnCreditsBuilder(BaseTxBuilder[BurnCreditsBody]):
    """Builder for BurnCredits transactions."""

    @property
    def tx_type(self) -> str:
        return "BurnCredits"

    @property
    def body_cls(self):
        return BurnCreditsBody

    def amount(self, amount: int) -> BurnCreditsBuilder:
        """Set the amount of credits to burn."""
        return self.with_field('amount', amount)


class TransferCreditsBuilder(BaseTxBuilder[TransferCreditsBody]):
    """Builder for TransferCredits transactions."""

    @property
    def tx_type(self) -> str:
        return "TransferCredits"

    @property
    def body_cls(self):
        return TransferCreditsBody

    def to(self, to_url: Union[str, AccountUrl]) -> TransferCreditsBuilder:
        """Set the recipient account URL."""
        return self.with_field('to', to_url)

    def amount(self, amount: int) -> TransferCreditsBuilder:
        """Set the amount of credits to transfer."""
        return self.with_field('amount', amount)


class UpdateAccountAuthBuilder(BaseTxBuilder[UpdateAccountAuthBody]):
    """Builder for UpdateAccountAuth transactions."""

    @property
    def tx_type(self) -> str:
        return "UpdateAccountAuth"

    @property
    def body_cls(self):
        return UpdateAccountAuthBody

    def authority(self, authority: Union[str, AccountUrl]) -> UpdateAccountAuthBuilder:
        """Set the authority to update."""
        return self.with_field('authority', authority)

    def operations(self, operations: List[str]) -> UpdateAccountAuthBuilder:
        """Set the list of operations."""
        return self.with_field('operations', operations)

    def add_operation(self, operation: str) -> UpdateAccountAuthBuilder:
        """Add a single operation."""
        current_ops = self.get_field('operations', [])
        current_ops.append(operation)
        return self.with_field('operations', current_ops)


class LockAccountBuilder(BaseTxBuilder[LockAccountBody]):
    """Builder for LockAccount transactions."""

    @property
    def tx_type(self) -> str:
        return "LockAccount"

    @property
    def body_cls(self):
        return LockAccountBody

    def height(self, height: int) -> LockAccountBuilder:
        """Set the block height until which to lock the account."""
        return self.with_field('height', height)


class AcmeFaucetBuilder(BaseTxBuilder[AcmeFaucetBody]):
    """Builder for AcmeFaucet transactions."""

    @property
    def tx_type(self) -> str:
        return "AcmeFaucet"

    @property
    def body_cls(self):
        return AcmeFaucetBody

    def url(self, url: Union[str, AccountUrl]) -> AcmeFaucetBuilder:
        """Set the account URL to receive ACME from faucet."""
        return self.with_field('url', url)


__all__ = [
    "AddCreditsBuilder",
    "BurnCreditsBuilder",
    "TransferCreditsBuilder",
    "UpdateAccountAuthBuilder",
    "LockAccountBuilder",
    "AcmeFaucetBuilder"
]