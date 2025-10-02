"""
Data transaction builders for Accumulate Protocol.

Provides builders for data-related transactions with ergonomic interfaces
and exact parity to the Go implementation.

Reference: C:/Accumulate_Stuff/accumulate/protocol/data.go
"""

from __future__ import annotations
from typing import Union, List, Optional

from ...runtime.url import AccountUrl
from ...transactions import (
    CreateDataAccountBody, WriteDataBody, WriteDataToBody
)
from .base import BaseTxBuilder


class CreateDataAccountBuilder(BaseTxBuilder[CreateDataAccountBody]):
    """Builder for CreateDataAccount transactions."""

    @property
    def tx_type(self) -> str:
        return "CreateDataAccount"

    @property
    def body_cls(self):
        return CreateDataAccountBody

    def url(self, url: Union[str, AccountUrl]) -> CreateDataAccountBuilder:
        """Set the data account URL to create."""
        return self.with_field('url', url)

    def key_book_url(self, url: Union[str, AccountUrl]) -> CreateDataAccountBuilder:
        """Set the key book URL for the data account."""
        return self.with_field('keyBookUrl', url)

    def scratch(self, scratch: bool = True) -> CreateDataAccountBuilder:
        """Set whether this is a scratch account."""
        return self.with_field('scratch', scratch)


class WriteDataBuilder(BaseTxBuilder[WriteDataBody]):
    """Builder for WriteData transactions."""

    @property
    def tx_type(self) -> str:
        return "WriteData"

    @property
    def body_cls(self):
        return WriteDataBody

    def data(self, data: bytes) -> WriteDataBuilder:
        """Set the data to write."""
        return self.with_field('data', data)

    def scratch(self, scratch: bool = True) -> WriteDataBuilder:
        """Set whether to write to scratch space."""
        return self.with_field('scratch', scratch)

    def entry_hash(self, hash_value: bytes) -> WriteDataBuilder:
        """Set the entry hash."""
        return self.with_field('entryHash', hash_value)

    def write_to_state(self, state: bool = True) -> WriteDataBuilder:
        """Set whether to write to state."""
        return self.with_field('writeToState', state)


class WriteDataToBuilder(BaseTxBuilder[WriteDataToBody]):
    """Builder for WriteDataTo transactions."""

    @property
    def tx_type(self) -> str:
        return "WriteDataTo"

    @property
    def body_cls(self):
        return WriteDataToBody

    def recipient(self, recipient_url: Union[str, AccountUrl]) -> WriteDataToBuilder:
        """Set the recipient data account URL."""
        return self.with_field('recipient', recipient_url)

    def data(self, data: bytes) -> WriteDataToBuilder:
        """Set the data to write."""
        return self.with_field('data', data)

    def scratch(self, scratch: bool = True) -> WriteDataToBuilder:
        """Set whether to write to scratch space."""
        return self.with_field('scratch', scratch)

    def entry_hash(self, hash_value: bytes) -> WriteDataToBuilder:
        """Set the entry hash."""
        return self.with_field('entryHash', hash_value)

    def write_to_state(self, state: bool = True) -> WriteDataToBuilder:
        """Set whether to write to state."""
        return self.with_field('writeToState', state)


class CreateLiteDataAccountBuilder(WriteDataToBuilder):
    """
    Builder for CreateLiteDataAccount transactions.

    Note: In Accumulate, lite data accounts are created implicitly by writing data to them.
    This builder is a convenience wrapper around WriteDataTo that creates the account
    by writing initial data.
    """

    @property
    def tx_type(self) -> str:
        return "WriteDataTo"  # The actual transaction type

    def url(self, url: Union[str, AccountUrl]) -> CreateLiteDataAccountBuilder:
        """Set the lite data account URL to create."""
        return self.recipient(url)

    def initial_data(self, data: bytes) -> CreateLiteDataAccountBuilder:
        """Set the initial data to write when creating the account."""
        return self.data(data)


__all__ = [
    "CreateDataAccountBuilder",
    "WriteDataBuilder",
    "WriteDataToBuilder",
    "CreateLiteDataAccountBuilder"
]