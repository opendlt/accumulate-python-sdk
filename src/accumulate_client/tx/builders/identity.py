"""
Identity transaction builders for Accumulate Protocol.

Provides builders for identity-related transactions with ergonomic interfaces
and exact parity to the Go implementation.

Reference: C:/Accumulate_Stuff/accumulate/protocol/identity.go
"""

from __future__ import annotations
from typing import Optional, List, Union

from ...runtime.url import AccountUrl
from ...transactions import (
    CreateIdentityBody, CreateKeyBookBody, CreateKeyPageBody,
    UpdateKeyPageBody, UpdateKeyBody
)
from .base import BaseTxBuilder


class CreateIdentityBuilder(BaseTxBuilder[CreateIdentityBody]):
    """Builder for CreateIdentity transactions."""

    @property
    def tx_type(self) -> str:
        return "CreateIdentity"

    @property
    def body_cls(self):
        return CreateIdentityBody

    def url(self, url: Union[str, AccountUrl]) -> CreateIdentityBuilder:
        """Set the identity URL to create."""
        return self.with_field('url', url)

    def key_book_url(self, url: Union[str, AccountUrl]) -> CreateIdentityBuilder:
        """Set the key book URL for the identity."""
        return self.with_field('keyBookUrl', url)

    def key_page_url(self, url: Union[str, AccountUrl]) -> CreateIdentityBuilder:
        """Set the key page URL for the identity."""
        return self.with_field('keyPageUrl', url)


class CreateKeyBookBuilder(BaseTxBuilder[CreateKeyBookBody]):
    """Builder for CreateKeyBook transactions."""

    @property
    def tx_type(self) -> str:
        return "CreateKeyBook"

    @property
    def body_cls(self):
        return CreateKeyBookBody

    def url(self, url: Union[str, AccountUrl]) -> CreateKeyBookBuilder:
        """Set the key book URL to create."""
        return self.with_field('url', url)

    def public_key_hash(self, hash_value: bytes) -> CreateKeyBookBuilder:
        """Set the public key hash for the key book."""
        return self.with_field('publicKeyHash', hash_value)

    def authorities(self, authorities: List[Union[str, AccountUrl]]) -> CreateKeyBookBuilder:
        """Set the authorities for the key book."""
        return self.with_field('authorities', authorities)


class CreateKeyPageBuilder(BaseTxBuilder[CreateKeyPageBody]):
    """Builder for CreateKeyPage transactions."""

    @property
    def tx_type(self) -> str:
        return "CreateKeyPage"

    @property
    def body_cls(self):
        return CreateKeyPageBody

    def keys(self, keys: List[bytes]) -> CreateKeyPageBuilder:
        """Set the public keys for the key page."""
        return self.with_field('keys', keys)

    def add_key(self, key: bytes) -> CreateKeyPageBuilder:
        """Add a single public key to the key page."""
        current_keys = self.get_field('keys', [])
        current_keys.append(key)
        return self.with_field('keys', current_keys)


class UpdateKeyPageBuilder(BaseTxBuilder[UpdateKeyPageBody]):
    """Builder for UpdateKeyPage transactions."""

    @property
    def tx_type(self) -> str:
        return "UpdateKeyPage"

    @property
    def body_cls(self):
        return UpdateKeyPageBody

    def operation(self, operation: str) -> UpdateKeyPageBuilder:
        """Set the key page operation (add, remove, update)."""
        return self.with_field('operation', operation)

    def key(self, key: bytes) -> UpdateKeyPageBuilder:
        """Set the key for the operation."""
        return self.with_field('key', key)

    def new_key(self, key: bytes) -> UpdateKeyPageBuilder:
        """Set the new key for update operations."""
        return self.with_field('newKey', key)

    def add_key_operation(self, key: bytes) -> UpdateKeyPageBuilder:
        """Configure as an add key operation."""
        return self.operation('add').key(key)

    def remove_key_operation(self, key: bytes) -> UpdateKeyPageBuilder:
        """Configure as a remove key operation."""
        return self.operation('remove').key(key)

    def update_key_operation(self, old_key: bytes, new_key: bytes) -> UpdateKeyPageBuilder:
        """Configure as an update key operation."""
        return self.operation('update').key(old_key).new_key(new_key)


class UpdateKeyBuilder(BaseTxBuilder[UpdateKeyBody]):
    """Builder for UpdateKey transactions."""

    @property
    def tx_type(self) -> str:
        return "UpdateKey"

    @property
    def body_cls(self):
        return UpdateKeyBody

    def new_key_hash(self, hash_value: bytes) -> UpdateKeyBuilder:
        """Set the new key hash."""
        return self.with_field('newKeyHash', hash_value)

    def priority(self, priority: int) -> UpdateKeyBuilder:
        """Set the key priority."""
        return self.with_field('priority', priority)


__all__ = [
    "CreateIdentityBuilder",
    "CreateKeyBookBuilder",
    "CreateKeyPageBuilder",
    "UpdateKeyPageBuilder",
    "UpdateKeyBuilder"
]