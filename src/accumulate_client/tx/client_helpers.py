"""
Client integration helpers for transaction builders.

Provides high-level methods to build, sign, and submit transactions
using the builder pattern with AccumulateClient integration.
"""

from __future__ import annotations
from typing import Any, Dict, Optional, Union

from ..api_client import AccumulateClient
from ..runtime.url import AccountUrl
from ..signers.signer import Signer
from .execute import sign_and_submit, build_sign_submit
from . import builders


class ClientTransactionMixin:
    """
    Mixin class that adds transaction builder methods to AccumulateClient.

    This provides high-level methods for common transaction patterns,
    integrating the builder system with client submission.
    """

    def create_identity(
        self,
        signer: Signer,
        url: Union[str, AccountUrl],
        key_book_url: Optional[Union[str, AccountUrl]] = None,
        key_page_url: Optional[Union[str, AccountUrl]] = None,
        *,
        wait: bool = True,
        timeout_s: int = 30,
        **kwargs
    ) -> Dict[str, Any]:
        """
        Build, sign, and submit a CreateIdentity transaction.

        Args:
            signer: Signer to use for transaction
            url: Identity URL to create
            key_book_url: Optional key book URL
            key_page_url: Optional key page URL
            wait: Whether to wait for completion
            timeout_s: Timeout in seconds
            **kwargs: Additional transaction parameters

        Returns:
            Transaction receipt or ID
        """
        builder = builders.CreateIdentityBuilder()
        builder.url(url)

        if key_book_url:
            builder.key_book_url(key_book_url)
        if key_page_url:
            builder.key_page_url(key_page_url)

        # Apply additional kwargs
        for key, value in kwargs.items():
            builder.with_field(key, value)

        envelope = builder.build_envelope(
            origin=signer.get_signer_url(),
            **kwargs
        )

        return sign_and_submit(
            self, envelope, signer,
            wait=wait, timeout_s=timeout_s
        )

    def send_tokens(
        self,
        signer: Signer,
        to: Union[str, AccountUrl],
        amount: int,
        *,
        wait: bool = True,
        timeout_s: int = 30,
        **kwargs
    ) -> Dict[str, Any]:
        """
        Build, sign, and submit a SendTokens transaction.

        Args:
            signer: Signer to use for transaction
            to: Recipient account URL
            amount: Amount to send (in token base units)
            wait: Whether to wait for completion
            timeout_s: Timeout in seconds
            **kwargs: Additional transaction parameters

        Returns:
            Transaction receipt or ID
        """
        builder = builders.SendTokensBuilder()
        builder.to(to).amount(amount)

        # Apply additional kwargs
        for key, value in kwargs.items():
            builder.with_field(key, value)

        envelope = builder.build_envelope(
            origin=signer.get_signer_url(),
            **kwargs
        )

        return sign_and_submit(
            self, envelope, signer,
            wait=wait, timeout_s=timeout_s
        )

    def create_token_account(
        self,
        signer: Signer,
        url: Union[str, AccountUrl],
        token_url: Union[str, AccountUrl],
        key_book_url: Optional[Union[str, AccountUrl]] = None,
        *,
        wait: bool = True,
        timeout_s: int = 30,
        **kwargs
    ) -> Dict[str, Any]:
        """
        Build, sign, and submit a CreateTokenAccount transaction.

        Args:
            signer: Signer to use for transaction
            url: Token account URL to create
            token_url: Token URL this account will hold
            key_book_url: Optional key book URL
            wait: Whether to wait for completion
            timeout_s: Timeout in seconds
            **kwargs: Additional transaction parameters

        Returns:
            Transaction receipt or ID
        """
        builder = builders.CreateTokenAccountBuilder()
        builder.url(url).token_url(token_url)

        if key_book_url:
            builder.key_book_url(key_book_url)

        # Apply additional kwargs
        for key, value in kwargs.items():
            builder.with_field(key, value)

        envelope = builder.build_envelope(
            origin=signer.get_signer_url(),
            **kwargs
        )

        return sign_and_submit(
            self, envelope, signer,
            wait=wait, timeout_s=timeout_s
        )

    def write_data(
        self,
        signer: Signer,
        data: bytes,
        *,
        scratch: bool = False,
        wait: bool = True,
        timeout_s: int = 30,
        **kwargs
    ) -> Dict[str, Any]:
        """
        Build, sign, and submit a WriteData transaction.

        Args:
            signer: Signer to use for transaction
            data: Data to write
            scratch: Whether to write to scratch space
            wait: Whether to wait for completion
            timeout_s: Timeout in seconds
            **kwargs: Additional transaction parameters

        Returns:
            Transaction receipt or ID
        """
        builder = builders.WriteDataBuilder()
        builder.data(data)

        if scratch:
            builder.scratch(scratch)

        # Apply additional kwargs
        for key, value in kwargs.items():
            builder.with_field(key, value)

        envelope = builder.build_envelope(
            origin=signer.get_signer_url(),
            **kwargs
        )

        return sign_and_submit(
            self, envelope, signer,
            wait=wait, timeout_s=timeout_s
        )

    def add_credits(
        self,
        signer: Signer,
        recipient: Union[str, AccountUrl],
        amount: int,
        oracle: Optional[float] = None,
        *,
        wait: bool = True,
        timeout_s: int = 30,
        **kwargs
    ) -> Dict[str, Any]:
        """
        Build, sign, and submit an AddCredits transaction.

        Args:
            signer: Signer to use for transaction
            recipient: Recipient account URL
            amount: Amount of credits to add
            oracle: Oracle price for ACME to credits conversion
            wait: Whether to wait for completion
            timeout_s: Timeout in seconds
            **kwargs: Additional transaction parameters

        Returns:
            Transaction receipt or ID
        """
        builder = builders.AddCreditsBuilder()
        builder.recipient(recipient).amount(amount)

        if oracle is not None:
            builder.oracle(oracle)

        # Apply additional kwargs
        for key, value in kwargs.items():
            builder.with_field(key, value)

        envelope = builder.build_envelope(
            origin=signer.get_signer_url(),
            **kwargs
        )

        return sign_and_submit(
            self, envelope, signer,
            wait=wait, timeout_s=timeout_s
        )

    def build_transaction(
        self,
        tx_type: str,
        signer: Signer,
        *,
        wait: bool = True,
        timeout_s: int = 30,
        **kwargs
    ) -> Dict[str, Any]:
        """
        Build, sign, and submit any transaction type using the builder system.

        Args:
            tx_type: Transaction type name
            signer: Signer to use for transaction
            wait: Whether to wait for completion
            timeout_s: Timeout in seconds
            **kwargs: Transaction parameters

        Returns:
            Transaction receipt or ID
        """
        return build_sign_submit(
            self, tx_type, signer,
            wait=wait, timeout_s=timeout_s,
            **kwargs
        )

    def get_builder(self, tx_type: str):
        """
        Get a transaction builder for the specified type.

        Args:
            tx_type: Transaction type name

        Returns:
            Builder instance
        """
        return builders.get_builder_for(tx_type)


class EnhancedAccumulateClient(AccumulateClient, ClientTransactionMixin):
    """
    Enhanced AccumulateClient with transaction builder integration.

    Combines the full API client with high-level transaction builder methods
    for a complete SDK experience.
    """
    pass


def create_enhanced_client(config: Union[str, Any]) -> EnhancedAccumulateClient:
    """
    Create an enhanced client with transaction builder integration.

    Args:
        config: Client configuration (endpoint string or ClientConfig)

    Returns:
        Enhanced client instance
    """
    return EnhancedAccumulateClient(config)


# Convenience functions
def mainnet_enhanced_client(**kwargs) -> EnhancedAccumulateClient:
    """Create an enhanced client for Accumulate mainnet."""
    return EnhancedAccumulateClient.for_network('mainnet', **kwargs)


def testnet_enhanced_client(**kwargs) -> EnhancedAccumulateClient:
    """Create an enhanced client for Accumulate testnet."""
    return EnhancedAccumulateClient.for_network('testnet', **kwargs)


def local_enhanced_client(**kwargs) -> EnhancedAccumulateClient:
    """Create an enhanced client for local Accumulate node."""
    return EnhancedAccumulateClient.for_network('local', **kwargs)


__all__ = [
    "ClientTransactionMixin",
    "EnhancedAccumulateClient",
    "create_enhanced_client",
    "mainnet_enhanced_client",
    "testnet_enhanced_client",
    "local_enhanced_client"
]