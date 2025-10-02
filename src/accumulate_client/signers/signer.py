r"""
Base signer interface for Accumulate Protocol.

Defines the signing interface that all signature types must implement.

Reference: C:/Accumulate_Stuff/accumulate\protocol\signature.go (lines 54-85)
"""

from __future__ import annotations
from abc import ABC, abstractmethod
from typing import Dict, Any, Optional, Union
from datetime import datetime, timezone

from ..enums import SignatureType, VoteType
from ..runtime.url import AccountUrl
from ..runtime.errors import AccumulateError


class SignerError(AccumulateError):
    """Base exception for signer operations."""
    pass


class Signer(ABC):
    """
    Base signer interface.

    All Accumulate signature types must implement this interface.
    Matches the Go protocol.Signature interface structure.
    """

    @abstractmethod
    def get_signature_type(self) -> SignatureType:
        """
        Get the signature type.

        Returns:
            SignatureType enum value
        """
        pass

    @abstractmethod
    def get_signer_url(self) -> AccountUrl:
        """
        Get the signer's URL.

        Returns:
            Account URL of the signer
        """
        pass

    @abstractmethod
    def sign(self, digest: bytes) -> bytes:
        """
        Sign a digest.

        Args:
            digest: 32-byte hash to sign

        Returns:
            Signature bytes

        Raises:
            SignerError: If signing fails
        """
        pass

    @abstractmethod
    def verify(self, signature: bytes, digest: bytes) -> bool:
        """
        Verify a signature against a digest.

        Args:
            signature: Signature bytes to verify
            digest: 32-byte hash that was signed

        Returns:
            True if signature is valid
        """
        pass

    @abstractmethod
    def get_public_key(self) -> bytes:
        """
        Get the public key bytes.

        Returns:
            Public key in the appropriate format for this signature type
        """
        pass

    def get_public_key_hash(self) -> bytes:
        """
        Get the hash of the public key.

        Default implementation uses SHA-256. Override if signature type
        requires different hashing.

        Returns:
            32-byte hash of the public key
        """
        from ..runtime.codec import hash_sha256
        return hash_sha256(self.get_public_key())

    def get_vote(self) -> VoteType:
        """
        Get the vote type for this signature.

        Default is ACCEPT. Override for reject/abstain signatures.

        Returns:
            Vote type
        """
        return VoteType.ACCEPT

    def get_timestamp(self) -> int:
        """
        Get the signature timestamp.

        Default implementation returns current time in nanoseconds.

        Returns:
            Unix timestamp in nanoseconds
        """
        return int(datetime.now(timezone.utc).timestamp() * 1_000_000_000)

    def get_signer_version(self) -> int:
        """
        Get the signer version.

        Default is 1. Override for versioned signers like KeyPages.

        Returns:
            Signer version number
        """
        return 1

    def to_accumulate_signature(self, digest: bytes, **kwargs) -> Dict[str, Any]:
        """
        Create Accumulate protocol signature structure.

        Args:
            digest: Hash that was signed
            **kwargs: Additional signature parameters

        Returns:
            Dictionary matching Accumulate signature format
        """
        signature_bytes = self.sign(digest)

        base_signature = {
            "type": self.get_signature_type().name.lower(),
            "publicKey": self.get_public_key().hex(),
            "signature": signature_bytes.hex(),
            "signer": str(self.get_signer_url()),
            "signerVersion": self.get_signer_version(),
            "timestamp": kwargs.get("timestamp", self.get_timestamp()),
            "vote": self.get_vote().name.lower()
        }

        # Add transaction hash if provided
        if "transaction_hash" in kwargs:
            base_signature["transactionHash"] = kwargs["transaction_hash"]

        # Add memo if provided
        if "memo" in kwargs:
            base_signature["memo"] = kwargs["memo"]

        # Add data if provided
        if "data" in kwargs:
            base_signature["data"] = kwargs["data"]

        return base_signature

    def can_initiate(self) -> bool:
        """
        Check if this signer can initiate transactions.

        System signatures (partition, receipt, internal) cannot initiate.

        Returns:
            True if signer can initiate transactions
        """
        return not self.get_signature_type().IsSystem()

    def routing_location(self) -> AccountUrl:
        """
        Get the routing location for this signature.

        Default implementation returns the signer URL.

        Returns:
            Account URL for routing
        """
        return self.get_signer_url()

    def metadata(self) -> Dict[str, Any]:
        """
        Get signature metadata.

        Returns:
            Dictionary of signature metadata
        """
        return {
            "type": self.get_signature_type().name,
            "signer": str(self.get_signer_url()),
            "version": self.get_signer_version(),
            "canInitiate": self.can_initiate(),
            "publicKeyHash": self.get_public_key_hash().hex()
        }

    def __str__(self) -> str:
        return f"{self.__class__.__name__}({self.get_signature_type().name}, {self.get_signer_url()})"

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}(type={self.get_signature_type()}, signer='{self.get_signer_url()}')"


class KeySigner(Signer):
    """
    Base class for key-based signers.

    Extends Signer with key-specific functionality matching the Go
    protocol.KeySignature interface.
    """

    @abstractmethod
    def get_signature_bytes(self, digest: bytes) -> bytes:
        """
        Get raw signature bytes without metadata.

        Args:
            digest: Hash to sign

        Returns:
            Raw signature bytes
        """
        pass

    def sign(self, digest: bytes) -> bytes:
        """
        Sign a digest (delegates to get_signature_bytes).

        Args:
            digest: 32-byte hash to sign

        Returns:
            Signature bytes
        """
        return self.get_signature_bytes(digest)


class UserSigner(KeySigner):
    """
    Base class for user signatures that can initiate transactions.

    Matches the Go protocol.UserSignature interface.
    """

    def initiator_hash(self) -> bytes:
        """
        Get the initiator hash for transaction initiation.

        This has been deprecated in favor of the principal field,
        but is kept for compatibility.

        Returns:
            32-byte initiator hash
        """
        from ..runtime.codec import hash_sha256
        # Use public key hash as initiator
        return self.get_public_key_hash()

    def can_initiate(self) -> bool:
        """User signatures can initiate transactions."""
        return True


class Verifier(ABC):
    """
    Base verifier interface for signature verification.

    Provides signature verification functionality without the ability to sign.
    """

    @abstractmethod
    def verify(self, digest: bytes, signature: bytes) -> bool:
        """
        Verify a signature against a digest.

        Args:
            digest: 32-byte hash that was signed
            signature: Signature bytes to verify

        Returns:
            True if signature is valid, False otherwise
        """
        pass

    @abstractmethod
    def verify_accumulate_signature(self, digest: bytes, signature_obj: Dict[str, Any]) -> bool:
        """
        Verify an Accumulate signature object.

        Args:
            digest: Transaction digest that was signed
            signature_obj: Accumulate signature dictionary

        Returns:
            True if signature is valid, False otherwise
        """
        pass

    @property
    @abstractmethod
    def signature_type(self) -> SignatureType:
        """Return the signature type for this verifier."""
        pass


# Export main classes
__all__ = [
    "Signer",
    "KeySigner",
    "UserSigner",
    "Verifier",
    "SignerError"
]