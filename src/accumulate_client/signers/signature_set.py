"""
Signature set for Accumulate protocol.

A signature set contains multiple signatures that together represent
an authority's approval of a transaction. Used for multi-signature
requirements and forwarding signatures between partitions.
"""

from typing import Dict, Any, List, Optional, Union

from ..enums import SignatureType, VoteType
from ..runtime.url import AccountUrl
from .signer import Signer, SignerError


class SignatureSetSigner(Signer):
    """
    Signature set implementation.

    A signature set aggregates multiple signatures from a single authority.
    It's used when a key page requires multiple signatures (threshold > 1)
    and for forwarding signatures between network partitions.
    """

    def __init__(
        self,
        signer_url: Union[str, AccountUrl],
        authority: Union[str, AccountUrl],
        signatures: Optional[List[Dict[str, Any]]] = None,
        vote: VoteType = VoteType.ACCEPT,
        signer_version: int = 1,
        transaction_hash: Optional[bytes] = None
    ):
        """
        Initialize signature set.

        Args:
            signer_url: URL of the signer (key page)
            authority: URL of the authority (key book)
            signatures: List of signature dictionaries
            vote: Overall vote type
            signer_version: Version of the signer
            transaction_hash: Optional transaction hash
        """
        self._signer_url = AccountUrl.parse(signer_url) if isinstance(signer_url, str) else signer_url
        self.authority = AccountUrl.parse(authority) if isinstance(authority, str) else authority
        self.signatures: List[Dict[str, Any]] = signatures or []
        self._vote = vote
        self._signer_version = signer_version
        self.transaction_hash = transaction_hash

    def get_signature_type(self) -> SignatureType:
        """Return the SET signature type."""
        return SignatureType.SET

    def get_signer_url(self) -> AccountUrl:
        """Get the signer URL."""
        return self._signer_url

    def get_signer_version(self) -> int:
        """Get the signer version."""
        return self._signer_version

    def get_vote(self) -> VoteType:
        """Get the overall vote type."""
        return self._vote

    def get_public_key(self) -> bytes:
        """
        Signature sets don't have a single public key.

        Returns:
            Empty bytes
        """
        return b""

    def get_public_key_hash(self) -> bytes:
        """
        Signature sets don't have a public key hash.

        Returns:
            Empty bytes
        """
        return bytes(32)

    def sign(self, digest: bytes) -> bytes:
        """
        Signature sets don't sign directly.

        They aggregate existing signatures.

        Returns:
            Empty bytes
        """
        return b""

    def verify(self, signature: bytes, digest: bytes) -> bool:
        """
        Verification requires checking all contained signatures.

        Returns:
            True (individual signature verification is done separately)
        """
        return True

    def can_initiate(self) -> bool:
        """Signature sets can initiate if any contained signature can."""
        return len(self.signatures) > 0

    def routing_location(self) -> AccountUrl:
        """Get routing location - routes to the authority."""
        return self.authority

    def add_signature(self, signature: Dict[str, Any]) -> None:
        """
        Add a signature to the set.

        Args:
            signature: Signature dictionary to add
        """
        self.signatures.append(signature)

    def remove_signature(self, index: int) -> Optional[Dict[str, Any]]:
        """
        Remove a signature from the set by index.

        Args:
            index: Index of signature to remove

        Returns:
            Removed signature or None if index invalid
        """
        if 0 <= index < len(self.signatures):
            return self.signatures.pop(index)
        return None

    def clear_signatures(self) -> None:
        """Remove all signatures from the set."""
        self.signatures.clear()

    def signature_count(self) -> int:
        """Get the number of signatures in the set."""
        return len(self.signatures)

    def get_signature_types(self) -> List[str]:
        """Get list of signature types in the set."""
        return [sig.get("type", "unknown") for sig in self.signatures]

    def to_accumulate_signature(self, digest: bytes, **kwargs) -> Dict[str, Any]:
        """
        Create an Accumulate protocol signature set.

        Args:
            digest: Transaction hash
            **kwargs: Additional parameters

        Returns:
            Dictionary with signature set structure
        """
        return {
            "type": "set",
            "vote": self._vote.name.lower() if hasattr(self._vote, 'name') else str(self._vote),
            "signer": str(self._signer_url),
            "signerVersion": self._signer_version,
            "authority": str(self.authority),
            "transactionHash": (self.transaction_hash or digest).hex(),
            "timestamp": kwargs.get("timestamp", self.get_timestamp()),
            "signatures": self.signatures
        }

    def metadata(self) -> Dict[str, Any]:
        """Get signature set metadata."""
        return {
            "type": self.get_signature_type().name,
            "signer": str(self._signer_url),
            "authority": str(self.authority),
            "vote": self._vote.name if hasattr(self._vote, 'name') else str(self._vote),
            "signatureCount": len(self.signatures),
            "signatureTypes": self.get_signature_types(),
            "canInitiate": self.can_initiate()
        }


class SignatureSetVerifier:
    """Verifier for signature sets."""

    def __init__(
        self,
        expected_authority: Union[str, AccountUrl],
        required_threshold: int = 1
    ):
        """
        Initialize signature set verifier.

        Args:
            expected_authority: Expected authority URL
            required_threshold: Minimum number of valid signatures required
        """
        self.expected_authority = (
            AccountUrl.parse(expected_authority)
            if isinstance(expected_authority, str)
            else expected_authority
        )
        self.required_threshold = required_threshold

    def signature_type(self) -> SignatureType:
        """Get the signature type for SET."""
        return SignatureType.SET

    def verify_signature_set(self, signature_obj: Dict[str, Any]) -> bool:
        """
        Verify a signature set structure.

        Args:
            signature_obj: Accumulate signature set dictionary

        Returns:
            True if structure is valid
        """
        if not isinstance(signature_obj, dict):
            return False

        if signature_obj.get("type") != "set":
            return False

        required_fields = ["signer", "authority", "signatures"]
        for field in required_fields:
            if field not in signature_obj:
                return False

        # Verify authority matches
        try:
            sig_authority = AccountUrl.parse(signature_obj["authority"])
            if sig_authority != self.expected_authority:
                return False
        except Exception:
            return False

        # Verify signatures is a list
        signatures = signature_obj.get("signatures", [])
        if not isinstance(signatures, list):
            return False

        # Check threshold
        if len(signatures) < self.required_threshold:
            return False

        return True


def create_signature_set(
    signer_url: Union[str, AccountUrl],
    authority: Union[str, AccountUrl],
    signatures: Optional[List[Dict[str, Any]]] = None,
    vote: VoteType = VoteType.ACCEPT
) -> SignatureSetSigner:
    """
    Create a signature set.

    Args:
        signer_url: Signer (key page) URL
        authority: Authority (key book) URL
        signatures: Initial list of signatures
        vote: Vote type

    Returns:
        Configured SignatureSetSigner
    """
    return SignatureSetSigner(
        signer_url=signer_url,
        authority=authority,
        signatures=signatures,
        vote=vote
    )


def aggregate_signatures(
    signer_url: Union[str, AccountUrl],
    authority: Union[str, AccountUrl],
    signers: List[Signer],
    digest: bytes,
    **kwargs
) -> SignatureSetSigner:
    """
    Aggregate multiple signers into a signature set.

    Args:
        signer_url: Signer (key page) URL
        authority: Authority (key book) URL
        signers: List of signers to aggregate
        digest: Transaction digest to sign
        **kwargs: Additional signature parameters

    Returns:
        SignatureSetSigner with all signatures
    """
    sig_set = SignatureSetSigner(
        signer_url=signer_url,
        authority=authority,
        transaction_hash=digest
    )

    for signer in signers:
        sig_dict = signer.to_accumulate_signature(digest, **kwargs)
        sig_set.add_signature(sig_dict)

    return sig_set


# Export main classes
__all__ = [
    'SignatureSetSigner',
    'SignatureSetVerifier',
    'create_signature_set',
    'aggregate_signatures'
]
