"""
Authority signer for Accumulate protocol.

Authority signatures are produced by authorities as part of the consensus process.
They represent an authority's vote on a transaction.
"""

from typing import Dict, Any, Optional, List, Union

from ..enums import SignatureType, VoteType
from ..runtime.url import AccountUrl
from .signer import Signer, SignerError


class AuthoritySigner(Signer):
    """
    Authority signature implementation.

    Authority signatures are produced when an authority votes on a pending transaction.
    They contain the authority URL, transaction ID being voted on, and the vote type.

    Unlike key-based signatures, authority signatures don't sign data directly -
    they represent a vote from a key book/page authority.
    """

    def __init__(
        self,
        origin: Union[str, AccountUrl],
        authority: Union[str, AccountUrl],
        tx_id: str,
        cause: Optional[str] = None,
        vote: VoteType = VoteType.ACCEPT,
        delegator: Optional[List[Union[str, AccountUrl]]] = None,
        memo: Optional[str] = None,
        signer_version: int = 1
    ):
        """
        Initialize authority signer.

        Args:
            origin: The origin key page URL
            authority: URL of the authority (key book)
            tx_id: Transaction ID being voted on
            cause: Optional cause transaction ID
            vote: Vote type (accept/reject/abstain/suggest)
            delegator: Optional list of delegator URLs for delegated authority
            memo: Optional memo string
            signer_version: Version of the signer (default: 1)
        """
        self.origin = AccountUrl.parse(origin) if isinstance(origin, str) else origin
        self.authority = AccountUrl.parse(authority) if isinstance(authority, str) else authority
        self.tx_id = tx_id
        self.cause = cause
        self._vote = vote
        self.delegator = [
            AccountUrl.parse(d) if isinstance(d, str) else d
            for d in (delegator or [])
        ]
        self.memo = memo
        self._signer_version = signer_version

    def get_signature_type(self) -> SignatureType:
        """Return the AUTHORITY signature type."""
        return SignatureType.AUTHORITY

    def get_signer_url(self) -> AccountUrl:
        """Get the signer URL (origin key page)."""
        return self.origin

    def get_signer_version(self) -> int:
        """Get the signer version."""
        return self._signer_version

    def get_vote(self) -> VoteType:
        """Get the vote type."""
        return self._vote

    def get_public_key(self) -> bytes:
        """
        Authority signatures don't have a public key.

        Returns:
            Empty bytes
        """
        return b""

    def get_public_key_hash(self) -> bytes:
        """
        Authority signatures don't have a public key hash.

        Returns:
            Empty bytes (32 zeros for compatibility)
        """
        return bytes(32)

    def sign(self, digest: bytes) -> bytes:
        """
        Authority signatures don't sign data directly.

        They represent a vote recorded by the network.

        Returns:
            Empty bytes
        """
        return b""

    def verify(self, signature: bytes, digest: bytes) -> bool:
        """
        Authority signatures are verified by the network through consensus.

        Returns:
            True (verification is implicit through network acceptance)
        """
        return True

    def can_initiate(self) -> bool:
        """Authority signatures cannot initiate transactions."""
        return False

    def routing_location(self) -> AccountUrl:
        """Get routing location - routes to the authority."""
        return self.authority

    def to_accumulate_signature(self, digest: bytes, **kwargs) -> Dict[str, Any]:
        """
        Create an Accumulate protocol authority signature.

        Args:
            digest: Transaction hash (used as transaction reference)
            **kwargs: Additional parameters

        Returns:
            Dictionary with authority signature structure
        """
        signature = {
            "type": "authority",
            "origin": str(self.origin),
            "authority": str(self.authority),
            "vote": self._vote.name.lower() if hasattr(self._vote, 'name') else str(self._vote),
            "txID": self.tx_id,
            "transactionHash": digest.hex(),
            "signerVersion": self._signer_version
        }

        if self.cause:
            signature["cause"] = self.cause

        if self.delegator:
            signature["delegator"] = [str(d) for d in self.delegator]

        if self.memo:
            signature["memo"] = self.memo

        # Add timestamp
        signature["timestamp"] = kwargs.get("timestamp", self.get_timestamp())

        return signature

    def metadata(self) -> Dict[str, Any]:
        """Get authority signature metadata."""
        return {
            "type": self.get_signature_type().name,
            "origin": str(self.origin),
            "authority": str(self.authority),
            "vote": self._vote.name if hasattr(self._vote, 'name') else str(self._vote),
            "txID": self.tx_id,
            "canInitiate": False,
            "hasDelegation": len(self.delegator) > 0
        }


class AuthorityVerifier:
    """Verifier for authority signatures."""

    def __init__(self, expected_authority: Union[str, AccountUrl]):
        """
        Initialize authority verifier.

        Args:
            expected_authority: Expected authority URL
        """
        self.expected_authority = (
            AccountUrl.parse(expected_authority)
            if isinstance(expected_authority, str)
            else expected_authority
        )

    def signature_type(self) -> SignatureType:
        """Get the signature type for AUTHORITY."""
        return SignatureType.AUTHORITY

    def verify_authority_signature(self, signature_obj: Dict[str, Any]) -> bool:
        """
        Verify an authority signature object structure.

        Args:
            signature_obj: Accumulate authority signature dictionary

        Returns:
            True if structure is valid and authority matches
        """
        if not isinstance(signature_obj, dict):
            return False

        if signature_obj.get("type") != "authority":
            return False

        required_fields = ["origin", "authority", "vote", "txID"]
        for field in required_fields:
            if field not in signature_obj:
                return False

        # Verify authority matches expected
        try:
            sig_authority = AccountUrl.parse(signature_obj["authority"])
            if sig_authority != self.expected_authority:
                return False
        except Exception:
            return False

        # Validate vote type
        valid_votes = ["accept", "reject", "abstain", "suggest"]
        if signature_obj.get("vote", "").lower() not in valid_votes:
            return False

        return True


def create_authority_vote(
    origin: Union[str, AccountUrl],
    authority: Union[str, AccountUrl],
    tx_id: str,
    vote: VoteType = VoteType.ACCEPT,
    cause: Optional[str] = None,
    memo: Optional[str] = None
) -> AuthoritySigner:
    """
    Create an authority vote signature.

    Args:
        origin: Origin key page URL
        authority: Authority (key book) URL
        tx_id: Transaction ID to vote on
        vote: Vote type (default: ACCEPT)
        cause: Optional cause transaction
        memo: Optional memo

    Returns:
        AuthoritySigner configured for voting
    """
    return AuthoritySigner(
        origin=origin,
        authority=authority,
        tx_id=tx_id,
        cause=cause,
        vote=vote,
        memo=memo
    )


# Export main classes
__all__ = [
    'AuthoritySigner',
    'AuthorityVerifier',
    'create_authority_vote'
]
