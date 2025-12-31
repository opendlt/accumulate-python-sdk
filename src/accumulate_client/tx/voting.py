"""
Voting helpers for transaction signatures.

Provides utilities for building transaction envelopes with votes,
supporting the Accumulate protocol's multi-signature voting mechanism.

Votes are used in multi-signature scenarios where key page authorities
need to approve, reject, or abstain from transactions.

Reference: C:/Accumulate_Stuff/accumulate/protocol/signatures.yml
"""

from __future__ import annotations
from typing import Optional, List, Dict, Any, Union, TYPE_CHECKING
from hashlib import sha256
from datetime import datetime, timezone
import json

from ..enums import VoteType
from .context import BuildContext

if TYPE_CHECKING:
    from ..signers.signer import Signer


# =============================================================================
# Canonical JSON Encoding
# =============================================================================

def canonical_json(obj: Dict[str, Any]) -> bytes:
    """
    Return canonical JSON bytes for hashing.

    Produces deterministic JSON encoding with:
    - Sorted keys
    - No whitespace
    - Consistent ordering

    Args:
        obj: Dictionary to encode

    Returns:
        UTF-8 encoded JSON bytes
    """
    return json.dumps(obj, separators=(',', ':'), sort_keys=True).encode('utf-8')


def compute_transaction_hash(transaction: Dict[str, Any]) -> bytes:
    """
    Compute the hash of a transaction.

    Args:
        transaction: Transaction dictionary with header and body

    Returns:
        32-byte SHA-256 hash
    """
    tx_bytes = canonical_json(transaction)
    return sha256(tx_bytes).digest()


# =============================================================================
# Vote Building Functions
# =============================================================================

def build_vote(
    ctx: BuildContext,
    body: Dict[str, Any],
    signer: Signer,
    vote: VoteType,
    signer_url: Optional[str] = None,
    signer_version: int = 1,
    memo: Optional[str] = None
) -> Dict[str, Any]:
    """
    Build a transaction envelope with a vote.

    Creates a complete signed transaction envelope with the specified
    vote type in the signature. This is the primary function for
    building voting transactions.

    Args:
        ctx: Build context with principal, timestamp, etc.
        body: Transaction body dictionary
        signer: Signer to create the signature
        vote: Vote type (ACCEPT, REJECT, ABSTAIN, SUGGEST)
        signer_url: Optional signer URL (defaults to ctx.principal)
        signer_version: Signer version (default 1)
        memo: Optional signature memo

    Returns:
        Complete envelope with transaction and signatures

    Example:
        ```python
        ctx = BuildContext.now("acc://my-adi.acme/page")
        body = {"type": "sendTokens", "to": [...]}

        # Vote to accept
        envelope = build_vote(ctx, body, signer, VoteType.ACCEPT)

        # Vote to reject with memo
        envelope = build_vote(
            ctx, body, signer, VoteType.REJECT,
            memo="Insufficient funds verification"
        )
        ```
    """
    # Build transaction
    transaction = ctx.build_envelope(body)

    # Calculate transaction hash
    tx_hash = compute_transaction_hash(transaction)

    # Determine signer URL
    effective_signer_url = signer_url or ctx.principal

    # Create signature with vote
    sig_dict = signer.to_accumulate_signature(
        tx_hash,
        timestamp=ctx.timestamp,
        signer_url=effective_signer_url,
        signer_version=signer_version,
        vote=vote,
        memo=memo
    )

    # Override vote in signature if method doesn't support it
    if "vote" not in sig_dict or sig_dict["vote"] != vote.name.lower():
        sig_dict["vote"] = vote.name.lower()

    return {
        "transaction": transaction,
        "signatures": [sig_dict]
    }


def build_accept_vote(
    ctx: BuildContext,
    body: Dict[str, Any],
    signer: Signer,
    signer_url: Optional[str] = None,
    signer_version: int = 1,
    memo: Optional[str] = None
) -> Dict[str, Any]:
    """
    Build a transaction with an ACCEPT vote.

    Convenience function for creating accepting votes.

    Args:
        ctx: Build context
        body: Transaction body
        signer: Signer to use
        signer_url: Optional signer URL
        signer_version: Signer version
        memo: Optional signature memo

    Returns:
        Signed envelope with ACCEPT vote
    """
    return build_vote(
        ctx, body, signer, VoteType.ACCEPT,
        signer_url=signer_url,
        signer_version=signer_version,
        memo=memo
    )


def build_reject_vote(
    ctx: BuildContext,
    body: Dict[str, Any],
    signer: Signer,
    signer_url: Optional[str] = None,
    signer_version: int = 1,
    memo: Optional[str] = None
) -> Dict[str, Any]:
    """
    Build a transaction with a REJECT vote.

    Convenience function for creating rejecting votes.

    Args:
        ctx: Build context
        body: Transaction body
        signer: Signer to use
        signer_url: Optional signer URL
        signer_version: Signer version
        memo: Optional rejection reason

    Returns:
        Signed envelope with REJECT vote
    """
    return build_vote(
        ctx, body, signer, VoteType.REJECT,
        signer_url=signer_url,
        signer_version=signer_version,
        memo=memo
    )


def build_abstain_vote(
    ctx: BuildContext,
    body: Dict[str, Any],
    signer: Signer,
    signer_url: Optional[str] = None,
    signer_version: int = 1,
    memo: Optional[str] = None
) -> Dict[str, Any]:
    """
    Build a transaction with an ABSTAIN vote.

    Convenience function for creating abstaining votes.

    Args:
        ctx: Build context
        body: Transaction body
        signer: Signer to use
        signer_url: Optional signer URL
        signer_version: Signer version
        memo: Optional abstain reason

    Returns:
        Signed envelope with ABSTAIN vote
    """
    return build_vote(
        ctx, body, signer, VoteType.ABSTAIN,
        signer_url=signer_url,
        signer_version=signer_version,
        memo=memo
    )


def build_suggest_vote(
    ctx: BuildContext,
    body: Dict[str, Any],
    signer: Signer,
    signer_url: Optional[str] = None,
    signer_version: int = 1,
    memo: Optional[str] = None
) -> Dict[str, Any]:
    """
    Build a transaction with a SUGGEST vote.

    Suggest votes put forth a proposal without committing to accept/reject.

    Args:
        ctx: Build context
        body: Transaction body
        signer: Signer to use
        signer_url: Optional signer URL
        signer_version: Signer version
        memo: Optional suggestion description

    Returns:
        Signed envelope with SUGGEST vote
    """
    return build_vote(
        ctx, body, signer, VoteType.SUGGEST,
        signer_url=signer_url,
        signer_version=signer_version,
        memo=memo
    )


# =============================================================================
# Multi-Signature Vote Collection
# =============================================================================

class VoteCollector:
    """
    Collector for multi-signature votes.

    Helps aggregate votes from multiple signers for multi-signature
    transactions.

    Example:
        ```python
        collector = VoteCollector(ctx, body)

        # Add votes from multiple signers
        collector.add_accept(signer1)
        collector.add_accept(signer2)
        collector.add_reject(signer3, memo="Disagree with amount")

        # Get the final envelope
        envelope = collector.build_envelope()

        # Check vote status
        print(f"Accepts: {collector.accept_count}")
        print(f"Rejects: {collector.reject_count}")
        ```
    """

    def __init__(
        self,
        ctx: BuildContext,
        body: Dict[str, Any],
        transaction_hash: Optional[bytes] = None
    ):
        """
        Initialize VoteCollector.

        Args:
            ctx: Build context
            body: Transaction body
            transaction_hash: Pre-computed transaction hash (computed if not provided)
        """
        self.ctx = ctx
        self.body = body
        self.transaction = ctx.build_envelope(body)
        self.transaction_hash = transaction_hash or compute_transaction_hash(self.transaction)
        self.signatures: List[Dict[str, Any]] = []
        self._votes: Dict[str, VoteType] = {}  # signer_url -> vote

    @property
    def accept_count(self) -> int:
        """Count of ACCEPT votes."""
        return sum(1 for v in self._votes.values() if v == VoteType.ACCEPT)

    @property
    def reject_count(self) -> int:
        """Count of REJECT votes."""
        return sum(1 for v in self._votes.values() if v == VoteType.REJECT)

    @property
    def abstain_count(self) -> int:
        """Count of ABSTAIN votes."""
        return sum(1 for v in self._votes.values() if v == VoteType.ABSTAIN)

    @property
    def suggest_count(self) -> int:
        """Count of SUGGEST votes."""
        return sum(1 for v in self._votes.values() if v == VoteType.SUGGEST)

    @property
    def total_votes(self) -> int:
        """Total number of votes collected."""
        return len(self._votes)

    def add_vote(
        self,
        signer: Signer,
        vote: VoteType,
        signer_url: Optional[str] = None,
        signer_version: int = 1,
        memo: Optional[str] = None
    ) -> VoteCollector:
        """
        Add a vote from a signer.

        Args:
            signer: Signer to use
            vote: Vote type
            signer_url: Optional signer URL (defaults to signer's URL)
            signer_version: Signer version
            memo: Optional memo

        Returns:
            Self for chaining
        """
        effective_signer_url = signer_url or str(signer.get_signer_url())

        # Create signature
        sig_dict = signer.to_accumulate_signature(
            self.transaction_hash,
            timestamp=self.ctx.timestamp,
            signer_url=effective_signer_url,
            signer_version=signer_version,
            vote=vote,
            memo=memo
        )

        # Ensure vote is set correctly
        sig_dict["vote"] = vote.name.lower()

        # Add transaction hash
        sig_dict["transactionHash"] = self.transaction_hash.hex()

        self.signatures.append(sig_dict)
        self._votes[effective_signer_url] = vote

        return self

    def add_accept(
        self,
        signer: Signer,
        signer_url: Optional[str] = None,
        signer_version: int = 1,
        memo: Optional[str] = None
    ) -> VoteCollector:
        """Add an ACCEPT vote."""
        return self.add_vote(signer, VoteType.ACCEPT, signer_url, signer_version, memo)

    def add_reject(
        self,
        signer: Signer,
        signer_url: Optional[str] = None,
        signer_version: int = 1,
        memo: Optional[str] = None
    ) -> VoteCollector:
        """Add a REJECT vote."""
        return self.add_vote(signer, VoteType.REJECT, signer_url, signer_version, memo)

    def add_abstain(
        self,
        signer: Signer,
        signer_url: Optional[str] = None,
        signer_version: int = 1,
        memo: Optional[str] = None
    ) -> VoteCollector:
        """Add an ABSTAIN vote."""
        return self.add_vote(signer, VoteType.ABSTAIN, signer_url, signer_version, memo)

    def add_suggest(
        self,
        signer: Signer,
        signer_url: Optional[str] = None,
        signer_version: int = 1,
        memo: Optional[str] = None
    ) -> VoteCollector:
        """Add a SUGGEST vote."""
        return self.add_vote(signer, VoteType.SUGGEST, signer_url, signer_version, memo)

    def get_vote(self, signer_url: str) -> Optional[VoteType]:
        """Get the vote for a specific signer."""
        return self._votes.get(signer_url)

    def has_voted(self, signer_url: str) -> bool:
        """Check if a signer has voted."""
        return signer_url in self._votes

    def clear_votes(self) -> VoteCollector:
        """Clear all collected votes."""
        self.signatures.clear()
        self._votes.clear()
        return self

    def build_envelope(self) -> Dict[str, Any]:
        """
        Build the final envelope with all collected signatures.

        Returns:
            Complete envelope with transaction and all signatures
        """
        return {
            "transaction": self.transaction,
            "signatures": self.signatures.copy()
        }

    def get_vote_summary(self) -> Dict[str, Any]:
        """
        Get a summary of collected votes.

        Returns:
            Dictionary with vote counts and details
        """
        return {
            "total": self.total_votes,
            "accept": self.accept_count,
            "reject": self.reject_count,
            "abstain": self.abstain_count,
            "suggest": self.suggest_count,
            "voters": list(self._votes.keys())
        }


# =============================================================================
# Vote Validation Helpers
# =============================================================================

def is_accepting_vote(vote: Union[VoteType, str, int]) -> bool:
    """
    Check if a vote is accepting.

    Args:
        vote: Vote to check

    Returns:
        True if vote is ACCEPT
    """
    if isinstance(vote, str):
        return vote.lower() == "accept"
    if isinstance(vote, int):
        return vote == VoteType.ACCEPT.value
    return vote == VoteType.ACCEPT


def is_rejecting_vote(vote: Union[VoteType, str, int]) -> bool:
    """
    Check if a vote is rejecting.

    Args:
        vote: Vote to check

    Returns:
        True if vote is REJECT
    """
    if isinstance(vote, str):
        return vote.lower() == "reject"
    if isinstance(vote, int):
        return vote == VoteType.REJECT.value
    return vote == VoteType.REJECT


def parse_vote_type(vote: Union[VoteType, str, int]) -> VoteType:
    """
    Parse a vote value into VoteType enum.

    Args:
        vote: Vote as enum, string, or integer

    Returns:
        VoteType enum value

    Raises:
        ValueError: If vote cannot be parsed
    """
    if isinstance(vote, VoteType):
        return vote

    if isinstance(vote, int):
        return VoteType(vote)

    if isinstance(vote, str):
        vote_upper = vote.upper()
        for vt in VoteType:
            if vt.name == vote_upper:
                return vt
        raise ValueError(f"Unknown vote type: {vote}")

    raise ValueError(f"Cannot parse vote type from: {type(vote)}")


def check_threshold(
    accept_count: int,
    total_keys: int,
    threshold: int
) -> bool:
    """
    Check if acceptance threshold is met.

    Args:
        accept_count: Number of accept votes
        total_keys: Total number of keys in the key page
        threshold: Required threshold (M of N)

    Returns:
        True if threshold is met
    """
    return accept_count >= threshold


def check_rejection_threshold(
    reject_count: int,
    total_keys: int,
    threshold: int
) -> bool:
    """
    Check if rejection threshold is met.

    Args:
        reject_count: Number of reject votes
        total_keys: Total number of keys in the key page
        threshold: Required rejection threshold

    Returns:
        True if rejection threshold is met (transaction will be rejected)
    """
    return reject_count >= threshold


# =============================================================================
# Signature Vote Extraction
# =============================================================================

def extract_vote_from_signature(signature: Dict[str, Any]) -> Optional[VoteType]:
    """
    Extract vote type from a signature dictionary.

    Args:
        signature: Accumulate signature dictionary

    Returns:
        VoteType if present, None otherwise
    """
    vote_value = signature.get("vote")
    if vote_value is None:
        return None

    try:
        return parse_vote_type(vote_value)
    except ValueError:
        return None


def get_signature_signer(signature: Dict[str, Any]) -> Optional[str]:
    """
    Get the signer URL from a signature.

    Args:
        signature: Accumulate signature dictionary

    Returns:
        Signer URL or None
    """
    return signature.get("signer")


def analyze_signatures(
    signatures: List[Dict[str, Any]]
) -> Dict[str, Any]:
    """
    Analyze a list of signatures for vote distribution.

    Args:
        signatures: List of signature dictionaries

    Returns:
        Analysis results including vote counts and signer details
    """
    votes = {
        VoteType.ACCEPT: [],
        VoteType.REJECT: [],
        VoteType.ABSTAIN: [],
        VoteType.SUGGEST: []
    }
    unknown_votes = []

    for sig in signatures:
        signer = get_signature_signer(sig)
        vote = extract_vote_from_signature(sig)

        if vote is not None and signer:
            votes[vote].append(signer)
        elif signer:
            unknown_votes.append(signer)

    return {
        "accept": {
            "count": len(votes[VoteType.ACCEPT]),
            "signers": votes[VoteType.ACCEPT]
        },
        "reject": {
            "count": len(votes[VoteType.REJECT]),
            "signers": votes[VoteType.REJECT]
        },
        "abstain": {
            "count": len(votes[VoteType.ABSTAIN]),
            "signers": votes[VoteType.ABSTAIN]
        },
        "suggest": {
            "count": len(votes[VoteType.SUGGEST]),
            "signers": votes[VoteType.SUGGEST]
        },
        "unknown": {
            "count": len(unknown_votes),
            "signers": unknown_votes
        },
        "total": len(signatures)
    }


__all__ = [
    # Core functions
    "canonical_json",
    "compute_transaction_hash",
    # Vote building
    "build_vote",
    "build_accept_vote",
    "build_reject_vote",
    "build_abstain_vote",
    "build_suggest_vote",
    # Multi-sig collection
    "VoteCollector",
    # Validation helpers
    "is_accepting_vote",
    "is_rejecting_vote",
    "parse_vote_type",
    "check_threshold",
    "check_rejection_threshold",
    # Signature analysis
    "extract_vote_from_signature",
    "get_signature_signer",
    "analyze_signatures",
]
