r"""
Delegation signer implementation for Accumulate Protocol.

Provides delegation authority resolution, chain validation, and
delegated signature creation.

Reference: C:/Accumulate_Stuff/accumulate\protocol\authority.go (delegation authority)
"""

from __future__ import annotations
from typing import List, Dict, Any, Optional, Set, Tuple
import logging

from ..enums import SignatureType
from ..runtime.url import AccountUrl
from ..runtime.errors import AccumulateError
from .signer import Signer, UserSigner, SignerError

logger = logging.getLogger(__name__)


class DelegationError(SignerError):
    """Delegation-specific errors."""
    pass


class DelegationChain:
    """
    Delegation authority chain.

    Manages delegation path resolution and cycle prevention.
    """

    def __init__(self, max_depth: int = 10):
        """
        Initialize delegation chain.

        Args:
            max_depth: Maximum delegation depth to prevent infinite loops
        """
        self.max_depth = max_depth
        self.chain: List[AccountUrl] = []
        self._visited: Set[str] = set()

    def add_delegation(self, from_authority: AccountUrl, to_authority: AccountUrl) -> bool:
        """
        Add a delegation link to the chain.

        Args:
            from_authority: Authority delegating
            to_authority: Authority being delegated to

        Returns:
            True if delegation was added successfully

        Raises:
            DelegationError: If delegation would create a cycle or exceed max depth
        """
        from_str = str(from_authority)
        to_str = str(to_authority)

        # Check for cycles
        if to_str in self._visited:
            raise DelegationError(f"Delegation cycle detected: {to_authority} already in chain")

        # Check depth limit
        if len(self.chain) >= self.max_depth:
            raise DelegationError(f"Delegation chain exceeds maximum depth {self.max_depth}")

        # Add to chain
        self.chain.append(to_authority)
        self._visited.add(to_str)

        logger.debug(f"Added delegation {from_authority} -> {to_authority} (depth {len(self.chain)})")
        return True

    def resolve_authority(self, starting_authority: AccountUrl) -> AccountUrl:
        """
        Resolve the final authority in the delegation chain.

        Args:
            starting_authority: Authority to start resolution from

        Returns:
            Final authority in the chain
        """
        if not self.chain:
            return starting_authority

        return self.chain[-1]

    def get_chain_length(self) -> int:
        """Get the length of the delegation chain."""
        return len(self.chain)

    def contains_authority(self, authority: AccountUrl) -> bool:
        """Check if an authority is in the delegation chain."""
        return str(authority) in self._visited

    def get_delegation_path(self) -> List[AccountUrl]:
        """Get the complete delegation path."""
        return self.chain.copy()

    def validate_chain(self) -> bool:
        """
        Validate the delegation chain for consistency.

        Returns:
            True if chain is valid
        """
        if len(self.chain) > self.max_depth:
            return False

        # Check for duplicates
        seen = set()
        for authority in self.chain:
            authority_str = str(authority)
            if authority_str in seen:
                return False
            seen.add(authority_str)

        return True

    def clear(self):
        """Clear the delegation chain."""
        self.chain.clear()
        self._visited.clear()
        logger.debug("Cleared delegation chain")

    def __str__(self) -> str:
        chain_str = " -> ".join(str(auth) for auth in self.chain)
        return f"DelegationChain({len(self.chain)} links: {chain_str})"

    def __repr__(self) -> str:
        return f"DelegationChain(length={len(self.chain)}, max_depth={self.max_depth})"


class DelegationSigner(UserSigner):
    """
    Delegation signer implementation.

    Coordinates delegated signatures through authority chains.
    """

    def __init__(self, delegating_authority: AccountUrl, delegate_signer: Signer):
        """
        Initialize delegation signer.

        Args:
            delegating_authority: Authority that is delegating
            delegate_signer: Signer that will perform the actual signing
        """
        self.delegating_authority = delegating_authority
        self.delegate_signer = delegate_signer
        self.delegation_chain = DelegationChain()

    def get_signature_type(self) -> SignatureType:
        return SignatureType.DELEGATED

    def get_signer_url(self) -> AccountUrl:
        return self.delegating_authority

    def get_delegate_url(self) -> AccountUrl:
        """Get the URL of the delegate signer."""
        return self.delegate_signer.get_signer_url()

    def add_delegation_link(self, from_authority: AccountUrl, to_authority: AccountUrl):
        """
        Add a delegation link to the chain.

        Args:
            from_authority: Authority delegating
            to_authority: Authority being delegated to
        """
        self.delegation_chain.add_delegation(from_authority, to_authority)

    def resolve_final_authority(self) -> AccountUrl:
        """
        Resolve the final authority that will sign.

        Returns:
            Final authority in the delegation chain
        """
        return self.delegation_chain.resolve_authority(self.delegating_authority)

    def sign(self, digest: bytes) -> bytes:
        """
        Create a delegated signature.

        Args:
            digest: Hash to sign

        Returns:
            Signature bytes from delegate

        Raises:
            DelegationError: If delegation chain is invalid
        """
        if not self.delegation_chain.validate_chain():
            raise DelegationError("Invalid delegation chain")

        # Delegate to the actual signer
        return self.delegate_signer.sign(digest)

    def verify(self, signature: bytes, digest: bytes) -> bool:
        """
        Verify a delegated signature.

        Args:
            signature: Signature to verify
            digest: Hash that was signed

        Returns:
            True if signature is valid
        """
        # Verify using the delegate signer
        return self.delegate_signer.verify(signature, digest)

    def get_public_key(self) -> bytes:
        """
        Get the public key of the delegate signer.

        Returns:
            Public key bytes
        """
        return self.delegate_signer.get_public_key()

    def get_signature_bytes(self, digest: bytes) -> bytes:
        """
        Get raw signature bytes from delegate.

        Args:
            digest: Hash to sign

        Returns:
            Raw signature bytes
        """
        if hasattr(self.delegate_signer, 'get_signature_bytes'):
            return self.delegate_signer.get_signature_bytes(digest)
        else:
            return self.delegate_signer.sign(digest)

    def to_accumulate_signature(self, digest: bytes, **kwargs) -> Dict[str, Any]:
        """
        Create Accumulate delegated signature structure.

        Args:
            digest: Hash that was signed
            **kwargs: Additional signature parameters

        Returns:
            Dictionary matching Accumulate delegated signature format
        """
        # Get base signature from delegate
        delegate_sig = self.delegate_signer.to_accumulate_signature(digest, **kwargs)

        # Wrap in delegation structure
        delegated_signature = {
            "type": "delegated",
            "authority": str(self.delegating_authority),
            "delegate": str(self.get_delegate_url()),
            "delegationChain": [str(auth) for auth in self.delegation_chain.get_delegation_path()],
            "signature": delegate_sig,
            "timestamp": kwargs.get("timestamp", self.get_timestamp())
        }

        # Add transaction hash if provided
        if "transaction_hash" in kwargs:
            delegated_signature["transactionHash"] = kwargs["transaction_hash"]

        # Add memo if provided
        if "memo" in kwargs:
            delegated_signature["memo"] = kwargs["memo"]

        return delegated_signature

    def can_sign_for_authority(self, authority_url: AccountUrl) -> bool:
        """
        Check if this delegation can sign for the given authority.

        Args:
            authority_url: Authority URL to check

        Returns:
            True if this delegation can sign for the authority
        """
        # Can sign for the delegating authority
        if authority_url == self.delegating_authority:
            return True

        # Check if authority is in delegation chain
        return self.delegation_chain.contains_authority(authority_url)

    def get_delegation_depth(self) -> int:
        """Get the depth of the delegation chain."""
        return self.delegation_chain.get_chain_length()

    def validate_delegation_policy(self, policy: Dict[str, Any]) -> bool:
        """
        Validate delegation against a policy.

        Args:
            policy: Delegation policy to validate against

        Returns:
            True if delegation satisfies policy
        """
        # Check maximum depth
        max_depth = policy.get("maxDepth", 10)
        if self.get_delegation_depth() > max_depth:
            return False

        # Check allowed delegates
        allowed_delegates = policy.get("allowedDelegates", [])
        if allowed_delegates:
            delegate_url_str = str(self.get_delegate_url())
            if delegate_url_str not in allowed_delegates:
                return False

        # Check forbidden authorities
        forbidden_authorities = policy.get("forbiddenAuthorities", [])
        for authority in self.delegation_chain.get_delegation_path():
            if str(authority) in forbidden_authorities:
                return False

        return True

    def __str__(self) -> str:
        return f"DelegationSigner({self.delegating_authority} -> {self.get_delegate_url()}, depth={self.get_delegation_depth()})"

    def __repr__(self) -> str:
        return f"DelegationSigner(authority='{self.delegating_authority}', delegate='{self.get_delegate_url()}')"


class DelegationResolver:
    """
    Delegation authority resolver.

    Manages delegation lookups and authority resolution.
    """

    def __init__(self):
        """Initialize delegation resolver."""
        self._delegations: Dict[str, AccountUrl] = {}  # authority -> delegate

    def add_delegation(self, authority: AccountUrl, delegate: AccountUrl):
        """
        Add a delegation mapping.

        Args:
            authority: Authority that is delegating
            delegate: Authority being delegated to
        """
        authority_str = str(authority)
        self._delegations[authority_str] = delegate
        logger.debug(f"Added delegation mapping {authority} -> {delegate}")

    def remove_delegation(self, authority: AccountUrl) -> bool:
        """
        Remove a delegation mapping.

        Args:
            authority: Authority to remove delegation for

        Returns:
            True if delegation was removed
        """
        authority_str = str(authority)
        if authority_str in self._delegations:
            del self._delegations[authority_str]
            logger.debug(f"Removed delegation for {authority}")
            return True
        return False

    def resolve_delegation_chain(self, authority: AccountUrl, max_depth: int = 10) -> DelegationChain:
        """
        Resolve the complete delegation chain for an authority.

        Args:
            authority: Starting authority
            max_depth: Maximum delegation depth

        Returns:
            Complete delegation chain

        Raises:
            DelegationError: If cycles are detected or max depth exceeded
        """
        chain = DelegationChain(max_depth)
        current_authority = authority

        while True:
            current_str = str(current_authority)

            # Check if there's a delegation for this authority
            delegate = self._delegations.get(current_str)
            if not delegate:
                break

            # Add to chain
            chain.add_delegation(current_authority, delegate)
            current_authority = delegate

        return chain

    def get_final_authority(self, authority: AccountUrl) -> AccountUrl:
        """
        Get the final authority in a delegation chain.

        Args:
            authority: Starting authority

        Returns:
            Final authority
        """
        chain = self.resolve_delegation_chain(authority)
        return chain.resolve_authority(authority)

    def has_delegation(self, authority: AccountUrl) -> bool:
        """
        Check if an authority has a delegation.

        Args:
            authority: Authority to check

        Returns:
            True if authority has a delegation
        """
        return str(authority) in self._delegations

    def get_delegation_count(self) -> int:
        """Get the number of delegations."""
        return len(self._delegations)

    def clear_all_delegations(self):
        """Clear all delegation mappings."""
        self._delegations.clear()
        logger.debug("Cleared all delegations")

    def get_all_delegations(self) -> Dict[AccountUrl, AccountUrl]:
        """
        Get all delegation mappings.

        Returns:
            Dictionary mapping authorities to delegates
        """
        return {AccountUrl(auth): delegate for auth, delegate in self._delegations.items()}

    def __str__(self) -> str:
        return f"DelegationResolver({len(self._delegations)} delegations)"

    def __repr__(self) -> str:
        return f"DelegationResolver(count={len(self._delegations)})"


# Export main classes
__all__ = [
    "DelegationSigner",
    "DelegationChain",
    "DelegationResolver",
    "DelegationError"
]