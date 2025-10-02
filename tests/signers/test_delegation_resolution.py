"""
Test delegation resolution and validation.

Tests delegation chain resolution, cycle detection,
and final signer resolution for delegated signatures.
"""

import pytest
import sys
from pathlib import Path

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))
from helpers import mk_ed25519_keypair, mk_identity_url

from accumulate_client.runtime.url import AccountUrl
from accumulate_client.runtime.errors import AccumulateError
from accumulate_client.crypto.ed25519 import Ed25519PrivateKey
from accumulate_client.signers.ed25519 import Ed25519Signer


class ValidationError(AccumulateError):
    """Validation error for delegation testing."""
    pass


class DelegationChain:
    """
    Mock delegation chain implementation for testing.

    TODO[ACC-P2-S910]: Replace with actual delegation infrastructure when implemented
    """

    def __init__(self):
        """Initialize delegation chain."""
        self.delegations = {}  # delegate -> delegator mapping

    def add_delegation(self, delegate: str, delegator: str):
        """
        Add a delegation relationship.

        Args:
            delegate: The delegate URL
            delegator: The delegator URL
        """
        self.delegations[delegate] = delegator

    def resolve_signer(self, start_url: str, max_depth: int = 10) -> str:
        """
        Resolve the final signer through delegation chain.

        Args:
            start_url: Starting URL
            max_depth: Maximum delegation depth

        Returns:
            Final signer URL

        Raises:
            ValidationError: If cycle detected or max depth exceeded
        """
        visited = set()
        current = start_url
        depth = 0

        while current in self.delegations and depth < max_depth:
            if current in visited:
                raise ValidationError(f"Delegation cycle detected involving {current}")

            visited.add(current)
            current = self.delegations[current]
            depth += 1

        if depth >= max_depth:
            raise ValidationError(f"Delegation chain too deep (max {max_depth})")

        return current


def test_delegation_chain_creation():
    """Test basic delegation chain creation."""
    chain = DelegationChain()

    # Add simple delegation: A delegates to B
    chain.add_delegation("acc://a.acme", "acc://b.acme")

    assert "acc://a.acme" in chain.delegations
    assert chain.delegations["acc://a.acme"] == "acc://b.acme"


def test_simple_delegation_resolution():
    """Test simple delegation resolution."""
    chain = DelegationChain()

    # A delegates to B
    chain.add_delegation("acc://a.acme", "acc://b.acme")

    # Resolving A should give B
    final_signer = chain.resolve_signer("acc://a.acme")
    assert final_signer == "acc://b.acme"

    # Resolving B should give B (no further delegation)
    final_signer = chain.resolve_signer("acc://b.acme")
    assert final_signer == "acc://b.acme"


def test_chain_delegation_resolution():
    """Test multi-level delegation chain resolution."""
    chain = DelegationChain()

    # Create chain: A -> B -> C -> D
    chain.add_delegation("acc://a.acme", "acc://b.acme")
    chain.add_delegation("acc://b.acme", "acc://c.acme")
    chain.add_delegation("acc://c.acme", "acc://d.acme")

    # Resolving A should give D (final signer)
    final_signer = chain.resolve_signer("acc://a.acme")
    assert final_signer == "acc://d.acme"

    # Resolving B should give D
    final_signer = chain.resolve_signer("acc://b.acme")
    assert final_signer == "acc://d.acme"

    # Resolving C should give D
    final_signer = chain.resolve_signer("acc://c.acme")
    assert final_signer == "acc://d.acme"

    # Resolving D should give D
    final_signer = chain.resolve_signer("acc://d.acme")
    assert final_signer == "acc://d.acme"


def test_delegation_cycle_detection():
    """Test that delegation cycles are detected and raise ValidationError."""
    chain = DelegationChain()

    # Create simple cycle: A -> B -> A
    chain.add_delegation("acc://a.acme", "acc://b.acme")
    chain.add_delegation("acc://b.acme", "acc://a.acme")

    with pytest.raises(ValidationError, match="Delegation cycle detected"):
        chain.resolve_signer("acc://a.acme")


def test_complex_delegation_cycle_detection():
    """Test cycle detection in longer chains."""
    chain = DelegationChain()

    # Create longer cycle: A -> B -> C -> D -> B
    chain.add_delegation("acc://a.acme", "acc://b.acme")
    chain.add_delegation("acc://b.acme", "acc://c.acme")
    chain.add_delegation("acc://c.acme", "acc://d.acme")
    chain.add_delegation("acc://d.acme", "acc://b.acme")  # Creates cycle

    with pytest.raises(ValidationError, match="Delegation cycle detected"):
        chain.resolve_signer("acc://a.acme")


def test_delegation_depth_limit():
    """Test that excessive delegation depth is rejected."""
    chain = DelegationChain()

    # Create very long chain
    prev = "acc://root.acme"
    for i in range(15):  # Create chain longer than max_depth (10)
        current = f"acc://delegate{i}.acme"
        chain.add_delegation(prev, current)
        prev = current

    with pytest.raises(ValidationError, match="Delegation chain too deep"):
        chain.resolve_signer("acc://root.acme", max_depth=10)


def test_delegation_with_signer_integration():
    """Test delegation resolution integrated with signer functionality."""
    chain = DelegationChain()

    # Create delegation: delegate -> final_signer
    delegate_url = "acc://delegate.acme"
    final_signer_url = "acc://final.acme"

    chain.add_delegation(delegate_url, final_signer_url)

    # Create actual signer for final signer
    private_key, _ = mk_ed25519_keypair(seed=6001)
    final_signer = Ed25519Signer(private_key, final_signer_url)

    # Resolve delegation
    resolved_url = chain.resolve_signer(delegate_url)
    assert resolved_url == final_signer_url

    # The resolved URL should match the actual signer's URL
    assert str(final_signer.get_signer_url()) == resolved_url


def test_delegation_mixed_scenarios():
    """Test mixed delegation scenarios."""
    chain = DelegationChain()

    # Mixed scenario:
    # - A delegates to B
    # - B delegates to C
    # - D delegates to C (multiple paths to same final signer)
    # - E has no delegation (self-signer)

    chain.add_delegation("acc://a.acme", "acc://b.acme")
    chain.add_delegation("acc://b.acme", "acc://c.acme")
    chain.add_delegation("acc://d.acme", "acc://c.acme")

    # A -> B -> C
    assert chain.resolve_signer("acc://a.acme") == "acc://c.acme"

    # B -> C
    assert chain.resolve_signer("acc://b.acme") == "acc://c.acme"

    # D -> C
    assert chain.resolve_signer("acc://d.acme") == "acc://c.acme"

    # E (no delegation)
    assert chain.resolve_signer("acc://e.acme") == "acc://e.acme"

    # C (final signer)
    assert chain.resolve_signer("acc://c.acme") == "acc://c.acme"


def test_delegation_self_reference():
    """Test delegation self-reference detection."""
    chain = DelegationChain()

    # Self-delegation: A -> A (should be detected as cycle)
    chain.add_delegation("acc://a.acme", "acc://a.acme")

    with pytest.raises(ValidationError, match="Delegation cycle detected"):
        chain.resolve_signer("acc://a.acme")


def test_empty_delegation_chain():
    """Test behavior with empty delegation chain."""
    chain = DelegationChain()

    # No delegations defined
    result = chain.resolve_signer("acc://any.acme")
    assert result == "acc://any.acme"  # Should return self


# TODO[ACC-P2-S911]: Add tests for delegation authentication and verification
# TODO[ACC-P2-S912]: Add tests for delegation revocation scenarios
# TODO[ACC-P2-S913]: Add tests for time-based delegation expiration
# TODO[ACC-P2-S914]: Add tests for delegation authorization validation
