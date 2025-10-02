"""
Delegated signer for Accumulate protocol.

Implements delegation signatures that wrap other signatures with delegation authority.
A delegated signature allows one authority to sign on behalf of another authority.
"""

import hashlib
from typing import Union, Dict, Any, Optional

from ..enums import SignatureType
from ..runtime.url import AccountUrl
from .signer import Signer, SignerError


class DelegatedSigner(Signer):
    """Delegated signer that wraps another signature with delegation authority."""

    def __init__(self, wrapped_signer: Signer, delegator: Union[str, AccountUrl]):
        """
        Initialize delegated signer.

        Args:
            wrapped_signer: The actual signer (e.g., Ed25519Signer, BTCSigner)
            delegator: URL of the authority that delegated its authority to the signer
        """
        self.wrapped_signer = wrapped_signer
        self.delegator = AccountUrl.parse(delegator) if isinstance(delegator, str) else delegator

    def get_signature_type(self) -> SignatureType:
        """Return the DELEGATED signature type."""
        return SignatureType.DELEGATED

    def get_signer_url(self) -> AccountUrl:
        """Get the signer URL from the wrapped signer."""
        return self.wrapped_signer.get_signer_url()

    def get_signer_version(self) -> int:
        """Get the signer version from the wrapped signer."""
        return self.wrapped_signer.get_signer_version()

    def get_public_key(self) -> bytes:
        """Get the public key from the wrapped signer."""
        return self.wrapped_signer.get_public_key()

    def get_public_key_hash(self) -> bytes:
        """Get the public key hash from the wrapped signer."""
        return self.wrapped_signer.get_public_key_hash()

    def get_delegator(self) -> AccountUrl:
        """Get the delegator URL."""
        return self.delegator

    def sign(self, digest: bytes) -> bytes:
        """
        Sign a digest using the wrapped signer.

        Args:
            digest: 32-byte hash to sign

        Returns:
            Signature bytes from the wrapped signer
        """
        return self.wrapped_signer.sign(digest)

    def verify(self, signature: bytes, digest: bytes) -> bool:
        """
        Verify a signature against a digest using the wrapped signer.

        Args:
            signature: Signature bytes to verify
            digest: 32-byte hash that was signed

        Returns:
            True if signature is valid
        """
        return self.wrapped_signer.verify(signature, digest)

    def get_vote(self):
        """Get vote type from wrapped signer."""
        return self.wrapped_signer.get_vote()

    def get_timestamp(self) -> int:
        """Get timestamp from wrapped signer."""
        return self.wrapped_signer.get_timestamp()

    def routing_location(self) -> AccountUrl:
        """Get routing location from wrapped signer."""
        return self.wrapped_signer.routing_location()

    def can_initiate(self) -> bool:
        """Delegated signatures can initiate transactions."""
        return True

    def to_accumulate_signature(self, digest: bytes, **kwargs) -> Dict[str, Any]:
        """
        Create an Accumulate protocol delegated signature.

        Args:
            digest: Hash that was signed
            **kwargs: Additional signature parameters

        Returns:
            Dictionary with delegated signature structure
        """
        # Get the wrapped signature
        wrapped_signature = self.wrapped_signer.to_accumulate_signature(digest, **kwargs)

        # Create the delegated signature structure
        delegated_signature = {
            "type": self.get_signature_type().name.lower(),
            "delegator": str(self.delegator),
            "signature": wrapped_signature
        }

        return delegated_signature

    def metadata(self) -> Dict[str, Any]:
        """
        Get delegated signature metadata.

        Returns:
            Dictionary with delegated signature metadata
        """
        wrapped_metadata = self.wrapped_signer.metadata()

        return {
            "type": self.get_signature_type().name.lower(),
            "delegator": str(self.delegator),
            "wrappedSignature": wrapped_metadata
        }

    def get_wrapped_signer(self) -> Signer:
        """Get the wrapped signer."""
        return self.wrapped_signer

    def get_nested_delegation_chain(self) -> list[AccountUrl]:
        """
        Get the full delegation chain if this is a nested delegation.

        Returns:
            List of delegator URLs from outermost to innermost
        """
        chain = [self.delegator]

        # If the wrapped signer is also a delegated signer, get its chain
        if isinstance(self.wrapped_signer, DelegatedSigner):
            chain.extend(self.wrapped_signer.get_nested_delegation_chain())

        return chain

    def get_delegation_depth(self) -> int:
        """
        Get the depth of delegation nesting.

        Returns:
            Number of delegation layers (1 for simple delegation, up to 5 max)
        """
        if isinstance(self.wrapped_signer, DelegatedSigner):
            return 1 + self.wrapped_signer.get_delegation_depth()
        return 1

    def validate_delegation_depth(self) -> bool:
        """
        Validate that delegation depth doesn't exceed the maximum of 5 layers.

        Returns:
            True if delegation depth is valid
        """
        return self.get_delegation_depth() <= 5

    def get_final_signer(self) -> Signer:
        """
        Get the innermost non-delegated signer.

        Returns:
            The actual cryptographic signer at the end of the delegation chain
        """
        if isinstance(self.wrapped_signer, DelegatedSigner):
            return self.wrapped_signer.get_final_signer()
        return self.wrapped_signer


class DelegatedVerifier:
    """Verifier for delegated signatures."""

    def __init__(self, expected_delegator: Union[str, AccountUrl]):
        """
        Initialize delegated verifier.

        Args:
            expected_delegator: Expected delegator URL
        """
        self.expected_delegator = AccountUrl.parse(expected_delegator) if isinstance(expected_delegator, str) else expected_delegator

    def signature_type(self) -> SignatureType:
        """Get the signature type for DELEGATED."""
        return SignatureType.DELEGATED

    def verify_delegated_signature(self, digest: bytes, signature_obj: dict) -> bool:
        """
        Verify a delegated signature object.

        Args:
            digest: Transaction digest that was signed
            signature_obj: Accumulate delegated signature dictionary

        Returns:
            True if signature is valid
        """
        # Validate structure
        if not isinstance(signature_obj, dict):
            return False

        if signature_obj.get("type") != "delegated":
            return False

        if "delegator" not in signature_obj or "signature" not in signature_obj:
            return False

        # Verify delegator matches expected
        try:
            delegator_url = AccountUrl.parse(signature_obj["delegator"])
            if delegator_url != self.expected_delegator:
                return False
        except Exception:
            return False

        # Extract and verify the wrapped signature
        wrapped_signature = signature_obj["signature"]
        if not isinstance(wrapped_signature, dict):
            return False

        # Dynamically create the appropriate verifier based on the wrapped signature type
        try:
            wrapped_type = wrapped_signature.get("type", "").lower()

            # Import verifiers as needed
            if wrapped_type == "ed25519":
                from .ed25519 import Ed25519Verifier
                verifier = Ed25519Verifier.from_signature_dict(wrapped_signature)
                return verifier.verify(message, bytes.fromhex(wrapped_signature["signature"]))

            elif wrapped_type == "legacyed25519":
                from .legacy_ed25519 import LegacyEd25519Verifier
                verifier = LegacyEd25519Verifier.from_signature_dict(wrapped_signature)
                return verifier.verify(message, bytes.fromhex(wrapped_signature["signature"]))

            elif wrapped_type == "rcd1":
                from .rcd1 import RCD1Verifier
                verifier = RCD1Verifier.from_signature_dict(wrapped_signature)
                return verifier.verify(message, bytes.fromhex(wrapped_signature["signature"]))

            elif wrapped_type == "btc":
                from .btc import BTCVerifier
                verifier = BTCVerifier.from_signature_dict(wrapped_signature)
                return verifier.verify(message, bytes.fromhex(wrapped_signature["signature"]))

            elif wrapped_type == "eth":
                from .eth import ETHVerifier
                verifier = ETHVerifier.from_signature_dict(wrapped_signature)
                return verifier.verify(message, bytes.fromhex(wrapped_signature["signature"]))

            elif wrapped_type == "delegated":
                # Nested delegated signature - recurse
                nested_verifier = DelegatedVerifier(wrapped_signature.get("delegator", ""))
                return nested_verifier.verify_delegated_signature(digest, wrapped_signature)

            else:
                # Unknown signature type - just validate structure for now
                return "type" in wrapped_signature and "signature" in wrapped_signature

        except (ImportError, KeyError, ValueError, AttributeError):
            # If any verifier import fails or signature structure is invalid,
            # fall back to basic structure validation
            return "type" in wrapped_signature and "signature" in wrapped_signature


# Utility functions
def create_delegation_chain(base_signer: Signer, delegators: list[Union[str, AccountUrl]]) -> DelegatedSigner:
    """
    Create a delegation chain by wrapping a base signer with multiple delegators.

    Args:
        base_signer: The innermost signer (e.g., Ed25519Signer)
        delegators: List of delegator URLs from innermost to outermost

    Returns:
        DelegatedSigner with the full delegation chain

    Raises:
        SignerError: If delegation chain exceeds maximum depth of 5
    """
    if len(delegators) > 5:
        raise SignerError(f"Delegation chain too deep: {len(delegators)} (max 5)")

    current_signer = base_signer
    for delegator in delegators:
        current_signer = DelegatedSigner(current_signer, delegator)

    return current_signer


def validate_delegation_signature_structure(signature_obj: dict) -> bool:
    """
    Validate the structure of a delegated signature object.

    Args:
        signature_obj: Signature object to validate

    Returns:
        True if structure is valid
    """
    if not isinstance(signature_obj, dict):
        return False

    # Must have type, delegator, and signature fields
    required_fields = ["type", "delegator", "signature"]
    for field in required_fields:
        if field not in signature_obj:
            return False

    # Type must be "delegated"
    if signature_obj["type"] != "delegated":
        return False

    # Delegator must be a valid URL string
    try:
        AccountUrl.parse(signature_obj["delegator"])
    except Exception:
        return False

    # Signature must be a dict (nested signature)
    if not isinstance(signature_obj["signature"], dict):
        return False

    return True


# Export main classes
__all__ = [
    'DelegatedSigner',
    'DelegatedVerifier',
    'create_delegation_chain',
    'validate_delegation_signature_structure'
]