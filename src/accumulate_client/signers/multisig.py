r"""
Multisig and signature set handling for Accumulate Protocol.

Provides SignatureSet handling including threshold verification,
aggregation, and serialization.

Reference: C:/Accumulate_Stuff/accumulate\protocol\signature.go (SignatureSet)
"""

from __future__ import annotations
from typing import List, Dict, Any, Optional, Set
import logging

from ..enums import SignatureType, VoteType
from ..runtime.url import AccountUrl
from ..runtime.errors import AccumulateError
from .signer import Signer, SignerError

logger = logging.getLogger(__name__)


class MultisigError(SignerError):
    """Multisig-specific errors."""
    pass


class SignatureSet:
    """
    Collection of signatures for multisig operations.

    Represents a set of signatures that together satisfy a threshold requirement.
    """

    def __init__(self, threshold: int = 1):
        """
        Initialize signature set.

        Args:
            threshold: Number of signatures required for validity
        """
        self.threshold = threshold
        self.signatures: List[Dict[str, Any]] = []
        self._signer_urls: Set[str] = set()

    def add_signature(self, signature_data: Dict[str, Any], signer_url: Optional[AccountUrl] = None):
        """
        Add a signature to the set.

        Args:
            signature_data: Signature data in Accumulate format
            signer_url: URL of the signer (optional, extracted from signature_data if not provided)

        Raises:
            MultisigError: If signature is invalid or duplicate
        """
        # Extract signer URL
        if signer_url:
            signer_url_str = str(signer_url)
        else:
            signer_info = signature_data.get("signer")
            if isinstance(signer_info, dict):
                # New dict format: {'url': 'acc://...', 'version': 1}
                signer_url_str = signer_info.get("url")
                if not signer_url_str:
                    raise MultisigError("Signature signer dict must include 'url' field")
            elif isinstance(signer_info, str):
                # Legacy string format
                signer_url_str = signer_info
            else:
                raise MultisigError("Signature must include signer URL")

        # Check for duplicates
        if signer_url_str in self._signer_urls:
            raise MultisigError(f"Duplicate signature from signer: {signer_url_str}")

        # Add to set
        self.signatures.append(signature_data.copy())
        self._signer_urls.add(signer_url_str)

        logger.debug(f"Added signature from {signer_url_str} to set ({len(self.signatures)}/{self.threshold})")

    def remove_signature(self, signer_url: AccountUrl) -> bool:
        """
        Remove a signature from the set.

        Args:
            signer_url: URL of the signer to remove

        Returns:
            True if signature was removed
        """
        signer_url_str = str(signer_url)

        for i, sig_data in enumerate(self.signatures):
            if sig_data.get("signer") == signer_url_str:
                del self.signatures[i]
                self._signer_urls.remove(signer_url_str)
                logger.debug(f"Removed signature from {signer_url_str}")
                return True

        return False

    def get_signature_count(self) -> int:
        """Get number of signatures in the set."""
        return len(self.signatures)

    def is_complete(self) -> bool:
        """Check if the signature set meets the threshold."""
        return len(self.signatures) >= self.threshold

    def get_signers(self) -> List[AccountUrl]:
        """Get list of signer URLs."""
        signers = []
        for sig_data in self.signatures:
            signer_url = sig_data.get("signer")
            if signer_url:
                signers.append(AccountUrl(signer_url))
        return signers

    def get_signature_for_signer(self, signer_url: AccountUrl) -> Optional[Dict[str, Any]]:
        """
        Get signature data for a specific signer.

        Args:
            signer_url: Signer URL to look for

        Returns:
            Signature data if found
        """
        signer_url_str = str(signer_url)
        for sig_data in self.signatures:
            if sig_data.get("signer") == signer_url_str:
                return sig_data.copy()
        return None

    def has_signer(self, signer_url: AccountUrl) -> bool:
        """Check if the set contains a signature from the given signer."""
        return str(signer_url) in self._signer_urls

    def set_threshold(self, threshold: int):
        """
        Set the threshold requirement.

        Args:
            threshold: Number of signatures required

        Raises:
            MultisigError: If threshold is invalid
        """
        if threshold < 1:
            raise MultisigError("Threshold must be at least 1")

        self.threshold = threshold
        logger.debug(f"Set signature set threshold to {threshold}")

    def get_threshold(self) -> int:
        """Get the threshold requirement."""
        return self.threshold

    def clear(self):
        """Remove all signatures from the set."""
        self.signatures.clear()
        self._signer_urls.clear()
        logger.debug("Cleared signature set")

    def verify_votes(self, required_vote: VoteType = VoteType.ACCEPT) -> bool:
        """
        Verify that all signatures have the required vote type.

        Args:
            required_vote: Required vote type

        Returns:
            True if all signatures have the required vote
        """
        for sig_data in self.signatures:
            vote_str = sig_data.get("vote", "accept").lower()
            try:
                vote = VoteType[vote_str.upper()]
                if vote != required_vote:
                    return False
            except KeyError:
                return False

        return True

    def get_vote_counts(self) -> Dict[VoteType, int]:
        """
        Get count of signatures by vote type.

        Returns:
            Dictionary mapping vote types to counts
        """
        counts = {vote: 0 for vote in VoteType}

        for sig_data in self.signatures:
            vote_str = sig_data.get("vote", "accept").lower()
            try:
                vote = VoteType[vote_str.upper()]
                counts[vote] += 1
            except KeyError:
                # Unknown vote type, skip
                pass

        return counts

    def to_accumulate_format(self) -> Dict[str, Any]:
        """
        Convert to Accumulate SignatureSet format.

        Returns:
            Dictionary matching Accumulate SignatureSet structure
        """
        return {
            "type": "set",
            "threshold": self.threshold,
            "signatures": self.signatures.copy(),
            "complete": self.is_complete(),
            "signerCount": len(self.signatures)
        }

    @classmethod
    def from_accumulate_format(cls, data: Dict[str, Any]) -> SignatureSet:
        """
        Create SignatureSet from Accumulate format.

        Args:
            data: Dictionary in Accumulate SignatureSet format

        Returns:
            SignatureSet instance
        """
        threshold = data.get("threshold", 1)
        sig_set = cls(threshold)

        for sig_data in data.get("signatures", []):
            sig_set.add_signature(sig_data)

        return sig_set

    def __str__(self) -> str:
        return f"SignatureSet({len(self.signatures)}/{self.threshold}, complete={self.is_complete()})"

    def __repr__(self) -> str:
        return f"SignatureSet(threshold={self.threshold}, signatures={len(self.signatures)})"


class MultisigSigner(Signer):
    """
    Multisig signer that manages a signature set.

    Coordinates multiple signers to meet threshold requirements.
    """

    def __init__(self, authority_url: AccountUrl, threshold: int = 1):
        """
        Initialize multisig signer.

        Args:
            authority_url: URL of the authority being signed for
            threshold: Number of signatures required
        """
        self.authority_url = authority_url
        self.signature_set = SignatureSet(threshold)
        self._signers: Dict[str, Signer] = {}  # signer_url -> signer

    def get_signature_type(self) -> SignatureType:
        return SignatureType.SET

    def get_signer_url(self) -> AccountUrl:
        return self.authority_url

    def add_signer(self, signer: Signer):
        """
        Add a signer to the multisig group.

        Args:
            signer: Signer to add

        Raises:
            MultisigError: If signer already exists
        """
        signer_url_str = str(signer.get_signer_url())
        if signer_url_str in self._signers:
            raise MultisigError(f"Signer already exists: {signer_url_str}")

        self._signers[signer_url_str] = signer
        logger.debug(f"Added signer {signer_url_str} to multisig group")

    def remove_signer(self, signer_url: AccountUrl) -> bool:
        """
        Remove a signer from the multisig group.

        Args:
            signer_url: URL of signer to remove

        Returns:
            True if signer was removed
        """
        signer_url_str = str(signer_url)
        if signer_url_str in self._signers:
            del self._signers[signer_url_str]
            # Also remove any signature from this signer
            self.signature_set.remove_signature(signer_url)
            logger.debug(f"Removed signer {signer_url_str} from multisig group")
            return True
        return False

    def get_signers(self) -> List[Signer]:
        """Get list of all signers in the group."""
        return list(self._signers.values())

    def get_signer_count(self) -> int:
        """Get number of signers in the group."""
        return len(self._signers)

    def sign_with_signer(self, digest: bytes, signer_url: AccountUrl, **kwargs) -> Dict[str, Any]:
        """
        Sign with a specific signer and add to signature set.

        Args:
            digest: Hash to sign
            signer_url: URL of signer to use
            **kwargs: Additional signature parameters

        Returns:
            Signature data in Accumulate format

        Raises:
            MultisigError: If signer not found or signing fails
        """
        signer_url_str = str(signer_url)
        signer = self._signers.get(signer_url_str)
        if not signer:
            raise MultisigError(f"Signer not found: {signer_url_str}")

        # Create signature
        signature_data = signer.to_accumulate_signature(digest, **kwargs)

        # Add to signature set
        self.signature_set.add_signature(signature_data, signer_url)

        return signature_data

    def sign(self, digest: bytes) -> bytes:
        """
        Sign with all available signers up to threshold.

        Args:
            digest: Hash to sign

        Returns:
            Serialized signature set

        Raises:
            MultisigError: If no signers available
        """
        if not self._signers:
            raise MultisigError("No signers available")

        # Clear existing signatures
        self.signature_set.clear()

        # Sign with signers until threshold is met
        signed_count = 0
        for signer_url_str, signer in self._signers.items():
            if signed_count >= self.signature_set.threshold:
                break

            try:
                signer_url = AccountUrl(signer_url_str)
                self.sign_with_signer(digest, signer_url)
                signed_count += 1
            except Exception as e:
                logger.warning(f"Failed to sign with {signer_url_str}: {e}")

        if not self.signature_set.is_complete():
            raise MultisigError(f"Could not meet threshold {self.signature_set.threshold} (got {signed_count})")

        # Return serialized signature set
        from ..runtime.codec import encode_json
        return encode_json(self.signature_set.to_accumulate_format()).encode('utf-8')

    def verify(self, signature: bytes, digest: bytes) -> bool:
        """
        Verify a multisig signature.

        Args:
            signature: Serialized signature set
            digest: Hash that was signed

        Returns:
            True if signature set is valid
        """
        try:
            # Deserialize signature set
            from ..runtime.codec import loads
            sig_set_data = loads(signature.decode('utf-8'))
            sig_set = SignatureSet.from_accumulate_format(sig_set_data)

            # Check threshold
            if not sig_set.is_complete():
                return False

            # Verify each signature
            for sig_data in sig_set.signatures:
                signer_url_str = sig_data.get("signer")
                if not signer_url_str:
                    return False

                signer = self._signers.get(signer_url_str)
                if not signer:
                    return False

                # Extract signature bytes
                sig_bytes_hex = sig_data.get("signature")
                if not sig_bytes_hex:
                    return False

                sig_bytes = bytes.fromhex(sig_bytes_hex)
                if not signer.verify(sig_bytes, digest):
                    return False

            return True

        except Exception as e:
            logger.warning(f"Multisig verification failed: {e}")
            return False

    def get_public_key(self) -> bytes:
        """
        Get representative public key (from first signer).

        Returns:
            Public key bytes

        Raises:
            MultisigError: If no signers available
        """
        if not self._signers:
            raise MultisigError("No signers available")

        first_signer = next(iter(self._signers.values()))
        return first_signer.get_public_key()

    def get_signature_set(self) -> SignatureSet:
        """Get the current signature set."""
        return self.signature_set

    def is_complete(self) -> bool:
        """Check if the signature set meets the threshold."""
        return self.signature_set.is_complete()

    def set_threshold(self, threshold: int):
        """Set the signature threshold."""
        self.signature_set.set_threshold(threshold)

    def get_threshold(self) -> int:
        """Get the signature threshold."""
        return self.signature_set.get_threshold()

    def __str__(self) -> str:
        return f"MultisigSigner({self.authority_url}, {self.get_signer_count()} signers, threshold={self.get_threshold()})"

    def __repr__(self) -> str:
        return f"MultisigSigner(authority='{self.authority_url}', signers={self.get_signer_count()}, threshold={self.get_threshold()})"


# Export main classes
__all__ = [
    "SignatureSet",
    "MultisigSigner",
    "MultisigError"
]