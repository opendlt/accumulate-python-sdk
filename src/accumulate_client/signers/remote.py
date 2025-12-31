"""
Remote signature for Accumulate protocol.

Remote signatures are used for forwarding signatures between network partitions.
They wrap an inner signature and specify the destination partition.
"""

from typing import Dict, Any, List, Optional, Union

from ..enums import SignatureType
from ..runtime.url import AccountUrl
from .signer import Signer, SignerError


class RemoteSignatureSigner(Signer):
    """
    Remote signature implementation.

    Remote signatures are used when a signature needs to be forwarded
    from one network partition to another. They wrap an inner signature
    and include routing information.
    """

    def __init__(
        self,
        destination: Union[str, AccountUrl],
        inner_signature: Dict[str, Any],
        cause: Optional[List[bytes]] = None,
        sequence: Optional[int] = None,
        signer_version: int = 1
    ):
        """
        Initialize remote signature.

        Args:
            destination: Destination partition/account URL
            inner_signature: The wrapped signature dictionary
            cause: List of cause transaction hashes
            sequence: Optional sequence number
            signer_version: Version of the signer
        """
        self.destination = AccountUrl.parse(destination) if isinstance(destination, str) else destination
        self.inner_signature = inner_signature
        self.cause = cause or []
        self.sequence = sequence
        self._signer_version = signer_version

    def get_signature_type(self) -> SignatureType:
        """Return the REMOTE signature type."""
        return SignatureType.REMOTE

    def get_signer_url(self) -> AccountUrl:
        """Get the signer URL from the inner signature."""
        inner_signer = self.inner_signature.get("signer", "")
        if isinstance(inner_signer, dict):
            inner_signer = inner_signer.get("url", "")
        if inner_signer:
            return AccountUrl.parse(inner_signer)
        return self.destination

    def get_signer_version(self) -> int:
        """Get the signer version."""
        return self._signer_version

    def get_public_key(self) -> bytes:
        """
        Get public key from inner signature if available.

        Returns:
            Public key bytes or empty bytes
        """
        pub_key_hex = self.inner_signature.get("publicKey", "")
        if pub_key_hex:
            try:
                return bytes.fromhex(pub_key_hex)
            except ValueError:
                pass
        return b""

    def get_public_key_hash(self) -> bytes:
        """
        Remote signatures derive hash from inner signature.

        Returns:
            Public key hash from inner signature or empty bytes
        """
        from ..runtime.codec import hash_sha256
        pub_key = self.get_public_key()
        if pub_key:
            return hash_sha256(pub_key)
        return bytes(32)

    def sign(self, digest: bytes) -> bytes:
        """
        Remote signatures don't sign directly.

        They wrap existing signatures.

        Returns:
            Inner signature bytes if available
        """
        sig_hex = self.inner_signature.get("signature", "")
        if sig_hex:
            try:
                return bytes.fromhex(sig_hex)
            except ValueError:
                pass
        return b""

    def verify(self, signature: bytes, digest: bytes) -> bool:
        """
        Verification is done at the destination.

        Returns:
            True (verification happens at destination partition)
        """
        return True

    def can_initiate(self) -> bool:
        """Remote signatures can initiate if inner signature can."""
        inner_type = self.inner_signature.get("type", "").lower()
        # System signatures cannot initiate
        non_initiating = ["receipt", "partition", "internal"]
        return inner_type not in non_initiating

    def routing_location(self) -> AccountUrl:
        """Get routing location - the destination."""
        return self.destination

    def get_inner_signature_type(self) -> str:
        """Get the type of the inner signature."""
        return self.inner_signature.get("type", "unknown")

    def add_cause(self, cause_hash: bytes) -> None:
        """
        Add a cause transaction hash.

        Args:
            cause_hash: Transaction hash that caused this signature
        """
        self.cause.append(cause_hash)

    def to_accumulate_signature(self, digest: bytes, **kwargs) -> Dict[str, Any]:
        """
        Create an Accumulate protocol remote signature.

        Args:
            digest: Transaction hash
            **kwargs: Additional parameters

        Returns:
            Dictionary with remote signature structure
        """
        result = {
            "type": "remote",
            "destination": str(self.destination),
            "signature": self.inner_signature,
            "timestamp": kwargs.get("timestamp", self.get_timestamp())
        }

        if self.cause:
            result["cause"] = [c.hex() for c in self.cause]

        if self.sequence is not None:
            result["sequence"] = self.sequence

        return result

    def metadata(self) -> Dict[str, Any]:
        """Get remote signature metadata."""
        return {
            "type": self.get_signature_type().name,
            "destination": str(self.destination),
            "innerSignatureType": self.get_inner_signature_type(),
            "causeCount": len(self.cause),
            "sequence": self.sequence,
            "canInitiate": self.can_initiate()
        }


class RemoteSignatureVerifier:
    """Verifier for remote signatures."""

    def __init__(self, expected_destination: Optional[Union[str, AccountUrl]] = None):
        """
        Initialize remote signature verifier.

        Args:
            expected_destination: Optional expected destination URL
        """
        self.expected_destination = (
            AccountUrl.parse(expected_destination)
            if expected_destination and isinstance(expected_destination, str)
            else expected_destination
        )

    def signature_type(self) -> SignatureType:
        """Get the signature type for REMOTE."""
        return SignatureType.REMOTE

    def verify_remote_signature(self, signature_obj: Dict[str, Any]) -> bool:
        """
        Verify a remote signature structure.

        Args:
            signature_obj: Accumulate remote signature dictionary

        Returns:
            True if structure is valid
        """
        if not isinstance(signature_obj, dict):
            return False

        if signature_obj.get("type") != "remote":
            return False

        required_fields = ["destination", "signature"]
        for field in required_fields:
            if field not in signature_obj:
                return False

        # Verify destination if expected
        if self.expected_destination:
            try:
                sig_dest = AccountUrl.parse(signature_obj["destination"])
                if sig_dest != self.expected_destination:
                    return False
            except Exception:
                return False

        # Inner signature must be a dict
        inner_sig = signature_obj.get("signature")
        if not isinstance(inner_sig, dict):
            return False

        # Inner signature must have a type
        if "type" not in inner_sig:
            return False

        return True


def create_remote_signature(
    destination: Union[str, AccountUrl],
    inner_signer: Signer,
    digest: bytes,
    cause: Optional[List[bytes]] = None,
    **kwargs
) -> RemoteSignatureSigner:
    """
    Create a remote signature wrapping another signer's output.

    Args:
        destination: Destination partition/account URL
        inner_signer: Signer to wrap
        digest: Transaction digest
        cause: Optional cause hashes
        **kwargs: Additional signature parameters

    Returns:
        Configured RemoteSignatureSigner
    """
    inner_sig = inner_signer.to_accumulate_signature(digest, **kwargs)
    return RemoteSignatureSigner(
        destination=destination,
        inner_signature=inner_sig,
        cause=cause
    )


def wrap_for_partition(
    signer: Signer,
    digest: bytes,
    source_partition: str,
    dest_partition: str,
    **kwargs
) -> RemoteSignatureSigner:
    """
    Wrap a signature for cross-partition forwarding.

    Args:
        signer: Signer to wrap
        digest: Transaction digest
        source_partition: Source partition ID
        dest_partition: Destination partition ID
        **kwargs: Additional signature parameters

    Returns:
        RemoteSignatureSigner configured for partition forwarding
    """
    # Create the destination URL based on partition
    dest_url = f"acc://{dest_partition}.acme"

    inner_sig = signer.to_accumulate_signature(digest, **kwargs)
    return RemoteSignatureSigner(
        destination=dest_url,
        inner_signature=inner_sig
    )


# Export main classes
__all__ = [
    'RemoteSignatureSigner',
    'RemoteSignatureVerifier',
    'create_remote_signature',
    'wrap_for_partition'
]
