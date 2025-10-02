r"""
KeyPage signer implementation for Accumulate Protocol.

Provides ADI KeyPage semantics including versioning, nonce handling,
and signer resolution by page/key hash.

Reference: C:/Accumulate_Stuff/accumulate\protocol\accounts.go (KeyPage)
Reference: C:/Accumulate_Stuff/accumulate\protocol\authority.go (KeyPage authority)
"""

from __future__ import annotations
from typing import Dict, List, Optional, Any, Tuple
import logging

from ..enums import SignatureType
from ..runtime.url import AccountUrl
from ..runtime.errors import AccumulateError
from .signer import Signer, UserSigner, SignerError

logger = logging.getLogger(__name__)


class KeyPageError(SignerError):
    """KeyPage-specific errors."""
    pass


class KeySpec:
    """
    Key specification within a KeyPage.

    Matches the Go protocol.KeySpec structure.
    """

    def __init__(self, public_key_hash: bytes, delegate: Optional[AccountUrl] = None, last_used_on: int = 0):
        """
        Initialize key specification.

        Args:
            public_key_hash: Hash of the public key
            delegate: Optional delegate URL
            last_used_on: Last block height this key was used
        """
        self.public_key_hash = public_key_hash
        self.delegate = delegate
        self.last_used_on = last_used_on

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        result = {
            "publicKeyHash": self.public_key_hash.hex(),
            "lastUsedOn": self.last_used_on
        }
        if self.delegate:
            result["delegate"] = str(self.delegate)
        return result

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> KeySpec:
        """Create from dictionary representation."""
        public_key_hash = bytes.fromhex(data["publicKeyHash"])
        delegate = AccountUrl(data["delegate"]) if data.get("delegate") else None
        last_used_on = data.get("lastUsedOn", 0)
        return cls(public_key_hash, delegate, last_used_on)

    def __str__(self) -> str:
        return f"KeySpec({self.public_key_hash.hex()[:16]}...)"


class KeyPageSigner(UserSigner):
    """
    KeyPage signer implementation.

    Provides ADI KeyPage semantics with versioning and key management.
    """

    def __init__(self, page_url: AccountUrl, version: int = 1, accept_threshold: int = 1):
        """
        Initialize KeyPage signer.

        Args:
            page_url: URL of the KeyPage
            version: Version number of the KeyPage
            accept_threshold: Number of signatures required for acceptance
        """
        self.page_url = page_url
        self.version = version
        self.accept_threshold = accept_threshold
        self.keys: List[KeySpec] = []
        self._signers: Dict[bytes, Signer] = {}  # key_hash -> signer

    def get_signature_type(self) -> SignatureType:
        """KeyPage uses the underlying key signature type."""
        # Return ED25519 as default - actual type determined by key
        return SignatureType.ED25519

    def get_signer_url(self) -> AccountUrl:
        return self.page_url

    def get_signer_version(self) -> int:
        return self.version

    def add_key(self, signer: Signer, delegate: Optional[AccountUrl] = None) -> bytes:
        """
        Add a key to the KeyPage.

        Args:
            signer: Signer to add
            delegate: Optional delegate URL

        Returns:
            Public key hash
        """
        public_key_hash = signer.get_public_key_hash()
        key_spec = KeySpec(public_key_hash, delegate)

        self.keys.append(key_spec)
        self._signers[public_key_hash] = signer

        logger.debug(f"Added key {public_key_hash.hex()[:16]}... to KeyPage {self.page_url}")
        return public_key_hash

    def remove_key(self, public_key_hash: bytes) -> bool:
        """
        Remove a key from the KeyPage.

        Args:
            public_key_hash: Hash of the key to remove

        Returns:
            True if key was removed
        """
        # Find and remove key spec
        for i, key_spec in enumerate(self.keys):
            if key_spec.public_key_hash == public_key_hash:
                del self.keys[i]
                self._signers.pop(public_key_hash, None)
                logger.debug(f"Removed key {public_key_hash.hex()[:16]}... from KeyPage {self.page_url}")
                return True

        return False

    def get_key_by_hash(self, public_key_hash: bytes) -> Optional[Signer]:
        """
        Get signer by public key hash.

        Args:
            public_key_hash: Hash of the public key

        Returns:
            Signer if found, None otherwise
        """
        return self._signers.get(public_key_hash)

    def get_keys(self) -> List[KeySpec]:
        """Get list of all key specifications."""
        return self.keys.copy()

    def get_key_count(self) -> int:
        """Get number of keys in the page."""
        return len(self.keys)

    def set_threshold(self, threshold: int):
        """
        Set the acceptance threshold.

        Args:
            threshold: Number of signatures required
        """
        if threshold < 1:
            raise KeyPageError("Threshold must be at least 1")
        if threshold > len(self.keys):
            raise KeyPageError(f"Threshold {threshold} exceeds key count {len(self.keys)}")

        self.accept_threshold = threshold
        logger.debug(f"Set threshold to {threshold} for KeyPage {self.page_url}")

    def get_threshold(self) -> int:
        """Get the acceptance threshold."""
        return self.accept_threshold

    def increment_version(self):
        """Increment the KeyPage version."""
        self.version += 1
        logger.debug(f"Incremented KeyPage {self.page_url} version to {self.version}")

    def update_key_usage(self, public_key_hash: bytes, block_height: int):
        """
        Update the last used block for a key.

        Args:
            public_key_hash: Hash of the key
            block_height: Block height where key was used
        """
        for key_spec in self.keys:
            if key_spec.public_key_hash == public_key_hash:
                key_spec.last_used_on = block_height
                break

    def get_book_url(self) -> AccountUrl:
        """
        Get the KeyBook URL for this KeyPage.

        Returns:
            KeyBook URL
        """
        # Parse KeyPage URL to get KeyBook
        # Format: acc://identity/book/page/N -> acc://identity/book
        url_parts = str(self.page_url).split('/')
        if len(url_parts) >= 3 and url_parts[-2] == 'page':
            book_parts = url_parts[:-2]  # Remove /page/N
            return AccountUrl('/'.join(book_parts))
        else:
            # Assume KeyPage is directly under identity
            return self.page_url.parent()

    def get_authority_url(self) -> AccountUrl:
        """
        Get the authority URL (usually the identity).

        Returns:
            Authority URL
        """
        return self.get_book_url().parent()

    def sign(self, digest: bytes) -> bytes:
        """
        Sign with the first available key.

        Args:
            digest: Hash to sign

        Returns:
            Signature bytes

        Raises:
            KeyPageError: If no keys available
        """
        if not self._signers:
            raise KeyPageError("No keys available for signing")

        # Use first available signer
        signer = next(iter(self._signers.values()))
        return signer.sign(digest)

    def sign_with_key(self, digest: bytes, public_key_hash: bytes) -> bytes:
        """
        Sign with a specific key.

        Args:
            digest: Hash to sign
            public_key_hash: Hash of the key to use

        Returns:
            Signature bytes

        Raises:
            KeyPageError: If key not found
        """
        signer = self._signers.get(public_key_hash)
        if not signer:
            raise KeyPageError(f"Key not found: {public_key_hash.hex()}")

        return signer.sign(digest)

    def verify(self, signature: bytes, digest: bytes, public_key_hash: Optional[bytes] = None) -> bool:
        """
        Verify a signature.

        Args:
            signature: Signature to verify
            digest: Hash that was signed
            public_key_hash: Optional key hash to verify against

        Returns:
            True if signature is valid
        """
        if public_key_hash:
            signer = self._signers.get(public_key_hash)
            if not signer:
                return False
            return signer.verify(signature, digest)
        else:
            # Try all keys
            for signer in self._signers.values():
                if signer.verify(signature, digest):
                    return True
            return False

    def get_public_key(self) -> bytes:
        """
        Get the first public key.

        Returns:
            Public key bytes

        Raises:
            KeyPageError: If no keys available
        """
        if not self._signers:
            raise KeyPageError("No keys available")

        signer = next(iter(self._signers.values()))
        return signer.get_public_key()

    def get_public_key_by_hash(self, public_key_hash: bytes) -> Optional[bytes]:
        """
        Get public key by hash.

        Args:
            public_key_hash: Hash of the key

        Returns:
            Public key bytes if found
        """
        signer = self._signers.get(public_key_hash)
        return signer.get_public_key() if signer else None

    def to_accumulate_keypage(self) -> Dict[str, Any]:
        """
        Convert to Accumulate KeyPage format.

        Returns:
            Dictionary matching Accumulate KeyPage structure
        """
        return {
            "type": "keyPage",
            "url": str(self.page_url),
            "version": self.version,
            "acceptThreshold": self.accept_threshold,
            "keys": [key_spec.to_dict() for key_spec in self.keys],
            "keyCount": len(self.keys)
        }

    @classmethod
    def from_accumulate_keypage(cls, data: Dict[str, Any]) -> KeyPageSigner:
        """
        Create KeyPage from Accumulate format.

        Args:
            data: Dictionary in Accumulate KeyPage format

        Returns:
            KeyPageSigner instance

        Note: This creates the KeyPage structure but signers must be
        added separately as private keys are not included in the format.
        """
        page_url = AccountUrl(data["url"])
        version = data.get("version", 1)
        accept_threshold = data.get("acceptThreshold", 1)

        keypage = cls(page_url, version, accept_threshold)

        # Add key specifications (without signers)
        for key_data in data.get("keys", []):
            key_spec = KeySpec.from_dict(key_data)
            keypage.keys.append(key_spec)

        return keypage

    def can_sign_for_authority(self, authority_url: AccountUrl) -> bool:
        """
        Check if this KeyPage can sign for the given authority.

        Args:
            authority_url: Authority URL to check

        Returns:
            True if this KeyPage can sign for the authority
        """
        return self.get_authority_url() == authority_url

    def __str__(self) -> str:
        return f"KeyPageSigner({self.page_url}, v{self.version}, {len(self.keys)} keys, threshold={self.accept_threshold})"

    def __repr__(self) -> str:
        return f"KeyPageSigner(page_url='{self.page_url}', version={self.version}, keys={len(self.keys)})"


def parse_keypage_url(page_url: AccountUrl) -> Tuple[AccountUrl, int]:
    """
    Parse a KeyPage URL to extract book URL and page index.

    Args:
        page_url: KeyPage URL (e.g., acc://identity/book/page/1)

    Returns:
        Tuple of (book_url, page_index)

    Raises:
        KeyPageError: If URL format is invalid
    """
    url_str = str(page_url)
    parts = url_str.split('/')

    if len(parts) < 2:
        raise KeyPageError(f"Invalid KeyPage URL format: {page_url}")

    # Look for /page/N pattern
    if len(parts) >= 4 and parts[-2] == 'page':
        try:
            page_index = int(parts[-1])
            book_parts = parts[:-2]
            book_url = AccountUrl('/'.join(book_parts))
            return book_url, page_index
        except ValueError:
            raise KeyPageError(f"Invalid page index in URL: {page_url}")

    # Default: assume page 0
    return page_url.parent(), 0


def format_keypage_url(book_url: AccountUrl, page_index: int) -> AccountUrl:
    """
    Format a KeyPage URL from book URL and page index.

    Args:
        book_url: KeyBook URL
        page_index: Page index

    Returns:
        KeyPage URL
    """
    return book_url.join("page", str(page_index))


# Export main classes and functions
__all__ = [
    "KeyPageSigner",
    "KeySpec",
    "KeyPageError",
    "parse_keypage_url",
    "format_keypage_url"
]