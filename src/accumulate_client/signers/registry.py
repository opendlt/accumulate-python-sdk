r"""
Signature type registry for Accumulate Protocol.

Provides dispatch for all 16 signature types with string/enum mapping
aligned with generated code.

Reference: C:/Accumulate_Stuff/accumulate\protocol\signature.go
"""

from __future__ import annotations
from typing import Dict, Type, Optional, Any, Union
import logging

from ..enums import SignatureType
from ..runtime.url import AccountUrl
from ..runtime.errors import AccumulateError
from .signer import Signer, UserSigner, KeySigner, SignerError
from .ed25519 import Ed25519Signer as ImportedEd25519Signer, Ed25519Verifier
from .legacy_ed25519 import LegacyEd25519Signer as ImportedLegacyEd25519Signer, LegacyEd25519Verifier
from ..crypto.ed25519 import Ed25519KeyPair
from ..crypto.secp256k1 import Secp256k1KeyPair, has_secp256k1_support

logger = logging.getLogger(__name__)


class SignatureRegistryError(SignerError):
    """Registry-specific errors."""
    pass


class Ed25519Signer(UserSigner):
    """Ed25519 signature implementation adapter for registry compatibility."""

    def __init__(self, key_pair: Ed25519KeyPair, signer_url: AccountUrl):
        self.key_pair = key_pair
        self.signer_url = signer_url
        # Create the actual signer instance
        self._signer = ImportedEd25519Signer(key_pair.private_key, str(signer_url))

    def get_signature_type(self) -> SignatureType:
        return SignatureType.ED25519

    def get_signer_url(self) -> AccountUrl:
        return self.signer_url

    def get_signature_bytes(self, digest: bytes) -> bytes:
        return self._signer.sign(digest)

    def verify(self, signature: bytes, digest: bytes) -> bool:
        verifier = Ed25519Verifier(self._signer.public_key)
        return verifier.verify(digest, signature)

    def get_public_key(self) -> bytes:
        return self._signer.public_key.encode()


class LegacyEd25519Signer(UserSigner):
    """Legacy Ed25519 signature implementation adapter for registry compatibility."""

    def __init__(self, key_pair: Ed25519KeyPair, signer_url: AccountUrl):
        self.key_pair = key_pair
        self.signer_url = signer_url
        # Create the actual signer instance
        self._signer = ImportedLegacyEd25519Signer(key_pair.private_key, str(signer_url))

    def get_signature_type(self) -> SignatureType:
        return SignatureType.LEGACYED25519

    def get_signer_url(self) -> AccountUrl:
        return self.signer_url

    def get_signature_bytes(self, digest: bytes) -> bytes:
        return self._signer.sign(digest)

    def verify(self, signature: bytes, digest: bytes) -> bool:
        verifier = LegacyEd25519Verifier(self._signer.public_key)
        return verifier.verify(digest, signature)

    def get_public_key(self) -> bytes:
        return self._signer.public_key.encode()


class BTCSigner(UserSigner):
    """Bitcoin signature implementation."""

    def __init__(self, key_pair: Secp256k1KeyPair, signer_url: AccountUrl):
        if not has_secp256k1_support():
            raise SignatureRegistryError("SECP256K1 support not available")
        self.key_pair = key_pair
        self.signer_url = signer_url

    def get_signature_type(self) -> SignatureType:
        return SignatureType.BTC

    def get_signer_url(self) -> AccountUrl:
        return self.signer_url

    def get_signature_bytes(self, digest: bytes) -> bytes:
        return self.key_pair.sign(digest).signature

    def verify(self, signature: bytes, digest: bytes) -> bool:
        from ..crypto.secp256k1 import Secp256k1Signature
        sig_obj = Secp256k1Signature(signature, self.get_public_key())
        return sig_obj.verify(digest)

    def get_public_key(self) -> bytes:
        return self.key_pair.public_key_bytes


class ETHSigner(BTCSigner):
    """Ethereum signature implementation."""

    def get_signature_type(self) -> SignatureType:
        return SignatureType.ETH


class RCD1Signer(UserSigner):
    """RCD1 (Bitcoin-style) signature implementation."""

    def __init__(self, key_pair: Secp256k1KeyPair, signer_url: AccountUrl):
        if not has_secp256k1_support():
            raise SignatureRegistryError("SECP256K1 support not available")
        self.key_pair = key_pair
        self.signer_url = signer_url

    def get_signature_type(self) -> SignatureType:
        return SignatureType.RCD1

    def get_signer_url(self) -> AccountUrl:
        return self.signer_url

    def get_signature_bytes(self, digest: bytes) -> bytes:
        return self.key_pair.sign(digest).signature

    def verify(self, signature: bytes, digest: bytes) -> bool:
        from ..crypto.secp256k1 import Secp256k1Signature
        sig_obj = Secp256k1Signature(signature, self.get_public_key())
        return sig_obj.verify(digest)

    def get_public_key(self) -> bytes:
        return self.key_pair.public_key_bytes


class SystemSigner(Signer):
    """Base class for system signatures that cannot initiate transactions."""

    def __init__(self, signer_url: AccountUrl):
        self.signer_url = signer_url

    def get_signer_url(self) -> AccountUrl:
        return self.signer_url

    def sign(self, digest: bytes) -> bytes:
        raise SignerError("System signatures cannot sign user transactions")

    def verify(self, signature: bytes, digest: bytes) -> bool:
        raise SignerError("System signature verification not implemented")

    def get_public_key(self) -> bytes:
        return b""  # System signatures don't have public keys

    def can_initiate(self) -> bool:
        return False


class ReceiptSigner(SystemSigner):
    """Receipt signature implementation."""

    def get_signature_type(self) -> SignatureType:
        return SignatureType.RECEIPT


class PartitionSigner(SystemSigner):
    """Partition signature implementation."""

    def get_signature_type(self) -> SignatureType:
        return SignatureType.PARTITION


class InternalSigner(SystemSigner):
    """Internal signature implementation."""

    def get_signature_type(self) -> SignatureType:
        return SignatureType.INTERNAL


class StubSigner(Signer):
    """Stub implementation for signature types not yet implemented."""

    def __init__(self, signature_type: SignatureType, signer_url: AccountUrl):
        self.signature_type = signature_type
        self.signer_url = signer_url

    def get_signature_type(self) -> SignatureType:
        return self.signature_type

    def get_signer_url(self) -> AccountUrl:
        return self.signer_url

    def sign(self, digest: bytes) -> bytes:
        raise SignerError(f"Signature type {self.signature_type.name} not yet implemented")

    def verify(self, signature: bytes, digest: bytes) -> bool:
        raise SignerError(f"Signature type {self.signature_type.name} not yet implemented")

    def get_public_key(self) -> bytes:
        return b""


class SignatureRegistry:
    """
    Registry for all 16 signature types.

    Provides factory methods and type dispatch for signature creation.
    """

    # Mapping from SignatureType to signer class
    SIGNER_CLASSES: Dict[SignatureType, Type[Signer]] = {
        SignatureType.ED25519: Ed25519Signer,
        SignatureType.LEGACYED25519: LegacyEd25519Signer,
        SignatureType.BTC: BTCSigner,
        SignatureType.ETH: ETHSigner,
        SignatureType.RCD1: RCD1Signer,
        SignatureType.RECEIPT: ReceiptSigner,
        SignatureType.PARTITION: PartitionSigner,
        SignatureType.INTERNAL: InternalSigner,
        # Remaining types use stub implementation
        SignatureType.SET: StubSigner,
        SignatureType.REMOTE: StubSigner,
        SignatureType.BTCLEGACY: StubSigner,
        SignatureType.DELEGATED: StubSigner,
        SignatureType.AUTHORITY: StubSigner,
        SignatureType.RSASHA256: StubSigner,
        SignatureType.ECDSASHA256: StubSigner,
        SignatureType.TYPEDDATA: StubSigner,
    }

    # String mappings (matching Go implementation)
    STRING_TO_TYPE: Dict[str, SignatureType] = {
        "ed25519": SignatureType.ED25519,
        "legacyed25519": SignatureType.LEGACYED25519,
        "rcd1": SignatureType.RCD1,
        "receipt": SignatureType.RECEIPT,
        "partition": SignatureType.PARTITION,
        "set": SignatureType.SET,
        "remote": SignatureType.REMOTE,
        "btc": SignatureType.BTC,
        "btclegacy": SignatureType.BTCLEGACY,
        "eth": SignatureType.ETH,
        "delegated": SignatureType.DELEGATED,
        "internal": SignatureType.INTERNAL,
        "authority": SignatureType.AUTHORITY,
        "rsasha256": SignatureType.RSASHA256,
        "ecdsasha256": SignatureType.ECDSASHA256,
        "typeddata": SignatureType.TYPEDDATA,
    }

    # Reverse mapping
    TYPE_TO_STRING: Dict[SignatureType, str] = {v: k for k, v in STRING_TO_TYPE.items()}

    @classmethod
    def create_signer(cls, signature_type: SignatureType, signer_url: AccountUrl, **kwargs) -> Signer:
        """
        Create a signer for the specified type.

        Args:
            signature_type: Type of signature to create
            signer_url: URL of the signer
            **kwargs: Additional parameters (key_pair, etc.)

        Returns:
            Signer instance

        Raises:
            SignatureRegistryError: If signer type is not supported
        """
        signer_class = cls.SIGNER_CLASSES.get(signature_type)
        if not signer_class:
            raise SignatureRegistryError(f"Unknown signature type: {signature_type}")

        # Handle key-based signers
        if signature_type in (SignatureType.ED25519, SignatureType.LEGACYED25519):
            key_pair = kwargs.get("key_pair")
            if not key_pair:
                raise SignatureRegistryError("Ed25519 signer requires key_pair parameter")
            return signer_class(key_pair, signer_url)

        elif signature_type in (SignatureType.BTC, SignatureType.ETH, SignatureType.RCD1):
            key_pair = kwargs.get("key_pair")
            if not key_pair:
                raise SignatureRegistryError(f"{signature_type.name} signer requires key_pair parameter")
            return signer_class(key_pair, signer_url)

        # Handle system signers
        elif signature_type in (SignatureType.RECEIPT, SignatureType.PARTITION, SignatureType.INTERNAL):
            return signer_class(signer_url)

        # Handle stub signers
        else:
            return StubSigner(signature_type, signer_url)

    @classmethod
    def create_ed25519_signer(cls, key_pair: Ed25519KeyPair, signer_url: AccountUrl) -> Ed25519Signer:
        """Create an Ed25519 signer."""
        return Ed25519Signer(key_pair, signer_url)

    @classmethod
    def create_legacy_ed25519_signer(cls, key_pair: Ed25519KeyPair, signer_url: AccountUrl) -> LegacyEd25519Signer:
        """Create a legacy Ed25519 signer."""
        return LegacyEd25519Signer(key_pair, signer_url)

    @classmethod
    def create_btc_signer(cls, key_pair: Secp256k1KeyPair, signer_url: AccountUrl) -> BTCSigner:
        """Create a Bitcoin signer."""
        return BTCSigner(key_pair, signer_url)

    @classmethod
    def create_eth_signer(cls, key_pair: Secp256k1KeyPair, signer_url: AccountUrl) -> ETHSigner:
        """Create an Ethereum signer."""
        return ETHSigner(key_pair, signer_url)

    @classmethod
    def from_string(cls, signature_type_str: str) -> SignatureType:
        """
        Get SignatureType from string.

        Args:
            signature_type_str: String representation

        Returns:
            SignatureType enum value

        Raises:
            SignatureRegistryError: If string is not recognized
        """
        signature_type = cls.STRING_TO_TYPE.get(signature_type_str.lower())
        if signature_type is None:
            raise SignatureRegistryError(f"Unknown signature type string: {signature_type_str}")
        return signature_type

    @classmethod
    def to_string(cls, signature_type: SignatureType) -> str:
        """
        Get string representation of SignatureType.

        Args:
            signature_type: SignatureType enum value

        Returns:
            String representation

        Raises:
            SignatureRegistryError: If type is not recognized
        """
        type_str = cls.TYPE_TO_STRING.get(signature_type)
        if type_str is None:
            raise SignatureRegistryError(f"Unknown signature type: {signature_type}")
        return type_str

    @classmethod
    def get_supported_types(cls) -> list[SignatureType]:
        """Get list of all supported signature types."""
        return list(cls.SIGNER_CLASSES.keys())

    @classmethod
    def get_implemented_types(cls) -> list[SignatureType]:
        """Get list of fully implemented signature types (not stubs)."""
        implemented = []
        for sig_type, signer_class in cls.SIGNER_CLASSES.items():
            if signer_class != StubSigner:
                implemented.append(sig_type)
        return implemented

    @classmethod
    def get_stub_types(cls) -> list[SignatureType]:
        """Get list of signature types that are stub implementations."""
        stubs = []
        for sig_type, signer_class in cls.SIGNER_CLASSES.items():
            if signer_class == StubSigner:
                stubs.append(sig_type)
        return stubs

    @classmethod
    def validate_registry(self) -> bool:
        """
        Validate that all 16 signature types are registered.

        Returns:
            True if all types are registered
        """
        all_types = set(SignatureType)
        registered_types = set(self.SIGNER_CLASSES.keys())
        missing = all_types - registered_types

        if missing:
            logger.error(f"Missing signature types in registry: {missing}")
            return False

        # Validate string mappings
        if len(self.STRING_TO_TYPE) != len(all_types):
            logger.error("String mapping incomplete")
            return False

        return True


# Convenience functions
def get_signer_for_type(signature_type: Union[SignatureType, str], signer_url: AccountUrl, **kwargs) -> Signer:
    """
    Get a signer for the specified type.

    Args:
        signature_type: SignatureType enum or string
        signer_url: URL of the signer
        **kwargs: Additional parameters

    Returns:
        Signer instance
    """
    if isinstance(signature_type, str):
        signature_type = SignatureRegistry.from_string(signature_type)

    return SignatureRegistry.create_signer(signature_type, signer_url, **kwargs)


def create_test_signer(signature_type: SignatureType, identity: str = "test.acme") -> Signer:
    """
    Create a test signer with deterministic keys.

    Args:
        signature_type: Type of signer to create
        identity: Identity name for URL

    Returns:
        Test signer instance
    """
    signer_url = AccountUrl(f"acc://{identity}")

    if signature_type in (SignatureType.ED25519, SignatureType.LEGACYED25519):
        key_pair = Ed25519KeyPair.from_seed(f"test-{identity}-{signature_type.name}")
        return SignatureRegistry.create_signer(signature_type, signer_url, key_pair=key_pair)

    elif signature_type in (SignatureType.BTC, SignatureType.ETH, SignatureType.RCD1):
        if has_secp256k1_support():
            # Create deterministic secp256k1 key for testing
            from ..crypto.secp256k1 import Secp256k1KeyPair
            import hashlib
            seed = f"test-{identity}-{signature_type.name}".encode()
            private_key_bytes = hashlib.sha256(seed).digest()
            key_pair = Secp256k1KeyPair(private_key_bytes)
            return SignatureRegistry.create_signer(signature_type, signer_url, key_pair=key_pair)
        else:
            # Return stub for testing
            return StubSigner(signature_type, signer_url)

    else:
        return SignatureRegistry.create_signer(signature_type, signer_url)


# Add alias for compatibility
SignerRegistry = SignatureRegistry

# Export main classes and functions
__all__ = [
    "SignatureRegistry",
    "SignerRegistry",
    "SignatureRegistryError",
    "Ed25519Signer",
    "LegacyEd25519Signer",
    "BTCSigner",
    "ETHSigner",
    "RCD1Signer",
    "ReceiptSigner",
    "PartitionSigner",
    "InternalSigner",
    "StubSigner",
    "get_signer_for_type",
    "create_test_signer"
]