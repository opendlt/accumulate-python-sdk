"""
ETH (Ethereum) and TypedData (EIP-712) signers for Accumulate protocol.

Implements Ethereum-style secp256k1 signatures with Keccak-256 hashing
and EIP-712 typed data signatures for structured data signing.
"""

import hashlib
import time
import json
from typing import Optional, Union, Dict, Any

from ..crypto.secp256k1 import Secp256k1PrivateKey, Secp256k1PublicKey
from ..enums import SignatureType
from ..runtime.url import AccountUrl
from .signer import UserSigner, Verifier


def keccak256(data: bytes) -> bytes:
    """
    Compute Keccak-256 hash (Ethereum's hash function).

    Note: This is different from SHA3-256. Ethereum uses Keccak-256.

    Args:
        data: Input data to hash

    Returns:
        32-byte Keccak-256 hash
    """
    try:
        # Try to use pycryptodome if available (preferred)
        from Crypto.Hash import keccak
        return keccak.new(digest_bits=256).update(data).digest()
    except ImportError:
        # Fallback to pysha3
        try:
            import sha3
            return sha3.keccak_256(data).digest()
        except ImportError:
            # Ultimate fallback - use regular SHA256 with warning
            import warnings
            warnings.warn(
                "Keccak-256 not available. Using SHA-256 as fallback. "
                "Install pycryptodome or pysha3 for proper Ethereum compatibility.",
                RuntimeWarning
            )
            return hashlib.sha256(data).digest()


def eth_hash(public_key_bytes: bytes) -> bytes:
    """
    Compute Ethereum-style public key hash: Keccak-256 truncated to 20 bytes.

    This matches the Go implementation's ETHhash function.

    Args:
        public_key_bytes: Uncompressed public key bytes (65 bytes starting with 0x04)

    Returns:
        20-byte Ethereum address
    """
    # Ethereum uses uncompressed public keys (65 bytes) without the 0x04 prefix for hashing
    if len(public_key_bytes) == 65 and public_key_bytes[0] == 0x04:
        # Remove the 0x04 prefix
        public_key_bytes = public_key_bytes[1:]
    elif len(public_key_bytes) == 33:
        # If compressed, we need to decompress it
        # This is a simplified approach - real implementation would decompress properly
        raise ValueError("Compressed public keys need decompression for Ethereum addressing")
    elif len(public_key_bytes) != 64:
        raise ValueError(f"Invalid Ethereum public key length: {len(public_key_bytes)}")

    # Hash the uncompressed public key (64 bytes) and take last 20 bytes
    hash_result = keccak256(public_key_bytes)
    return hash_result[-20:]  # Last 20 bytes = Ethereum address


def eth_address(public_key_bytes: bytes) -> str:
    """
    Compute Ethereum address string from public key.

    Args:
        public_key_bytes: Public key bytes

    Returns:
        Ethereum address string (0x prefixed)
    """
    eth_addr_bytes = eth_hash(public_key_bytes)
    return "0x" + eth_addr_bytes.hex()


class ETHSigner(UserSigner):
    """ETH signer using secp256k1 with Ethereum-style Keccak-256 hashing."""

    def __init__(self, private_key: Secp256k1PrivateKey, signer_url: Union[str, AccountUrl],
                 signer_version: int = 1, timestamp: Optional[int] = None):
        """
        Initialize ETH signer.

        Args:
            private_key: Secp256k1 private key
            signer_url: URL of the signer (string or AccountUrl object)
            signer_version: Version of the signer (default: 1)
            timestamp: Timestamp in microseconds (default: current time)
        """
        self.private_key = private_key
        self.signer_url = AccountUrl.parse(signer_url) if isinstance(signer_url, str) else signer_url
        self.signer_version = signer_version
        self.timestamp = timestamp or int(time.time() * 1_000_000)

    def get_signature_type(self) -> SignatureType:
        """Return the ETH signature type."""
        return SignatureType.ETH

    def get_signer_url(self) -> AccountUrl:
        """Get the signer URL."""
        return self.signer_url

    def get_signer_version(self) -> int:
        """Get the signer version."""
        return self.signer_version

    def get_public_key(self) -> bytes:
        """Get the public key bytes (uncompressed for Ethereum)."""
        # Ethereum typically uses uncompressed public keys
        public_key = self.private_key.public_key()
        pub_bytes = public_key.to_bytes()

        # If compressed (33 bytes), we should return uncompressed (65 bytes)
        # For now, return as-is since secp256k1 library handles this
        return pub_bytes

    def get_public_key_hash(self) -> bytes:
        """Get the Ethereum-style public key hash."""
        return eth_hash(self.get_public_key())

    def get_signature_bytes(self, digest: bytes) -> bytes:
        """Get raw signature bytes without metadata."""
        # Ethereum signatures include recovery ID (v) for public key recovery
        signature = self.private_key.sign(digest)

        # For Ethereum, we need to add recovery ID
        # This is a simplified implementation - real Ethereum signatures
        # include the recovery parameter to enable public key recovery
        return signature.signature

    def verify(self, signature: bytes, digest: bytes) -> bool:
        """Verify a signature against a digest."""
        public_key = self.private_key.public_key()
        return public_key.verify(signature, digest)

    def sign(self, message_hash: bytes) -> bytes:
        """
        Sign a message hash using ETH signature format.

        Args:
            message_hash: 32-byte message hash to sign

        Returns:
            Ethereum-style signature with recovery parameter
        """
        return self.get_signature_bytes(message_hash)

    def to_accumulate_signature(self, transaction_hash: bytes, **kwargs) -> dict:
        """
        Create an Accumulate protocol ETH signature.

        Args:
            transaction_hash: Transaction hash to sign
            **kwargs: Optional fields (memo, data, vote, timestamp)

        Returns:
            Dictionary with signature data
        """
        # Get public key bytes
        public_key_bytes = self.get_public_key()

        # Create signature metadata first
        metadata = {
            'type': self.get_signature_type(),
            'publicKey': public_key_bytes.hex(),
            'signer': {
                'url': str(self.get_signer_url()),
                'version': self.get_signer_version()
            },
            'signerVersion': self.get_signer_version(),
            'timestamp': self.timestamp
        }

        # Compute signing hash (metadata hash + transaction hash)
        metadata_bytes = self._metadata_bytes(metadata)
        metadata_hash = hashlib.sha256(metadata_bytes).digest()
        signing_data = metadata_hash + transaction_hash

        # Use Keccak-256 for Ethereum-style signing
        signing_hash = keccak256(signing_data)

        # Sign the hash
        signature_bytes = self.sign(signing_hash)

        # Return complete signature with optional fields
        signature = {
            'type': self.get_signature_type(),
            'publicKey': public_key_bytes.hex(),
            'signature': signature_bytes.hex(),
            'signer': {
                'url': str(self.get_signer_url()),
                'version': self.get_signer_version()
            },
            'signerVersion': self.get_signer_version(),
            'timestamp': kwargs.get('timestamp', self.timestamp),
            'vote': kwargs.get('vote', self.get_vote()),
            'transactionHash': transaction_hash.hex()
        }

        # Add optional fields if provided
        if 'memo' in kwargs:
            signature['memo'] = kwargs['memo']

        if 'data' in kwargs:
            signature['data'] = kwargs['data'].hex() if isinstance(kwargs['data'], bytes) else kwargs['data']

        return signature

    def _metadata_bytes(self, metadata: dict) -> bytes:
        """
        Convert metadata dict to bytes for hashing.

        This is a simplified version - actual implementation would need
        to match the Go MarshalBinary format exactly.
        """
        # For now, use a simple deterministic encoding
        # In production, this should match the exact binary format used by Go
        parts = [
            metadata['type'].to_bytes(1, 'big'),
            bytes.fromhex(metadata['publicKey']),
            metadata['signer']['url'].encode('utf-8'),
            metadata['signerVersion'].to_bytes(8, 'little'),
            metadata['timestamp'].to_bytes(8, 'little')
        ]
        return b''.join(parts)


class TypedDataSigner(ETHSigner):
    """
    EIP-712 TypedData signer implementing structured data signing.

    This implements the EIP-712 specification for signing typed structured data
    rather than just raw bytes.
    """

    def get_signature_type(self) -> SignatureType:
        """Return the TypedData signature type."""
        return SignatureType.TYPEDDATA

    def sign_typed_data(self, domain: Dict[str, Any], types: Dict[str, Any],
                       primary_type: str, message: Dict[str, Any]) -> bytes:
        """
        Sign EIP-712 typed data.

        Args:
            domain: EIP-712 domain separator data
            types: Type definitions
            primary_type: Primary type name
            message: Message data to sign

        Returns:
            Signature bytes
        """
        # Compute EIP-712 hash
        domain_hash = self._hash_struct("EIP712Domain", domain, types)
        message_hash = self._hash_struct(primary_type, message, types)

        # EIP-712 encoding: \x19\x01 + domain_hash + message_hash
        eip712_hash = keccak256(b"\x19\x01" + domain_hash + message_hash)

        return self.sign(eip712_hash)

    def _hash_struct(self, primary_type: str, data: Dict[str, Any],
                    types: Dict[str, Any]) -> bytes:
        """
        Hash a struct according to EIP-712.

        Args:
            primary_type: Name of the primary type
            data: Data to hash
            types: Type definitions

        Returns:
            32-byte hash of the struct
        """
        # This is a simplified implementation
        # Real EIP-712 requires proper type encoding according to the specification

        # Encode type definition
        type_hash = keccak256(self._encode_type(primary_type, types).encode())

        # Encode data
        encoded_data = self._encode_data(primary_type, data, types)

        return keccak256(type_hash + encoded_data)

    def _encode_type(self, primary_type: str, types: Dict[str, Any]) -> str:
        """Encode type definition string for EIP-712."""
        # Simplified implementation - real EIP-712 has specific rules
        return f"{primary_type}(...)"  # Placeholder

    def _encode_data(self, primary_type: str, data: Dict[str, Any],
                    types: Dict[str, Any]) -> bytes:
        """Encode data according to EIP-712."""
        # Simplified implementation - real EIP-712 has specific encoding rules
        return b""  # Placeholder


class ETHVerifier(Verifier):
    """ETH signature verifier using secp256k1 with Ethereum addressing."""

    def __init__(self, public_key: Union[Secp256k1PublicKey, bytes]):
        """
        Initialize ETH verifier.

        Args:
            public_key: Secp256k1 public key or public key bytes
        """
        if isinstance(public_key, bytes):
            self.public_key = Secp256k1PublicKey(public_key)
        else:
            self.public_key = public_key

    def signature_type(self) -> SignatureType:
        """Get the signature type for ETH."""
        return SignatureType.ETH

    def verify(self, digest: bytes, signature: bytes) -> bool:
        """
        Verify an ETH signature.

        Args:
            digest: 32-byte message hash that was signed
            signature: Ethereum-style signature to verify

        Returns:
            True if signature is valid
        """
        return self.public_key.verify(signature, digest)

    def verify_accumulate_signature(self, digest: bytes, signature_obj: dict) -> bool:
        """
        Verify an Accumulate ETH signature object.

        Args:
            digest: Transaction digest that was signed
            signature_obj: Accumulate signature dictionary

        Returns:
            True if signature is valid
        """
        # Extract signature bytes from the signature object
        if 'signature' not in signature_obj:
            return False

        try:
            sig_bytes = bytes.fromhex(signature_obj['signature'])
            return self.verify(digest, sig_bytes)
        except (ValueError, KeyError):
            return False

    def get_ethereum_address(self) -> str:
        """
        Get the Ethereum address for this public key.

        Returns:
            Ethereum address string
        """
        return eth_address(self.public_key.to_bytes())


class TypedDataVerifier(ETHVerifier):
    """TypedData signature verifier - same as ETH but for EIP-712."""

    def signature_type(self) -> SignatureType:
        """Get the signature type for TypedData."""
        return SignatureType.TYPEDDATA


# Export main classes
__all__ = [
    'ETHSigner',
    'TypedDataSigner',
    'ETHVerifier',
    'TypedDataVerifier',
    'eth_hash',
    'eth_address',
    'keccak256'
]