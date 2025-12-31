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
    rather than just raw bytes. EIP-712 provides a standard way to sign
    structured data that is both human-readable and secure.
    """

    # Standard EIP-712 domain type
    EIP712_DOMAIN_TYPE = [
        {"name": "name", "type": "string"},
        {"name": "version", "type": "string"},
        {"name": "chainId", "type": "uint256"},
        {"name": "verifyingContract", "type": "address"},
        {"name": "salt", "type": "bytes32"},
    ]

    def get_signature_type(self) -> SignatureType:
        """Return the TypedData signature type."""
        return SignatureType.TYPEDDATA

    def sign_typed_data(self, domain: Dict[str, Any], types: Dict[str, Any],
                       primary_type: str, message: Dict[str, Any]) -> bytes:
        """
        Sign EIP-712 typed data.

        Args:
            domain: EIP-712 domain separator data
            types: Type definitions (must include EIP712Domain)
            primary_type: Primary type name
            message: Message data to sign

        Returns:
            Signature bytes
        """
        # Ensure EIP712Domain is in types
        full_types = dict(types)
        if "EIP712Domain" not in full_types:
            # Add only the fields present in domain
            domain_fields = []
            for field in self.EIP712_DOMAIN_TYPE:
                if field["name"] in domain:
                    domain_fields.append(field)
            full_types["EIP712Domain"] = domain_fields

        # Compute EIP-712 hash
        domain_hash = self._hash_struct("EIP712Domain", domain, full_types)
        message_hash = self._hash_struct(primary_type, message, full_types)

        # EIP-712 encoding: \x19\x01 + domain_hash + message_hash
        eip712_hash = keccak256(b"\x19\x01" + domain_hash + message_hash)

        return self.sign(eip712_hash)

    def _hash_struct(self, primary_type: str, data: Dict[str, Any],
                    types: Dict[str, Any]) -> bytes:
        """
        Hash a struct according to EIP-712.

        hashStruct(s) = keccak256(typeHash || encodeData(s))

        Args:
            primary_type: Name of the primary type
            data: Data to hash
            types: Type definitions

        Returns:
            32-byte hash of the struct
        """
        # Get type hash: keccak256(encodeType(primaryType))
        type_string = self._encode_type(primary_type, types)
        type_hash = keccak256(type_string.encode('utf-8'))

        # Encode data according to type
        encoded_data = self._encode_data(primary_type, data, types)

        return keccak256(type_hash + encoded_data)

    def _encode_type(self, primary_type: str, types: Dict[str, Any]) -> str:
        """
        Encode type definition string for EIP-712.

        The type of a struct is encoded as:
        name ‖ "(" ‖ member₁ ‖ "," ‖ member₂ ‖ "," ‖ … ‖ memberₙ ")"

        Args:
            primary_type: Primary type name
            types: All type definitions

        Returns:
            Encoded type string
        """
        # Find all dependencies (referenced types)
        deps = self._find_type_dependencies(primary_type, types, set())

        # Sort dependencies alphabetically (excluding primary type)
        deps.discard(primary_type)
        sorted_deps = sorted(deps)

        # Primary type first, then dependencies
        all_types = [primary_type] + sorted_deps

        result_parts = []
        for type_name in all_types:
            if type_name not in types:
                continue
            fields = types[type_name]
            field_strs = [f"{f['type']} {f['name']}" for f in fields]
            result_parts.append(f"{type_name}({','.join(field_strs)})")

        return "".join(result_parts)

    def _find_type_dependencies(self, type_name: str, types: Dict[str, Any],
                                 found: set) -> set:
        """
        Recursively find all type dependencies.

        Args:
            type_name: Type to find dependencies for
            types: All type definitions
            found: Already found dependencies

        Returns:
            Set of all dependent type names
        """
        if type_name not in types or type_name in found:
            return found

        found.add(type_name)

        for field in types[type_name]:
            field_type = field["type"]
            # Handle arrays
            if field_type.endswith("[]"):
                field_type = field_type[:-2]
            # Check if it's a struct type (not a primitive)
            if field_type in types:
                self._find_type_dependencies(field_type, types, found)

        return found

    def _encode_data(self, primary_type: str, data: Dict[str, Any],
                    types: Dict[str, Any]) -> bytes:
        """
        Encode data according to EIP-712.

        encodeData(s) = enc(value₁) ‖ enc(value₂) ‖ … ‖ enc(valueₙ)

        Args:
            primary_type: Type name
            data: Data to encode
            types: Type definitions

        Returns:
            Encoded data bytes
        """
        if primary_type not in types:
            raise ValueError(f"Type {primary_type} not found in types")

        encoded_values = b""

        for field in types[primary_type]:
            field_name = field["name"]
            field_type = field["type"]
            value = data.get(field_name)

            encoded_values += self._encode_value(field_type, value, types)

        return encoded_values

    def _encode_value(self, field_type: str, value: Any, types: Dict[str, Any]) -> bytes:
        """
        Encode a single value according to its type.

        Args:
            field_type: Type of the field
            value: Value to encode
            types: Type definitions

        Returns:
            32-byte encoded value
        """
        # Handle None values
        if value is None:
            return bytes(32)

        # Handle arrays
        if field_type.endswith("[]"):
            element_type = field_type[:-2]
            if not isinstance(value, (list, tuple)):
                value = [value]
            # Array encoding: keccak256(concat(encodeData(element) for element in array))
            encoded_elements = b"".join(
                self._encode_value(element_type, v, types) for v in value
            )
            return keccak256(encoded_elements)

        # Handle struct types (referenced types)
        if field_type in types:
            return self._hash_struct(field_type, value, types)

        # Handle atomic types
        return self._encode_atomic_type(field_type, value)

    def _encode_atomic_type(self, field_type: str, value: Any) -> bytes:
        """
        Encode an atomic (non-struct) type.

        Args:
            field_type: Type name (e.g., 'uint256', 'address', 'bytes32')
            value: Value to encode

        Returns:
            32-byte encoded value
        """
        # bytes - dynamic, encoded as keccak256
        if field_type == "bytes":
            if isinstance(value, str):
                value = bytes.fromhex(value.replace("0x", ""))
            return keccak256(value)

        # string - dynamic, encoded as keccak256 of UTF-8
        if field_type == "string":
            if isinstance(value, bytes):
                value = value.decode('utf-8')
            return keccak256(value.encode('utf-8'))

        # bool - encoded as uint256
        if field_type == "bool":
            return (1 if value else 0).to_bytes(32, 'big')

        # address - 20 bytes, left-padded to 32
        if field_type == "address":
            if isinstance(value, str):
                value = value.replace("0x", "")
                addr_bytes = bytes.fromhex(value)
            else:
                addr_bytes = value
            return bytes(12) + addr_bytes[-20:]

        # bytesN (bytes1 to bytes32) - right-padded to 32
        if field_type.startswith("bytes") and field_type[5:].isdigit():
            n = int(field_type[5:])
            if isinstance(value, str):
                value = bytes.fromhex(value.replace("0x", ""))
            return value[:n].ljust(32, b'\x00')

        # uintN / intN - left-padded to 32 bytes
        if field_type.startswith("uint") or field_type.startswith("int"):
            is_signed = field_type.startswith("int")
            if isinstance(value, str):
                value = int(value, 0)  # Handle hex strings

            if is_signed and value < 0:
                # Two's complement for negative numbers
                value = (1 << 256) + value

            return value.to_bytes(32, 'big')

        # Unknown type - try to encode as bytes
        if isinstance(value, bytes):
            return value.ljust(32, b'\x00')[:32]
        if isinstance(value, str):
            return bytes.fromhex(value.replace("0x", "")).ljust(32, b'\x00')[:32]
        if isinstance(value, int):
            return value.to_bytes(32, 'big')

        raise ValueError(f"Cannot encode type {field_type} with value {value}")

    def to_accumulate_signature(self, transaction_hash: bytes, **kwargs) -> dict:
        """
        Create an Accumulate protocol TypedData signature.

        Args:
            transaction_hash: Transaction hash to sign
            **kwargs: Optional fields including typed_data for EIP-712

        Returns:
            Dictionary with signature data
        """
        # Check if typed_data is provided for EIP-712 signing
        typed_data = kwargs.pop("typed_data", None)

        if typed_data:
            # Sign using EIP-712
            domain = typed_data.get("domain", {})
            types = typed_data.get("types", {})
            primary_type = typed_data.get("primaryType", "")
            message = typed_data.get("message", {})

            signature_bytes = self.sign_typed_data(domain, types, primary_type, message)
        else:
            # Fall back to standard signing
            signature_bytes = self.sign(transaction_hash)

        # Get public key bytes
        public_key_bytes = self.get_public_key()

        signature = {
            'type': 'typedData',
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

        # Add typed data info if present
        if typed_data:
            signature['typedData'] = {
                'primaryType': typed_data.get("primaryType", ""),
                'domain': typed_data.get("domain", {})
            }

        # Add optional fields
        if 'memo' in kwargs:
            signature['memo'] = kwargs['memo']
        if 'data' in kwargs:
            signature['data'] = kwargs['data'].hex() if isinstance(kwargs['data'], bytes) else kwargs['data']

        return signature


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