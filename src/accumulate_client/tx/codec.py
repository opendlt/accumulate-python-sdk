"""
Transaction codec for Accumulate Protocol.

Provides canonical JSON and binary encoding/decoding for exact parity
with the Go implementation.

Reference: C:/Accumulate_Stuff/accumulate/protocol/encoding.go
"""

from __future__ import annotations
from typing import TypeVar, Type, Any, Dict, Union
import json

from ..runtime.codec import encode_json, loads, hash_sha256

T = TypeVar('T')

# Try to import generated types - will be available after codegen
try:
    from ._type_index import lookup_tx_model
    from .types_generated import model_to_canonical_json, dict_to_model
    HAS_GENERATED_TYPES = True
except ImportError:
    HAS_GENERATED_TYPES = False


def to_canonical_json(obj: Any) -> bytes:
    """
    Convert an object to canonical JSON bytes.

    Args:
        obj: Object to encode (transaction, body, etc.)

    Returns:
        Canonical JSON bytes
    """
    # Use generated model helper if available and obj is a Pydantic model
    if HAS_GENERATED_TYPES and hasattr(obj, 'model_dump'):
        try:
            return model_to_canonical_json(obj)
        except Exception:
            # Fall back to standard encoding
            pass

    if hasattr(obj, 'model_dump'):
        # Pydantic model
        data = obj.model_dump(exclude_none=True)
    elif hasattr(obj, 'dict'):
        # Pydantic v1 compatibility
        data = obj.dict(exclude_none=True)
    else:
        # Plain dict or other object
        data = obj

    return encode_json(data).encode('utf-8')


def from_canonical_json(data: bytes, cls: Type[T] = None, tx_type: str = None) -> T:
    """
    Create an object from canonical JSON bytes.

    Args:
        data: Canonical JSON bytes
        cls: Target class type (optional if tx_type is provided)
        tx_type: Transaction type string for lookup (optional)

    Returns:
        Instantiated object
    """
    json_str = data.decode('utf-8')
    parsed = loads(json_str)

    # Try to use generated model if tx_type is provided or can be inferred
    # But only if a specific model class is requested, not dict
    if HAS_GENERATED_TYPES and cls and cls != dict:
        inferred_tx_type = tx_type or parsed.get('type')
        if inferred_tx_type:
            try:
                return dict_to_model(inferred_tx_type, parsed)
            except Exception:
                # Fall back to standard decoding
                pass

    # Standard Pydantic decoding
    if cls:
        if hasattr(cls, 'model_validate'):
            # Pydantic v2
            return cls.model_validate(parsed)
        elif hasattr(cls, 'parse_obj'):
            # Pydantic v1 compatibility
            return cls.parse_obj(parsed)
        else:
            # Plain class
            return cls(**parsed)
    else:
        # Return parsed dict if no class specified
        return parsed


def to_binary(obj: Any) -> bytes:
    """
    Convert an object to binary format.

    Currently uses canonical JSON as the binary format for consistency
    with the reference implementation.

    Args:
        obj: Object to encode

    Returns:
        Binary encoded bytes
    """
    return to_canonical_json(obj)


def from_binary(data: bytes, cls: Type[T]) -> T:
    """
    Create an object from binary format.

    Currently uses canonical JSON as the binary format for consistency
    with the reference implementation.

    Args:
        data: Binary encoded bytes
        cls: Target class type

    Returns:
        Instantiated object
    """
    return from_canonical_json(data, cls)


def hash_transaction(obj: Any) -> bytes:
    """
    Compute the hash of a transaction object.

    Args:
        obj: Transaction object to hash

    Returns:
        32-byte transaction hash
    """
    canonical_bytes = to_canonical_json(obj)
    return hash_sha256(canonical_bytes)


def serialize_for_signature(obj: Any) -> bytes:
    """
    Serialize an object for signature computation.

    Uses canonical JSON encoding to ensure consistent signature hashes.

    Args:
        obj: Object to serialize for signing

    Returns:
        Serialized bytes for signature computation
    """
    return to_canonical_json(obj)


def encode_varint(value: int) -> bytes:
    """
    Encode an integer as a variable-length integer (varint).

    Uses LEB128 encoding (Little Endian Base 128) which is common
    in Protocol Buffers and other binary formats.

    Args:
        value: Non-negative integer to encode

    Returns:
        Varint-encoded bytes

    Raises:
        ValueError: If value is negative
    """
    if value < 0:
        raise ValueError("Cannot encode negative values as varint")

    result = bytearray()
    while value >= 0x80:
        result.append((value & 0x7F) | 0x80)
        value >>= 7
    result.append(value & 0x7F)
    return bytes(result)


def decode_varint(data: bytes, offset: int = 0) -> tuple[int, int]:
    """
    Decode a variable-length integer (varint) from bytes.

    Args:
        data: Bytes containing varint-encoded data
        offset: Starting offset in the data

    Returns:
        Tuple of (decoded_value, bytes_consumed)

    Raises:
        ValueError: If data is malformed or truncated
    """
    if offset >= len(data):
        raise ValueError("Insufficient data for varint decoding")

    result = 0
    shift = 0
    bytes_read = 0

    for i in range(offset, len(data)):
        byte = data[i]
        bytes_read += 1

        # Add the 7 bits to the result
        result |= (byte & 0x7F) << shift

        # If MSB is not set, we're done
        if (byte & 0x80) == 0:
            return result, bytes_read

        shift += 7

        # Prevent overflow for very large varints
        if shift >= 64:
            raise ValueError("Varint too large")

    raise ValueError("Truncated varint")


def marshal_binary(data: bytes) -> bytes:
    """
    Marshal bytes into a length-prefixed binary format.

    Prepends the data length as a varint followed by the data itself.
    This is a common pattern in binary protocols.

    Args:
        data: Raw bytes to marshal

    Returns:
        Length-prefixed binary data
    """
    if not isinstance(data, bytes):
        raise ValueError("marshal_binary expects bytes")

    length_prefix = encode_varint(len(data))
    return length_prefix + data


def unmarshal_binary(data: bytes, offset: int = 0) -> bytes:
    """
    Unmarshal length-prefixed binary data.

    Reads the length varint and extracts the following data.

    Args:
        data: Length-prefixed binary data
        offset: Starting offset in the data

    Returns:
        Unmarshaled raw bytes

    Raises:
        ValueError: If data is malformed or truncated
    """
    if offset >= len(data):
        raise ValueError("Insufficient data for binary unmarshaling")

    # Decode the length prefix
    length, length_bytes = decode_varint(data, offset)
    data_start = offset + length_bytes

    # Check if we have enough data
    if data_start + length > len(data):
        raise ValueError("Insufficient data for binary unmarshaling")

    # Extract the data
    return data[data_start:data_start + length]


def receipt_hash(receipt: Dict[str, Any]) -> bytes:
    """
    Calculate hash of a receipt object.

    Args:
        receipt: Receipt dictionary

    Returns:
        32-byte hash of the receipt
    """
    return hash_transaction(receipt)


# Alias for backwards compatibility
canonical_json = to_canonical_json


__all__ = [
    "to_canonical_json",
    "canonical_json",
    "from_canonical_json",
    "to_binary",
    "from_binary",
    "hash_transaction",
    "serialize_for_signature",
    "encode_varint",
    "decode_varint",
    "marshal_binary",
    "unmarshal_binary",
    "receipt_hash"
]