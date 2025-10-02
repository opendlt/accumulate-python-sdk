"""
Accumulate Encoding/Decoding and Hashing

This module provides canonical binary and JSON encoding/decoding functionality
for Accumulate protocol types, matching the Go implementation.
"""

from __future__ import annotations
import json
import hashlib
import struct
from typing import Any, Dict, List, Union, Optional, Type, get_type_hints
from datetime import datetime, timezone
import base64
from dataclasses import is_dataclass, fields
from enum import IntEnum

from ..enums import *
from .url import AccountUrl
from .errors import EncodingError, MarshalError, UnmarshalError


class FieldType(IntEnum):
    """Binary field type indicators matching Go implementation."""

    # Basic types
    BOOL = 1
    UINT = 2
    INT = 3
    BYTES = 4
    STRING = 5
    BIGINT = 6
    URL = 7
    HASH = 8
    TXID = 9
    TIME = 10
    DURATION = 11

    # Complex types
    ARRAY = 16
    OBJECT = 17
    UNION = 18
    OPTIONAL = 19

    # Special types
    VARINT = 32
    UVARINT = 33
    RAW = 34


def write_varint(value: int) -> bytes:
    """
    Write a variable-length integer.

    Args:
        value: Integer value to encode

    Returns:
        Encoded bytes
    """
    if value < 0:
        raise ValueError("varint cannot be negative")

    result = bytearray()
    while value >= 0x80:
        result.append((value & 0x7F) | 0x80)
        value >>= 7
    result.append(value & 0x7F)
    return bytes(result)


def read_varint(data: bytes, offset: int = 0) -> tuple[int, int]:
    """
    Read a variable-length integer.

    Args:
        data: Bytes to read from
        offset: Starting offset

    Returns:
        Tuple of (value, new_offset)
    """
    value = 0
    shift = 0
    pos = offset

    while pos < len(data):
        byte = data[pos]
        pos += 1

        value |= (byte & 0x7F) << shift
        if (byte & 0x80) == 0:
            return value, pos

        shift += 7
        if shift >= 64:
            raise ValueError("varint too large")

    raise ValueError("unexpected end of varint")


def write_uvarint(value: int) -> bytes:
    """Write an unsigned varint (same as varint for non-negative values)."""
    return write_varint(value)


def read_uvarint(data: bytes, offset: int = 0) -> tuple[int, int]:
    """Read an unsigned varint."""
    return read_varint(data, offset)


class BinaryEncoder:
    """
    Binary encoder for Accumulate protocol types.

    Implements the canonical binary encoding used by the Go implementation.
    """

    def __init__(self):
        self.buffer = bytearray()

    def encode(self, value: Any, field_type: Optional[FieldType] = None) -> bytes:
        """
        Encode a value to binary format.

        Args:
            value: Value to encode
            field_type: Optional explicit field type

        Returns:
            Encoded bytes
        """
        self.buffer.clear()
        self._encode_value(value, field_type)
        return bytes(self.buffer)

    def _encode_value(self, value: Any, field_type: Optional[FieldType] = None):
        """Internal method to encode a value."""
        if value is None:
            if field_type == FieldType.OPTIONAL:
                self.buffer.append(0)  # Null marker
            return

        # Determine field type if not provided
        if field_type is None:
            field_type = self._infer_type(value)

        # Write type marker for complex types
        if field_type in (FieldType.ARRAY, FieldType.OBJECT, FieldType.UNION, FieldType.OPTIONAL):
            self.buffer.extend(write_uvarint(field_type.value))

        # Encode based on type
        if field_type == FieldType.BOOL:
            self.buffer.append(1 if value else 0)

        elif field_type == FieldType.UINT:
            self.buffer.extend(write_uvarint(value))

        elif field_type == FieldType.INT:
            # Signed varint encoding
            encoded = value << 1
            if value < 0:
                encoded = ~encoded
            self.buffer.extend(write_uvarint(encoded))

        elif field_type == FieldType.UVARINT:
            self.buffer.extend(write_uvarint(value))

        elif field_type == FieldType.VARINT:
            self.buffer.extend(write_varint(value))

        elif field_type == FieldType.BYTES:
            if isinstance(value, str):
                value = bytes.fromhex(value) if len(value) % 2 == 0 else value.encode('utf-8')
            self.buffer.extend(write_uvarint(len(value)))
            self.buffer.extend(value)

        elif field_type == FieldType.STRING:
            encoded = value.encode('utf-8')
            self.buffer.extend(write_uvarint(len(encoded)))
            self.buffer.extend(encoded)

        elif field_type == FieldType.BIGINT:
            # Encode as string representation for now
            str_repr = str(value)
            encoded = str_repr.encode('utf-8')
            self.buffer.extend(write_uvarint(len(encoded)))
            self.buffer.extend(encoded)

        elif field_type == FieldType.URL:
            if isinstance(value, AccountUrl):
                value = str(value)
            encoded = value.encode('utf-8')
            self.buffer.extend(write_uvarint(len(encoded)))
            self.buffer.extend(encoded)

        elif field_type == FieldType.HASH:
            if isinstance(value, str):
                value = bytes.fromhex(value)
            self.buffer.extend(write_uvarint(len(value)))
            self.buffer.extend(value)

        elif field_type == FieldType.TIME:
            if isinstance(value, datetime):
                # Convert to Unix timestamp nanoseconds
                timestamp = int(value.timestamp() * 1_000_000_000)
            else:
                timestamp = int(value)
            self.buffer.extend(write_uvarint(timestamp))

        elif field_type == FieldType.ARRAY:
            self.buffer.extend(write_uvarint(len(value)))
            for item in value:
                self._encode_value(item)

        elif field_type == FieldType.OBJECT:
            self._encode_object(value)

        elif field_type == FieldType.OPTIONAL:
            if value is None:
                self.buffer.append(0)
            else:
                self.buffer.append(1)
                self._encode_value(value)

        elif field_type == FieldType.UNION:
            self._encode_union(value)

        else:
            raise EncodingError(f"Unsupported field type: {field_type}")

    def _encode_object(self, obj: Any):
        """Encode a structured object."""
        if hasattr(obj, '__dict__'):
            # Pydantic model or similar
            data = obj.__dict__ if hasattr(obj, '__dict__') else obj
        elif hasattr(obj, 'model_dump'):
            # Pydantic v2
            data = obj.model_dump()
        elif hasattr(obj, 'dict'):
            # Pydantic v1
            data = obj.dict()
        elif isinstance(obj, dict):
            data = obj
        else:
            raise EncodingError(f"Cannot encode object of type {type(obj)}")

        # Sort fields for canonical encoding
        sorted_fields = sorted(data.items())
        self.buffer.extend(write_uvarint(len(sorted_fields)))

        for key, value in sorted_fields:
            # Encode field name
            encoded_key = key.encode('utf-8')
            self.buffer.extend(write_uvarint(len(encoded_key)))
            self.buffer.extend(encoded_key)

            # Encode field value
            self._encode_value(value)

    def _encode_union(self, value: Any):
        """Encode a union type based on discriminator."""
        if hasattr(value, 'kind'):
            # Discriminated union with 'kind' field
            kind = value.kind
            encoded_kind = kind.encode('utf-8')
            self.buffer.extend(write_uvarint(len(encoded_kind)))
            self.buffer.extend(encoded_kind)
            self._encode_object(value)
        else:
            raise EncodingError("Union type must have 'kind' discriminator")

    def _infer_type(self, value: Any) -> FieldType:
        """Infer the field type from a value."""
        if isinstance(value, bool):
            return FieldType.BOOL
        elif isinstance(value, int):
            return FieldType.UVARINT
        elif isinstance(value, bytes):
            return FieldType.BYTES
        elif isinstance(value, str):
            return FieldType.STRING
        elif isinstance(value, AccountUrl):
            return FieldType.URL
        elif isinstance(value, datetime):
            return FieldType.TIME
        elif isinstance(value, (list, tuple)):
            return FieldType.ARRAY
        elif isinstance(value, dict) or hasattr(value, '__dict__'):
            return FieldType.OBJECT
        elif hasattr(value, 'kind'):
            return FieldType.UNION
        else:
            raise EncodingError(f"Cannot infer type for {type(value)}")


class BinaryDecoder:
    """
    Binary decoder for Accumulate protocol types.
    """

    def __init__(self, data: bytes):
        self.data = data
        self.offset = 0

    def decode(self, target_type: Type = None) -> Any:
        """
        Decode binary data to the specified type.

        Args:
            target_type: Type to decode to

        Returns:
            Decoded value
        """
        return self._decode_value(target_type)

    def _decode_value(self, target_type: Type = None) -> Any:
        """Internal method to decode a value."""
        if self.offset >= len(self.data):
            raise UnmarshalError("Unexpected end of data")

        # For simple types, decode directly
        if target_type == bool:
            return self._read_bool()
        elif target_type == int:
            return self._read_uvarint()
        elif target_type == str:
            return self._read_string()
        elif target_type == bytes:
            return self._read_bytes()
        elif target_type == AccountUrl:
            return AccountUrl(self._read_string())
        elif target_type == datetime:
            return self._read_time()

        # For complex types, read type marker first
        field_type, self.offset = read_uvarint(self.data, self.offset)
        field_type = FieldType(field_type)

        if field_type == FieldType.ARRAY:
            return self._decode_array(target_type)
        elif field_type == FieldType.OBJECT:
            return self._decode_object(target_type)
        elif field_type == FieldType.UNION:
            return self._decode_union(target_type)
        elif field_type == FieldType.OPTIONAL:
            return self._decode_optional(target_type)
        else:
            raise UnmarshalError(f"Unsupported field type: {field_type}")

    def _read_bool(self) -> bool:
        """Read a boolean value."""
        if self.offset >= len(self.data):
            raise UnmarshalError("Unexpected end of data")
        value = self.data[self.offset]
        self.offset += 1
        return bool(value)

    def _read_uvarint(self) -> int:
        """Read an unsigned varint."""
        value, self.offset = read_uvarint(self.data, self.offset)
        return value

    def _read_string(self) -> str:
        """Read a string value."""
        length = self._read_uvarint()
        if self.offset + length > len(self.data):
            raise UnmarshalError("String length exceeds data")
        value = self.data[self.offset:self.offset + length].decode('utf-8')
        self.offset += length
        return value

    def _read_bytes(self) -> bytes:
        """Read a bytes value."""
        length = self._read_uvarint()
        if self.offset + length > len(self.data):
            raise UnmarshalError("Bytes length exceeds data")
        value = self.data[self.offset:self.offset + length]
        self.offset += length
        return value

    def _read_time(self) -> datetime:
        """Read a timestamp value."""
        timestamp_ns = self._read_uvarint()
        timestamp_s = timestamp_ns / 1_000_000_000
        return datetime.fromtimestamp(timestamp_s, timezone.utc)

    def _decode_array(self, target_type: Type) -> List[Any]:
        """Decode an array."""
        length = self._read_uvarint()
        result = []
        for _ in range(length):
            result.append(self._decode_value())
        return result

    def _decode_object(self, target_type: Type) -> Dict[str, Any]:
        """Decode an object."""
        field_count = self._read_uvarint()
        result = {}

        for _ in range(field_count):
            key = self._read_string()
            value = self._decode_value()
            result[key] = value

        return result

    def _decode_union(self, target_type: Type) -> Any:
        """Decode a union type."""
        kind = self._read_string()
        obj_data = self._decode_object(None)
        obj_data['kind'] = kind
        return obj_data

    def _decode_optional(self, target_type: Type) -> Optional[Any]:
        """Decode an optional value."""
        has_value = self._read_bool()
        if not has_value:
            return None
        return self._decode_value(target_type)


class JSONEncoder:
    """
    Canonical JSON encoder for Accumulate types.

    Produces deterministic JSON output matching the Go implementation.
    """

    def encode(self, value: Any) -> str:
        """
        Encode a value to canonical JSON.

        Args:
            value: Value to encode

        Returns:
            JSON string
        """
        canonical_value = self._canonicalize(value)
        return json.dumps(canonical_value, sort_keys=True, separators=(',', ':'))

    def _canonicalize(self, value: Any) -> Any:
        """Convert value to canonical form for JSON encoding."""
        if value is None:
            return None
        elif isinstance(value, bool):
            return value
        elif isinstance(value, (int, float)):
            return value
        elif isinstance(value, str):
            return value
        elif isinstance(value, bytes):
            return base64.b64encode(value).decode('ascii')
        elif isinstance(value, AccountUrl):
            return str(value)
        elif isinstance(value, datetime):
            return value.isoformat() + 'Z'
        elif isinstance(value, (list, tuple)):
            return [self._canonicalize(item) for item in value]
        elif isinstance(value, dict):
            return {key: self._canonicalize(val) for key, val in value.items()}
        elif hasattr(value, 'model_dump'):
            # Pydantic v2
            return self._canonicalize(value.model_dump())
        elif hasattr(value, 'dict'):
            # Pydantic v1
            return self._canonicalize(value.dict())
        elif hasattr(value, '__dict__'):
            return self._canonicalize(value.__dict__)
        else:
            return str(value)


class Hasher:
    """
    Hashing utilities for Accumulate protocol.

    Provides consistent hashing functions matching the Go implementation.
    """

    @staticmethod
    def sha256(data: Union[bytes, str]) -> bytes:
        """
        Compute SHA-256 hash.

        Args:
            data: Data to hash

        Returns:
            32-byte hash
        """
        if isinstance(data, str):
            data = data.encode('utf-8')
        return hashlib.sha256(data).digest()

    @staticmethod
    def sha256_hex(data: Union[bytes, str]) -> str:
        """
        Compute SHA-256 hash as hex string.

        Args:
            data: Data to hash

        Returns:
            64-character hex string
        """
        return Hasher.sha256(data).hex()

    @staticmethod
    def hash_object(obj: Any) -> bytes:
        """
        Hash an object using canonical binary encoding.

        Args:
            obj: Object to hash

        Returns:
            32-byte hash
        """
        encoder = BinaryEncoder()
        encoded = encoder.encode(obj)
        return Hasher.sha256(encoded)

    @staticmethod
    def hash_object_hex(obj: Any) -> str:
        """
        Hash an object as hex string.

        Args:
            obj: Object to hash

        Returns:
            64-character hex string
        """
        return Hasher.hash_object(obj).hex()

    @staticmethod
    def merkle_hash(left: bytes, right: bytes) -> bytes:
        """
        Compute Merkle tree hash of two nodes.

        Args:
            left: Left node hash
            right: Right node hash

        Returns:
            Parent node hash
        """
        return Hasher.sha256(left + right)

    @staticmethod
    def transaction_hash(tx_data: Dict[str, Any]) -> str:
        """
        Compute transaction hash.

        Args:
            tx_data: Transaction data

        Returns:
            Transaction hash as hex string
        """
        # Remove signature fields for hash computation
        tx_copy = tx_data.copy()
        tx_copy.pop('signatures', None)
        tx_copy.pop('signature', None)

        return Hasher.hash_object_hex(tx_copy)


# Legacy compatibility functions
def dumps(obj: Any, **kwargs) -> str:
    """
    Serialize an object to JSON string (legacy compatibility).

    This is a thin wrapper over json.dumps with sensible defaults.
    """
    defaults = {
        'ensure_ascii': False,
        'separators': (',', ':'),
        'sort_keys': True
    }
    defaults.update(kwargs)
    return json.dumps(obj, **defaults)


def loads(s: Union[str, bytes], **kwargs) -> Any:
    """
    Deserialize JSON string to Python object (legacy compatibility).

    This is a thin wrapper over json.loads.
    """
    return json.loads(s, **kwargs)


def to_wire_bytes(obj: Any) -> bytes:
    """
    Convert object to wire format bytes.

    Uses the new binary encoding system.
    """
    encoder = BinaryEncoder()
    return encoder.encode(obj)


def from_wire_bytes(data: bytes, target_type: Type = None) -> Any:
    """
    Convert wire format bytes to object.

    Uses the new binary decoding system.
    """
    decoder = BinaryDecoder(data)
    return decoder.decode(target_type)


def to_dict(obj: Any) -> Dict[str, Any]:
    """
    Convert a Pydantic model or other object to a dictionary.

    Handles Pydantic models via model_dump(), other objects via dict().
    """
    if hasattr(obj, 'model_dump'):
        # Pydantic v2 model
        return obj.model_dump()
    elif hasattr(obj, 'dict'):
        # Pydantic v1 model
        return obj.dict()
    elif hasattr(obj, '__dict__'):
        return obj.__dict__
    else:
        return dict(obj) if obj else {}


# Convenience functions
def encode_binary(value: Any) -> bytes:
    """Encode value to binary format."""
    encoder = BinaryEncoder()
    return encoder.encode(value)


def decode_binary(data: bytes, target_type: Type = None) -> Any:
    """Decode binary data."""
    decoder = BinaryDecoder(data)
    return decoder.decode(target_type)


def encode_json(value: Any) -> str:
    """Encode value to canonical JSON."""
    encoder = JSONEncoder()
    return encoder.encode(value)


def hash_sha256(data: Union[bytes, str]) -> bytes:
    """Compute SHA-256 hash."""
    return Hasher.sha256(data)


def hash_sha256_hex(data: Union[bytes, str]) -> str:
    """Compute SHA-256 hash as hex string."""
    return Hasher.sha256_hex(data)


def decode_transaction(canonical_bytes: bytes) -> Dict[str, Any]:
    """
    Decode transaction from canonical JSON bytes.

    Args:
        canonical_bytes: Canonical JSON as bytes

    Returns:
        Transaction body dictionary
    """
    canonical_str = canonical_bytes.decode('utf-8')
    return json.loads(canonical_str)


def encode_canonical_json(body: Dict[str, Any]) -> str:
    """
    Encode transaction body to canonical JSON string.

    Args:
        body: Transaction body dictionary

    Returns:
        Canonical JSON string
    """
    return encode_json(body)


# Export all public functions and classes
__all__ = [
    "FieldType",
    "write_varint", "read_varint", "write_uvarint", "read_uvarint",
    "BinaryEncoder", "BinaryDecoder", "JSONEncoder", "Hasher",
    "encode_binary", "decode_binary", "encode_json",
    "hash_sha256", "hash_sha256_hex",
    "decode_transaction", "encode_canonical_json",
    "dumps", "loads", "to_wire_bytes", "from_wire_bytes", "to_dict"
]