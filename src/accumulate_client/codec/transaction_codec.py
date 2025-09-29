"""
Transaction Codec - 1:1 mapping to Dart transaction_codec.dart

Implements exact transaction hashing and encoding semantics matching Dart TransactionCodec.
Follows discovered rules from Go/TypeScript implementations.
"""

import json
from typing import Dict, Any

from .hashes import sha256_bytes
from .writer import BinaryWriter
from .reader import BinaryReader
from ..canonjson import dumps_canonical


class AccumulateCodec:
    """
    Accumulate binary codec that matches TypeScript/Go implementation.

    Maps to: Dart codec.dart AccumulateCodec class
    Implements same field encoding, varint handling, and validation rules.
    """

    @staticmethod
    def field_marshal_binary(field: int, val: bytes) -> bytes:
        """
        Encode a field with a field number (1-32).

        Maps to: Dart codec.dart:9-14 fieldMarshalBinary(int field, Uint8List val)

        Args:
            field: Field number (1-32)
            val: Field value as bytes

        Returns:
            Encoded field with number prefix

        Raises:
            ValueError: If field number is out of range
        """
        if field < 1 or field > 32:
            raise ValueError(f"Field number is out of range [1, 32]: {field}")

        writer = BinaryWriter()
        writer.uvarint(field)
        writer.bytes(val)
        return writer.to_bytes()

    @staticmethod
    def uvarint_marshal_binary(val: int, field: int = None) -> bytes:
        """
        Encode unsigned varint (ULEB128).

        Maps to: Dart codec.dart:17-37 uvarintMarshalBinary(int val, [int? field])

        Args:
            val: Value to encode
            field: Optional field number

        Returns:
            Encoded varint, optionally with field prefix

        Raises:
            ValueError: If value exceeds safe integer range
        """
        if val > 0x7FFFFFFFFFFFFFFF:
            raise ValueError("Cannot marshal binary number greater than MAX_SAFE_INTEGER")

        writer = BinaryWriter()
        writer.uvarint(val)
        data = writer.to_bytes()

        if field is not None:
            return AccumulateCodec.field_marshal_binary(field, data)
        return data

    @staticmethod
    def varint_marshal_binary(val: int, field: int = None) -> bytes:
        """
        Encode signed varint (zigzag encoding).

        Maps to: Dart codec.dart:40-47 varintMarshalBinary(int val, [int? field])

        Args:
            val: Signed value to encode
            field: Optional field number

        Returns:
            Encoded signed varint with zigzag encoding
        """
        # Zigzag encoding: map signed to unsigned
        ux = val << 1
        if val < 0:
            ux = ~ux
        return AccumulateCodec.uvarint_marshal_binary(ux, field)

    @staticmethod
    def boolean_marshal_binary(b: bool, field: int = None) -> bytes:
        """
        Encode boolean.

        Maps to: Dart codec.dart:50-53 booleanMarshalBinary(bool b, [int? field])

        Args:
            b: Boolean value
            field: Optional field number

        Returns:
            Encoded boolean (1 byte: 0 or 1)
        """
        data = bytes([1 if b else 0])
        if field is not None:
            return AccumulateCodec.field_marshal_binary(field, data)
        return data

    @staticmethod
    def string_marshal_binary(val: str, field: int = None) -> bytes:
        """
        Encode string (UTF-8, length-prefixed).

        Maps to: Dart codec.dart:56-59 stringMarshalBinary(String val, [int? field])

        Args:
            val: String value
            field: Optional field number

        Returns:
            Encoded string with length prefix
        """
        data = AccumulateCodec.bytes_marshal_binary(val.encode('utf-8'))
        if field is not None:
            return AccumulateCodec.field_marshal_binary(field, data)
        return data

    @staticmethod
    def bytes_marshal_binary(val: bytes, field: int = None) -> bytes:
        """
        Encode bytes (length-prefixed).

        Maps to: Dart codec.dart:62-66 bytesMarshalBinary(Uint8List val, [int? field])

        Args:
            val: Bytes value
            field: Optional field number

        Returns:
            Encoded bytes with length prefix
        """
        writer = BinaryWriter()
        writer.len_prefixed_bytes(val)
        data = writer.to_bytes()

        if field is not None:
            return AccumulateCodec.field_marshal_binary(field, data)
        return data

    @staticmethod
    def hash_marshal_binary(val: bytes, field: int = None) -> bytes:
        """
        Encode hash (32 bytes, no length prefix).

        Maps to: Dart codec.dart:69-74 hashMarshalBinary(Uint8List val, [int? field])

        Args:
            val: Hash bytes (must be 32 bytes)
            field: Optional field number

        Returns:
            Encoded hash without length prefix

        Raises:
            ValueError: If not exactly 32 bytes
        """
        if len(val) != 32:
            raise ValueError(f"Invalid length, value is not a hash: {len(val)}")

        if field is not None:
            return AccumulateCodec.field_marshal_binary(field, val)
        return val

    @staticmethod
    def bigint_marshal_binary(bn: int, field: int = None) -> bytes:
        """
        Encode BigInt (as big-endian bytes, length-prefixed).

        Maps to: Dart codec.dart:77-93 bigIntMarshalBinary(BigInt bn, [int? field])

        Args:
            bn: Integer value (non-negative)
            field: Optional field number

        Returns:
            Encoded big integer as length-prefixed big-endian bytes

        Raises:
            ValueError: If negative integer
        """
        if bn < 0:
            raise ValueError("Cannot marshal a negative bigint")

        # Convert to hex string, ensure even length
        s = hex(bn)[2:]  # Remove '0x' prefix
        if len(s) % 2 == 1:
            s = "0" + s

        # Convert hex string to bytes
        bytes_data = bytes.fromhex(s)
        data = AccumulateCodec.bytes_marshal_binary(bytes_data)

        if field is not None:
            return AccumulateCodec.field_marshal_binary(field, data)
        return data


class TransactionCodec:
    """
    Transaction hashing facade implementing discovered rules from Go/TypeScript.

    Maps to: Dart transaction_codec.dart TransactionCodec class

    Key discoveries:
    - Go: protocol/transaction_hash.go:27-71 - SHA256(SHA256(header_binary) + SHA256(body_binary))
    - TypeScript: src/core/base.ts:13-44 - Same algorithm with special WriteData handling
    - Signing: protocol/signature_utils.go:50-57 - SHA256(signature_metadata_hash + transaction_hash)
    """

    @staticmethod
    def encode_tx_for_signing(header: Dict[str, Any], body: Dict[str, Any]) -> bytes:
        """
        Encode transaction for signing - implements discovered preimage construction.

        Maps to: Dart transaction_codec.dart:15-30 encodeTxForSigning()
        Based on Go: protocol/transaction_hash.go:27-71 and TypeScript: src/core/base.ts:13-44

        Args:
            header: Transaction header dict
            body: Transaction body dict

        Returns:
            Transaction hash for signing (32 bytes)
        """
        # Encode header and body to canonical binary format using Dart-compatible canonical JSON
        header_json = dumps_canonical(header).encode('utf-8')
        body_json = dumps_canonical(body).encode('utf-8')

        header_bytes = AccumulateCodec.bytes_marshal_binary(header_json)
        body_bytes = AccumulateCodec.bytes_marshal_binary(body_json)

        # Hash header and body separately
        header_hash = sha256_bytes(header_bytes)
        body_hash = sha256_bytes(body_bytes)

        # Transaction hash = SHA256(SHA256(header) + SHA256(body))
        combined = header_hash + body_hash
        return sha256_bytes(combined)

    @staticmethod
    def create_signing_preimage(signature_metadata_hash: bytes, transaction_hash: bytes) -> bytes:
        """
        Create signing preimage - implements discovered signing rules.

        Maps to: Dart transaction_codec.dart:34-39 createSigningPreimage()
        Based on Go: protocol/signature_utils.go:50-57

        Args:
            signature_metadata_hash: Hash of signature metadata
            transaction_hash: Hash of transaction

        Returns:
            Final signing preimage (32 bytes)
        """
        combined = signature_metadata_hash + transaction_hash
        return sha256_bytes(combined)