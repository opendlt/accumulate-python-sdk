"""
Binary Writer - 1:1 mapping to Dart writer.dart

Implements exact binary encoding semantics matching Dart BinaryWriter class.
Provides primitive encoding with same endianness, varint format, and byte handling.
"""

import struct
from typing import List


class BinaryWriter:
    """
    Binary writer implementing exact Dart writer.dart semantics.

    Maps 1:1 to Dart class BinaryWriter in writer.dart.
    Maintains same method names, signatures, and binary output format.
    """

    def __init__(self):
        """Initialize writer with empty byte buffer."""
        self._bb: List[int] = []

    def u8(self, v: int) -> None:
        """
        Write unsigned 8-bit integer.

        Maps to: Dart writer.dart:5-7 void u8(int v)

        Args:
            v: Integer value to write (0-255)
        """
        self._bb.append(v & 0xFF)

    def u32le(self, v: int) -> None:
        """
        Write unsigned 32-bit integer in little-endian format.

        Maps to: Dart writer.dart:9-13 void u32le(int v)

        Args:
            v: Integer value to write as 32-bit little-endian
        """
        # Pack as little-endian uint32, extend to match Dart behavior
        packed = struct.pack('<I', v & 0xFFFFFFFF)
        self._bb.extend(packed)

    def u64le(self, v: int) -> None:
        """
        Write unsigned 64-bit integer in little-endian format.

        Maps to: Dart writer.dart:15-20 void u64le(int v)

        Args:
            v: Integer value to write as 64-bit little-endian
        """
        # Pack as little-endian uint64, mask to match Dart behavior
        packed = struct.pack('<Q', v & 0xFFFFFFFFFFFFFFFF)
        self._bb.extend(packed)

    def bytes(self, v: bytes) -> None:
        """
        Write raw bytes without length prefix.

        Maps to: Dart writer.dart:22-24 void bytes(Uint8List v)

        Args:
            v: Bytes to write directly
        """
        self._bb.extend(v)

    def len_prefixed_bytes(self, v: bytes) -> None:
        """
        Write bytes with length prefix using uvarint.

        Maps to: Dart writer.dart:26-29 void lenPrefixedBytes(Uint8List v)

        Args:
            v: Bytes to write with length prefix
        """
        self.uvarint(len(v))
        self.bytes(v)

    def string_ascii(self, s: str) -> None:
        """
        Write ASCII string with length prefix.

        Maps to: Dart writer.dart:31-34 void stringAscii(String s)

        Args:
            s: ASCII string to write with length prefix
        """
        # Convert to bytes using codeUnits (ASCII) like Dart
        b = bytes(ord(c) for c in s)
        self.len_prefixed_bytes(b)

    def uvarint(self, v: int) -> None:
        """
        Write unsigned varint in ULEB128 format.

        Maps to: Dart writer.dart:36-44 void uvarint(int v)
        Implements same ULEB128 algorithm as Go binary/varint and Dart.

        Args:
            v: Unsigned integer value to encode as varint
        """
        # ULEB128 encoding - same as Go binary/varint, Dart implementation
        x = v & 0xFFFFFFFFFFFFFFFF  # Ensure unsigned, match Dart >>> 0 behavior
        while x >= 0x80:
            self.u8((x & 0x7F) | 0x80)
            x >>= 7
        self.u8(x)

    def to_bytes(self) -> bytes:
        """
        Return accumulated bytes as immutable bytes object.

        Maps to: Dart writer.dart:46 Uint8List toBytes()

        Returns:
            Bytes containing all written data
        """
        return bytes(self._bb)