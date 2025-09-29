"""
Binary Reader - 1:1 mapping to Dart reader.dart

Implements exact binary decoding semantics matching Dart BinaryReader class.
Provides primitive decoding with same endianness, varint format, and byte handling.
"""

import builtins
import struct


class BinaryReader:
    """
    Binary reader implementing exact Dart reader.dart semantics.

    Maps 1:1 to Dart class BinaryReader in reader.dart.
    Maintains same method names, signatures, and binary parsing behavior.
    """

    def __init__(self, buf: builtins.bytes):
        """
        Initialize reader with byte buffer.

        Maps to: Dart reader.dart:6 BinaryReader(this._buf)

        Args:
            buf: Byte buffer to read from
        """
        self._buf = buf
        self._off = 0

    @property
    def eof(self) -> bool:
        """
        Check if at end of buffer.

        Maps to: Dart reader.dart:7 bool get eof => _off >= _buf.length

        Returns:
            True if at end of buffer
        """
        return self._off >= len(self._buf)

    def u8(self) -> int:
        """
        Read unsigned 8-bit integer.

        Maps to: Dart reader.dart:9-11 int u8()

        Returns:
            Unsigned 8-bit integer value
        """
        if self._off >= len(self._buf):
            raise IndexError("Buffer overflow: attempting to read beyond end")
        val = self._buf[self._off]
        self._off += 1
        return val

    def u32le(self) -> int:
        """
        Read unsigned 32-bit integer in little-endian format.

        Maps to: Dart reader.dart:13-18 int u32le()

        Returns:
            Unsigned 32-bit integer value
        """
        if self._off + 4 > len(self._buf):
            raise IndexError("Buffer overflow: attempting to read u32le beyond end")
        # Use struct.unpack to match Dart ByteData.getUint32(0, Endian.little)
        val = struct.unpack("<I", self._buf[self._off : self._off + 4])[0]
        self._off += 4
        return val

    def u64le(self) -> int:
        """
        Read unsigned 64-bit integer in little-endian format.

        Maps to: Dart reader.dart:20-25 int u64le()

        Returns:
            Unsigned 64-bit integer value
        """
        if self._off + 8 > len(self._buf):
            raise IndexError("Buffer overflow: attempting to read u64le beyond end")
        # Use struct.unpack to match Dart ByteData.getUint64(0, Endian.little)
        val = struct.unpack("<Q", self._buf[self._off : self._off + 8])[0]
        self._off += 8
        return val

    def uvarint(self) -> int:
        """
        Read unsigned varint in ULEB128 format.

        Maps to: Dart reader.dart:27-39 int uvarint()
        Implements same ULEB128 algorithm as Dart.

        Returns:
            Decoded unsigned integer value
        """
        x = 0
        s = 0
        while True:
            if self._off >= len(self._buf):
                raise IndexError("Buffer overflow: attempting to read varint beyond end")
            b = self.u8()
            if b < 0x80:
                x |= b << s
                break
            x |= (b & 0x7F) << s
            s += 7
        return x

    def bytes(self, n: int) -> builtins.bytes:
        """
        Read n bytes from buffer.

        Maps to: Dart reader.dart:41-45 Uint8List bytes(int n)

        Args:
            n: Number of bytes to read

        Returns:
            Bytes of specified length
        """
        if self._off + n > len(self._buf):
            raise IndexError(f"Buffer overflow: attempting to read {n} bytes beyond end")
        # Use slice to match Dart Uint8List.sublistView behavior
        out = self._buf[self._off : self._off + n]
        self._off += n
        return out

    def len_prefixed_bytes(self) -> builtins.bytes:
        """
        Read bytes with length prefix using uvarint.

        Maps to: Dart reader.dart:47-50 Uint8List lenPrefixedBytes()

        Returns:
            Bytes with length read from uvarint prefix
        """
        n = self.uvarint()
        return self.bytes(n)

    def string_ascii(self) -> str:
        """
        Read ASCII string with length prefix.

        Maps to: Dart reader.dart:52-55 String stringAscii()

        Returns:
            ASCII string decoded from length-prefixed bytes
        """
        b = self.len_prefixed_bytes()
        # Use String.fromCharCodes equivalent - decode as ASCII
        return "".join(chr(byte) for byte in b)
