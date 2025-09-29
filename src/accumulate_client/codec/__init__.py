"""
Accumulate Binary Codec Module

Provides bit-for-bit binary parity with Dart SDK codec implementation.
Implements canonical binary encoding/decoding for transactions, envelopes,
and core types following exact Dart semantics.

Key components:
- writer.py: Binary writer with varint/primitive encoding (1:1 mapping to Dart writer.dart)
- reader.py: Binary reader with varint/primitive decoding (1:1 mapping to Dart reader.dart)
- transaction_codec.py: Transaction hashing and encoding (1:1 mapping to Dart transaction_codec.dart)
- hashes.py: SHA-256 hashing helpers (1:1 mapping to Dart hash.dart)
"""

from .hashes import sha256_bytes, sha256_of_bytes
from .reader import BinaryReader
from .transaction_codec import TransactionCodec
from .writer import BinaryWriter

__all__ = [
    "BinaryReader",
    "BinaryWriter",
    "TransactionCodec",
    "sha256_bytes",
    "sha256_of_bytes",
]
