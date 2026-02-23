"""
Convenience utilities for Accumulate SDK.

Provides high-level APIs matching Dart SDK patterns:
- SmartSigner: Auto-version tracking signer with sign/submit/wait
- TxBody: Factory methods for creating transaction bodies
- QuickStart: Ultra-simple API for rapid development
- KeyManager: Key page query and management utilities

Example usage:
    ```python
    from accumulate_client import Accumulate
    from accumulate_client.convenience import SmartSigner, TxBody, QuickStart

    # QuickStart API (simplest)
    acc = QuickStart.devnet()
    wallet = acc.create_wallet()
    acc.fund_wallet(wallet)
    adi = acc.setup_adi(wallet, "my-adi")

    # SmartSigner API (more control)
    client = Accumulate.devnet()
    signer = SmartSigner(client.v3, keypair, signer_url)
    result = signer.sign_submit_and_wait(
        principal="acc://my-adi.acme/tokens",
        body=TxBody.send_tokens_single("acc://recipient.acme", "1000000000"),
        memo="Send 10 ACME"
    )
    ```
"""

from __future__ import annotations
import hashlib
import time
import asyncio
from typing import Optional, Dict, Any, List, Union, Tuple, TYPE_CHECKING
from dataclasses import dataclass, field
from datetime import datetime

if TYPE_CHECKING:
    from .v3.client import AccumulateV3Client
    from .facade import Accumulate


# =============================================================================
# Binary Encoding Helpers for Accumulate Protocol
# =============================================================================
# These implement the exact binary field encoding used by Go's MarshalBinary()
# for computing transaction hashes and signing preimages.
# Reference: Go protocol/types_gen.go, protocol/signature.go

def _sha256(data: bytes) -> bytes:
    """SHA-256 hash."""
    return hashlib.sha256(data).digest()


def _encode_uvarint(val: int) -> bytes:
    """Encode unsigned varint (ULEB128)."""
    result = bytearray()
    x = val & 0xFFFFFFFFFFFFFFFF
    while x >= 0x80:
        result.append((x & 0x7F) | 0x80)
        x >>= 7
    result.append(x)
    return bytes(result)


def _field(field_num: int, val: bytes) -> bytes:
    """Encode a field: uvarint(field_number) + raw_bytes(value)."""
    return _encode_uvarint(field_num) + val


def _field_uvarint(field_num: int, val: int) -> bytes:
    """Encode a uvarint field."""
    return _field(field_num, _encode_uvarint(val))


def _field_bytes(field_num: int, val: bytes) -> bytes:
    """Encode a bytes field (length-prefixed)."""
    return _field(field_num, _encode_uvarint(len(val)) + val)


def _field_string(field_num: int, val: str) -> bytes:
    """Encode a string field (length-prefixed UTF-8)."""
    encoded = val.encode("utf-8")
    return _field(field_num, _encode_uvarint(len(encoded)) + encoded)


def _field_hash(field_num: int, val: bytes) -> bytes:
    """Encode a 32-byte hash field (no length prefix)."""
    assert len(val) == 32, f"Hash must be 32 bytes, got {len(val)}"
    return _field(field_num, val)


def _field_bigint(field_num: int, val: int) -> bytes:
    """Encode a BigInt field (big-endian bytes, length-prefixed)."""
    if val == 0:
        return _field_bytes(field_num, b'\x00')
    s = hex(val)[2:]
    if len(s) % 2 == 1:
        s = "0" + s
    bigint_bytes = bytes.fromhex(s)
    return _field_bytes(field_num, bigint_bytes)


def _combine_hashes(a: bytes, b: bytes) -> bytes:
    """Combine two hashes: SHA256(a + b). Matches Go's combineHashes."""
    return _sha256(a + b)


def _merkle_hash(hashes: list) -> bytes:
    """
    Compute Merkle DAG root from a list of 32-byte hashes.

    Matches Go's merkle.State.AddEntry + Anchor pattern.
    Uses binary carry addition for incremental tree construction.
    """
    if not hashes:
        return b'\x00' * 32

    pending = []
    count = 0

    for h in hashes:
        count += 1
        # Pad pending if needed
        while len(pending) < count.bit_length():
            pending.append(None)

        current = h
        for i in range(len(pending)):
            if pending[i] is None:
                pending[i] = current
                break
            current = _combine_hashes(pending[i], current)
            pending[i] = None
        else:
            pending.append(current)

    # Compute anchor
    anchor = None
    for v in pending:
        if anchor is None:
            if v is not None:
                anchor = v[:]
        elif v is not None:
            anchor = _combine_hashes(v, anchor)

    return anchor if anchor else b'\x00' * 32


def _data_entry_hash(entry: dict) -> bytes:
    """
    Compute the hash of a data entry.

    For DoubleHashDataEntry: double-SHA256 of merkle root of data hashes.
    For AccumulateDataEntry: merkle root of data hashes (single hash).
    """
    data_items = entry.get("data", [])
    entry_type = entry.get("type", "")

    # Build list of SHA256(data_item) for each data item
    item_hashes = []
    for d in data_items:
        if isinstance(d, str):
            d = bytes.fromhex(d)
        item_hashes.append(_sha256(d))

    merkle_root = _merkle_hash(item_hashes)

    if entry_type in ("doubleHash", "doubleHashDataEntry"):
        # DoubleHashDataEntry: double hash the merkle root
        return _sha256(merkle_root)
    else:
        # AccumulateDataEntry: just the merkle root
        return merkle_root


def _compute_write_data_body_hash(body: dict) -> bytes:
    """
    Compute WriteData body hash using the special GetHash() algorithm.

    Instead of SHA256(MarshalBinary(body)), WriteData uses:
    1. Marshal body WITHOUT the entry field
    2. Compute entry.Hash() separately
    3. Return MerkleHash([SHA256(body_without_entry), entry_hash])
    """
    # Step 1: Marshal body without entry - just the type field (and scratch/writeToState if set)
    body_parts = bytearray()
    body_parts += _field_uvarint(1, 5)  # TransactionType = writeData = 5
    if body.get("scratch"):
        body_parts += _field_uvarint(3, 1)
    if body.get("writeToState"):
        body_parts += _field_uvarint(4, 1)
    body_without_entry = bytes(body_parts)

    # Step 2: Compute entry hash
    entry = body.get("entry", {})
    entry_hash = _data_entry_hash(entry)

    # Step 3: Merkle hash of [SHA256(body_without_entry), entry_hash]
    h1 = _sha256(body_without_entry)
    return _merkle_hash([h1, entry_hash])


def _encode_ed25519_sig_metadata(
    public_key: bytes,
    signer_url: str,
    signer_version: int,
    timestamp: int
) -> bytes:
    """
    Binary-encode ED25519 signature metadata for initiator/preimage computation.

    Go struct field order (protocol/types_gen.go):
      Field 1: Type (SignatureType)
      Field 2: PublicKey (bytes)
      Field 3: Signature (bytes) - SKIPPED in metadata
      Field 4: Signer (URL)
      Field 5: SignerVersion (uint64)
      Field 6: Timestamp (uint64)
      Field 7: Vote (VoteType) - 0=Accept, skipped when default
    """
    parts = bytearray()

    # Field 1: Type = ED25519 (SignatureType.ED25519 = 2)
    parts += _field_uvarint(1, 2)

    # Field 2: PublicKey
    parts += _field_bytes(2, public_key)

    # Field 3: Signature - SKIPPED in metadata

    # Field 4: Signer URL
    parts += _field_string(4, signer_url)

    # Field 5: SignerVersion (skip if 0)
    if signer_version != 0:
        parts += _field_uvarint(5, signer_version)

    # Field 6: Timestamp (skip if 0)
    if timestamp != 0:
        parts += _field_uvarint(6, timestamp)

    # Field 7: Vote = ACCEPT (0) - skipped as zero value

    return bytes(parts)


def _encode_tx_header(
    principal: str,
    initiator: bytes,
    memo: Optional[str] = None,
    metadata: Optional[bytes] = None
) -> bytes:
    """
    Binary-encode transaction header.

    Go struct field order (protocol/types_gen.go):
      Field 1: Principal (URL)
      Field 2: Initiator (Hash, 32 bytes)
      Field 3: Memo (string, optional)
      Field 4: Metadata (bytes, optional)
      Field 5: Expire (optional)
      Field 6: HoldUntil (optional)
      Field 7: Authorities (optional)
    """
    parts = bytearray()

    # Field 1: Principal URL
    parts += _field_string(1, principal)

    # Field 2: Initiator hash (32 bytes)
    if initiator and initiator != b'\x00' * 32:
        parts += _field_hash(2, initiator)

    # Field 3: Memo (optional)
    if memo:
        parts += _field_string(3, memo)

    # Field 4: Metadata (optional)
    if metadata:
        parts += _field_bytes(4, metadata)

    # Fields 5-7: Expire, HoldUntil, Authorities - not implemented for basic use

    return bytes(parts)


def _encode_tx_body(body: Dict[str, Any]) -> bytes:
    """
    Binary-encode transaction body based on type.

    Each body type encodes: Field 1 = TransactionType (uint), then type-specific fields.
    """
    body_type = body.get("type", "")
    parts = bytearray()

    _TX_TYPE_MAP = {
        "createIdentity": 1, "createTokenAccount": 2, "sendTokens": 3,
        "createDataAccount": 4, "writeData": 5, "writeDataTo": 6,
        "acmeFaucet": 7, "createToken": 8, "issueTokens": 9,
        "burnTokens": 10, "createLiteTokenAccount": 11,
        "createKeyPage": 12, "createKeyBook": 13, "addCredits": 14,
        "updateKeyPage": 15, "lockAccount": 16, "burnCredits": 17,
        "transferCredits": 18, "updateAccountAuth": 21, "updateKey": 22,
    }

    tx_type_val = _TX_TYPE_MAP.get(body_type, 0)

    # Field 1: TransactionType
    parts += _field_uvarint(1, tx_type_val)

    if body_type == "addCredits":
        if body.get("recipient"):
            parts += _field_string(2, body["recipient"])
        amount = int(body.get("amount", 0))
        if amount > 0:
            parts += _field_bigint(3, amount)
        oracle = body.get("oracle", 0)
        if oracle:
            parts += _field_uvarint(4, oracle)

    elif body_type == "sendTokens":
        # Go field order: Type(1), Hash(2), Meta(3), To(4)
        for recipient in body.get("to", []):
            r_parts = bytearray()
            if recipient.get("url"):
                r_parts += _field_string(1, recipient["url"])
            amt = int(recipient.get("amount", 0))
            if amt > 0:
                r_parts += _field_bigint(2, amt)
            parts += _field_bytes(4, bytes(r_parts))

    elif body_type == "createIdentity":
        # Go field order: Type(1), Url(2), KeyHash(3, WriteBytes), KeyBookUrl(4), Authorities(6)
        if body.get("url"):
            parts += _field_string(2, body["url"])
        if body.get("keyHash"):
            kh = body["keyHash"]
            if isinstance(kh, str):
                kh = bytes.fromhex(kh)
            parts += _field_bytes(3, kh)  # WriteBytes, not WriteHash
        if body.get("keyBookUrl"):
            parts += _field_string(4, body["keyBookUrl"])

    elif body_type == "createTokenAccount":
        if body.get("url"):
            parts += _field_string(2, body["url"])
        if body.get("tokenUrl"):
            parts += _field_string(3, body["tokenUrl"])

    elif body_type == "createDataAccount":
        if body.get("url"):
            parts += _field_string(2, body["url"])

    elif body_type == "writeData":
        entry = body.get("entry", {})
        entry_bytes = _encode_data_entry(entry)
        if entry_bytes:
            parts += _field_bytes(2, entry_bytes)
        if body.get("scratch"):
            parts += _field_uvarint(3, 1)

    elif body_type == "createToken":
        # Go field order: Type(1), Url(2), Symbol(4), Precision(5), Properties(6), SupplyLimit(7)
        if body.get("url"):
            parts += _field_string(2, body["url"])
        if body.get("symbol"):
            parts += _field_string(4, body["symbol"])
        if body.get("precision") is not None:
            parts += _field_uvarint(5, body["precision"])
        if body.get("supplyLimit") is not None:
            parts += _field_bigint(7, body["supplyLimit"])

    elif body_type == "issueTokens":
        # Go field order: Type(1), Recipient(2), Amount(3), To(4)
        for recipient in body.get("to", []):
            r_parts = bytearray()
            if recipient.get("url"):
                r_parts += _field_string(1, recipient["url"])
            amt = int(recipient.get("amount", 0))
            if amt > 0:
                r_parts += _field_bigint(2, amt)
            parts += _field_bytes(4, bytes(r_parts))

    elif body_type == "burnTokens":
        amount = int(body.get("amount", 0))
        if amount > 0:
            parts += _field_bigint(2, amount)

    elif body_type == "createKeyPage":
        # Go uses KeySpec: PublicKeyHash(1, WriteBytes), LastUsedOn(2), Delegate(3, WriteUrl)
        for key_spec in body.get("keys", []):
            ks_parts = bytearray()
            if key_spec.get("keyHash"):
                kh = key_spec["keyHash"]
                if isinstance(kh, str):
                    kh = bytes.fromhex(kh)
                ks_parts += _field_bytes(1, kh)  # WriteBytes, not WriteHash
            if key_spec.get("delegate"):
                ks_parts += _field_string(3, key_spec["delegate"])  # KeySpec delegate=field 3
            parts += _field_bytes(2, bytes(ks_parts))

    elif body_type == "createKeyBook":
        # Go field order: Type(1), Url(2), PublicKeyHash(3, WriteBytes), Authorities(5)
        if body.get("url"):
            parts += _field_string(2, body["url"])
        if body.get("publicKeyHash"):
            pkh = body["publicKeyHash"]
            if isinstance(pkh, str):
                pkh = bytes.fromhex(pkh)
            parts += _field_bytes(3, pkh)  # WriteBytes, not WriteHash

    elif body_type == "updateKeyPage":
        for op in body.get("operation", []):
            op_bytes = _encode_key_page_operation(op)
            if op_bytes:
                parts += _field_bytes(2, op_bytes)

    return bytes(parts)


def _encode_data_entry(entry: Dict[str, Any]) -> bytes:
    """Encode a data entry for WriteData body."""
    entry_type = entry.get("type", "")
    parts = bytearray()

    _ENTRY_TYPE_MAP = {"accumulate": 2, "dataEntry": 2, "doubleHash": 3, "doubleHashDataEntry": 3}
    type_val = _ENTRY_TYPE_MAP.get(entry_type, 0)

    if type_val:
        parts += _field_uvarint(1, type_val)

    for d in entry.get("data", []):
        if isinstance(d, str):
            d = bytes.fromhex(d)
        parts += _field_bytes(2, d)

    return bytes(parts)


def _encode_key_page_operation(op: Dict[str, Any]) -> bytes:
    """Encode a key page operation."""
    op_type = op.get("type", "")
    parts = bytearray()

    _OP_TYPE_MAP = {"update": 1, "remove": 2, "add": 3, "setThreshold": 4}
    type_val = _OP_TYPE_MAP.get(op_type, 0)
    parts += _field_uvarint(1, type_val)

    if op_type in ("add", "remove", "update"):
        # KeySpecParams: KeyHash(1, WriteBytes), Delegate(2, WriteUrl)
        entry = op.get("entry", {})
        e_parts = bytearray()
        if entry.get("keyHash"):
            kh = entry["keyHash"]
            if isinstance(kh, str):
                kh = bytes.fromhex(kh)
            e_parts += _field_bytes(1, kh)  # WriteBytes, not WriteHash
        if entry.get("delegate"):
            e_parts += _field_string(2, entry["delegate"])
        parts += _field_bytes(2, bytes(e_parts))

    elif op_type == "setThreshold":
        parts += _field_uvarint(2, op.get("threshold", 1))

    return bytes(parts)


def _compute_tx_hash_and_sign(
    keypair: Any,
    principal: str,
    body: Dict[str, Any],
    signer_url: str,
    signer_version: int,
    memo: Optional[str] = None,
    timestamp: Optional[int] = None
) -> Tuple[Dict[str, Any], int]:
    """
    Compute transaction hash and sign using proper binary encoding.

    Returns:
        Tuple of (envelope_dict, timestamp_used)
    """
    # Get public key
    if hasattr(keypair, 'public_key_bytes'):
        public_key_bytes = keypair.public_key_bytes()
    elif hasattr(keypair, 'public_key'):
        pk = keypair.public_key
        public_key_bytes = pk().to_bytes() if callable(pk) else pk.to_bytes()
    else:
        raise ValueError("Keypair must have public_key or public_key_bytes")

    if timestamp is None:
        timestamp = int(time.time() * 1_000_000)  # microseconds

    # Step 1: Binary-encode signature metadata
    sig_metadata_binary = _encode_ed25519_sig_metadata(
        public_key=public_key_bytes,
        signer_url=signer_url,
        signer_version=signer_version,
        timestamp=timestamp
    )

    # Step 2: Compute initiator = SHA256(sig_metadata_binary)
    initiator = _sha256(sig_metadata_binary)

    # Step 3: Binary-encode transaction header (NO timestamp - only in signature)
    header_binary = _encode_tx_header(
        principal=principal,
        initiator=initiator,
        memo=memo
    )

    # Step 4: Binary-encode transaction body
    body_binary = _encode_tx_body(body)

    # Step 5: Compute tx_hash = SHA256(SHA256(header) + body_hash)
    # WriteData/WriteDataTo use a special body hash (Merkle of body-without-entry + entry hash)
    header_hash = _sha256(header_binary)
    body_type = body.get("type", "")
    if body_type in ("writeData", "writeDataTo"):
        body_hash = _compute_write_data_body_hash(body)
    else:
        body_hash = _sha256(body_binary)
    tx_hash = _sha256(header_hash + body_hash)

    # Step 6: Compute signing preimage = SHA256(initiator + tx_hash)
    signing_preimage = _sha256(initiator + tx_hash)

    # Step 7: Sign the preimage
    if hasattr(keypair, 'sign'):
        signature = keypair.sign(signing_preimage)
    elif hasattr(keypair, 'private_key'):
        signature = keypair.private_key.sign(signing_preimage)
    else:
        raise ValueError("Keypair must have sign method or private_key")

    # Step 8: Build envelope
    transaction = {
        "header": {
            "principal": principal,
            "initiator": initiator.hex()
        },
        "body": body
    }
    if memo:
        transaction["header"]["memo"] = memo

    envelope = {
        "transaction": transaction,
        "signatures": [{
            "type": "ed25519",
            "publicKey": public_key_bytes.hex(),
            "signature": signature.hex(),
            "signer": signer_url,
            "signerVersion": signer_version,
            "timestamp": timestamp
        }]
    }

    return envelope, timestamp


# =============================================================================
# Data Classes
# =============================================================================

@dataclass
class SubmitResult:
    """Result of a transaction submission."""
    success: bool
    txid: Optional[str] = None
    error: Optional[str] = None
    response: Optional[Dict[str, Any]] = None


@dataclass
class Wallet:
    """Simple wallet containing keypair and derived URLs."""
    keypair: Any
    lite_identity: str
    lite_token_account: str
    public_key_hash: str


@dataclass
class ADI:
    """ADI (Accumulate Digital Identifier) with associated resources."""
    url: str
    key_book_url: str
    key_page_url: str
    keypair: Any
    public_key_hash: str


@dataclass
class KeyPageInfo:
    """Key page state information."""
    url: str
    version: int
    credits: int
    threshold: int
    key_count: int
    keys: List[str]


# =============================================================================
# TxBody - Transaction Body Factory
# =============================================================================

class TxBody:
    """
    Factory class for creating transaction bodies.

    Provides static methods matching Dart SDK's TxBody pattern for
    easy transaction body construction.

    Example:
        ```python
        body = TxBody.send_tokens_single("acc://recipient.acme", "1000000000")
        body = TxBody.create_identity("acc://my-adi.acme", "acc://my-adi.acme/book", key_hash)
        body = TxBody.add_credits("acc://recipient.acme", "1000000000", oracle)
        ```
    """

    @staticmethod
    def send_tokens_single(to_url: str, amount: str) -> Dict[str, Any]:
        """Create SendTokens body for single recipient."""
        return {
            "type": "sendTokens",
            "to": [{"url": to_url, "amount": amount}]
        }

    @staticmethod
    def send_tokens(recipients: List[Dict[str, str]]) -> Dict[str, Any]:
        """Create SendTokens body for multiple recipients."""
        return {
            "type": "sendTokens",
            "to": [{"url": r["url"], "amount": r["amount"]} for r in recipients]
        }

    @staticmethod
    def add_credits(recipient: str, amount: str, oracle: int) -> Dict[str, Any]:
        """Create AddCredits body."""
        return {
            "type": "addCredits",
            "recipient": recipient,
            "amount": amount,
            "oracle": oracle
        }

    @staticmethod
    def buy_credits(recipient_url: str, amount: str, oracle: int) -> Dict[str, Any]:
        """Alias for add_credits (Dart SDK compatibility)."""
        return TxBody.add_credits(recipient_url, amount, oracle)

    @staticmethod
    def create_identity(
        url: str,
        key_book_url: str,
        public_key_hash: str
    ) -> Dict[str, Any]:
        """Create CreateIdentity body."""
        return {
            "type": "createIdentity",
            "url": url,
            "keyBookUrl": key_book_url,
            "keyHash": public_key_hash
        }

    @staticmethod
    def create_token_account(url: str, token_url: str = "acc://ACME") -> Dict[str, Any]:
        """Create CreateTokenAccount body."""
        return {
            "type": "createTokenAccount",
            "url": url,
            "tokenUrl": token_url
        }

    @staticmethod
    def create_data_account(url: str) -> Dict[str, Any]:
        """Create CreateDataAccount body."""
        return {
            "type": "createDataAccount",
            "url": url
        }

    @staticmethod
    def write_data(entries_hex: List[str], scratch: bool = False, write_to_state: bool = False) -> Dict[str, Any]:
        """Create WriteData body with hex-encoded entries.

        Uses DoubleHashDataEntry type (matches Go protocol general.yml).
        Note: "dataEntry" type is deprecated; use "doubleHash" instead.
        """
        body: Dict[str, Any] = {
            "type": "writeData",
            "entry": {
                "type": "doubleHash",
                "data": entries_hex
            }
        }
        if scratch:
            body["scratch"] = True
        if write_to_state:
            body["writeToState"] = True
        return body

    @staticmethod
    def write_data_strings(entries: List[str], scratch: bool = False, write_to_state: bool = False) -> Dict[str, Any]:
        """Create WriteData body with string entries (auto hex-encoded)."""
        hex_entries = [entry.encode().hex() for entry in entries]
        return TxBody.write_data(hex_entries, scratch=scratch, write_to_state=write_to_state)

    @staticmethod
    def create_token(
        url: str,
        symbol: str,
        precision: int,
        supply_limit: Optional[int] = None
    ) -> Dict[str, Any]:
        """Create CreateToken body."""
        body: Dict[str, Any] = {
            "type": "createToken",
            "url": url,
            "symbol": symbol,
            "precision": precision
        }
        if supply_limit is not None:
            body["supplyLimit"] = supply_limit
        return body

    @staticmethod
    def issue_tokens_single(to_url: str, amount: str) -> Dict[str, Any]:
        """Create IssueTokens body for single recipient."""
        return {
            "type": "issueTokens",
            "to": [{"url": to_url, "amount": amount}]
        }

    @staticmethod
    def burn_tokens(amount: int) -> Dict[str, Any]:
        """Create BurnTokens body."""
        return {
            "type": "burnTokens",
            "amount": amount
        }

    @staticmethod
    def create_key_page(keys: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Create CreateKeyPage body."""
        return {
            "type": "createKeyPage",
            "keys": keys
        }

    @staticmethod
    def create_key_book(url: str, public_key_hash: str) -> Dict[str, Any]:
        """Create CreateKeyBook body."""
        return {
            "type": "createKeyBook",
            "url": url,
            "publicKeyHash": public_key_hash
        }

    @staticmethod
    def update_key_page(operations: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Create UpdateKeyPage body."""
        return {
            "type": "updateKeyPage",
            "operation": operations
        }

    @staticmethod
    def add_key_operation(key_hash: bytes) -> Dict[str, Any]:
        """Create an AddKey operation for UpdateKeyPage."""
        return {
            "type": "add",
            "entry": {"keyHash": key_hash.hex()}
        }

    @staticmethod
    def remove_key_operation(key_hash: bytes) -> Dict[str, Any]:
        """Create a RemoveKey operation for UpdateKeyPage."""
        return {
            "type": "remove",
            "entry": {"keyHash": key_hash.hex()}
        }

    @staticmethod
    def set_threshold_operation(threshold: int) -> Dict[str, Any]:
        """Create a SetThreshold operation for UpdateKeyPage."""
        return {
            "type": "setThreshold",
            "threshold": threshold
        }

    @staticmethod
    def acme_faucet(url: str) -> Dict[str, Any]:
        """Create AcmeFaucet body."""
        return {
            "type": "acmeFaucet",
            "url": url
        }

    @staticmethod
    def transfer_credits(to: str, amount: int) -> Dict[str, Any]:
        """Create TransferCredits body."""
        return {
            "type": "transferCredits",
            "to": [{"url": to, "amount": amount}]
        }

    @staticmethod
    def burn_credits(amount: int) -> Dict[str, Any]:
        """Create BurnCredits body."""
        return {
            "type": "burnCredits",
            "amount": amount
        }

    @staticmethod
    def update_key(new_key_hash: str) -> Dict[str, Any]:
        """Create UpdateKey body for key rotation."""
        return {
            "type": "updateKey",
            "newKeyHash": new_key_hash
        }

    @staticmethod
    def lock_account(height: int) -> Dict[str, Any]:
        """Create LockAccount body."""
        return {
            "type": "lockAccount",
            "height": height
        }

    @staticmethod
    def update_account_auth(operations: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Create UpdateAccountAuth body."""
        return {
            "type": "updateAccountAuth",
            "operations": operations
        }

    @staticmethod
    def write_data_to(recipient: str, entries_hex: List[str]) -> Dict[str, Any]:
        """Create WriteDataTo body with hex-encoded entries."""
        return {
            "type": "writeDataTo",
            "recipient": recipient,
            "entry": {
                "type": "doubleHash",
                "data": entries_hex
            }
        }


# =============================================================================
# SmartSigner - High-level signer with auto-version tracking
# =============================================================================

class SmartSigner:
    """
    High-level signer with auto-version tracking and sign/submit/wait.

    SmartSigner automatically fetches and tracks the signer version,
    making it easy to sign and submit transactions without manual
    version management.

    Example:
        ```python
        signer = SmartSigner(client.v3, keypair, "acc://my-adi.acme/book/1")

        # Sign, submit, and wait for result
        result = signer.sign_submit_and_wait(
            principal="acc://my-adi.acme/tokens",
            body=TxBody.send_tokens_single("acc://recipient.acme", "100000000"),
            memo="Send 1 ACME",
            max_attempts=30
        )

        if result.success:
            print(f"Transaction ID: {result.txid}")
        else:
            print(f"Failed: {result.error}")
        ```
    """

    def __init__(
        self,
        client: AccumulateV3Client,
        keypair: Any,
        signer_url: str
    ):
        """
        Initialize SmartSigner.

        Args:
            client: V3 API client
            keypair: Ed25519KeyPair or compatible keypair object
            signer_url: URL of the signing key page
        """
        self.client = client
        self.keypair = keypair
        self.signer_url = signer_url
        self._cached_version: Optional[int] = None

    def get_signer_version(self) -> int:
        """Fetch current signer version from network."""
        try:
            result = self.client.query(self.signer_url)
            if result.get("account"):
                self._cached_version = result["account"].get("version", 1)
            else:
                self._cached_version = 1
        except Exception:
            self._cached_version = 1
        return self._cached_version

    def sign_and_build(
        self,
        principal: str,
        body: Dict[str, Any],
        memo: Optional[str] = None,
        signer_version: Optional[int] = None
    ) -> Dict[str, Any]:
        """
        Sign a transaction and build the envelope.

        Uses proper binary encoding matching the Go protocol implementation:
        1. Binary-encode signature metadata → compute initiator hash
        2. Binary-encode transaction header (with initiator) and body
        3. Compute tx_hash = SHA256(SHA256(header_binary) + SHA256(body_binary))
        4. Compute signing preimage = SHA256(initiator + tx_hash)
        5. Sign the preimage

        Args:
            principal: Transaction principal URL
            body: Transaction body
            memo: Optional memo
            signer_version: Optional explicit version (auto-fetched if None)

        Returns:
            Complete transaction envelope ready for submission
        """
        # Get signer version
        if signer_version is None:
            signer_version = self.get_signer_version()

        envelope, _ = _compute_tx_hash_and_sign(
            keypair=self.keypair,
            principal=principal,
            body=body,
            signer_url=self.signer_url,
            signer_version=signer_version,
            memo=memo
        )

        return envelope

    def sign_submit_and_wait(
        self,
        principal: str,
        body: Dict[str, Any],
        memo: Optional[str] = None,
        max_attempts: int = 30,
        poll_interval: float = 2.0,
        verbose: bool = False
    ) -> SubmitResult:
        """
        Sign, submit, and wait for transaction completion.

        Args:
            principal: Transaction principal URL
            body: Transaction body
            memo: Optional memo
            max_attempts: Maximum poll attempts
            poll_interval: Seconds between polls
            verbose: If True, print full RPC responses for debugging

        Returns:
            SubmitResult with success status and transaction ID
        """
        try:
            # Build and sign envelope
            envelope = self.sign_and_build(principal, body, memo)

            if verbose:
                import json
                print(f"\n[VERBOSE] Envelope being submitted:")
                print(json.dumps(envelope, indent=2, default=str))

            # Submit
            try:
                response = self.client.submit(envelope)
            except Exception as submit_error:
                if verbose:
                    import json
                    print(f"\n[VERBOSE] Submit FAILED with exception:")
                    print(f"  Error type: {type(submit_error).__name__}")
                    print(f"  Error message: {submit_error}")
                    if hasattr(submit_error, 'code'):
                        print(f"  Error code: {submit_error.code}")
                    if hasattr(submit_error, 'data'):
                        print(f"  Error data: {submit_error.data}")
                raise

            if verbose:
                import json
                print(f"\n[VERBOSE] Submit response:")
                print(json.dumps(response, indent=2, default=str))

            # Extract transaction ID and check for errors
            txid = None
            if isinstance(response, list) and response:
                first_result = response[0]
                if isinstance(first_result, dict) and first_result.get("status"):
                    txid = first_result["status"].get("txID")
                    # Check ALL results for errors
                    for res_item in response:
                        if isinstance(res_item, dict):
                            status = res_item.get("status", {})
                            msg = res_item.get("message", "")
                            if status.get("failed") or status.get("error") or "invalid signature" in msg.lower():
                                error_msg = status.get("error", {}).get("message", msg) if isinstance(status.get("error"), dict) else msg
                                if verbose:
                                    print(f"\n[VERBOSE] Transaction error: {error_msg}")
                                return SubmitResult(
                                    success=False,
                                    txid=txid,
                                    error=f"Transaction error: {error_msg}",
                                    response=response
                                )

            if not txid:
                return SubmitResult(
                    success=False,
                    error="Could not extract transaction ID from response",
                    response=response
                )

            # Wait for confirmation
            for attempt in range(max_attempts):
                try:
                    tx_result = self.client.query(txid)
                    if verbose and attempt == 0:
                        import json
                        print(f"\n[VERBOSE] First query result for {txid}:")
                        print(json.dumps(tx_result, indent=2, default=str))

                    # Handle non-dict responses (sometimes API returns a string)
                    if not isinstance(tx_result, dict):
                        if verbose and attempt < 3:
                            print(f"\n[VERBOSE] Query returned non-dict (attempt {attempt+1}): {type(tx_result).__name__}")
                        time.sleep(poll_interval)
                        continue

                    status = tx_result.get("status", {})
                    if isinstance(status, dict) and status.get("delivered", False):
                        # Check for execution error
                        if status.get("error"):
                            if verbose:
                                print(f"\n[VERBOSE] Delivered with error: {status.get('error')}")
                            return SubmitResult(
                                success=False,
                                txid=txid,
                                error=f"Transaction failed: {status.get('error')}",
                                response=tx_result
                            )
                        return SubmitResult(
                            success=True,
                            txid=txid,
                            response=tx_result
                        )
                except Exception as e:
                    if verbose and attempt < 3:
                        print(f"\n[VERBOSE] Query error (attempt {attempt+1}): {e}")

                time.sleep(poll_interval)

            # Timeout - but transaction may still succeed
            return SubmitResult(
                success=True,  # Assume success if submitted
                txid=txid,
                response=response
            )

        except Exception as e:
            if verbose:
                import traceback
                print(f"\n[VERBOSE] Exception: {e}")
                traceback.print_exc()
            return SubmitResult(
                success=False,
                error=str(e)
            )

    def add_key(self, new_keypair: Any) -> SubmitResult:
        """
        Add a key to the signer's key page.

        Args:
            new_keypair: Keypair to add

        Returns:
            SubmitResult
        """
        # Get public key hash
        if hasattr(new_keypair, 'public_key_bytes'):
            public_key_bytes = new_keypair.public_key_bytes()
        elif hasattr(new_keypair, 'public_key'):
            pk = new_keypair.public_key
            if callable(pk):
                public_key_bytes = pk().to_bytes()
            else:
                public_key_bytes = pk.to_bytes()
        else:
            raise ValueError("Keypair must have public_key or public_key_bytes")

        key_hash = hashlib.sha256(public_key_bytes).digest()

        body = TxBody.update_key_page([
            TxBody.add_key_operation(key_hash)
        ])

        return self.sign_submit_and_wait(
            principal=self.signer_url,
            body=body,
            memo="Add key to key page"
        )

    def set_threshold(self, threshold: int) -> SubmitResult:
        """
        Set the accept threshold for the signer's key page.

        Args:
            threshold: New threshold value

        Returns:
            SubmitResult
        """
        body = TxBody.update_key_page([
            TxBody.set_threshold_operation(threshold)
        ])

        return self.sign_submit_and_wait(
            principal=self.signer_url,
            body=body,
            memo=f"Set threshold to {threshold}"
        )


# =============================================================================
# KeyManager - Key page query and management
# =============================================================================

class KeyManager:
    """
    Utility for querying and managing key pages.

    Example:
        ```python
        km = KeyManager(client.v3, "acc://my-adi.acme/book/1")
        state = km.get_key_page_state()
        print(f"Version: {state.version}, Keys: {state.key_count}")
        ```
    """

    def __init__(self, client: AccumulateV3Client, key_page_url: str):
        """
        Initialize KeyManager.

        Args:
            client: V3 API client
            key_page_url: Key page URL to manage
        """
        self.client = client
        self.key_page_url = key_page_url

    def get_key_page_state(self) -> KeyPageInfo:
        """
        Get current key page state.

        Returns:
            KeyPageInfo with current state
        """
        result = self.client.query(self.key_page_url)

        account = result.get("account", {})
        keys = account.get("keys", [])

        return KeyPageInfo(
            url=account.get("url", self.key_page_url),
            version=account.get("version", 1),
            credits=account.get("creditBalance", 0),
            threshold=account.get("acceptThreshold", 1),
            key_count=len(keys),
            keys=[k.get("publicKeyHash", "") for k in keys if isinstance(k, dict)]
        )


# =============================================================================
# QuickStart - Ultra-simple API
# =============================================================================

class QuickStart:
    """
    Ultra-simple API for rapid Accumulate development.

    QuickStart reduces hundreds of lines of boilerplate to just a few
    lines per operation, matching the Dart SDK's simplicity.

    Example:
        ```python
        # Connect to devnet
        acc = QuickStart.devnet()

        # Create and fund a wallet
        wallet = acc.create_wallet()
        acc.fund_wallet(wallet)

        # Set up an ADI
        adi = acc.setup_adi(wallet, "my-adi")

        # Buy credits
        acc.buy_credits_for_adi(wallet, adi, 500)

        # Create accounts
        acc.create_token_account(adi, "tokens")
        acc.create_data_account(adi, "mydata")

        # Write data
        acc.write_data(adi, "mydata", ["Hello", "World"])
        ```
    """

    def __init__(
        self,
        v2_endpoint: str = "http://127.0.0.1:26660/v2",
        v3_endpoint: str = "http://127.0.0.1:26660/v3"
    ):
        """
        Initialize QuickStart with endpoints.

        Args:
            v2_endpoint: V2 API endpoint
            v3_endpoint: V3 API endpoint
        """
        from .facade import Accumulate

        # Extract base endpoint
        base = v3_endpoint.replace("/v3", "").replace("/v2", "")
        self.client = Accumulate(base)
        self._v2_endpoint = v2_endpoint
        self._v3_endpoint = v3_endpoint

    @classmethod
    def devnet(cls, host: str = "127.0.0.1", port: int = 26660) -> QuickStart:
        """Connect to local DevNet."""
        return cls(
            v2_endpoint=f"http://{host}:{port}/v2",
            v3_endpoint=f"http://{host}:{port}/v3"
        )

    @classmethod
    def kermit(cls) -> QuickStart:
        """Connect to Kermit public testnet."""
        return cls(
            v2_endpoint="https://kermit.accumulatenetwork.io/v2",
            v3_endpoint="https://kermit.accumulatenetwork.io/v3"
        )

    @classmethod
    def testnet(cls) -> QuickStart:
        """Connect to Accumulate testnet."""
        return cls(
            v2_endpoint="https://testnet.accumulatenetwork.io/v2",
            v3_endpoint="https://testnet.accumulatenetwork.io/v3"
        )

    def close(self) -> None:
        """Close the client connection."""
        self.client.close()

    def create_wallet(self) -> Wallet:
        """
        Create a new wallet with lite accounts.

        Returns:
            Wallet with keypair and derived URLs
        """
        from .crypto.ed25519 import Ed25519KeyPair

        # Generate keypair
        keypair = Ed25519KeyPair.generate()
        public_key_bytes = keypair.public_key_bytes()
        public_key_hash = hashlib.sha256(public_key_bytes).digest()

        # Derive lite URLs (with proper checksum)
        lite_identity = keypair.derive_lite_identity_url()
        lite_token_account = keypair.derive_lite_token_account_url("ACME")

        return Wallet(
            keypair=keypair,
            lite_identity=lite_identity,
            lite_token_account=lite_token_account,
            public_key_hash=public_key_hash.hex()
        )

    def fund_wallet(
        self,
        wallet: Wallet,
        times: int = 5,
        wait_seconds: int = 15
    ) -> None:
        """
        Fund a wallet from the faucet.

        Args:
            wallet: Wallet to fund
            times: Number of faucet requests
            wait_seconds: Seconds to wait after funding
        """
        import requests

        print(f"Funding wallet from faucet ({times} times)...")

        for i in range(times):
            try:
                response = requests.post(
                    self._v2_endpoint,
                    json={
                        "jsonrpc": "2.0",
                        "method": "faucet",
                        "params": {
                            "url": wallet.lite_token_account
                        },
                        "id": i + 1
                    },
                    timeout=30
                )
                result = response.json()
                txid = result.get("result", {}).get("txid", "submitted")
                print(f"  Faucet {i+1}/{times}: {txid[:40] if len(str(txid)) > 40 else txid}...")
                time.sleep(2)
            except Exception as e:
                print(f"  Faucet {i+1}/{times} failed: {e}")

        if wait_seconds > 0:
            print(f"Waiting {wait_seconds}s for transactions to process...")
            time.sleep(wait_seconds)

    def get_balance(self, wallet: Wallet) -> int:
        """
        Get wallet ACME balance.

        Args:
            wallet: Wallet to check

        Returns:
            Balance in smallest units
        """
        try:
            result = self.client.v3.query(wallet.lite_token_account)
            balance = result.get("account", {}).get("balance", "0")
            return int(balance)
        except Exception:
            return 0

    def get_oracle_price(self) -> int:
        """Get current oracle price."""
        from . import NetworkStatusOptions
        result = self.client.v3.network_status(NetworkStatusOptions(partition="directory"))
        return result.get("oracle", {}).get("price", 500000)

    def setup_adi(self, wallet: Wallet, adi_name: str) -> ADI:
        """
        Create a complete ADI with key book and page.

        This is a high-level operation that:
        1. Adds credits to the lite identity
        2. Creates the ADI with key book
        3. Returns the ADI info

        Args:
            wallet: Funded wallet to use
            adi_name: ADI name (without .acme suffix)

        Returns:
            ADI object with all URLs
        """
        from .crypto.ed25519 import Ed25519KeyPair

        # Generate ADI keypair
        adi_keypair = Ed25519KeyPair.generate()
        adi_public_key = adi_keypair.public_key_bytes()
        adi_key_hash = hashlib.sha256(adi_public_key).digest()

        adi_url = f"acc://{adi_name}.acme"
        book_url = f"{adi_url}/book"
        key_page_url = f"{book_url}/1"

        # Get oracle price and add credits to lite identity
        oracle = self.get_oracle_price()
        credits = 1000
        amount = (credits * 10000000000) // oracle

        print(f"Adding credits to lite identity...")

        # Create signer for lite identity
        signer = SmartSigner(self.client.v3, wallet.keypair, wallet.lite_identity)

        # Add credits
        result = signer.sign_submit_and_wait(
            principal=wallet.lite_token_account,
            body=TxBody.add_credits(wallet.lite_identity, str(amount), oracle),
            memo="Add credits for ADI creation"
        )

        if not result.success:
            print(f"Warning: Add credits may have failed: {result.error}")

        time.sleep(5)

        # Create identity
        print(f"Creating ADI: {adi_url}")
        result = signer.sign_submit_and_wait(
            principal=wallet.lite_token_account,
            body=TxBody.create_identity(adi_url, book_url, adi_key_hash.hex()),
            memo=f"Create ADI: {adi_name}"
        )

        if result.success:
            print(f"  ADI created: {result.txid}")

        time.sleep(5)

        return ADI(
            url=adi_url,
            key_book_url=book_url,
            key_page_url=key_page_url,
            keypair=adi_keypair,
            public_key_hash=adi_key_hash.hex()
        )

    def buy_credits_for_adi(
        self,
        wallet: Wallet,
        adi: ADI,
        credits: int = 500
    ) -> None:
        """
        Buy credits for an ADI's key page.

        Args:
            wallet: Funded wallet
            adi: ADI to fund
            credits: Number of credits to buy
        """
        oracle = self.get_oracle_price()
        amount = (credits * 10000000000) // oracle

        print(f"Buying {credits} credits for ADI key page...")

        signer = SmartSigner(self.client.v3, wallet.keypair, wallet.lite_identity)
        result = signer.sign_submit_and_wait(
            principal=wallet.lite_token_account,
            body=TxBody.add_credits(adi.key_page_url, str(amount), oracle),
            memo=f"Buy {credits} credits for ADI"
        )

        if result.success:
            print(f"  Credits purchased: {result.txid}")

    def get_key_page_info(self, key_page_url: str) -> Optional[KeyPageInfo]:
        """
        Get key page information.

        Args:
            key_page_url: Key page URL

        Returns:
            KeyPageInfo or None if not found
        """
        try:
            km = KeyManager(self.client.v3, key_page_url)
            return km.get_key_page_state()
        except Exception:
            return None

    def create_token_account(self, adi: ADI, account_name: str) -> None:
        """
        Create a token account under an ADI.

        Args:
            adi: ADI to create account under
            account_name: Account name
        """
        account_url = f"{adi.url}/{account_name}"
        print(f"Creating token account: {account_url}")

        signer = SmartSigner(self.client.v3, adi.keypair, adi.key_page_url)
        result = signer.sign_submit_and_wait(
            principal=adi.url,
            body=TxBody.create_token_account(account_url),
            memo=f"Create token account: {account_name}"
        )

        if result.success:
            print(f"  Token account created: {result.txid}")

    def create_data_account(self, adi: ADI, account_name: str) -> None:
        """
        Create a data account under an ADI.

        Args:
            adi: ADI to create account under
            account_name: Account name
        """
        account_url = f"{adi.url}/{account_name}"
        print(f"Creating data account: {account_url}")

        signer = SmartSigner(self.client.v3, adi.keypair, adi.key_page_url)
        result = signer.sign_submit_and_wait(
            principal=adi.url,
            body=TxBody.create_data_account(account_url),
            memo=f"Create data account: {account_name}"
        )

        if result.success:
            print(f"  Data account created: {result.txid}")

    def write_data(self, adi: ADI, account_name: str, entries: List[str]) -> None:
        """
        Write data entries to a data account.

        Args:
            adi: ADI containing the data account
            account_name: Data account name
            entries: List of string entries to write
        """
        account_url = f"{adi.url}/{account_name}"
        print(f"Writing {len(entries)} entries to {account_url}")

        signer = SmartSigner(self.client.v3, adi.keypair, adi.key_page_url)
        result = signer.sign_submit_and_wait(
            principal=account_url,
            body=TxBody.write_data_strings(entries),
            memo="Write data"
        )

        if result.success:
            print(f"  Data written: {result.txid}")

    def add_key_to_adi(self, adi: ADI, new_keypair: Any) -> None:
        """
        Add a key to an ADI's key page.

        Args:
            adi: ADI to modify
            new_keypair: Keypair to add
        """
        print(f"Adding key to {adi.key_page_url}")

        signer = SmartSigner(self.client.v3, adi.keypair, adi.key_page_url)
        result = signer.add_key(new_keypair)

        if result.success:
            print(f"  Key added: {result.txid}")

    def set_multisig_threshold(self, adi: ADI, threshold: int) -> None:
        """
        Set multi-sig threshold for an ADI.

        Args:
            adi: ADI to modify
            threshold: New threshold value
        """
        print(f"Setting threshold to {threshold} for {adi.key_page_url}")

        signer = SmartSigner(self.client.v3, adi.keypair, adi.key_page_url)
        result = signer.set_threshold(threshold)

        if result.success:
            print(f"  Threshold set: {result.txid}")


# =============================================================================
# Exports
# =============================================================================

__all__ = [
    # Data classes
    "SubmitResult",
    "Wallet",
    "ADI",
    "KeyPageInfo",
    # Main classes
    "TxBody",
    "SmartSigner",
    "KeyManager",
    "QuickStart",
]
