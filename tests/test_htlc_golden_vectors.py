"""Byte-for-byte conformance of the binary encoders against Go-generated vectors.

The vectors in ``golden/htlc_vectors_1_4_6_7.json`` were produced by marshaling
Go ``protocol`` types from Accumulate 1.4.6.7 (commit e1d1db9). Each entry holds
the JSON form Go emits, the exact binary, and (for full transactions) the
transaction hash.

If one of these fails, the SDK's marshaling disagrees with the network: that is
a consensus-visible bug, not a fixture to update.
"""
import hashlib
import json
from pathlib import Path

import pytest

from accumulate_client.convenience import (
    _encode_hash_lock_options,
    _encode_tx_body,
    _encode_tx_header_from_json,
)

VECTORS = {
    v["name"]: v
    for v in json.loads(
        (Path(__file__).parent / "golden" / "htlc_vectors_1_4_6_7.json").read_text()
    )
}


def _names(prefix):
    return sorted(n for n in VECTORS if n.startswith(prefix))


def _sha256(b: bytes) -> bytes:
    return hashlib.sha256(b).digest()


@pytest.mark.parametrize("name", _names("header_"))
def test_header_binary_matches_go(name):
    v = VECTORS[name]
    hdr = v["json"]
    got = _encode_tx_header_from_json(hdr, bytes.fromhex(hdr["initiator"]))
    assert got.hex() == v["binaryHex"]


@pytest.mark.parametrize("name", _names("hashlockoptions_"))
def test_hash_lock_options_binary_matches_go(name):
    v = VECTORS[name]
    assert _encode_hash_lock_options(v["json"]).hex() == v["binaryHex"]


@pytest.mark.parametrize("name", _names("tx_"))
def test_transaction_hash_matches_go(name):
    v = VECTORS[name]
    hdr, body = v["json"]["header"], v["json"]["body"]
    header_bin = _encode_tx_header_from_json(hdr, bytes.fromhex(hdr["initiator"]))
    body_bin = _encode_tx_body(body)
    # Go's Transaction.MarshalBinary is header+body; check the hash, which is what is signed.
    tx_hash = _sha256(_sha256(header_bin) + _sha256(body_bin))
    assert tx_hash.hex() == v["hashHex"]


def test_transaction_type_codes():
    from accumulate_client.enums import TransactionType

    assert TransactionType.RELEASELOCKEDOPERATION == 0x18
    assert TransactionType.SYNTHETICLOCKEDDEPOSIT == 0x37


def test_plain_header_unchanged_without_new_fields():
    """Headers that don't use field 5-8 must encode as before the new fields existed."""
    v = VECTORS["header_plain"]
    hdr = v["json"]
    assert _encode_tx_header_from_json(hdr, bytes.fromhex(hdr["initiator"])).hex() == v["binaryHex"]


def test_signed_envelope_roundtrips_hash_lock():
    """The header JSON placed in the envelope re-encodes to the bytes that were hashed/signed."""
    from datetime import datetime, timezone

    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    from accumulate_client.convenience import (
        TxBody,
        _compute_tx_hash_and_sign,
        _encode_tx_header,
    )
    from accumulate_client.tx.header import HashLockOptions

    class Kp:
        def __init__(self):
            self._k = Ed25519PrivateKey.generate()

        def public_key_bytes(self):
            from cryptography.hazmat.primitives import serialization as s

            return self._k.public_key().public_bytes(s.Encoding.Raw, s.PublicFormat.Raw)

        def sign(self, data):
            return self._k.sign(data)

    exp = datetime(2030, 1, 2, 3, 4, 5, tzinfo=timezone.utc)
    lock = HashLockOptions(hash_algorithm="sha256", hash=bytes(range(1, 33)), expiration=exp)
    body = TxBody.send_tokens_single("acc://bob.acme/tokens", "12345")
    env, _ = _compute_tx_hash_and_sign(
        Kp(), "acc://alice.acme/tokens", body, "acc://alice.acme/book/1", 1,
        timestamp=1700000000000000, hash_lock=lock,
    )
    hdr = env["transaction"][0]["header"]
    assert hdr["hashLock"] == {
        "hashAlgorithm": "sha256",
        "hash": bytes(range(1, 33)).hex(),
        "expiration": "2030-01-02T03:04:05Z",
    }
    initiator = bytes.fromhex(hdr["initiator"])
    direct = _encode_tx_header(
        "acc://alice.acme/tokens", initiator,
        hash_lock={"hashAlgorithm": 1, "hash": bytes(range(1, 33)), "expiration": exp},
    )
    assert _encode_tx_header_from_json(hdr, initiator) == direct


def test_release_locked_operation_helper():
    from accumulate_client.convenience import TxBody

    b = TxBody.release_locked_operation("acc://" + "ab" * 32 + "@alice.acme/tokens", b"secret")
    assert b == {
        "type": "releaseLockedOperation",
        "lockedTxID": "acc://" + "ab" * 32 + "@alice.acme/tokens",
        "preimage": b"secret".hex(),
    }
    assert _encode_tx_body(b).startswith(bytes([0x01, 0x18]))
