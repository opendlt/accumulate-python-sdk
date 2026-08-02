"""A 32-byte seed must mean the same thing here as in every other SDK.

`from_seed` used to SHA-256 its input unconditionally, so the same 32 bytes
produced a different identity in Python than in Rust, Dart, JavaScript and C#.
Anyone handed a private key got a key that was not theirs, and the mismatch only
surfaced when the node rejected the signature with "key does not belong to
signer". These tests pin the corrected behaviour.
"""
from accumulate_client.crypto.ed25519 import Ed25519KeyPair, Ed25519PrivateKey

# Derived from the all-0xAA seed by Rust's AccumulateClient::keypair_from_seed.
# Any divergence here means the fleet no longer agrees on identity.
RAW_SEED = bytes.fromhex("aa" * 32)
CROSS_SDK_PUBLIC_KEY = "e734ea6c2b6257de72355e472aa05a4c487e6b463c029ed306df2f01b5636b58"


def test_32_byte_seed_is_used_raw():
    kp = Ed25519KeyPair.from_seed(RAW_SEED)
    assert kp.public_key.to_hex() == CROSS_SDK_PUBLIC_KEY


def test_from_seed_agrees_with_from_private_hex():
    assert (
        Ed25519KeyPair.from_seed(RAW_SEED).public_key.to_hex()
        == Ed25519KeyPair.from_private_hex("aa" * 32).public_key.to_hex()
    )


def test_private_key_from_seed_matches_from_bytes():
    assert (
        Ed25519PrivateKey.from_seed(RAW_SEED).to_bytes()
        == Ed25519PrivateKey.from_bytes(RAW_SEED).to_bytes()
    )


def test_passphrase_is_still_stretched():
    """Non-key material must still be hashed to 32 bytes."""
    kp = Ed25519KeyPair.from_seed("a passphrase, not a key")
    assert len(kp.private_key.to_bytes()) == 32
    assert kp.public_key.to_hex() != CROSS_SDK_PUBLIC_KEY


def test_short_and_long_inputs_are_stretched():
    for seed in (b"short", b"x" * 64):
        assert len(Ed25519PrivateKey.from_seed(seed).to_bytes()) == 32


def test_keypair_rejects_wrong_length_bytes():
    """The length check exists to catch a truncated key, not to be bypassed."""
    try:
        Ed25519KeyPair.from_seed(b"\x01" * 31)
    except ValueError:
        return
    raise AssertionError("expected ValueError for a 31-byte seed")
