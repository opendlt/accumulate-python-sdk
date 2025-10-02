"""
Test ED25519 and Legacy ED25519 signers for compatibility and correctness.

Verifies that both signer types work correctly and can interoperate
where the protocol allows.
"""

import pytest
import hashlib
from accumulate_client.crypto.ed25519 import Ed25519PrivateKey
from accumulate_client.signers.ed25519 import Ed25519Signer, Ed25519Verifier
from accumulate_client.signers.legacy_ed25519 import LegacyEd25519Signer, LegacyEd25519Verifier
from accumulate_client.enums import SignatureType


# Fixed test vectors for deterministic testing
TEST_SEED = b"accumulate_test_seed_for_ed25519"
TEST_DIGEST = b"test_transaction_hash_digest_32b"
assert len(TEST_DIGEST) == 32


@pytest.fixture
def deterministic_keypair():
    """Generate deterministic keypair from fixed seed."""
    # Create deterministic private key from seed
    private_key = Ed25519PrivateKey.from_seed(TEST_SEED)
    public_key = private_key.public_key()
    return private_key, public_key


@pytest.mark.unit
def test_ed25519_signer_basic(deterministic_keypair):
    """Test basic ED25519 signer functionality."""
    private_key, public_key = deterministic_keypair

    # Create signer
    signer = Ed25519Signer(private_key, "acc://test.acme/book/1")

    # Sign test digest
    signature_dict = signer.to_accumulate_signature(TEST_DIGEST)

    # Verify signature structure
    assert signature_dict['type'] == SignatureType.ED25519
    assert 'publicKey' in signature_dict
    assert 'signature' in signature_dict
    assert signature_dict['signer']['url'] == "acc://test.acme/book/1"

    # Verify signature is deterministic
    signature_dict_2 = signer.to_accumulate_signature(TEST_DIGEST)
    assert signature_dict['signature'] == signature_dict_2['signature']


@pytest.mark.unit
def test_ed25519_verifier_basic(deterministic_keypair):
    """Test basic ED25519 verifier functionality."""
    private_key, public_key = deterministic_keypair

    # Create signer and verifier
    signer = Ed25519Signer(private_key, "acc://test.acme/book/1")
    verifier = Ed25519Verifier(public_key)

    # Sign and verify
    signature_dict = signer.to_accumulate_signature(TEST_DIGEST)
    signature_bytes = bytes.fromhex(signature_dict['signature'])

    # Direct verification
    assert verifier.verify(TEST_DIGEST, signature_bytes)

    # Verification with wrong message should fail
    wrong_digest = b"wrong_transaction_hash_digest32b"
    assert not verifier.verify(wrong_digest, signature_bytes)


@pytest.mark.unit
def test_legacy_ed25519_signer_basic(deterministic_keypair):
    """Test basic Legacy ED25519 signer functionality."""
    private_key, public_key = deterministic_keypair

    # Create legacy signer
    signer = LegacyEd25519Signer(private_key, "acc://test.acme/book/1")

    # Sign test digest
    signature_dict = signer.to_accumulate_signature(TEST_DIGEST)

    # Verify signature structure
    assert signature_dict['type'] == SignatureType.LEGACYED25519
    assert 'publicKey' in signature_dict
    assert 'signature' in signature_dict
    assert signature_dict['signer']['url'] == "acc://test.acme/book/1"

    # Verify signature is deterministic
    signature_dict_2 = signer.to_accumulate_signature(TEST_DIGEST)
    assert signature_dict['signature'] == signature_dict_2['signature']


@pytest.mark.unit
def test_legacy_ed25519_verifier_basic(deterministic_keypair):
    """Test basic Legacy ED25519 verifier functionality."""
    private_key, public_key = deterministic_keypair

    # Create legacy signer and verifier
    signer = LegacyEd25519Signer(private_key, "acc://test.acme/book/1")
    verifier = LegacyEd25519Verifier(public_key)

    # Sign and verify
    signature_dict = signer.to_accumulate_signature(TEST_DIGEST)
    signature_bytes = bytes.fromhex(signature_dict['signature'])

    # Direct verification
    assert verifier.verify(TEST_DIGEST, signature_bytes)

    # Verification with wrong message should fail
    wrong_digest = b"wrong_transaction_hash_digest32b"
    assert not verifier.verify(wrong_digest, signature_bytes)


@pytest.mark.unit
def test_ed25519_signature_uniqueness(deterministic_keypair):
    """Test that different messages produce different signatures."""
    private_key, public_key = deterministic_keypair

    signer = Ed25519Signer(private_key, "acc://test.acme/book/1")

    # Sign different messages
    sig1 = signer.to_accumulate_signature(TEST_DIGEST)
    sig2 = signer.to_accumulate_signature(b"different_message_digest_32b")

    # Signatures should be different
    assert sig1['signature'] != sig2['signature']

    # But public key should be the same
    assert sig1['publicKey'] == sig2['publicKey']


@pytest.mark.unit
def test_legacy_ed25519_signature_uniqueness(deterministic_keypair):
    """Test that different messages produce different legacy signatures."""
    private_key, public_key = deterministic_keypair

    signer = LegacyEd25519Signer(private_key, "acc://test.acme/book/1")

    # Sign different messages
    sig1 = signer.to_accumulate_signature(TEST_DIGEST)
    sig2 = signer.to_accumulate_signature(b"different_message_digest_32b")

    # Signatures should be different
    assert sig1['signature'] != sig2['signature']

    # But public key should be the same
    assert sig1['publicKey'] == sig2['publicKey']


@pytest.mark.unit
def test_signature_type_differences(deterministic_keypair):
    """Test that ED25519 and Legacy ED25519 produce different signature types."""
    private_key, public_key = deterministic_keypair

    # Create both signer types
    ed25519_signer = Ed25519Signer(private_key, "acc://test.acme/book/1")
    legacy_signer = LegacyEd25519Signer(private_key, "acc://test.acme/book/1")

    # Sign same message with both
    ed25519_sig = ed25519_signer.to_accumulate_signature(TEST_DIGEST)
    legacy_sig = legacy_signer.to_accumulate_signature(TEST_DIGEST)

    # Different signature types
    assert ed25519_sig['type'] == SignatureType.ED25519
    assert legacy_sig['type'] == SignatureType.LEGACYED25519

    # Same public key (both derive from same private key)
    assert ed25519_sig['publicKey'] == legacy_sig['publicKey']


@pytest.mark.unit
def test_verifier_from_signature_dict(deterministic_keypair):
    """Test creating verifiers from signature dictionaries."""
    private_key, public_key = deterministic_keypair

    # Create signature
    signer = Ed25519Signer(private_key, "acc://test.acme/book/1")
    signature_dict = signer.to_accumulate_signature(TEST_DIGEST)

    # Create verifier from signature dict
    verifier = Ed25519Verifier.from_signature_dict(signature_dict)

    # Should be able to verify the signature
    signature_bytes = bytes.fromhex(signature_dict['signature'])
    assert verifier.verify(TEST_DIGEST, signature_bytes)


@pytest.mark.unit
def test_cross_compatibility_awareness(deterministic_keypair):
    """Test awareness of cross-compatibility rules between signer types."""
    private_key, public_key = deterministic_keypair

    # Create both signer types
    ed25519_signer = Ed25519Signer(private_key, "acc://test.acme/book/1")
    legacy_signer = LegacyEd25519Signer(private_key, "acc://test.acme/book/1")

    # Create both signatures
    ed25519_sig = ed25519_signer.to_accumulate_signature(TEST_DIGEST)
    legacy_sig = legacy_signer.to_accumulate_signature(TEST_DIGEST)

    # Different signature formats (may have different encodings)
    # Note: The actual signature bytes might differ due to different signing algorithms
    # This test documents the expected behavior rather than assuming compatibility

    assert ed25519_sig['type'] != legacy_sig['type']

    # Both should have valid signature structure
    for sig_dict in [ed25519_sig, legacy_sig]:
        assert 'publicKey' in sig_dict
        assert 'signature' in sig_dict
        assert 'signer' in sig_dict
        assert len(bytes.fromhex(sig_dict['signature'])) == 64  # ED25519 signatures are 64 bytes


@pytest.mark.unit
def test_authority_preservation():
    """Test that signer authority is preserved in signatures."""
    private_key = Ed25519PrivateKey.from_seed(TEST_SEED)

    authorities = [
        "acc://alice.acme/book/1",
        "acc://bob.acme/keys/primary",
        "acc://system.acme/admin"
    ]

    for authority in authorities:
        signer = Ed25519Signer(private_key, authority)
        signature_dict = signer.to_accumulate_signature(TEST_DIGEST)

        assert signature_dict['signer']['url'] == authority
        assert signature_dict['signer']['version'] == 1
