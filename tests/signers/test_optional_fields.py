"""
Test optional fields support across all signature implementations.

Tests that all signature types properly support memo, data, vote, and
transactionHash optional fields according to the Accumulate protocol.
"""

import pytest
import hashlib
import sys
from pathlib import Path

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))
from helpers import mk_ed25519_keypair, mk_identity_url

from accumulate_client.enums import SignatureType, VoteType
from accumulate_client.crypto.secp256k1 import Secp256k1PrivateKey
from accumulate_client.signers.ed25519 import Ed25519Signer
from accumulate_client.signers.btc import BTCSigner, BTCLegacySigner
from accumulate_client.signers.eth import ETHSigner, TypedDataSigner
from accumulate_client.signers.rcd1 import RCD1Signer
from accumulate_client.signers.rsa import RSASigner, generate_rsa_keypair, has_rsa_support
from accumulate_client.signers.ecdsa_sha256 import ECDSASigner, generate_ecdsa_keypair, has_ecdsa_support
from accumulate_client.signers.delegated import DelegatedSigner


# Test data
SAMPLE_MEMO = "Test memo for signature"
SAMPLE_DATA = b"Binary test data for signature"
SAMPLE_VOTE = VoteType.ACCEPT


def test_ed25519_optional_fields():
    """Test ED25519 signature with optional fields."""
    private_key, _ = mk_ed25519_keypair(seed=12345)
    signer = Ed25519Signer(private_key, mk_identity_url("test.acme"))

    digest = hashlib.sha256(b"test message").digest()

    # Test with all optional fields
    signature = signer.to_accumulate_signature(
        digest,
        memo=SAMPLE_MEMO,
        data=SAMPLE_DATA,
        vote=SAMPLE_VOTE
    )

    # Verify optional fields are included
    assert 'memo' in signature
    assert 'data' in signature
    assert 'vote' in signature
    assert 'transactionHash' in signature

    assert signature['memo'] == SAMPLE_MEMO
    assert signature['data'] == SAMPLE_DATA.hex()
    assert signature['vote'] == SAMPLE_VOTE
    assert signature['transactionHash'] == digest.hex()


def test_btc_optional_fields():
    """Test BTC signature with optional fields."""
    seed = b'test_btc_optional_fields'[:32].ljust(32, b'\x00')
    private_key = Secp256k1PrivateKey(seed)
    signer = BTCSigner(private_key, mk_identity_url("test.acme"))

    digest = hashlib.sha256(b"test message").digest()

    # Test with all optional fields
    signature = signer.to_accumulate_signature(
        digest,
        memo=SAMPLE_MEMO,
        data=SAMPLE_DATA,
        vote=SAMPLE_VOTE
    )

    # Verify optional fields are included
    assert 'memo' in signature
    assert 'data' in signature
    assert 'vote' in signature
    assert 'transactionHash' in signature

    assert signature['memo'] == SAMPLE_MEMO
    assert signature['data'] == SAMPLE_DATA.hex()
    assert signature['vote'] == SAMPLE_VOTE
    assert signature['transactionHash'] == digest.hex()


def test_eth_optional_fields():
    """Test ETH signature with optional fields."""
    seed = b'test_eth_optional_fields'[:32].ljust(32, b'\x00')
    private_key = Secp256k1PrivateKey(seed)
    signer = ETHSigner(private_key, mk_identity_url("test.acme"))

    digest = hashlib.sha256(b"test message").digest()

    # Test with all optional fields
    signature = signer.to_accumulate_signature(
        digest,
        memo=SAMPLE_MEMO,
        data=SAMPLE_DATA,
        vote=SAMPLE_VOTE
    )

    # Verify optional fields are included
    assert 'memo' in signature
    assert 'data' in signature
    assert 'vote' in signature
    assert 'transactionHash' in signature

    assert signature['memo'] == SAMPLE_MEMO
    assert signature['data'] == SAMPLE_DATA.hex()
    assert signature['vote'] == SAMPLE_VOTE
    assert signature['transactionHash'] == digest.hex()


def test_typeddata_optional_fields():
    """Test TypedData signature with optional fields (inherits from ETH)."""
    seed = b'test_typeddata_optional'[:32].ljust(32, b'\x00')
    private_key = Secp256k1PrivateKey(seed)
    signer = TypedDataSigner(private_key, mk_identity_url("test.acme"))

    digest = hashlib.sha256(b"test message").digest()

    # Test with all optional fields
    signature = signer.to_accumulate_signature(
        digest,
        memo=SAMPLE_MEMO,
        data=SAMPLE_DATA,
        vote=SAMPLE_VOTE
    )

    # Verify optional fields are included
    assert 'memo' in signature
    assert 'data' in signature
    assert 'vote' in signature
    assert 'transactionHash' in signature

    assert signature['memo'] == SAMPLE_MEMO
    assert signature['data'] == SAMPLE_DATA.hex()
    assert signature['vote'] == SAMPLE_VOTE
    assert signature['transactionHash'] == digest.hex()


def test_rcd1_optional_fields():
    """Test RCD1 signature with optional fields."""
    private_key, _ = mk_ed25519_keypair(seed=54321)
    signer = RCD1Signer(private_key, mk_identity_url("test.acme"))

    digest = hashlib.sha256(b"test message").digest()

    # Test with all optional fields
    signature = signer.to_accumulate_signature(
        digest,
        memo=SAMPLE_MEMO,
        data=SAMPLE_DATA,
        vote=SAMPLE_VOTE
    )

    # Verify optional fields are included
    assert 'memo' in signature
    assert 'data' in signature
    assert 'vote' in signature
    assert 'transactionHash' in signature

    assert signature['memo'] == SAMPLE_MEMO
    assert signature['data'] == SAMPLE_DATA.hex()
    assert signature['vote'] == SAMPLE_VOTE
    assert signature['transactionHash'] == digest.hex()


@pytest.mark.skipif(not has_rsa_support(), reason="RSA support not available")
def test_rsa_optional_fields():
    """Test RSA signature with optional fields."""
    private_key, _ = generate_rsa_keypair(key_size=2048)
    signer = RSASigner(private_key, mk_identity_url("test.acme"))

    digest = hashlib.sha256(b"test message").digest()

    # Test with all optional fields
    signature = signer.to_accumulate_signature(
        digest,
        memo=SAMPLE_MEMO,
        data=SAMPLE_DATA,
        vote=SAMPLE_VOTE
    )

    # Verify optional fields are included
    assert 'memo' in signature
    assert 'data' in signature
    assert 'vote' in signature
    assert 'transactionHash' in signature

    assert signature['memo'] == SAMPLE_MEMO
    assert signature['data'] == SAMPLE_DATA.hex()
    assert signature['vote'] == SAMPLE_VOTE
    assert signature['transactionHash'] == digest.hex()


@pytest.mark.skipif(not has_ecdsa_support(), reason="ECDSA support not available")
def test_ecdsa_optional_fields():
    """Test ECDSA signature with optional fields."""
    private_key, _ = generate_ecdsa_keypair(curve_name='P-256')
    signer = ECDSASigner(private_key, mk_identity_url("test.acme"))

    digest = hashlib.sha256(b"test message").digest()

    # Test with all optional fields
    signature = signer.to_accumulate_signature(
        digest,
        memo=SAMPLE_MEMO,
        data=SAMPLE_DATA,
        vote=SAMPLE_VOTE
    )

    # Verify optional fields are included
    assert 'memo' in signature
    assert 'data' in signature
    assert 'vote' in signature
    assert 'transactionHash' in signature

    assert signature['memo'] == SAMPLE_MEMO
    assert signature['data'] == SAMPLE_DATA.hex()
    assert signature['vote'] == SAMPLE_VOTE
    assert signature['transactionHash'] == digest.hex()


def test_delegated_optional_fields():
    """Test delegated signature with optional fields."""
    private_key, _ = mk_ed25519_keypair(seed=99999)
    base_signer = Ed25519Signer(private_key, mk_identity_url("employee.acme"))
    delegated_signer = DelegatedSigner(base_signer, mk_identity_url("manager.acme"))

    digest = hashlib.sha256(b"test message").digest()

    # Test with all optional fields
    signature = delegated_signer.to_accumulate_signature(
        digest,
        memo=SAMPLE_MEMO,
        data=SAMPLE_DATA,
        vote=SAMPLE_VOTE
    )

    # Verify delegated signature structure
    assert signature['type'] == 'delegated'
    assert 'signature' in signature

    # Verify optional fields are passed to wrapped signature
    wrapped_sig = signature['signature']
    assert 'memo' in wrapped_sig
    assert 'data' in wrapped_sig
    assert 'vote' in wrapped_sig
    assert 'transactionHash' in wrapped_sig

    assert wrapped_sig['memo'] == SAMPLE_MEMO
    assert wrapped_sig['data'] == SAMPLE_DATA.hex()
    assert wrapped_sig['vote'] == SAMPLE_VOTE
    assert wrapped_sig['transactionHash'] == digest.hex()


def test_optional_fields_default_values():
    """Test default values when optional fields are not provided."""
    private_key, _ = mk_ed25519_keypair(seed=11111)
    signer = Ed25519Signer(private_key, mk_identity_url("test.acme"))

    digest = hashlib.sha256(b"test message").digest()

    # Test without optional fields
    signature = signer.to_accumulate_signature(digest)

    # Should have defaults for vote and transactionHash but not memo/data
    assert 'vote' in signature
    assert 'transactionHash' in signature
    assert 'memo' not in signature
    assert 'data' not in signature

    assert signature['vote'] == VoteType.ACCEPT  # Default vote
    assert signature['transactionHash'] == digest.hex()


def test_data_field_encoding():
    """Test that data field is properly encoded as hex."""
    private_key, _ = mk_ed25519_keypair(seed=22222)
    signer = Ed25519Signer(private_key, mk_identity_url("test.acme"))

    digest = hashlib.sha256(b"test message").digest()

    # Test with bytes data
    bytes_data = b"binary test data"
    signature1 = signer.to_accumulate_signature(digest, data=bytes_data)
    assert signature1['data'] == bytes_data.hex()

    # Test with string data (should pass through)
    string_data = "string test data"
    signature2 = signer.to_accumulate_signature(digest, data=string_data)
    assert signature2['data'] == string_data


def test_vote_type_values():
    """Test different vote type values."""
    private_key, _ = mk_ed25519_keypair(seed=33333)
    signer = Ed25519Signer(private_key, mk_identity_url("test.acme"))

    digest = hashlib.sha256(b"test message").digest()

    # Test different vote types
    vote_types = [VoteType.ACCEPT, VoteType.REJECT, VoteType.ABSTAIN]

    for vote_type in vote_types:
        signature = signer.to_accumulate_signature(digest, vote=vote_type)
        assert signature['vote'] == vote_type


if __name__ == "__main__":
    pytest.main([__file__, "-v"])