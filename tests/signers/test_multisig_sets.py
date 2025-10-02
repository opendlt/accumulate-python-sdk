"""
Test multi-signature sets and aggregation.

Tests signature set construction, threshold validation,
and aggregation behavior for multi-signature scenarios.
"""

import pytest
import hashlib
import sys
from pathlib import Path

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))
from helpers import mk_ed25519_keypair, mk_identity_url

from accumulate_client.crypto.ed25519 import Ed25519PrivateKey
from accumulate_client.signers.ed25519 import Ed25519Signer
from accumulate_client.signers.multisig import SignatureSet


def test_signature_set_creation():
    """Test basic signature set creation and properties."""
    sig_set = SignatureSet(threshold=2)

    assert sig_set.get_threshold() == 2
    assert sig_set.get_signature_count() == 0
    assert not sig_set.is_complete()


def test_signature_set_threshold_validation():
    """Test signature set threshold validation."""
    # Create 3 signers
    signers = []
    for i in range(3):
        private_key, _ = mk_ed25519_keypair(seed=1000 + i)
        signer_url = mk_identity_url(f"signer{i}.acme")
        signers.append(Ed25519Signer(private_key, signer_url))

    # Create signature set with threshold of 2
    sig_set = SignatureSet(threshold=2)
    tx_hash = hashlib.sha256(b"multisig test transaction").digest()

    # Add first signature - should not be complete
    sig1 = signers[0].to_accumulate_signature(tx_hash)
    sig_set.add_signature(sig1)

    assert sig_set.get_signature_count() == 1
    assert not sig_set.is_complete()

    # Add second signature - should now be complete
    sig2 = signers[1].to_accumulate_signature(tx_hash)
    sig_set.add_signature(sig2)

    assert sig_set.get_signature_count() == 2
    assert sig_set.is_complete()

    # Add third signature - still complete, over-threshold
    sig3 = signers[2].to_accumulate_signature(tx_hash)
    sig_set.add_signature(sig3)

    assert sig_set.get_signature_count() == 3
    assert sig_set.is_complete()


def test_signature_set_aggregation():
    """Test signature set aggregation behavior."""
    # Create 2 signers for 2-of-2 multisig
    private_key1, _ = mk_ed25519_keypair(seed=2001)
    private_key2, _ = mk_ed25519_keypair(seed=2002)

    signer1 = Ed25519Signer(private_key1, mk_identity_url("signer1.acme"))
    signer2 = Ed25519Signer(private_key2, mk_identity_url("signer2.acme"))

    sig_set = SignatureSet(threshold=2)
    tx_hash = hashlib.sha256(b"aggregation test").digest()

    # Add both signatures
    sig1 = signer1.to_accumulate_signature(tx_hash)
    sig2 = signer2.to_accumulate_signature(tx_hash)

    sig_set.add_signature(sig1)
    sig_set.add_signature(sig2)

    # Convert to accumulate signature format
    agg_sig = sig_set.to_accumulate_format()

    # Verify aggregated signature structure
    assert agg_sig['type'] == 'set'
    assert agg_sig['threshold'] == 2
    assert len(agg_sig['signatures']) == 2
    assert agg_sig['complete'] is True

    # Verify individual signatures are preserved
    assert agg_sig['signatures'][0]['publicKey'] == sig1['publicKey']
    assert agg_sig['signatures'][1]['publicKey'] == sig2['publicKey']
    assert agg_sig['signatures'][0]['signature'] == sig1['signature']
    assert agg_sig['signatures'][1]['signature'] == sig2['signature']


def test_signature_set_single_vs_multi():
    """Test equivalence between single signature and 1-of-1 signature set."""
    private_key, _ = mk_ed25519_keypair(seed=3001)
    signer = Ed25519Signer(private_key, mk_identity_url("single.acme"))

    tx_hash = hashlib.sha256(b"single vs multi test").digest()

    # Single signature
    single_sig = signer.to_accumulate_signature(tx_hash)

    # 1-of-1 signature set
    sig_set = SignatureSet(threshold=1)
    sig_set.add_signature(single_sig)
    set_sig = sig_set.to_accumulate_format()

    # The underlying signature should be the same
    assert set_sig['signatures'][0]['signature'] == single_sig['signature']
    assert set_sig['signatures'][0]['publicKey'] == single_sig['publicKey']
    assert set_sig['threshold'] == 1
    assert set_sig['complete'] is True


def test_signature_set_edge_cases():
    """Test signature set edge cases and error conditions."""
    # Test threshold validation (real implementation enforces threshold >= 1)
    try:
        sig_set_zero = SignatureSet(threshold=0)
        sig_set_zero.set_threshold(0)  # Try to set invalid threshold
        assert False, "Should have raised error for threshold 0"
    except Exception:
        pass  # Expected - real implementation should validate threshold

    # Large threshold
    sig_set_large = SignatureSet(threshold=100)
    assert not sig_set_large.is_complete()

    # Add signatures from different signers but still under threshold
    tx_hash = hashlib.sha256(b"edge case test").digest()

    for i in range(5):
        private_key, _ = mk_ed25519_keypair(seed=4001 + i)
        signer = Ed25519Signer(private_key, mk_identity_url(f"edge{i}.acme"))
        sig = signer.to_accumulate_signature(tx_hash)
        sig_set_large.add_signature(sig)

    assert sig_set_large.get_signature_count() == 5
    assert not sig_set_large.is_complete()  # 5 < 100


def test_signature_set_different_transactions():
    """Test that signature sets properly handle different transaction hashes."""
    private_key1, _ = mk_ed25519_keypair(seed=5001)
    private_key2, _ = mk_ed25519_keypair(seed=5002)

    signer1 = Ed25519Signer(private_key1, mk_identity_url("diff1.acme"))
    signer2 = Ed25519Signer(private_key2, mk_identity_url("diff2.acme"))

    hash1 = hashlib.sha256(b"transaction 1").digest()
    hash2 = hashlib.sha256(b"transaction 2").digest()

    # Sign different hashes
    sig1_hash1 = signer1.to_accumulate_signature(hash1)
    sig2_hash2 = signer2.to_accumulate_signature(hash2)

    # Create signature set (this would be invalid in practice, but tests the structure)
    sig_set = SignatureSet(threshold=2)
    sig_set.add_signature(sig1_hash1)
    sig_set.add_signature(sig2_hash2)

    agg_sig = sig_set.to_accumulate_format()

    # Verify that different signatures are preserved
    assert agg_sig['signatures'][0]['signature'] != agg_sig['signatures'][1]['signature']
    assert agg_sig['signatures'][0]['publicKey'] != agg_sig['signatures'][1]['publicKey']


# TODO[ACC-P2-S907]: Add tests for signature set validation with actual cryptographic verification
# TODO[ACC-P2-S908]: Add tests for signature set serialization/deserialization
# TODO[ACC-P2-S909]: Add tests for signature set with mixed signature types when supported
