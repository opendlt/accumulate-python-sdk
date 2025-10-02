"""
Test specific delegation functionality for Accumulate protocol.

Tests delegation chains, nested delegations, and delegation validation.
"""

import pytest
import hashlib
import sys
from pathlib import Path

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))
from helpers import mk_ed25519_keypair, mk_identity_url

from accumulate_client.enums import SignatureType
from accumulate_client.signers.ed25519 import Ed25519Signer
from accumulate_client.signers.btc import BTCSigner
from accumulate_client.signers.delegated import (
    DelegatedSigner,
    DelegatedVerifier,
    create_delegation_chain,
    validate_delegation_signature_structure
)
from accumulate_client.crypto.secp256k1 import Secp256k1PrivateKey


def test_basic_delegation():
    """Test basic delegation functionality."""
    # Create base signer
    private_key, _ = mk_ed25519_keypair(seed=12345)
    signer_url = mk_identity_url("employee.acme")
    base_signer = Ed25519Signer(private_key, signer_url)

    # Create delegator
    delegator_url = mk_identity_url("manager.acme")
    delegated_signer = DelegatedSigner(base_signer, delegator_url)

    # Test properties
    assert delegated_signer.get_signature_type() == SignatureType.DELEGATED
    assert delegated_signer.get_signer_url() == signer_url
    assert delegated_signer.get_delegator() == delegator_url
    assert delegated_signer.get_public_key() == base_signer.get_public_key()
    assert delegated_signer.can_initiate() == True

    # Test signing
    message = b"test delegation message"
    digest = hashlib.sha256(message).digest()

    # Both signers should produce the same raw signature
    base_signature = base_signer.sign(digest)
    delegated_signature = delegated_signer.sign(digest)
    assert base_signature == delegated_signature

    # Test verification
    assert delegated_signer.verify(delegated_signature, digest)
    assert base_signer.verify(base_signature, digest)


def test_delegation_signature_structure():
    """Test delegated signature object structure."""
    private_key, _ = mk_ed25519_keypair(seed=54321)
    signer_url = mk_identity_url("alice.acme")
    base_signer = Ed25519Signer(private_key, signer_url)

    delegator_url = mk_identity_url("department.acme")
    delegated_signer = DelegatedSigner(base_signer, delegator_url)

    # Create signature object
    digest = hashlib.sha256(b"test message").digest()
    signature = delegated_signer.to_accumulate_signature(digest)

    # Verify delegated signature structure
    assert signature['type'] == 'delegated'
    assert signature['delegator'] == str(delegator_url)
    assert 'signature' in signature

    # Verify wrapped signature structure
    wrapped_sig = signature['signature']
    assert wrapped_sig['type'] == SignatureType.ED25519
    assert 'publicKey' in wrapped_sig
    assert 'signature' in wrapped_sig
    assert wrapped_sig['signer']['url'] == str(signer_url)

    # Test structure validation
    assert validate_delegation_signature_structure(signature)


def test_nested_delegation():
    """Test multiple levels of delegation (delegation chains)."""
    # Create base signer
    private_key, _ = mk_ed25519_keypair(seed=99999)
    base_url = mk_identity_url("employee.acme")
    base_signer = Ed25519Signer(private_key, base_url)

    # Create delegation chain: employee -> team_lead -> manager -> director
    delegators = [
        mk_identity_url("team_lead.acme"),
        mk_identity_url("manager.acme"),
        mk_identity_url("director.acme")
    ]

    chained_signer = create_delegation_chain(base_signer, delegators)

    # Test delegation properties
    assert chained_signer.get_delegation_depth() == 3
    assert chained_signer.validate_delegation_depth()

    # Test delegation chain
    chain = chained_signer.get_nested_delegation_chain()
    expected_chain = [
        mk_identity_url("director.acme"),    # outermost
        mk_identity_url("manager.acme"),
        mk_identity_url("team_lead.acme")    # innermost delegation
    ]
    assert chain == expected_chain

    # Test final signer
    assert chained_signer.get_final_signer() == base_signer

    # Test signing still works
    digest = hashlib.sha256(b"nested delegation test").digest()
    signature = chained_signer.sign(digest)
    assert chained_signer.verify(signature, digest)


def test_delegation_with_different_base_signers():
    """Test delegation works with different base signature types."""
    digest = hashlib.sha256(b"multi-type delegation test").digest()

    # Test with BTC signer
    btc_seed = b'test_btc_delegation_seed_value'[:32].ljust(32, b'\x00')
    btc_private_key = Secp256k1PrivateKey(btc_seed)
    btc_signer_url = mk_identity_url("btc.acme")
    btc_base_signer = BTCSigner(btc_private_key, btc_signer_url)

    btc_delegator = mk_identity_url("btc_manager.acme")
    btc_delegated = DelegatedSigner(btc_base_signer, btc_delegator)

    # Test BTC delegation
    assert btc_delegated.get_signature_type() == SignatureType.DELEGATED
    btc_signature = btc_delegated.to_accumulate_signature(digest)
    assert btc_signature['type'] == 'delegated'
    assert btc_signature['signature']['type'] == SignatureType.BTC
    assert btc_delegated.sign(digest) == btc_base_signer.sign(digest)


def test_delegation_chain_depth_limit():
    """Test delegation chain depth validation."""
    private_key, _ = mk_ed25519_keypair(seed=77777)
    base_signer = Ed25519Signer(private_key, mk_identity_url("base.acme"))

    # Test maximum valid depth (5 levels)
    max_delegators = [mk_identity_url(f"level{i}.acme") for i in range(1, 6)]
    max_chain = create_delegation_chain(base_signer, max_delegators)
    assert max_chain.get_delegation_depth() == 5
    assert max_chain.validate_delegation_depth()

    # Test exceeding maximum depth should raise error
    too_many_delegators = [mk_identity_url(f"level{i}.acme") for i in range(1, 7)]
    with pytest.raises(Exception):  # Should raise SignerError
        create_delegation_chain(base_signer, too_many_delegators)


def test_delegation_verifier():
    """Test delegated signature verification."""
    private_key, _ = mk_ed25519_keypair(seed=88888)
    signer_url = mk_identity_url("signer.acme")
    base_signer = Ed25519Signer(private_key, signer_url)

    delegator_url = mk_identity_url("delegator.acme")
    delegated_signer = DelegatedSigner(base_signer, delegator_url)

    # Create signature
    digest = hashlib.sha256(b"verifier test").digest()
    signature_obj = delegated_signer.to_accumulate_signature(digest)

    # Test verifier
    verifier = DelegatedVerifier(delegator_url)
    assert verifier.signature_type() == SignatureType.DELEGATED
    assert verifier.verify_delegated_signature(digest, signature_obj)

    # Test with wrong delegator
    wrong_verifier = DelegatedVerifier(mk_identity_url("wrong.acme"))
    assert not wrong_verifier.verify_delegated_signature(digest, signature_obj)

    # Test with malformed signature
    bad_signature = {"type": "delegated", "delegator": "invalid"}
    assert not verifier.verify_delegated_signature(digest, bad_signature)


def test_delegation_metadata():
    """Test delegated signature metadata."""
    private_key, _ = mk_ed25519_keypair(seed=66666)
    base_signer = Ed25519Signer(private_key, mk_identity_url("base.acme"))
    delegated_signer = DelegatedSigner(base_signer, mk_identity_url("delegator.acme"))

    metadata = delegated_signer.metadata()

    assert metadata['type'] == 'delegated'
    assert metadata['delegator'] == 'acc://delegator.acme'
    assert 'wrappedSignature' in metadata
    assert metadata['wrappedSignature']['type'] == 'ED25519'


if __name__ == "__main__":
    pytest.main([__file__, "-v"])