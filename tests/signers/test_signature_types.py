"""
Test signature types across the Accumulate protocol.

Tests signature generation, verification, and roundtrip marshaling
for all supported signature types in the protocol.
"""

import pytest
import hashlib
import sys
from pathlib import Path

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))
from helpers import mk_ed25519_keypair, mk_identity_url

from accumulate_client.enums import SignatureType
from accumulate_client.crypto.ed25519 import Ed25519PrivateKey
from accumulate_client.crypto.secp256k1 import Secp256k1PrivateKey
from accumulate_client.signers.ed25519 import Ed25519Signer, Ed25519Verifier
from accumulate_client.signers.legacy_ed25519 import LegacyEd25519Signer, LegacyEd25519Verifier
from accumulate_client.signers.btc import BTCSigner, BTCLegacySigner, BTCVerifier, BTCLegacyVerifier
from accumulate_client.signers.eth import ETHSigner, TypedDataSigner, ETHVerifier, TypedDataVerifier
from accumulate_client.signers.rcd1 import RCD1Signer, RCD1Verifier
from accumulate_client.signers.rsa import RSASigner, RSAVerifier, generate_rsa_keypair, has_rsa_support
from accumulate_client.signers.ecdsa_sha256 import ECDSASigner, ECDSAVerifier, generate_ecdsa_keypair, has_ecdsa_support
from accumulate_client.signers.delegated import DelegatedSigner, DelegatedVerifier


# Get all signature types from enum
ALL_SIGNATURE_TYPES = [
    (name, getattr(SignatureType, name))
    for name in dir(SignatureType)
    if not name.startswith('_') and isinstance(getattr(SignatureType, name), int)
]

# Define which signature types are currently supported
SUPPORTED_TYPES = {
    'ED25519',
    'LEGACYED25519',
    'BTC',
    'BTCLEGACY',
    'ETH',
    'TYPEDDATA',
    'RCD1',
    'RSASHA256',
    'ECDSASHA256',
    'DELEGATED'
}

# Sample transaction data for signing
SAMPLE_TX_DATA = b"sample transaction data for signature testing"


@pytest.mark.parametrize("sig_name,sig_type", ALL_SIGNATURE_TYPES)
def test_signature_type_coverage(sig_name, sig_type):
    """Test that we have awareness of all signature types."""
    # Just ensure we can enumerate all types
    assert isinstance(sig_type, int)
    assert sig_name is not None

    if sig_name == 'UNKNOWN':
        assert sig_type == 0
    else:
        assert sig_type > 0


@pytest.mark.parametrize("sig_name,sig_type", [
    (name, value) for name, value in ALL_SIGNATURE_TYPES
    if name in SUPPORTED_TYPES
])
def test_supported_signature_roundtrip(sig_name, sig_type):
    """Test signature generation and verification for supported types."""
    signer_url = mk_identity_url("test.acme")

    if sig_name == 'ED25519':
        private_key, public_key = mk_ed25519_keypair(seed=12345)
        signer = Ed25519Signer(private_key, signer_url)
    elif sig_name == 'LEGACYED25519':
        private_key, public_key = mk_ed25519_keypair(seed=12345)
        signer = LegacyEd25519Signer(private_key, signer_url)
    elif sig_name == 'BTC':
        # Use secp256k1 for BTC signatures (32-byte private key)
        seed = b'test_seed_for_btc_signature_xyz'[:32].ljust(32, b'\x00')
        private_key = Secp256k1PrivateKey(seed)
        signer = BTCSigner(private_key, signer_url)
    elif sig_name == 'BTCLEGACY':
        # Use secp256k1 for BTCLegacy signatures (32-byte private key)
        seed = b'test_seed_for_btc_legacy_sig123'[:32].ljust(32, b'\x00')
        private_key = Secp256k1PrivateKey(seed)
        signer = BTCLegacySigner(private_key, signer_url)
    elif sig_name == 'ETH':
        # Use secp256k1 for ETH signatures (32-byte private key)
        seed = b'test_seed_for_eth_signature_xyz'[:32].ljust(32, b'\x00')
        private_key = Secp256k1PrivateKey(seed)
        signer = ETHSigner(private_key, signer_url)
    elif sig_name == 'TYPEDDATA':
        # Use secp256k1 for TypedData signatures (32-byte private key)
        seed = b'test_seed_for_typeddata_sig123'[:32].ljust(32, b'\x00')
        private_key = Secp256k1PrivateKey(seed)
        signer = TypedDataSigner(private_key, signer_url)
    elif sig_name == 'RCD1':
        # Use ED25519 for RCD1 signatures
        private_key, public_key = mk_ed25519_keypair(seed=54321)
        signer = RCD1Signer(private_key, signer_url)
    elif sig_name == 'RSASHA256':
        # Use RSA for RSA-SHA256 signatures
        if not has_rsa_support():
            pytest.skip("RSA support not available")
        private_key, public_key = generate_rsa_keypair(key_size=2048)
        signer = RSASigner(private_key, signer_url)
    elif sig_name == 'ECDSASHA256':
        # Use ECDSA for ECDSA-SHA256 signatures
        if not has_ecdsa_support():
            pytest.skip("ECDSA support not available")
        private_key, public_key = generate_ecdsa_keypair(curve_name='P-256')
        signer = ECDSASigner(private_key, signer_url)
    elif sig_name == 'DELEGATED':
        # Use ED25519 as base signer, then wrap with delegation
        private_key, public_key = mk_ed25519_keypair(seed=67890)
        base_signer = Ed25519Signer(private_key, signer_url)
        delegator_url = mk_identity_url("delegator.acme")
        signer = DelegatedSigner(base_signer, delegator_url)
    else:
        pytest.fail(f"No signer implementation for {sig_name}")

    # Hash sample transaction
    tx_hash = hashlib.sha256(SAMPLE_TX_DATA).digest()

    # Sign the hash
    signature = signer.to_accumulate_signature(tx_hash)

    # Verify signature structure
    assert isinstance(signature, dict)
    assert 'type' in signature
    assert 'signature' in signature

    # DELEGATED signatures have a different structure
    if sig_name != 'DELEGATED':
        assert 'publicKey' in signature
    else:
        # DELEGATED signatures have delegator and wrapped signature
        assert 'delegator' in signature
        assert isinstance(signature['signature'], dict)
        assert 'publicKey' in signature['signature']

    # Verify signature length/format expectations
    if sig_name in ('ED25519', 'LEGACYED25519'):
        # ED25519 signatures should be 64 bytes (128 hex chars)
        sig_bytes = bytes.fromhex(signature['signature'])
        assert len(sig_bytes) == 64, f"ED25519 signature should be 64 bytes, got {len(sig_bytes)}"

        # Public key should be 32 bytes (64 hex chars)
        pub_key_bytes = bytes.fromhex(signature['publicKey'])
        assert len(pub_key_bytes) == 32, f"ED25519 public key should be 32 bytes, got {len(pub_key_bytes)}"

    elif sig_name in ('BTC', 'BTCLEGACY'):
        # BTC signatures are DER-encoded and variable length (typically 70-72 bytes)
        sig_bytes = bytes.fromhex(signature['signature'])
        assert 68 <= len(sig_bytes) <= 73, f"BTC signature should be ~70-72 bytes, got {len(sig_bytes)}"

        # BTC public keys are 33 bytes (compressed) or 65 bytes (uncompressed)
        pub_key_bytes = bytes.fromhex(signature['publicKey'])
        assert len(pub_key_bytes) in (33, 65), f"BTC public key should be 33 or 65 bytes, got {len(pub_key_bytes)}"

    elif sig_name in ('ETH', 'TYPEDDATA'):
        # ETH signatures are secp256k1 based, variable length (typically 65-73 bytes)
        sig_bytes = bytes.fromhex(signature['signature'])
        assert 64 <= len(sig_bytes) <= 73, f"ETH signature should be ~65-73 bytes, got {len(sig_bytes)}"

        # ETH public keys are 33 bytes (compressed) or 65 bytes (uncompressed)
        pub_key_bytes = bytes.fromhex(signature['publicKey'])
        assert len(pub_key_bytes) in (33, 65), f"ETH public key should be 33 or 65 bytes, got {len(pub_key_bytes)}"

    elif sig_name == 'RCD1':
        # RCD1 signatures use ED25519, same as ED25519 signature
        sig_bytes = bytes.fromhex(signature['signature'])
        assert len(sig_bytes) == 64, f"RCD1 signature should be 64 bytes, got {len(sig_bytes)}"

        # RCD1 public keys are ED25519 (32 bytes)
        pub_key_bytes = bytes.fromhex(signature['publicKey'])
        assert len(pub_key_bytes) == 32, f"RCD1 public key should be 32 bytes, got {len(pub_key_bytes)}"

    elif sig_name == 'RSASHA256':
        # RSA signatures depend on key size (2048-bit = 256 bytes, 4096-bit = 512 bytes)
        sig_bytes = bytes.fromhex(signature['signature'])
        assert len(sig_bytes) >= 256, f"RSA signature should be at least 256 bytes, got {len(sig_bytes)}"

        # RSA public keys are DER encoded, variable length
        pub_key_bytes = bytes.fromhex(signature['publicKey'])
        assert len(pub_key_bytes) >= 270, f"RSA public key (DER) should be at least 270 bytes, got {len(pub_key_bytes)}"

    elif sig_name == 'ECDSASHA256':
        # ECDSA signatures are DER encoded, variable length
        sig_bytes = bytes.fromhex(signature['signature'])
        assert 8 <= len(sig_bytes) <= 73, f"ECDSA signature should be 8-73 bytes, got {len(sig_bytes)}"

        # ECDSA public keys are DER encoded, variable length
        pub_key_bytes = bytes.fromhex(signature['publicKey'])
        assert len(pub_key_bytes) >= 90, f"ECDSA public key (DER) should be at least 90 bytes, got {len(pub_key_bytes)}"

    elif sig_name == 'DELEGATED':
        # DELEGATED signatures have a different structure - they wrap other signatures
        assert 'delegator' in signature, "DELEGATED signature should have 'delegator' field"
        assert 'signature' in signature, "DELEGATED signature should have wrapped 'signature' field"

        # The wrapped signature should be a dict (another signature object)
        wrapped_sig = signature['signature']
        assert isinstance(wrapped_sig, dict), "DELEGATED wrapped signature should be a dict"
        assert 'type' in wrapped_sig, "DELEGATED wrapped signature should have 'type' field"

        # Delegator should be a valid URL
        delegator = signature['delegator']
        assert delegator.startswith('acc://'), "DELEGATED delegator should be an Accumulate URL"

    # Test basic signature verification using the raw key
    raw_signature = signer.sign(tx_hash)

    # Verify signature length based on type
    if sig_name in ('ED25519', 'LEGACYED25519', 'RCD1'):
        assert len(raw_signature) == 64, f"{sig_name} signatures should be 64 bytes, got {len(raw_signature)}"
    elif sig_name in ('BTC', 'BTCLEGACY', 'ETH', 'TYPEDDATA'):
        assert 64 <= len(raw_signature) <= 73, f"{sig_name} signatures should be ~64-73 bytes, got {len(raw_signature)}"
    elif sig_name == 'RSASHA256':
        assert len(raw_signature) >= 256, f"RSA signatures should be at least 256 bytes, got {len(raw_signature)}"
    elif sig_name == 'ECDSASHA256':
        assert 8 <= len(raw_signature) <= 73, f"ECDSA signatures should be 8-73 bytes, got {len(raw_signature)}"
    elif sig_name == 'DELEGATED':
        # DELEGATED uses the wrapped signer's signature length (ED25519 in this test = 64 bytes)
        assert len(raw_signature) == 64, f"DELEGATED (wrapping ED25519) signatures should be 64 bytes, got {len(raw_signature)}"

    # Test actual signature verification
    if sig_name == 'ED25519':
        verifier = Ed25519Verifier(public_key)
        assert verifier.verify(tx_hash, raw_signature), f"ED25519 signature verification failed"

        # Test with tampered digest (should fail)
        tampered_hash = tx_hash[:-1] + b'\x00'
        assert not verifier.verify(tampered_hash, raw_signature), f"ED25519 should reject tampered digest"

    elif sig_name == 'LEGACYED25519':
        verifier = LegacyEd25519Verifier(public_key)
        assert verifier.verify(tx_hash, raw_signature), f"LEGACYED25519 signature verification failed"

        # Test with tampered digest (should fail)
        tampered_hash = tx_hash[:-1] + b'\x00'
        assert not verifier.verify(tampered_hash, raw_signature), f"LEGACYED25519 should reject tampered digest"

    elif sig_name == 'BTC':
        public_key = signer.private_key.public_key()
        verifier = BTCVerifier(public_key)
        assert verifier.verify(tx_hash, raw_signature), f"BTC signature verification failed"

        # Test with tampered digest (should fail)
        tampered_hash = tx_hash[:-1] + b'\x00'
        assert not verifier.verify(tampered_hash, raw_signature), f"BTC should reject tampered digest"

    elif sig_name == 'BTCLEGACY':
        public_key = signer.private_key.public_key()
        verifier = BTCLegacyVerifier(public_key)
        assert verifier.verify(tx_hash, raw_signature), f"BTCLEGACY signature verification failed"

        # Test with tampered digest (should fail)
        tampered_hash = tx_hash[:-1] + b'\x00'
        assert not verifier.verify(tampered_hash, raw_signature), f"BTCLEGACY should reject tampered digest"

    elif sig_name == 'ETH':
        public_key = signer.private_key.public_key()
        verifier = ETHVerifier(public_key)
        assert verifier.verify(tx_hash, raw_signature), f"ETH signature verification failed"

        # Test with tampered digest (should fail)
        tampered_hash = tx_hash[:-1] + b'\x00'
        assert not verifier.verify(tampered_hash, raw_signature), f"ETH should reject tampered digest"

    elif sig_name == 'TYPEDDATA':
        public_key = signer.private_key.public_key()
        verifier = TypedDataVerifier(public_key)
        assert verifier.verify(tx_hash, raw_signature), f"TYPEDDATA signature verification failed"

        # Test with tampered digest (should fail)
        tampered_hash = tx_hash[:-1] + b'\x00'
        assert not verifier.verify(tampered_hash, raw_signature), f"TYPEDDATA should reject tampered digest"

    elif sig_name == 'RCD1':
        verifier = RCD1Verifier(public_key)
        assert verifier.verify(tx_hash, raw_signature), f"RCD1 signature verification failed"

        # Test with tampered digest (should fail)
        tampered_hash = tx_hash[:-1] + b'\x00'
        assert not verifier.verify(tampered_hash, raw_signature), f"RCD1 should reject tampered digest"

    elif sig_name == 'RSASHA256':
        verifier = RSAVerifier(public_key)
        assert verifier.verify(tx_hash, raw_signature), f"RSASHA256 signature verification failed"

        # Test with tampered digest (should fail)
        tampered_hash = tx_hash[:-1] + b'\x00'
        assert not verifier.verify(tampered_hash, raw_signature), f"RSASHA256 should reject tampered digest"

    elif sig_name == 'ECDSASHA256':
        verifier = ECDSAVerifier(public_key)
        assert verifier.verify(tx_hash, raw_signature), f"ECDSASHA256 signature verification failed"

        # Test with tampered digest (should fail)
        tampered_hash = tx_hash[:-1] + b'\x00'
        assert not verifier.verify(tampered_hash, raw_signature), f"ECDSASHA256 should reject tampered digest"


@pytest.mark.parametrize("sig_name,sig_type", [
    (name, value) for name, value in ALL_SIGNATURE_TYPES
    if name not in SUPPORTED_TYPES and name != 'UNKNOWN'
])
def test_unsupported_signature_types(sig_name, sig_type):
    """Mark unsupported signature types as expected failures."""
    pytest.xfail(f"Signature type {sig_name} not yet implemented")


def test_signature_determinism():
    """Test that signatures are deterministic for the same input."""
    private_key, _ = mk_ed25519_keypair(seed=54321)
    signer_url = mk_identity_url("determinism.acme")
    signer = Ed25519Signer(private_key, signer_url)

    tx_hash = hashlib.sha256(b"determinism test data").digest()

    # Generate signature twice
    sig1 = signer.to_accumulate_signature(tx_hash)
    sig2 = signer.to_accumulate_signature(tx_hash)

    # Signatures should be deterministic (same signature bytes)
    # Note: timestamps might differ, so we check core signature components
    assert sig1['signature'] == sig2['signature']
    assert sig1['publicKey'] == sig2['publicKey']
    assert sig1['type'] == sig2['type']


def test_signature_uniqueness():
    """Test that different inputs produce different signatures."""
    private_key, _ = mk_ed25519_keypair(seed=98765)
    signer_url = mk_identity_url("uniqueness.acme")
    signer = Ed25519Signer(private_key, signer_url)

    hash1 = hashlib.sha256(b"first message").digest()
    hash2 = hashlib.sha256(b"second message").digest()

    sig1 = signer.to_accumulate_signature(hash1)
    sig2 = signer.to_accumulate_signature(hash2)

    # Different inputs should produce different signatures
    assert sig1['signature'] != sig2['signature']
    # But same public key
    assert sig1['publicKey'] == sig2['publicKey']


def test_signature_format_validation():
    """Test signature format validation and requirements."""
    private_key, _ = mk_ed25519_keypair(seed=11111)
    signer_url = mk_identity_url("format.acme")
    signer = Ed25519Signer(private_key, signer_url)

    tx_hash = hashlib.sha256(b"format test").digest()
    signature = signer.to_accumulate_signature(tx_hash)

    # Required fields
    required_fields = ['type', 'signature', 'publicKey', 'signer']
    for field in required_fields:
        assert field in signature, f"Missing required field: {field}"
        assert signature[field] is not None, f"Field {field} is None"

    # Validate hex encoding
    try:
        bytes.fromhex(signature['signature'])
        bytes.fromhex(signature['publicKey'])
    except ValueError as e:
        pytest.fail(f"Invalid hex encoding in signature: {e}")

    # Validate signer URL format
    signer_info = signature['signer']
    if isinstance(signer_info, dict):
        signer_url = signer_info.get('url', '')
        assert signer_url.startswith('acc://'), "Signer URL should be an Accumulate URL"
    else:
        assert signer_info.startswith('acc://'), "Signer should be an Accumulate URL"


# TODO[ACC-P2-S902]: Add tests for signature marshaling/unmarshaling when signature models support it
# TODO[ACC-P2-S903]: Add tests for BTC signature types when implemented
# TODO[ACC-P2-S904]: Add tests for ETH signature types when implemented
# TODO[ACC-P2-S905]: Add tests for RSA signature types when implemented
