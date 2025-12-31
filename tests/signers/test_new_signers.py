"""
Tests for new signer implementations (Phase 3).

Tests DelegatedSigner, AuthoritySigner, SignatureSetSigner, RemoteSignatureSigner,
BTCLegacySigner, RSASigner, ECDSASigner, and TypedDataSigner.
"""

import pytest
import hashlib
from unittest.mock import Mock, MagicMock

from accumulate_client.enums import SignatureType, VoteType
from accumulate_client.runtime.url import AccountUrl


# =============================================================================
# DelegatedSigner Tests
# =============================================================================

class TestDelegatedSigner:
    """Tests for DelegatedSigner implementation."""

    @pytest.fixture
    def mock_inner_signer(self):
        """Create a mock inner signer."""
        mock = Mock()
        mock.get_signer_url.return_value = AccountUrl.parse("acc://test.acme/page")
        mock.get_signer_version.return_value = 1
        mock.get_public_key.return_value = bytes(32)
        mock.get_public_key_hash.return_value = hashlib.sha256(bytes(32)).digest()
        mock.sign.return_value = b"test_signature"
        mock.verify.return_value = True
        mock.get_vote.return_value = VoteType.ACCEPT
        mock.get_timestamp.return_value = 1234567890
        mock.routing_location.return_value = AccountUrl.parse("acc://test.acme")
        mock.to_accumulate_signature.return_value = {
            "type": "ed25519",
            "publicKey": "00" * 32,
            "signature": "00" * 64
        }
        return mock

    def test_initialization(self, mock_inner_signer):
        """Test delegated signer initialization."""
        from accumulate_client.signers.delegated import DelegatedSigner

        delegator = "acc://delegator.acme/book"
        signer = DelegatedSigner(mock_inner_signer, delegator)

        assert signer.wrapped_signer is mock_inner_signer
        assert str(signer.delegator) == delegator

    def test_signature_type(self, mock_inner_signer):
        """Test signature type is DELEGATED."""
        from accumulate_client.signers.delegated import DelegatedSigner

        signer = DelegatedSigner(mock_inner_signer, "acc://delegator.acme/book")
        assert signer.get_signature_type() == SignatureType.DELEGATED

    def test_sign_delegates_to_inner(self, mock_inner_signer):
        """Test sign delegates to inner signer."""
        from accumulate_client.signers.delegated import DelegatedSigner

        signer = DelegatedSigner(mock_inner_signer, "acc://delegator.acme/book")
        digest = bytes(32)

        result = signer.sign(digest)

        mock_inner_signer.sign.assert_called_once_with(digest)
        assert result == b"test_signature"

    def test_verify_delegates_to_inner(self, mock_inner_signer):
        """Test verify delegates to inner signer."""
        from accumulate_client.signers.delegated import DelegatedSigner

        signer = DelegatedSigner(mock_inner_signer, "acc://delegator.acme/book")

        result = signer.verify(b"sig", bytes(32))

        mock_inner_signer.verify.assert_called_once()
        assert result is True

    def test_to_accumulate_signature(self, mock_inner_signer):
        """Test Accumulate signature structure."""
        from accumulate_client.signers.delegated import DelegatedSigner

        signer = DelegatedSigner(mock_inner_signer, "acc://delegator.acme/book")
        digest = bytes(32)

        sig = signer.to_accumulate_signature(digest)

        assert sig["type"] == "delegated"
        assert sig["delegator"] == "acc://delegator.acme/book"
        assert "signature" in sig
        assert sig["signature"]["type"] == "ed25519"

    def test_can_initiate(self, mock_inner_signer):
        """Test delegated signatures can initiate."""
        from accumulate_client.signers.delegated import DelegatedSigner

        signer = DelegatedSigner(mock_inner_signer, "acc://delegator.acme/book")
        assert signer.can_initiate() is True

    def test_nested_delegation_chain(self, mock_inner_signer):
        """Test nested delegation chain tracking."""
        from accumulate_client.signers.delegated import DelegatedSigner

        # Create a 2-level delegation
        inner = DelegatedSigner(mock_inner_signer, "acc://inner.acme/book")
        outer = DelegatedSigner(inner, "acc://outer.acme/book")

        chain = outer.get_nested_delegation_chain()

        assert len(chain) == 2
        assert str(chain[0]) == "acc://outer.acme/book"
        assert str(chain[1]) == "acc://inner.acme/book"

    def test_delegation_depth(self, mock_inner_signer):
        """Test delegation depth calculation."""
        from accumulate_client.signers.delegated import DelegatedSigner

        level1 = DelegatedSigner(mock_inner_signer, "acc://d1.acme/book")
        level2 = DelegatedSigner(level1, "acc://d2.acme/book")
        level3 = DelegatedSigner(level2, "acc://d3.acme/book")

        assert level1.get_delegation_depth() == 1
        assert level2.get_delegation_depth() == 2
        assert level3.get_delegation_depth() == 3

    def test_validate_delegation_depth(self, mock_inner_signer):
        """Test delegation depth validation."""
        from accumulate_client.signers.delegated import DelegatedSigner

        # Build 5-deep delegation (valid)
        current = mock_inner_signer
        for i in range(5):
            current = DelegatedSigner(current, f"acc://d{i}.acme/book")

        assert current.validate_delegation_depth() is True
        assert current.get_delegation_depth() == 5

    def test_get_final_signer(self, mock_inner_signer):
        """Test getting the final non-delegated signer."""
        from accumulate_client.signers.delegated import DelegatedSigner

        level1 = DelegatedSigner(mock_inner_signer, "acc://d1.acme/book")
        level2 = DelegatedSigner(level1, "acc://d2.acme/book")

        final = level2.get_final_signer()
        assert final is mock_inner_signer


class TestDelegationChainUtility:
    """Tests for delegation chain utility function."""

    def test_create_delegation_chain(self):
        """Test creating a delegation chain."""
        from accumulate_client.signers.delegated import create_delegation_chain
        from accumulate_client.signers.ed25519 import Ed25519Signer, Ed25519PrivateKey

        # Create a base signer
        private_key = Ed25519PrivateKey.generate()
        base_signer = Ed25519Signer(private_key, "acc://signer.acme/page")

        delegators = ["acc://d1.acme/book", "acc://d2.acme/book"]

        result = create_delegation_chain(base_signer, delegators)

        assert result.get_delegation_depth() == 2
        assert result.get_final_signer() is base_signer

    def test_create_delegation_chain_max_depth(self):
        """Test delegation chain max depth enforcement."""
        from accumulate_client.signers.delegated import create_delegation_chain
        from accumulate_client.signers.signer import SignerError

        mock_signer = Mock()
        delegators = [f"acc://d{i}.acme/book" for i in range(6)]  # 6 levels = too deep

        with pytest.raises(SignerError, match="too deep"):
            create_delegation_chain(mock_signer, delegators)


# =============================================================================
# AuthoritySigner Tests
# =============================================================================

class TestAuthoritySigner:
    """Tests for AuthoritySigner implementation."""

    def test_initialization(self):
        """Test authority signer initialization."""
        from accumulate_client.signers.authority import AuthoritySigner

        signer = AuthoritySigner(
            origin="acc://test.acme/page",
            authority="acc://test.acme/book",
            tx_id="acc://test.acme@abc123",
            vote=VoteType.ACCEPT
        )

        assert str(signer.origin) == "acc://test.acme/page"
        assert str(signer.authority) == "acc://test.acme/book"
        assert signer.tx_id == "acc://test.acme@abc123"
        assert signer.get_vote() == VoteType.ACCEPT

    def test_signature_type(self):
        """Test signature type is AUTHORITY."""
        from accumulate_client.signers.authority import AuthoritySigner

        signer = AuthoritySigner(
            origin="acc://test.acme/page",
            authority="acc://test.acme/book",
            tx_id="tx123"
        )

        assert signer.get_signature_type() == SignatureType.AUTHORITY

    def test_cannot_initiate(self):
        """Test authority signatures cannot initiate."""
        from accumulate_client.signers.authority import AuthoritySigner

        signer = AuthoritySigner(
            origin="acc://test.acme/page",
            authority="acc://test.acme/book",
            tx_id="tx123"
        )

        assert signer.can_initiate() is False

    def test_sign_returns_empty(self):
        """Test sign returns empty bytes (authority doesn't sign directly)."""
        from accumulate_client.signers.authority import AuthoritySigner

        signer = AuthoritySigner(
            origin="acc://test.acme/page",
            authority="acc://test.acme/book",
            tx_id="tx123"
        )

        assert signer.sign(bytes(32)) == b""

    def test_verify_returns_true(self):
        """Test verify returns true (network validates)."""
        from accumulate_client.signers.authority import AuthoritySigner

        signer = AuthoritySigner(
            origin="acc://test.acme/page",
            authority="acc://test.acme/book",
            tx_id="tx123"
        )

        assert signer.verify(b"", bytes(32)) is True

    def test_to_accumulate_signature(self):
        """Test Accumulate signature structure."""
        from accumulate_client.signers.authority import AuthoritySigner

        signer = AuthoritySigner(
            origin="acc://test.acme/page",
            authority="acc://test.acme/book",
            tx_id="acc://test@abc123",
            cause="acc://test@def456",
            vote=VoteType.ACCEPT,
            memo="Test vote"
        )

        sig = signer.to_accumulate_signature(bytes(32))

        assert sig["type"] == "authority"
        assert sig["origin"] == "acc://test.acme/page"
        assert sig["authority"] == "acc://test.acme/book"
        assert sig["txID"] == "acc://test@abc123"
        assert sig["cause"] == "acc://test@def456"
        assert sig["vote"] == "accept"
        assert sig["memo"] == "Test vote"

    def test_with_delegators(self):
        """Test authority signer with delegators."""
        from accumulate_client.signers.authority import AuthoritySigner

        signer = AuthoritySigner(
            origin="acc://test.acme/page",
            authority="acc://test.acme/book",
            tx_id="tx123",
            delegator=["acc://d1.acme/book", "acc://d2.acme/book"]
        )

        sig = signer.to_accumulate_signature(bytes(32))

        assert "delegator" in sig
        assert len(sig["delegator"]) == 2

    def test_vote_types(self):
        """Test different vote types."""
        from accumulate_client.signers.authority import AuthoritySigner

        for vote in [VoteType.ACCEPT, VoteType.REJECT, VoteType.ABSTAIN, VoteType.SUGGEST]:
            signer = AuthoritySigner(
                origin="acc://test.acme/page",
                authority="acc://test.acme/book",
                tx_id="tx123",
                vote=vote
            )
            assert signer.get_vote() == vote


class TestAuthorityVoteUtility:
    """Tests for authority vote utility function."""

    def test_create_authority_vote(self):
        """Test create_authority_vote utility."""
        from accumulate_client.signers.authority import create_authority_vote

        signer = create_authority_vote(
            origin="acc://test.acme/page",
            authority="acc://test.acme/book",
            tx_id="tx123",
            vote=VoteType.REJECT,
            memo="Rejecting for security reasons"
        )

        assert signer.get_vote() == VoteType.REJECT
        assert signer.memo == "Rejecting for security reasons"


# =============================================================================
# SignatureSetSigner Tests
# =============================================================================

class TestSignatureSetSigner:
    """Tests for SignatureSetSigner implementation."""

    def test_initialization(self):
        """Test signature set initialization."""
        from accumulate_client.signers.signature_set import SignatureSetSigner

        signer = SignatureSetSigner(
            signer_url="acc://test.acme/page",
            authority="acc://test.acme/book"
        )

        assert str(signer._signer_url) == "acc://test.acme/page"
        assert str(signer.authority) == "acc://test.acme/book"
        assert signer.signatures == []

    def test_signature_type(self):
        """Test signature type is SET."""
        from accumulate_client.signers.signature_set import SignatureSetSigner

        signer = SignatureSetSigner(
            signer_url="acc://test.acme/page",
            authority="acc://test.acme/book"
        )

        assert signer.get_signature_type() == SignatureType.SET

    def test_add_signature(self):
        """Test adding signatures to the set."""
        from accumulate_client.signers.signature_set import SignatureSetSigner

        signer = SignatureSetSigner(
            signer_url="acc://test.acme/page",
            authority="acc://test.acme/book"
        )

        sig1 = {"type": "ed25519", "signature": "abc"}
        sig2 = {"type": "ed25519", "signature": "def"}

        signer.add_signature(sig1)
        signer.add_signature(sig2)

        assert signer.signature_count() == 2
        assert signer.signatures[0] == sig1
        assert signer.signatures[1] == sig2

    def test_remove_signature(self):
        """Test removing signatures from the set."""
        from accumulate_client.signers.signature_set import SignatureSetSigner

        signer = SignatureSetSigner(
            signer_url="acc://test.acme/page",
            authority="acc://test.acme/book",
            signatures=[{"type": "ed25519", "signature": "abc"}]
        )

        removed = signer.remove_signature(0)

        assert removed == {"type": "ed25519", "signature": "abc"}
        assert signer.signature_count() == 0

    def test_clear_signatures(self):
        """Test clearing all signatures."""
        from accumulate_client.signers.signature_set import SignatureSetSigner

        signer = SignatureSetSigner(
            signer_url="acc://test.acme/page",
            authority="acc://test.acme/book",
            signatures=[{"sig": 1}, {"sig": 2}, {"sig": 3}]
        )

        signer.clear_signatures()

        assert signer.signature_count() == 0

    def test_can_initiate_with_signatures(self):
        """Test can_initiate when signatures exist."""
        from accumulate_client.signers.signature_set import SignatureSetSigner

        signer = SignatureSetSigner(
            signer_url="acc://test.acme/page",
            authority="acc://test.acme/book",
            signatures=[{"type": "ed25519", "signature": "abc"}]
        )

        assert signer.can_initiate() is True

    def test_cannot_initiate_empty(self):
        """Test can_initiate when empty."""
        from accumulate_client.signers.signature_set import SignatureSetSigner

        signer = SignatureSetSigner(
            signer_url="acc://test.acme/page",
            authority="acc://test.acme/book"
        )

        assert signer.can_initiate() is False

    def test_to_accumulate_signature(self):
        """Test Accumulate signature structure."""
        from accumulate_client.signers.signature_set import SignatureSetSigner

        signer = SignatureSetSigner(
            signer_url="acc://test.acme/page",
            authority="acc://test.acme/book",
            signatures=[{"type": "ed25519"}],
            vote=VoteType.ACCEPT
        )

        sig = signer.to_accumulate_signature(bytes(32))

        assert sig["type"] == "set"
        assert sig["signer"] == "acc://test.acme/page"
        assert sig["authority"] == "acc://test.acme/book"
        assert sig["vote"] == "accept"
        assert sig["signatures"] == [{"type": "ed25519"}]

    def test_get_signature_types(self):
        """Test getting signature types in the set."""
        from accumulate_client.signers.signature_set import SignatureSetSigner

        signer = SignatureSetSigner(
            signer_url="acc://test.acme/page",
            authority="acc://test.acme/book",
            signatures=[
                {"type": "ed25519"},
                {"type": "btc"},
                {"type": "eth"}
            ]
        )

        types = signer.get_signature_types()

        assert types == ["ed25519", "btc", "eth"]


class TestSignatureSetUtilities:
    """Tests for signature set utility functions."""

    def test_create_signature_set(self):
        """Test create_signature_set utility."""
        from accumulate_client.signers.signature_set import create_signature_set

        sig_set = create_signature_set(
            signer_url="acc://test.acme/page",
            authority="acc://test.acme/book",
            signatures=[{"type": "ed25519"}]
        )

        assert sig_set.signature_count() == 1

    def test_aggregate_signatures(self):
        """Test aggregate_signatures utility."""
        from accumulate_client.signers.signature_set import aggregate_signatures

        mock_signer1 = Mock()
        mock_signer1.to_accumulate_signature.return_value = {"type": "ed25519", "sig": 1}

        mock_signer2 = Mock()
        mock_signer2.to_accumulate_signature.return_value = {"type": "btc", "sig": 2}

        sig_set = aggregate_signatures(
            signer_url="acc://test.acme/page",
            authority="acc://test.acme/book",
            signers=[mock_signer1, mock_signer2],
            digest=bytes(32)
        )

        assert sig_set.signature_count() == 2


# =============================================================================
# RemoteSignatureSigner Tests
# =============================================================================

class TestRemoteSignatureSigner:
    """Tests for RemoteSignatureSigner implementation."""

    def test_initialization(self):
        """Test remote signature initialization."""
        from accumulate_client.signers.remote import RemoteSignatureSigner

        inner_sig = {"type": "ed25519", "signature": "abc", "publicKey": "00" * 32}

        signer = RemoteSignatureSigner(
            destination="acc://BVN1.acme",
            inner_signature=inner_sig
        )

        assert str(signer.destination) == "acc://BVN1.acme"
        assert signer.inner_signature == inner_sig

    def test_signature_type(self):
        """Test signature type is REMOTE."""
        from accumulate_client.signers.remote import RemoteSignatureSigner

        signer = RemoteSignatureSigner(
            destination="acc://BVN1.acme",
            inner_signature={"type": "ed25519"}
        )

        assert signer.get_signature_type() == SignatureType.REMOTE

    def test_routing_location(self):
        """Test routing location is destination."""
        from accumulate_client.signers.remote import RemoteSignatureSigner

        signer = RemoteSignatureSigner(
            destination="acc://BVN1.acme",
            inner_signature={"type": "ed25519"}
        )

        assert str(signer.routing_location()) == "acc://BVN1.acme"

    def test_get_inner_signature_type(self):
        """Test getting inner signature type."""
        from accumulate_client.signers.remote import RemoteSignatureSigner

        signer = RemoteSignatureSigner(
            destination="acc://BVN1.acme",
            inner_signature={"type": "ed25519"}
        )

        assert signer.get_inner_signature_type() == "ed25519"

    def test_add_cause(self):
        """Test adding cause hashes."""
        from accumulate_client.signers.remote import RemoteSignatureSigner

        signer = RemoteSignatureSigner(
            destination="acc://BVN1.acme",
            inner_signature={"type": "ed25519"}
        )

        cause_hash = bytes(32)
        signer.add_cause(cause_hash)

        assert len(signer.cause) == 1
        assert signer.cause[0] == cause_hash

    def test_to_accumulate_signature(self):
        """Test Accumulate signature structure."""
        from accumulate_client.signers.remote import RemoteSignatureSigner

        inner_sig = {"type": "ed25519", "signature": "abc"}

        signer = RemoteSignatureSigner(
            destination="acc://BVN1.acme",
            inner_signature=inner_sig,
            cause=[bytes(32)],
            sequence=5
        )

        sig = signer.to_accumulate_signature(bytes(32))

        assert sig["type"] == "remote"
        assert sig["destination"] == "acc://BVN1.acme"
        assert sig["signature"] == inner_sig
        assert len(sig["cause"]) == 1
        assert sig["sequence"] == 5

    def test_can_initiate_with_initiating_type(self):
        """Test can_initiate for initiating signature type."""
        from accumulate_client.signers.remote import RemoteSignatureSigner

        signer = RemoteSignatureSigner(
            destination="acc://BVN1.acme",
            inner_signature={"type": "ed25519"}
        )

        assert signer.can_initiate() is True

    def test_cannot_initiate_with_system_type(self):
        """Test can_initiate for system signature types."""
        from accumulate_client.signers.remote import RemoteSignatureSigner

        for non_init_type in ["receipt", "partition", "internal"]:
            signer = RemoteSignatureSigner(
                destination="acc://BVN1.acme",
                inner_signature={"type": non_init_type}
            )
            assert signer.can_initiate() is False


class TestRemoteSignatureUtilities:
    """Tests for remote signature utility functions."""

    def test_create_remote_signature(self):
        """Test create_remote_signature utility."""
        from accumulate_client.signers.remote import create_remote_signature

        mock_signer = Mock()
        mock_signer.to_accumulate_signature.return_value = {"type": "ed25519", "sig": "abc"}

        remote = create_remote_signature(
            destination="acc://BVN1.acme",
            inner_signer=mock_signer,
            digest=bytes(32)
        )

        assert str(remote.destination) == "acc://BVN1.acme"
        assert remote.inner_signature["type"] == "ed25519"

    def test_wrap_for_partition(self):
        """Test wrap_for_partition utility."""
        from accumulate_client.signers.remote import wrap_for_partition

        mock_signer = Mock()
        mock_signer.to_accumulate_signature.return_value = {"type": "ed25519"}

        remote = wrap_for_partition(
            signer=mock_signer,
            digest=bytes(32),
            source_partition="BVN0",
            dest_partition="BVN1"
        )

        assert "BVN1" in str(remote.destination)


# =============================================================================
# RSASigner Tests
# =============================================================================

class TestRSASigner:
    """Tests for RSASigner implementation."""

    @pytest.fixture
    def rsa_keypair(self):
        """Generate RSA keypair for tests."""
        from accumulate_client.signers.rsa import has_rsa_support, generate_rsa_keypair

        if not has_rsa_support():
            pytest.skip("RSA support not available (cryptography not installed)")

        return generate_rsa_keypair(2048)

    def test_has_rsa_support(self):
        """Test RSA support detection."""
        from accumulate_client.signers.rsa import has_rsa_support

        # Should return True if cryptography is installed
        result = has_rsa_support()
        assert isinstance(result, bool)

    def test_key_generation(self):
        """Test RSA key generation."""
        from accumulate_client.signers.rsa import has_rsa_support, RSAPrivateKey

        if not has_rsa_support():
            pytest.skip("RSA support not available")

        private_key = RSAPrivateKey.generate(2048)

        assert private_key.key_size() == 2048
        assert private_key.public_key() is not None

    def test_signature_type(self, rsa_keypair):
        """Test signature type is RSASHA256."""
        from accumulate_client.signers.rsa import RSASigner

        private_key, _ = rsa_keypair
        signer = RSASigner(private_key, "acc://test.acme/page")

        assert signer.get_signature_type() == SignatureType.RSASHA256

    def test_sign_and_verify(self, rsa_keypair):
        """Test signing and verification."""
        from accumulate_client.signers.rsa import RSASigner

        private_key, _ = rsa_keypair
        signer = RSASigner(private_key, "acc://test.acme/page")

        message = b"test message"
        signature = signer.sign(message)

        assert len(signature) == 256  # 2048 bits / 8 = 256 bytes
        assert signer.verify(signature, message) is True

    def test_to_accumulate_signature(self, rsa_keypair):
        """Test Accumulate signature structure."""
        from accumulate_client.signers.rsa import RSASigner

        private_key, _ = rsa_keypair
        signer = RSASigner(private_key, "acc://test.acme/page")

        sig = signer.to_accumulate_signature(bytes(32))

        assert sig["type"] == SignatureType.RSASHA256
        assert "publicKey" in sig
        assert "signature" in sig
        assert sig["keySize"] == 2048

    def test_public_key_hash(self, rsa_keypair):
        """Test public key hash generation."""
        from accumulate_client.signers.rsa import RSASigner

        private_key, _ = rsa_keypair
        signer = RSASigner(private_key, "acc://test.acme/page")

        hash_result = signer.get_public_key_hash()

        assert len(hash_result) == 32  # SHA-256 hash


class TestRSAVerifier:
    """Tests for RSAVerifier."""

    @pytest.fixture
    def rsa_keypair(self):
        """Generate RSA keypair for tests."""
        from accumulate_client.signers.rsa import has_rsa_support, generate_rsa_keypair

        if not has_rsa_support():
            pytest.skip("RSA support not available")

        return generate_rsa_keypair(2048)

    def test_verify_valid_signature(self, rsa_keypair):
        """Test verifying a valid RSA signature."""
        from accumulate_client.signers.rsa import RSASigner, RSAVerifier

        private_key, public_key = rsa_keypair
        signer = RSASigner(private_key, "acc://test.acme/page")
        verifier = RSAVerifier(public_key)

        message = b"test message"
        signature = signer.sign(message)

        assert verifier.verify(message, signature) is True

    def test_verify_invalid_signature(self, rsa_keypair):
        """Test verifying an invalid signature."""
        from accumulate_client.signers.rsa import RSAVerifier

        _, public_key = rsa_keypair
        verifier = RSAVerifier(public_key)

        assert verifier.verify(bytes(32), b"invalid") is False


# =============================================================================
# ECDSASigner Tests
# =============================================================================

class TestECDSASigner:
    """Tests for ECDSASigner implementation."""

    @pytest.fixture
    def ecdsa_keypair(self):
        """Generate ECDSA keypair for tests."""
        from accumulate_client.signers.ecdsa_sha256 import has_ecdsa_support, generate_ecdsa_keypair

        if not has_ecdsa_support():
            pytest.skip("ECDSA support not available (cryptography not installed)")

        return generate_ecdsa_keypair("P-256")

    def test_has_ecdsa_support(self):
        """Test ECDSA support detection."""
        from accumulate_client.signers.ecdsa_sha256 import has_ecdsa_support

        result = has_ecdsa_support()
        assert isinstance(result, bool)

    def test_get_supported_curves(self):
        """Test getting supported curves."""
        from accumulate_client.signers.ecdsa_sha256 import has_ecdsa_support, get_supported_curves

        if not has_ecdsa_support():
            pytest.skip("ECDSA support not available")

        curves = get_supported_curves()

        assert "P-256" in curves
        assert "secp256k1" in curves

    def test_key_generation(self):
        """Test ECDSA key generation."""
        from accumulate_client.signers.ecdsa_sha256 import has_ecdsa_support, ECDSAPrivateKey

        if not has_ecdsa_support():
            pytest.skip("ECDSA support not available")

        private_key = ECDSAPrivateKey.generate("P-256")

        assert private_key.curve_name() == "P-256"
        assert private_key.key_size() == 256
        assert private_key.public_key() is not None

    def test_signature_type(self, ecdsa_keypair):
        """Test signature type is ECDSASHA256."""
        from accumulate_client.signers.ecdsa_sha256 import ECDSASigner

        private_key, _ = ecdsa_keypair
        signer = ECDSASigner(private_key, "acc://test.acme/page")

        assert signer.get_signature_type() == SignatureType.ECDSASHA256

    def test_sign_and_verify(self, ecdsa_keypair):
        """Test signing and verification."""
        from accumulate_client.signers.ecdsa_sha256 import ECDSASigner

        private_key, _ = ecdsa_keypair
        signer = ECDSASigner(private_key, "acc://test.acme/page")

        message = b"test message"
        signature = signer.sign(message)

        # ECDSA signatures are DER encoded and variable length
        assert len(signature) > 0
        assert signer.verify(signature, message) is True

    def test_to_accumulate_signature(self, ecdsa_keypair):
        """Test Accumulate signature structure."""
        from accumulate_client.signers.ecdsa_sha256 import ECDSASigner

        private_key, _ = ecdsa_keypair
        signer = ECDSASigner(private_key, "acc://test.acme/page")

        sig = signer.to_accumulate_signature(bytes(32))

        assert sig["type"] == SignatureType.ECDSASHA256
        assert "publicKey" in sig
        assert "signature" in sig
        assert sig["curve"] == "P-256"
        assert sig["keySize"] == 256

    def test_different_curves(self):
        """Test different ECDSA curves."""
        from accumulate_client.signers.ecdsa_sha256 import has_ecdsa_support, ECDSAPrivateKey

        if not has_ecdsa_support():
            pytest.skip("ECDSA support not available")

        for curve in ["P-256", "P-384", "secp256k1"]:
            private_key = ECDSAPrivateKey.generate(curve)
            assert private_key.curve_name() == curve


class TestECDSAVerifier:
    """Tests for ECDSAVerifier."""

    @pytest.fixture
    def ecdsa_keypair(self):
        """Generate ECDSA keypair for tests."""
        from accumulate_client.signers.ecdsa_sha256 import has_ecdsa_support, generate_ecdsa_keypair

        if not has_ecdsa_support():
            pytest.skip("ECDSA support not available")

        return generate_ecdsa_keypair("P-256")

    def test_verify_valid_signature(self, ecdsa_keypair):
        """Test verifying a valid ECDSA signature."""
        from accumulate_client.signers.ecdsa_sha256 import ECDSASigner, ECDSAVerifier

        private_key, public_key = ecdsa_keypair
        signer = ECDSASigner(private_key, "acc://test.acme/page")
        verifier = ECDSAVerifier(public_key)

        message = b"test message"
        signature = signer.sign(message)

        assert verifier.verify(message, signature) is True

    def test_verify_invalid_signature(self, ecdsa_keypair):
        """Test verifying an invalid signature."""
        from accumulate_client.signers.ecdsa_sha256 import ECDSAVerifier

        _, public_key = ecdsa_keypair
        verifier = ECDSAVerifier(public_key)

        # Invalid signature format
        assert verifier.verify(bytes(32), b"invalid") is False


# =============================================================================
# BTCLegacySigner Tests
# =============================================================================

class TestBTCLegacySigner:
    """Tests for BTCLegacySigner implementation."""

    @pytest.fixture
    def btc_keypair(self):
        """Generate BTC keypair for tests."""
        from accumulate_client.crypto.secp256k1 import Secp256k1PrivateKey

        private_key = Secp256k1PrivateKey.generate()
        public_key = private_key.public_key()
        return private_key, public_key

    def test_signature_type(self, btc_keypair):
        """Test signature type is BTCLEGACY."""
        from accumulate_client.signers.btc import BTCLegacySigner

        private_key, _ = btc_keypair
        signer = BTCLegacySigner(private_key, "acc://test.acme/page")

        assert signer.get_signature_type() == SignatureType.BTCLEGACY

    def test_sign_and_verify(self, btc_keypair):
        """Test signing and verification."""
        from accumulate_client.signers.btc import BTCLegacySigner

        private_key, _ = btc_keypair
        signer = BTCLegacySigner(private_key, "acc://test.acme/page")

        message = bytes(32)
        signature = signer.sign(message)

        assert len(signature) > 0
        assert signer.verify(signature, message) is True

    def test_to_accumulate_signature(self, btc_keypair):
        """Test Accumulate signature structure."""
        from accumulate_client.signers.btc import BTCLegacySigner

        private_key, _ = btc_keypair
        signer = BTCLegacySigner(private_key, "acc://test.acme/page")

        sig = signer.to_accumulate_signature(bytes(32))

        assert sig["type"] == SignatureType.BTCLEGACY
        assert "publicKey" in sig
        assert "signature" in sig


class TestBTCLegacyVerifier:
    """Tests for BTCLegacyVerifier."""

    @pytest.fixture
    def btc_keypair(self):
        """Generate BTC keypair for tests."""
        from accumulate_client.crypto.secp256k1 import Secp256k1PrivateKey

        private_key = Secp256k1PrivateKey.generate()
        public_key = private_key.public_key()
        return private_key, public_key

    def test_signature_type(self, btc_keypair):
        """Test verifier signature type is BTCLEGACY."""
        from accumulate_client.signers.btc import BTCLegacyVerifier

        _, public_key = btc_keypair
        verifier = BTCLegacyVerifier(public_key)

        assert verifier.signature_type() == SignatureType.BTCLEGACY

    def test_verify_valid_signature(self, btc_keypair):
        """Test verifying a valid BTCLegacy signature."""
        from accumulate_client.signers.btc import BTCLegacySigner, BTCLegacyVerifier

        private_key, public_key = btc_keypair
        signer = BTCLegacySigner(private_key, "acc://test.acme/page")
        verifier = BTCLegacyVerifier(public_key)

        message = bytes(32)
        signature = signer.sign(message)

        assert verifier.verify(message, signature) is True


# =============================================================================
# ETHSigner and TypedDataSigner Tests
# =============================================================================

class TestETHSigner:
    """Tests for ETHSigner implementation."""

    @pytest.fixture
    def eth_keypair(self):
        """Generate ETH keypair for tests."""
        from accumulate_client.crypto.secp256k1 import Secp256k1PrivateKey

        private_key = Secp256k1PrivateKey.generate()
        public_key = private_key.public_key()
        return private_key, public_key

    def test_signature_type(self, eth_keypair):
        """Test signature type is ETH."""
        from accumulate_client.signers.eth import ETHSigner

        private_key, _ = eth_keypair
        signer = ETHSigner(private_key, "acc://test.acme/page")

        assert signer.get_signature_type() == SignatureType.ETH

    def test_sign(self, eth_keypair):
        """Test signing."""
        from accumulate_client.signers.eth import ETHSigner

        private_key, _ = eth_keypair
        signer = ETHSigner(private_key, "acc://test.acme/page")

        message = bytes(32)
        signature = signer.sign(message)

        assert len(signature) > 0

    def test_keccak256_function(self):
        """Test keccak256 hash function."""
        from accumulate_client.signers.eth import keccak256

        data = b"test"
        hash_result = keccak256(data)

        assert len(hash_result) == 32


class TestEthAddressUtilities:
    """Tests for Ethereum address utilities."""

    def test_eth_hash(self):
        """Test eth_hash function with valid public key."""
        from accumulate_client.signers.eth import eth_hash

        # 64-byte uncompressed public key (without 0x04 prefix)
        pubkey = bytes(64)

        result = eth_hash(pubkey)

        assert len(result) == 20  # Ethereum address is 20 bytes

    def test_eth_address(self):
        """Test eth_address function."""
        from accumulate_client.signers.eth import eth_address

        pubkey = bytes(64)

        result = eth_address(pubkey)

        assert result.startswith("0x")
        assert len(result) == 42  # 0x + 40 hex chars


# =============================================================================
# Verifier Structure Tests
# =============================================================================

class TestDelegatedVerifier:
    """Tests for DelegatedVerifier."""

    def test_verify_valid_structure(self):
        """Test verifying valid delegated signature structure."""
        from accumulate_client.signers.delegated import DelegatedVerifier

        verifier = DelegatedVerifier("acc://delegator.acme/book")

        sig_obj = {
            "type": "delegated",
            "delegator": "acc://delegator.acme/book",
            "signature": {
                "type": "ed25519",
                "signature": "abc"
            }
        }

        # Structure validation should pass
        result = verifier.verify_delegated_signature(bytes(32), sig_obj)
        assert result is True

    def test_reject_wrong_delegator(self):
        """Test rejecting wrong delegator."""
        from accumulate_client.signers.delegated import DelegatedVerifier

        verifier = DelegatedVerifier("acc://expected.acme/book")

        sig_obj = {
            "type": "delegated",
            "delegator": "acc://wrong.acme/book",
            "signature": {"type": "ed25519"}
        }

        result = verifier.verify_delegated_signature(bytes(32), sig_obj)
        assert result is False


class TestAuthorityVerifier:
    """Tests for AuthorityVerifier."""

    def test_verify_valid_structure(self):
        """Test verifying valid authority signature structure."""
        from accumulate_client.signers.authority import AuthorityVerifier

        verifier = AuthorityVerifier("acc://test.acme/book")

        sig_obj = {
            "type": "authority",
            "origin": "acc://test.acme/page",
            "authority": "acc://test.acme/book",
            "vote": "accept",
            "txID": "tx123"
        }

        result = verifier.verify_authority_signature(sig_obj)
        assert result is True

    def test_reject_invalid_vote(self):
        """Test rejecting invalid vote type."""
        from accumulate_client.signers.authority import AuthorityVerifier

        verifier = AuthorityVerifier("acc://test.acme/book")

        sig_obj = {
            "type": "authority",
            "origin": "acc://test.acme/page",
            "authority": "acc://test.acme/book",
            "vote": "invalid_vote",
            "txID": "tx123"
        }

        result = verifier.verify_authority_signature(sig_obj)
        assert result is False


class TestSignatureSetVerifier:
    """Tests for SignatureSetVerifier."""

    def test_verify_valid_structure(self):
        """Test verifying valid signature set structure."""
        from accumulate_client.signers.signature_set import SignatureSetVerifier

        verifier = SignatureSetVerifier("acc://test.acme/book")

        sig_obj = {
            "type": "set",
            "signer": "acc://test.acme/page",
            "authority": "acc://test.acme/book",
            "signatures": [{"type": "ed25519"}]
        }

        result = verifier.verify_signature_set(sig_obj)
        assert result is True

    def test_reject_below_threshold(self):
        """Test rejecting signature set below threshold."""
        from accumulate_client.signers.signature_set import SignatureSetVerifier

        verifier = SignatureSetVerifier("acc://test.acme/book", required_threshold=2)

        sig_obj = {
            "type": "set",
            "signer": "acc://test.acme/page",
            "authority": "acc://test.acme/book",
            "signatures": [{"type": "ed25519"}]  # Only 1 signature, need 2
        }

        result = verifier.verify_signature_set(sig_obj)
        assert result is False


class TestRemoteSignatureVerifier:
    """Tests for RemoteSignatureVerifier."""

    def test_verify_valid_structure(self):
        """Test verifying valid remote signature structure."""
        from accumulate_client.signers.remote import RemoteSignatureVerifier

        verifier = RemoteSignatureVerifier("acc://BVN1.acme")

        sig_obj = {
            "type": "remote",
            "destination": "acc://BVN1.acme",
            "signature": {
                "type": "ed25519"
            }
        }

        result = verifier.verify_remote_signature(sig_obj)
        assert result is True

    def test_reject_wrong_destination(self):
        """Test rejecting wrong destination."""
        from accumulate_client.signers.remote import RemoteSignatureVerifier

        verifier = RemoteSignatureVerifier("acc://BVN1.acme")

        sig_obj = {
            "type": "remote",
            "destination": "acc://BVN2.acme",
            "signature": {"type": "ed25519"}
        }

        result = verifier.verify_remote_signature(sig_obj)
        assert result is False
