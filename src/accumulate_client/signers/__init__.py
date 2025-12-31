"""
Signature infrastructure for Accumulate Protocol.

Provides signing, verification, and signature management for all 16 signature types.
All signature types are now fully implemented with no stubs.
"""

from .signer import Signer, SignerError
from .registry import SignatureRegistry, get_signer_for_type
from .keypage import KeyPageSigner
from .multisig import SignatureSet, MultisigSigner
from .delegation import DelegationSigner, DelegationChain, DelegationResolver
from .ed25519 import Ed25519Signer, Ed25519Verifier
from .legacy_ed25519 import LegacyEd25519Signer, LegacyEd25519Verifier
from .btc import BTCSigner, BTCLegacySigner, BTCVerifier, BTCLegacyVerifier
from .eth import ETHSigner, TypedDataSigner, ETHVerifier, TypedDataVerifier
from .rcd1 import RCD1Signer, RCD1Verifier
from .rsa import RSASigner, RSAVerifier
from .ecdsa_sha256 import ECDSASigner, ECDSAVerifier
from .delegated import DelegatedSigner, DelegatedVerifier
from .authority import AuthoritySigner, AuthorityVerifier
from .signature_set import SignatureSetSigner, SignatureSetVerifier
from .remote import RemoteSignatureSigner, RemoteSignatureVerifier


def get_signer_types():
    """Get list of available signer type strings."""
    return list(SignatureRegistry.STRING_TO_TYPE.keys())


def get_implemented_signer_types():
    """Get list of fully implemented signer types (no stubs)."""
    return SignatureRegistry.get_implemented_types()


__all__ = [
    # Base classes
    "Signer",
    "SignerError",
    "SignatureRegistry",
    "get_signer_for_type",
    "get_signer_types",
    "get_implemented_signer_types",
    # Key page and multisig
    "KeyPageSigner",
    "SignatureSet",
    "MultisigSigner",
    "DelegationSigner",
    "DelegationChain",
    "DelegationResolver",
    # Ed25519
    "Ed25519Signer",
    "Ed25519Verifier",
    "LegacyEd25519Signer",
    "LegacyEd25519Verifier",
    # Bitcoin/Secp256k1
    "BTCSigner",
    "BTCLegacySigner",
    "BTCVerifier",
    "BTCLegacyVerifier",
    # Ethereum
    "ETHSigner",
    "TypedDataSigner",
    "ETHVerifier",
    "TypedDataVerifier",
    # Factom RCD1
    "RCD1Signer",
    "RCD1Verifier",
    # RSA
    "RSASigner",
    "RSAVerifier",
    # ECDSA
    "ECDSASigner",
    "ECDSAVerifier",
    # Delegated
    "DelegatedSigner",
    "DelegatedVerifier",
    # Authority
    "AuthoritySigner",
    "AuthorityVerifier",
    # Signature Set
    "SignatureSetSigner",
    "SignatureSetVerifier",
    # Remote
    "RemoteSignatureSigner",
    "RemoteSignatureVerifier",
]