"""
Signature infrastructure for Accumulate Protocol.

Provides signing, verification, and signature management for all 17 signature types.
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


def get_signer_types():
    """Get list of available signer type strings."""
    return list(SignatureRegistry.STRING_TO_TYPE.keys())

__all__ = [
    "Signer",
    "SignerError",
    "SignatureRegistry",
    "get_signer_for_type",
    "get_signer_types",
    "KeyPageSigner",
    "SignatureSet",
    "MultisigSigner",
    "DelegationSigner",
    "DelegationChain",
    "DelegationResolver",
    "Ed25519Signer",
    "Ed25519Verifier",
    "LegacyEd25519Signer",
    "LegacyEd25519Verifier",
    "BTCSigner",
    "BTCLegacySigner",
    "BTCVerifier",
    "BTCLegacyVerifier",
    "ETHSigner",
    "TypedDataSigner",
    "ETHVerifier",
    "TypedDataVerifier",
    "RCD1Signer",
    "RCD1Verifier",
    "RSASigner",
    "RSAVerifier",
    "ECDSASigner",
    "ECDSAVerifier",
    "DelegatedSigner",
    "DelegatedVerifier"
]