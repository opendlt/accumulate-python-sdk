"""
Cryptographic primitives for Accumulate Protocol.

Provides Ed25519, hash utilities, and other cryptographic operations matching the Go implementation.
"""

from .ed25519 import Ed25519KeyPair, Ed25519PublicKey, Ed25519PrivateKey, Ed25519Signature
from .secp256k1 import Secp256k1KeyPair, Secp256k1Signature, has_secp256k1_support
from .hash_utils import merkle_tree_hash, chain_hash, double_sha256, merkle_proof_verify
import hashlib


def btc_key_from_seed(seed: bytes):
    """
    Derive a Bitcoin key from seed.

    Args:
        seed: 32-byte seed

    Returns:
        Secp256k1KeyPair or raises NotImplementedError
    """
    if not has_secp256k1_support():
        raise NotImplementedError("Bitcoin key derivation requires secp256k1 support")

    # Simple derivation for now - hash the seed to get private key
    private_key = hashlib.sha256(seed).digest()
    return Secp256k1KeyPair(private_key)


def eth_key_from_seed(seed: bytes):
    """
    Derive an Ethereum key from seed.

    Args:
        seed: 32-byte seed

    Returns:
        Secp256k1KeyPair or raises NotImplementedError
    """
    if not has_secp256k1_support():
        raise NotImplementedError("Ethereum key derivation requires secp256k1 support")

    # Simple derivation for now - hash seed with "ETH" prefix
    eth_seed = b"ETH" + seed
    private_key = hashlib.sha256(eth_seed).digest()
    return Secp256k1KeyPair(private_key)

__all__ = [
    "Ed25519KeyPair",
    "Ed25519PublicKey",
    "Ed25519PrivateKey",
    "Ed25519Signature",
    "Secp256k1KeyPair",
    "Secp256k1Signature",
    "merkle_tree_hash",
    "chain_hash",
    "double_sha256",
    "merkle_proof_verify",
    "btc_key_from_seed",
    "eth_key_from_seed"
]