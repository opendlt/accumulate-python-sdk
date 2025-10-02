"""
Accumulate Python SDK public API surface.

This module re-exports the most commonly used classes and helpers so tests and
consumers can simply `from src.accumulate_client import ...`.
"""

# ---- Client types -----------------------------------------------------------
# Keep your streaming client
try:
    from .client import StreamingAccumulateClient  # type: ignore
except Exception:
    StreamingAccumulateClient = None  # type: ignore

# Also try to expose JsonRpcClient if present (module name may vary)
JsonRpcClient = None  # type: ignore
for _mod in (
    ".client.json_rpc_client",
    ".client.jsonrpc_client",
    ".client.json_rpc",
):
    if JsonRpcClient is None:
        try:
            JsonRpcClient = __import__(__name__ + _mod, fromlist=["JsonRpcClient"]).JsonRpcClient  # type: ignore
        except Exception:
            pass

# ---- Crypto: Ed25519 -------------------------------------------------------
# Export Ed25519 types and shims if available
Ed25519KeyPair = Ed25519PrivateKey = Ed25519PublicKey = None  # type: ignore
keypair_from_seed = verify_ed25519 = None  # type: ignore

try:
    _ed = __import__(__name__ + ".crypto.ed25519", fromlist=[
        "Ed25519KeyPair", "Ed25519PrivateKey", "Ed25519PublicKey",
        "keypair_from_seed", "verify_ed25519"
    ])
    Ed25519KeyPair = getattr(_ed, "Ed25519KeyPair", None)
    Ed25519PrivateKey = getattr(_ed, "Ed25519PrivateKey", None)
    Ed25519PublicKey = getattr(_ed, "Ed25519PublicKey", None)
    keypair_from_seed = getattr(_ed, "keypair_from_seed", None)
    verify_ed25519 = getattr(_ed, "verify_ed25519", None)
except Exception:
    pass

# ---- Codec / Canonical JSON ------------------------------------------------
# TransactionCodec: try a few plausible module paths
TransactionCodec = None  # type: ignore
for _mod in (
    ".codec.transaction_codec",
    ".codec.codec",
    ".codec.transactions",
    ".codec",
):
    if TransactionCodec is None:
        try:
            TransactionCodec = __import__(__name__ + _mod, fromlist=["TransactionCodec"]).TransactionCodec  # type: ignore
        except Exception:
            pass

# dumps_canonical (canonical JSON encoder)
dumps_canonical = None  # type: ignore
for _mod, _name in (
    (".codec.canonical_json", "dumps_canonical"),
    (".codec.json_canonical", "dumps_canonical"),
    (".codec.json", "dumps_canonical"),
    (".codec", "dumps_canonical"),
):
    if dumps_canonical is None:
        try:
            dumps_canonical = getattr(__import__(__name__ + _mod, fromlist=[_name]), _name)  # type: ignore
        except Exception:
            pass

# sha256_bytes (hash helper)
sha256_bytes = None  # type: ignore
for _mod, _name in (
    (".crypto.hashing", "sha256_bytes"),
    (".codec.hashing", "sha256_bytes"),
    (".crypto.hash", "sha256_bytes"),
    (".codec", "sha256_bytes"),
):
    if sha256_bytes is None:
        try:
            sha256_bytes = getattr(__import__(__name__ + _mod, fromlist=[_name]), _name)  # type: ignore
        except Exception:
            pass

# ---- Public API list -------------------------------------------------------
__all__ = [
    name for name in [
        "StreamingAccumulateClient",
        "JsonRpcClient",
        "Ed25519KeyPair",
        "Ed25519PrivateKey",
        "Ed25519PublicKey",
        "keypair_from_seed",
        "verify_ed25519",
        "TransactionCodec",
        "dumps_canonical",
        "sha256_bytes",
    ] if globals().get(name) is not None
]
