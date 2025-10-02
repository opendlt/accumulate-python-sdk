"""
Hash utilities for Accumulate Protocol.

Provides Merkle tree operations and other hash utilities matching the Go implementation.

Reference: C:/Accumulate_Stuff/accumulate/internal/core/hash.go
"""

import hashlib
from typing import List


def merkle_tree_hash(leaves: List[bytes]) -> bytes:
    """
    Calculate Merkle tree root hash from leaf hashes.

    Implements binary Merkle tree construction where:
    - Leaf nodes are hashed transaction data
    - Internal nodes are SHA256(left + right)
    - Single leaf returns the leaf itself
    - Odd number of nodes duplicates the last node

    Args:
        leaves: List of leaf hash values (32 bytes each)

    Returns:
        Root hash (32 bytes)

    Raises:
        ValueError: If leaves is empty or contains invalid hashes
    """
    if not leaves:
        raise ValueError("Cannot compute Merkle root of empty leaf set")

    # Validate all leaves are 32 bytes (SHA256 length)
    for i, leaf in enumerate(leaves):
        if not isinstance(leaf, bytes):
            raise ValueError(f"Leaf {i} must be bytes, got {type(leaf)}")
        if len(leaf) != 32:
            raise ValueError(f"Leaf {i} must be 32 bytes, got {len(leaf)}")

    # Single leaf case
    if len(leaves) == 1:
        return leaves[0]

    # Build tree bottom-up
    current_level = leaves[:]

    while len(current_level) > 1:
        next_level = []

        # Process pairs
        for i in range(0, len(current_level), 2):
            left = current_level[i]

            # If odd number of nodes, duplicate the last one
            if i + 1 < len(current_level):
                right = current_level[i + 1]
            else:
                right = left

            # Hash the pair: SHA256(left + right)
            parent = hashlib.sha256(left + right).digest()
            next_level.append(parent)

        current_level = next_level

    return current_level[0]


def chain_hash(prev_hash: bytes, current_hash: bytes) -> bytes:
    """
    Calculate chained hash for sequential operations.

    Used for building chains of transactions or blocks where each
    hash depends on the previous one.

    Args:
        prev_hash: Previous hash in chain (32 bytes)
        current_hash: Current hash to chain (32 bytes)

    Returns:
        Chained hash: SHA256(prev_hash + current_hash)

    Raises:
        ValueError: If hashes are not 32 bytes
    """
    if not isinstance(prev_hash, bytes) or len(prev_hash) != 32:
        raise ValueError("prev_hash must be 32 bytes")
    if not isinstance(current_hash, bytes) or len(current_hash) != 32:
        raise ValueError("current_hash must be 32 bytes")

    return hashlib.sha256(prev_hash + current_hash).digest()


def double_sha256(data: bytes) -> bytes:
    """
    Calculate double SHA256 hash.

    Used in some blockchain protocols for additional security.

    Args:
        data: Data to hash

    Returns:
        SHA256(SHA256(data))
    """
    if not isinstance(data, bytes):
        raise ValueError("data must be bytes")

    first_hash = hashlib.sha256(data).digest()
    return hashlib.sha256(first_hash).digest()


def merkle_proof_verify(leaf_hash: bytes, proof: List[bytes], root_hash: bytes, index: int) -> bool:
    """
    Verify a Merkle inclusion proof.

    Args:
        leaf_hash: Hash of the leaf to verify (32 bytes)
        proof: List of sibling hashes in the proof path
        root_hash: Expected root hash (32 bytes)
        index: Index of the leaf in the tree

    Returns:
        True if proof is valid
    """
    if not isinstance(leaf_hash, bytes) or len(leaf_hash) != 32:
        raise ValueError("leaf_hash must be 32 bytes")
    if not isinstance(root_hash, bytes) or len(root_hash) != 32:
        raise ValueError("root_hash must be 32 bytes")

    current_hash = leaf_hash
    current_index = index

    for sibling_hash in proof:
        if not isinstance(sibling_hash, bytes) or len(sibling_hash) != 32:
            raise ValueError("All proof hashes must be 32 bytes")

        # Determine if current node is left or right child
        if current_index % 2 == 0:
            # Left child
            current_hash = hashlib.sha256(current_hash + sibling_hash).digest()
        else:
            # Right child
            current_hash = hashlib.sha256(sibling_hash + current_hash).digest()

        current_index //= 2

    return current_hash == root_hash


__all__ = [
    "merkle_tree_hash",
    "chain_hash",
    "double_sha256",
    "merkle_proof_verify"
]