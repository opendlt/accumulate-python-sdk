"""
Test factories for creating test data consistently.

Provides utilities for creating keypairs, URLs, transaction builders,
and mock signing/submission flows.
"""

from __future__ import annotations
import hashlib
import secrets
from typing import Union, Dict, Any, Optional

from accumulate_client.crypto.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from accumulate_client.runtime.url import AccountUrl
from accumulate_client.tx import builders


def mk_ed25519_keypair(seed: Union[int, bytes, None] = None) -> tuple[Ed25519PrivateKey, Ed25519PublicKey]:
    """
    Create a deterministic ED25519 keypair for testing.

    Args:
        seed: Optional seed for deterministic generation

    Returns:
        Tuple of (private_key, public_key)
    """
    if seed is None:
        # Use secure random for non-deterministic tests
        seed_bytes = secrets.token_bytes(32)
    elif isinstance(seed, int):
        # Convert int to deterministic bytes
        seed_bytes = seed.to_bytes(32, 'big')
    else:
        # Use provided bytes, pad or hash to 32 bytes
        if len(seed) == 32:
            seed_bytes = seed
        elif len(seed) < 32:
            seed_bytes = seed + b'\x00' * (32 - len(seed))
        else:
            seed_bytes = hashlib.sha256(seed).digest()

    private_key = Ed25519PrivateKey.from_seed(seed_bytes)
    public_key = private_key.public_key()

    return private_key, public_key


def mk_identity_url(name: str = "example.acme") -> str:
    """
    Create a test identity URL.

    Args:
        name: Identity name (default: "example.acme")

    Returns:
        Formatted identity URL string
    """
    return f"acc://{name}"


def mk_token_url(name: str = "acme") -> str:
    """
    Create a test token URL.

    Args:
        name: Token name (default: "acme")

    Returns:
        Formatted token URL string
    """
    return f"acc://{name}.acme/tokens"


def mk_data_url(identity: str = "example.acme", account: str = "data") -> str:
    """
    Create a test data account URL.

    Args:
        identity: Identity name
        account: Data account name

    Returns:
        Formatted data account URL string
    """
    return f"acc://{identity}/{account}"


def mk_key_book_url(identity: str = "example.acme") -> str:
    """
    Create a test key book URL.

    Args:
        identity: Identity name

    Returns:
        Formatted key book URL string
    """
    return f"acc://{identity}/book"


def mk_key_page_url(identity: str = "example.acme", page: int = 0) -> str:
    """
    Create a test key page URL.

    Args:
        identity: Identity name
        page: Page number

    Returns:
        Formatted key page URL string
    """
    return f"acc://{identity}/book/{page}"


def mk_tx_builder(tx_type: str, **kwargs):
    """
    Create a transaction builder with optional initial fields.

    Args:
        tx_type: Transaction type name
        **kwargs: Initial field values

    Returns:
        Configured transaction builder
    """
    builder = builders.get_builder_for(tx_type)

    for key, value in kwargs.items():
        builder.with_field(key, value)

    return builder


def sign_and_submit_mock(client, builder, signer) -> Dict[str, Any]:
    """
    Mock signing and submission for testing.

    Args:
        client: Mock client (not used in mock)
        builder: Transaction builder
        signer: Signer instance

    Returns:
        Mock transaction receipt
    """
    # Build canonical envelope
    envelope = builder.build_envelope(
        origin=signer.get_signer_url()
    )

    # Create mock transaction hash
    tx_data = str(envelope).encode('utf-8')
    tx_hash = hashlib.sha256(tx_data).hexdigest()

    # Return mock receipt
    return {
        'txid': tx_hash,
        'status': 'delivered',
        'envelope': envelope,
        'result': {
            'type': 'success',
            'fee': 1000
        }
    }


def mk_minimal_valid_body(tx_type: str) -> Dict[str, Any]:
    """
    Create minimal valid transaction body for the given type.

    Args:
        tx_type: Transaction type name

    Returns:
        Dictionary with minimal required fields
    """
    # Common minimal fields for different transaction categories
    minimal_bodies = {
        # Identity transactions
        'CreateIdentity': {
            'url': mk_identity_url(),
            'keyBookUrl': mk_key_book_url()
        },
        'CreateKeyBook': {
            'url': mk_key_book_url(),
            'publicKeyHash': b'\x01' * 32
        },
        'CreateKeyPage': {
            'keys': [b'\x02' * 32]
        },
        'UpdateKeyPage': {
            'operation': 'add',
            'key': b'\x03' * 32
        },
        'UpdateKey': {
            'newKeyHash': b'\x04' * 32
        },

        # Token transactions
        'CreateToken': {
            'url': mk_token_url(),
            'symbol': 'TEST',
            'precision': 8
        },
        'CreateTokenAccount': {
            'url': mk_identity_url() + '/tokens',
            'tokenUrl': mk_token_url(),
            'keyBookUrl': mk_key_book_url()
        },
        'CreateLiteTokenAccount': {},
        'SendTokens': {
            'to': mk_identity_url() + '/tokens',
            'amount': 1000000
        },
        'IssueTokens': {
            'recipient': mk_identity_url() + '/tokens',
            'amount': 1000000
        },
        'BurnTokens': {
            'amount': 1000000
        },

        # Data transactions
        'CreateDataAccount': {
            'url': mk_data_url(),
            'keyBookUrl': mk_key_book_url()
        },
        'WriteData': {
            'data': b'test data'
        },
        'WriteDataTo': {
            'recipient': mk_data_url(),
            'data': b'test data'
        },

        # Account transactions
        'AddCredits': {
            'recipient': mk_identity_url(),
            'amount': 1000000,
            'oracle': 0.05
        },
        'BurnCredits': {
            'amount': 1000
        },
        'TransferCredits': {
            'to': mk_identity_url(),
            'amount': 1000
        },
        'UpdateAccountAuth': {
            'authority': mk_identity_url(),
            'operations': ['UpdateKeyPage']
        },
        'LockAccount': {
            'height': 1000
        },
        'AcmeFaucet': {
            'url': mk_identity_url()
        },

        # System transactions
        'NetworkMaintenance': {
            'operation': 'update',
            'target': mk_identity_url()
        },
        'SystemGenesis': {
            'networkName': 'testnet',
            'version': '1.0.0'
        },
        'SystemWriteData': {
            'data': b'system data'
        },
        'DirectoryAnchor': {
            'source': mk_identity_url(),
            'rootChainAnchor': b'\x05' * 32,
            'stateTreeAnchor': b'\x06' * 32
        },
        'BlockValidatorAnchor': {
            'source': mk_identity_url(),
            'rootChainAnchor': b'\x07' * 32,
            'stateTreeAnchor': b'\x08' * 32,
            'minorBlocks': [b'\x09' * 32]
        },

        # Synthetic transactions
        'SyntheticCreateIdentity': {
            'url': mk_identity_url(),
            'cause': b'\x0a' * 32
        },
        'SyntheticWriteData': {
            'data': b'synthetic data',
            'cause': b'\x0b' * 32
        },
        'SyntheticDepositTokens': {
            'token': mk_token_url(),
            'amount': 1000000,
            'cause': b'\x0c' * 32
        },
        'SyntheticDepositCredits': {
            'amount': 1000,
            'cause': b'\x0d' * 32
        },
        'SyntheticBurnTokens': {
            'amount': 1000000,
            'cause': b'\x0e' * 32
        },
        'SyntheticForwardTransaction': {
            'envelope': {'test': 'envelope'},
            'cause': b'\x0f' * 32
        },
        'RemoteTransaction': {
            'hash': b'\x10' * 32
        }
    }

    return minimal_bodies.get(tx_type, {})


__all__ = [
    'mk_ed25519_keypair',
    'mk_identity_url',
    'mk_token_url',
    'mk_data_url',
    'mk_key_book_url',
    'mk_key_page_url',
    'mk_tx_builder',
    'sign_and_submit_mock',
    'mk_minimal_valid_body'
]
