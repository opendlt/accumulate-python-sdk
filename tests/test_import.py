"""Test basic imports from the unified package."""

import pytest


def test_main_import():
    """Test that the main package imports successfully."""
    import accumulate_client
    assert accumulate_client.__version__ == "2.0.3"
    assert hasattr(accumulate_client, 'AccumulateClient')
    assert hasattr(accumulate_client, 'AccumulateV3Client')


def test_crypto_import():
    """Test crypto module imports."""
    import accumulate_client.crypto as crypto
    assert hasattr(crypto, 'Ed25519KeyPair')


def test_signers_import():
    """Test signers module imports."""
    import accumulate_client.signers as signers
    assert hasattr(signers, 'Signer')
    assert hasattr(signers, 'SignatureRegistry')


def test_keys_import():
    """Test keys module imports."""
    import accumulate_client.keys as keys
    assert hasattr(keys, 'KeyStore')
    assert hasattr(keys, 'WalletManager')


def test_tx_import():
    """Test transaction module imports."""
    import accumulate_client.tx as tx
    assert hasattr(tx, 'TransactionBuilder')


def test_runtime_import():
    """Test runtime module imports."""
    import accumulate_client.runtime as runtime
    assert hasattr(runtime, 'AccountUrl')


def test_types_import():
    """Test types module imports."""
    import accumulate_client.types
    import accumulate_client.enums
    # These should import without error
