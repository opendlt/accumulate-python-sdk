"""Test basic functionality of the unified package."""

import pytest
import accumulate_client as acc


def test_account_url():
    """Test AccountUrl functionality."""
    url = acc.AccountUrl("acc://example.acme")
    assert str(url) == "acc://example.acme"
    assert str(url).startswith("acc://")


def test_ed25519_keypair():
    """Test Ed25519 key pair generation."""
    keypair = acc.crypto.Ed25519KeyPair.generate()
    assert len(keypair.public_key.to_bytes()) == 32
    assert len(keypair.private_key.to_bytes()) == 32


def test_signature_registry():
    """Test signature registry functionality."""
    from accumulate_client.enums import SignatureType

    types = acc.signers.SignatureRegistry.get_supported_types()
    assert SignatureType.ED25519 in types
    assert len(types) == 16  # Should support all 16 signature types


def test_memory_keystore():
    """Test memory key store functionality."""
    keystore = acc.keys.MemoryKeyStore()

    # Generate a key
    keypair = acc.crypto.Ed25519KeyPair.generate()

    # Store it
    key_info = keystore.store_key("test-key", keypair)
    assert key_info.key_id == "test-key"
    assert key_info.key_type == "ed25519"

    # Retrieve it
    retrieved = keystore.get_key("test-key")
    assert retrieved is not None
    assert retrieved.public_key.to_bytes() == keypair.public_key.to_bytes()


def test_transaction_fields():
    """Test transaction field validation."""
    from accumulate_client.tx.fields import StringField, IntegerField

    # String field validation
    string_field = StringField("name", min_length=3, max_length=10)
    validated = string_field.validate("test")
    assert validated == "test"

    # Integer field validation
    int_field = IntegerField("amount", min_value=0, unsigned=True)
    validated = int_field.validate(100)
    assert validated == 100


def test_wallet_manager():
    """Test wallet manager functionality."""
    manager = acc.keys.WalletManager()

    # Create a wallet
    wallet = manager.create_wallet("test-wallet")
    assert wallet.name == "test-wallet"

    # Create an account
    account_url = acc.AccountUrl("acc://test.acme")
    account = wallet.create_account(account_url)
    assert account.url == account_url


def test_client_availability():
    """Test that clients are available."""
    # Test that we can create client instances
    assert hasattr(acc, 'mainnet_client')
    assert hasattr(acc, 'testnet_client')
    assert hasattr(acc, 'local_client')

    # Note: We don't actually call them since they may require network access
