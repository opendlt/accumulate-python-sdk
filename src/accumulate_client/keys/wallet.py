r"""
Wallet management for Accumulate Protocol.

Provides unified key operations, account management, and transaction signing.

Reference: C:/Accumulate_Stuff/accumulate\cmd\accumulated\wallets\manager.go
"""

from __future__ import annotations
from typing import Dict, List, Optional, Any, Union, Set
import logging
from datetime import datetime, timezone

from ..runtime.url import AccountUrl
from ..runtime.errors import AccumulateError
from ..enums import SignatureType
from ..crypto.ed25519 import Ed25519KeyPair
from ..crypto.secp256k1 import Secp256k1KeyPair, has_secp256k1_support
from ..signers.signer import Signer
from ..signers.registry import SignatureRegistry
from ..signers.keypage import KeyPageSigner
from ..signers.multisig import MultisigSigner
from .keystore import KeyStore, MemoryKeyStore, KeyInfo

logger = logging.getLogger(__name__)


class WalletError(AccumulateError):
    """Wallet-specific errors."""
    pass


class Account:
    """
    Account representation in a wallet.

    Manages keys and signers for a specific account URL.
    """

    def __init__(self, url: AccountUrl, account_type: str = "lite"):
        """
        Initialize account.

        Args:
            url: Account URL
            account_type: Type of account (lite, adi, keypage)
        """
        self.url = url
        self.account_type = account_type
        self.keys: List[str] = []  # key IDs
        self.metadata: Dict[str, Any] = {}
        self.created_at = int(datetime.now(timezone.utc).timestamp() * 1_000_000_000)

    def add_key(self, key_id: str):
        """Add a key to this account."""
        if key_id not in self.keys:
            self.keys.append(key_id)

    def remove_key(self, key_id: str) -> bool:
        """Remove a key from this account."""
        if key_id in self.keys:
            self.keys.remove(key_id)
            return True
        return False

    def has_key(self, key_id: str) -> bool:
        """Check if account has a key."""
        return key_id in self.keys

    def get_key_count(self) -> int:
        """Get number of keys in this account."""
        return len(self.keys)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "url": str(self.url),
            "type": self.account_type,
            "keys": self.keys.copy(),
            "metadata": self.metadata.copy(),
            "createdAt": self.created_at
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> Account:
        """Create from dictionary representation."""
        account = cls(
            url=AccountUrl(data["url"]),
            account_type=data.get("type", "lite")
        )
        account.keys = data.get("keys", [])
        account.metadata = data.get("metadata", {})
        account.created_at = data.get("createdAt", account.created_at)
        return account

    def __str__(self) -> str:
        return f"Account({self.url}, {self.account_type}, {len(self.keys)} keys)"

    def __repr__(self) -> str:
        return f"Account(url='{self.url}', type='{self.account_type}', keys={len(self.keys)})"


class Wallet:
    """
    Wallet for managing accounts and keys.

    Provides a unified interface for account and key management.
    """

    def __init__(self, name: str, key_store: KeyStore):
        """
        Initialize wallet.

        Args:
            name: Wallet name
            key_store: Key store for persistent storage
        """
        self.name = name
        self.key_store = key_store
        self.accounts: Dict[str, Account] = {}  # url -> account
        self.created_at = int(datetime.now(timezone.utc).timestamp() * 1_000_000_000)

    def create_account(self, url: AccountUrl, account_type: str = "lite", **metadata) -> Account:
        """
        Create a new account in the wallet.

        Args:
            url: Account URL
            account_type: Type of account
            **metadata: Additional metadata

        Returns:
            Created account

        Raises:
            WalletError: If account already exists
        """
        url_str = str(url)
        if url_str in self.accounts:
            raise WalletError(f"Account already exists: {url}")

        account = Account(url, account_type)
        account.metadata.update(metadata)
        self.accounts[url_str] = account

        logger.debug(f"Created account {url} in wallet {self.name}")
        return account

    def get_account(self, url: AccountUrl) -> Optional[Account]:
        """
        Get an account by URL.

        Args:
            url: Account URL

        Returns:
            Account if found
        """
        return self.accounts.get(str(url))

    def has_account(self, url: AccountUrl) -> bool:
        """Check if wallet has an account."""
        return str(url) in self.accounts

    def list_accounts(self) -> List[Account]:
        """List all accounts in the wallet."""
        return list(self.accounts.values())

    def delete_account(self, url: AccountUrl, delete_keys: bool = False) -> bool:
        """
        Delete an account from the wallet.

        Args:
            url: Account URL
            delete_keys: Whether to delete associated keys

        Returns:
            True if account was deleted
        """
        url_str = str(url)
        account = self.accounts.get(url_str)
        if not account:
            return False

        if delete_keys:
            # Delete all keys associated with this account
            for key_id in account.keys:
                self.key_store.delete_key(key_id)

        del self.accounts[url_str]
        logger.debug(f"Deleted account {url} from wallet {self.name}")
        return True

    def generate_key(
        self,
        key_id: str,
        signature_type: SignatureType = SignatureType.ED25519,
        account_url: Optional[AccountUrl] = None,
        **metadata
    ) -> KeyInfo:
        """
        Generate a new key pair.

        Args:
            key_id: Unique key identifier
            signature_type: Type of signature to generate
            account_url: Optional account URL to associate
            **metadata: Additional metadata

        Returns:
            Key information

        Raises:
            WalletError: If key generation fails
        """
        # Generate key pair based on signature type
        if signature_type in (SignatureType.ED25519, SignatureType.LEGACYED25519):
            key_pair = Ed25519KeyPair.generate()
        elif signature_type in (SignatureType.BTC, SignatureType.ETH, SignatureType.RCD1):
            if not has_secp256k1_support():
                raise WalletError("SECP256K1 support not available")
            key_pair = Secp256k1KeyPair.generate()
        else:
            raise WalletError(f"Key generation not supported for signature type: {signature_type}")

        # Store in key store
        metadata["signature_type"] = signature_type.name
        if account_url:
            metadata["account_url"] = account_url

        key_info = self.key_store.store_key(key_id, key_pair, **metadata)

        # Associate with account if provided
        if account_url:
            account = self.get_account(account_url)
            if account:
                account.add_key(key_id)

        logger.debug(f"Generated {signature_type.name} key {key_id} in wallet {self.name}")
        return key_info

    def import_key(
        self,
        key_id: str,
        key_pair: Union[Ed25519KeyPair, Secp256k1KeyPair],
        account_url: Optional[AccountUrl] = None,
        **metadata
    ) -> KeyInfo:
        """
        Import an existing key pair.

        Args:
            key_id: Unique key identifier
            key_pair: Key pair to import
            account_url: Optional account URL to associate
            **metadata: Additional metadata

        Returns:
            Key information
        """
        if account_url:
            metadata["account_url"] = account_url

        key_info = self.key_store.store_key(key_id, key_pair, **metadata)

        # Associate with account if provided
        if account_url:
            account = self.get_account(account_url)
            if account:
                account.add_key(key_id)

        logger.debug(f"Imported key {key_id} in wallet {self.name}")
        return key_info

    def get_key(self, key_id: str) -> Optional[Union[Ed25519KeyPair, Secp256k1KeyPair]]:
        """Get a key pair by ID."""
        return self.key_store.get_key(key_id)

    def get_key_info(self, key_id: str) -> Optional[KeyInfo]:
        """Get key information by ID."""
        return self.key_store.get_key_info(key_id)

    def list_keys(self, account_url: Optional[AccountUrl] = None) -> List[KeyInfo]:
        """
        List keys in the wallet.

        Args:
            account_url: Optional account URL to filter by

        Returns:
            List of key information
        """
        if account_url:
            return self.key_store.find_keys_by_account_url(account_url)
        else:
            return self.key_store.list_keys()

    def delete_key(self, key_id: str) -> bool:
        """
        Delete a key from the wallet.

        Args:
            key_id: Key identifier

        Returns:
            True if key was deleted
        """
        # Remove from accounts
        for account in self.accounts.values():
            account.remove_key(key_id)

        # Delete from key store
        return self.key_store.delete_key(key_id)

    def create_signer(self, key_id: str, signer_url: Optional[AccountUrl] = None) -> Optional[Signer]:
        """
        Create a signer from a stored key.

        Args:
            key_id: Key identifier
            signer_url: Optional signer URL (defaults to key's account URL)

        Returns:
            Signer instance if key found
        """
        key_pair = self.get_key(key_id)
        key_info = self.get_key_info(key_id)

        if not key_pair or not key_info:
            return None

        # Determine signer URL
        if not signer_url:
            signer_url = key_info.account_url
        if not signer_url:
            raise WalletError(f"No signer URL available for key {key_id}")

        # Get signature type from metadata
        signature_type_str = key_info.metadata.get("signature_type", "ED25519")
        try:
            signature_type = SignatureType[signature_type_str]
        except KeyError:
            signature_type = SignatureType.ED25519

        # Create signer
        return SignatureRegistry.create_signer(signature_type, signer_url, key_pair=key_pair)

    def get_account_count(self) -> int:
        """Get number of accounts in the wallet."""
        return len(self.accounts)

    def get_key_count(self) -> int:
        """Get number of keys in the wallet."""
        return self.key_store.get_key_count()

    def __str__(self) -> str:
        return f"Wallet({self.name}, {len(self.accounts)} accounts, {self.get_key_count()} keys)"

    def __repr__(self) -> str:
        return f"Wallet(name='{self.name}', accounts={len(self.accounts)}, keys={self.get_key_count()})"


class WalletManager:
    """
    Manager for multiple wallets.

    Provides high-level wallet and account management operations.
    """

    def __init__(self, default_key_store: Optional[KeyStore] = None):
        """
        Initialize wallet manager.

        Args:
            default_key_store: Default key store for new wallets
        """
        self.default_key_store = default_key_store or MemoryKeyStore()
        self.wallets: Dict[str, Wallet] = {}

    def create_wallet(self, name: str, key_store: Optional[KeyStore] = None) -> Wallet:
        """
        Create a new wallet.

        Args:
            name: Wallet name
            key_store: Optional key store (uses default if not provided)

        Returns:
            Created wallet

        Raises:
            WalletError: If wallet already exists
        """
        if name in self.wallets:
            raise WalletError(f"Wallet already exists: {name}")

        wallet = Wallet(name, key_store or self.default_key_store)
        self.wallets[name] = wallet

        logger.debug(f"Created wallet {name}")
        return wallet

    def get_wallet(self, name: str) -> Optional[Wallet]:
        """
        Get a wallet by name.

        Args:
            name: Wallet name

        Returns:
            Wallet if found
        """
        return self.wallets.get(name)

    def has_wallet(self, name: str) -> bool:
        """Check if wallet exists."""
        return name in self.wallets

    def list_wallets(self) -> List[Wallet]:
        """List all wallets."""
        return list(self.wallets.values())

    def delete_wallet(self, name: str, delete_keys: bool = False) -> bool:
        """
        Delete a wallet.

        Args:
            name: Wallet name
            delete_keys: Whether to delete all keys

        Returns:
            True if wallet was deleted
        """
        wallet = self.wallets.get(name)
        if not wallet:
            return False

        if delete_keys:
            wallet.key_store.clear_all_keys()

        del self.wallets[name]
        logger.debug(f"Deleted wallet {name}")
        return True

    def find_account(self, url: AccountUrl) -> Optional[tuple[Wallet, Account]]:
        """
        Find an account across all wallets.

        Args:
            url: Account URL

        Returns:
            Tuple of (wallet, account) if found
        """
        for wallet in self.wallets.values():
            account = wallet.get_account(url)
            if account:
                return wallet, account
        return None

    def find_key(self, key_id: str) -> Optional[tuple[Wallet, KeyInfo]]:
        """
        Find a key across all wallets.

        Args:
            key_id: Key identifier

        Returns:
            Tuple of (wallet, key_info) if found
        """
        for wallet in self.wallets.values():
            key_info = wallet.get_key_info(key_id)
            if key_info:
                return wallet, key_info
        return None

    def get_all_accounts(self) -> List[tuple[Wallet, Account]]:
        """
        Get all accounts across all wallets.

        Returns:
            List of (wallet, account) tuples
        """
        result = []
        for wallet in self.wallets.values():
            for account in wallet.list_accounts():
                result.append((wallet, account))
        return result

    def get_all_keys(self) -> List[tuple[Wallet, KeyInfo]]:
        """
        Get all keys across all wallets.

        Returns:
            List of (wallet, key_info) tuples
        """
        result = []
        for wallet in self.wallets.values():
            for key_info in wallet.list_keys():
                result.append((wallet, key_info))
        return result

    def get_wallet_count(self) -> int:
        """Get number of wallets."""
        return len(self.wallets)

    def get_total_account_count(self) -> int:
        """Get total number of accounts across all wallets."""
        return sum(wallet.get_account_count() for wallet in self.wallets.values())

    def get_total_key_count(self) -> int:
        """Get total number of keys across all wallets."""
        return sum(wallet.get_key_count() for wallet in self.wallets.values())

    def __str__(self) -> str:
        return f"WalletManager({len(self.wallets)} wallets, {self.get_total_account_count()} accounts, {self.get_total_key_count()} keys)"

    def __repr__(self) -> str:
        return f"WalletManager(wallets={len(self.wallets)}, accounts={self.get_total_account_count()}, keys={self.get_total_key_count()})"


# Export main classes
__all__ = [
    "Wallet",
    "Account",
    "WalletManager",
    "WalletError"
]