"""
Convenience utilities for Accumulate SDK.

Provides high-level APIs matching Dart SDK patterns:
- SmartSigner: Auto-version tracking signer with sign/submit/wait
- TxBody: Factory methods for creating transaction bodies
- QuickStart: Ultra-simple API for rapid development
- KeyManager: Key page query and management utilities

Example usage:
    ```python
    from accumulate_client import Accumulate
    from accumulate_client.convenience import SmartSigner, TxBody, QuickStart

    # QuickStart API (simplest)
    acc = QuickStart.devnet()
    wallet = acc.create_wallet()
    acc.fund_wallet(wallet)
    adi = acc.setup_adi(wallet, "my-adi")

    # SmartSigner API (more control)
    client = Accumulate.devnet()
    signer = SmartSigner(client.v3, keypair, signer_url)
    result = signer.sign_submit_and_wait(
        principal="acc://my-adi.acme/tokens",
        body=TxBody.send_tokens_single("acc://recipient.acme", "1000000000"),
        memo="Send 10 ACME"
    )
    ```
"""

from __future__ import annotations
import hashlib
import time
import asyncio
from typing import Optional, Dict, Any, List, Union, Tuple, TYPE_CHECKING
from dataclasses import dataclass, field
from datetime import datetime

if TYPE_CHECKING:
    from .v3.client import AccumulateV3Client
    from .facade import Accumulate


# =============================================================================
# Data Classes
# =============================================================================

@dataclass
class SubmitResult:
    """Result of a transaction submission."""
    success: bool
    txid: Optional[str] = None
    error: Optional[str] = None
    response: Optional[Dict[str, Any]] = None


@dataclass
class Wallet:
    """Simple wallet containing keypair and derived URLs."""
    keypair: Any
    lite_identity: str
    lite_token_account: str
    public_key_hash: str


@dataclass
class ADI:
    """ADI (Accumulate Digital Identifier) with associated resources."""
    url: str
    key_book_url: str
    key_page_url: str
    keypair: Any
    public_key_hash: str


@dataclass
class KeyPageInfo:
    """Key page state information."""
    url: str
    version: int
    credits: int
    threshold: int
    key_count: int
    keys: List[str]


# =============================================================================
# TxBody - Transaction Body Factory
# =============================================================================

class TxBody:
    """
    Factory class for creating transaction bodies.

    Provides static methods matching Dart SDK's TxBody pattern for
    easy transaction body construction.

    Example:
        ```python
        body = TxBody.send_tokens_single("acc://recipient.acme", "1000000000")
        body = TxBody.create_identity("acc://my-adi.acme", "acc://my-adi.acme/book", key_hash)
        body = TxBody.add_credits("acc://recipient.acme", "1000000000", oracle)
        ```
    """

    @staticmethod
    def send_tokens_single(to_url: str, amount: str) -> Dict[str, Any]:
        """Create SendTokens body for single recipient."""
        return {
            "type": "sendTokens",
            "to": [{"url": to_url, "amount": amount}]
        }

    @staticmethod
    def send_tokens(recipients: List[Dict[str, str]]) -> Dict[str, Any]:
        """Create SendTokens body for multiple recipients."""
        return {
            "type": "sendTokens",
            "to": [{"url": r["url"], "amount": r["amount"]} for r in recipients]
        }

    @staticmethod
    def add_credits(recipient: str, amount: str, oracle: int) -> Dict[str, Any]:
        """Create AddCredits body."""
        return {
            "type": "addCredits",
            "recipient": recipient,
            "amount": amount,
            "oracle": oracle
        }

    @staticmethod
    def buy_credits(recipient_url: str, amount: str, oracle: int) -> Dict[str, Any]:
        """Alias for add_credits (Dart SDK compatibility)."""
        return TxBody.add_credits(recipient_url, amount, oracle)

    @staticmethod
    def create_identity(
        url: str,
        key_book_url: str,
        public_key_hash: str
    ) -> Dict[str, Any]:
        """Create CreateIdentity body."""
        return {
            "type": "createIdentity",
            "url": url,
            "keyBookUrl": key_book_url,
            "keyHash": public_key_hash
        }

    @staticmethod
    def create_token_account(url: str, token_url: str = "acc://ACME") -> Dict[str, Any]:
        """Create CreateTokenAccount body."""
        return {
            "type": "createTokenAccount",
            "url": url,
            "tokenUrl": token_url
        }

    @staticmethod
    def create_data_account(url: str) -> Dict[str, Any]:
        """Create CreateDataAccount body."""
        return {
            "type": "createDataAccount",
            "url": url
        }

    @staticmethod
    def write_data(entries_hex: List[str], scratch: bool = False, write_to_state: bool = False) -> Dict[str, Any]:
        """Create WriteData body with hex-encoded entries.

        Uses DoubleHashDataEntry type (matches Go protocol general.yml).
        Note: "dataEntry" type is deprecated; use "doubleHash" instead.
        """
        body: Dict[str, Any] = {
            "type": "writeData",
            "entry": {
                "type": "doubleHash",
                "data": entries_hex
            }
        }
        if scratch:
            body["scratch"] = True
        if write_to_state:
            body["writeToState"] = True
        return body

    @staticmethod
    def write_data_strings(entries: List[str], scratch: bool = False, write_to_state: bool = False) -> Dict[str, Any]:
        """Create WriteData body with string entries (auto hex-encoded)."""
        hex_entries = [entry.encode().hex() for entry in entries]
        return TxBody.write_data(hex_entries, scratch=scratch, write_to_state=write_to_state)

    @staticmethod
    def create_token(
        url: str,
        symbol: str,
        precision: int,
        supply_limit: Optional[int] = None
    ) -> Dict[str, Any]:
        """Create CreateToken body."""
        body: Dict[str, Any] = {
            "type": "createToken",
            "url": url,
            "symbol": symbol,
            "precision": precision
        }
        if supply_limit is not None:
            body["supplyLimit"] = supply_limit
        return body

    @staticmethod
    def issue_tokens_single(to_url: str, amount: str) -> Dict[str, Any]:
        """Create IssueTokens body for single recipient."""
        return {
            "type": "issueTokens",
            "to": [{"url": to_url, "amount": amount}]
        }

    @staticmethod
    def burn_tokens(amount: int) -> Dict[str, Any]:
        """Create BurnTokens body."""
        return {
            "type": "burnTokens",
            "amount": amount
        }

    @staticmethod
    def create_key_page(keys: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Create CreateKeyPage body."""
        return {
            "type": "createKeyPage",
            "keys": keys
        }

    @staticmethod
    def create_key_book(url: str, public_key_hash: str) -> Dict[str, Any]:
        """Create CreateKeyBook body."""
        return {
            "type": "createKeyBook",
            "url": url,
            "publicKeyHash": public_key_hash
        }

    @staticmethod
    def update_key_page(operations: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Create UpdateKeyPage body."""
        return {
            "type": "updateKeyPage",
            "operation": operations
        }

    @staticmethod
    def add_key_operation(key_hash: bytes) -> Dict[str, Any]:
        """Create an AddKey operation for UpdateKeyPage."""
        return {
            "type": "add",
            "entry": {"keyHash": key_hash.hex()}
        }

    @staticmethod
    def remove_key_operation(key_hash: bytes) -> Dict[str, Any]:
        """Create a RemoveKey operation for UpdateKeyPage."""
        return {
            "type": "remove",
            "entry": {"keyHash": key_hash.hex()}
        }

    @staticmethod
    def set_threshold_operation(threshold: int) -> Dict[str, Any]:
        """Create a SetThreshold operation for UpdateKeyPage."""
        return {
            "type": "setThreshold",
            "threshold": threshold
        }

    @staticmethod
    def acme_faucet(url: str) -> Dict[str, Any]:
        """Create AcmeFaucet body."""
        return {
            "type": "acmeFaucet",
            "url": url
        }


# =============================================================================
# SmartSigner - High-level signer with auto-version tracking
# =============================================================================

class SmartSigner:
    """
    High-level signer with auto-version tracking and sign/submit/wait.

    SmartSigner automatically fetches and tracks the signer version,
    making it easy to sign and submit transactions without manual
    version management.

    Example:
        ```python
        signer = SmartSigner(client.v3, keypair, "acc://my-adi.acme/book/1")

        # Sign, submit, and wait for result
        result = signer.sign_submit_and_wait(
            principal="acc://my-adi.acme/tokens",
            body=TxBody.send_tokens_single("acc://recipient.acme", "100000000"),
            memo="Send 1 ACME",
            max_attempts=30
        )

        if result.success:
            print(f"Transaction ID: {result.txid}")
        else:
            print(f"Failed: {result.error}")
        ```
    """

    def __init__(
        self,
        client: AccumulateV3Client,
        keypair: Any,
        signer_url: str
    ):
        """
        Initialize SmartSigner.

        Args:
            client: V3 API client
            keypair: Ed25519KeyPair or compatible keypair object
            signer_url: URL of the signing key page
        """
        self.client = client
        self.keypair = keypair
        self.signer_url = signer_url
        self._cached_version: Optional[int] = None

    def get_signer_version(self) -> int:
        """Fetch current signer version from network."""
        try:
            result = self.client.query(self.signer_url)
            if result.get("account"):
                self._cached_version = result["account"].get("version", 1)
            else:
                self._cached_version = 1
        except Exception:
            self._cached_version = 1
        return self._cached_version

    def sign_and_build(
        self,
        principal: str,
        body: Dict[str, Any],
        memo: Optional[str] = None,
        signer_version: Optional[int] = None
    ) -> Dict[str, Any]:
        """
        Sign a transaction and build the envelope.

        Args:
            principal: Transaction principal URL
            body: Transaction body
            memo: Optional memo
            signer_version: Optional explicit version (auto-fetched if None)

        Returns:
            Complete transaction envelope ready for submission
        """
        from .crypto.ed25519 import Ed25519PrivateKey
        from .tx.context import BuildContext

        # Get signer version
        if signer_version is None:
            signer_version = self.get_signer_version()

        # Get public key and hash
        if hasattr(self.keypair, 'public_key_bytes'):
            # Ed25519KeyPair has public_key_bytes() method
            public_key_bytes = self.keypair.public_key_bytes()
        elif hasattr(self.keypair, 'public_key'):
            # Check if public_key is callable (method) or attribute
            pk = self.keypair.public_key
            if callable(pk):
                # Ed25519PrivateKey has public_key() method
                public_key_bytes = pk().to_bytes()
            else:
                # Ed25519KeyPair has public_key attribute
                public_key_bytes = pk.to_bytes()
        else:
            raise ValueError("Keypair must have public_key or public_key_bytes")

        public_key_hash = hashlib.sha256(public_key_bytes).digest()

        # Build context
        timestamp = int(time.time() * 1_000_000)  # microseconds

        # Build transaction
        transaction = {
            "header": {
                "principal": principal,
                "initiator": public_key_hash.hex(),
                "timestamp": timestamp
            },
            "body": body
        }

        if memo:
            transaction["header"]["memo"] = memo

        # Compute transaction hash using canonical JSON
        from .canonjson import dumps_canonical
        tx_bytes = dumps_canonical(transaction).encode('utf-8')
        tx_hash = hashlib.sha256(tx_bytes).digest()

        # Sign
        if hasattr(self.keypair, 'sign'):
            signature = self.keypair.sign(tx_hash)
        elif hasattr(self.keypair, 'private_key'):
            signature = self.keypair.private_key.sign(tx_hash)
        else:
            raise ValueError("Keypair must have sign method or private_key")

        # Build envelope (V3 format)
        envelope = {
            "transaction": transaction,
            "signatures": [{
                "type": "ed25519",
                "publicKey": public_key_bytes.hex(),
                "signature": signature.hex(),
                "signer": self.signer_url,
                "signerVersion": signer_version,
                "timestamp": timestamp
            }]
        }

        return envelope

    def sign_submit_and_wait(
        self,
        principal: str,
        body: Dict[str, Any],
        memo: Optional[str] = None,
        max_attempts: int = 30,
        poll_interval: float = 2.0
    ) -> SubmitResult:
        """
        Sign, submit, and wait for transaction completion.

        Args:
            principal: Transaction principal URL
            body: Transaction body
            memo: Optional memo
            max_attempts: Maximum poll attempts
            poll_interval: Seconds between polls

        Returns:
            SubmitResult with success status and transaction ID
        """
        try:
            # Build and sign envelope
            envelope = self.sign_and_build(principal, body, memo)

            # Submit
            response = self.client.submit(envelope)

            # Extract transaction ID
            txid = None
            if isinstance(response, list) and response:
                first_result = response[0]
                if isinstance(first_result, dict) and first_result.get("status"):
                    txid = first_result["status"].get("txID")

            if not txid:
                return SubmitResult(
                    success=False,
                    error="Could not extract transaction ID from response",
                    response=response
                )

            # Wait for confirmation
            for attempt in range(max_attempts):
                try:
                    tx_result = self.client.query(txid)
                    if tx_result.get("status", {}).get("delivered", False):
                        return SubmitResult(
                            success=True,
                            txid=txid,
                            response=tx_result
                        )
                except Exception:
                    pass

                time.sleep(poll_interval)

            # Timeout - but transaction may still succeed
            return SubmitResult(
                success=True,  # Assume success if submitted
                txid=txid,
                response=response
            )

        except Exception as e:
            return SubmitResult(
                success=False,
                error=str(e)
            )

    def add_key(self, new_keypair: Any) -> SubmitResult:
        """
        Add a key to the signer's key page.

        Args:
            new_keypair: Keypair to add

        Returns:
            SubmitResult
        """
        # Get public key hash
        if hasattr(new_keypair, 'public_key_bytes'):
            public_key_bytes = new_keypair.public_key_bytes()
        elif hasattr(new_keypair, 'public_key'):
            pk = new_keypair.public_key
            if callable(pk):
                public_key_bytes = pk().to_bytes()
            else:
                public_key_bytes = pk.to_bytes()
        else:
            raise ValueError("Keypair must have public_key or public_key_bytes")

        key_hash = hashlib.sha256(public_key_bytes).digest()

        body = TxBody.update_key_page([
            TxBody.add_key_operation(key_hash)
        ])

        return self.sign_submit_and_wait(
            principal=self.signer_url,
            body=body,
            memo="Add key to key page"
        )

    def set_threshold(self, threshold: int) -> SubmitResult:
        """
        Set the accept threshold for the signer's key page.

        Args:
            threshold: New threshold value

        Returns:
            SubmitResult
        """
        body = TxBody.update_key_page([
            TxBody.set_threshold_operation(threshold)
        ])

        return self.sign_submit_and_wait(
            principal=self.signer_url,
            body=body,
            memo=f"Set threshold to {threshold}"
        )


# =============================================================================
# KeyManager - Key page query and management
# =============================================================================

class KeyManager:
    """
    Utility for querying and managing key pages.

    Example:
        ```python
        km = KeyManager(client.v3, "acc://my-adi.acme/book/1")
        state = km.get_key_page_state()
        print(f"Version: {state.version}, Keys: {state.key_count}")
        ```
    """

    def __init__(self, client: AccumulateV3Client, key_page_url: str):
        """
        Initialize KeyManager.

        Args:
            client: V3 API client
            key_page_url: Key page URL to manage
        """
        self.client = client
        self.key_page_url = key_page_url

    def get_key_page_state(self) -> KeyPageInfo:
        """
        Get current key page state.

        Returns:
            KeyPageInfo with current state
        """
        result = self.client.query(self.key_page_url)

        account = result.get("account", {})
        keys = account.get("keys", [])

        return KeyPageInfo(
            url=account.get("url", self.key_page_url),
            version=account.get("version", 1),
            credits=account.get("creditBalance", 0),
            threshold=account.get("acceptThreshold", 1),
            key_count=len(keys),
            keys=[k.get("publicKeyHash", "") for k in keys if isinstance(k, dict)]
        )


# =============================================================================
# QuickStart - Ultra-simple API
# =============================================================================

class QuickStart:
    """
    Ultra-simple API for rapid Accumulate development.

    QuickStart reduces hundreds of lines of boilerplate to just a few
    lines per operation, matching the Dart SDK's simplicity.

    Example:
        ```python
        # Connect to devnet
        acc = QuickStart.devnet()

        # Create and fund a wallet
        wallet = acc.create_wallet()
        acc.fund_wallet(wallet)

        # Set up an ADI
        adi = acc.setup_adi(wallet, "my-adi")

        # Buy credits
        acc.buy_credits_for_adi(wallet, adi, 500)

        # Create accounts
        acc.create_token_account(adi, "tokens")
        acc.create_data_account(adi, "mydata")

        # Write data
        acc.write_data(adi, "mydata", ["Hello", "World"])
        ```
    """

    def __init__(
        self,
        v2_endpoint: str = "http://127.0.0.1:26660/v2",
        v3_endpoint: str = "http://127.0.0.1:26660/v3"
    ):
        """
        Initialize QuickStart with endpoints.

        Args:
            v2_endpoint: V2 API endpoint
            v3_endpoint: V3 API endpoint
        """
        from .facade import Accumulate

        # Extract base endpoint
        base = v3_endpoint.replace("/v3", "").replace("/v2", "")
        self.client = Accumulate(base)
        self._v2_endpoint = v2_endpoint
        self._v3_endpoint = v3_endpoint

    @classmethod
    def devnet(cls, host: str = "127.0.0.1", port: int = 26660) -> QuickStart:
        """Connect to local DevNet."""
        return cls(
            v2_endpoint=f"http://{host}:{port}/v2",
            v3_endpoint=f"http://{host}:{port}/v3"
        )

    @classmethod
    def kermit(cls) -> QuickStart:
        """Connect to Kermit public testnet."""
        return cls(
            v2_endpoint="https://kermit.accumulatenetwork.io/v2",
            v3_endpoint="https://kermit.accumulatenetwork.io/v3"
        )

    @classmethod
    def testnet(cls) -> QuickStart:
        """Connect to Accumulate testnet."""
        return cls(
            v2_endpoint="https://testnet.accumulatenetwork.io/v2",
            v3_endpoint="https://testnet.accumulatenetwork.io/v3"
        )

    def close(self) -> None:
        """Close the client connection."""
        self.client.close()

    def create_wallet(self) -> Wallet:
        """
        Create a new wallet with lite accounts.

        Returns:
            Wallet with keypair and derived URLs
        """
        from .crypto.ed25519 import Ed25519KeyPair

        # Generate keypair
        keypair = Ed25519KeyPair.generate()
        public_key_bytes = keypair.public_key_bytes()
        public_key_hash = hashlib.sha256(public_key_bytes).digest()

        # Derive lite URLs (with proper checksum)
        lite_identity = keypair.derive_lite_identity_url()
        lite_token_account = keypair.derive_lite_token_account_url("ACME")

        return Wallet(
            keypair=keypair,
            lite_identity=lite_identity,
            lite_token_account=lite_token_account,
            public_key_hash=public_key_hash.hex()
        )

    def fund_wallet(
        self,
        wallet: Wallet,
        times: int = 5,
        wait_seconds: int = 15
    ) -> None:
        """
        Fund a wallet from the faucet.

        Args:
            wallet: Wallet to fund
            times: Number of faucet requests
            wait_seconds: Seconds to wait after funding
        """
        import requests

        print(f"Funding wallet from faucet ({times} times)...")

        for i in range(times):
            try:
                response = requests.post(
                    self._v2_endpoint,
                    json={
                        "jsonrpc": "2.0",
                        "method": "faucet",
                        "params": {
                            "url": wallet.lite_token_account
                        },
                        "id": i + 1
                    },
                    timeout=30
                )
                result = response.json()
                txid = result.get("result", {}).get("txid", "submitted")
                print(f"  Faucet {i+1}/{times}: {txid[:40] if len(str(txid)) > 40 else txid}...")
                time.sleep(2)
            except Exception as e:
                print(f"  Faucet {i+1}/{times} failed: {e}")

        if wait_seconds > 0:
            print(f"Waiting {wait_seconds}s for transactions to process...")
            time.sleep(wait_seconds)

    def get_balance(self, wallet: Wallet) -> int:
        """
        Get wallet ACME balance.

        Args:
            wallet: Wallet to check

        Returns:
            Balance in smallest units
        """
        try:
            result = self.client.v3.query(wallet.lite_token_account)
            balance = result.get("account", {}).get("balance", "0")
            return int(balance)
        except Exception:
            return 0

    def get_oracle_price(self) -> int:
        """Get current oracle price."""
        from . import NetworkStatusOptions
        result = self.client.v3.network_status(NetworkStatusOptions(partition="directory"))
        return result.get("oracle", {}).get("price", 500000)

    def setup_adi(self, wallet: Wallet, adi_name: str) -> ADI:
        """
        Create a complete ADI with key book and page.

        This is a high-level operation that:
        1. Adds credits to the lite identity
        2. Creates the ADI with key book
        3. Returns the ADI info

        Args:
            wallet: Funded wallet to use
            adi_name: ADI name (without .acme suffix)

        Returns:
            ADI object with all URLs
        """
        from .crypto.ed25519 import Ed25519KeyPair

        # Generate ADI keypair
        adi_keypair = Ed25519KeyPair.generate()
        adi_public_key = adi_keypair.public_key_bytes()
        adi_key_hash = hashlib.sha256(adi_public_key).digest()

        adi_url = f"acc://{adi_name}.acme"
        book_url = f"{adi_url}/book"
        key_page_url = f"{book_url}/1"

        # Get oracle price and add credits to lite identity
        oracle = self.get_oracle_price()
        credits = 1000
        amount = (credits * 10000000000) // oracle

        print(f"Adding credits to lite identity...")

        # Create signer for lite identity
        signer = SmartSigner(self.client.v3, wallet.keypair, wallet.lite_identity)

        # Add credits
        result = signer.sign_submit_and_wait(
            principal=wallet.lite_token_account,
            body=TxBody.add_credits(wallet.lite_identity, str(amount), oracle),
            memo="Add credits for ADI creation"
        )

        if not result.success:
            print(f"Warning: Add credits may have failed: {result.error}")

        time.sleep(5)

        # Create identity
        print(f"Creating ADI: {adi_url}")
        result = signer.sign_submit_and_wait(
            principal=wallet.lite_token_account,
            body=TxBody.create_identity(adi_url, book_url, adi_key_hash.hex()),
            memo=f"Create ADI: {adi_name}"
        )

        if result.success:
            print(f"  ADI created: {result.txid}")

        time.sleep(5)

        return ADI(
            url=adi_url,
            key_book_url=book_url,
            key_page_url=key_page_url,
            keypair=adi_keypair,
            public_key_hash=adi_key_hash.hex()
        )

    def buy_credits_for_adi(
        self,
        wallet: Wallet,
        adi: ADI,
        credits: int = 500
    ) -> None:
        """
        Buy credits for an ADI's key page.

        Args:
            wallet: Funded wallet
            adi: ADI to fund
            credits: Number of credits to buy
        """
        oracle = self.get_oracle_price()
        amount = (credits * 10000000000) // oracle

        print(f"Buying {credits} credits for ADI key page...")

        signer = SmartSigner(self.client.v3, wallet.keypair, wallet.lite_identity)
        result = signer.sign_submit_and_wait(
            principal=wallet.lite_token_account,
            body=TxBody.add_credits(adi.key_page_url, str(amount), oracle),
            memo=f"Buy {credits} credits for ADI"
        )

        if result.success:
            print(f"  Credits purchased: {result.txid}")

    def get_key_page_info(self, key_page_url: str) -> Optional[KeyPageInfo]:
        """
        Get key page information.

        Args:
            key_page_url: Key page URL

        Returns:
            KeyPageInfo or None if not found
        """
        try:
            km = KeyManager(self.client.v3, key_page_url)
            return km.get_key_page_state()
        except Exception:
            return None

    def create_token_account(self, adi: ADI, account_name: str) -> None:
        """
        Create a token account under an ADI.

        Args:
            adi: ADI to create account under
            account_name: Account name
        """
        account_url = f"{adi.url}/{account_name}"
        print(f"Creating token account: {account_url}")

        signer = SmartSigner(self.client.v3, adi.keypair, adi.key_page_url)
        result = signer.sign_submit_and_wait(
            principal=adi.url,
            body=TxBody.create_token_account(account_url),
            memo=f"Create token account: {account_name}"
        )

        if result.success:
            print(f"  Token account created: {result.txid}")

    def create_data_account(self, adi: ADI, account_name: str) -> None:
        """
        Create a data account under an ADI.

        Args:
            adi: ADI to create account under
            account_name: Account name
        """
        account_url = f"{adi.url}/{account_name}"
        print(f"Creating data account: {account_url}")

        signer = SmartSigner(self.client.v3, adi.keypair, adi.key_page_url)
        result = signer.sign_submit_and_wait(
            principal=adi.url,
            body=TxBody.create_data_account(account_url),
            memo=f"Create data account: {account_name}"
        )

        if result.success:
            print(f"  Data account created: {result.txid}")

    def write_data(self, adi: ADI, account_name: str, entries: List[str]) -> None:
        """
        Write data entries to a data account.

        Args:
            adi: ADI containing the data account
            account_name: Data account name
            entries: List of string entries to write
        """
        account_url = f"{adi.url}/{account_name}"
        print(f"Writing {len(entries)} entries to {account_url}")

        signer = SmartSigner(self.client.v3, adi.keypair, adi.key_page_url)
        result = signer.sign_submit_and_wait(
            principal=account_url,
            body=TxBody.write_data_strings(entries),
            memo="Write data"
        )

        if result.success:
            print(f"  Data written: {result.txid}")

    def add_key_to_adi(self, adi: ADI, new_keypair: Any) -> None:
        """
        Add a key to an ADI's key page.

        Args:
            adi: ADI to modify
            new_keypair: Keypair to add
        """
        print(f"Adding key to {adi.key_page_url}")

        signer = SmartSigner(self.client.v3, adi.keypair, adi.key_page_url)
        result = signer.add_key(new_keypair)

        if result.success:
            print(f"  Key added: {result.txid}")

    def set_multisig_threshold(self, adi: ADI, threshold: int) -> None:
        """
        Set multi-sig threshold for an ADI.

        Args:
            adi: ADI to modify
            threshold: New threshold value
        """
        print(f"Setting threshold to {threshold} for {adi.key_page_url}")

        signer = SmartSigner(self.client.v3, adi.keypair, adi.key_page_url)
        result = signer.set_threshold(threshold)

        if result.success:
            print(f"  Threshold set: {result.txid}")


# =============================================================================
# Exports
# =============================================================================

__all__ = [
    # Data classes
    "SubmitResult",
    "Wallet",
    "ADI",
    "KeyPageInfo",
    # Main classes
    "TxBody",
    "SmartSigner",
    "KeyManager",
    "QuickStart",
]
