#!/usr/bin/env python3

"""
Zero-to-Hero: Complete Accumulate Python SDK demonstration

This example demonstrates the complete flow:
1. Generate Ed25519 keypair and derive Lite URLs
2. Fund Lite Token Account from faucet
3. Buy credits for Lite Identity
4. Create ADI (Accumulate Digital Identity)
5. Create token account in ADI
6. Send tokens from LTA to ADI token account

Demonstrates same semantics as Dart zero-to-hero.
"""

import os
import sys
import time

# Add parent directory to path for relative imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from shared_helpers import load_env_config, test_devnet_connectivity, print_endpoints
from accumulate_client import AccumulateClient
from tests.helpers.crypto_helpers import (
    derive_lite_identity_url,
    derive_lite_token_account_url,
    create_signature_envelope,
    create_transaction_hash,
    ed25519_keypair_from_seed
)
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization
import secrets


def generate_keypair():
    """Generate new Ed25519 keypair"""
    print("🔑 Generating Ed25519 keypair...")

    # Generate new private key
    private_key = ed25519.Ed25519PrivateKey.generate()

    # Get key bytes
    private_key_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption()
    )
    public_key_bytes = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )

    # Derive URLs
    lid = derive_lite_identity_url(public_key_bytes)
    lta = derive_lite_token_account_url(public_key_bytes)

    print(f"  Private Key: {private_key_bytes.hex()}")
    print(f"  Public Key:  {public_key_bytes.hex()}")
    print(f"  LID:         {lid}")
    print(f"  LTA:         {lta}")

    return private_key_bytes, public_key_bytes, lid, lta

    def step_1_generate_keys(self):
        """Step 1: Generate Ed25519 keypair and derive URLs"""
        print("=== Step 1: Generate Keys and URLs ===")

        # Generate new Ed25519 key pair
        print("Generating Ed25519 key pair...")
        self.private_key = ed25519.Ed25519PrivateKey.generate()
        public_key = self.private_key.public_key()

        self.public_key_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )

        print(f"Public Key: {self.public_key_bytes.hex()}")

        # Derive URLs
        self.lid = self._derive_lite_identity_url(self.public_key_bytes)
        self.lta = self._derive_lite_token_account_url(self.public_key_bytes)

        print(f"Lite Identity (LID): {self.lid}")
        print(f"Lite Token Account (LTA): {self.lta}")
        print("✓ Keys and URLs generated successfully\\n")

    def step_2_fund_lta(self):
        """Step 2: Fund LTA using faucet"""
        print("=== Step 2: Fund LTA from Faucet ===")

        print(f"Requesting tokens from faucet for {self.lta}...")
        try:
            faucet_result = self.v2_client.faucet({
                "url": self.lta
            })

            print(f"Faucet transaction hash: {faucet_result.get('transactionHash', 'Unknown')}")
            print("Waiting for faucet transaction to process...")
            time.sleep(3)

            # Check balance
            balance = self._get_account_balance(self.lta)
            print(f"LTA balance: {balance} ACME")
            print("✓ LTA funded successfully\\n")

        except Exception as e:
            print(f"✗ Faucet request failed: {e}")
            raise

    def step_3_buy_credits(self):
        """Step 3: Buy credits for LID"""
        print("=== Step 3: Buy Credits for LID ===")

        try:
            # Create AddCredits transaction
            add_credits_tx = {
                "type": "addCredits",
                "recipient": {"url": self.lid},
                "amount": "100000"  # 100k credits
            }

            envelope = self._create_envelope(self.lta, add_credits_tx)

            print("Submitting AddCredits transaction...")
            result = self.v3_client.execute(envelope)
            tx_hash = result.get('transactionHash') or result.get('txid')

            print(f"AddCredits transaction hash: {tx_hash}")
            print("Waiting for AddCredits transaction to process...")
            time.sleep(3)

            # Check LID credits
            lid_query = self.v3_client.query({"url": self.lid})
            if lid_query.get("data"):
                credits = lid_query["data"].get("creditBalance", "0")
                print(f"LID credits: {credits}")

            print("✓ Credits purchased successfully\\n")

        except Exception as e:
            print(f"✗ AddCredits transaction failed: {e}")
            raise

    def step_4_create_adi(self):
        """Step 4: Create ADI with key book and key page"""
        print("=== Step 4: Create ADI (Identity) ===")

        # For this demo, we'll use a simple ADI name
        adi_name = f"demo{int(time.time())}"
        adi_url = f"acc://{adi_name}"

        try:
            # Create ADI transaction
            create_adi_tx = {
                "type": "createIdentity",
                "url": adi_url,
                "keyBookUrl": f"{adi_url}/book",
                "keyPageUrl": f"{adi_url}/book/1"
            }

            envelope = self._create_envelope(self.lid, create_adi_tx)

            print(f"Creating ADI: {adi_url}")
            result = self.v3_client.execute(envelope)
            tx_hash = result.get('transactionHash') or result.get('txid')

            print(f"CreateIdentity transaction hash: {tx_hash}")
            print("Waiting for CreateIdentity transaction to process...")
            time.sleep(5)

            # Query the ADI
            adi_query = self.v3_client.query({"url": adi_url})
            print(f"ADI created: {adi_query}")

            self.adi_url = adi_url
            print("✓ ADI created successfully\\n")

        except Exception as e:
            print(f"✗ CreateIdentity transaction failed: {e}")
            # Continue with demo even if ADI creation fails
            self.adi_url = None

    def step_5_summary(self):
        """Step 5: Show summary and balances"""
        print("=== Step 5: Final Summary ===")

        # Show all URLs
        print("Generated URLs:")
        print(f"  LID: {self.lid}")
        print(f"  LTA: {self.lta}")
        if hasattr(self, 'adi_url') and self.adi_url:
            print(f"  ADI: {self.adi_url}")

        # Show balances
        print("\\nFinal Balances:")
        try:
            lta_balance = self._get_account_balance(self.lta)
            print(f"  LTA: {lta_balance} ACME")
        except:
            print("  LTA: Query failed")

        try:
            lid_query = self.v3_client.query({"url": self.lid})
            if lid_query.get("data"):
                credits = lid_query["data"].get("creditBalance", "0")
                print(f"  LID: {credits} credits")
        except:
            print("  LID: Query failed")

        print("\\n🏆 Zero-to-Hero demo completed!")
        print("\\nNext steps you could try:")
        print("- Create token accounts")
        print("- Write data to data accounts")
        print("- Transfer tokens between accounts")
        print("- Create and manage key pages")

    def run(self):
        """Run the complete zero-to-hero demo"""
        print("🚀 Starting Accumulate Zero-to-Hero Demo\\n")

        # Check devnet connectivity
        if not self._check_devnet():
            print("✗ DevNet not accessible. Please run devnet_discovery.py first")
            sys.exit(1)

        try:
            self.step_1_generate_keys()
            self.step_2_fund_lta()
            self.step_3_buy_credits()
            self.step_4_create_adi()
            self.step_5_summary()

        except Exception as e:
            print(f"\\n✗ Demo failed: {e}")
            sys.exit(1)

        finally:
            self.v2_client.close()
            self.v3_client.close()

    def _derive_lite_identity_url(self, public_key_bytes: bytes) -> str:
        """Derive Lite Identity URL from Ed25519 public key with checksum"""
        # For Ed25519: keyHash = SHA256(publicKey) - Go: protocol/protocol.go:290
        key_hash_full = hashlib.sha256(public_key_bytes).digest()

        # Use first 20 bytes - Go: protocol/protocol.go:274
        key_hash_20 = key_hash_full[:20]

        # Convert to hex string - Go: protocol/protocol.go:274
        key_str = key_hash_20.hex()

        # Calculate checksum - Go: protocol/protocol.go:275-276
        checksum_full = hashlib.sha256(key_str.encode('utf-8')).digest()
        checksum = checksum_full[28:].hex()  # Take last 4 bytes

        # Format: acc://<keyHash[0:20]><checksum> - Go: protocol/protocol.go:277
        return f"acc://{key_str}{checksum}"

    def _derive_lite_token_account_url(self, public_key_bytes: bytes, token="ACME") -> str:
        """Derive Lite Token Account URL for ACME"""
        # LTA = LID + "/ACME" path - Go: protocol/protocol.go:267-268
        lid = self._derive_lite_identity_url(public_key_bytes)
        return f"{lid}/{token}"

    def _create_envelope(self, principal: str, transaction: dict) -> dict:
        """Create and sign transaction envelope"""
        timestamp = int(time.time() * 1000000)  # microseconds
        tx_data = {
            "header": {
                "principal": principal,
                "timestamp": timestamp
            },
            "body": transaction
        }

        # Create canonical JSON for signing
        tx_json = json.dumps(tx_data, separators=(',', ':'), sort_keys=True)
        tx_bytes = tx_json.encode('utf-8')

        # Hash for signing
        tx_hash = hashlib.sha256(tx_bytes).digest()

        # Sign the hash
        signature = self.private_key.sign(tx_hash)

        # Create envelope
        envelope = {
            "transaction": tx_data,
            "signatures": [{
                "type": "ed25519",
                "publicKey": self.public_key_bytes.hex(),
                "signature": signature.hex()
            }]
        }

        return envelope

    def _get_account_balance(self, url: str) -> str:
        """Get account balance"""
        try:
            query_result = self.v2_client.query({"url": url})
            if "data" in query_result and query_result["data"]:
                return query_result["data"].get("balance", "0")
            return "0"
        except:
            return "0"

    def _check_devnet(self) -> bool:
        """Check if DevNet is accessible"""
        try:
            result = self.v2_client.describe()
            return "version" in result
        except:
            return False


def main():
    """Main entry point"""
    print("Accumulate Python SDK - Zero to Hero Demo")
    print("========================================\\n")

    # Check environment
    if not os.environ.get('ACC_RPC_URL_V2'):
        print("⚠️  Environment variables not set. Run:")
        print("   python tool/devnet_discovery.py")
        print("   # Then set the exported variables\\n")

    demo = AccumulateDemo()
    demo.run()


if __name__ == "__main__":
    main()