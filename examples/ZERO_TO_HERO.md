# Zero to Hero: Accumulate Python SDK Guide

This guide walks you through using the Accumulate Python SDK from key generation to advanced operations.

## Quick Start

### 1. Install

```bash
pip install accumulate-sdk-opendlt
```

Or from source:

```bash
git clone https://github.com/opendlt/accumulate-python-sdk.git
cd accumulate-python-sdk/unified
pip install -e ".[dev]"
```

### 2. Run the QuickStart Demo

```bash
python examples/v3/example_12_quickstart_demo.py
```

This single example creates a wallet, funds it, creates an ADI, token accounts, data accounts, and more.

## Step-by-Step Guide

### Step 1: Generate Keys and URLs

```python
from accumulate_client.crypto.ed25519 import Ed25519KeyPair

# Generate Ed25519 keypair
kp = Ed25519KeyPair.generate()

# Derive Lite Identity and Token Account URLs
lid = kp.derive_lite_identity_url()
lta = kp.derive_lite_token_account_url("ACME")

print(f"Lite Identity: {lid}")
print(f"Lite Token Account: {lta}")
```

**Output:**
- Lite Identity (LID): `acc://{hash40}{checksum8}` — for signing transactions
- Lite Token Account (LTA): `acc://{hash40}{checksum8}/ACME` — for receiving ACME tokens

### Step 2: Connect to Kermit Testnet

```python
from accumulate_client import Accumulate

client = Accumulate(
    "https://kermit.accumulatenetwork.io/v2",
    v3_endpoint="https://kermit.accumulatenetwork.io/v3",
)
```

Or use factory methods:

```python
client = Accumulate.testnet()    # Generic testnet
client = Accumulate.devnet()     # Local DevNet (localhost:26660)
client = Accumulate.mainnet()    # Mainnet (production)
```

### Step 3: Fund from Faucet

```python
# Request tokens from Kermit faucet
result = client.faucet(lta)
print(f"Faucet TxID: {result}")
```

### Step 4: Set Up SmartSigner

```python
from accumulate_client.convenience import SmartSigner, TxBody

# SmartSigner automatically tracks signer version
signer = SmartSigner(client, kp, f"{lid}/1")
```

### Step 5: Buy Credits

```python
import hashlib

oracle = client.get_oracle_price()
result = signer.sign_submit_and_wait(
    principal=lta,
    body=TxBody.add_credits(
        recipient=lid,
        amount=1000000,
        oracle=oracle,
    ),
)
print(f"AddCredits: {result.txid}")
```

### Step 6: Create an ADI

```python
# Generate ADI keypair
adi_kp = Ed25519KeyPair.generate()
adi_key_hash = hashlib.sha256(adi_kp.public_key_bytes()).digest().hex()

adi_url = "acc://my-identity.acme"
book_url = f"{adi_url}/book"

result = signer.sign_submit_and_wait(
    principal=lta,
    body=TxBody.create_identity(adi_url, book_url, adi_key_hash),
)
print(f"ADI created: {result.txid}")
```

## The QuickStart API (Easiest Path)

For rapid prototyping, use `QuickStart` which wraps all the above into single method calls:

```python
from accumulate_client.convenience import QuickStart

# Connect to Kermit testnet
qs = QuickStart.kermit()

# Create and fund a wallet
wallet = qs.create_wallet()
qs.fund_wallet(wallet)

# Create an ADI with key book and page
adi = qs.setup_adi(wallet, "my-adi-name")

# Create a token account under the ADI
qs.create_token_account(adi, "tokens")

# Create a data account and write data
qs.create_data_account(adi, "mydata")
qs.write_data(adi, "mydata", ["Hello", "World"])
```

## Key Concepts

### URL Structure

Accumulate uses hierarchical URLs:

- **Lite Identity**: `acc://{hash40}{checksum8}`
- **Lite Token Account**: `acc://{hash40}{checksum8}/ACME`
- **ADI**: `acc://my-identity.acme`
- **ADI Sub-account**: `acc://my-identity.acme/tokens`

### API Levels

| Level | Class | Best For |
|-------|-------|----------|
| High | `QuickStart` | Prototyping, scripts, learning |
| Mid | `SmartSigner` + `TxBody` | Production apps with full control |
| Low | `AccumulateV3Client` | Custom protocols, raw JSON-RPC |

### API Versions

- **V2 API**: Stable, used for faucet and basic queries
- **V3 API**: Full features, transaction submission, network status

## Common Operations

### Query Account

```python
result = client.query("acc://my-identity.acme/tokens")
print(f"Balance: {result.get('balance')}")
```

### Send Tokens

```python
result = signer.sign_submit_and_wait(
    principal="acc://my-identity.acme/tokens",
    body=TxBody.send_tokens_single(
        to_url="acc://recipient.acme/tokens",
        amount="100000000",
    ),
)
```

### Write Data

```python
import binascii

entries_hex = [binascii.hexlify(b"Hello, Accumulate!").decode()]
result = signer.sign_submit_and_wait(
    principal="acc://my-identity.acme/data",
    body=TxBody.write_data(entries_hex=entries_hex),
)
```

## Error Handling

```python
from accumulate_client.api_client import (
    AccumulateAPIError,
    AccumulateNetworkError,
    AccumulateValidationError,
)

try:
    result = client.query("acc://nonexistent.acme")
except AccumulateValidationError as e:
    print(f"Validation error: {e}")
except AccumulateNetworkError as e:
    print(f"Network error: {e}")
except AccumulateAPIError as e:
    print(f"API error: {e}")
```

## Complete Examples

See [`v3/`](v3/) for 12 complete, runnable examples that cover every major SDK feature.

Start with:
1. `v3/example_01_lite_identities.py` — basics
2. `v3/example_02_accumulate_identities.py` — ADI creation
3. `v3/example_12_quickstart_demo.py` — everything in one script

## Resources

- [Accumulate Protocol](https://accumulatenetwork.io/)
- [API Documentation](https://docs.accumulatenetwork.io/)
- [Kermit Testnet Explorer](https://kermit.explorer.accumulatenetwork.io/)
