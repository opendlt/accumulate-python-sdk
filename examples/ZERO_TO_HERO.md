# Zero to Hero: Accumulate Python SDK Guide

This guide walks you through using the Accumulate Python SDK from key generation to
advanced operations.

> **Package name:** `accumulate-sdk-opendlt` on PyPI, imported as `accumulate_client`.
> If you see references to `accumulate-python-client` or imports like
> `from accumulate.api.client import ...`, those are from an older, deprecated package.
> This guide covers the current SDK only.

## Quick Start

### 1. Install

```bash
pip install accumulate-sdk-opendlt
```

Or from source:

```bash
git clone https://github.com/opendlt/accumulate-python-client.git
cd accumulate-python-client/unified
pip install -e ".[dev]"
```

### 2. Run the QuickStart Demo

```bash
python examples/v3/example_12_quickstart_demo.py
```

This single example creates a wallet, funds it, creates an ADI, token accounts, data accounts, and more.

## Understanding the Three API Levels

The SDK provides three levels of abstraction. Each layer builds on the one below it.

### Level 1: QuickStart (Highest)

`QuickStart` wraps entire multi-transaction workflows into single method calls. Under
the hood, each method creates a `SmartSigner`, builds a `TxBody`, signs, submits, and
polls for delivery.

**Best for:** Learning, prototyping, scripts, demos.

```python
from accumulate_client.convenience import QuickStart

qs = QuickStart.kermit()
wallet = qs.create_wallet()
qs.fund_wallet(wallet)
adi = qs.setup_adi(wallet, "my-adi-name")
```

### Level 2: SmartSigner + TxBody (Mid)

`SmartSigner` handles signer version tracking and the complete sign/submit/poll
lifecycle. `TxBody` is a static factory class that returns correctly-structured
transaction body dicts. Together they give you per-transaction control while hiding all
binary encoding and hash computation.

**Best for:** Production applications, any code that needs explicit control over each
transaction.

**What SmartSigner does under the hood (in order):**
1. Queries the network for the current signer version (key page version)
2. Binary-encodes signature metadata (type=ED25519, public key, signer URL, version, timestamp)
3. Computes `initiator = SHA256(signature_metadata_binary)`
4. Binary-encodes the transaction header (principal URL + initiator hash + optional memo)
5. Binary-encodes the transaction body using type-specific field encoding
6. Computes `tx_hash = SHA256( SHA256(header_binary) + SHA256(body_binary) )`
7. Computes `signing_preimage = SHA256(initiator + tx_hash)`
8. Signs the 32-byte preimage with Ed25519
9. Assembles the JSON envelope: `{transaction: {header, body}, signatures: [...]}`
10. Submits the envelope via V3 JSON-RPC (`execute` method)
11. Polls the transaction ID until the network reports delivered or failed

**What TxBody does:** Each static method returns a plain Python dict with the correct
JSON field names and structure for that transaction type.

```python
from accumulate_client.convenience import SmartSigner, TxBody

signer = SmartSigner(client.v3, keypair, f"{lite_identity}/1")
result = signer.sign_submit_and_wait(
    principal=lite_token_account,
    body=TxBody.add_credits(lite_identity, str(amount), oracle),
)
```

### Level 3: Raw Binary Encoding (Lowest)

Build envelopes manually using the binary encoding helpers exported from
`accumulate_client.convenience`:

- `_encode_uvarint(val)` — unsigned variable-length integer (ULEB128)
- `_field_bytes(field_num, val)` — length-prefixed byte field
- `_field_string(field_num, val)` — length-prefixed UTF-8 string field
- `_field_uvarint(field_num, val)` — uvarint field
- `_encode_ed25519_sig_metadata(...)` — binary signature metadata
- `_encode_tx_header(...)` — binary transaction header
- `_encode_tx_body(body)` — binary transaction body
- `_compute_tx_hash_and_sign(...)` — full sign pipeline returning an envelope

See [example_14](v3/example_14_low_level_adi_creation.py) for a complete walkthrough
that does everything example_02 does, but without any convenience methods.

**Best for:** Understanding the protocol, custom signing flows, cross-language
compatibility testing.

## Step-by-Step Guide (SmartSigner Level)

### Step 1: Generate Keys and URLs

```python
from accumulate_client.crypto.ed25519 import Ed25519KeyPair

kp = Ed25519KeyPair.generate()
lid = kp.derive_lite_identity_url()     # signing identity
lta = kp.derive_lite_token_account_url("ACME")  # receives tokens

print(f"Lite Identity: {lid}")
print(f"Lite Token Account: {lta}")
```

**Output:**
- Lite Identity (LID): `acc://{hash40}{checksum8}` — for signing transactions
- Lite Token Account (LTA): `acc://{hash40}{checksum8}/ACME` — for receiving ACME tokens

### Step 2: Connect to Kermit Testnet

```python
from accumulate_client import Accumulate

client = Accumulate("https://kermit.accumulatenetwork.io")
```

### Step 3: Fund from Faucet

The faucet is a V2-only JSON-RPC method. The examples use `requests.post()` directly:

```python
import requests
response = requests.post(
    "https://kermit.accumulatenetwork.io/v2",
    json={"jsonrpc": "2.0", "method": "faucet", "params": {"url": lta}, "id": 1},
    timeout=30,
)
```

### Step 4: Set Up SmartSigner

```python
from accumulate_client.convenience import SmartSigner, TxBody

# SmartSigner auto-queries signer version from the network
signer = SmartSigner(client.v3, kp, lid)
```

### Step 5: Buy Credits

```python
# TxBody.add_credits() returns: {"type": "addCredits", "recipient": ..., "amount": ..., "oracle": ...}
# SmartSigner handles: binary encode → hash → sign → submit → poll
result = signer.sign_submit_and_wait(
    principal=lta,
    body=TxBody.add_credits(lid, str(amount), oracle),
)
print(f"AddCredits: {result.txid}")
```

### Step 6: Create an ADI

```python
import hashlib

adi_kp = Ed25519KeyPair.generate()
adi_key_hash = hashlib.sha256(adi_kp.public_key_bytes()).digest().hex()

adi_url = "acc://my-identity.acme"
book_url = f"{adi_url}/book"

# TxBody.create_identity() returns: {"type": "createIdentity", "url": ..., "keyBookUrl": ..., "keyHash": ...}
result = signer.sign_submit_and_wait(
    principal=lta,
    body=TxBody.create_identity(adi_url, book_url, adi_key_hash),
)
print(f"ADI created: {result.txid}")
```

## Convenience Method Reference

| Method | Returns / Does |
|--------|---------------|
| `TxBody.add_credits(recipient, amount, oracle)` | `{"type": "addCredits", "recipient": ..., "amount": ..., "oracle": ...}` |
| `TxBody.create_identity(url, book_url, key_hash)` | `{"type": "createIdentity", "url": ..., "keyBookUrl": ..., "keyHash": ...}` |
| `TxBody.send_tokens_single(to_url, amount)` | `{"type": "sendTokens", "to": [{"url": ..., "amount": ...}]}` |
| `TxBody.create_token_account(url, token_url)` | `{"type": "createTokenAccount", "url": ..., "tokenUrl": ...}` |
| `TxBody.write_data(entries_hex)` | `{"type": "writeData", "entry": {"type": "doubleHash", "data": [...]}}` |
| `TxBody.create_token(url, symbol, precision)` | `{"type": "createToken", "url": ..., "symbol": ..., "precision": ...}` |
| `TxBody.update_key_page(operations)` | `{"type": "updateKeyPage", "operation": [...]}` |
| `SmartSigner.sign_and_build(principal, body)` | Builds signed envelope without submitting |
| `SmartSigner.sign_submit_and_wait(principal, body)` | Full lifecycle: sign → submit → poll → `SubmitResult` |
| `QuickStart.create_wallet()` | Generates keypair, derives lite identity/token URLs |
| `QuickStart.fund_wallet(wallet)` | Faucet + add credits in one call |
| `QuickStart.setup_adi(wallet, name)` | CreateIdentity + fund key page in one call |

## Key Concepts

### URL Structure

Accumulate uses hierarchical URLs:

- **Lite Identity**: `acc://{hash40}{checksum8}`
- **Lite Token Account**: `acc://{hash40}{checksum8}/ACME`
- **ADI**: `acc://my-identity.acme`
- **ADI Sub-account**: `acc://my-identity.acme/tokens`

### API Versions

- **V2 API**: Stable, used for faucet and basic queries
- **V3 API**: Full features, transaction submission, network status

## Common Operations

### Query Account

```python
result = client.v3.query("acc://my-identity.acme/tokens")
print(f"Balance: {result.get('account', {}).get('balance')}")
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
from accumulate_client.runtime.errors import (
    AccumulateError,
    ValidationError,
    NetworkError,
)

try:
    result = client.v3.query("acc://nonexistent.acme")
except ValidationError as e:
    print(f"Validation error: {e}")
except NetworkError as e:
    print(f"Network error: {e}")
except AccumulateError as e:
    print(f"API error: {e}")
```

## Complete Examples

See [`v3/`](v3/) for complete, runnable examples that cover every major SDK feature.

Start with:
1. `v3/example_01_lite_identities.py` — basics (SmartSigner level)
2. `v3/example_02_accumulate_identities.py` — ADI creation (SmartSigner level)
3. `v3/example_12_quickstart_demo.py` — everything in one script (QuickStart level)
4. `v3/example_14_low_level_adi_creation.py` — same as #2 but no convenience methods (raw level)

## Resources

- [Accumulate Protocol](https://accumulatenetwork.io/)
- [API Documentation](https://docs.accumulatenetwork.io/)
- [Kermit Testnet Explorer](https://kermit.explorer.accumulatenetwork.io/)
- [PyPI Package](https://pypi.org/project/accumulate-sdk-opendlt/)
