# Examples

Complete usage examples for the Accumulate Python SDK (`accumulate-sdk-opendlt`).

> **Important:** This SDK is published as `accumulate-sdk-opendlt` on PyPI and imported as
> `accumulate_client`. If you see references to a different package name or import path
> (e.g., `from accumulate.api.client import ...`), those refer to an older, deprecated SDK.
> All examples here use the current SDK exclusively.

## Quick Start

```bash
pip install accumulate-sdk-opendlt
python examples/v3/example_01_lite_identities.py
```

## SDK API Levels

The SDK provides three levels of abstraction. Pick the one that fits your use case:

### Level 1: QuickStart (Highest — for prototyping and scripts)

`QuickStart` wraps everything into single method calls. Under the hood it creates a
`SmartSigner`, calls `TxBody` factory methods, signs, submits, and polls for you.

```python
from accumulate_client.convenience import QuickStart

qs = QuickStart.kermit()
wallet = qs.create_wallet()       # generates keypair, derives URLs
qs.fund_wallet(wallet)            # faucet + add credits in one call
adi = qs.setup_adi(wallet, "my-adi")  # createIdentity + fund key page
```

### Level 2: SmartSigner + TxBody (Mid — for production apps)

`SmartSigner` handles signer version tracking and the entire sign → submit → poll
lifecycle. `TxBody` is a static factory that builds correctly-shaped transaction body
dicts. Together they hide all binary encoding, hash computation, and envelope
construction while giving you full control over each transaction.

**What SmartSigner does under the hood:**
1. Queries the network for the current signer version (key page version)
2. Binary-encodes signature metadata (type, public key, signer URL, version, timestamp)
3. Computes `initiator = SHA256(signature_metadata_binary)`
4. Binary-encodes the transaction header (principal URL + initiator hash)
5. Binary-encodes the transaction body (type-specific field encoding)
6. Computes `tx_hash = SHA256(SHA256(header_binary) + SHA256(body_binary))`
7. Computes `signing_preimage = SHA256(initiator + tx_hash)`
8. Signs the preimage with Ed25519
9. Builds the JSON envelope with transaction + signature
10. Submits via V3 JSON-RPC and polls until delivered or failed

**What TxBody does:** Returns a plain dict with the correct field names and structure
for each transaction type (e.g., `sendTokens` needs `to: [{url, amount}]`).

```python
from accumulate_client.convenience import SmartSigner, TxBody

signer = SmartSigner(client.v3, keypair, f"{lite_identity}/1")
result = signer.sign_submit_and_wait(
    principal=lite_token_account,
    body=TxBody.add_credits(recipient=lite_identity, amount="1000000", oracle=oracle),
)
```

### Level 3: Raw Binary Encoding (Lowest — for custom protocols)

Use `AccumulateV3Client` directly for JSON-RPC calls, and the binary encoding helpers
in `accumulate_client.convenience` for manual envelope construction. See
[example_14](v3/example_14_low_level_adi_creation.py) for a complete walkthrough.

## Available Examples

| Example | API Level | Description |
|---------|-----------|-------------|
| `v3/example_01_lite_identities.py` | SmartSigner | Create lite identity and token accounts, faucet integration |
| `v3/example_02_accumulate_identities.py` | SmartSigner | Create Accumulate Digital Identifier (ADI) |
| `v3/example_03_adi_token_accounts.py` | SmartSigner | ADI token account management |
| `v3/example_04_data_accounts_entries.py` | SmartSigner | Data account creation and WriteData operations |
| `v3/example_05_adi_to_adi_transfer.py` | SmartSigner | ADI-to-ADI token transfers |
| `v3/example_06_custom_tokens.py` | SmartSigner | Custom token issuer creation |
| `v3/example_08_query_tx_signatures.py` | SmartSigner | Transaction and signature queries |
| `v3/example_09_key_management.py` | SmartSigner | Key page and key book management |
| `v3/example_10_update_key_page_threshold.py` | SmartSigner | Multi-sig threshold updates |
| `v3/example_11_multi_signature_types.py` | SmartSigner | Ed25519, RCD1, BTC, ETH signatures |
| `v3/example_12_quickstart_demo.py` | QuickStart | Complete zero-to-hero workflow |
| `v3/example_13_adi_to_adi_transfer_with_header_options.py` | SmartSigner | Memo, metadata, expire, hold_until |
| `v3/example_14_low_level_adi_creation.py` | Raw | Same as example_02 but with no convenience methods |

## Convenience Method Reference

| Method | What it does for you |
|--------|---------------------|
| `TxBody.add_credits(recipient, amount, oracle)` | Returns `{"type": "addCredits", "recipient": ..., "amount": ..., "oracle": ...}` |
| `TxBody.create_identity(url, key_book_url, key_hash)` | Returns `{"type": "createIdentity", "url": ..., "keyBookUrl": ..., "keyHash": ...}` |
| `TxBody.send_tokens_single(to_url, amount)` | Returns `{"type": "sendTokens", "to": [{"url": ..., "amount": ...}]}` |
| `TxBody.create_token_account(url, token_url)` | Returns `{"type": "createTokenAccount", "url": ..., "tokenUrl": ...}` |
| `TxBody.write_data(entries_hex)` | Returns `{"type": "writeData", "entry": {"type": "doubleHash", "data": [...]}}` |
| `SmartSigner.sign_and_build(principal, body)` | Binary-encode → hash → sign → return envelope (no submit) |
| `SmartSigner.sign_submit_and_wait(principal, body)` | Binary-encode → hash → sign → submit → poll → return `SubmitResult` |
| `QuickStart.create_wallet()` | Generate keypair + derive lite identity/token account URLs |
| `QuickStart.fund_wallet(wallet)` | Faucet + add credits in one call |
| `QuickStart.setup_adi(wallet, name)` | CreateIdentity + fund key page in one call |

## Running Examples

### Against Kermit Testnet (Default)

All V3 examples default to Kermit testnet:

```bash
python examples/v3/example_01_lite_identities.py
```

### Against Local DevNet

Edit the endpoint variables at the top of any example:

```python
# Comment out Kermit endpoints:
# KERMIT_V2 = "https://kermit.accumulatenetwork.io/v2"
# KERMIT_V3 = "https://kermit.accumulatenetwork.io/v3"

# Uncomment DevNet endpoints:
KERMIT_V2 = "http://127.0.0.1:26660/v2"
KERMIT_V3 = "http://127.0.0.1:26660/v3"
```

## Network Configuration

### Kermit Testnet (Recommended)
- Faucet available for free tokens
- Stable environment for testing
- Same protocol as mainnet

### Local DevNet
- Run locally for fastest iteration
- Full protocol support
- Requires local Accumulate instance

### Mainnet (Production)
- Real tokens with value
- Use with caution
- Same API as testnet

## Troubleshooting

### Network Timeout
If examples timeout, check your network connection to Kermit testnet.

### Faucet Rate Limiting
Wait a few seconds between faucet requests, or use different accounts.

### Transaction Pending
Some transactions take multiple blocks to confirm. The SmartSigner handles waiting automatically.
