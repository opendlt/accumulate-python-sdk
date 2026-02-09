# OpenDLT Accumulate Python SDK

[![Python](https://img.shields.io/badge/Python-3.9+-blue.svg)](https://python.org)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

Production-ready Python SDK for the Accumulate blockchain protocol. Supports all signature types, V2/V3 API endpoints, and provides a high-level signing API with automatic version tracking.

## Features

- **Multi-Signature Support**: Ed25519, RCD1, BTC, ETH, RSA-SHA256, ECDSA-SHA256
- **Smart Signing**: Automatic signer version tracking with `SmartSigner`
- **Complete Protocol**: All 33 transaction types and account operations
- **Cross-Platform**: Pure Python implementation
- **Network Ready**: Mainnet, Testnet (Kermit), and local DevNet support

## Installation

```bash
pip install accumulate-sdk-opendlt
```

Or install from source:

```bash
git clone https://github.com/opendlt/accumulate-python-sdk.git
cd accumulate-python-sdk/unified
pip install -e ".[dev]"
```

## Quick Start

```python
from accumulate_client import Accumulate
from accumulate_client.crypto.ed25519 import Ed25519KeyPair

# Connect to Kermit testnet
client = Accumulate(
    "https://kermit.accumulatenetwork.io/v2",
    v3_endpoint="https://kermit.accumulatenetwork.io/v3",
)

# Generate key pair and derive lite account URLs
kp = Ed25519KeyPair.generate()
lid = kp.derive_lite_identity_url()
lta = kp.derive_lite_token_account_url("ACME")

print(f"Lite Identity: {lid}")
print(f"Lite Token Account: {lta}")

# Query account
account = client.query(lta)
print(f"Account: {account}")
```

## Smart Signing API

The `SmartSigner` class handles version tracking automatically:

```python
from accumulate_client import Accumulate
from accumulate_client.crypto.ed25519 import Ed25519KeyPair
from accumulate_client.convenience import SmartSigner, TxBody

# Connect to Kermit testnet
client = Accumulate(
    "https://kermit.accumulatenetwork.io/v2",
    v3_endpoint="https://kermit.accumulatenetwork.io/v3",
)
kp = Ed25519KeyPair.generate()
lid = kp.derive_lite_identity_url()
lta = kp.derive_lite_token_account_url("ACME")

# Create SmartSigner - automatically queries and tracks signer version
signer = SmartSigner(
    client=client,
    keypair=kp,
    signer_url=f"{lid}/1",
)

# Sign, submit, and wait for delivery in one call
result = signer.sign_submit_and_wait(
    principal=lta,
    body=TxBody.send_tokens_single(
        to_url="acc://recipient.acme/tokens",
        amount="100000000",  # 1 ACME
    ),
    memo="Payment",
)

if result.success:
    print(f"Transaction delivered: {result.txid}")
```

## Supported Signature Types

| Type | Signer Class | Use Case |
|------|-------------|----------|
| Ed25519 | `Ed25519Signer` | Default, recommended |
| Legacy Ed25519 | `LegacyEd25519Signer` | Pre-signed message format |
| RCD1 | `RCD1Signer` | Factom compatibility |
| BTC | `BTCSigner` | Bitcoin/Secp256k1 ecosystem |
| ETH | `ETHSigner` | Ethereum/Secp256k1 ecosystem |

Signer classes are in `accumulate_client.signers`.

## Transaction Builders

Build transactions using the `TxBody` class:

```python
from accumulate_client.convenience import TxBody

# Send tokens
TxBody.send_tokens_single(to_url="acc://...", amount="100000000")

# Add credits
TxBody.add_credits(recipient="acc://...", amount=1000000, oracle=oracle_price)

# Create ADI
TxBody.create_identity(url="acc://my-adi.acme", key_book_url="acc://my-adi.acme/book", public_key_hash=key_hash)

# Create token account
TxBody.create_token_account(url="acc://my-adi.acme/tokens", token_url="acc://ACME")

# Create custom token
TxBody.create_token(url="acc://my-adi.acme/mytoken", symbol="MTK", precision=8)

# Write data
TxBody.write_data(entries_hex=[data_hex])
```

## Network Endpoints

```python
from accumulate_client import Accumulate

# Public networks
mainnet = Accumulate.mainnet()
testnet = Accumulate.testnet()

# Kermit testnet (explicit endpoints)
kermit = Accumulate(
    "https://kermit.accumulatenetwork.io/v2",
    v3_endpoint="https://kermit.accumulatenetwork.io/v3",
)

# Local development
devnet = Accumulate.devnet()
```

## Examples

See [`examples/v3/`](examples/v3/) for complete working examples:

| Example | Description |
|---------|-------------|
| `example_01_lite_identities.py` | Lite identity and token account operations |
| `example_02_accumulate_identities.py` | ADI creation and credit purchasing |
| `example_03_adi_token_accounts.py` | ADI token account management |
| `example_04_data_accounts_entries.py` | Data account creation and WriteData |
| `example_05_adi_to_adi_transfer.py` | ADI-to-ADI token transfers |
| `example_06_custom_tokens.py` | Custom token issuer creation |
| `example_08_query_tx_signatures.py` | Transaction and signature queries |
| `example_09_key_management.py` | Key page and key book management |
| `example_10_update_key_page_threshold.py` | Multi-sig threshold updates |
| `example_11_multi_signature_types.py` | Ed25519, RCD1, BTC, ETH signatures |
| `example_12_quickstart_demo.py` | Complete zero-to-hero workflow |
| `example_13_adi_to_adi_transfer_with_header_options.py` | Memo, metadata, expire, hold_until |

Run any example:
```bash
python examples/v3/example_01_lite_identities.py
```

## Project Structure

```
src/accumulate_client/
├── facade.py          # Accumulate unified client (V2/V3)
├── api_client.py      # Low-level API client
├── convenience.py     # SmartSigner, TxBody, QuickStart, Wallet, ADI
├── crypto/            # Key pair implementations (Ed25519, Secp256k1)
├── signers/           # Signature type classes (Ed25519, RCD1, BTC, ETH)
├── tx/                # Transaction builders and header options
├── types.py           # Protocol types (103 types)
├── enums.py           # Protocol enums (14 enums)
└── runtime/           # URL handling, codecs, validation
examples/
└── v3/                # V3 API examples with SmartSigner (12 examples)
tests/
├── unit/              # Unit tests
├── integration/       # Network integration tests
└── conformance/       # Cross-implementation compatibility
```

## Development

### Running Tests
```bash
pytest tests/                    # All tests
pytest tests/unit/               # Unit tests only
pytest tests/integration/        # Integration tests (requires network)
```

### Code Quality
```bash
ruff check src/
mypy src/
ruff format src/
```

### Self-Check
```bash
python tooling/scripts/selfcheck.py
```

Expected output:
```
Status: PASS
Checks: 11/11 passed (100.0%)
Enums=14, Types=103, Signatures=16, Transactions=33, API methods=35
```

## Error Handling

```python
from accumulate_client.api_client import (
    AccumulateAPIError,
    AccumulateNetworkError,
    AccumulateValidationError,
)

try:
    result = client.submit(envelope)
except AccumulateValidationError as e:
    print(f"Validation error: {e}")
except AccumulateNetworkError as e:
    print(f"Network error: {e}")
except AccumulateAPIError as e:
    print(f"API error: {e.code} - {e}")
```

## License

MIT License - see [LICENSE](LICENSE) for details.

## Links

- [Accumulate Protocol](https://accumulatenetwork.io/)
- [API Documentation](https://docs.accumulatenetwork.io/)
- [Kermit Testnet Explorer](https://kermit.explorer.accumulatenetwork.io/)
