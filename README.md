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
pip install accumulate-client
```

Or install from source:

```bash
git clone https://github.com/opendlt/accumulate-python.git
cd accumulate-python/unified
pip install -e ".[dev]"
```

## Quick Start

```python
from accumulate_client import AccumulateClient
from accumulate_client.crypto.ed25519 import Ed25519KeyPair
from accumulate_client.signing.smart_signer import SmartSigner

# Connect to Kermit testnet
client = AccumulateClient("https://kermit.accumulatenetwork.io/v3")

# Generate key pair and derive lite account URLs
kp = Ed25519KeyPair.generate()
lid = kp.lite_identity_url()
lta = kp.lite_token_account_url()

print(f"Lite Identity: {lid}")
print(f"Lite Token Account: {lta}")

# Query account
account = client.query(lta)
print(f"Account: {account}")
```

## Smart Signing API

The `SmartSigner` class handles version tracking automatically:

```python
from accumulate_client import AccumulateClient
from accumulate_client.crypto.ed25519 import Ed25519KeyPair
from accumulate_client.signing.smart_signer import SmartSigner
from accumulate_client.convenience import TxBody

# Connect to testnet
client = AccumulateClient("https://kermit.accumulatenetwork.io/v3")
kp = Ed25519KeyPair.generate()
lid = kp.lite_identity_url()
lta = kp.lite_token_account_url()

# Create SmartSigner - automatically queries and tracks signer version
signer = SmartSigner(
    client=client,
    keypair=kp,
    signer_url=lid,
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

| Type | Key Pair Class | Use Case |
|------|---------------|----------|
| Ed25519 | `Ed25519KeyPair` | Default, recommended |
| RCD1 | `RCD1KeyPair` | Factom compatibility |
| BTC | `Secp256k1KeyPair` | Bitcoin ecosystem |
| ETH | `Secp256k1KeyPair` | Ethereum ecosystem |
| RSA-SHA256 | `RsaKeyPair` | Enterprise/legacy systems |
| ECDSA-SHA256 | `EcdsaKeyPair` | P-256 curve operations |

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
from accumulate_client import AccumulateClient

# Public networks
mainnet = AccumulateClient("https://mainnet.accumulatenetwork.io/v3")
testnet = AccumulateClient("https://kermit.accumulatenetwork.io/v3")

# Local development
devnet = AccumulateClient("http://localhost:26660/v3")
```

## Examples

See [`examples/`](examples/) for complete working examples:

| Example | Description |
|---------|-------------|
| `example01_lite_identities.py` | Lite identity and token account operations |
| `example02_accumulate_identities.py` | ADI creation |
| `example03_adi_token_accounts.py` | ADI token account management |
| `example04_data_accounts.py` | Data account operations |
| `example05_send_acme_adi_to_adi.py` | ADI-to-ADI transfers |
| `example06_custom_tokens.py` | Custom token creation |
| `example09_key_management.py` | Key page and key book management |
| `example12_quickstart_demo.py` | Complete zero-to-hero workflow |

Run any example:
```bash
python examples/example01_lite_identities.py
```

## Project Structure

```
src/accumulate_client/
├── api_client.py      # V2/V3 API client
├── convenience.py     # TxBody builders and helpers
├── crypto/            # Key pair implementations
├── signing/           # SmartSigner, signature management
├── signers/           # Signature type classes
├── tx/                # Transaction builders
├── types.py           # Protocol types (103 types)
├── enums.py           # Protocol enums (14 enums)
└── runtime/           # URL handling, codecs, validation
examples/
├── example01_*.py     # V3 API examples with SmartSigner
└── ...                # 12 complete workflow examples
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
python scripts/selfcheck.py
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
