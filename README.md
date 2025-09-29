# Accumulate Python SDK

Python client for the Accumulate blockchain JSON-RPC API with unified support for V2 and V3 APIs. Features Ed25519 key generation, URL derivation, transaction signing, and comprehensive DevNet integration.

## Features

- ✅ **Unified V2+V3 API** - Single client for all Accumulate APIs
- ✅ **Ed25519 Cryptography** - Key generation and transaction signing
- ✅ **Lite Account URLs** - Proper URL derivation with checksums
- ✅ **DevNet Discovery** - Automatic endpoint and faucet detection
- ✅ **Zero-to-Hero Examples** - Complete workflow demonstrations
- ✅ **TypeScript Conformance** - Tested against TS SDK golden values
- ✅ **Comprehensive Testing** - Unit, integration, and conformance tests
- ✅ **Code Generation** - Generated from official API specifications

## Quick Start

### 1. Installation

```bash
# Create and activate virtual environment
python -m venv .venv
.venv\Scripts\activate  # Windows
# source .venv/bin/activate  # Linux/Mac

# Install package in development mode
pip install -e .
```

### 2. DevNet Setup

```bash
# Discover DevNet endpoints and faucet
python tool/devnet_discovery.py

# Set environment variables (copy from discovery output)
# PowerShell:
$env:ACC_RPC_URL_V2="http://localhost:26660/v2"
$env:ACC_RPC_URL_V3="http://localhost:26660/v3"
$env:ACC_FAUCET_ACCOUNT="acc://a21555da824d14f3f066214657a44e6a1a347dad3052a23a/ACME"
```

### 3. Run Examples

```bash
# Complete zero-to-hero workflow
python examples/999_zero_to_hero.py

# Individual examples
python examples/100_keygen_lite_urls.py
python examples/120_faucet_local_devnet.py
python examples/210_buy_credits_lite.py
```

## Usage Examples

### Basic Client Usage

```python
from accumulate_client import AccumulateClient

# Create clients for V2 and V3 APIs
v2_client = AccumulateClient("http://localhost:26660/v2")
v3_client = AccumulateClient("http://localhost:26660/v3")

# Query network status
status = v2_client.describe()
print(f"Network: {status}")

# Request tokens from faucet
result = v2_client.faucet({"url": "acc://your-lta-url/ACME"})
print(f"Faucet TX: {result['transactionHash']}")

# Always close clients
v2_client.close()
v3_client.close()
```

### Key Generation and URL Derivation

```python
import hashlib
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization

# Generate Ed25519 keypair
private_key = ed25519.Ed25519PrivateKey.generate()
public_key_bytes = private_key.public_key().public_bytes(
    encoding=serialization.Encoding.Raw,
    format=serialization.PublicFormat.Raw
)

# Derive Lite Identity URL (with proper checksum)
def derive_lite_identity_url(public_key_bytes):
    key_hash_full = hashlib.sha256(public_key_bytes).digest()
    key_hash_20 = key_hash_full[:20]
    key_str = key_hash_20.hex()

    # Calculate checksum
    checksum_full = hashlib.sha256(key_str.encode('utf-8')).digest()
    checksum = checksum_full[28:].hex()

    return f"acc://{key_str}{checksum}"

# Derive Lite Token Account URL
def derive_lite_token_account_url(public_key_bytes):
    lid = derive_lite_identity_url(public_key_bytes)
    return f"{lid}/ACME"

lid = derive_lite_identity_url(public_key_bytes)
lta = derive_lite_token_account_url(public_key_bytes)
print(f"LID: {lid}")
print(f"LTA: {lta}")
```

### Transaction Signing and Submission

```python
import json
import time

# Create transaction
add_credits_tx = {
    "type": "addCredits",
    "recipient": {"url": lid_url},
    "amount": "1000000"
}

# Create envelope
timestamp = int(time.time() * 1000000)  # microseconds
tx_data = {
    "header": {
        "principal": lta_url,
        "timestamp": timestamp
    },
    "body": add_credits_tx
}

# Sign transaction
tx_json = json.dumps(tx_data, separators=(',', ':'), sort_keys=True)
tx_hash = hashlib.sha256(tx_json.encode('utf-8')).digest()
signature = private_key.sign(tx_hash)

# Create envelope
envelope = {
    "transaction": tx_data,
    "signatures": [{
        "type": "ed25519",
        "publicKey": public_key_bytes.hex(),
        "signature": signature.hex()
    }]
}

# Submit transaction
result = v3_client.execute(envelope)
print(f"TX Hash: {result.get('transactionHash')}")
```

## API Reference

### AccumulateClient

Main client class supporting both V2 and V3 APIs:

```python
client = AccumulateClient(server_url)

# Common methods
client.describe()                    # V2: Node information
client.faucet({"url": "acc://..."})  # V2: Request test tokens
client.call(method, params)          # Low-level JSON-RPC call
client.close()                       # Close HTTP session

# V3 methods
client.execute(envelope)             # Submit transaction
client.call('network-status', {})    # Network status
client.call('query', {"url": "..."}) # Query account
```

### DevNet Discovery

```python
# Run discovery tool
python tool/devnet_discovery.py

# Programmatic usage
from tool.devnet_discovery import discover_devnet_config
config = discover_devnet_config("C:/path/to/devnet")
```

## Testing

```bash
# Run all tests
pytest

# Run specific test suites
pytest tests/unit/           # Unit tests (mocked)
pytest tests/conformance/    # TS SDK compatibility tests
pytest tests/integration/    # DevNet integration tests

# Run with options
pytest -v                    # Verbose output
pytest -q                    # Quiet output
pytest --tb=short           # Short traceback format
```

## Development

### Prerequisites

- Python 3.8+
- DevNet running locally (for integration tests)
- Go toolchain (for code regeneration)

### Development Setup

```bash
# Install with dev dependencies
pip install -e .[dev]

# Run linting
python -m ruff check src/

# Run type checking (optional)
python -m mypy src/

# Run tests with coverage
pytest --cov=src/
```

### Code Generation

This SDK is generated from official Accumulate API specifications:

```bash
# Regenerate Python client code
cd C:/Accumulate_Stuff/accumulate
tools/cmd/gen-sdk/gen-sdk.exe \
  --lang python \
  --template-dir C:/Accumulate_Stuff/opendlt-python-v2v3-sdk/tooling/templates \
  --api-version both \
  --unified \
  --out C:/Accumulate_Stuff/opendlt-python-v2v3-sdk/unified/src/accumulate_client \
  internal/api/v2/methods.yml
```

See [REGENERATION_GUIDE.md](REGENERATION_GUIDE.md) for detailed instructions.

## Project Structure

```
unified/
├── src/accumulate_client/          # Generated client package
│   ├── __init__.py                 # Package exports
│   ├── client.py                   # Main AccumulateClient class
│   ├── json_rpc_client.py          # Low-level JSON-RPC client
│   └── types.py                    # API type definitions
├── tool/
│   └── devnet_discovery.py         # DevNet endpoint discovery
├── examples/                       # Usage examples
│   ├── 100_keygen_lite_urls.py     # Key generation and URL derivation
│   ├── 120_faucet_local_devnet.py  # Faucet funding
│   ├── 210_buy_credits_lite.py     # Buy credits for lite identity
│   └── 999_zero_to_hero.py         # Complete workflow demo
├── tests/                          # Test suites
│   ├── unit/                       # Unit tests with mocks
│   ├── conformance/                # TypeScript SDK compatibility
│   ├── integration/                # DevNet integration tests
│   └── golden/                     # Test fixtures and golden values
├── tooling/templates/              # Code generation templates
├── pyproject.toml                  # Package configuration
├── README.md                       # This file
├── REGENERATION_GUIDE.md           # Code regeneration instructions
└── ZERO_TO_HERO.md                 # Complete usage guide
```

## Conformance and Compatibility

This SDK is tested for compatibility with:

- **TypeScript SDK**: Crypto operations and URL derivation
- **Dart SDK**: Transaction patterns and API usage
- **Go Core**: Direct API specification conformance

Golden test vectors ensure consistent behavior across implementations.

## Contributing

1. **DO NOT** manually edit generated files in `src/accumulate_client/`
2. Edit templates in `tooling/templates/` instead
3. Regenerate code using the gen-sdk tool
4. Add tests for new functionality
5. Update documentation and examples
6. Ensure all tests pass before submitting

## Support and Documentation

- **Zero-to-Hero Guide**: [ZERO_TO_HERO.md](ZERO_TO_HERO.md)
- **Code Regeneration**: [REGENERATION_GUIDE.md](REGENERATION_GUIDE.md)
- **Examples**: See `examples/` directory
- **Tests**: See `tests/` directory for usage patterns
- **Accumulate Docs**: https://docs.accumulatenetwork.io
- **API Reference**: https://docs.accumulatenetwork.io/accumulate/developers

## License

MIT License - see LICENSE file for details.