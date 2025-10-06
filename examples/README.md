# Examples

Complete usage examples for the Accumulate Python SDK. All examples are runnable and demonstrate real-world integration patterns with comprehensive error handling and validation.

## Available Examples

### DevNet Journey Examples

The SDK includes four sequential examples that demonstrate the complete Accumulate workflow:

#### `01_lite_and_faucet.py` - Lite Account and Faucet
Create a lite account and request ACME tokens from the faucet.

```bash
# Basic usage
python examples/01_lite_and_faucet.py --endpoint http://127.0.0.1:26660

# With specific key seed
python examples/01_lite_and_faucet.py --endpoint http://127.0.0.1:26660 --key-seed 000102030405060708090a0b0c0d0e0f
```

**Features demonstrated**:
- Ed25519 key generation from seed
- Lite account URL derivation
- Faucet API integration
- Transaction validation and parity checks

#### `02_create_adi_and_buy_credits.py` - ADI Creation and Credits
Create an Accumulate Digital Identifier (ADI) and purchase credits.

```bash
python examples/02_create_adi_and_buy_credits.py --endpoint http://127.0.0.1:26660 --key-seed 000102030405060708090a0b0c0d0e0f --adi acc://demo.acme
```

**Features demonstrated**:
- CreateIdentity transaction building
- Credit purchase workflow
- Key page and key book management
- Multi-step transaction coordination

#### `03_token_account_and_transfer.py` - Token Operations
Create token accounts and transfer ACME between accounts.

```bash
python examples/03_token_account_and_transfer.py --endpoint http://127.0.0.1:26660 --key-seed 000102030405060708090a0b0c0d0e0f --adi acc://demo.acme
```

**Features demonstrated**:
- CreateTokenAccount transaction
- SendTokens transaction building
- Account balance queries
- Token transfer validation

#### `04_data_account_and_write.py` - Data Management
Create data accounts and write data entries.

```bash
python examples/04_data_account_and_write.py --endpoint http://127.0.0.1:26660 --key-seed 000102030405060708090a0b0c0d0e0f --adi acc://demo.acme
```

**Features demonstrated**:
- CreateDataAccount transaction
- WriteData transaction building
- Data entry management
- Complex data structures

### Legacy Examples

#### `submit_identity_and_write_data.py` - Complete Workflow
End-to-end identity creation and data writing demonstration.

```bash
# Create identity and write data (mock mode)
python examples/submit_identity_and_write_data.py --mock --identity alice.acme

# With real network
python examples/submit_identity_and_write_data.py --api https://api.accumulate.io/v3 --identity alice.acme
```

#### `multisig_transfer_tokens.py` - Multi-signature Transactions
Advanced multi-signature token transfers with configurable thresholds.

```bash
# Multi-signature token transfer (2/3 threshold)
python examples/multisig_transfer_tokens.py --mock --amount 1000 --threshold 2

# With custom signers
python examples/multisig_transfer_tokens.py --mock --amount 1000 --threshold 2 --signers 3
```

#### `faucet_and_create_token_account.py` - Faucet Integration
Faucet integration and token account management.

```bash
# Faucet and token account creation
python examples/faucet_and_create_token_account.py --mock --identity bob.acme

# With real DevNet
python examples/faucet_and_create_token_account.py --api http://127.0.0.1:26660 --identity bob.acme
```

## Quick Start

### 1. Environment Setup
```bash
# Create virtual environment
python -m venv .venv
.venv\Scripts\activate  # Windows
# source .venv/bin/activate  # Linux/Mac

# Install SDK with development dependencies
pip install -e ".[dev]"
```

### 2. DevNet Setup (Local Development)
```bash
# Start local DevNet instance
cd /path/to/devnet-accumulate-instance
./start-devnet.sh
```

DevNet endpoints:
- API Endpoint: http://127.0.0.1:26660
- Faucet: Available at `/faucet` endpoint

### 3. Run DevNet Journey
```bash
# Complete 4-step DevNet journey
python examples/01_lite_and_faucet.py --endpoint http://127.0.0.1:26660 --key-seed 000102030405060708090a0b0c0d0e0f
python examples/02_create_adi_and_buy_credits.py --endpoint http://127.0.0.1:26660 --key-seed 000102030405060708090a0b0c0d0e0f --adi acc://demo.acme
python examples/03_token_account_and_transfer.py --endpoint http://127.0.0.1:26660 --key-seed 000102030405060708090a0b0c0d0e0f --adi acc://demo.acme
python examples/04_data_account_and_write.py --endpoint http://127.0.0.1:26660 --key-seed 000102030405060708090a0b0c0d0e0f --adi acc://demo.acme
```

## Command Line Options

All examples support comprehensive command-line configuration:

### Common Options
- `--endpoint <url>` - Accumulate API endpoint (default: http://127.0.0.1:26660)
- `--key-seed <hex>` - Deterministic key seed for reproducible results
- `--mock` - Run in mock mode without network calls (legacy examples)
- `--help` - Detailed usage information and examples

### DevNet Journey Options
- `--adi <url>` - ADI URL for identity creation (examples 2-4)
- `--amount <tokens>` - Token amount for transfers (default: 1000)
- `--replay-store <path>` - Custom replay store location

### Legacy Example Options
- `--api <url>` - API endpoint for legacy examples
- `--identity <name>` - Identity name for creation
- `--threshold <n>` - Multi-signature threshold (multisig example)
- `--signers <n>` - Number of signers for multi-signature (multisig example)

## Example Features

### Comprehensive Validation
Every example includes:
- **Transaction Validation**: Encode → decode → re-encode parity checks
- **Error Handling**: Comprehensive error catching and recovery
- **Retry Logic**: Automatic retry with exponential backoff
- **Status Reporting**: Detailed progress and result reporting

### Network Integration
- **DevNet Support**: Optimized for local DevNet development
- **TestNet Compatibility**: Easy switching to TestNet endpoints
- **Custom Endpoints**: Support for any Accumulate-compatible API
- **Faucet Integration**: Automatic token requests for testing

### Development Features
- **Deterministic Keys**: Reproducible results with seed-based key generation
- **Mock Mode**: Testing without network dependency (legacy examples)
- **Detailed Logging**: Comprehensive operation logging
- **Transaction Replay**: Automatic transaction replay on failure

## Running Examples

### Individual Examples
```bash
# Run specific example with debug output
python examples/01_lite_and_faucet.py --endpoint http://127.0.0.1:26660 --key-seed 000102030405060708090a0b0c0d0e0f

# Legacy example in mock mode
python examples/submit_identity_and_write_data.py --mock --identity alice.acme

# Multi-signature example
python examples/multisig_transfer_tokens.py --mock --amount 500 --threshold 2 --signers 3
```

### Batch Execution
```bash
# Run all DevNet journey examples in sequence
for script in examples/0*.py; do
    echo "Running $script..."
    python "$script" --endpoint http://127.0.0.1:26660 --key-seed 000102030405060708090a0b0c0d0e0f
done
```

### Testing Examples
```bash
# Test all examples in mock mode
pytest tests/examples/ -v

# Test specific example functionality
python -m pytest tests/examples/test_01_lite_and_faucet.py -v
```

## Network Configuration

### Local DevNet (Recommended for Development)
```bash
# DevNet configuration
--endpoint http://127.0.0.1:26660
```
- **Features**: Full protocol support, faucet available, fastest iteration
- **Use Case**: Development, testing, debugging

### TestNet (Integration Testing)
```bash
# TestNet configuration
--endpoint https://testnet.accumulate.io/v3
```
- **Features**: Stable environment, faucet available, external hosting
- **Use Case**: Integration testing, staging

### MainNet (Production)
```bash
# MainNet configuration
--endpoint https://api.accumulate.io/v3
```
- **Features**: Production network, real value tokens, no faucet
- **Use Case**: Production deployment, real transactions

## Advanced Features Demonstrated

### Transaction Building
```python
from accumulate_client.tx.builders import get_builder_for

# Build any transaction type
builder = get_builder_for('CreateIdentity')
builder.with_field('url', 'acc://alice.acme')
builder.with_field('keyBookUrl', 'acc://alice.acme/book')
builder.validate()

# Get canonical JSON for hashing
canonical_json = builder.to_canonical_json()
```

### Signature Management
```python
from accumulate_client.crypto.ed25519 import Ed25519PrivateKey
from accumulate_client.signers.ed25519 import Ed25519Signer

# Generate key and create signer
private_key = Ed25519PrivateKey.generate()
signer = Ed25519Signer(private_key, 'acc://alice.acme/book/1')

# Sign transaction hash
signature = signer.to_accumulate_signature(tx_hash)
```

### Client Configuration
```python
from accumulate_client import AccumulateClient

# Configure client with custom settings
client = AccumulateClient(
    endpoint='http://127.0.0.1:26660',
    timeout=30,
    retry_config={'max_attempts': 5, 'backoff_factor': 2.0}
)
```

## Error Handling Patterns

Examples demonstrate comprehensive error handling:

```python
from accumulate_client.api_client import (
    AccumulateAPIError,
    AccumulateNetworkError,
    AccumulateValidationError
)

try:
    result = client.submit(envelope)
    print(f"✅ Success: {result['data']['transactionHash']}")
except AccumulateValidationError as e:
    print(f"❌ Validation error: {e}")
except AccumulateNetworkError as e:
    print(f"❌ Network error: {e}")
    # Implement retry logic
except AccumulateAPIError as e:
    print(f"❌ API error: {e.code} - {e}")
```

## Contributing Examples

When adding new examples:

1. **Follow naming convention**: `NN_description.py` for numbered sequence
2. **Include comprehensive error handling**: Use try/catch with specific exceptions
3. **Add command-line arguments**: Support `--endpoint`, `--help`, etc.
4. **Document features**: Include docstring explaining what the example demonstrates
5. **Add tests**: Create corresponding test file in `tests/examples/`
6. **Update this README**: Add the new example to the appropriate section

### Example Template
```python
#!/usr/bin/env python3
"""
Example: Description of what this example does

Demonstrates:
- Feature 1
- Feature 2
- Feature 3
"""

import argparse
import sys
from accumulate_client import AccumulateClient

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--endpoint', default='http://127.0.0.1:26660',
                       help='Accumulate API endpoint')
    parser.add_argument('--key-seed',
                       help='Hex key seed for deterministic keys')
    args = parser.parse_args()

    try:
        # Example implementation
        client = AccumulateClient(args.endpoint)
        # ... implementation ...
        print("✅ Example completed successfully")
    except Exception as e:
        print(f"❌ Example failed: {e}")
        sys.exit(1)

if __name__ == '__main__':
    main()
```