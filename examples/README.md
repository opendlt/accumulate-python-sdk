# Examples

Complete usage examples for the Accumulate Python SDK. All examples are runnable and demonstrate real-world integration patterns.

## Available Examples

### V3 API Examples with SmartSigner

| Example | Description |
|---------|-------------|
| `example01_lite_identities.py` | Create lite identity and token accounts, faucet integration |
| `example02_accumulate_identities.py` | Create Accumulate Digital Identifier (ADI) |
| `example03_adi_token_accounts.py` | ADI token account management |
| `example04_data_accounts.py` | Data account creation and WriteData operations |
| `example05_send_acme_adi_to_adi.py` | ADI-to-ADI token transfers |
| `example06_custom_tokens.py` | Custom token issuer creation |
| `example07_sub_adi_and_directories.py` | Sub-ADI and directory management |
| `example08_staking_and_delegation.py` | Staking and delegation operations |
| `example09_key_management.py` | Key page and key book management |
| `example10_multisig_transactions.py` | Multi-signature transaction workflows |
| `example11_authority_management.py` | Authority and governance operations |
| `example12_quickstart_demo.py` | Complete zero-to-hero workflow |

### Quick Start

```bash
# 1. Environment Setup
python -m venv .venv
.venv\Scripts\activate  # Windows
# source .venv/bin/activate  # Linux/Mac
pip install -e ".[dev]"

# 2. Run any example
python examples/example01_lite_identities.py
```

## Running Examples

### Against Kermit Testnet (Default)

All examples default to Kermit testnet:

```bash
python examples/example01_lite_identities.py
```

### Against Local DevNet

```bash
# Set environment variable
set ACC_API_URL=http://localhost:26660/v3  # Windows
# export ACC_API_URL=http://localhost:26660/v3  # Linux/Mac

python examples/example01_lite_identities.py
```

### Run All Examples

```bash
# Run all 12 examples in sequence
for i in 01 02 03 04 05 06 07 08 09 10 11 12; do
    python examples/example${i}_*.py
done
```

## Example Output

Each example outputs transaction IDs and status:

```
[Example 1] Lite Identities and Token Accounts
==================================================
Generated key pair
  Public key: a1b2c3d4e5f6...
  Lite Identity: acc://a1b2c3d4e5f6.../
  Lite Token Account: acc://a1b2c3d4e5f6.../ACME

[1/3] Requesting tokens from faucet...
  TxID: 1234567890abcdef...
  Status: delivered

[2/3] Querying token balance...
  Balance: 10.00000000 ACME

[3/3] Sending tokens...
  TxID: abcdef1234567890...
  Status: delivered

Example completed successfully!
```

## Key Features Demonstrated

- **Ed25519 Cryptography**: Pure Python key generation and signing
- **SmartSigner API**: Automatic signer version tracking
- **Protocol Compatibility**: V2 and V3 API support
- **Transaction Building**: Type-safe builders with TxBody
- **Error Handling**: Comprehensive retry logic and error reporting
- **Network Integration**: Testnet and DevNet support

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
If examples timeout, increase the timeout:
```python
client = AccumulateClient(endpoint, timeout=60)
```

### Faucet Rate Limiting
Wait a few seconds between faucet requests, or use different accounts.

### Transaction Pending
Some transactions take multiple blocks to confirm. The SmartSigner handles waiting automatically.
