# Examples

Complete usage examples for the Accumulate Python SDK. All examples are runnable and demonstrate real-world integration patterns.

## Available Examples

### V3 API Examples with SmartSigner

| Example | Description |
|---------|-------------|
| `v3/example_01_lite_identities.py` | Create lite identity and token accounts, faucet integration |
| `v3/example_02_accumulate_identities.py` | Create Accumulate Digital Identifier (ADI) |
| `v3/example_03_adi_token_accounts.py` | ADI token account management |
| `v3/example_04_data_accounts_entries.py` | Data account creation and WriteData operations |
| `v3/example_05_adi_to_adi_transfer.py` | ADI-to-ADI token transfers |
| `v3/example_06_custom_tokens.py` | Custom token issuer creation |
| `v3/example_08_query_tx_signatures.py` | Transaction and signature queries |
| `v3/example_09_key_management.py` | Key page and key book management |
| `v3/example_10_update_key_page_threshold.py` | Multi-sig threshold updates |
| `v3/example_11_multi_signature_types.py` | Ed25519, RCD1, BTC, ETH signatures |
| `v3/example_12_quickstart_demo.py` | Complete zero-to-hero workflow |
| `v3/example_13_adi_to_adi_transfer_with_header_options.py` | Memo, metadata, expire, hold_until |

### Quick Start

```bash
# 1. Install the SDK
pip install accumulate-sdk-opendlt

# 2. Run any example
python examples/v3/example_01_lite_identities.py
```

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

## Key Features Demonstrated

- **Ed25519 Cryptography**: Pure Python key generation and signing
- **SmartSigner API**: Automatic signer version tracking
- **Protocol Compatibility**: V2 and V3 API support
- **Transaction Building**: Type-safe builders with TxBody
- **Error Handling**: Comprehensive retry logic and error reporting
- **Network Integration**: Kermit testnet and local DevNet support

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
