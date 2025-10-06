# Zero to Hero: Accumulate Python SDK Guide

This guide walks you through using the Accumulate Python SDK from key generation to advanced operations.

## Quick Start

### 1. Environment Setup

```bash
# Create and activate virtual environment
python -m venv .venv
.venv\Scripts\activate  # Windows
# source .venv/bin/activate  # Linux/Mac

# Install the package
pip install -e .

# Discover DevNet endpoints
python tool/devnet_discovery.py
```

Set the environment variables from the discovery output:
```bash
# PowerShell
$env:ACC_RPC_URL_V2="http://localhost:26660/v2"
$env:ACC_RPC_URL_V3="http://localhost:26660/v3"
$env:ACC_FAUCET_ACCOUNT="acc://a21555da824d14f3f066214657a44e6a1a347dad3052a23a/ACME"

# Bash
export ACC_RPC_URL_V2="http://localhost:26660/v2"
export ACC_RPC_URL_V3="http://localhost:26660/v3"
export ACC_FAUCET_ACCOUNT="acc://a21555da824d14f3f066214657a44e6a1a347dad3052a23a/ACME"
```

### 2. Complete Workflow

Run the complete zero-to-hero demo:
```bash
python examples/999_zero_to_hero.py
```

## Step-by-Step Guide

### Step 1: Generate Keys and URLs (100_keygen_lite_urls.py)

```python
from cryptography.hazmat.primitives.asymmetric import ed25519
import hashlib

# Generate Ed25519 keypair
private_key = ed25519.Ed25519PrivateKey.generate()
public_key_bytes = private_key.public_key().public_bytes(...)

# Derive Lite Identity URL (with checksum)
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
```

**Output:**
- Lite Identity (LID): For signing transactions
- Lite Token Account (LTA): For receiving ACME tokens

### Step 2: Fund from Faucet (120_faucet_local_devnet.py)

```python
from accumulate_client import AccumulateClient

# Create V2 client for faucet
v2_client = AccumulateClient(v2_url)

# Request tokens from faucet
result = v2_client.faucet({"url": lta_url})
print(f"Transaction hash: {result['transactionHash']}")
```

### Step 3: Buy Credits (210_buy_credits_lite.py)

```python
# Create AddCredits transaction
add_credits_tx = {
    "type": "addCredits",
    "recipient": {"url": lid_url},
    "amount": "1000000"  # 1M credits
}

# Sign and submit transaction
envelope = create_envelope(lta_url, add_credits_tx, private_key)
result = v3_client.execute(envelope)
```

## Key Concepts

### URL Structure

Accumulate uses hierarchical URLs:

- **Lite Identity**: `acc://{hash40}{checksum8}`
- **Lite Token Account**: `acc://{hash40}{checksum8}/ACME`
- **ADI**: `acc://my-identity`
- **ADI Sub-account**: `acc://my-identity/tokens`

### Transaction Envelope Format

```python
envelope = {
    "transaction": {
        "header": {
            "principal": "acc://...",  # Signing account
            "timestamp": 1234567890000  # Microseconds
        },
        "body": {
            "type": "addCredits",      # Transaction type
            # ... transaction-specific fields
        }
    },
    "signatures": [{
        "type": "ed25519",
        "publicKey": "...",            # Hex-encoded public key
        "signature": "..."             # Hex-encoded signature
    }]
}
```

### API Versions

- **V2 API**: Stable, used for faucet and basic queries
- **V3 API**: New features, transaction submission, network status

## Common Operations

### Query Account

```python
# V3 query (preferred)
result = client.call('query', {"url": "acc://..."})

# V2 query
result = client.query({"url": "acc://..."})
```

### Submit Transaction

```python
# V3 only
result = client.execute(envelope)
```

### Check Network Status

```python
# V3 only
status = client.call('network-status', {})
```

## Advanced Examples

### Create ADI (Identity)

```python
create_adi_tx = {
    "type": "createIdentity",
    "url": "acc://my-identity",
    "keyBookUrl": "acc://my-identity/book",
    "keyPageUrl": "acc://my-identity/book/1"
}

envelope = create_envelope(lid_url, create_adi_tx, private_key)
result = v3_client.execute(envelope)
```

### Transfer Tokens

```python
send_tokens_tx = {
    "type": "sendTokens",
    "to": [{"url": "acc://recipient", "amount": "1000000"}]
}

envelope = create_envelope(sender_url, send_tokens_tx, private_key)
result = v3_client.execute(envelope)
```

## Error Handling

Common error patterns:

```python
try:
    result = client.faucet({"url": lta_url})
except Exception as e:
    if "validation" in str(e).lower():
        print("Invalid request parameters")
    elif "insufficient" in str(e).lower():
        print("Insufficient balance or credits")
    else:
        print(f"Unexpected error: {e}")
```

## DevNet Development

### Prerequisites

1. DevNet running locally
2. Environment variables set from `devnet_discovery.py`
3. Network connectivity to localhost:26660

### Best Practices

1. **Always use discovery tool** to get current endpoints
2. **Wait for transactions** to be processed (3-5 seconds)
3. **Handle errors gracefully** - DevNet can be unstable
4. **Use generous timeouts** for integration tests
5. **Check balances** before and after operations

### DevNet Limitations

- Faucet may have rate limits
- Transactions may occasionally fail
- Network resets lose all data
- Some V3 features may be experimental

## Testing

```bash
# Run all tests
pytest

# Run specific test suites
pytest tests/unit/           # Unit tests
pytest tests/conformance/    # TS SDK compatibility
pytest tests/integration/    # DevNet integration

# Run with verbose output
pytest -v

# Run quietly
pytest -q
```

## Troubleshooting

### Environment Issues

**Problem**: Environment variables not set
**Solution**: Run `python tool/devnet_discovery.py` and set variables

**Problem**: DevNet not accessible
**Solution**: Check DevNet is running, check firewall/network

### Transaction Issues

**Problem**: "Insufficient credits"
**Solution**: Buy more credits with AddCredits transaction

**Problem**: "Account does not exist"
**Solution**: Create account first or fund with faucet

**Problem**: "Invalid signature"
**Solution**: Check transaction envelope format and signing

### API Issues

**Problem**: "Method not found"
**Solution**: Check API version (V2 vs V3) and method availability

**Problem**: "Scope is missing"
**Solution**: V3 queries may need additional parameters

## Next Steps

1. **Explore Examples**: Run all examples in `examples/` directory
2. **Read Tests**: Review test files for usage patterns
3. **Check API Docs**: Refer to Accumulate documentation
4. **Join Community**: Connect with other Accumulate developers

## Resources

- [Accumulate Documentation](https://docs.accumulatenetwork.io)
- [API Reference](https://docs.accumulatenetwork.io/accumulate/developers)
- [DevNet Setup](https://docs.accumulatenetwork.io/accumulate/developers/devnet)
- [Transaction Types](https://docs.accumulatenetwork.io/accumulate/developers/transactions)