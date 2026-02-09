# Accumulate Client Source Code

Main source code for the Accumulate Python SDK.

## Package Structure

```
src/accumulate_client/
├── __init__.py        # Main package exports
├── api_client.py      # V2/V3 API client (35 methods)
├── convenience.py     # TxBody builders and helpers
├── enums.py           # Protocol enumerations (14 enums)
├── types.py           # Protocol types (103 types)
├── crypto/            # Key pair implementations (Ed25519, Secp256k1)
├── signers/           # Signature type classes (Ed25519, RCD1, BTC, ETH)
├── tx/                # Transaction builders (33 types)
├── runtime/           # URL handling, codecs, validation
├── transport/         # HTTP and WebSocket transports
├── performance/       # Batching and connection pooling
├── recovery/          # Retry policies and circuit breakers
├── monitoring/        # Metrics and exporters
└── streaming/         # WebSocket streaming
```

## Core Modules

### API Client (`api_client.py`)

```python
from accumulate_client import AccumulateClient

client = AccumulateClient("https://kermit.accumulatenetwork.io/v3")
status = client.status()
account = client.query("acc://alice.acme")
result = client.submit(envelope)
```

### Transaction Builders (`convenience.py`)

```python
from accumulate_client.convenience import TxBody

body = TxBody.send_tokens_single(to_url="acc://...", amount="100000000")
body = TxBody.create_identity(url="acc://my-adi.acme", ...)
body = TxBody.write_data(entries_hex=[data_hex])
```

### Cryptography (`crypto/`)

```python
from accumulate_client.crypto.ed25519 import Ed25519KeyPair

kp = Ed25519KeyPair.generate()
lid = kp.derive_lite_identity_url()
lta = kp.derive_lite_token_account_url("ACME")
signature = kp.sign(message)
```

### Smart Signing (`convenience.py`)

```python
from accumulate_client.convenience import SmartSigner

signer = SmartSigner(client=client, keypair=kp, signer_url=f"{lid}/1")
result = signer.sign_submit_and_wait(principal=lta, body=body)
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

## Code Quality

- **Type Safety**: 100% type annotation coverage
- **Test Coverage**: 85% minimum requirement
- **Documentation**: Comprehensive docstrings
- **Validation**: Runtime input validation

## Generated Code

Do not edit directly:
- `types.py` - Generated from protocol specifications
- `enums.py` - Generated from protocol definitions
