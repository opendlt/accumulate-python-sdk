# Accumulate Client Source Code

Main source code for the Accumulate Python SDK (`accumulate-sdk-opendlt`).

## Package Structure

```
src/accumulate_client/
├── __init__.py        # Main package exports (Accumulate facade)
├── facade.py          # Accumulate unified client (V2/V3)
├── convenience.py     # SmartSigner, TxBody, QuickStart, binary encoding helpers
├── enums.py           # Protocol enumerations (14 enums)
├── types.py           # Protocol types (103 types)
├── crypto/            # Key pair implementations (Ed25519, Secp256k1)
├── signers/           # Signature type classes (Ed25519, RCD1, BTC, ETH)
├── tx/                # Transaction builders (33 types) and Pydantic body models
├── runtime/           # URL handling, codecs, validation
├── transport/         # HTTP and WebSocket transports
├── performance/       # Batching and connection pooling
├── recovery/          # Retry policies and circuit breakers
├── monitoring/        # Metrics and exporters
└── streaming/         # WebSocket streaming
```

## Core Modules

### Convenience Layer (`convenience.py`)

This is the primary module most users interact with. It provides three API levels:

**TxBody** — static factory for transaction body dicts:
```python
from accumulate_client.convenience import TxBody

body = TxBody.send_tokens_single(to_url="acc://...", amount="100000000")
body = TxBody.create_identity(url="acc://my-adi.acme", key_book_url="acc://my-adi.acme/book", public_key_hash=kh)
body = TxBody.add_credits(recipient="acc://...", amount="1000000", oracle=500)
body = TxBody.write_data(entries_hex=[data_hex])
```

**SmartSigner** — auto-version-tracking signer with sign/submit/poll:
```python
from accumulate_client.convenience import SmartSigner

signer = SmartSigner(client=client.v3, keypair=kp, signer_url=lid)
result = signer.sign_submit_and_wait(principal=lta, body=body)
```

SmartSigner handles: version query, binary encoding of signature metadata + header +
body, SHA256 hash chain computation, Ed25519 signing, envelope assembly, V3 submission,
and delivery polling.

**QuickStart** — ultra-high-level API:
```python
from accumulate_client.convenience import QuickStart

qs = QuickStart.kermit()
wallet = qs.create_wallet()
qs.fund_wallet(wallet)
adi = qs.setup_adi(wallet, "my-adi")
```

**Binary encoding helpers** (used internally by SmartSigner, exposed for low-level use):
- `_encode_uvarint()`, `_field_bytes()`, `_field_string()`, `_field_uvarint()`
- `_encode_ed25519_sig_metadata()`, `_encode_tx_header()`, `_encode_tx_body()`
- `_compute_tx_hash_and_sign()` — full sign pipeline

### Cryptography (`crypto/`)

```python
from accumulate_client.crypto.ed25519 import Ed25519KeyPair

kp = Ed25519KeyPair.generate()
lid = kp.derive_lite_identity_url()
lta = kp.derive_lite_token_account_url("ACME")
signature = kp.sign(message)
```

### Facade (`facade.py`)

```python
from accumulate_client import Accumulate

client = Accumulate("https://kermit.accumulatenetwork.io")
# client.v2 — V2 JSON-RPC client (faucet, basic queries)
# client.v3 — V3 JSON-RPC client (submit, query, network_status)
```

## Error Handling

```python
from accumulate_client.runtime.errors import (
    AccumulateError,
    ValidationError,
    NetworkError,
)

try:
    result = client.v3.submit(envelope)
except ValidationError as e:
    print(f"Validation error: {e}")
except NetworkError as e:
    print(f"Network error: {e}")
except AccumulateError as e:
    print(f"API error: {e.code} - {e}")
```

## Generated Code

Do not edit directly:
- `types.py` - Generated from protocol specifications
- `enums.py` - Generated from protocol definitions
