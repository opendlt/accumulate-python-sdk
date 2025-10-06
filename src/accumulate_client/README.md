# Accumulate Client Source Code

Main source code for the Accumulate Python SDK, organized by functional area with comprehensive type safety and validation.

## Package Structure

```
src/accumulate_client/
├── __init__.py             # Main package exports and public API
├── api_client.py           # Complete API client (35 methods)
├── enums.py                # Protocol enumerations (14 enums)
├── types.py                # Protocol types (103 types)
├── runtime/                # Runtime utilities and helpers
├── tx/                     # Transaction builders (33 types)
├── signers/                # Signature implementations (17 types)
├── crypto/                 # Cryptographic primitives
├── keys/                   # Key management and storage
├── wallet/                 # High-level wallet abstractions
├── transport/              # Network transport layers
├── performance/            # Performance optimization components
├── recovery/               # Error recovery and fault tolerance
├── monitoring/             # Metrics and observability
└── streaming/              # WebSocket streaming functionality
```

## Core Modules

### API Client (`api_client.py`)
Complete Accumulate API client with all 35 API methods:

```python
from accumulate_client import AccumulateClient

# Create client
client = AccumulateClient("https://api.accumulate.io/v3")

# Core API methods
status = client.status()
account = client.query_account("acc://alice.acme")
result = client.submit(envelope)
```

**Key Features**:
- **Complete API Coverage**: All Accumulate API endpoints
- **Error Handling**: Comprehensive error types and retry logic
- **Connection Management**: HTTP connection pooling and timeouts
- **Authentication**: API key and authorization support

### Enumerations (`enums.py`)
All 14 protocol enumeration types with proper serialization:

```python
from accumulate_client.enums import TransactionType, SignatureType

# Use enums in transactions
tx_type = TransactionType.SEND_TOKENS
sig_type = SignatureType.ED25519

# JSON serialization
assert tx_type.to_json() == "sendTokens"
```

**Enumeration Types**:
- TransactionType, SignatureType, AccountType
- NetworkType, KeyType, ValidatorType
- And 8 additional protocol enums

### Protocol Types (`types.py`)
Complete protocol type system with 103 types:

```python
from accumulate_client.types import Transaction, Account, Signature

# Type-safe protocol structures
transaction = Transaction(
    header=TransactionHeader(...),
    body=SendTokensBody(...)
)
```

**Type Categories**:
- **Core Types**: Transaction, Account, Signature
- **Transaction Bodies**: All 33 transaction body types
- **API Types**: Request/response structures
- **Utility Types**: URLs, hashes, timestamps

## Functional Modules

### Runtime (`runtime/`)
Core runtime utilities and validation:

```
runtime/
├── __init__.py
├── urls.py                 # Accumulate URL handling
├── errors.py               # Error types and handling
├── validation.py           # Input validation
├── codecs.py              # Encoding/decoding utilities
└── helpers.py             # Common utility functions
```

**Key Components**:
- **URL Handling**: Accumulate URL parsing and validation
- **Error Management**: Comprehensive error hierarchy
- **Validation**: Input validation and constraints
- **Codecs**: Canonical JSON and binary encoding

### Transaction Builders (`tx/`)
Type-safe transaction builders for all 33 transaction types:

```
tx/
├── __init__.py
├── builders.py            # Main builder factory and base classes
├── send_tokens.py         # SendTokens transaction builder
├── create_identity.py     # CreateIdentity transaction builder
├── write_data.py          # WriteData transaction builder
└── ...                    # All 33 transaction types
```

**Usage Example**:
```python
from accumulate_client.tx.builders import get_builder_for

# Build any transaction type
builder = get_builder_for('SendTokens')
builder.with_field('to', [{'url': 'acc://bob.acme', 'amount': '1000'}])
builder.validate()

# Get canonical representation
canonical_json = builder.to_canonical_json()
transaction_body = builder.to_body()
```

### Signature Management (`signers/`)
Comprehensive signature implementations:

```
signers/
├── __init__.py
├── registry.py            # Signer registry and factory
├── ed25519.py            # Ed25519 signature implementation
├── legacy_ed25519.py     # Legacy Ed25519 support
├── multisig.py           # Multi-signature support
└── ...                   # All 17 signature types
```

**Usage Example**:
```python
from accumulate_client.signers import get_signer_for
from accumulate_client.crypto.ed25519 import Ed25519PrivateKey

# Create signer
private_key = Ed25519PrivateKey.generate()
signer = get_signer_for('ed25519', private_key, 'acc://alice.acme/book/1')

# Sign transaction
signature = signer.to_accumulate_signature(tx_hash)
```

### Cryptographic Primitives (`crypto/`)
Low-level cryptographic functions:

```
crypto/
├── __init__.py
├── ed25519.py            # Ed25519 cryptography
├── secp256k1.py          # SECP256K1 elliptic curves
├── hashing.py            # Hash functions (SHA-256, RIPEMD-160)
└── keys.py               # Key generation and management
```

**Features**:
- **Ed25519**: Key generation, signing, verification
- **SECP256K1**: Elliptic curve cryptography
- **Hashing**: Cryptographic hash functions
- **Key Derivation**: BIP32/BIP39 compatible key derivation

### Key Management (`keys/`)
Secure key storage and management:

```
keys/
├── __init__.py
├── storage.py            # Key storage backends
├── derivation.py         # Key derivation utilities
├── keystore.py           # High-level keystore interface
└── backends/             # Storage backend implementations
    ├── memory.py         # In-memory key storage
    ├── file.py           # File-based key storage
    └── encrypted.py      # Encrypted key storage
```

### Wallet Abstractions (`wallet/`)
High-level wallet management:

```
wallet/
├── __init__.py
├── wallet.py             # Main wallet interface
├── account_manager.py    # Account management
├── transaction_manager.py # Transaction coordination
└── key_manager.py        # Key lifecycle management
```

## Advanced Features

### Transport Layer (`transport/`)
Network communication abstractions:

```
transport/
├── __init__.py
├── http.py               # HTTP transport with connection pooling
├── websocket.py          # WebSocket streaming transport
├── retry.py              # Retry policies and circuit breakers
└── pool.py               # Connection pool management
```

### Performance Optimization (`performance/`)
High-performance components for scaling:

```
performance/
├── __init__.py
├── batch.py              # Request batching
├── pipeline.py           # Transaction pipelines
├── pool.py               # Connection pooling
└── cache.py              # Response caching
```

### Error Recovery (`recovery/`)
Fault tolerance and recovery mechanisms:

```
recovery/
├── __init__.py
├── retry.py              # Retry policies
├── circuit_breaker.py    # Circuit breaker patterns
├── replay.py             # Transaction replay
└── backoff.py            # Backoff strategies
```

### Monitoring (`monitoring/`)
Observability and metrics:

```
monitoring/
├── __init__.py
├── metrics.py            # Metrics collection
├── exporters.py          # Metrics export (JSON, Prometheus)
├── logging.py            # Enhanced logging
└── tracing.py            # Distributed tracing
```

### Streaming (`streaming/`)
Real-time data streaming:

```
streaming/
├── __init__.py
├── client.py             # WebSocket streaming client
├── events.py             # Event types and handlers
├── reconnection.py       # Automatic reconnection
└── backpressure.py       # Flow control
```

## Type Safety and Validation

### Type Annotations
All code includes comprehensive type annotations:

```python
from typing import Dict, List, Optional, Union
from accumulate_client.types import Transaction, Account

def submit_transaction(
    client: AccumulateClient,
    transaction: Transaction,
    timeout: Optional[float] = None
) -> Dict[str, Any]:
    """Submit transaction with full type safety."""
    pass
```

### Runtime Validation
Input validation with detailed error messages:

```python
from accumulate_client.runtime.validation import validate_account_url

# Validates and raises detailed errors
validate_account_url("acc://alice.acme")  # ✅ Valid
validate_account_url("invalid-url")       # ❌ Raises ValidationError
```

### Protocol Compliance
Exact compatibility with Accumulate protocol:

```python
# Canonical JSON generation
canonical = canonical_json(transaction)

# Hash generation
tx_hash = sha256_json(transaction)

# Binary encoding
binary_data = encode_transaction(transaction)
```

## Error Handling

### Error Hierarchy
Comprehensive error types for different failure modes:

```python
from accumulate_client.api_client import (
    AccumulateAPIError,        # Base API error
    AccumulateNetworkError,    # Network connectivity issues
    AccumulateValidationError, # Input validation failures
    AccumulateTimeoutError,    # Request timeout errors
)

try:
    result = client.submit(envelope)
except AccumulateValidationError as e:
    # Handle validation errors
    print(f"Validation error: {e.details}")
except AccumulateNetworkError as e:
    # Handle network errors with retry
    print(f"Network error: {e}, retrying...")
except AccumulateAPIError as e:
    # Handle API errors
    print(f"API error {e.code}: {e.message}")
```

### Automatic Recovery
Built-in retry and recovery mechanisms:

```python
from accumulate_client.recovery import ExponentialBackoff

# Automatic retry with backoff
retry_policy = ExponentialBackoff(max_attempts=5)
result = retry_policy.execute(client.submit, envelope)
```

## Integration Patterns

### Client Factory
Simplified client creation with common configurations:

```python
from accumulate_client import (
    mainnet_client,
    testnet_client,
    devnet_client,
    AccumulateClient
)

# Preconfigured clients
mainnet = mainnet_client()
testnet = testnet_client()
devnet = devnet_client()

# Custom client
custom = AccumulateClient(
    endpoint="https://custom.accumulate.io/v3",
    timeout=30,
    retry_config={'max_attempts': 3}
)
```

### Context Managers
Resource management with context managers:

```python
async with AccumulateClient("https://api.accumulate.io/v3") as client:
    # Client automatically manages connections
    result = await client.submit(envelope)
# Connections automatically closed
```

### Async Support
Full async/await support for high-performance applications:

```python
import asyncio
from accumulate_client.async_client import AsyncAccumulateClient

async def main():
    async with AsyncAccumulateClient("https://api.accumulate.io/v3") as client:
        # Concurrent operations
        tasks = [
            client.query_account(f"acc://account{i}.acme")
            for i in range(10)
        ]
        results = await asyncio.gather(*tasks)
```

## Development and Testing

### Generated Code
Much of the source code is generated from protocol specifications:
- **Enums**: Generated from protocol enumeration definitions
- **Types**: Generated from protocol type specifications
- **API Methods**: Generated from OpenAPI specifications
- **Transaction Builders**: Generated from transaction schemas

### Code Quality
All source code maintains high quality standards:
- **Type Safety**: 100% type annotation coverage
- **Test Coverage**: 85% minimum coverage requirement
- **Documentation**: Comprehensive docstrings
- **Validation**: Runtime input validation
- **Error Handling**: Comprehensive error management

### Contributing
When contributing to the source code:
1. **Follow Type Annotations**: All new code must include type hints
2. **Add Tests**: New functionality requires comprehensive tests
3. **Document Changes**: Update docstrings and documentation
4. **Validate**: Run quality gates before submitting
5. **Generated Code**: Don't edit generated files directly