# Accumulate Python SDK

**Version 0.1.0** - Comprehensive Python SDK for the Accumulate Protocol

A complete, production-ready Python client for the Accumulate blockchain featuring comprehensive API coverage, robust transaction handling, multi-signature support, and enterprise-grade reliability.

## What is the Accumulate Python SDK?

The Accumulate Python SDK provides a complete interface to the Accumulate Protocol, enabling developers to:
- Build and submit all 33 transaction types
- Interact with all 35 API endpoints
- Generate and manage cryptographic signatures (17 signature types supported)
- Handle complex workflows like multi-signature transactions
- Validate and execute transactions with comprehensive error handling

## Installation

### From GitHub (Recommended)

```bash
# Clone and install in development mode
git clone https://github.com/accumulate/accumulate-python-sdk.git
cd accumulate-python-sdk/unified
pip install -e ".[dev]"
```

### Quick Installation

```bash
pip install git+https://github.com/accumulate/accumulate-python-sdk.git#subdirectory=unified
```

## Quickstart

### Local DevNet Setup

```powershell
# Create virtual environment and install SDK
py -3.11 -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -e ".\unified[dev]"

# Run complete devnet example sequence
python .\unified\examples\01_lite_and_faucet.py --help
```

### DevNet Example Journey

The SDK includes four complete example scripts that demonstrate the entire Accumulate workflow:

```powershell
# 1. Create lite account and get ACME from faucet
python .\unified\examples\01_lite_and_faucet.py --endpoint http://127.0.0.1:26660 --key-seed 000102030405060708090a0b0c0d0e0f

# 2. Create ADI identity and buy credits
python .\unified\examples\02_create_adi_and_buy_credits.py --endpoint http://127.0.0.1:26660 --key-seed 000102030405060708090a0b0c0d0e0f --adi acc://demo.acme

# 3. Create token account and transfer ACME
python .\unified\examples\03_token_account_and_transfer.py --endpoint http://127.0.0.1:26660 --key-seed 000102030405060708090a0b0c0d0e0f --adi acc://demo.acme

# 4. Create data account and write entries
python .\unified\examples\04_data_account_and_write.py --endpoint http://127.0.0.1:26660 --key-seed 000102030405060708090a0b0c0d0e0f --adi acc://demo.acme
```

Each script includes:
- Transaction validation with encode→decode→re-encode parity checks
- Automatic retry policies for network reliability
- Comprehensive error handling and status reporting
- Support for custom endpoints and replay stores

### 1. Create a Client and Query Status

```python
from accumulate_client import AccumulateClient

# Connect to Accumulate network
client = AccumulateClient("https://api.accumulate.io/v3")

# Query network status
status = client.status()
print(f"Network: {status['data']['network']}")
print(f"Version: {status['data']['version']}")
```

### 2. Create an Identity

```python
from accumulate_client.tx.builders import get_builder_for
from accumulate_client.crypto.ed25519 import Ed25519PrivateKey
from accumulate_client.signers.ed25519 import Ed25519Signer
import hashlib

# Generate keypair
private_key = Ed25519PrivateKey.generate()
identity_url = "acc://alice.acme"

# Build CreateIdentity transaction
builder = get_builder_for('CreateIdentity')
builder.with_field('url', identity_url)
builder.with_field('keyBookUrl', f"{identity_url}/book")
builder.with_field('keyPageUrl', f"{identity_url}/book/1")

# Validate and sign
builder.validate()
canonical_json = builder.to_canonical_json()
tx_hash = hashlib.sha256(canonical_json.encode()).digest()

signer = Ed25519Signer(private_key, f"{identity_url}/book/1")
signature = signer.to_accumulate_signature(tx_hash)

# Submit transaction
envelope = {
    'transaction': builder.to_body(),
    'signatures': [signature]
}
result = client.submit(envelope)
print(f"Transaction ID: {result['data']['transactionHash']}")
```

### 3. Write Data

```python
# Build WriteData transaction
builder = get_builder_for('WriteData')
builder.with_field('data', b'Hello from Accumulate SDK!')
builder.with_field('scratch', False)

# Sign and submit (similar process as above)
builder.validate()
canonical_json = builder.to_canonical_json()
tx_hash = hashlib.sha256(canonical_json.encode()).digest()
signature = signer.to_accumulate_signature(tx_hash)

envelope = {
    'transaction': builder.to_body(),
    'signatures': [signature]
}
result = client.submit(envelope)
```

## Code Examples

The SDK includes comprehensive examples demonstrating real-world usage:

### Complete Workflow Examples

- **[submit_identity_and_write_data.py](examples/submit_identity_and_write_data.py)** - End-to-end identity creation and data writing
- **[multisig_transfer_tokens.py](examples/multisig_transfer_tokens.py)** - Multi-signature token transfers (2/3 threshold)
- **[faucet_and_create_token_account.py](examples/faucet_and_create_token_account.py)** - Faucet integration and token account management

### Running Examples

```bash
# Create identity and write data (mock mode)
python examples/submit_identity_and_write_data.py --mock --identity alice.acme

# Multi-signature token transfer
python examples/multisig_transfer_tokens.py --mock --amount 1000 --threshold 2

# Faucet and token account creation
python examples/faucet_and_create_token_account.py --mock --identity bob.acme
```

All examples support:
- `--mock` flag for testing without network calls
- `--api` flag for custom endpoints
- `--help` for detailed usage information

## Supported Features

### Complete Protocol Coverage
- **14 Enums** - All protocol enumeration types
- **103 Types** - Complete type system from protocol specification
- **16 Signature Types** - Including ED25519, Legacy ED25519, and more
- **33 Transaction Types** - All transaction body classes with builders
- **35 API Methods** - Complete client interface with error handling

### Advanced Capabilities
- **Multi-signature transactions** with configurable thresholds
- **Golden vector validation** for protocol compliance
- **Fuzz testing** with 500+ test iterations
- **Runtime parity verification**
- **Comprehensive error handling** with typed exceptions
- **Automatic retries** with exponential backoff

## Advanced Features (Phase 3)

The SDK includes enterprise-grade advanced features for production environments:

### Real-time Streaming (WebSocket)

Stream live data from the Accumulate network with automatic reconnection and backpressure handling:

```python
from accumulate_client import StreamingAccumulateClient, AccumulateClient

# Create streaming client
http_client = AccumulateClient("https://api.accumulate.io/v3")
streaming_client = StreamingAccumulateClient(http_client)

async with streaming_client:
    # Stream live blocks
    async for block_event in streaming_client.stream_blocks():
        print(f"New block: {block_event.block_height}")

    # Snapshot-then-stream pattern for consistency
    def get_current_state():
        return http_client.query("acc://my-account")

    async def stream_updates():
        async for event in streaming_client.stream_tx_status("tx123"):
            yield event

    # Get snapshot + live updates with no gaps
    async for event in streaming_client.snapshot_then_stream(
        get_current_state, stream_updates
    ):
        print(f"Event: {event.type} - {event.data}")
```

### High-Performance Batching & Pipeline

Optimize throughput with automatic request batching and transaction pipelines:

```python
from accumulate_client.performance import BatchClient, PipelineClient

# HTTP connection pooling + request batching
pool = HttpConnectionPool(max_connections=100)
batch_client = BatchClient(endpoint="https://api.accumulate.io/v3", pool=pool)

async with batch_client:
    # Automatically batches requests for efficiency
    results = await batch_client.submit_many([
        {"method": "query", "params": {"url": "acc://account1"}},
        {"method": "query", "params": {"url": "acc://account2"}},
        {"method": "query", "params": {"url": "acc://account3"}},
    ])

# High-throughput transaction pipeline
pipeline = PipelineClient(client=http_client, config=PipelineConfig(
    max_concurrent_submission=50,
    max_queue_size=1000
))

async with pipeline:
    # Submit transactions for parallel processing
    submission_ids = []
    for tx in transactions:
        submission_id = await pipeline.submit_transaction(tx)
        submission_ids.append(submission_id)

    # Wait for completion
    results = await pipeline.wait_for_all(submission_ids)
```

### Error Recovery & Fault Tolerance

Robust error handling with retry policies, circuit breakers, and transaction replay:

```python
from accumulate_client.recovery import (
    ExponentialBackoff, CircuitBreaker, TransactionReplay
)

# Configurable retry policies
retry_policy = ExponentialBackoff(
    max_attempts=5,
    base_delay=1.0,
    factor=2.0,
    max_delay=60.0
)

# Automatic retries with exponential backoff
result = await retry_policy.execute(client.submit, transaction)

# Circuit breaker for fault tolerance
circuit = CircuitBreaker("api_calls", CircuitBreakerConfig(
    failure_threshold=5,
    timeout=30.0,
    failure_rate_threshold=0.5
))

async with circuit:
    result = await circuit.call(client.query, "acc://my-account")

# Transaction replay for guaranteed delivery
replay_system = TransactionReplay(client, ReplayConfig(
    max_attempts=10,
    retry_delay=2.0,
    enable_deduplication=True
))

async with replay_system:
    replay_id = await replay_system.submit_transaction(transaction)
    result = await replay_system.wait_for_delivery(replay_id)
```

### Comprehensive Metrics & Monitoring

Built-in observability with multiple export formats:

```python
from accumulate_client.monitoring import (
    get_registry, JsonExporter, PrometheusExporter, instrument_client
)

# Automatic client instrumentation
instrumentation = instrument_client(client)

# Manual metrics
registry = get_registry()
request_counter = registry.counter("requests_total", "Total requests")
request_timer = registry.timer("request_duration", "Request duration")

with request_timer.time():
    request_counter.increment()
    result = client.query("acc://my-account")

# Export metrics in multiple formats
json_exporter = JsonExporter()
prometheus_exporter = PrometheusExporter()

# JSON format for dashboards
json_metrics = json_exporter.export(registry)
print(json_metrics)

# Prometheus format for monitoring systems
prometheus_metrics = prometheus_exporter.export(registry)
print(prometheus_metrics)
```

### Performance Tuning

Optimize performance for your specific use case:

#### Recommended Profiles

**High Throughput (Batch Processing)**:
```python
from accumulate_client.performance import create_high_throughput_pipeline

# Optimized for maximum transaction throughput
pipeline = create_high_throughput_pipeline(client, pool, batch_client)
pool_config = PoolConfig(max_connections=200, max_connections_per_host=50)
```

**Low Latency (Real-time Applications)**:
```python
from accumulate_client.performance import create_low_latency_pipeline

# Optimized for minimal response time
pipeline = create_low_latency_pipeline(client, pool)
batch_config = BatchClient(max_batch_size=1, max_wait_time=0.001)
```

**Conservative (Stable Networks)**:
```python
from accumulate_client.performance import create_conservative_pool

# Optimized for stability and reliability
pool = create_conservative_pool()
retry_policy = ExponentialBackoff(max_attempts=10, base_delay=2.0)
```

#### Connection Pool Sizing

- **max_connections**: Total connection pool size (default: 100)
- **max_connections_per_host**: Per-host limit (default: 30)
- **connection_timeout**: TCP connection timeout (default: 10s)
- **request_timeout**: HTTP request timeout (default: 30s)

#### Batch Configuration

- **max_batch_size**: Requests per batch (default: 100)
- **max_wait_time**: Batch window in seconds (default: 0.1s)
- **max_concurrent_batches**: Parallel batch limit (default: 10)

### Troubleshooting

#### WebSocket Dependencies

If streaming features fail with import errors:

```bash
pip install websockets  # Required for WebSocket streaming
```

#### Replay Store Configuration

Transaction replay uses in-memory storage by default. For persistence:

```python
from accumulate_client.recovery import FileReplayStore

# Enable file-based persistence
store = FileReplayStore("/path/to/replay.json")
replay_system = TransactionReplay(client, config, store)
```

#### Metrics Output

Metrics are collected automatically but not exported by default. Enable monitoring:

```python
from accumulate_client.monitoring import LoggingExporter

# Export metrics to logs
exporter = LoggingExporter()
exporter.export(get_registry())

# Or export to file
from accumulate_client.monitoring import FileExporter
file_exporter = FileExporter("/path/to/metrics.json", JsonExporter())
file_exporter.export(get_registry())
```

#### Debug Logging

Enable detailed logging for troubleshooting:

```python
import logging
logging.basicConfig(level=logging.DEBUG)

# Component-specific logging
logging.getLogger("accumulate_client.transport.ws").setLevel(logging.DEBUG)
logging.getLogger("accumulate_client.performance").setLevel(logging.DEBUG)
logging.getLogger("accumulate_client.recovery").setLevel(logging.DEBUG)
```

## Testing & Self-Check

### Run Self-Check

```bash
python scripts/selfcheck.py
```

Expected output:
```
Status: PASS
Checks: 11/11 passed (100.0%)
Enums=14, Types=103, Signatures=16, Transactions=33, API methods=35
```

### Run Test Suite

```bash
# Run all tests
pytest tests/

# Run specific test categories
pytest tests/signers/         # Signature tests
pytest tests/tx/              # Transaction builder tests
pytest tests/client/          # API client tests
pytest tests/fuzz/            # Fuzz tests
```

### Generate Coverage Report

```bash
pytest tests/ --cov=accumulate_client --cov-report=html
```

## Documentation

### Generate Local Documentation

```bash
python scripts/make_docs.py
```

This creates comprehensive API documentation in the `site/` directory with:
- Complete API reference for all modules
- Interactive examples and code snippets
- Getting started guides
- Module-by-module documentation

### Versioning & Compatibility

- **SDK Version**: 2.3.0
- **Protocol Compatibility**: Accumulate Protocol v2.3
- **Python Requirements**: Python 3.8+
- **API Versions**: Supports both v2 and v3 JSON-RPC APIs
- **Network Compatibility**: Mainnet, Testnet, Local DevNet

## Development & Contributing

### Development Setup

```bash
# Clone repository
git clone https://github.com/accumulate/accumulate-python-sdk.git
cd accumulate-python-sdk/unified

# Create development environment
python -m venv .venv
.venv\Scripts\activate  # Windows
# source .venv/bin/activate  # Linux/Mac

# Install in development mode with all dependencies
pip install -e ".[dev]"

# Run tests to verify installation
pytest tests/ --tb=short
```

### Code Quality Tools

```bash
# Run linting
ruff check src/

# Run type checking
mypy src/

# Format code
ruff format src/
```

### Project Structure

```
unified/
├── src/accumulate_client/          # Main SDK package
│   ├── api_client.py              # Complete API client (35 methods)
│   ├── tx/                        # Transaction builders (33 types)
│   ├── signers/                   # Signature implementations (17 types)
│   ├── crypto/                    # Cryptographic primitives
│   ├── types.py                   # Generated protocol types (103 types)
│   ├── enums.py                   # Protocol enumerations (14 enums)
│   └── runtime/                   # Runtime utilities
├── tests/                         # Comprehensive test suite
│   ├── signers/                   # Signature testing
│   ├── tx/                        # Transaction testing
│   ├── client/                    # API client testing
│   ├── fuzz/                      # Fuzz testing
│   └── golden/                    # Golden vector validation
├── examples/                      # End-to-end examples
├── scripts/                       # Utility scripts
└── reports/                       # Generated reports
```

## Error Handling

The SDK provides comprehensive error handling with typed exceptions:

```python
from accumulate_client.api_client import (
    AccumulateAPIError,
    AccumulateNetworkError,
    AccumulateValidationError
)

try:
    result = client.query("acc://invalid-url")
except AccumulateValidationError as e:
    print(f"Validation error: {e}")
except AccumulateNetworkError as e:
    print(f"Network error: {e}")
except AccumulateAPIError as e:
    print(f"API error: {e.code} - {e}")
```

## Performance & Reliability

- **Automatic retries** with configurable backoff strategies
- **Connection pooling** for improved performance
- **Request timeout management** with sensible defaults
- **Memory-efficient** transaction building and validation
- **Thread-safe** client operations
- **Comprehensive logging** for debugging and monitoring

## Coverage & Quality Gates

The SDK maintains high code quality with comprehensive test coverage and strict quality gates.

### Running Coverage Tests

```bash
# Run tests with coverage reporting
pytest tests/ --cov=accumulate_client --cov-report=term-missing --cov-report=html

# Run specific test categories
pytest tests/unit/ -m unit            # Unit tests only
pytest tests/ -m "performance or recovery"  # Performance and recovery tests
pytest tests/ -m streaming            # Streaming functionality tests
```

### Coverage Reports

- **Terminal**: Coverage summary displayed after test run
- **HTML Report**: Detailed coverage report generated in `htmlcov/`
- **Quality Gate**: Minimum 85% coverage required (configured in `.coveragerc`)

```bash
# View HTML coverage report
python -c "import webbrowser; webbrowser.open('htmlcov/index.html')"
```

### Coverage Configuration

Coverage settings are configured in `.coveragerc`:
- **Branch coverage**: Enabled for thorough testing
- **Fail threshold**: 85% minimum coverage
- **Exclusions**: Test files, examples, and boilerplate code excluded

## Parity Suite

The SDK includes a comprehensive parity validation suite that compares Python encodings against Go reference implementations to ensure byte-for-byte compatibility.

### Running Parity Tests

```bash
# Run parity suite with audit reports (no Go required)
python scripts/run_parity_suite.py --audit-root "C:\Accumulate_Stuff\py_parity_audit"

# Run with live Go reference encoding (requires Go toolchain)
python scripts/run_parity_suite.py --use-go --go-root "C:\Accumulate_Stuff\accumulate"

# Generate comprehensive reports
python scripts/run_parity_suite.py --audit-root "C:\Accumulate_Stuff\py_parity_audit" --out "reports"
```

### Parity Reports

The suite generates detailed reports in the `reports/` directory:

- **parity_suite.json** - Machine-readable test results and metrics
- **PY_vs_Go_Parity_Report.md** - Human-readable summary with component counts
- **coverage_summary.txt** - Latest test coverage summary with quality gate status

### Component Validation

The parity suite validates all SDK components against expected counts:

- **14 Enums** - Protocol enumeration types
- **103 Types** - Complete type system from protocol spec
- **16 Signature Types** - All supported signature algorithms
- **33 Transaction Types** - Complete transaction body coverage
- **35 API Methods** - Full client interface validation

## All-Green Gate

The SDK includes a comprehensive validation orchestrator that ensures all components pass quality gates with automatic repair capabilities.

### Running the All-Green Gate

```bash
# Run complete validation suite with auto-repair
python .\unified\scripts\green_gate.py
```

### Validation Stages

The Green Gate runs four critical validation stages:

1. **Tests with Coverage** - Pytest with ≥85% coverage requirement
2. **Selfcheck** - Phase 3 health checks with auto-repair hooks
3. **Parity Suite** - Python vs Go encoding validation
4. **Example Flows** - End-to-end devnet journey (or mock mode)

### Auto-Repair System

When validation stages fail, the Green Gate automatically attempts targeted repairs:

- **Test Failures** - Creates additional coverage tests, fixes import issues, adjusts timeouts
- **Selfcheck Issues** - Repairs signer exports, API method counts, WebSocket graceful fallbacks
- **Parity Problems** - Generates golden vectors, fixes codec roundtrips
- **Example Errors** - Creates missing utilities, fixes builder compatibility

All repairs are:
- **Idempotent** - Safe to run multiple times
- **Targeted** - Address specific failure patterns
- **Conservative** - No sweeping refactors, only minimal fixes

### Reports Generated

On completion, find validation reports at:

- **Coverage Report** - `htmlcov/index.html`
- **Parity Analysis** - `reports/PY_vs_Go_Parity_Report.md`
- **Selfcheck Results** - `reports/selfcheck.json`
- **Auto-Repair Actions** - Console output with detailed fix descriptions

The Green Gate only exits successfully (✅ ALL GREEN) when all stages pass validation.

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Support & Community

- **GitHub Issues**: [Report bugs and request features](https://github.com/accumulate/accumulate-python-sdk/issues)
- **Documentation**: Generate local docs with `python scripts/make_docs.py`
- **Examples**: See `examples/` directory for working code samples
- **Discord**: Join the Accumulate developer community

---

*Built with ❤️ for the Accumulate ecosystem*