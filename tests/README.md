# Test Suite

Comprehensive test suite for the Accumulate Python SDK, organized by functional area with extensive coverage requirements and quality gates.

## Test Structure

```
tests/
├── unit/                   # Unit tests for individual components
├── client/                 # API client testing
├── codec/                  # Encoding/decoding tests
├── conformance/            # Protocol conformance tests
├── coverage/               # Coverage-specific tests
├── coverage_boost/         # Additional coverage enhancement tests
├── crypto/                 # Cryptographic function tests
├── examples/               # Example script testing
├── fuzz/                   # Fuzzing and property-based tests
├── golden/                 # Golden vector validation
├── helpers/                # Test utilities and helpers
├── integration/            # End-to-end integration tests
├── introspection/          # SDK introspection and validation
├── performance/            # Performance and benchmarking tests
├── recovery/               # Error recovery and retry logic tests
├── repo/                   # Repository structure validation
├── runtime/                # Runtime functionality tests
├── signers/                # Signature implementation tests
├── streaming/              # WebSocket streaming tests
├── tx/                     # Transaction builder tests
├── wallet/                 # Wallet functionality tests
└── _autofix/               # Auto-generated test fixes
```

## Running Tests

### Complete Test Suite
```bash
# Run all tests with coverage
pytest tests/ --cov=accumulate_client --cov-report=html --cov-report=term-missing

# Run with quality gate (requires 85% coverage)
pytest tests/ --cov=accumulate_client --cov-fail-under=85
```

### By Category
```bash
# Unit tests
pytest tests/unit/ -v

# API client tests
pytest tests/client/ -v

# Transaction builder tests
pytest tests/tx/ -v

# Cryptographic tests
pytest tests/crypto/ -v

# Signature tests
pytest tests/signers/ -v

# Integration tests (requires network/DevNet)
pytest tests/integration/ -v

# Performance tests
pytest tests/performance/ -v

# Fuzzing tests
pytest tests/fuzz/ -v
```

### By Test Markers
```bash
# Unit tests only
pytest -m unit

# Performance tests
pytest -m performance

# Streaming functionality tests
pytest -m streaming

# Recovery mechanism tests
pytest -m recovery

# Skip slow tests
pytest -m "not slow"

# Run only critical path tests
pytest -m critical
```

## Test Categories

### Unit Tests (`unit/`)
Fast, isolated tests for individual SDK components:
- **API Methods**: Individual API method testing
- **Transaction Builders**: Builder pattern validation
- **Type System**: Protocol type validation
- **Runtime Utilities**: Helper function testing

### Client Tests (`client/`)
Complete API client functionality:
- **Connection Handling**: Network connectivity and error scenarios
- **Request/Response**: JSON-RPC communication validation
- **Authentication**: API key and authentication testing
- **Timeout Management**: Request timeout and retry logic

### Codec Tests (`codec/`)
Encoding and decoding validation:
- **JSON Serialization**: Canonical JSON generation
- **Binary Encoding**: Protocol buffer encoding/decoding
- **Hash Generation**: SHA-256 hash validation
- **Roundtrip Testing**: Encode → decode → re-encode validation

### Conformance Tests (`conformance/`)
Protocol specification compliance:
- **Golden Vector Validation**: Cross-language compatibility
- **Protocol Compliance**: Specification adherence
- **Type Matrix**: Complete type system validation
- **API Specification**: Complete API coverage validation

### Crypto Tests (`crypto/`)
Cryptographic function validation:
- **Ed25519**: Key generation, signing, verification
- **SECP256K1**: Elliptic curve cryptography
- **Hash Functions**: SHA-256, RIPEMD-160
- **Key Derivation**: BIP32, BIP39 compatibility

### Signature Tests (`signers/`)
Signature implementation testing:
- **Ed25519 Signatures**: Standard and legacy variants
- **Multi-signature**: Threshold signature schemes
- **Delegation**: Signature delegation patterns
- **Signature Types**: All 16 supported signature types

### Transaction Tests (`tx/`)
Transaction builder validation:
- **Builder Patterns**: Type-safe transaction construction
- **Validation Logic**: Field validation and constraints
- **Canonical Form**: Deterministic transaction encoding
- **All Transaction Types**: Complete coverage of 33 transaction types

### Integration Tests (`integration/`)
End-to-end workflow testing:
- **DevNet Integration**: Complete workflow against local DevNet
- **Zero-to-Hero**: Full user journey testing
- **Multi-step Transactions**: Complex transaction sequences
- **Error Recovery**: Network failure and retry scenarios

### Performance Tests (`performance/`)
Performance and scalability validation:
- **Throughput Testing**: High-volume transaction processing
- **Latency Measurement**: Response time analysis
- **Memory Usage**: Memory efficiency validation
- **Connection Pooling**: Performance optimization testing

### Streaming Tests (`streaming/`)
WebSocket streaming functionality:
- **Connection Management**: WebSocket connection lifecycle
- **Real-time Updates**: Live data streaming
- **Reconnection Logic**: Automatic reconnection handling
- **Backpressure**: Flow control and buffering

### Recovery Tests (`recovery/`)
Error recovery and fault tolerance:
- **Retry Logic**: Exponential backoff and retry policies
- **Circuit Breakers**: Fault tolerance mechanisms
- **Transaction Replay**: Guaranteed delivery systems
- **Error Handling**: Comprehensive error scenario coverage

### Fuzzing Tests (`fuzz/`)
Property-based and fuzzing tests:
- **Random Input Generation**: Property-based testing
- **Cross-language Compatibility**: Fuzzing against Go reference
- **Edge Case Discovery**: Automated edge case testing
- **Regression Prevention**: Fuzzing-based regression testing

## Test Configuration

### Coverage Configuration (`.coveragerc`)
```ini
[run]
source = accumulate_client
branch = True
omit =
    tests/*
    examples/*
    */test_*.py

[report]
fail_under = 85
show_missing = True
skip_covered = False

[html]
directory = htmlcov
```

### Pytest Configuration (`pytest.ini`)
```ini
[tool:pytest]
testpaths = tests
python_files = test_*.py
python_classes = Test*
python_functions = test_*
markers =
    unit: Unit tests
    integration: Integration tests
    performance: Performance tests
    streaming: Streaming functionality tests
    recovery: Recovery mechanism tests
    slow: Slow-running tests
    critical: Critical path tests
    network: Tests requiring network access
```

### Environment Variables
```bash
# Test configuration
export PYTEST_XDIST_WORKER_COUNT=4  # Parallel test execution
export ACCUMULATE_TEST_ENDPOINT="http://127.0.0.1:26660"
export ACCUMULATE_TEST_TIMEOUT=30

# Coverage configuration
export COVERAGE_THRESHOLD=85
export COVERAGE_REPORT_FORMAT="html,term-missing"

# Integration test configuration
export DEVNET_ENDPOINT="http://127.0.0.1:26660"
export INTEGRATION_TIMEOUT=60
```

## Quality Gates

### Coverage Requirements
- **Overall Coverage**: Minimum 85% line and branch coverage
- **Critical Modules**: Minimum 90% coverage for core SDK components
- **New Code**: 100% coverage requirement for new functionality
- **Regression Prevention**: Coverage cannot decrease between releases

### Test Requirements
- **All Tests Pass**: Zero test failures allowed
- **Performance Benchmarks**: Performance regression detection
- **Memory Leaks**: Memory usage validation
- **Cross-Platform**: Tests must pass on Windows, Linux, macOS

### Validation Gates
```bash
# Run complete validation suite
python scripts/green_gate.py

# Individual quality gates
pytest tests/ --cov=accumulate_client --cov-fail-under=85  # Coverage gate
python scripts/run_parity_suite.py                        # Parity gate
pytest tests/performance/ --benchmark-only                # Performance gate
```

## Golden Vector Testing

### Golden Vector Structure
```
tests/golden/
├── transactions/          # Transaction golden vectors
│   ├── create_identity/   # CreateIdentity examples
│   ├── send_tokens/       # SendTokens examples
│   └── ...               # All 33 transaction types
├── signatures/           # Signature golden vectors
│   ├── ed25519/         # Ed25519 signature examples
│   ├── legacy/          # Legacy signature formats
│   └── ...              # All 16 signature types
└── index.json           # Golden vector index
```

### Running Golden Vector Tests
```bash
# Validate all golden vectors
pytest tests/golden/ -v

# Regenerate golden vectors (when needed)
python scripts/gen_golden.py

# Cross-language validation
python scripts/run_parity_suite.py --audit-root "C:\Accumulate_Stuff\py_parity_audit"
```

## Auto-Fix System

The test suite includes an automatic repair system for common test failures:

### Auto-Fix Categories
```
tests/_autofix/
├── coverage_boost/       # Automatically generated coverage tests
├── import_fixes/         # Import resolution fixes
├── timeout_adjustments/  # Timeout optimization
└── compatibility_shims/  # Cross-version compatibility fixes
```

### Running Auto-Fix
```bash
# Auto-fix is triggered automatically by green_gate.py
python scripts/green_gate.py

# Manual auto-fix execution
python scripts/autofix_tests.py --category coverage
python scripts/autofix_tests.py --category imports
```

## Test Data Management

### Test Data Sources
- **Upstream Vectors**: From Go reference implementation
- **Synthetic Data**: Generated deterministic test data
- **Real Network Data**: Captured from DevNet/TestNet
- **Fuzzing Data**: Property-based test generation

### Test Data Validation
```bash
# Validate test data integrity
python scripts/validate_test_data.py

# Update test data from upstream
python scripts/sync_test_data.py --source go-repo

# Generate synthetic test data
python scripts/gen_test_data.py --count 1000
```

## Writing Tests

### Test Guidelines
1. **Isolation**: Tests should not depend on external state
2. **Determinism**: Tests should produce consistent results
3. **Speed**: Unit tests should complete in <1 second
4. **Coverage**: New code requires 100% test coverage
5. **Documentation**: Complex tests require clear documentation

### Test Patterns
```python
import pytest
from accumulate_client import AccumulateClient
from accumulate_client.api_client import AccumulateAPIError

class TestAPIClient:
    def test_successful_query(self):
        """Test successful account query."""
        client = AccumulateClient("http://test.example.com")
        # Test implementation

    def test_network_error_handling(self):
        """Test network error handling and retry logic."""
        with pytest.raises(AccumulateAPIError):
            # Test error scenario
            pass

    @pytest.mark.integration
    def test_devnet_integration(self):
        """Test integration with DevNet (requires running DevNet)."""
        # Integration test implementation
        pass
```

### Property-Based Testing
```python
from hypothesis import given, strategies as st

@given(st.text(min_size=1, max_size=100))
def test_url_validation(url_string):
    """Property-based test for URL validation."""
    # Test that URL validation is consistent
    pass
```

## Debugging Tests

### Test Debugging
```bash
# Run tests with detailed output
pytest tests/ -v -s

# Debug specific test
pytest tests/client/test_api_client.py::test_submit -v -s

# Run tests with Python debugger
pytest tests/ --pdb

# Profile test performance
pytest tests/ --profile
```

### Test Logging
```python
import logging

def test_with_logging():
    """Test with debug logging enabled."""
    logging.basicConfig(level=logging.DEBUG)
    logger = logging.getLogger("accumulate_client")
    # Test implementation with logging
```

## Continuous Integration

### CI Test Execution
```bash
# CI-optimized test run
pytest tests/ \
    --cov=accumulate_client \
    --cov-report=xml \
    --junit-xml=test-results.xml \
    --maxfail=5 \
    --tb=short

# Parallel test execution
pytest tests/ -n auto
```

### Test Artifacts
- **Coverage Reports**: `htmlcov/index.html`
- **Test Results**: `test-results.xml` (JUnit format)
- **Performance Reports**: `performance-results.json`
- **Parity Reports**: `reports/PY_vs_Go_Parity_Report.md`