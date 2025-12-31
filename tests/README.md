# Test Suite

Comprehensive test suite for the Accumulate Python SDK, organized by functional concern.

## Test Structure

```
tests/
├── unit/               # Unit tests for individual components
│   ├── api/           # API client testing
│   ├── builders/      # Transaction builder tests
│   ├── codec/         # Encoding/decoding tests
│   ├── enums/         # Enum serialization tests
│   ├── errors/        # Error handling tests
│   ├── protocol_types/ # Protocol type validation
│   ├── runtime/       # Runtime helper tests
│   ├── signatures/    # Cryptographic signature tests
│   └── transactions/  # Transaction validation tests
├── conformance/       # Protocol conformance tests
│   ├── codec/         # Binary encoding conformance
│   └── json/          # JSON canonicalization conformance
├── integration/       # End-to-end integration tests
│   └── network/       # Network connectivity tests
├── crypto/            # Cryptographic function tests
├── signers/           # Signature implementation tests
├── tx/                # Transaction builder tests
├── golden/            # Golden master test vectors
└── support/           # Test utilities and helpers
```

## Running Tests

### All Tests
```bash
pytest tests/
```

### By Category
```bash
# Unit tests only
pytest tests/unit/

# Conformance tests only
pytest tests/conformance/

# Integration tests only (requires network)
pytest tests/integration/

# Crypto tests
pytest tests/crypto/

# Signer tests
pytest tests/signers/
```

### Specific Test Files
```bash
# Single test file
pytest tests/unit/errors/error_handling_test.py

# Pattern matching
pytest -k "JSON"  # Run tests with "JSON" in name
```

### With Coverage
```bash
pytest tests/ --cov=accumulate_client --cov-report=html

# With coverage threshold
pytest tests/ --cov=accumulate_client --cov-fail-under=85
```

## Test Categories

### Unit Tests (`unit/`)
Fast, isolated tests for individual components:

- **API**: Client wrapper functionality and endpoint handling
- **Builders**: Transaction builder validation and construction
- **Codec**: Binary/JSON encoding and decoding logic
- **Enums**: Enum serialization and validation
- **Errors**: Error handling and validation edge cases
- **Protocol Types**: Protocol type validation and constraints
- **Runtime**: Helper functions and validation utilities
- **Signatures**: Cryptographic signature generation and validation
- **Transactions**: Transaction header and body validation

### Conformance Tests (`conformance/`)
Tests against protocol specifications:

- **Binary Encoding**: Matches Go implementation exactly
- **Hash Vectors**: SHA-256 hash conformance with golden files
- **JSON Canonicalization**: Deterministic JSON encoding
- **Envelope Encoding**: Transaction envelope structure validation

### Integration Tests (`integration/`)
End-to-end tests with external dependencies:

- **DevNet E2E**: Full workflow testing against local DevNet
- **Network Smoke Tests**: Basic connectivity and endpoint validation
- **Zero-to-Hero**: Complete user journey from key generation to transactions

## Test Data

### Golden Files (`golden/`)
Reference test vectors for conformance testing:
- `envelope_fixed.golden.json` - Transaction envelope examples
- `sample.golden.json` - General test data
- `sig_ed25519.golden.json` - Ed25519 signature vectors
- `tx_only.golden.json` - Transaction-only test cases

### Test Utilities (`support/`)
- `test_paths.py` - Path resolution helpers
- `golden_loader.py` - Golden file loading utilities

## Configuration

### Test Selection by Tags
Tests use markers for categorization:
```bash
# Run only unit tests
pytest -m unit

# Exclude integration tests
pytest -m "not integration"

# Run conformance tests only
pytest -m conformance
```

### Environment Variables
- `ACC_DEVNET_DIR` - DevNet directory for integration tests
- `ACC_RPC_URL_V2` - V2 API endpoint override
- `ACC_RPC_URL_V3` - V3 API endpoint override

## Writing Tests

### Test Placement
- **Unit tests**: Test single functions/classes in isolation
- **Conformance**: Test against external specifications or golden files
- **Integration**: Test complete workflows requiring external services

### Test Patterns
```python
import pytest
from accumulate_client import AccumulateClient

class TestAPIClient:
    def test_successful_query(self):
        """Test successful account query."""
        # Arrange
        client = AccumulateClient("http://test.example.com")

        # Act
        result = client.status()

        # Assert
        assert "data" in result

    @pytest.mark.integration
    def test_devnet_integration(self):
        """Test integration with DevNet (requires running DevNet)."""
        pass
```

### Golden File Tests
```python
def test_signature_matches_golden(golden_data):
    """Test that signature matches golden vector."""
    result = sign_transaction(golden_data["input"])
    assert result == golden_data["expected_output"]
```

## Test Quality

- **Coverage**: Minimum 85% line and branch coverage
- **Isolation**: Unit tests should not depend on external services
- **Speed**: Unit and conformance tests should run quickly
- **Reliability**: Integration tests should be resilient to network issues
- **Clarity**: Test names should clearly describe what is being tested
