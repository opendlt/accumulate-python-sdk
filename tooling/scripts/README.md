# Development Scripts

Automation scripts for development, testing, and quality assurance.

## Quality Assurance

### `green_gate.py`
Comprehensive validation orchestrator with automatic repair capabilities.

```bash
python tooling/scripts/green_gate.py
```

Runs four validation stages:
1. **Tests with Coverage** - pytest with 85% coverage requirement
2. **Selfcheck** - SDK health checks with auto-repair
3. **Parity Suite** - Python vs Go encoding validation
4. **Example Flows** - End-to-end workflow testing

### `selfcheck.py`
SDK health and completeness validation.

```bash
python tooling/scripts/selfcheck.py
```

Validates:
- Component counts (14 enums, 103 types, 16 signatures, 33 transactions, 35 API methods)
- Import resolution
- Signer registry completeness
- WebSocket functionality

### `run_parity_suite.py`
Cross-language compatibility validation against Go reference.

```bash
python tooling/scripts/run_parity_suite.py --audit-root "path/to/py_parity_audit"
```

## Development Tools

### `make_docs.py`
Generate API documentation.

```bash
python tooling/scripts/make_docs.py
```

### `gen_golden.py`
Generate and manage golden test vectors.

```bash
python tooling/scripts/gen_golden.py
ACC_UPDATE_GOLDENS=1 python tooling/scripts/gen_golden.py  # Force regeneration
```

## Usage Patterns

### Pre-commit Validation
```bash
python tooling/scripts/green_gate.py --skip-examples
```

### Quick Test Run
```bash
pytest tests/ -x  # Stop on first failure
```

### Release Preparation
```bash
python tooling/scripts/green_gate.py
python tooling/scripts/make_docs.py
```

## Exit Codes

- **0**: Success
- **1**: General failure
- **3**: Test failure
- **4**: Coverage threshold not met
- **5**: Parity validation failure
