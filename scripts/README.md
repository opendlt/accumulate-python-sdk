# Development Scripts

Automation scripts for development, testing, quality assurance, and deployment of the Accumulate Python SDK.

## Available Scripts

### Quality Assurance Scripts

#### `green_gate.py`
**Purpose**: Comprehensive validation orchestrator with automatic repair capabilities.

```bash
# Run complete validation suite with auto-repair
python scripts/green_gate.py

# Dry-run mode (show what would be done)
python scripts/green_gate.py --dry-run

# Skip specific validation stages
python scripts/green_gate.py --skip-tests --skip-parity
```

**Validation Stages**:
1. **Tests with Coverage** - Pytest with ≥85% coverage requirement
2. **Selfcheck** - Phase 3 health checks with auto-repair hooks
3. **Parity Suite** - Python vs Go encoding validation
4. **Example Flows** - End-to-end DevNet journey (or mock mode)

**Auto-Repair Capabilities**:
- **Test Failures**: Creates coverage tests, fixes imports, adjusts timeouts
- **Selfcheck Issues**: Repairs signer exports, API counts, WebSocket fallbacks
- **Parity Problems**: Generates golden vectors, fixes codec roundtrips
- **Example Errors**: Creates utilities, fixes builder compatibility

#### `run_parity_suite.py`
**Purpose**: Cross-language compatibility validation against Go reference implementation.

```bash
# Run with pre-generated audit files (recommended)
python scripts/run_parity_suite.py --audit-root "C:\Accumulate_Stuff\py_parity_audit"

# Run with live Go reference (requires Go toolchain)
python scripts/run_parity_suite.py --use-go --go-root "C:\Accumulate_Stuff\accumulate"

# Generate comprehensive reports
python scripts/run_parity_suite.py --audit-root "C:\Accumulate_Stuff\py_parity_audit" --out "reports"

# Validate specific components
python scripts/run_parity_suite.py --component transactions --audit-root "C:\Accumulate_Stuff\py_parity_audit"
```

**Validation Components**:
- **14 Enums**: Protocol enumeration types
- **103 Types**: Complete type system validation
- **16 Signature Types**: All supported signature algorithms
- **33 Transaction Types**: Complete transaction body coverage
- **35 API Methods**: Full client interface validation

#### `selfcheck.py`
**Purpose**: SDK health and completeness validation with component counting.

```bash
# Run complete selfcheck
python scripts/selfcheck.py

# Check specific components
python scripts/selfcheck.py --component enums
python scripts/selfcheck.py --component transactions
python scripts/selfcheck.py --component signatures

# Output JSON report
python scripts/selfcheck.py --output reports/selfcheck.json
```

**Validation Checks**:
- Component counts match expected values
- All imports resolve correctly
- Signer registry completeness
- API method coverage
- WebSocket functionality (with graceful fallback)

### Development Tools

#### `make_docs.py`
**Purpose**: Generate comprehensive API documentation.

```bash
# Generate complete documentation
python scripts/make_docs.py

# Generate with custom output directory
python scripts/make_docs.py --output custom_docs/

# Include private members
python scripts/make_docs.py --private

# Generate single-page documentation
python scripts/make_docs.py --single-page
```

**Generated Documentation**:
- Complete API reference for all modules
- Interactive examples and code snippets
- Type annotation documentation
- Cross-reference links
- Search functionality

#### `gen_golden.py`
**Purpose**: Generate and manage golden test vectors.

```bash
# Generate all golden vectors
python scripts/gen_golden.py

# Force regeneration of all vectors
ACC_UPDATE_GOLDENS=1 python scripts/gen_golden.py

# Generate specific component vectors
python scripts/gen_golden.py --component transactions
python scripts/gen_golden.py --component signatures

# Validate existing vectors
python scripts/gen_golden.py --validate-only
```

**Vector Types**:
- **Transaction Vectors**: All 33 transaction types
- **Signature Vectors**: All 16 signature types
- **Encoding Vectors**: Canonical JSON and binary encoding
- **Hash Vectors**: SHA-256 hash validation

#### `update_requirements.py`
**Purpose**: Dependency management and security auditing.

```bash
# Update all dependencies
python scripts/update_requirements.py

# Check for security vulnerabilities
python scripts/update_requirements.py --security-check

# Update only development dependencies
python scripts/update_requirements.py --dev-only

# Generate requirements.txt from pyproject.toml
python scripts/update_requirements.py --export
```

### Testing and Coverage

#### `run_tests.py`
**Purpose**: Enhanced test execution with detailed reporting.

```bash
# Run all tests with coverage
python scripts/run_tests.py

# Run specific test categories
python scripts/run_tests.py --category unit
python scripts/run_tests.py --category integration
python scripts/run_tests.py --category performance

# Run with specific coverage threshold
python scripts/run_tests.py --coverage-threshold 90

# Generate multiple report formats
python scripts/run_tests.py --reports html,xml,json
```

#### `coverage_analysis.py`
**Purpose**: Detailed coverage analysis and reporting.

```bash
# Generate coverage report
python scripts/coverage_analysis.py

# Coverage with quality gates
python scripts/coverage_analysis.py --fail-under 85

# Generate trend analysis
python scripts/coverage_analysis.py --trend

# Export coverage data
python scripts/coverage_analysis.py --export coverage_data.json
```

#### `autofix_tests.py`
**Purpose**: Automatic test repair and enhancement.

```bash
# Auto-fix failed tests
python scripts/autofix_tests.py

# Fix specific categories
python scripts/autofix_tests.py --category coverage
python scripts/autofix_tests.py --category imports
python scripts/autofix_tests.py --category timeouts

# Dry-run mode
python scripts/autofix_tests.py --dry-run
```

**Auto-Fix Categories**:
- **Coverage Enhancement**: Generate additional coverage tests
- **Import Resolution**: Fix import path issues
- **Timeout Optimization**: Adjust test timeouts
- **Compatibility Shims**: Add cross-version compatibility

### Build and Package

#### `build_package.py`
**Purpose**: Package building and validation.

```bash
# Build package
python scripts/build_package.py

# Build with version bump
python scripts/build_package.py --bump minor

# Validate package structure
python scripts/build_package.py --validate

# Build and upload to test PyPI
python scripts/build_package.py --upload-test
```

#### `validate_package.py`
**Purpose**: Package integrity and metadata validation.

```bash
# Validate package metadata
python scripts/validate_package.py

# Check for common packaging issues
python scripts/validate_package.py --comprehensive

# Validate dependencies
python scripts/validate_package.py --check-deps

# Test installation in clean environment
python scripts/validate_package.py --test-install
```

### Maintenance and Utilities

#### `cleanup.py`
**Purpose**: Repository cleanup and maintenance.

```bash
# Clean build artifacts
python scripts/cleanup.py

# Clean all generated files
python scripts/cleanup.py --all

# Clean test artifacts only
python scripts/cleanup.py --tests

# Clean with confirmation prompts
python scripts/cleanup.py --interactive
```

#### `sync_upstream.py`
**Purpose**: Synchronize with upstream repositories and protocol updates.

```bash
# Sync protocol definitions
python scripts/sync_upstream.py --component protocol

# Sync test vectors
python scripts/sync_upstream.py --component vectors

# Dry-run sync
python scripts/sync_upstream.py --dry-run

# Sync from specific repository
python scripts/sync_upstream.py --source "path/to/accumulate-go"
```

## Script Categories

### Quality Gates
- **Green Gate**: Complete validation orchestrator
- **Parity Suite**: Cross-language compatibility
- **Selfcheck**: SDK health validation
- **Coverage Analysis**: Test coverage enforcement

### Development Workflow
- **Documentation**: API documentation generation
- **Testing**: Enhanced test execution and reporting
- **Golden Vectors**: Test vector generation and management
- **Dependency Management**: Requirements and security updates

### Build and Deploy
- **Package Building**: Distribution package creation
- **Package Validation**: Integrity and metadata checking
- **Upload and Deploy**: PyPI publishing automation
- **Release Management**: Version management and tagging

### Maintenance
- **Cleanup**: Repository maintenance and cleanup
- **Upstream Sync**: Protocol and test vector synchronization
- **Auto-Fix**: Automatic repair and enhancement
- **Monitoring**: Health checks and alerting

## Usage Patterns

### Local Development
```bash
# Pre-commit validation
python scripts/green_gate.py --skip-examples

# Quick test run
python scripts/run_tests.py --category unit

# Documentation updates
python scripts/make_docs.py
```

### CI/CD Pipeline
```bash
# Full validation pipeline
python scripts/green_gate.py

# Package validation
python scripts/validate_package.py --comprehensive

# Security checks
python scripts/update_requirements.py --security-check
```

### Release Preparation
```bash
# Complete validation
python scripts/green_gate.py

# Documentation generation
python scripts/make_docs.py

# Package building
python scripts/build_package.py --validate

# Parity validation
python scripts/run_parity_suite.py --audit-root "C:\Accumulate_Stuff\py_parity_audit"
```

## Configuration

### Environment Variables
```bash
# Test configuration
export PYTEST_WORKERS=4
export COVERAGE_THRESHOLD=85
export TEST_TIMEOUT=30

# Development paths
export ACCUMULATE_GO_ROOT="/path/to/accumulate"
export AUDIT_ROOT="/path/to/py_parity_audit"
export DEVNET_ENDPOINT="http://127.0.0.1:26660"

# Build configuration
export BUILD_VERSION="auto"
export UPLOAD_REPOSITORY="testpypi"
```

### Script Configuration Files
```
scripts/
├── config/
│   ├── green_gate.json      # Green Gate configuration
│   ├── parity_suite.json    # Parity validation settings
│   ├── coverage.json        # Coverage requirements
│   └── build.json          # Build and package settings
```

## Output and Reporting

### Report Formats
- **JSON**: Machine-readable structured data
- **HTML**: Human-readable visual reports
- **Markdown**: Documentation-friendly reports
- **XML**: CI/CD system integration (JUnit, Cobertura)

### Report Locations
- **Coverage Reports**: `htmlcov/index.html`
- **Parity Reports**: `reports/PY_vs_Go_Parity_Report.md`
- **Selfcheck Results**: `reports/selfcheck.json`
- **Test Results**: `test-results.xml`
- **Documentation**: `site/index.html`

### Exit Codes
- **0**: Success
- **1**: General failure
- **2**: Configuration error
- **3**: Test failure
- **4**: Coverage threshold not met
- **5**: Parity validation failure
- **6**: Build/package error

## Adding New Scripts

### Script Template
```python
#!/usr/bin/env python3
"""
Script Name: Description of what this script does

Usage:
    python scripts/script_name.py [options]

Examples:
    python scripts/script_name.py --option value
"""

import argparse
import sys
import logging
from pathlib import Path

# Add src to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

def setup_logging(verbose: bool = False):
    """Setup logging configuration."""
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )

def main():
    """Main script entry point."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--verbose', '-v', action='store_true',
                       help='Enable verbose output')
    parser.add_argument('--dry-run', action='store_true',
                       help='Show what would be done without executing')

    args = parser.parse_args()
    setup_logging(args.verbose)

    try:
        # Script implementation
        logging.info("Script starting...")
        # ... implementation ...
        logging.info("Script completed successfully")
        return 0
    except Exception as e:
        logging.error(f"Script failed: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        return 1

if __name__ == '__main__':
    sys.exit(main())
```

### Best Practices
1. **Error Handling**: Comprehensive error handling with appropriate exit codes
2. **Logging**: Clear progress indicators and debug information
3. **Configuration**: Support for configuration files and environment variables
4. **Documentation**: Comprehensive docstrings and help messages
5. **Testing**: Scripts should be testable and include unit tests
6. **Idempotency**: Scripts should be safe to run multiple times
7. **Validation**: Input validation and sanity checks

### Integration Points
- **Green Gate**: Register new validation scripts
- **CI/CD**: Add to automated pipeline
- **Documentation**: Update script documentation
- **Testing**: Add script testing to test suite