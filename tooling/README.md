# Development Tooling

Build tools, code generation utilities, and development infrastructure for the Accumulate Python SDK.

## Tooling Structure

```
tooling/
├── ts-fixture-exporter/     # TypeScript fixture generation for cross-language testing
├── type-manifests/          # Protocol type manifests and metadata
├── codegen/                 # Code generation utilities
├── templates/               # Code and documentation templates
└── validators/              # Validation and verification tools
```

## TypeScript Fixture Exporter (`ts-fixture-exporter/`)

**Purpose**: Generate deterministic test vectors from TypeScript SDK for cross-language compatibility validation.

### Usage
```bash
cd tooling/ts-fixture-exporter/

# Install dependencies
npm install

# Generate random vectors for fuzzing
TS_FUZZ_N=1000 node export-random-vectors.js > ../../tests/golden/ts_rand_vectors.jsonl

# Generate standard fixtures
node export-fixtures.js > ../../tests/golden/ts_standard_fixtures.jsonl

# CI environment (fewer vectors for speed)
TS_FUZZ_N=200 node export-random-vectors.js > ../../tests/golden/ts_rand_vectors.jsonl
```

### Output Format
Each line in the JSON Lines output contains:
```json
{
  "hexBin": "4143435500...",
  "canonicalJson": "{\"body\":{...}}",
  "txHashHex": "4be49c59c717...",
  "meta": {
    "index": 0,
    "txType": "send-tokens",
    "numSignatures": 1,
    "binarySize": 445,
    "canonicalSize": 161
  }
}
```

### Verification Process
The Python SDK validates:
1. **Binary Roundtrip**: `decode(hexBin) → structs → encode() == hexBin`
2. **Canonical JSON**: `dumps_canonical(transaction) == canonicalJson`
3. **Hash Verification**: `sha256_json(transaction) == txHashHex`

## Type Manifests (`type-manifests/`)

**Purpose**: Protocol type metadata and validation manifests for SDK generation and verification.

### Manifest Files
- **`enum_manifest.json`** - Enumeration type definitions and counts
- **`transaction_manifest.json`** - Transaction type metadata
- **`signature_manifest.json`** - Signature type specifications
- **`api_manifest.json`** - API method definitions and schemas

### Manifest Structure
```json
{
  "version": "2.3.0",
  "generated_at": "2024-01-01T12:00:00Z",
  "components": {
    "enums": {
      "count": 14,
      "types": [...]
    },
    "transactions": {
      "count": 33,
      "types": [...]
    }
  }
}
```

### Usage
```bash
# Validate type manifests
python tooling/validators/validate_manifests.py

# Update manifests from protocol definitions
python tooling/codegen/update_manifests.py --source "path/to/accumulate-go"

# Generate SDK components from manifests
python tooling/codegen/generate_from_manifests.py
```

## Code Generation (`codegen/`)

**Purpose**: Automated code generation for SDK components based on protocol specifications.

### Generators
- **`enum_generator.py`** - Generate Python enum classes from protocol definitions
- **`transaction_generator.py`** - Generate transaction builder classes
- **`signature_generator.py`** - Generate signature implementation classes
- **`api_generator.py`** - Generate API client methods

### Code Generation Workflow
```bash
# Generate all SDK components
python tooling/codegen/generate_all.py

# Generate specific components
python tooling/codegen/enum_generator.py --output src/accumulate_client/enums.py
python tooling/codegen/transaction_generator.py --output src/accumulate_client/tx/
python tooling/codegen/signature_generator.py --output src/accumulate_client/signers/

# Validate generated code
python tooling/validators/validate_generated.py
```

### Generation Configuration
```yaml
# codegen/config.yaml
generation:
  output_directory: "src/accumulate_client"
  template_directory: "tooling/templates"
  validation: true

components:
  enums:
    enabled: true
    template: "enum_template.py.j2"
  transactions:
    enabled: true
    template: "transaction_template.py.j2"
```

## Templates (`templates/`)

**Purpose**: Jinja2 templates for code generation and documentation creation.

### Template Categories
- **Code Templates**: Python class and module generation
- **Documentation Templates**: API documentation and guides
- **Test Templates**: Test case generation
- **Configuration Templates**: Build and deployment configurations

### Template Files
```
templates/
├── python/
│   ├── enum_template.py.j2         # Enum class generation
│   ├── transaction_template.py.j2   # Transaction builder generation
│   ├── signature_template.py.j2     # Signature implementation generation
│   └── api_method_template.py.j2    # API method generation
├── docs/
│   ├── api_doc_template.md.j2       # API documentation generation
│   └── guide_template.md.j2         # User guide generation
└── tests/
    ├── unit_test_template.py.j2     # Unit test generation
    └── integration_test_template.py.j2  # Integration test generation
```

### Template Usage
```python
from jinja2 import Environment, FileSystemLoader

# Setup template environment
env = Environment(loader=FileSystemLoader('tooling/templates'))
template = env.get_template('python/enum_template.py.j2')

# Render template with data
output = template.render(
    enums=enum_data,
    package_name="accumulate_client",
    version="2.3.0"
)
```

## Validators (`validators/`)

**Purpose**: Validation tools for generated code, manifests, and SDK integrity.

### Validation Tools
- **`validate_manifests.py`** - Type manifest validation
- **`validate_generated.py`** - Generated code verification
- **`validate_signatures.py`** - Signature implementation validation
- **`validate_api_coverage.py`** - API coverage verification

### Validation Execution
```bash
# Run all validations
python tooling/validators/validate_all.py

# Specific validations
python tooling/validators/validate_manifests.py
python tooling/validators/validate_generated.py --component enums
python tooling/validators/validate_api_coverage.py --manifest tooling/type-manifests/api_manifest.json
```

### Validation Reports
```bash
# Generate validation report
python tooling/validators/generate_report.py --output reports/validation_report.json

# View validation status
python tooling/validators/status.py
```

## Development Workflow

### Initial Setup
```bash
# Install tooling dependencies
cd tooling/ts-fixture-exporter/
npm install

# Setup Python tooling environment
pip install -r tooling/requirements.txt

# Validate tooling setup
python tooling/validators/validate_setup.py
```

### Code Generation Workflow
```bash
# 1. Update type manifests from upstream
python tooling/codegen/update_manifests.py --source "C:\Accumulate_Stuff\accumulate"

# 2. Generate SDK components
python tooling/codegen/generate_all.py

# 3. Validate generated code
python tooling/validators/validate_generated.py

# 4. Run tests to verify integration
pytest tests/unit/ -k generated
```

### Cross-Language Testing
```bash
# 1. Generate TypeScript fixtures
cd tooling/ts-fixture-exporter/
TS_FUZZ_N=1000 node export-random-vectors.js > ../../tests/golden/ts_rand_vectors.jsonl

# 2. Run parity tests
python scripts/run_parity_suite.py --audit-root "C:\Accumulate_Stuff\py_parity_audit"

# 3. Validate compatibility
python tooling/validators/validate_compatibility.py
```

## Configuration and Environment

### Environment Variables
```bash
# Code generation
export ACCUMULATE_GO_ROOT="/path/to/accumulate"
export CODEGEN_OUTPUT_DIR="src/accumulate_client"
export TEMPLATE_DIR="tooling/templates"

# TypeScript fixture generation
export TS_FUZZ_N=1000
export TS_SDK_ROOT="/path/to/typescript-sdk"

# Validation
export MANIFEST_DIR="tooling/type-manifests"
export VALIDATION_STRICT=true
```

### Configuration Files
```
tooling/
├── config/
│   ├── codegen.yaml         # Code generation configuration
│   ├── validation.yaml      # Validation rules and thresholds
│   └── templates.yaml       # Template configuration
```

## Advanced Features

### Custom Code Generation
```python
# Custom generator example
from tooling.codegen.base import BaseGenerator

class CustomGenerator(BaseGenerator):
    def generate(self, manifest_data):
        """Generate custom SDK component."""
        template = self.get_template('custom_template.py.j2')
        return template.render(data=manifest_data)

# Usage
generator = CustomGenerator('tooling/templates')
output = generator.generate(manifest_data)
```

### Template Inheritance
```jinja2
{# Base template: base_class.py.j2 #}
class {{ class_name }}:
    """{{ class_description }}"""

    {% block methods %}
    {# Default methods #}
    {% endblock %}

{# Child template: enum_class.py.j2 #}
{% extends "base_class.py.j2" %}

{% block methods %}
{{ super() }}

def to_json(self):
    """Convert enum to JSON representation."""
    return self.value
{% endblock %}
```

### Validation Plugins
```python
# Custom validation plugin
from tooling.validators.base import BaseValidator

class CustomValidator(BaseValidator):
    def validate(self, component):
        """Perform custom validation."""
        errors = []
        # Custom validation logic
        return errors

# Register plugin
from tooling.validators.registry import register_validator
register_validator('custom', CustomValidator)
```

## Maintenance and Updates

### Keeping Tooling Updated
```bash
# Update TypeScript dependencies
cd tooling/ts-fixture-exporter/
npm update

# Update Python tooling dependencies
pip install -r tooling/requirements.txt --upgrade

# Update type manifests
python tooling/codegen/update_manifests.py --source "latest"
```

### Troubleshooting
```bash
# Verify tooling environment
python tooling/validators/validate_setup.py

# Check TypeScript fixture generation
cd tooling/ts-fixture-exporter/
node export-random-vectors.js | head -5

# Validate generated code syntax
python -m py_compile src/accumulate_client/enums.py
```

### Adding New Tools
1. **Create tool in appropriate subdirectory**
2. **Add configuration to relevant config files**
3. **Update this README with usage instructions**
4. **Add validation for the new tool**
5. **Include in integration testing**

## Integration with SDK

### Build Integration
The tooling is integrated into the SDK build process:
- **Pre-build**: Type manifest validation
- **Build**: Code generation from manifests
- **Post-build**: Generated code validation
- **Test**: Cross-language compatibility testing

### CI/CD Integration
```bash
# CI workflow integration
python tooling/validators/validate_all.py
python tooling/codegen/generate_all.py
python scripts/green_gate.py
```

This ensures that all generated code is up-to-date and validated before SDK release.