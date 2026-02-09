#!/usr/bin/env python3
"""
Dual-source transaction/type codegen for Accumulate Protocol.

Generates complete Pydantic v2 models from either:
1) Live devnet /v3 describe endpoint (default)
2) Pinned YAML manifest for reproducibility

Outputs:
- types_generated.py: All structs/enums/tx body models
- _type_index.py: Registry and lookup helpers
- Optional YAML freeze for reproducibility
"""

import argparse
import json
import hashlib
import re
import sys
from pathlib import Path
from typing import Dict, Any, List, Set, Optional, Tuple
from datetime import datetime

try:
    import requests
    import yaml
except ImportError as e:
    print(f"Missing dependency: {e}")
    print("Install with: pip install requests pyyaml")
    sys.exit(1)

# Add src to path for imports
script_dir = Path(__file__).parent
unified_dir = script_dir.parent
src_dir = unified_dir / "src"
sys.path.insert(0, str(src_dir))


class TypeMapper:
    """Maps Accumulate schema types to Python/Pydantic types."""

    def __init__(self):
        self.generated_types: Set[str] = set()
        self.enums: Dict[str, Dict] = {}
        self.structs: Dict[str, Dict] = {}
        self.tx_types: Dict[str, Dict] = {}
        self.type_dependencies: Dict[str, Set[str]] = {}

    def map_primitive_type(self, acc_type: str) -> str:
        """Map Accumulate primitive types to Python types."""
        type_mapping = {
            'string': 'str',
            'bool': 'bool',
            'int': 'int',
            'int8': 'int',
            'int16': 'int',
            'int32': 'int',
            'int64': 'int',
            'uint': 'int',
            'uint8': 'int',
            'uint16': 'int',
            'uint32': 'int',
            'uint64': 'int',
            'float': 'float',
            'float32': 'float',
            'float64': 'float',
            'bytes': 'bytes',
            'hash': 'bytes',
            'url': 'str',
            'duration': 'int',  # nanoseconds
            'time': 'str',      # ISO format
        }
        return type_mapping.get(acc_type, acc_type)

    def is_primitive(self, acc_type: str) -> bool:
        """Check if type is a primitive."""
        primitives = {
            'string', 'bool', 'int', 'int8', 'int16', 'int32', 'int64',
            'uint', 'uint8', 'uint16', 'uint32', 'uint64',
            'float', 'float32', 'float64', 'bytes', 'hash', 'url',
            'duration', 'time'
        }
        return acc_type in primitives

    def extract_types_from_schema(self, schema: Dict[str, Any]) -> None:
        """Extract all types from the describe schema."""
        if 'types' in schema:
            for type_name, type_def in schema['types'].items():
                if type_def.get('kind') == 'enum':
                    self.enums[type_name] = type_def
                elif type_def.get('kind') == 'struct':
                    self.structs[type_name] = type_def

        # Extract transaction types
        if 'transactions' in schema:
            for tx_name, tx_def in schema['transactions'].items():
                self.tx_types[tx_name] = tx_def

    def generate_enum_code(self, enum_name: str, enum_def: Dict[str, Any]) -> str:
        """Generate Python enum class code."""
        values = enum_def.get('values', [])
        if not values:
            return f"# Empty enum {enum_name} skipped\n"

        code = f'class {enum_name}(str, Enum):\n'
        code += f'    """{enum_def.get("description", f"Enum {enum_name}")}"""\n'

        for value in values:
            if isinstance(value, dict):
                name = value.get('name', '')
                val = value.get('value', name)
                desc = value.get('description', '')
            else:
                name = val = str(value)
                desc = ''

            # Convert to valid Python identifier
            py_name = re.sub(r'[^a-zA-Z0-9_]', '_', name).upper()
            if py_name[0].isdigit():
                py_name = f'_{py_name}'

            if desc:
                code += f'    {py_name} = "{val}"  # {desc}\n'
            else:
                code += f'    {py_name} = "{val}"\n'

        return code + '\n'

    def generate_field_code(self, field_name: str, field_def: Dict[str, Any]) -> Tuple[str, Set[str]]:
        """Generate Pydantic field definition code."""
        field_type = field_def.get('type', 'str')
        description = field_def.get('description', '')
        required = not field_def.get('optional', False)
        repeated = field_def.get('repeated', False)

        dependencies = set()

        # Handle arrays
        if repeated:
            if self.is_primitive(field_type):
                py_type = f"List[{self.map_primitive_type(field_type)}]"
            else:
                py_type = f"List[{field_type}]"
                dependencies.add(field_type)
        else:
            if self.is_primitive(field_type):
                py_type = self.map_primitive_type(field_type)
            else:
                py_type = field_type
                dependencies.add(field_type)

        # Handle optional fields
        if not required:
            py_type = f"Optional[{py_type}]"

        # Generate field definition
        field_parts = []
        if description:
            field_parts.append(f'description="{description}"')

        # Note: Pydantic v2 validators are handled differently - skip for now

        if field_parts:
            field_code = f"Field({', '.join(field_parts)})"
        else:
            field_code = "Field()"

        if not required:
            if repeated:
                field_code = f"Field(default_factory=list, {', '.join(field_parts[1:]) if len(field_parts) > 1 else ''})"
            else:
                field_code = f"Field(default=None, {', '.join(field_parts) if field_parts else ''})"
        elif field_parts:
            field_code = f"Field({', '.join(field_parts)})"
        else:
            field_code = ""

        return f"    {field_name}: {py_type}" + (f" = {field_code}" if field_code else ""), dependencies

    def generate_struct_code(self, struct_name: str, struct_def: Dict[str, Any]) -> Tuple[str, Set[str]]:
        """Generate Python struct class code."""
        fields = struct_def.get('fields', [])
        description = struct_def.get('description', f"Struct {struct_name}")

        all_dependencies = set()

        code = f'class {struct_name}(BaseModel):\n'
        code += f'    """{description}"""\n'

        if not fields:
            code += '    pass\n'
            return code + '\n', all_dependencies

        # Sort fields for deterministic output
        sorted_fields = sorted(fields, key=lambda f: f.get('name', ''))

        for field in sorted_fields:
            field_name = field.get('name', '')
            if not field_name:
                continue

            field_code, deps = self.generate_field_code(field_name, field)
            code += field_code + '\n'
            all_dependencies.update(deps)

        return code + '\n', all_dependencies

    def generate_tx_body_code(self, tx_name: str, tx_def: Dict[str, Any]) -> Tuple[str, Set[str]]:
        """Generate transaction body model code."""
        # Use the transaction definition to create body model
        body_fields = tx_def.get('fields', [])
        description = tx_def.get('description', f"Transaction body for {tx_name}")

        all_dependencies = set()

        code = f'class {tx_name}(BaseModel):\n'
        code += f'    """{description}"""\n'

        if not body_fields:
            code += '    pass\n'
            return code + '\n', all_dependencies

        # Sort fields for deterministic output
        sorted_fields = sorted(body_fields, key=lambda f: f.get('name', ''))

        for field in sorted_fields:
            field_name = field.get('name', '')
            if not field_name:
                continue

            field_code, deps = self.generate_field_code(field_name, field)
            code += field_code + '\n'
            all_dependencies.update(deps)

        return code + '\n', all_dependencies

    def sort_types_by_dependencies(self) -> List[str]:
        """Sort types to ensure dependencies are defined before use."""
        # Simple topological sort
        sorted_types = []
        remaining = set(self.structs.keys()) | set(self.enums.keys()) | set(self.tx_types.keys())

        while remaining:
            # Find types with no unresolved dependencies
            ready = []
            for type_name in remaining:
                deps = self.type_dependencies.get(type_name, set())
                unresolved_deps = deps & remaining
                if not unresolved_deps:
                    ready.append(type_name)

            if not ready:
                # Circular dependency or missing type - just take one
                ready = [next(iter(remaining))]

            for type_name in ready:
                sorted_types.append(type_name)
                remaining.discard(type_name)

        return sorted_types


def fetch_devnet_schema(devnet_url: str = "http://127.0.0.1:26660/v3") -> Dict[str, Any]:
    """Fetch schema from devnet describe endpoint."""
    payload = {
        "jsonrpc": "2.0",
        "method": "describe",
        "id": 1
    }

    try:
        response = requests.post(devnet_url, json=payload, timeout=10)
        response.raise_for_status()

        data = response.json()
        if 'result' not in data:
            if 'error' in data:
                raise ValueError(f"Devnet error: {data['error']}")
            raise ValueError(f"Invalid response format: missing 'result' field")

        return data['result']

    except requests.RequestException as e:
        raise RuntimeError(f"Failed to fetch from devnet: {e}")


def load_yaml_manifest(yaml_path: Path) -> Dict[str, Any]:
    """Load schema from YAML manifest."""
    try:
        with open(yaml_path, 'r', encoding='utf-8') as f:
            return yaml.safe_load(f)
    except Exception as e:
        raise RuntimeError(f"Failed to load YAML manifest: {e}")


def save_yaml_manifest(schema: Dict[str, Any], yaml_path: Path) -> None:
    """Save schema as YAML manifest."""
    yaml_path.parent.mkdir(parents=True, exist_ok=True)

    with open(yaml_path, 'w', encoding='utf-8') as f:
        yaml.dump(schema, f, default_flow_style=False, sort_keys=True, indent=2)


def calculate_content_hash(data: Dict[str, Any]) -> str:
    """Calculate deterministic hash of schema content."""
    # Sort and serialize for consistent hashing
    content = json.dumps(data, sort_keys=True, separators=(',', ':'))
    return hashlib.sha256(content.encode('utf-8')).hexdigest()[:16]


def generate_types_file(mapper: TypeMapper, output_path: Path) -> None:
    """Generate the types_generated.py file."""
    output_path.parent.mkdir(parents=True, exist_ok=True)

    # File header
    header = '''"""
Generated transaction and type models from Accumulate protocol schema.

This file is auto-generated. Do not edit manually.
Use gen_types_from_manifest.py to regenerate.
"""

from enum import Enum
from typing import List, Optional, Dict, Any, Union
from pydantic import BaseModel, Field, field_validator
import re
import json


# Helper functions
def model_to_canonical_json(obj: BaseModel) -> bytes:
    """Convert Pydantic model to canonical JSON bytes."""
    data = obj.model_dump(exclude_none=True, by_alias=True)
    # Convert bytes to hex
    data = _normalize_bytes_to_hex(data)
    # Sort keys and compact format
    json_str = json.dumps(data, sort_keys=True, separators=(',', ':'))
    return json_str.encode('utf-8')


def dict_to_model(tx_type: str, data_dict: Dict[str, Any]):
    """Convert dict to the appropriate model type."""
    from ._type_index import lookup_tx_model

    model_cls = lookup_tx_model(tx_type)
    if not model_cls:
        raise ValueError(f"Unknown transaction type: {tx_type}")

    # Normalize hex strings to bytes where needed
    normalized_data = _normalize_hex_to_bytes(data_dict, model_cls)

    return model_cls.model_validate(normalized_data)


def _normalize_bytes_to_hex(data):
    """Recursively convert bytes to hex strings."""
    if isinstance(data, bytes):
        return data.hex()
    elif isinstance(data, dict):
        return {k: _normalize_bytes_to_hex(v) for k, v in data.items()}
    elif isinstance(data, list):
        return [_normalize_bytes_to_hex(item) for item in data]
    return data


def _normalize_hex_to_bytes(data, model_cls):
    """Recursively convert hex strings to bytes for bytes fields."""
    # This would need field introspection - simplified for now
    return data


'''

    code_parts = [header]


    # Generate enums first
    enum_count = 0
    for enum_name in sorted(mapper.enums.keys()):
        enum_def = mapper.enums[enum_name]
        enum_code = mapper.generate_enum_code(enum_name, enum_def)
        code_parts.append(enum_code)
        enum_count += 1

    # Generate structs
    struct_count = 0
    sorted_types = mapper.sort_types_by_dependencies()

    for type_name in sorted_types:
        if type_name in mapper.structs:
            struct_def = mapper.structs[type_name]
            struct_code, deps = mapper.generate_struct_code(type_name, struct_def)
            code_parts.append(struct_code)
            struct_count += 1

    # Generate transaction body models
    tx_count = 0
    for tx_name in sorted(mapper.tx_types.keys()):
        tx_def = mapper.tx_types[tx_name]
        tx_code, deps = mapper.generate_tx_body_code(tx_name, tx_def)
        code_parts.append(tx_code)
        tx_count += 1

    # Write the file
    with open(output_path, 'w', encoding='utf-8') as f:
        f.write(''.join(code_parts))

    print(f"Generated {output_path}")
    print(f"  - {enum_count} enums")
    print(f"  - {struct_count} structs")
    print(f"  - {tx_count} transaction models")


def generate_registry_file(mapper: TypeMapper, output_path: Path) -> None:
    """Generate the _type_index.py registry file."""
    output_path.parent.mkdir(parents=True, exist_ok=True)

    # Import all generated types
    imports = ["from .types_generated import ("]

    all_types = sorted(set(mapper.enums.keys()) | set(mapper.structs.keys()) | set(mapper.tx_types.keys()))
    for i, type_name in enumerate(all_types):
        comma = "," if i < len(all_types) - 1 else ""
        imports.append(f"    {type_name}{comma}")
    imports.append(")")

    # Create registry
    registry_code = [
        "\n\n# Transaction model registry",
        "TX_MODEL_REGISTRY = {"
    ]

    for tx_name in sorted(mapper.tx_types.keys()):
        registry_code.append(f'    "{tx_name}": {tx_name},')

    registry_code.extend([
        "}",
        "",
        "",
        "def lookup_tx_model(tx_type: str):",
        '    """Look up transaction model class by name."""',
        "    return TX_MODEL_REGISTRY.get(tx_type)",
        "",
        "",
        "# All type registry for general lookup",
        "ALL_TYPES_REGISTRY = {"
    ])

    for type_name in all_types:
        registry_code.append(f'    "{type_name}": {type_name},')

    registry_code.extend([
        "}",
        "",
        "",
        "def lookup_type(type_name: str):",
        '    """Look up any type by name."""',
        "    return ALL_TYPES_REGISTRY.get(type_name)",
    ])

    # File header
    header = '''"""
Type registry and lookup helpers for generated Accumulate types.

This file is auto-generated. Do not edit manually.
Use gen_types_from_manifest.py to regenerate.
"""

'''

    # Write the file
    with open(output_path, 'w', encoding='utf-8') as f:
        f.write(header)
        f.write('\n'.join(imports))
        f.write('\n'.join(registry_code))
        f.write('\n')

    print(f"Generated {output_path}")
    print(f"  - {len(mapper.tx_types)} tx models in registry")
    print(f"  - {len(all_types)} total types")


def generate_report(schema: Dict[str, Any], mapper: TypeMapper, source_info: str, output_path: Path) -> None:
    """Generate schema codegen report."""
    output_path.parent.mkdir(parents=True, exist_ok=True)

    content_hash = calculate_content_hash(schema)

    report = f"""# Schema Codegen Report

**Generated**: {datetime.now().isoformat()}
**Source**: {source_info}
**Content Hash**: {content_hash}

## Summary

- **Enums**: {len(mapper.enums)}
- **Structs**: {len(mapper.structs)}
- **Transaction Models**: {len(mapper.tx_types)}
- **Total Types**: {len(mapper.enums) + len(mapper.structs) + len(mapper.tx_types)}

## Transaction Types

"""

    for tx_name in sorted(mapper.tx_types.keys()):
        tx_def = mapper.tx_types[tx_name]
        field_count = len(tx_def.get('fields', []))
        desc = tx_def.get('description', 'No description')
        report += f"- **{tx_name}**: {field_count} fields - {desc}\n"

    report += "\n## Enums\n\n"
    for enum_name in sorted(mapper.enums.keys()):
        enum_def = mapper.enums[enum_name]
        value_count = len(enum_def.get('values', []))
        desc = enum_def.get('description', 'No description')
        report += f"- **{enum_name}**: {value_count} values - {desc}\n"

    report += "\n## Structs\n\n"
    for struct_name in sorted(mapper.structs.keys()):
        struct_def = mapper.structs[struct_name]
        field_count = len(struct_def.get('fields', []))
        desc = struct_def.get('description', 'No description')
        report += f"- **{struct_name}**: {field_count} fields - {desc}\n"

    with open(output_path, 'w', encoding='utf-8') as f:
        f.write(report)

    print(f"Generated report: {output_path}")


def main():
    parser = argparse.ArgumentParser(description="Generate Accumulate transaction types")

    # Source selection
    source_group = parser.add_mutually_exclusive_group(required=False)
    source_group.add_argument('--devnet', action='store_true', default=True,
                             help='Fetch from devnet /v3 describe (default)')
    source_group.add_argument('--yaml', type=Path,
                             help='Load from YAML manifest instead')

    # Output paths
    parser.add_argument('--out-py', type=Path,
                       default='unified/src/accumulate_client/tx/types_generated.py',
                       help='Output path for generated types')
    parser.add_argument('--out-reg', type=Path,
                       default='unified/src/accumulate_client/tx/_type_index.py',
                       help='Output path for registry')
    parser.add_argument('--out-raw', type=Path,
                       default='unified/reports/describe_raw.json',
                       help='Output path for raw devnet response')
    parser.add_argument('--out-yaml', type=Path,
                       default='unified/tooling/type-manifests/accumulate_v3.yaml',
                       help='Output path for YAML freeze')

    # Options
    parser.add_argument('--freeze', action='store_true',
                       help='When using --devnet, also save YAML snapshot')

    args = parser.parse_args()

    # Resolve paths relative to unified directory
    script_dir = Path(__file__).parent
    unified_dir = script_dir.parent

    for attr in ['out_py', 'out_reg', 'out_raw', 'out_yaml']:
        path = getattr(args, attr)
        if not path.is_absolute():
            setattr(args, attr, unified_dir / path)

    try:
        # Load schema
        if args.yaml:
            print(f"Loading schema from YAML: {args.yaml}")
            schema = load_yaml_manifest(args.yaml)
            source_info = f"YAML manifest: {args.yaml}"
        else:
            print("Fetching schema from devnet...")
            schema = fetch_devnet_schema()
            source_info = "Live devnet /v3 describe"

            # Save raw response
            args.out_raw.parent.mkdir(parents=True, exist_ok=True)
            with open(args.out_raw, 'w', encoding='utf-8') as f:
                json.dump(schema, f, indent=2, sort_keys=True)
            print(f"Saved raw response: {args.out_raw}")

            # Save YAML freeze if requested
            if args.freeze:
                save_yaml_manifest(schema, args.out_yaml)
                print(f"Saved YAML freeze: {args.out_yaml}")

        # Generate types
        print("Processing schema...")
        mapper = TypeMapper()
        mapper.extract_types_from_schema(schema)

        # Calculate dependencies
        for type_name in mapper.structs:
            deps = set()
            struct_def = mapper.structs[type_name]
            for field in struct_def.get('fields', []):
                field_type = field.get('type', '')
                if not mapper.is_primitive(field_type):
                    deps.add(field_type)
            mapper.type_dependencies[type_name] = deps

        for type_name in mapper.tx_types:
            deps = set()
            tx_def = mapper.tx_types[type_name]
            for field in tx_def.get('fields', []):
                field_type = field.get('type', '')
                if not mapper.is_primitive(field_type):
                    deps.add(field_type)
            mapper.type_dependencies[type_name] = deps

        # Generate files
        generate_types_file(mapper, args.out_py)
        generate_registry_file(mapper, args.out_reg)

        # Generate report
        report_path = unified_dir / "reports" / "schema_codegen_report.md"
        generate_report(schema, mapper, source_info, report_path)

        print("\nCodegen completed successfully!")

    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == '__main__':
    main()