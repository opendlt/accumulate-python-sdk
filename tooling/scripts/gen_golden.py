#!/usr/bin/env python3
"""
Generate golden vectors for transactions and signatures.

Scans read-only reference sources for canonical examples,
and generates synthetic examples where upstream samples are not available.
"""

import os
import sys
import json
import hashlib
import glob
from pathlib import Path
from typing import Dict, List, Any, Optional

# Add src and tests to path for imports
script_dir = os.path.dirname(__file__)
sys.path.insert(0, os.path.join(script_dir, '..', 'src'))
sys.path.insert(0, os.path.join(script_dir, '..'))

from accumulate_client.tx.builders import BUILDER_REGISTRY
from accumulate_client.enums import SignatureType
from tests.helpers import mk_minimal_valid_body, mk_ed25519_keypair, mk_identity_url


# Read-only source directories
READ_ONLY_SOURCES = [
    r"C:\Accumulate_Stuff\accumulate",
    r"C:\Accumulate_Stuff\accumulate\_claude_audit",
    r"C:\Accumulate_Stuff\accumulate\_analysis_codegen"
]

# Output directories
GOLDEN_DIR = Path("tests/golden")
TX_GOLDEN_DIR = GOLDEN_DIR / "transactions"
SIG_GOLDEN_DIR = GOLDEN_DIR / "signatures"


def ensure_golden_dirs():
    """Create golden vector directories if they don't exist."""
    TX_GOLDEN_DIR.mkdir(parents=True, exist_ok=True)
    SIG_GOLDEN_DIR.mkdir(parents=True, exist_ok=True)


def scan_upstream_sources() -> Dict[str, List[str]]:
    """
    Scan read-only sources for transaction and signature examples.

    Returns:
        Dictionary with 'transactions' and 'signatures' keys containing file paths
    """
    found_files = {'transactions': [], 'signatures': []}

    for source_dir in READ_ONLY_SOURCES:
        if not os.path.exists(source_dir):
            print(f"Warning: Source directory not found: {source_dir}")
            continue

        print(f"Scanning {source_dir}...")

        # Look for JSON files that might contain examples
        json_patterns = [
            "**/*.json",
            "**/test*.json",
            "**/example*.json",
            "**/fixture*.json",
            "**/golden*.json"
        ]

        for pattern in json_patterns:
            for file_path in glob.glob(os.path.join(source_dir, pattern), recursive=True):
                try:
                    with open(file_path, 'r', encoding='utf-8') as f:
                        content = f.read()

                        # Look for transaction-like content
                        if any(keyword in content.lower() for keyword in [
                            'createidentity', 'sendtokens', 'transaction', 'envelope'
                        ]):
                            found_files['transactions'].append(file_path)

                        # Look for signature-like content
                        if any(keyword in content.lower() for keyword in [
                            'signature', 'ed25519', 'publickey', 'sign'
                        ]):
                            found_files['signatures'].append(file_path)

                except (UnicodeDecodeError, IOError):
                    # Skip binary or unreadable files
                    continue

    print(f"Found {len(found_files['transactions'])} potential transaction files")
    print(f"Found {len(found_files['signatures'])} potential signature files")

    return found_files


def extract_upstream_examples(file_paths: List[str], example_type: str) -> Dict[str, Any]:
    """
    Extract examples from upstream files.

    Args:
        file_paths: List of file paths to examine
        example_type: 'transactions' or 'signatures'

    Returns:
        Dictionary mapping example names to example data
    """
    examples = {}

    for file_path in file_paths:
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                data = json.load(f)

            # Extract examples based on type
            if example_type == 'transactions':
                extracted = extract_transaction_examples(data, file_path)
            else:
                extracted = extract_signature_examples(data, file_path)

            examples.update(extracted)

        except (json.JSONDecodeError, IOError) as e:
            print(f"Warning: Could not parse {file_path}: {e}")
            continue

    return examples


def extract_transaction_examples(data: Any, source_path: str) -> Dict[str, Any]:
    """Extract transaction examples from JSON data."""
    examples = {}

    def search_recursive(obj, path=""):
        if isinstance(obj, dict):
            # Look for transaction-like structures
            if 'type' in obj and any(tx_type in str(obj.get('type', '')) for tx_type in BUILDER_REGISTRY.keys()):
                tx_type = str(obj['type']).replace('Body', '').replace('Transaction', '')
                if tx_type in BUILDER_REGISTRY:
                    example_name = f"{tx_type}_upstream_{len(examples)}"
                    examples[example_name] = {
                        'source': 'upstream',
                        'source_file': source_path,
                        'source_path': path,
                        'data': obj,
                        'hash': hashlib.sha256(json.dumps(obj, sort_keys=True).encode()).hexdigest()
                    }

            # Look for envelope structures
            if 'header' in obj and 'body' in obj:
                example_name = f"envelope_upstream_{len(examples)}"
                examples[example_name] = {
                    'source': 'upstream',
                    'source_file': source_path,
                    'source_path': path,
                    'data': obj,
                    'hash': hashlib.sha256(json.dumps(obj, sort_keys=True).encode()).hexdigest()
                }

            # Recurse into nested objects
            for key, value in obj.items():
                search_recursive(value, f"{path}.{key}" if path else key)

        elif isinstance(obj, list):
            for i, item in enumerate(obj):
                search_recursive(item, f"{path}[{i}]" if path else f"[{i}]")

    search_recursive(data)
    return examples


def extract_signature_examples(data: Any, source_path: str) -> Dict[str, Any]:
    """Extract signature examples from JSON data."""
    examples = {}

    def search_recursive(obj, path=""):
        if isinstance(obj, dict):
            # Look for signature structures
            if 'signature' in obj and 'publicKey' in obj:
                sig_type = obj.get('type', 'unknown')
                example_name = f"{sig_type}_upstream_{len(examples)}"
                examples[example_name] = {
                    'source': 'upstream',
                    'source_file': source_path,
                    'source_path': path,
                    'data': obj,
                    'hash': hashlib.sha256(json.dumps(obj, sort_keys=True).encode()).hexdigest()
                }

            # Recurse into nested objects
            for key, value in obj.items():
                search_recursive(value, f"{path}.{key}" if path else key)

        elif isinstance(obj, list):
            for i, item in enumerate(obj):
                search_recursive(item, f"{path}[{i}]" if path else f"[{i}]")

    search_recursive(data)
    return examples


def generate_synthetic_transactions() -> Dict[str, Any]:
    """Generate synthetic transaction examples for all registered types."""
    examples = {}

    for tx_type in BUILDER_REGISTRY.keys():
        try:
            # Get minimal valid body
            minimal_fields = mk_minimal_valid_body(tx_type)

            if not minimal_fields:
                print(f"Warning: No minimal fields defined for {tx_type}")
                continue

            # Create builder and apply fields
            from accumulate_client.tx.builders import get_builder_for
            builder = get_builder_for(tx_type)

            for field_name, field_value in minimal_fields.items():
                builder.with_field(field_name, field_value)

            # Generate canonical JSON
            try:
                canonical_json = builder.to_canonical_json()
                body_data = json.loads(canonical_json.decode('utf-8'))

                examples[tx_type] = {
                    'source': 'synthetic',
                    'source_file': 'generated',
                    'source_path': f'synthetic.{tx_type}',
                    'data': body_data,
                    'hash': hashlib.sha256(canonical_json).hexdigest(),
                    'fields': minimal_fields
                }

            except Exception as e:
                print(f"Warning: Could not generate synthetic {tx_type}: {e}")
                # Create minimal synthetic example
                examples[tx_type] = {
                    'source': 'synthetic',
                    'source_file': 'generated',
                    'source_path': f'synthetic.{tx_type}',
                    'data': minimal_fields,
                    'hash': hashlib.sha256(json.dumps(minimal_fields, sort_keys=True).encode()).hexdigest(),
                    'fields': minimal_fields,
                    'note': f'Minimal synthetic due to generation error: {e}'
                }

        except Exception as e:
            print(f"Error generating synthetic {tx_type}: {e}")

    return examples


def generate_synthetic_signatures() -> Dict[str, Any]:
    """Generate synthetic signature examples for all signature types."""
    examples = {}

    # Get signature types from enum
    sig_types = [(name, getattr(SignatureType, name))
                 for name in dir(SignatureType)
                 if not name.startswith('_') and isinstance(getattr(SignatureType, name), int)]

    # Generate test data to sign
    test_data = b"test transaction data for signature generation"

    for sig_name, sig_value in sig_types:
        if sig_name == 'UNKNOWN':
            continue

        try:
            if sig_name in ('ED25519', 'LEGACYED25519'):
                # Try to generate ED25519 signature
                try:
                    private_key, public_key = mk_ed25519_keypair(seed=sig_value)
                    from accumulate_client.signers.ed25519 import Ed25519Signer

                    signer_url = mk_identity_url(f"synthetic-{sig_name.lower()}.acme")
                    signer = Ed25519Signer(private_key, signer_url)

                    signature_data = signer.to_accumulate_signature(test_data)

                    examples[sig_name] = {
                        'source': 'synthetic',
                        'source_file': 'generated',
                        'source_path': f'synthetic.{sig_name}',
                        'data': signature_data,
                        'hash': hashlib.sha256(json.dumps(signature_data, sort_keys=True).encode()).hexdigest(),
                        'test_data': test_data.hex()
                    }
                except ImportError:
                    # Signer module not available - create placeholder
                    examples[sig_name] = {
                        'source': 'synthetic',
                        'source_file': 'generated',
                        'source_path': f'synthetic.{sig_name}',
                        'data': {
                            'type': sig_name.lower(),
                            'publicKey': mk_ed25519_keypair(seed=sig_value)[1].to_bytes().hex(),
                            'signature': 'placeholder_signature_64_bytes_hex',
                            'note': f'Placeholder for {sig_name} (signer module not available)'
                        },
                        'hash': hashlib.sha256(f'placeholder_{sig_name}'.encode()).hexdigest(),
                        'placeholder': True,
                        'test_data': test_data.hex()
                    }

            else:
                # Unsupported signature type - create placeholder
                examples[sig_name] = {
                    'source': 'synthetic',
                    'source_file': 'generated',
                    'source_path': f'synthetic.{sig_name}',
                    'data': {
                        'type': sig_name.lower(),
                        'note': f'Signature type {sig_name} not yet implemented'
                    },
                    'hash': hashlib.sha256(f'placeholder_{sig_name}'.encode()).hexdigest(),
                    'unsupported': True
                }

        except Exception as e:
            print(f"Error generating synthetic signature {sig_name}: {e}")

    return examples


def save_golden_vectors(examples: Dict[str, Any], example_type: str):
    """Save golden vectors to files."""
    output_dir = TX_GOLDEN_DIR if example_type == 'transactions' else SIG_GOLDEN_DIR

    for example_name, example_data in examples.items():
        output_file = output_dir / f"{example_name}.json"

        # Convert bytes to hex strings for JSON serialization
        serializable_data = convert_bytes_to_hex(example_data)

        with open(output_file, 'w') as f:
            json.dump(serializable_data, f, indent=2, sort_keys=True)

    print(f"Saved {len(examples)} {example_type} golden vectors to {output_dir}")


def convert_bytes_to_hex(obj):
    """Recursively convert bytes objects to hex strings for JSON serialization."""
    if isinstance(obj, bytes):
        return {'__type__': 'bytes', '__value__': obj.hex()}
    elif isinstance(obj, dict):
        return {k: convert_bytes_to_hex(v) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [convert_bytes_to_hex(item) for item in obj]
    else:
        return obj


def generate_index() -> Dict[str, Any]:
    """Generate index of all golden vectors."""
    index = {
        'generated_at': __import__('datetime').datetime.now().isoformat(),
        'transactions': {},
        'signatures': {}
    }

    # Index transaction golden vectors
    for file_path in TX_GOLDEN_DIR.glob("*.json"):
        try:
            with open(file_path, 'r') as f:
                data = json.load(f)

            name = file_path.stem
            index['transactions'][name] = {
                'source': data.get('source', 'unknown'),
                'hash': data.get('hash', ''),
                'file': str(file_path.relative_to(GOLDEN_DIR))
            }
        except Exception as e:
            print(f"Warning: Could not index {file_path}: {e}")

    # Index signature golden vectors
    for file_path in SIG_GOLDEN_DIR.glob("*.json"):
        try:
            with open(file_path, 'r') as f:
                data = json.load(f)

            name = file_path.stem
            index['signatures'][name] = {
                'source': data.get('source', 'unknown'),
                'hash': data.get('hash', ''),
                'file': str(file_path.relative_to(GOLDEN_DIR))
            }
        except Exception as e:
            print(f"Warning: Could not index {file_path}: {e}")

    # Save index
    index_file = GOLDEN_DIR / "index.json"
    with open(index_file, 'w') as f:
        json.dump(index, f, indent=2, sort_keys=True)

    return index


def generate_readme():
    """Generate README for golden vectors."""
    readme_content = """# Golden Vectors

This directory contains golden vectors (canonical test examples) for Accumulate Protocol
transactions and signatures.

## Policy

- **Prefer upstream**: Examples from Go implementation or official sources are preferred
- **Synthetic fallback**: Where upstream examples are not available, deterministic synthetic examples are generated
- **Hash stabilized**: All examples include a hash for change detection

## Structure

- `transactions/`: Transaction golden vectors organized by transaction type
- `signatures/`: Signature golden vectors organized by signature type
- `index.json`: Complete index of all golden vectors with metadata

## Sources

- `upstream`: Extracted from Go implementation or official sources
- `synthetic`: Generated deterministically from minimal valid examples

## Usage

Golden vectors are used for:
- Cross-language compatibility testing
- Regression testing for serialization changes
- Canonical example documentation
- Fuzzing seed data

## Regeneration

To regenerate golden vectors:

```bash
python tooling/scripts/gen_golden.py
```

Set `ACC_UPDATE_GOLDENS=1` to force regeneration of all vectors.
"""

    readme_file = GOLDEN_DIR / "README.md"
    with open(readme_file, 'w') as f:
        f.write(readme_content)


def print_summary(tx_examples: Dict[str, Any], sig_examples: Dict[str, Any]):
    """Print summary table of generated golden vectors."""
    print("\n" + "="*80)
    print("GOLDEN VECTORS SUMMARY")
    print("="*80)

    # Transaction summary
    print("\nTRANSACTIONS:")
    print("-" * 60)
    print(f"{'Transaction Type':<25} {'Source':<12} {'File Path':<23}")
    print("-" * 60)

    for tx_name, tx_data in sorted(tx_examples.items()):
        source = tx_data.get('source', 'unknown')
        file_path = f"transactions/{tx_name}.json"
        print(f"{tx_name:<25} {source:<12} {file_path:<23}")

    # Signature summary
    print(f"\nSIGNATURES:")
    print("-" * 60)
    print(f"{'Signature Type':<25} {'Source':<12} {'File Path':<23}")
    print("-" * 60)

    for sig_name, sig_data in sorted(sig_examples.items()):
        source = sig_data.get('source', 'unknown')
        file_path = f"signatures/{sig_name}.json"
        print(f"{sig_name:<25} {source:<12} {file_path:<23}")

    # Statistics
    tx_upstream = sum(1 for ex in tx_examples.values() if ex.get('source') == 'upstream')
    tx_synthetic = sum(1 for ex in tx_examples.values() if ex.get('source') == 'synthetic')

    sig_upstream = sum(1 for ex in sig_examples.values() if ex.get('source') == 'upstream')
    sig_synthetic = sum(1 for ex in sig_examples.values() if ex.get('source') == 'synthetic')

    print(f"\nSTATISTICS:")
    print(f"Transactions: {len(tx_examples)} total ({tx_upstream} upstream, {tx_synthetic} synthetic)")
    print(f"Signatures:   {len(sig_examples)} total ({sig_upstream} upstream, {sig_synthetic} synthetic)")


def main():
    """Main golden vector generation script."""
    print("Generating golden vectors for Accumulate Protocol...")

    # Ensure output directories exist
    ensure_golden_dirs()

    # Scan upstream sources
    upstream_files = scan_upstream_sources()

    # Extract upstream examples
    print("\nExtracting upstream examples...")
    upstream_tx = extract_upstream_examples(upstream_files['transactions'], 'transactions')
    upstream_sig = extract_upstream_examples(upstream_files['signatures'], 'signatures')

    print(f"Found {len(upstream_tx)} upstream transaction examples")
    print(f"Found {len(upstream_sig)} upstream signature examples")

    # Generate synthetic examples
    print("\nGenerating synthetic examples...")
    synthetic_tx = generate_synthetic_transactions()
    synthetic_sig = generate_synthetic_signatures()

    print(f"Generated {len(synthetic_tx)} synthetic transaction examples")
    print(f"Generated {len(synthetic_sig)} synthetic signature examples")

    # Combine examples (upstream takes precedence)
    all_tx = {**synthetic_tx, **upstream_tx}
    all_sig = {**synthetic_sig, **upstream_sig}

    # Save golden vectors
    save_golden_vectors(all_tx, 'transactions')
    save_golden_vectors(all_sig, 'signatures')

    # Generate index and README
    index = generate_index()
    generate_readme()

    # Print summary
    print_summary(all_tx, all_sig)

    print(f"\nGolden vectors generated successfully!")
    print(f"Index saved to: {GOLDEN_DIR / 'index.json'}")


if __name__ == '__main__':
    main()