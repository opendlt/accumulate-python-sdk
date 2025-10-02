# Golden Vectors

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
python scripts/gen_golden.py
```

Set `ACC_UPDATE_GOLDENS=1` to force regeneration of all vectors.
