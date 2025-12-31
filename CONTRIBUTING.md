# Contributing to opendlt-accumulate

Thank you for your interest in contributing to the Accumulate Python SDK!

## Development Setup

1. Ensure you have Python 3.9+ installed
2. Clone the repository
3. Create a virtual environment and install dependencies:
   ```bash
   python -m venv .venv
   .venv\Scripts\activate  # Windows
   # source .venv/bin/activate  # Linux/Mac
   pip install -e ".[dev]"
   ```
4. Run `python scripts/selfcheck.py` to validate your setup

## Code Guidelines

### Do NOT Edit Generated Files
- `src/accumulate_client/types.py` - Generated type definitions
- `src/accumulate_client/enums.py` - Generated enumeration types

These files are regenerated from the Go repository using code generation tools. If changes are needed, update the generator templates instead.

### Code Standards
- Run `ruff format src/` before committing
- Ensure `ruff check src/` passes with no issues
- Run `mypy src/` for type checking
- Write tests for new functionality
- Follow existing code patterns and naming conventions
- Add inline documentation for public APIs

### Testing
- All tests must pass: `pytest tests/`
- Add golden file tests for encoding/signing compatibility
- Include both unit tests and integration tests
- Test examples to ensure they work end-to-end
- Maintain minimum 85% test coverage

## Submitting Changes

1. **Run Quality Gates**
   ```bash
   python scripts/green_gate.py
   ```

2. **Commit Standards**
   - Use clear, descriptive commit messages
   - Reference issues when applicable
   - Keep commits focused and atomic

3. **Pull Request Process**
   - Ensure all tests pass
   - Update documentation if needed
   - Add entry to CHANGELOG.md
   - Request review from maintainers

## Cross-Language Compatibility

This SDK maintains bit-for-bit compatibility with Go and Dart implementations:

- **Signing**: Must match preimage construction exactly
- **Encoding**: Binary codecs must produce identical bytes
- **LID/LTA**: Key derivation must match character-for-character
- **Golden Tests**: Use shared test vectors when possible

Any changes to cryptographic or encoding logic must be verified against reference implementations.

## Testing Against Networks

### Local DevNet
```bash
# Start local DevNet
cd /path/to/devnet-accumulate-instance
./start-devnet.sh

# Run integration tests
pytest tests/integration/ -v
```

### Kermit Testnet
```bash
# Run examples against testnet
python examples/example01_lite_identities.py
```

## Release Process

1. Update version in `src/accumulate_client/_version.py`
2. Update CHANGELOG.md with release notes
3. Run full validation suite:
   ```bash
   python scripts/green_gate.py
   ```
4. Create release tag and push

## Questions?

- Open an issue for bugs or feature requests
- Check existing issues before creating new ones
- Be respectful and constructive in all interactions
