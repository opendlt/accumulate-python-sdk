# Documentation

Documentation for the Accumulate Python SDK.

## Generating Documentation

```bash
python tooling/scripts/make_docs.py
```

Opens generated documentation in browser at `site/index.html`.

## Documentation Structure

```
docs/
├── index.md                              # Main documentation index
├── accumulate_client_*.md                # Module documentation
└── README.md                             # This file
```

## User Guides

- **[Main README](../README.md)** - Quick start and installation
- **[Examples](../examples/README.md)** - Working code examples
- **[Tests](../tests/README.md)** - Test organization and execution
- **[Scripts](../tooling/scripts/README.md)** - Development scripts

## API Reference

Generated documentation includes:
- Complete API reference for all modules
- Type annotations and docstrings
- Cross-reference links
- Search functionality

## External Resources

- [Accumulate Protocol](https://accumulatenetwork.io/)
- [API Documentation](https://docs.accumulatenetwork.io/)
- [Kermit Testnet Explorer](https://kermit.explorer.accumulatenetwork.io/)

## Contributing Documentation

1. **API Docs**: Automatically generated from docstrings
2. **User Guides**: Maintained in markdown files
3. **Examples**: Runnable examples with embedded docs

### Docstring Format
Use Google-style docstrings:

```python
def submit_transaction(envelope: dict, timeout: float = 30.0) -> dict:
    """Submit a transaction to the network.

    Args:
        envelope: Transaction envelope with header, body, and signatures.
        timeout: Request timeout in seconds.

    Returns:
        API response with transaction ID and status.

    Raises:
        AccumulateAPIError: If the API returns an error.
        AccumulateNetworkError: If the network is unreachable.
    """
    pass
```
