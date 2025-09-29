# Code Regeneration Guide

This guide explains how to regenerate the Python client code from the Accumulate API specifications.

## Prerequisites

1. Go development environment
2. Access to the Accumulate core repository at `C:\Accumulate_Stuff\accumulate`
3. Python templates in `C:\Accumulate_Stuff\opendlt-python-v2v3-sdk\tooling\templates\`

## Regeneration Command

To regenerate the unified Python client with both V2 and V3 API support:

```bash
cd C:/Accumulate_Stuff/accumulate
tools/cmd/gen-sdk/gen-sdk.exe \
  --lang python \
  --template-dir C:/Accumulate_Stuff/opendlt-python-v2v3-sdk/tooling/templates \
  --api-version both \
  --unified \
  --out C:/Accumulate_Stuff/opendlt-python-v2v3-sdk/unified/src/accumulate_client \
  internal/api/v2/methods.yml
```

## What Gets Generated

The command generates these files:

- `__init__.py` - Package initialization and exports
- `client.py` - Main AccumulateClient class with all API methods
- `json_rpc_client.py` - Low-level JSON-RPC client implementation
- `types.py` - Type definitions for API data structures

## Template Files

The Python templates are located in `tooling/templates/`:

- `__init__.py.tmpl` - Package initialization template
- `client.py.tmpl` - Main client class template
- `json_rpc_client.py.tmpl` - JSON-RPC client template
- `types.py.tmpl` - Type definitions template

## After Regeneration

1. **DO NOT manually edit generated files** - they will be overwritten
2. Run tests to verify functionality: `pytest -q`
3. Run linting (optional): `python -m ruff check src/`
4. Update examples if API surface has changed

## Template Modifications

If you need to modify the generated code:

1. Edit the appropriate template file in `tooling/templates/`
2. Regenerate using the command above
3. Test the changes
4. Commit both template changes and regenerated code

## Gen-SDK Tool Enhancements

The gen-sdk tool has been enhanced with Python-specific template functions:

- `pythonType` - Maps Go types to Python types
- `pythonClassName` - Converts names to Python class naming conventions
- `pythonMethodName` - Converts names to Python method naming (snake_case)
- `pythonFieldName` - Converts field names to Python conventions
- `pythonFromDict` / `pythonToDict` - Helpers for serialization

These functions are defined in `C:\Accumulate_Stuff\accumulate\tools\cmd\gen-sdk\main.go`.

## Troubleshooting

### Gen-SDK Not Found
If the gen-sdk tool is not found, rebuild it:
```bash
cd C:/Accumulate_Stuff/accumulate/tools/cmd/gen-sdk
go build -o gen-sdk.exe .
```

### Template Errors
Check template syntax and ensure all template variables are properly defined in the gen-sdk tool.

### API Changes
If the core API specification changes, you may need to update templates to handle new data structures or method signatures.