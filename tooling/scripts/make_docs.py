#!/usr/bin/env python3
"""
Documentation site generator for Accumulate Python SDK.

Generates unified/docs/ and unified/site/ by introspecting public modules
without external dependencies.

Usage:
    python tooling/scripts/make_docs.py
"""

import os
import sys
import inspect
import importlib
from pathlib import Path
from typing import Dict, List, Any, Optional


def safe_import(module_name: str) -> Optional[Any]:
    """Safely import a module, returning None if import fails."""
    try:
        return importlib.import_module(module_name)
    except ImportError as e:
        print(f"Warning: Could not import {module_name}: {e}")
        return None


def get_module_info(module) -> Dict[str, Any]:
    """Extract information from a module."""
    if module is None:
        return {}

    info = {
        'name': getattr(module, '__name__', 'unknown'),
        'doc': getattr(module, '__doc__', ''),
        'file': getattr(module, '__file__', ''),
        'classes': [],
        'functions': [],
        'constants': []
    }

    try:
        for name, obj in inspect.getmembers(module):
            if name.startswith('_'):
                continue

            if inspect.isclass(obj):
                class_info = {
                    'name': name,
                    'doc': getattr(obj, '__doc__', ''),
                    'methods': []
                }

                # Get public methods
                for method_name, method_obj in inspect.getmembers(obj):
                    if (not method_name.startswith('_') and
                        callable(method_obj) and
                        method_name != 'mro'):

                        try:
                            sig = str(inspect.signature(method_obj))
                        except (ValueError, TypeError):
                            sig = '(...)'

                        class_info['methods'].append({
                            'name': method_name,
                            'signature': sig,
                            'doc': getattr(method_obj, '__doc__', '')
                        })

                info['classes'].append(class_info)

            elif inspect.isfunction(obj):
                try:
                    sig = str(inspect.signature(obj))
                except (ValueError, TypeError):
                    sig = '(...)'

                info['functions'].append({
                    'name': name,
                    'signature': sig,
                    'doc': getattr(obj, '__doc__', '')
                })

            elif isinstance(obj, (str, int, float, list, dict, tuple)):
                info['constants'].append({
                    'name': name,
                    'type': type(obj).__name__,
                    'value': str(obj)[:100] + ('...' if len(str(obj)) > 100 else '')
                })

    except Exception as e:
        print(f"Warning: Error introspecting {info['name']}: {e}")

    return info


def generate_markdown_page(module_info: Dict[str, Any]) -> str:
    """Generate markdown documentation for a module."""
    if not module_info:
        return "# Module Documentation\n\nModule could not be loaded.\n"

    md = f"# {module_info['name']}\n\n"

    if module_info.get('doc'):
        md += f"{module_info['doc']}\n\n"

    # Constants
    if module_info.get('constants'):
        md += "## Constants\n\n"
        for const in module_info['constants']:
            md += f"- **{const['name']}** ({const['type']}): `{const['value']}`\n"
        md += "\n"

    # Functions
    if module_info.get('functions'):
        md += "## Functions\n\n"
        for func in module_info['functions']:
            md += f"### {func['name']}{func['signature']}\n\n"
            if func.get('doc'):
                md += f"{func['doc']}\n\n"

    # Classes
    if module_info.get('classes'):
        md += "## Classes\n\n"
        for cls in module_info['classes']:
            md += f"### {cls['name']}\n\n"
            if cls.get('doc'):
                md += f"{cls['doc']}\n\n"

            if cls.get('methods'):
                md += f"#### Methods\n\n"
                for method in cls['methods']:
                    md += f"- **{method['name']}{method['signature']}**"
                    if method.get('doc'):
                        doc_summary = method['doc'].split('\n')[0]
                        md += f": {doc_summary}"
                    md += "\n"
                md += "\n"

    return md


def generate_index_page(modules: Dict[str, Dict[str, Any]]) -> str:
    """Generate index page with links to all modules."""
    md = "# Accumulate Python SDK - Advanced Features Documentation\n\n"
    md += "This documentation covers the advanced features introduced in Phase 3.\n\n"

    md += "## Core Client Features\n\n"

    if 'accumulate_client.client.streaming' in modules:
        md += "- **[Streaming Client](accumulate_client_client_streaming.md)** - Real-time WebSocket streaming\n"

    md += "\n## Transport Layer\n\n"

    if 'accumulate_client.transport.ws' in modules:
        md += "- **[WebSocket Transport](accumulate_client_transport_ws.md)** - WebSocket connection management\n"

    md += "\n## Performance Optimization\n\n"

    perf_modules = [
        ('accumulate_client.performance.pool', 'HTTP Connection Pool'),
        ('accumulate_client.performance.batch', 'Request Batching'),
        ('accumulate_client.performance.pipeline', 'Transaction Pipeline')
    ]

    for mod_name, display_name in perf_modules:
        if mod_name in modules:
            safe_name = mod_name.replace('.', '_')
            md += f"- **[{display_name}]({safe_name}.md)** - {display_name} implementation\n"

    md += "\n## Error Recovery\n\n"

    recovery_modules = [
        ('accumulate_client.recovery.retry', 'Retry Policies'),
        ('accumulate_client.recovery.circuit_breaker', 'Circuit Breaker'),
        ('accumulate_client.recovery.replay', 'Transaction Replay')
    ]

    for mod_name, display_name in recovery_modules:
        if mod_name in modules:
            safe_name = mod_name.replace('.', '_')
            md += f"- **[{display_name}]({safe_name}.md)** - {display_name} implementation\n"

    md += "\n## Monitoring & Telemetry\n\n"

    monitoring_modules = [
        ('accumulate_client.monitoring.metrics', 'Metrics Registry'),
        ('accumulate_client.monitoring.exporters', 'Metrics Exporters'),
        ('accumulate_client.monitoring.instrumentation', 'Instrumentation')
    ]

    for mod_name, display_name in monitoring_modules:
        if mod_name in modules:
            safe_name = mod_name.replace('.', '_')
            md += f"- **[{display_name}]({safe_name}.md)** - {display_name} implementation\n"

    md += "\n## Quick Start Examples\n\n"

    md += """
### WebSocket Streaming

```python
from accumulate_client import StreamingAccumulateClient, AccumulateClient

async with StreamingAccumulateClient(AccumulateClient("https://api.accumulate.io/v3")) as streaming:
    async for block in streaming.stream_blocks():
        print(f"Block {block.block_height}")
```

### Request Batching

```python
from accumulate_client.performance import BatchClient

async with BatchClient("https://api.accumulate.io/v3") as batch:
    results = await batch.submit_many([
        {"method": "query", "params": {"url": "acc://account1"}},
        {"method": "query", "params": {"url": "acc://account2"}}
    ])
```

### Error Recovery

```python
from accumulate_client.recovery import ExponentialBackoff

retry_policy = ExponentialBackoff(max_attempts=5)
result = await retry_policy.execute(client.submit, transaction)
```

### Metrics Export

```python
from accumulate_client.monitoring import get_registry, JsonExporter

registry = get_registry()
exporter = JsonExporter()
metrics_json = exporter.export(registry)
print(metrics_json)
```
"""

    return md


def main():
    """Main documentation generation function."""
    # Ensure we're in the right directory
    script_dir = Path(__file__).parent.absolute()
    project_root = script_dir.parent
    os.chdir(project_root)

    # Add src to Python path
    src_path = project_root / "src"
    if str(src_path) not in sys.path:
        sys.path.insert(0, str(src_path))

    # Create output directories
    docs_dir = project_root / "docs"
    site_dir = project_root / "site"

    docs_dir.mkdir(exist_ok=True)
    site_dir.mkdir(exist_ok=True)

    print(f"Generating documentation in {docs_dir} and {site_dir}")

    # Modules to document
    modules_to_document = [
        # Core client
        'accumulate_client.client.streaming',

        # Transport
        'accumulate_client.transport.ws',

        # Performance
        'accumulate_client.performance.pool',
        'accumulate_client.performance.batch',
        'accumulate_client.performance.pipeline',

        # Recovery
        'accumulate_client.recovery.retry',
        'accumulate_client.recovery.circuit_breaker',
        'accumulate_client.recovery.replay',

        # Monitoring
        'accumulate_client.monitoring.metrics',
        'accumulate_client.monitoring.exporters',
        'accumulate_client.monitoring.instrumentation'
    ]

    # Import and analyze modules
    modules = {}
    successful_imports = 0

    for module_name in modules_to_document:
        print(f"Processing {module_name}...")
        module = safe_import(module_name)
        if module:
            modules[module_name] = get_module_info(module)
            successful_imports += 1
        else:
            modules[module_name] = {}

    # Generate documentation files
    pages_generated = 0

    # Generate index page
    index_content = generate_index_page(modules)
    index_file = docs_dir / "index.md"
    with open(index_file, 'w', encoding='utf-8') as f:
        f.write(index_content)

    # Copy index to site directory as well
    site_index = site_dir / "index.md"
    with open(site_index, 'w', encoding='utf-8') as f:
        f.write(index_content)

    pages_generated += 1

    # Generate module pages
    for module_name, module_info in modules.items():
        if module_info:
            content = generate_markdown_page(module_info)

            # Safe filename (replace dots with underscores)
            safe_name = module_name.replace('.', '_')

            # Write to docs directory
            docs_file = docs_dir / f"{safe_name}.md"
            with open(docs_file, 'w', encoding='utf-8') as f:
                f.write(content)

            # Write to site directory
            site_file = site_dir / f"{safe_name}.md"
            with open(site_file, 'w', encoding='utf-8') as f:
                f.write(content)

            pages_generated += 1

    # Generate file listings
    docs_files = list(docs_dir.glob("*.md"))
    site_files = list(site_dir.glob("*.md"))

    # Summary output
    print(f"\nDocumentation generation complete!")
    print(f"Modules processed: {successful_imports}/{len(modules_to_document)}")
    print(f"Pages generated: {pages_generated}")
    print(f"Docs directory: {len(docs_files)} files")
    print(f"Site directory: {len(site_files)} files")

    print(f"\nGenerated files:")
    for file_path in sorted(docs_files):
        print(f"  docs/{file_path.name}")

    if successful_imports == 0:
        print("\nWarning: No modules could be imported. Check that the SDK is installed.")
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())