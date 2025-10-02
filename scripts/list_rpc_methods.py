#!/usr/bin/env python3
"""
JSON-RPC Method Discovery Utility

Discovers available RPC methods from Accumulate devnet using the "describe" method
and generates reports in JSON and Markdown formats.

Usage:
    python list_rpc_methods.py                           # Print to stdout
    python list_rpc_methods.py --out ./reports/         # Save to files
"""

import json
import argparse
import sys
from pathlib import Path
from typing import Dict, Any, Optional, List

try:
    import urllib.request
    import urllib.parse
    import urllib.error
except ImportError:
    print("urllib not available, using fallback")
    urllib = None


def make_rpc_request(endpoint: str, method: str, params: Any = None) -> Optional[Dict[str, Any]]:
    """Make JSON-RPC request to endpoint."""
    if not urllib:
        print("❌ urllib not available for HTTP requests")
        return None

    payload = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": method,
        "params": params or {}
    }

    try:
        # Encode payload
        data = json.dumps(payload).encode('utf-8')

        # Create request
        req = urllib.request.Request(
            endpoint,
            data=data,
            headers={
                'Content-Type': 'application/json',
                'Accept': 'application/json'
            }
        )

        # Make request
        with urllib.request.urlopen(req, timeout=10) as response:
            result = json.loads(response.read().decode('utf-8'))
            return result

    except urllib.error.URLError as e:
        print(f"❌ Network error: {e}")
        return None
    except json.JSONDecodeError as e:
        print(f"❌ JSON decode error: {e}")
        return None
    except Exception as e:
        print(f"❌ Request failed: {e}")
        return None


def discover_rpc_methods(endpoint: str) -> Optional[Dict[str, Any]]:
    """Discover RPC methods using the 'describe' method."""
    print(f"Discovering RPC methods from {endpoint}")

    # Call describe method
    result = make_rpc_request(endpoint, "describe")

    if not result:
        return None

    if "error" in result:
        print(f"RPC error: {result['error']}")
        return None

    if "result" not in result:
        print(f"No result in response")
        return None

    describe_result = result["result"]

    # Extract methods information
    methods_info = {
        "endpoint": endpoint,
        "timestamp": None,
        "version": describe_result.get("version", "unknown"),
        "methods": [],
        "categories": {},
        "total_count": 0
    }

    # Process methods
    if "methods" in describe_result:
        methods = describe_result["methods"]
        methods_info["methods"] = methods
        methods_info["total_count"] = len(methods)

        # Categorize methods
        categories = {}
        for method in methods:
            method_name = method if isinstance(method, str) else method.get("name", "unknown")

            # Simple categorization based on method name patterns
            if "query" in method_name.lower():
                category = "Query"
            elif "submit" in method_name.lower() or "send" in method_name.lower():
                category = "Transaction"
            elif "describe" in method_name.lower() or "version" in method_name.lower():
                category = "Meta"
            elif "faucet" in method_name.lower():
                category = "Faucet"
            elif "metrics" in method_name.lower() or "status" in method_name.lower():
                category = "Status"
            else:
                category = "Other"

            if category not in categories:
                categories[category] = []
            categories[category].append(method_name)

        methods_info["categories"] = categories

    print(f"Discovered {methods_info['total_count']} RPC methods")
    return methods_info


def print_methods_summary(methods_data: Dict[str, Any]):
    """Print methods summary to stdout."""
    print(f"\nRPC Methods Summary")
    print(f"Endpoint: {methods_data['endpoint']}")
    print(f"Version: {methods_data['version']}")
    print(f"Total Methods: {methods_data['total_count']}")

    print(f"\nMethods by Category:")
    for category, method_list in methods_data['categories'].items():
        print(f"  {category}: {len(method_list)} methods")

    print(f"\nAll Methods:")
    for i, method in enumerate(methods_data['methods'], 1):
        method_name = method if isinstance(method, str) else method.get("name", "unknown")
        print(f"  {i:2d}. {method_name}")


def save_rpc_reports(methods_data: Dict[str, Any], output_dir: Path):
    """Save RPC methods to JSON and Markdown files."""
    output_dir = Path(output_dir)
    output_dir.mkdir(exist_ok=True)

    # Save JSON report
    json_file = output_dir / "rpc_methods.json"
    with open(json_file, 'w', encoding='utf-8') as f:
        json.dump(methods_data, f, indent=2, ensure_ascii=False)
    print(f"JSON report saved: {json_file}")

    # Save Markdown report
    md_file = output_dir / "rpc_methods.md"
    with open(md_file, 'w', encoding='utf-8') as f:
        f.write(generate_markdown_report(methods_data))
    print(f"Markdown report saved: {md_file}")


def generate_markdown_report(methods_data: Dict[str, Any]) -> str:
    """Generate Markdown report of RPC methods."""
    md = []
    md.append("# Accumulate JSON-RPC Methods")
    md.append("")
    md.append(f"**Endpoint:** `{methods_data['endpoint']}`")
    md.append(f"**Version:** `{methods_data['version']}`")
    md.append(f"**Total Methods:** {methods_data['total_count']}")
    md.append(f"**Discovered:** Auto-generated by `list_rpc_methods.py`")
    md.append("")

    # Methods by category
    md.append("## Methods by Category")
    md.append("")

    for category, method_list in methods_data['categories'].items():
        md.append(f"### {category} ({len(method_list)} methods)")
        md.append("")
        for method in sorted(method_list):
            md.append(f"- `{method}`")
        md.append("")

    # All methods table
    md.append("## Complete Method List")
    md.append("")
    md.append("| # | Method Name | Category |")
    md.append("|---|-------------|----------|")

    # Find category for each method
    method_to_category = {}
    for category, method_list in methods_data['categories'].items():
        for method in method_list:
            method_to_category[method] = category

    for i, method in enumerate(methods_data['methods'], 1):
        method_name = method if isinstance(method, str) else method.get("name", "unknown")
        category = method_to_category.get(method_name, "Other")
        md.append(f"| {i} | `{method_name}` | {category} |")

    md.append("")

    # Usage instructions
    md.append("## Usage Instructions")
    md.append("")
    md.append("### Making RPC Calls")
    md.append("")
    md.append("```bash")
    md.append("# Example: Query network status")
    md.append("curl -X POST http://127.0.0.1:26660/v3 \\")
    md.append("  -H 'Content-Type: application/json' \\")
    md.append("  -d '{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"status\",\"params\":{}}'")
    md.append("")
    md.append("# Example: Query account")
    md.append("curl -X POST http://127.0.0.1:26660/v3 \\")
    md.append("  -H 'Content-Type: application/json' \\")
    md.append("  -d '{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"query\",\"params\":{\"url\":\"acc://example.acme\"}}'")
    md.append("```")
    md.append("")

    md.append("### Python Example")
    md.append("")
    md.append("```python")
    md.append("import json")
    md.append("import urllib.request")
    md.append("")
    md.append("def call_rpc(method, params=None):")
    md.append("    payload = {")
    md.append("        'jsonrpc': '2.0',")
    md.append("        'id': 1,")
    md.append("        'method': method,")
    md.append("        'params': params or {}")
    md.append("    }")
    md.append("    ")
    md.append("    req = urllib.request.Request(")
    md.append(f"        '{methods_data['endpoint']}',")
    md.append("        data=json.dumps(payload).encode('utf-8'),")
    md.append("        headers={'Content-Type': 'application/json'}")
    md.append("    )")
    md.append("    ")
    md.append("    with urllib.request.urlopen(req) as response:")
    md.append("        return json.loads(response.read().decode('utf-8'))")
    md.append("")
    md.append("# Example usage")
    md.append("result = call_rpc('status')")
    md.append("print(json.dumps(result, indent=2))")
    md.append("```")
    md.append("")

    md.append("---")
    md.append("*Report generated by Accumulate Python SDK*")

    return '\n'.join(md)


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(description="Discover Accumulate JSON-RPC methods")
    parser.add_argument(
        "--endpoint",
        default="http://127.0.0.1:26660/v3",
        help="Accumulate RPC endpoint"
    )
    parser.add_argument(
        "--out",
        help="Output directory for JSON and Markdown reports"
    )

    args = parser.parse_args()

    # Discover methods
    methods_data = discover_rpc_methods(args.endpoint)

    if not methods_data:
        print("Failed to discover RPC methods")
        return 1

    # Print summary
    print_methods_summary(methods_data)

    # Save reports if output directory specified
    if args.out:
        save_rpc_reports(methods_data, Path(args.out))

    return 0


if __name__ == "__main__":
    sys.exit(main())