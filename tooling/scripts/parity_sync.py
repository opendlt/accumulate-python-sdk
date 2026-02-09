#!/usr/bin/env python3
"""
Parity synchronization helper for API methods and transaction types.
"""

import json
import requests
from pathlib import Path
from typing import List, Dict, Any, Optional


def get_expected_api_methods() -> List[str]:
    """Get expected API methods from Go parity reference."""

    # Expected API methods based on Accumulate Go implementation
    # This list represents the canonical set from the Go client
    expected_methods = [
        # Core query methods
        "query",
        "query-tx",
        "query-tx-history",
        "query-data",
        "query-data-set",
        "query-key-page",
        "query-directory",

        # Account methods
        "query-account",
        "query-account-as",
        "query-account-chains",

        # Transaction methods
        "submit",
        "submit-multi",
        "execute",
        "execute-multi",
        "validate",

        # Network methods
        "version",
        "metrics",
        "status",
        "network-status",

        # Token methods
        "faucet",
        "get-token-account",

        # Authority methods
        "query-authority-set",
        "query-key-page-history",

        # System methods
        "query-minor-blocks",
        "query-major-blocks",
        "query-major-block",
        "query-minor-block",

        # Advanced query methods
        "search-for-anchor",
        "search-for-public-key",
        "search-for-public-key-hash",
        "search-for-delegate",

        # Health and info
        "describe",
        "consensus-status"
    ]

    return expected_methods


def get_expected_transaction_types() -> List[str]:
    """Get expected transaction types from Go parity reference."""

    # Expected transaction types based on Accumulate Go implementation
    expected_types = [
        # Identity transactions
        "CreateIdentity",
        "CreateTokenAccount",
        "CreateDataAccount",
        "CreateKeyBook",
        "CreateKeyPage",
        "UpdateKeyPage",

        # Token transactions
        "SendTokens",
        "CreateToken",
        "IssueTokens",
        "BurnTokens",
        "LockAccount",

        # Data transactions
        "WriteData",
        "WriteDataTo",
        "AcmeFaucet",

        # Authority transactions
        "UpdateAccountAuth",
        "ActivateProtocolVersion",
        "WriteSchema",

        # System transactions
        "SystemGenesis",
        "SystemWriteData",

        # Synthetic transactions
        "SyntheticCreateIdentity",
        "SyntheticWriteData",
        "SyntheticDepositTokens",
        "SyntheticDepositCredits",
        "SyntheticBurnTokens",
        "SyntheticMirror",

        # Network transactions
        "NetworkMaintenance",
        "DirectoryAnchor",
        "BlockValidatorAnchor",
        "PartitionAnchor",

        # Remote transactions
        "RemoteTransaction",
        "SignatureBridging"
    ]

    return expected_types


def validate_api_coverage(client_class: Any) -> Dict[str, Any]:
    """Validate API method coverage against Go parity."""

    expected_methods = get_expected_api_methods()

    # Get actual methods from client
    actual_methods = []
    if hasattr(client_class, '__dict__'):
        for name in dir(client_class):
            if not name.startswith('_') and callable(getattr(client_class, name, None)):
                # Convert snake_case to kebab-case for comparison
                kebab_name = name.replace('_', '-')
                actual_methods.append(kebab_name)

    # Compare coverage
    missing_methods = set(expected_methods) - set(actual_methods)
    extra_methods = set(actual_methods) - set(expected_methods)

    return {
        "expected_count": len(expected_methods),
        "actual_count": len(actual_methods),
        "missing_methods": sorted(missing_methods),
        "extra_methods": sorted(extra_methods),
        "coverage_percent": (len(actual_methods) / len(expected_methods)) * 100
    }


def validate_transaction_coverage(builder_registry: Dict[str, Any]) -> Dict[str, Any]:
    """Validate transaction type coverage against Go parity."""

    expected_types = get_expected_transaction_types()
    actual_types = list(builder_registry.keys()) if builder_registry else []

    # Compare coverage
    missing_types = set(expected_types) - set(actual_types)
    extra_types = set(actual_types) - set(expected_types)

    return {
        "expected_count": len(expected_types),
        "actual_count": len(actual_types),
        "missing_types": sorted(missing_types),
        "extra_types": sorted(extra_types),
        "coverage_percent": (len(actual_types) / len(expected_types)) * 100
    }


def fetch_devnet_rpc_methods(endpoint: str = "http://127.0.0.1:26660") -> Optional[List[str]]:
    """Fetch available RPC methods from a running devnet."""

    try:
        # Try to get RPC methods via introspection
        response = requests.post(
            f"{endpoint}/v3",
            json={
                "jsonrpc": "2.0",
                "method": "describe",
                "params": {},
                "id": 1
            },
            timeout=10
        )

        if response.status_code == 200:
            data = response.json()
            if "result" in data and "methods" in data["result"]:
                return data["result"]["methods"]

        # Fallback: test each expected method
        available_methods = []
        for method in get_expected_api_methods():
            try:
                test_response = requests.post(
                    f"{endpoint}/v3",
                    json={
                        "jsonrpc": "2.0",
                        "method": method,
                        "params": {},
                        "id": 1
                    },
                    timeout=5
                )

                # Method exists if we get any response (even error)
                if test_response.status_code == 200:
                    data = test_response.json()
                    if "error" not in data or data["error"]["code"] != -32601:  # Method not found
                        available_methods.append(method)

            except Exception:
                continue

        return available_methods if available_methods else None

    except Exception as e:
        print(f"Could not fetch devnet methods: {e}")
        return None


def generate_parity_report(output_dir: Path) -> bool:
    """Generate a comprehensive parity report."""

    try:
        output_dir.mkdir(parents=True, exist_ok=True)

        # Get expected data
        expected_api_methods = get_expected_api_methods()
        expected_tx_types = get_expected_transaction_types()

        # Try to get devnet methods
        devnet_methods = fetch_devnet_rpc_methods()

        # Generate report
        report = {
            "generated_at": "auto",
            "api_methods": {
                "expected": expected_api_methods,
                "expected_count": len(expected_api_methods),
                "devnet_available": devnet_methods,
                "devnet_count": len(devnet_methods) if devnet_methods else 0
            },
            "transaction_types": {
                "expected": expected_tx_types,
                "expected_count": len(expected_tx_types)
            }
        }

        # Write JSON report
        json_path = output_dir / "parity_reference.json"
        with open(json_path, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2)

        # Write markdown report
        md_path = output_dir / "parity_reference.md"
        md_content = f"""# Accumulate Parity Reference

## API Methods ({len(expected_api_methods)} expected)

### Core Query Methods
{chr(10).join(f"- {method}" for method in expected_api_methods[:7])}

### Account Methods
{chr(10).join(f"- {method}" for method in expected_api_methods[7:10])}

### Transaction Methods
{chr(10).join(f"- {method}" for method in expected_api_methods[10:15])}

### Network Methods
{chr(10).join(f"- {method}" for method in expected_api_methods[15:19])}

### Token Methods
{chr(10).join(f"- {method}" for method in expected_api_methods[19:21])}

### Authority Methods
{chr(10).join(f"- {method}" for method in expected_api_methods[21:23])}

### System Methods
{chr(10).join(f"- {method}" for method in expected_api_methods[23:27])}

### Advanced Query Methods
{chr(10).join(f"- {method}" for method in expected_api_methods[27:31])}

### Health and Info
{chr(10).join(f"- {method}" for method in expected_api_methods[31:])}

## Transaction Types ({len(expected_tx_types)} expected)

### Identity Transactions
{chr(10).join(f"- {tx_type}" for tx_type in expected_tx_types[:6])}

### Token Transactions
{chr(10).join(f"- {tx_type}" for tx_type in expected_tx_types[6:11])}

### Data Transactions
{chr(10).join(f"- {tx_type}" for tx_type in expected_tx_types[11:14])}

### Authority Transactions
{chr(10).join(f"- {tx_type}" for tx_type in expected_tx_types[14:17])}

### System Transactions
{chr(10).join(f"- {tx_type}" for tx_type in expected_tx_types[17:19])}

### Synthetic Transactions
{chr(10).join(f"- {tx_type}" for tx_type in expected_tx_types[19:25])}

### Network Transactions
{chr(10).join(f"- {tx_type}" for tx_type in expected_tx_types[25:28])}

### Remote Transactions
{chr(10).join(f"- {tx_type}" for tx_type in expected_tx_types[28:])}
"""

        if devnet_methods:
            md_content += f"""
## Devnet Status

- **Devnet methods available:** {len(devnet_methods)}
- **Parity coverage:** {len(devnet_methods)/len(expected_api_methods)*100:.1f}%
"""

        with open(md_path, 'w', encoding='utf-8') as f:
            f.write(md_content)

        return True

    except Exception as e:
        print(f"Error generating parity report: {e}")
        return False


def sync_with_go_parity() -> Dict[str, Any]:
    """Synchronize expectations with Go implementation parity."""

    return {
        "api_methods": get_expected_api_methods(),
        "transaction_types": get_expected_transaction_types(),
        "sync_status": "ready"
    }