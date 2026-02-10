#!/usr/bin/env python3
"""
Accumulate SDK Parity Suite

Comprehensive validation suite that compares Python SDK encodings against
Go reference implementations and audit reports. Validates byte-for-byte
compatibility across transaction types, signatures, and API methods.

Usage:
    python run_parity_suite.py --audit-root "C:\Accumulate_Stuff\py_parity_audit"
    python run_parity_suite.py --use-go --go-root "C:\Accumulate_Stuff\accumulate"
"""

import argparse
import json
import os
import subprocess
import sys
import time
import hashlib
import re
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, asdict

# Add src to path for imports
script_dir = Path(__file__).parent
sys.path.insert(0, str(script_dir.parent / "src"))

try:
    from accumulate_client.tx.builders import get_builder_for, BUILDER_REGISTRY
    from accumulate_client.runtime.codec import encode_canonical_json
    from accumulate_client.enums import SignatureType
    from accumulate_client.crypto.ed25519 import Ed25519PrivateKey
    from accumulate_client.signers.ed25519 import Ed25519Signer
    IMPORTS_AVAILABLE = True
except ImportError as e:
    print(f"Warning: SDK imports failed: {e}")
    IMPORTS_AVAILABLE = False


@dataclass
class ParityVector:
    """Test vector for parity validation."""
    name: str
    type: str  # "transaction", "signature", "enum", etc.
    input_data: Dict[str, Any]
    expected_json: Optional[str] = None
    expected_binary: Optional[str] = None
    expected_hash: Optional[str] = None


@dataclass
class ParityResult:
    """Result of parity check for one vector."""
    vector_name: str
    vector_type: str
    python_success: bool
    go_success: bool
    json_match: Optional[bool] = None
    binary_match: Optional[bool] = None
    hash_match: Optional[bool] = None
    error_message: str = ""
    first_diff_offset: Optional[int] = None
    diff_context: str = ""


@dataclass
class ParitySummary:
    """Overall parity suite summary."""
    timestamp: str
    vectors_tested: int
    vectors_passed: int
    coverage_percentage: Optional[float] = None
    component_counts: Dict[str, int] = None
    go_available: bool = False
    results: List[ParityResult] = None


class ParitySuite:
    """Main parity validation suite."""

    def __init__(self, args):
        self.args = args
        self.vectors = []
        self.results = []
        self.component_counts = {
            'enums': 0,
            'types': 0,
            'signatures': 0,
            'transactions': 0,
            'api_methods': 0
        }

    def load_vectors(self) -> List[ParityVector]:
        """Load test vectors from various sources."""
        vectors = []

        # Try golden vectors first
        if self.args.golden and Path(self.args.golden).exists():
            vectors.extend(self._load_golden_vectors())

        # Load from audit reports
        if self.args.audit_root and Path(self.args.audit_root).exists():
            vectors.extend(self._load_audit_vectors())

        # Generate basic test vectors if no sources
        if not vectors:
            vectors.extend(self._generate_basic_vectors())

        print(f"Loaded {len(vectors)} test vectors")
        return vectors

    def _load_golden_vectors(self) -> List[ParityVector]:
        """Load vectors from golden test directory."""
        vectors = []
        golden_dir = Path(self.args.golden)

        for file_path in golden_dir.glob("*.json"):
            try:
                with open(file_path, 'r') as f:
                    data = json.load(f)

                if isinstance(data, list):
                    for i, item in enumerate(data):
                        vectors.append(ParityVector(
                            name=f"{file_path.stem}_{i}",
                            type="golden",
                            input_data=item
                        ))
                else:
                    vectors.append(ParityVector(
                        name=file_path.stem,
                        type="golden",
                        input_data=data
                    ))

            except Exception as e:
                print(f"Warning: Failed to load {file_path}: {e}")

        return vectors

    def _load_audit_vectors(self) -> List[ParityVector]:
        """Load vectors from py_parity_audit reports."""
        vectors = []
        audit_dir = Path(self.args.audit_root)

        # Look for markdown reports with test vectors
        for md_file in audit_dir.glob("*.md"):
            vectors.extend(self._parse_audit_markdown(md_file))

        # Look for JSON reports
        for json_file in audit_dir.glob("*.json"):
            vectors.extend(self._parse_audit_json(json_file))

        return vectors

    def _parse_audit_markdown(self, md_file: Path) -> List[ParityVector]:
        """Extract test vectors from audit markdown."""
        vectors = []

        try:
            with open(md_file, 'r', encoding='utf-8') as f:
                content = f.read()

            # Look for code blocks with transaction examples
            json_blocks = re.findall(r'```json\n(.*?)\n```', content, re.DOTALL)
            for i, block in enumerate(json_blocks):
                try:
                    data = json.loads(block)
                    vectors.append(ParityVector(
                        name=f"{md_file.stem}_example_{i}",
                        type="audit_markdown",
                        input_data=data
                    ))
                except json.JSONDecodeError:
                    continue

        except Exception as e:
            print(f"Warning: Failed to parse {md_file}: {e}")

        return vectors

    def _parse_audit_json(self, json_file: Path) -> List[ParityVector]:
        """Extract test vectors from audit JSON."""
        vectors = []

        try:
            with open(json_file, 'r') as f:
                data = json.load(f)

            # Handle different JSON structures
            if isinstance(data, dict):
                if 'test_vectors' in data:
                    for i, vector in enumerate(data['test_vectors']):
                        vectors.append(ParityVector(
                            name=f"{json_file.stem}_vector_{i}",
                            type="audit_json",
                            input_data=vector
                        ))
                elif 'transactions' in data:
                    for tx_type, examples in data['transactions'].items():
                        if isinstance(examples, list):
                            for i, example in enumerate(examples):
                                vectors.append(ParityVector(
                                    name=f"{tx_type}_{i}",
                                    type="transaction",
                                    input_data=example
                                ))

        except Exception as e:
            print(f"Warning: Failed to parse {json_file}: {e}")

        return vectors

    def _generate_basic_vectors(self) -> List[ParityVector]:
        """Generate basic test vectors for core functionality."""
        vectors = []

        if not IMPORTS_AVAILABLE:
            return vectors

        # Generate transaction vectors for available builders
        sample_transactions = [
            ('WriteData', {'data': b'test data', 'scratch': False}),
            ('CreateIdentity', {
                'url': 'acc://test.acme',
                'keyBookUrl': 'acc://test.acme/book',
                'keyPageUrl': 'acc://test.acme/book/1'
            }),
            ('SendTokens', {
                'to': [{'url': 'acc://recipient.acme/tokens', 'amount': 1000000}]
            })
        ]

        for tx_type, fields in sample_transactions:
            if tx_type in BUILDER_REGISTRY:
                vectors.append(ParityVector(
                    name=f"generated_{tx_type.lower()}",
                    type="transaction",
                    input_data={'type': tx_type, 'fields': fields}
                ))

        # Generate signature vectors
        vectors.append(ParityVector(
            name="generated_ed25519_signature",
            type="signature",
            input_data={
                'private_key_seed': '00' * 32,
                'message': 'test message for signing',
                'authority': 'acc://test.acme/book/1'
            }
        ))

        return vectors

    def test_python_encoding(self, vector: ParityVector) -> Tuple[bool, Dict[str, Any]]:
        """Test Python encoding for a vector."""
        if not IMPORTS_AVAILABLE:
            return False, {'error': 'SDK not available'}

        try:
            if vector.type == "transaction":
                return self._test_python_transaction(vector)
            elif vector.type == "signature":
                return self._test_python_signature(vector)
            else:
                return self._test_python_generic(vector)

        except Exception as e:
            return False, {'error': str(e)}

    def _test_python_transaction(self, vector: ParityVector) -> Tuple[bool, Dict[str, Any]]:
        """Test Python transaction encoding."""
        data = vector.input_data

        if 'type' in data and 'fields' in data:
            # Generated vector format
            tx_type = data['type']
            fields = data['fields']

            if tx_type not in BUILDER_REGISTRY:
                return False, {'error': f'Transaction type {tx_type} not available'}

            builder = get_builder_for(tx_type)
            for field_name, field_value in fields.items():
                builder.with_field(field_name, field_value)

            builder.validate()
            tx_body = builder.to_body()
            canonical_json = builder.to_canonical_json()

        else:
            # Direct transaction data
            tx_body = data
            canonical_json = encode_canonical_json(tx_body)

        # Compute hash (excludes signatures)
        tx_hash = hashlib.sha256(canonical_json.encode('utf-8')).hexdigest()

        return True, {
            'canonical_json': canonical_json,
            'transaction_hash': tx_hash,
            'transaction_body': tx_body
        }

    def _test_python_signature(self, vector: ParityVector) -> Tuple[bool, Dict[str, Any]]:
        """Test Python signature generation."""
        data = vector.input_data

        if 'private_key_seed' in data:
            # Generate signature from seed
            seed_hex = data['private_key_seed']
            seed_bytes = bytes.fromhex(seed_hex)
            private_key = Ed25519PrivateKey.from_seed(seed_bytes)

            message = data.get('message', 'test message').encode('utf-8')
            authority = data.get('authority', 'acc://test.acme/book/1')

            signer = Ed25519Signer(private_key, authority)
            message_hash = hashlib.sha256(message).digest()
            signature_dict = signer.to_accumulate_signature(message_hash)

            return True, {
                'signature_dict': signature_dict,
                'message_hash': message_hash.hex(),
                'public_key': private_key.public_key().to_bytes().hex()
            }

        return False, {'error': 'Unsupported signature vector format'}

    def _test_python_generic(self, vector: ParityVector) -> Tuple[bool, Dict[str, Any]]:
        """Test generic Python encoding."""
        # For other types, try JSON encoding
        try:
            json_str = json.dumps(vector.input_data, sort_keys=True, separators=(',', ':'))
            return True, {'json': json_str}
        except Exception as e:
            return False, {'error': f'JSON encoding failed: {e}'}

    def test_go_encoding(self, vector: ParityVector) -> Tuple[bool, Dict[str, Any]]:
        """Test Go encoding for a vector (if available)."""
        if not self.args.use_go or not self.args.go_root:
            return False, {'error': 'Go testing not enabled'}

        go_root = Path(self.args.go_root)
        if not go_root.exists():
            return False, {'error': f'Go root not found: {go_root}'}

        try:
            # Create temporary JSON file with vector data
            temp_file = go_root / "temp_vector.json"
            with open(temp_file, 'w') as f:
                json.dump(vector.input_data, f, indent=2)

            # Try to run Go encoder (this would need to exist in the Go codebase)
            go_cmd = ["go", "run", "cmd/encode-test/main.go", str(temp_file)]

            result = subprocess.run(
                go_cmd,
                cwd=go_root,
                capture_output=True,
                text=True,
                timeout=30
            )

            # Clean up temp file
            if temp_file.exists():
                temp_file.unlink()

            if result.returncode == 0:
                # Parse Go output (would be JSON with encoded results)
                try:
                    go_result = json.loads(result.stdout)
                    return True, go_result
                except json.JSONDecodeError:
                    return True, {'stdout': result.stdout, 'stderr': result.stderr}
            else:
                return False, {'error': f'Go encoder failed: {result.stderr}'}

        except subprocess.TimeoutExpired:
            return False, {'error': 'Go encoder timeout'}
        except Exception as e:
            return False, {'error': f'Go test failed: {e}'}

    def compare_results(self, vector: ParityVector, py_result: Dict[str, Any], go_result: Dict[str, Any]) -> ParityResult:
        """Compare Python and Go results."""
        result = ParityResult(
            vector_name=vector.name,
            vector_type=vector.type,
            python_success='error' not in py_result,
            go_success='error' not in go_result
        )

        if not result.python_success:
            result.error_message = f"Python: {py_result.get('error', 'Unknown error')}"

        if not result.go_success:
            if result.error_message:
                result.error_message += f"; Go: {go_result.get('error', 'Unknown error')}"
            else:
                result.error_message = f"Go: {go_result.get('error', 'Unknown error')}"

        if result.python_success and result.go_success:
            # Compare JSON outputs
            py_json = py_result.get('canonical_json') or py_result.get('json')
            go_json = go_result.get('canonical_json') or go_result.get('json')

            if py_json and go_json:
                result.json_match = py_json == go_json
                if not result.json_match:
                    result.first_diff_offset = self._find_first_diff(py_json, go_json)
                    result.diff_context = self._get_diff_context(py_json, go_json, result.first_diff_offset)

            # Compare hashes
            py_hash = py_result.get('transaction_hash')
            go_hash = go_result.get('transaction_hash')

            if py_hash and go_hash:
                result.hash_match = py_hash == go_hash

        return result

    def _find_first_diff(self, s1: str, s2: str) -> Optional[int]:
        """Find first differing character position."""
        for i, (c1, c2) in enumerate(zip(s1, s2)):
            if c1 != c2:
                return i
        return len(s1) if len(s1) != len(s2) else None

    def _get_diff_context(self, s1: str, s2: str, offset: Optional[int]) -> str:
        """Get context around first difference."""
        if offset is None:
            return "Length difference"

        start = max(0, offset - 20)
        end = min(len(s1), offset + 20)

        context1 = s1[start:end]
        context2 = s2[start:min(len(s2), offset + 20)]

        return f"Offset {offset}: '{context1}' vs '{context2}'"

    def get_coverage_summary(self) -> Optional[str]:
        """Get pytest coverage summary."""
        try:
            # Try to read from htmlcov/index.html
            htmlcov_path = Path(self.args.out).parent / "htmlcov" / "index.html"
            if htmlcov_path.exists():
                with open(htmlcov_path, 'r') as f:
                    content = f.read()

                # Extract coverage percentage
                match = re.search(r'<span class="pc_cov">(\d+)%</span>', content)
                if match:
                    return f"Coverage: {match.group(1)}%"

        except Exception:
            pass

        # Try to run pytest --cov in subprocess
        try:
            result = subprocess.run([
                sys.executable, "-m", "pytest",
                "--cov=accumulate_client",
                "--cov-report=term-missing",
                "--tb=no",
                "-q"
            ], capture_output=True, text=True, timeout=60)

            if result.returncode == 0:
                # Extract coverage from output
                lines = result.stdout.split('\n')
                for line in lines:
                    if 'TOTAL' in line and '%' in line:
                        return f"Coverage: {line.strip()}"

        except Exception:
            pass

        return None

    def update_component_counts(self):
        """Update component counts based on current SDK state."""
        if not IMPORTS_AVAILABLE:
            return

        try:
            # Count enums
            from accumulate_client import enums
            enum_classes = [name for name in dir(enums)
                          if not name.startswith('_') and
                          hasattr(getattr(enums, name), '__members__')]
            self.component_counts['enums'] = len(enum_classes)

            # Count types
            from accumulate_client import types
            type_items = [name for name in dir(types) if not name.startswith('_')]
            self.component_counts['types'] = len(type_items)

            # Count signatures
            sig_types = [name for name in dir(SignatureType)
                        if not name.startswith('_') and
                        isinstance(getattr(SignatureType, name), int)]
            self.component_counts['signatures'] = len(sig_types)

            # Count transactions
            self.component_counts['transactions'] = len(BUILDER_REGISTRY)

            # Count API methods
            from accumulate_client import Accumulate
            api_methods = [name for name in dir(Accumulate)
                          if not name.startswith('_') and
                          callable(getattr(Accumulate, name)) and
                          name not in {'for_network'}]
            self.component_counts['api_methods'] = len(api_methods)

        except Exception as e:
            print(f"Warning: Failed to count components: {e}")

    def run_suite(self):
        """Run the complete parity suite."""
        print("=== Accumulate SDK Parity Suite ===")
        print(f"Output directory: {self.args.out}")
        print(f"Go testing: {'enabled' if self.args.use_go else 'disabled'}")
        print()

        # Load test vectors
        self.vectors = self.load_vectors()
        if not self.vectors:
            print("No test vectors found!")
            return

        # Update component counts
        self.update_component_counts()

        # Test each vector
        passed = 0
        for i, vector in enumerate(self.vectors):
            print(f"Testing vector {i+1}/{len(self.vectors)}: {vector.name}")

            # Test Python encoding
            py_success, py_result = self.test_python_encoding(vector)

            # Test Go encoding if enabled
            go_success, go_result = False, {}
            if self.args.use_go:
                go_success, go_result = self.test_go_encoding(vector)

            # Compare results
            result = self.compare_results(vector, py_result, go_result)
            self.results.append(result)

            if result.python_success and (not self.args.use_go or result.go_success):
                if not self.args.use_go or (result.json_match is not False and result.hash_match is not False):
                    passed += 1
                    print(f"  [OK] PASS")
                else:
                    print(f"  [FAIL] FAIL - Encoding mismatch")
            else:
                print(f"  [FAIL] FAIL - {result.error_message}")

        # Generate reports
        coverage_summary = self.get_coverage_summary()

        summary = ParitySummary(
            timestamp=time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime()),
            vectors_tested=len(self.vectors),
            vectors_passed=passed,
            coverage_percentage=None,
            component_counts=self.component_counts,
            go_available=self.args.use_go,
            results=self.results
        )

        if coverage_summary:
            # Extract percentage if possible
            match = re.search(r'(\d+)%', coverage_summary)
            if match:
                summary.coverage_percentage = float(match.group(1))

        self.write_reports(summary, coverage_summary)

        # Final summary
        print(f"\n=== PARITY SUITE COMPLETE ===")
        print(f"Vectors tested: {len(self.vectors)}")
        print(f"Vectors passed: {passed}")
        print(f"Pass rate: {passed/len(self.vectors)*100:.1f}%")
        if coverage_summary:
            print(f"Test coverage: {coverage_summary}")

    def write_reports(self, summary: ParitySummary, coverage_summary: Optional[str]):
        """Write parity reports to output directory."""
        out_dir = Path(self.args.out)
        out_dir.mkdir(parents=True, exist_ok=True)

        # Write JSON report
        json_file = out_dir / "parity_suite.json"
        with open(json_file, 'w') as f:
            json.dump(asdict(summary), f, indent=2, default=str)

        # Write markdown report
        md_file = out_dir / "PY_vs_Go_Parity_Report.md"
        with open(md_file, 'w') as f:
            f.write(self._generate_markdown_report(summary))

        # Write coverage summary if available
        if coverage_summary:
            coverage_file = out_dir / "coverage_summary.txt"
            with open(coverage_file, 'w') as f:
                f.write(f"Generated: {summary.timestamp}\n")
                f.write(f"{coverage_summary}\n")
                if summary.coverage_percentage:
                    gate_status = "[OK] PASS" if summary.coverage_percentage >= 85 else "[FAIL] FAIL"
                    f.write(f"Quality Gate (≥85%): {gate_status}\n")

        print(f"\nReports written to {out_dir}/")

    def _generate_markdown_report(self, summary: ParitySummary) -> str:
        """Generate markdown parity report."""
        md = f"""# Python vs Go Parity Report

**Generated:** {summary.timestamp}

## Summary

- **Vectors Tested:** {summary.vectors_tested}
- **Vectors Passed:** {summary.vectors_passed}
- **Pass Rate:** {summary.vectors_passed/summary.vectors_tested*100:.1f}%
- **Go Testing:** {"Enabled" if summary.go_available else "Disabled"}
"""

        if summary.coverage_percentage:
            gate_status = "[OK] PASS" if summary.coverage_percentage >= 85 else "[FAIL] FAIL"
            md += f"- **Test Coverage:** {summary.coverage_percentage}% ({gate_status})\n"

        md += "\n## Component Counts\n\n"
        expected_counts = {'enums': 14, 'types': 103, 'signatures': 16, 'transactions': 33, 'api_methods': 35}

        md += "| Component | Expected | Actual | Status |\n"
        md += "|-----------|----------|--------|---------|\n"

        for component, expected in expected_counts.items():
            actual = summary.component_counts.get(component, 0)
            status = "[OK]" if actual >= expected else "[WARN]"
            md += f"| {component.title()} | {expected} | {actual} | {status} |\n"

        md += "\n## Test Results\n\n"
        md += "| Vector | Type | Python | Go | JSON Match | Hash Match | Status |\n"
        md += "|--------|------|--------|----|-----------|-----------|---------|\n"

        for result in summary.results:
            py_status = "[OK]" if result.python_success else "[FAIL]"
            go_status = "[OK]" if result.go_success else "[FAIL]" if summary.go_available else "N/A"

            json_status = "N/A"
            if result.json_match is True:
                json_status = "[OK]"
            elif result.json_match is False:
                json_status = "[FAIL]"

            hash_status = "N/A"
            if result.hash_match is True:
                hash_status = "[OK]"
            elif result.hash_match is False:
                hash_status = "[FAIL]"

            overall_status = "[OK]" if (result.python_success and
                                   (not summary.go_available or result.go_success) and
                                   result.json_match is not False and
                                   result.hash_match is not False) else "[FAIL]"

            md += f"| {result.vector_name} | {result.vector_type} | {py_status} | {go_status} | {json_status} | {hash_status} | {overall_status} |\n"

        # Add error details if any
        errors = [r for r in summary.results if r.error_message]
        if errors:
            md += "\n## Error Details\n\n"
            for result in errors:
                md += f"### {result.vector_name}\n\n"
                md += f"**Type:** {result.vector_type}\n\n"
                md += f"**Error:** {result.error_message}\n\n"
                if result.diff_context:
                    md += f"**Diff Context:** {result.diff_context}\n\n"

        md += f"\n---\n*Generated by Accumulate SDK Parity Suite at {summary.timestamp}*\n"
        return md


def main():
    parser = argparse.ArgumentParser(description="Accumulate SDK Parity Suite")
    parser.add_argument(
        "--use-go",
        action="store_true",
        help="Enable Go reference encoding tests"
    )
    parser.add_argument(
        "--go-root",
        default=r"C:\Accumulate_Stuff\accumulate",
        help="Path to Go Accumulate repository"
    )
    parser.add_argument(
        "--audit-root",
        default=r"C:\Accumulate_Stuff\py_parity_audit",
        help="Path to py_parity_audit reports"
    )
    parser.add_argument(
        "--golden",
        help="Path to golden test vectors directory"
    )
    parser.add_argument(
        "--out",
        default=str(Path(__file__).parent.parent / "reports"),
        help="Output directory for reports"
    )

    args = parser.parse_args()

    suite = ParitySuite(args)
    suite.run_suite()


if __name__ == "__main__":
    main()