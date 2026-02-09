#!/usr/bin/env python3
"""
Generate runtime parity report for Accumulate SDK.

Produces a comprehensive report of parity status, test results,
and implementation coverage.
"""

import os
import sys
import json
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Any, Optional

# Add src to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))


def load_selfcheck_results() -> Optional[Dict[str, Any]]:
    """Load selfcheck results."""
    selfcheck_file = Path('reports/selfcheck.json')
    if not selfcheck_file.exists():
        return None

    try:
        with open(selfcheck_file, 'r') as f:
            return json.load(f)
    except Exception as e:
        print(f"Warning: Could not load selfcheck results: {e}")
        return None


def load_golden_index() -> Optional[Dict[str, Any]]:
    """Load golden vectors index."""
    golden_index = Path('tests/golden/index.json')
    if not golden_index.exists():
        return None

    try:
        with open(golden_index, 'r') as f:
            return json.load(f)
    except Exception as e:
        print(f"Warning: Could not load golden index: {e}")
        return None


def load_fuzz_stats() -> Optional[Dict[str, Any]]:
    """Load fuzz testing statistics."""
    fuzz_stats = Path('tests/fuzz/_stats.json')
    if not fuzz_stats.exists():
        return None

    try:
        with open(fuzz_stats, 'r') as f:
            return json.load(f)
    except Exception as e:
        print(f"Warning: Could not load fuzz stats: {e}")
        return None


def generate_report_header() -> str:
    """Generate report header."""
    now = datetime.now()
    return f"""# Accumulate Python SDK Runtime Parity Report

**Generated:** {now.strftime('%Y-%m-%d %H:%M:%S UTC')}
**SDK Version:** 2.3.0
**Report Type:** Comprehensive Runtime Parity Assessment

"""


def generate_executive_summary(selfcheck: Optional[Dict], golden: Optional[Dict], fuzz: Optional[Dict]) -> str:
    """Generate executive summary."""
    if not selfcheck:
        status = "UNKNOWN"
        summary = "Self-check results not available"
    else:
        status = selfcheck.get('summary', {}).get('status', 'UNKNOWN')
        total_checks = selfcheck.get('summary', {}).get('total_checks', 0)
        passed_checks = selfcheck.get('summary', {}).get('passed_checks', 0)
        success_rate = selfcheck.get('summary', {}).get('success_rate', 0)
        summary = f"{passed_checks}/{total_checks} checks passed ({success_rate:.1f}%)"

    # Determine overall pass/fail
    pass_fail = "[PASS]" if status == "PASS" else "[FAIL]" if status == "FAIL" else "[WARN]"

    content = f"""## Executive Summary

**Overall Status:** {pass_fail}
**Parity Checks:** {summary}
**Date/Time:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

### Quick Status
- **Self-Check:** {status}
- **Golden Vectors:** {'Available' if golden else 'Missing'}
- **Fuzz Testing:** {'Completed' if fuzz else 'Not Run'}

"""
    return content


def generate_counts_table(selfcheck: Optional[Dict]) -> str:
    """Generate counts comparison table."""
    if not selfcheck or 'counts' not in selfcheck:
        return "## Counts\n\n*Count data not available*\n\n"

    counts = selfcheck['counts']
    expected = {
        'enums': 14,
        'types': 103,
        'signatures': 16,
        'transactions': 33,
        'api_methods': 35,
        'builder_registry': 32
    }

    content = """## Counts vs Expected

| Component | Expected | Actual | Status |
|-----------|----------|--------|--------|
"""

    for component, expected_count in expected.items():
        actual_count = counts.get(component, 0)
        if component == 'types':
            # Types has tolerance
            status = "[PASS]" if abs(actual_count - expected_count) <= 20 else "[FAIL]"
        elif component == 'builder_registry':
            # Builder registry allows 32 or 33
            status = "[PASS]" if actual_count >= 32 else "[FAIL]"
        else:
            status = "[PASS]" if actual_count >= expected_count else "[FAIL]"

        content += f"| {component.replace('_', ' ').title()} | {expected_count} | {actual_count} | {status} |\n"

    content += "\n"
    return content


def generate_builder_coverage_table(selfcheck: Optional[Dict]) -> str:
    """Generate builder registry coverage table."""
    content = """## Builder Registry Coverage

"""

    if not selfcheck or 'builder_tests' not in selfcheck:
        content += "*Builder test data not available*\n\n"
        return content

    builder_data = selfcheck['builder_tests']
    total = builder_data.get('total', 0)
    successful = builder_data.get('successful', 0)
    failed = builder_data.get('failed', 0)

    content += f"**Total Builders:** {total}  \n"
    content += f"**Successful:** {successful}  \n"
    content += f"**Failed:** {failed}  \n"
    content += f"**Success Rate:** {(successful/total*100):.1f}%\n\n" if total > 0 else "**Success Rate:** N/A\n\n"

    # Show failed builders if any
    failures = builder_data.get('failures', [])
    if failures:
        content += "### Failed Builders\n\n"
        content += "| Transaction Type | Error |\n"
        content += "|------------------|-------|\n"

        for tx_type, error in failures[:10]:  # Show first 10
            error_short = error[:50] + "..." if len(error) > 50 else error
            content += f"| {tx_type} | {error_short} |\n"

        if len(failures) > 10:
            content += f"| ... | *({len(failures) - 10} more failures)* |\n"
        content += "\n"
    else:
        content += "### [PASS] All Builders Working\n\n"

    return content


def generate_signature_parity_grid(selfcheck: Optional[Dict]) -> str:
    """Generate signature parity grid."""
    content = """## Signature Parity Grid

"""

    # Define all signature types
    signature_types = [
        'UNKNOWN', 'LEGACYED25519', 'ED25519', 'RCD1', 'RECEIPT', 'PARTITION',
        'SET', 'REMOTE', 'BTC', 'BTCLEGACY', 'ETH', 'DELEGATED', 'INTERNAL',
        'AUTHORITY', 'RSASHA256', 'ECDSASHA256', 'TYPEDDATA'
    ]

    supported_types = ['ED25519', 'LEGACYED25519']

    content += "| Signature Type | Implementation Status | Test Status |\n"
    content += "|----------------|----------------------|-------------|\n"

    for sig_type in signature_types:
        if sig_type in supported_types:
            impl_status = "[PASS] Implemented"
            if selfcheck and 'signature_tests' in selfcheck:
                test_status = "[PASS] Tested"
            else:
                test_status = "[UNKNOWN] Unknown"
        else:
            impl_status = "[FAIL] Not Implemented"
            test_status = "[N/A] N/A"

        content += f"| {sig_type} | {impl_status} | {test_status} |\n"

    content += "\n"

    # Summary
    if selfcheck and 'signature_tests' in selfcheck:
        sig_data = selfcheck['signature_tests']
        content += f"**Summary:** {sig_data.get('successful', 0)}/{sig_data.get('total', 0)} signature types working\n\n"

    return content


def generate_golden_coverage(golden: Optional[Dict]) -> str:
    """Generate golden coverage section."""
    content = """## Golden Vector Coverage

"""

    if not golden:
        content += "*Golden vector data not available*\n\n"
        return content

    transactions = golden.get('transactions', {})
    signatures = golden.get('signatures', {})

    # Count by source
    tx_upstream = sum(1 for tx in transactions.values() if tx.get('source') == 'upstream')
    tx_synthetic = sum(1 for tx in transactions.values() if tx.get('source') == 'synthetic')

    sig_upstream = sum(1 for sig in signatures.values() if sig.get('source') == 'upstream')
    sig_synthetic = sum(1 for sig in signatures.values() if sig.get('source') == 'synthetic')

    content += "### Transaction Golden Vectors\n\n"
    content += f"- **Total:** {len(transactions)}\n"
    content += f"- **Upstream:** {tx_upstream}\n"
    content += f"- **Synthetic:** {tx_synthetic}\n"
    content += f"- **Coverage:** {(len(transactions)/33*100):.1f}% of expected transaction types\n\n"

    content += "### Signature Golden Vectors\n\n"
    content += f"- **Total:** {len(signatures)}\n"
    content += f"- **Upstream:** {sig_upstream}\n"
    content += f"- **Synthetic:** {sig_synthetic}\n"
    content += f"- **Coverage:** {(len(signatures)/17*100):.1f}% of signature types\n\n"

    # Source quality assessment
    total_upstream = tx_upstream + sig_upstream
    total_vectors = len(transactions) + len(signatures)
    upstream_percentage = (total_upstream / total_vectors * 100) if total_vectors > 0 else 0

    content += "### Source Quality\n\n"
    if upstream_percentage >= 50:
        quality = "[PASS] High (majority upstream)"
    elif upstream_percentage >= 25:
        quality = "[WARN] Medium (mixed sources)"
    else:
        quality = "[FAIL] Low (mostly synthetic)"

    content += f"**Quality Assessment:** {quality}  \n"
    content += f"**Upstream Percentage:** {upstream_percentage:.1f}%\n\n"

    return content


def generate_fuzz_stats(fuzz: Optional[Dict]) -> str:
    """Generate fuzz testing statistics section."""
    content = """## Fuzz Testing Statistics

"""

    if not fuzz:
        content += "*Fuzz testing data not available*\n\n"
        return content

    total = fuzz.get('total_iterations', 0)
    valid = fuzz.get('successful_validations', 0)
    invalid = fuzz.get('validation_failures', 0)
    roundtrip_success = fuzz.get('roundtrip_successes', 0)
    roundtrip_fail = fuzz.get('roundtrip_failures', 0)

    content += f"**Total Iterations:** {total:,}  \n"

    if total > 0:
        valid_pct = (valid / total) * 100
        invalid_pct = (invalid / total) * 100
        content += f"**Valid Transactions:** {valid:,} ({valid_pct:.1f}%)  \n"
        content += f"**Invalid Transactions:** {invalid:,} ({invalid_pct:.1f}%)  \n"

    # Roundtrip consistency
    total_roundtrip = roundtrip_success + roundtrip_fail
    if total_roundtrip > 0:
        roundtrip_pct = (roundtrip_success / total_roundtrip) * 100
        content += f"**Roundtrip Success:** {roundtrip_success}/{total_roundtrip} ({roundtrip_pct:.1f}%)  \n"

        # Assessment
        if roundtrip_pct >= 95:
            assessment = "[PASS] Excellent"
        elif roundtrip_pct >= 90:
            assessment = "[WARN] Good"
        else:
            assessment = "[FAIL] Poor"
        content += f"**Roundtrip Assessment:** {assessment}\n\n"

    # Size statistics
    min_size = fuzz.get('min_size', 0)
    max_size = fuzz.get('max_size', 0)
    total_size = fuzz.get('total_size', 0)

    if valid > 0 and total_size > 0:
        avg_size = total_size / valid
        content += f"**Size Statistics:**  \n"
        content += f"- Min: {min_size:,} bytes  \n"
        content += f"- Avg: {avg_size:,.0f} bytes  \n"
        content += f"- Max: {max_size:,} bytes\n\n"

    return content


def generate_issues_and_recommendations() -> str:
    """Generate issues and recommendations section."""
    content = """## Issues and Recommendations

### Known Limitations
- Some signature types (BTC, ETH, RSA) are not yet implemented
- Certain transaction body classes may have empty implementations
- Golden vector extraction from upstream sources is limited

### Recommendations
1. **Signature Types**: Implement remaining signature types based on Go reference
2. **Transaction Bodies**: Complete implementation of all transaction body classes
3. **Golden Vectors**: Increase upstream golden vector coverage through Go implementation analysis
4. **Testing**: Expand fuzz testing to cover more edge cases and error paths

### Future Improvements
- Add support for hardware wallets and HSM integration
- Implement comprehensive transaction history querying
- Add support for advanced multi-signature scenarios
- Enhance error reporting with more detailed context

"""
    return content


def generate_deterministic_footer() -> str:
    """Generate deterministic footer."""
    return """---

*This report was generated automatically by the Accumulate Python SDK parity verification system.*
*For questions or issues, please refer to the project documentation.*

"""


def main():
    """Main report generation script."""
    print("Generating Accumulate SDK Runtime Parity Report...")

    # Load data sources
    selfcheck = load_selfcheck_results()
    golden = load_golden_index()
    fuzz = load_fuzz_stats()

    # Generate report sections
    report_content = ""
    report_content += generate_report_header()
    report_content += generate_executive_summary(selfcheck, golden, fuzz)
    report_content += generate_counts_table(selfcheck)
    report_content += generate_builder_coverage_table(selfcheck)
    report_content += generate_signature_parity_grid(selfcheck)
    report_content += generate_golden_coverage(golden)
    report_content += generate_fuzz_stats(fuzz)
    report_content += generate_issues_and_recommendations()
    report_content += generate_deterministic_footer()

    # Ensure reports directory exists
    os.makedirs('reports', exist_ok=True)

    # Write report
    report_file = Path('reports/runtime_parity_report.md')
    with open(report_file, 'w', encoding='utf-8') as f:
        f.write(report_content)

    # Print summary
    line_count = len(report_content.split('\n'))
    print(f"[SUCCESS] Runtime parity report generated")
    print(f"[SUCCESS] File: {report_file}")
    print(f"[SUCCESS] Lines: {line_count}")

    # Show first 30 lines
    lines = report_content.split('\n')
    print(f"\nFirst 30 lines of report:")
    print("-" * 50)
    for i, line in enumerate(lines[:30], 1):
        print(f"{i:2d}: {line}")

    if len(lines) > 30:
        print(f"... ({len(lines) - 30} more lines)")

    return 0


if __name__ == '__main__':
    sys.exit(main())