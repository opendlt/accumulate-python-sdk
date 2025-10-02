# Write-Check: C:\Accumulate_Stuff\opendlt-python-v2v3-sdk\unified\scripts\test_failure_atlas.py
# (This script must only write within unified\)
import os
import re
import sys
import json
import time
import shlex
import socket
import pathlib
import subprocess
from collections import defaultdict, Counter
from typing import Dict, List, Tuple, Any

ABS_ROOT = pathlib.Path(r"C:\Accumulate_Stuff\opendlt-python-v2v3-sdk\unified").resolve()
REPORTS_DIR = ABS_ROOT / "reports"
REPORT_MD = REPORTS_DIR / "test_failure_atlas.md"
REPORT_JSON = REPORTS_DIR / "test_failure_atlas.json"
THIS_FILE = pathlib.Path(__file__).resolve()

def _assert_write_path(p: pathlib.Path):
    if not str(p.resolve()).startswith(str(ABS_ROOT)):
        print(f"ABORT: attempted write outside absolute root: {p}")
        sys.exit(2)

def _ensure_reports_dir():
    _assert_write_path(REPORTS_DIR)
    if not REPORTS_DIR.exists():
        print(f"Write-Check: {REPORTS_DIR}")
        REPORTS_DIR.mkdir(parents=True, exist_ok=True)

def _repo_root() -> pathlib.Path:
    return ABS_ROOT.parent  # unified/.. = repo root

def _tests_dir_candidates() -> List[pathlib.Path]:
    # Prefer unified/tests; also try tests/ as fallback
    return [
        ABS_ROOT / "tests",
        _repo_root() / "tests",  # fallback if some tests still at root
    ]

def _list_test_files() -> List[str]:
    files = []
    for base in _tests_dir_candidates():
        if base.exists():
            for p in base.rglob("test_*.py"):
                files.append(str(p))
            for p in base.rglob("*_test.py"):
                files.append(str(p))
    return sorted(set(files))

def _python_exe() -> str:
    return sys.executable

def _run(cmd: List[str], cwd: pathlib.Path) -> Tuple[int, str, str, float]:
    t0 = time.time()
    proc = subprocess.Popen(
        cmd, cwd=str(cwd), stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
    )
    out, err = proc.communicate()
    dt = time.time() - t0
    return proc.returncode, out, err, dt

def _devnet_health(timeout=1.0) -> bool:
    try:
        with socket.create_connection(("127.0.0.1", 26660), timeout=timeout):
            return True
    except Exception:
        return False

# --- Pytest runners ---------------------------------------------------------

def _pytest_collect_only(repo: pathlib.Path) -> Tuple[int, str, str, float]:
    # Collect all tests, quiet but list nodes
    cmd = [
        _python_exe(), "-m", "pytest", "-q",
        str(ABS_ROOT / "tests"),
        "--collect-only",
    ]
    return _run(cmd, repo)

def _pytest_full_run(repo: pathlib.Path) -> Tuple[int, str, str, float]:
    # Full run; NO coverage gate; capture everything; no maxfail
    cmd = [
        _python_exe(), "-m", "pytest",
        str(ABS_ROOT / "tests"),
        "-vv", "-rA", "--maxfail=0",
    ]
    return _run(cmd, repo)

# --- Parsing helpers --------------------------------------------------------

FAIL_SPLIT_RE = re.compile(r"=+ (FAILURES|ERRORS) =+|=+ short test summary info =+", re.IGNORECASE)
NODE_LINE_RE = re.compile(r"^([^\s]+::[^\s]+)(?:\s+)?$", re.MULTILINE)

def _extract_nodes_from_collect(stdout: str) -> List[str]:
    # For -q --collect-only, pytest prints each node on a line
    nodes = []
    for line in stdout.splitlines():
        line = line.strip()
        if not line or line.startswith("no tests collected"):
            continue
        # node id lines look like: tests/module/test_file.py::TestClass::test_method
        if "::" in line and (line.endswith("]") or True):
            nodes.append(line)
        elif line.endswith(".py"):
            nodes.append(line)
    # Deduplicate
    return sorted(set(nodes))

def _categorize_failure_block(block: str) -> Dict[str, Any]:
    """
    Heuristically determine failure category and core info from a single failure block.
    """
    info = {
        "category": "AssertionError",
        "test_node": None,
        "file": None,
        "line": None,
        "exception": None,
        "message": None,
        "hints": [],
    }

    # Test node usually appears at top like: __________ TestClass::test_x __________
    m_node = re.search(r"_{2,}\s+([^\s].*?)\s+_{2,}", block)
    if m_node:
        info["test_node"] = m_node.group(1).strip()

    # File:line - look for pytest style trace line endings
    m_loc = re.search(r"^([^\n]+\.py):(\d+):", block, re.MULTILINE)
    if m_loc:
        info["file"], info["line"] = m_loc.group(1), m_loc.group(2)

    # Exception type
    m_exc = re.search(r"^\s*E\s+([A-Za-z_][A-Za-z0-9_\.]*):\s*(.*)$", block, re.MULTILINE)
    if m_exc:
        info["exception"] = m_exc.group(1)
        info["message"] = m_exc.group(2)

    # Category heuristics
    text = block
    if "ModuleNotFoundError" in text or "No module named" in text:
        info["category"] = "Import/ModuleNotFound"
        info["hints"].append("Check package paths and __init__.py exports; ensure dependency installed.")
    elif "ImportError" in text:
        info["category"] = "ImportError"
        info["hints"].append("Reconcile import names vs actual structure; add missing exports.")
    elif "AttributeError" in text and (".signers." in text or ".crypto." in text):
        info["category"] = "AttributeError (SDK symbol missing)"
        info["hints"].append("Export or implement the missing symbol in accumulate_client.")
    elif "AttributeError" in text:
        info["category"] = "AttributeError"
        info["hints"].append("Either implementation missing attribute or test imports wrong name.")
    elif "TypeError" in text and "positional" in text:
        info["category"] = "TypeError (signature mismatch)"
        info["hints"].append("Align function/method signatures with tests/Go parity.")
    elif "requests.exceptions" in text or "ConnectionError" in text:
        info["category"] = "Network/Request Error"
        info["hints"].append("Check devnet availability and endpoint; align method names (v3).")
    elif "Timeout" in text or "timed out" in text:
        info["category"] = "Timeout"
        info["hints"].append("Adjust timeouts or ensure async path signals completion.")
    elif "AssertionError" in text or re.search(r"^\s*E\s+assert ", text, re.MULTILINE):
        info["category"] = "AssertionError"
        info["hints"].append("Compare expected vs actual; parity/hashing/encoding differences are common.")
    elif "NameError" in text:
        info["category"] = "NameError"
        info["hints"].append("Missing symbol in test or SDK scope; add import/export.")
    else:
        # leave default category
        pass

    # Go parity hints
    if "ed25519" in text.lower() or "LEGACYED25519".lower() in text.lower():
        info["hints"].append("Verify ed25519/legacy implementations & sign/verify parity with Go.")
    if "network-status" in text or "describe" in text:
        info["hints"].append("Ensure v3 JSON-RPC method names are correct against devnet /v3 describe.")

    return info

def _split_failures(stdout: str, stderr: str) -> List[str]:
    """
    Split full pytest output into failure blocks by scanning section markers.
    """
    # Try to find 'FAILURES' and 'ERRORS' sections
    content = stdout + "\n" + stderr
    parts = re.split(r"\n=+ (FAILURES|ERRORS) =+\n", content)
    if len(parts) <= 1:
        # Maybe only short summary exists — capture that region
        m = re.search(r"=+ short test summary info =+\n(.*)", content, re.DOTALL)
        if m:
            return [m.group(1)]
        return []
    # parts like: [before, 'FAILURES', fail_content, 'ERRORS', error_content, after...]
    blocks = []
    for i in range(1, len(parts), 2):
        label = parts[i]
        body = parts[i+1]
        # Further split by dashed separators between failures
        subs = re.split(r"\n_{10,}.*?\n", body)
        # If split lost markers, fallback to chunk
        subblocks = [s.strip() for s in subs if s.strip()]
        if not subblocks:
            subblocks = [body.strip()]
        blocks.extend(subblocks)
    return blocks

def main():
    # Safety: ensure we only write under unified\
    if not str(THIS_FILE).startswith(str(ABS_ROOT)):
        print("ABORT: script is not located under unified\\")
        sys.exit(2)

    _ensure_reports_dir()

    repo = _repo_root()
    tests_found = _list_test_files()
    if not tests_found:
        # Note in the report: no tests discovered on disk
        print("No test files discovered under unified\\tests or root\\tests; running pytest anyway for its discovery.")
    else:
        print(f"Discovered {len(tests_found)} test files.")

    # Collect-only
    rc_col, out_col, err_col, dt_col = _pytest_collect_only(repo)
    collected_nodes = _extract_nodes_from_collect(out_col)
    print(f"[Collect] return={rc_col} nodes={len(collected_nodes)} time={dt_col:.1f}s")

    # Full run (no coverage)
    print("[Run] executing full test suite (no coverage gate)...")
    rc_run, out_run, err_run, dt_run = _pytest_full_run(repo)
    print(f"[Run] return={rc_run} time={dt_run:.1f}s")

    # Parse
    failure_blocks = _split_failures(out_run, err_run)
    issues: List[Dict[str, Any]] = []
    for blk in failure_blocks:
        info = _categorize_failure_block(blk)
        info["raw"] = blk
        issues.append(info)

    # Stats
    counts_by_cat = Counter([i["category"] for i in issues])
    files_counter = Counter([i["file"] for i in issues if i.get("file")])
    modules_counter = Counter()
    for i in issues:
        fp = i.get("file")
        if not fp:
            continue
        # derive "module-ish" name under accumulate_client/
        try:
            p = pathlib.Path(fp)
            k = None
            if "accumulate_client" in fp:
                idx = fp.replace("\\", "/").split("accumulate_client", 1)[-1].lstrip("/\\")
                k = "accumulate_client/" + idx
            elif "\\tests\\" in fp or "/tests/" in fp:
                idx = fp.replace("\\", "/").split("tests", 1)[-1].lstrip("/\\")
                k = "tests/" + idx
            modules_counter[k or fp] += 1
        except Exception:
            modules_counter[fp] += 1

    # JSON sidecar
    atlas = {
        "env": {
            "python": sys.version,
            "repo_root": str(repo),
            "unified_root": str(ABS_ROOT),
            "devnet_reachable": _devnet_health(),
        },
        "collect": {
            "rc": rc_col,
            "nodes": len(collected_nodes),
        },
        "run": {
            "rc": rc_run,
            "duration_sec": dt_run,
        },
        "issues": issues,
        "by_category": counts_by_cat,
        "by_file": files_counter,
        "by_module": modules_counter,
        "stdout_tail": out_run[-2000:],  # keep it light
        "stderr_tail": err_run[-2000:],
    }

    # Write JSON
    _assert_write_path(REPORT_JSON)
    print(f"Write-Check: {REPORT_JSON}")
    with open(REPORT_JSON, "w", encoding="utf-8") as f:
        json.dump(atlas, f, indent=2)

    # Write Markdown
    _assert_write_path(REPORT_MD)
    print(f"Write-Check: {REPORT_MD}")
    with open(REPORT_MD, "w", encoding="utf-8") as f:
        f.write("# Test Failure Atlas (All Suites, No Coverage Gate)\n\n")
        f.write(f"- Generated: {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())}\n")
        f.write(f"- Python: `{sys.version.split()[0]}`\n")
        f.write(f"- Devnet reachable: **{atlas['env']['devnet_reachable']}**\n")
        f.write(f"- Collected test nodes: **{atlas['collect']['nodes']}** (rc={atlas['collect']['rc']})\n")
        f.write(f"- Test run rc: **{atlas['run']['rc']}** in {atlas['run']['duration_sec']:.1f}s\n\n")

        # Summary by category
        f.write("## Summary by Category\n\n")
        if counts_by_cat:
            f.write("| Category | Count |\n|---|---:|\n")
            for cat, n in counts_by_cat.most_common():
                f.write(f"| {cat} | {n} |\n")
        else:
            f.write("_No failures/errors detected by parser (or 0 tests ran)._ \n")
        f.write("\n")

        # Top files/modules
        f.write("## Hotspots by File\n\n")
        if files_counter:
            f.write("| File | Count |\n|---|---:|\n")
            for k, v in files_counter.most_common(30):
                f.write(f"| `{k}` | {v} |\n")
        else:
            f.write("_No file-level locations extracted._\n")
        f.write("\n")

        f.write("## Hotspots by Module Path\n\n")
        if modules_counter:
            f.write("| Module-ish Path | Count |\n|---|---:|\n")
            for k, v in modules_counter.most_common(30):
                f.write(f"| `{k}` | {v} |\n")
        else:
            f.write("_No module-level aggregation available._\n")
        f.write("\n")

        # Buckets & guidance
        f.write("## Fix Buckets & Guidance\n\n")
        f.write("- **Import/ModuleNotFound / ImportError** → Ensure `accumulate_client` exports match tests. Add missing `__init__.py` exports, create missing modules (e.g., `signers/ed25519.py`), and confirm dev dependencies installed.\n")
        f.write("- **AttributeError (SDK symbol missing)** → Implement/alias missing classes (e.g., `Secp256k1PrivateKey`, `SignerRegistry`, `FileKeystore`) and export them where tests expect.\n")
        f.write("- **TypeError (signature mismatch)** → Align function signatures with tests/Go parity; check builder/execute signatures and parameter names.\n")
        f.write("- **AssertionError** → Compare expected vs actual JSON/hash/fee; verify canonical JSON sorting, binary encoding, and fee rules vs Go. Use golden vectors.\n")
        f.write("- **Network/Request Error / Timeout** → Ensure correct v3 method names (`network-status`, `describe`, etc.) and configured endpoint. Your devnet is reachable — use it where tests intend.\n")
        f.write("- **ed25519/legacy gaps** → Confirm ED25519 and LEGACYED25519 sign/verify parity; expose verifiers in `accumulate_client.signers`.\n\n")

        # Detailed index
        f.write("## Detailed Index (Grouped)\n\n")
        grouped: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
        for i in issues:
            grouped[i["category"]].append(i)

        if not grouped:
            f.write("_No grouped issues; either all tests passed or none executed._\n")
        else:
            for cat in sorted(grouped.keys(), key=lambda k: (-len(grouped[k]), k)):
                f.write(f"### {cat} ({len(grouped[cat])})\n\n")
                for idx, it in enumerate(grouped[cat], 1):
                    file_loc = f"{it['file']}:{it['line']}" if it.get("file") else "(unknown)"
                    f.write(f"**{idx}.** `{it.get('test_node') or '(node unknown)'}` — `{file_loc}`\n\n")
                    if it.get("exception"):
                        f.write(f"- Exception: `{it['exception']}`\n")
                    if it.get("message"):
                        msg = it["message"].strip()
                        msg = (msg[:500] + "…") if len(msg) > 500 else msg
                        f.write(f"- Message: {msg}\n")
                    if it.get("hints"):
                        f.write(f"- Hints: {', '.join(it['hints'])}\n")
                    # Include a short snippet of raw
                    raw = it.get("raw", "")
                    snippet = "\n".join(raw.splitlines()[:30])
                    f.write("\n```text\n")
                    f.write(snippet)
                    f.write("\n```\n\n")

        # Footer
        f.write("---\n")
        f.write(f"**JSON sidecar:** `{REPORT_JSON}`\n")

    print("\n=== REPORT WRITTEN ===")
    print(f"Markdown: {REPORT_MD}")
    print(f"JSON    : {REPORT_JSON}")
    print("\nNext: open the Markdown, pick the largest bucket (by count), and we'll draft a targeted fix prompt.")
    return 0

if __name__ == "__main__":
    sys.exit(main())