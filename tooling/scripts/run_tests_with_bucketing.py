# Write-Check: C:\Accumulate_Stuff\opendlt-python-v2v3-sdk\unified\scripts\run_tests_with_bucketing.py
import os
import re
import sys
import json
import time
import pathlib
import socket
import subprocess
from typing import Dict, List, Any
from collections import defaultdict, Counter

ABS_ROOT = pathlib.Path(r"C:\Accumulate_Stuff\opendlt-python-v2v3-sdk\unified").resolve()
REPORTS = ABS_ROOT / "reports"
REPORT_MD = REPORTS / "failure_buckets.md"
REPORT_JSON = REPORTS / "failure_buckets.json"

def _assert_write_path(p: pathlib.Path):
    if not str(p.resolve()).startswith(str(ABS_ROOT)):
        print(f"ABORT: attempted write outside absolute root: {p}")
        sys.exit(2)

def _ensure_reports():
    _assert_write_path(REPORTS)
    REPORTS.mkdir(parents=True, exist_ok=True)

def _repo_root():
    return ABS_ROOT.parent

def _python_exe() -> str:
    return sys.executable

def _devnet_health(timeout=0.8) -> bool:
    try:
        with socket.create_connection(("127.0.0.1", 26660), timeout=timeout):
            return True
    except Exception:
        return False

def _run(cmd: List[str], cwd: pathlib.Path) -> (int, str, str, float):
    t0 = time.time()
    proc = subprocess.Popen(cmd, cwd=str(cwd), stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    out, err = proc.communicate()
    return proc.returncode, out, err, time.time() - t0

def _pytest_collect(repo: pathlib.Path):
    # Use verbose collect to capture collection errors
    cmd = [
        _python_exe(), "-m", "pytest",
        str(ABS_ROOT / "tests"),
        "--collect-only", "-vv"
    ]
    return _run(cmd, repo)

def _pytest_run(repo: pathlib.Path):
    # Full run; no coverage gating; keep all output
    cmd = [
        _python_exe(), "-m", "pytest",
        str(ABS_ROOT / "tests"),
        "-vv", "-rA", "--maxfail=0"
    ]
    return _run(cmd, repo)

# --- automatic bucketing (dynamic) ------------------------------------------

def _split_sections(stdout: str, stderr: str) -> Dict[str, str]:
    content = stdout + "\n" + stderr
    sections = {}
    # capture meaningful segments
    for key in ["ERRORS", "FAILURES", "short test summary info"]:
        m = re.search(rf"\n=+ {re.escape(key)} =+\n(.*?)(?=\n=+ |\Z)", content, re.DOTALL | re.IGNORECASE)
        if m:
            sections[key] = m.group(1)
    return sections

def _infer_bucket(block: str) -> str:
    b = block
    # collection-time buckets
    if "ModuleNotFoundError" in b or "No module named" in b:
        return "Collection: Import/ModuleNotFound"
    if "ImportError" in b and "during import" in b:
        return "Collection: ImportError during import"
    if "SyntaxError" in b:
        return "Collection: SyntaxError"

    # runtime buckets
    if re.search(r"\bAttributeError\b", b):
        if ".signers." in b or ".crypto." in b or ".tx." in b:
            return "Runtime: SDK symbol missing/renamed"
        return "Runtime: AttributeError"
    if re.search(r"\bTypeError\b", b) and "positional" in b:
        return "Runtime: Signature mismatch (args/kwargs)"
    if re.search(r"\bAssertionError\b", b) or re.search(r"^\s*E\s+assert ", b, re.MULTILINE):
        # Common sub-buckets
        if "hash" in b.lower() or "digest" in b.lower():
            return "Runtime: Assertion — hashing/codec parity"
        if "json" in b.lower():
            return "Runtime: Assertion — JSON/canonical encoding"
        if "fee" in b.lower() or "credits" in b.lower():
            return "Runtime: Assertion — fees/credits"
        return "Runtime: Assertion — general"
    if "requests.exceptions" in b or "ConnectionError" in b:
        return "Runtime: Network/Request error"
    if "timed out" in b or "Timeout" in b:
        return "Runtime: Timeout / async scheduling"
    if "KeyError:" in b:
        return "Runtime: KeyError (mapping/enum mismatch)"
    if "ValueError:" in b and "enum" in b.lower():
        return "Runtime: Enum mismatch/unknown"
    if "ed25519" in b.lower() or "legacyed25519" in b.lower():
        return "Runtime: Crypto — ED25519/LEGACY parity"
    return "Runtime: Other/Unclassified"

def _extract_fail_blocks(stdout: str, stderr: str) -> List[str]:
    content = stdout + "\n" + stderr
    # Split by lines of underscores (pytest separator); keep chunks with E ... lines
    chunks = re.split(r"\n_{5,}.*?\n", content)
    blocks = []
    for c in chunks:
        if re.search(r"^\s*E\s+", c, re.MULTILINE) or "short test summary info" in c:
            blocks.append(c.strip())
    return [b for b in blocks if b]

def _summarize(out: str, err: str) -> Dict[str, Any]:
    blocks = _extract_fail_blocks(out, err)
    if not blocks:
        # maybe only short summary
        m = re.search(r"=+ short test summary info =+\n(.*)", out + "\n" + err, re.DOTALL | re.IGNORECASE)
        if m:
            blocks = [m.group(1)]
    buckets = defaultdict(list)
    for b in blocks:
        buckets[_infer_bucket(b)].append(b)

    # attempt to pull node+file
    file_counts = Counter()
    node_counts = Counter()
    file_re = re.compile(r"^([^\n]+\.py):(\d+):", re.MULTILINE)
    node_re = re.compile(r"_{2,}\s+([^\s].*?)\s+_{2,}")
    for b in blocks:
        for m in file_re.finditer(b):
            file_counts[m.group(1)] += 1
        mnode = node_re.search(b)
        if mnode:
            node_counts[mnode.group(1)] += 1

    return {
        "buckets": {k: len(v) for k, v in buckets.items()},
        "blocks_by_bucket": {k: v for k, v in buckets.items()},
        "files": file_counts.most_common(),
        "nodes": node_counts.most_common(),
    }

def main():
    if not str(pathlib.Path(__file__).resolve()).startswith(str(ABS_ROOT)):
        print("ABORT: script must reside under unified\\")
        return 2

    _ensure_reports()
    repo = _repo_root()

    # 1) Collect
    print("[1/3] Pytest collection …")
    rc_c, out_c, err_c, dt_c = _pytest_collect(repo)
    print(f"  collect rc={rc_c} time={dt_c:.1f}s")

    # 2) Run
    print("[2/3] Full test run (no coverage gate) …")
    rc_r, out_r, err_r, dt_r = _pytest_run(repo)
    print(f"  run rc={rc_r} time={dt_r:.1f}s")

    # 3) Parse & bucket
    print("[3/3] Parsing and bucketing …")
    summary = _summarize(out_r, err_r)
    report = {
        "env": {
            "python": sys.version,
            "devnet_reachable": _devnet_health(),
            "repo_root": str(repo),
            "unified_root": str(ABS_ROOT),
        },
        "collect": {"rc": rc_c, "duration_sec": dt_c},
        "run": {"rc": rc_r, "duration_sec": dt_r},
        "summary": summary,
        "stdout_tail": (out_r or "")[-4000:],
        "stderr_tail": (err_r or "")[-2000:],
    }

    # Write JSON
    _assert_write_path(REPORT_JSON)
    print(f"Write-Check: {REPORT_JSON}")
    with open(REPORT_JSON, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)

    # Write Markdown
    _assert_write_path(REPORT_MD)
    print(f"Write-Check: {REPORT_MD}")
    with open(REPORT_MD, "w", encoding="utf-8") as f:
        f.write("# Failure Buckets (auto-inferred)\n\n")
        f.write(f"- Generated: {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())}\n")
        f.write(f"- Python: `{sys.version.split()[0]}`\n")
        f.write(f"- Devnet reachable: **{report['env']['devnet_reachable']}**\n")
        f.write(f"- Collect rc: **{rc_c}** in {dt_c:.1f}s\n")
        f.write(f"- Run rc: **{rc_r}** in {dt_r:.1f}s\n\n")

        f.write("## Buckets Summary\n\n")
        buckets = summary.get("buckets", {})
        if buckets:
            f.write("| Bucket | Count |\n|---|---:|\n")
            for k, v in sorted(buckets.items(), key=lambda kv: (-kv[1], kv[0])):
                f.write(f"| {k} | {v} |\n")
        else:
            f.write("_No failures parsed or 0 tests ran._\n")
        f.write("\n")

        files = summary.get("files", [])
        if files:
            f.write("## Hot Files\n\n| File | Count |\n|---|---:|\n")
            for fpath, n in files[:30]:
                f.write(f"| `{fpath}` | {n} |\n")
            f.write("\n")

        nodes = summary.get("nodes", [])
        if nodes:
            f.write("## Frequent Nodes\n\n| Test Node | Count |\n|---|---:|\n")
            for node, n in nodes[:30]:
                f.write(f"| `{node}` | {n} |\n")
            f.write("\n")

        # Detail per bucket
        detail = summary.get("blocks_by_bucket", {})
        for bk in sorted(detail.keys(), key=lambda k: (-len(detail[k]), k)):
            items = detail[bk]
            f.write(f"## {bk} ({len(items)})\n\n")
            # offer guidance dynamically based on bucket
            guidance = {
                "Collection: Import/ModuleNotFound": "→ Fix sys.path/test discovery or add missing __init__.py exports; confirm package installed editable.",
                "Collection: ImportError during import": "→ Check circular imports / invalid top-level imports; align package structure.",
                "Collection: SyntaxError": "→ Fix Python 3.13 incompat or stray escape sequences.",
                "Runtime: SDK symbol missing/renamed": "→ Implement or export missing symbol in accumulate_client; match tests' expected names.",
                "Runtime: Signature mismatch (args/kwargs)": "→ Align function signatures with tests and Go parity.",
                "Runtime: Assertion — hashing/codec parity": "→ Reconcile canonical JSON / binary hashing with Go; use golden vectors.",
                "Runtime: Assertion — JSON/canonical encoding": "→ Confirm key ordering, spacing, and canonicalization.",
                "Runtime: Assertion — fees/credits": "→ Re-check fee schedule + rounding rules.",
                "Runtime: Network/Request error": "→ Validate /v3 method names (e.g., network-status, describe) and endpoint.",
                "Runtime: Timeout / async scheduling": "→ Increase timeouts or await proper signals.",
                "Runtime: Crypto — ED25519/LEGACY parity": "→ Verify sign/verify; include legacy variant and verifiers.",
            }
            if bk in guidance:
                f.write(f"> **Hint:** {guidance[bk]}\n\n")
            for i, block in enumerate(items, 1):
                trimmed = "\n".join(block.splitlines()[:60])
                f.write(f"**Case {i}**\n\n```text\n{trimmed}\n```\n\n")

        f.write("---\n")
        f.write(f"**JSON sidecar:** `{REPORT_JSON}`\n")

    print("\n=== REPORT WRITTEN ===")
    print(f"Markdown: {REPORT_MD}")
    print(f"JSON    : {REPORT_JSON}")
    print("\nNext step: open the Markdown and paste the largest bucket here; I'll generate a surgical fix prompt for that group.")
    return 0

if __name__ == "__main__":
    sys.exit(main())