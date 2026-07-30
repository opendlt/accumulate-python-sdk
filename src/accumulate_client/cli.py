"""
Accumulate SDK command-line interface (RB-04).

A large population of agents works through a terminal rather than by compiling a
program. Without this, "what is this account's balance?" costs six turns: make a
project, add a dependency, write a file, compile, run, clean up. Here it is one.

Contract: docs/ai-agent-readiness/CLI-SPEC.md in accumulate-studio.
  * Under --json, stdout carries EXACTLY ONE envelope object. Logs go to stderr.
  * Exit codes: 0 ok · 1 operation failed · 2 usage error · 3 network unreachable.
  * Errors carry canonical ACC_* codes, so `retryable` tells an agent whether a
    retry is productive instead of leaving it to guess.
  * Never prompts. Mainnet needs --network mainnet AND ACCUMULATE_ALLOW_MAINNET=1.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from typing import Any, Dict, List, Optional, Tuple

ENVELOPE_VERSION = "1"
SDK_NAME = "python"

EXIT_OK = 0
EXIT_FAILED = 1
EXIT_USAGE = 2
EXIT_NETWORK = 3

DEFAULT_NETWORK = "kermit"


# ---------------------------------------------------------------------------
# Error catalog (RB-05)
#
# Mirrors packages/codegen/src/manifests/errors.catalog.json. Only the entries the
# CLI can actually surface are inlined, with the wire codes verified against a
# live node by tools/agent-harness/negative-cases.mjs.
# ---------------------------------------------------------------------------
CATALOG: Dict[str, Dict[str, Any]] = {
    "ACC_ACCOUNT_NOT_FOUND": {
        "category": "not_found",
        "retryable": False,
        "protocolCodes": [-32807, -33404],
        "patterns": ["accumulate error not found", "not found", "-32807", "-33404"],
        "hint": "The account URL does not exist on this network.",
        "remediation": (
            "Verify the URL and the network. If you just created the account, wait for its "
            "creating transaction to reach 'delivered' first. Note that on the V2 API a "
            "malformed URL is also reported as not-found."
        ),
    },
    "ACC_INVALID_PARAMS": {
        "category": "validation",
        "retryable": False,
        "protocolCodes": [-32802, -32602],
        "patterns": ["validation error", "field validation for", "invalid params", "-32802", "-32602"],
        "hint": "The request parameters were rejected by the node.",
        "remediation": "Check the operation's declared inputs. Hashes are 32-byte hex; amounts are base-unit integers.",
    },
    "ACC_METHOD_NOT_FOUND": {
        "category": "validation",
        "retryable": False,
        "protocolCodes": [-32601],
        "patterns": ["method not found", "-32601"],
        "hint": "The node does not expose the RPC method that was called.",
        "remediation": "Use the SDK's canonical client rather than raw RPC; it targets the right API version.",
    },
    "ACC_ROUTING_FAILED": {
        "category": "validation",
        "retryable": False,
        "protocolCodes": [-33400],
        "patterns": ["cannot route request", "nothing to route", "-33400"],
        "hint": "The node could not determine which partition should handle the request.",
        "remediation": (
            "Every transaction needs a header with a valid `principal` — that URL is the routing "
            "key. Build envelopes with TxBody + SmartSigner rather than by hand."
        ),
    },
    "ACC_INSUFFICIENT_CREDITS": {
        "category": "insufficient_credits",
        "retryable": False,
        "protocolCodes": [],
        "patterns": ["insufficientcredits", "insufficient credits"],
        "hint": "The signing key page does not hold enough credits to pay for this transaction.",
        "remediation": "Call add_credits for the SIGNING key page, then wait for the credits to settle.",
    },
    "ACC_UNAUTHORIZED_SIGNER": {
        "category": "auth",
        "retryable": False,
        "protocolCodes": [403],
        "patterns": ["unauthorized", "key does not belong to signer"],
        "hint": "The signing key is not on the key page that authorizes this principal.",
        "remediation": "Sign with a key on the principal's authorizing key page (after create_identity, `<adi>/book/1`).",
    },
    "ACC_INSUFFICIENT_BALANCE": {
        "category": "insufficient_balance",
        "retryable": False,
        "protocolCodes": [],
        "patterns": ["insufficient balance", "insufficient funds", "exceeds balance"],
        "hint": "The source account does not hold enough tokens for this transfer.",
        "remediation": "Confirm the balance first. 1 ACME = 1e8 base units; custom tokens carry their own precision.",
    },
    "ACC_NETWORK_UNAVAILABLE": {
        "category": "network",
        "retryable": True,
        "protocolCodes": [],
        "patterns": [
            "econnrefused", "econnreset", "etimedout", "timeout", "connection closed",
            "connection reset", "connection refused", "service unavailable",
            "max retries exceeded", "failed to establish", "name or service not known",
            "temporary failure in name resolution", "nodename nor servname",
        ],
        "hint": "The endpoint could not be reached, or the request timed out.",
        "remediation": "Retry with exponential backoff. This is the only class where a bare retry is productive.",
    },
    "ACC_INTERNAL": {
        "category": "internal",
        "retryable": True,
        "protocolCodes": [-32603],
        "patterns": ["internal error", "-32603"],
        "hint": "The node reported an internal error.",
        "remediation": "Retry once with backoff. If it persists, re-check the request shape.",
    },
    "ACC_USAGE": {
        "category": "validation",
        "retryable": False,
        "protocolCodes": [],
        "patterns": [],
        "hint": "The command was invoked incorrectly.",
        "remediation": "Run `accumulate --help --json` for the full command tree, flags and required arguments.",
    },
}

# Longest pattern wins, so "key does not belong to signer" beats a bare "unauthorized".
_PATTERN_INDEX: List[Tuple[str, str]] = sorted(
    ((p, code) for code, e in CATALOG.items() for p in e["patterns"]),
    key=lambda pair: len(pair[0]),
    reverse=True,
)


def classify(raw: str) -> str:
    """Map a raw error string onto a catalog code.

    Unrecognized errors deliberately fall back to a NON-retryable code: an
    unknown failure is far more often a malformed request than a transient fault,
    and defaulting to retryable is how an agent burns a turn budget in a loop.
    """
    text = (raw or "").lower()
    for pattern, code in _PATTERN_INDEX:
        if pattern in text:
            return code
    return "ACC_INVALID_PARAMS"


def error_payload(raw: str, code: Optional[str] = None) -> Dict[str, Any]:
    code = code or classify(raw)
    entry = CATALOG[code]
    payload = {
        "code": code,
        "category": entry["category"],
        "retryable": entry["retryable"],
        "hint": entry["hint"],
        "remediation": entry["remediation"],
        "raw": raw if raw is not None else "",
    }
    if entry["protocolCodes"]:
        payload["protocolCodes"] = entry["protocolCodes"]
    return payload



def load_private_key(ns) -> str:
    """Resolve the signing key from an EXPLICIT source only.

    Never falls back to an ambient default: a CLI that quietly finds a key is a
    CLI that signs something the caller did not intend. Keys are never accepted
    as positional arguments either, so they stay out of shell history.
    """
    key_file = getattr(ns, "key_file", None)
    key_env = getattr(ns, "key_env", None)
    if key_file and key_env:
        raise UsageError("pass only one of --key-file or --key-env")
    if key_file:
        try:
            with open(key_file, "r", encoding="utf-8") as fh:
                return fh.read().strip()
        except OSError as e:
            raise UsageError("could not read --key-file: " + str(e))
    if key_env:
        val = os.environ.get(key_env)
        if not val:
            raise UsageError("--key-env '" + str(key_env) + "' is not set or empty")
        return val.strip()
    raise UsageError(
        "signing requires an explicit key source: --key-file <path> or --key-env <VAR>. "
        "No ambient default key is ever used."
    )


# ---------------------------------------------------------------------------
# Envelope emission
# ---------------------------------------------------------------------------
class Emitter:
    """Owns stdout. Exactly one object is ever written to it."""

    def __init__(self, as_json: bool, network: Optional[str], started: float):
        self.as_json = as_json
        self.network = network
        self.started = started
        self._emitted = False

    def _meta(self) -> Dict[str, Any]:
        from . import __version__

        return {
            "network": self.network,
            "sdk": SDK_NAME,
            "version": __version__,
            "durationMs": round((time.monotonic() - self.started) * 1000, 3),
        }

    def ok(self, data: Any) -> int:
        assert not self._emitted, "envelope emitted twice"
        self._emitted = True
        if self.as_json:
            env = {"envelope": ENVELOPE_VERSION, "ok": True, "data": data, "meta": self._meta()}
            sys.stdout.write(json.dumps(env, default=str))
            sys.stdout.write("\n")
        else:
            sys.stdout.write(_human(data) + "\n")
        return EXIT_OK

    def fail(self, raw: str, code: Optional[str] = None, exit_code: Optional[int] = None) -> int:
        assert not self._emitted, "envelope emitted twice"
        self._emitted = True
        err = error_payload(raw, code)
        if exit_code is None:
            if err["code"] == "ACC_USAGE":
                exit_code = EXIT_USAGE
            elif err["code"] == "ACC_NETWORK_UNAVAILABLE":
                exit_code = EXIT_NETWORK
            else:
                exit_code = EXIT_FAILED
        if self.as_json:
            env = {"envelope": ENVELOPE_VERSION, "ok": False, "error": err, "meta": self._meta()}
            sys.stdout.write(json.dumps(env, default=str))
            sys.stdout.write("\n")
        else:
            # Human mode: the diagnosis goes to stderr, stdout stays clean.
            sys.stderr.write(f"error: {err['code']}: {err['hint']}\n")
            sys.stderr.write(f"  retryable: {'yes' if err['retryable'] else 'no'}\n")
            sys.stderr.write(f"  fix: {err['remediation']}\n")
        return exit_code


def _human(data: Any) -> str:
    if isinstance(data, (dict, list)):
        return json.dumps(data, indent=2, default=str)
    return str(data)


# ---------------------------------------------------------------------------
# Command tree — the single source for both argparse and `--help --json`
# ---------------------------------------------------------------------------
VERBS: List[Dict[str, Any]] = [
    {"name": "query", "summary": "Query any Accumulate account", "network": True, "signs": False,
     "args": [{"name": "url", "type": "string", "required": True}], "flags": []},
    {"name": "balance", "summary": "Get a token account balance", "network": True, "signs": False,
     "args": [{"name": "url", "type": "string", "required": True}], "flags": []},
    {"name": "chain", "summary": "Read chain entries for an account", "network": True, "signs": False,
     "args": [{"name": "url", "type": "string", "required": True}],
     "flags": [{"name": "--chain", "type": "string", "required": False, "default": "main"},
               {"name": "--start", "type": "integer", "required": False, "default": 0},
               {"name": "--count", "type": "integer", "required": False, "default": 10}]},
    {"name": "faucet", "summary": "Request testnet ACME for a lite token account", "network": True, "signs": False,
     "args": [{"name": "url", "type": "string", "required": True}], "flags": []},
    {"name": "credits estimate", "summary": "Estimate credits purchased for an ACME amount",
     "network": True, "signs": False, "args": [{"name": "url", "type": "string", "required": True}],
     "flags": [{"name": "--amount", "type": "number", "required": True}]},
    {"name": "tx build", "summary": "Build an unsigned transaction body", "network": False, "signs": False,
     "args": [{"name": "op", "type": "string", "required": True}],
     "flags": [{"name": "--param", "type": "key=value", "required": False, "repeatable": True},
               {"name": "--out", "type": "path", "required": False}]},
    {"name": "tx sign", "summary": "Sign a transaction body into a submittable envelope",
     "network": True, "signs": True, "args": [],
     "flags": [{"name": "--body", "type": "path", "required": True},
               {"name": "--principal", "type": "string", "required": True},
               {"name": "--signer", "type": "string", "required": True},
               {"name": "--key-file", "type": "path", "required": False},
               {"name": "--key-env", "type": "string", "required": False},
               {"name": "--out", "type": "path", "required": False}]},
    {"name": "tx submit", "summary": "Submit an ALREADY-SIGNED envelope (does not sign)",
     "network": True, "signs": False,
     "args": [], "flags": [{"name": "--envelope", "type": "path", "required": True}]},
    {"name": "tx wait", "summary": "Poll a transaction until it reaches a final state",
     "network": True, "signs": False, "args": [{"name": "txid", "type": "string", "required": True}],
     "flags": [{"name": "--timeout", "type": "integer", "required": False, "default": 60}]},
    {"name": "tx status", "summary": "Read a transaction's current status", "network": True, "signs": False,
     "args": [{"name": "txid", "type": "string", "required": True}], "flags": []},
    {"name": "keys generate", "summary": "Generate a keypair (never written to disk)",
     "network": False, "signs": False, "args": [],
     "flags": [{"name": "--algorithm", "type": "string", "required": False, "default": "ed25519"}]},
    {"name": "net list", "summary": "List known networks", "network": False, "signs": False, "args": [], "flags": []},
    {"name": "net status", "summary": "Check the selected network's reachability", "network": True,
     "signs": False, "args": [], "flags": []},
    {"name": "version", "summary": "Report SDK and envelope versions", "network": False, "signs": False,
     "args": [], "flags": []},
]

GLOBAL_FLAGS = [
    {"name": "--json", "type": "boolean", "summary": "Emit one envelope object on stdout"},
    {"name": "--network", "type": "string", "default": DEFAULT_NETWORK,
     "summary": "Target network; mainnet also requires ACCUMULATE_ALLOW_MAINNET=1"},
    {"name": "--help", "type": "boolean", "summary": "Show help; with --json returns the command tree"},
]


def command_tree() -> Dict[str, Any]:
    return {"command": "accumulate", "envelopeVersion": ENVELOPE_VERSION,
            "globalFlags": GLOBAL_FLAGS, "verbs": VERBS}


# ---------------------------------------------------------------------------
# Network resolution
# ---------------------------------------------------------------------------
def resolve_client(network: str):
    """Build a client, enforcing the two-key mainnet gate."""
    from . import Accumulate

    if network == "mainnet":
        if os.environ.get("ACCUMULATE_ALLOW_MAINNET") != "1":
            raise UsageError(
                "refusing to target mainnet: pass --network mainnet AND set "
                "ACCUMULATE_ALLOW_MAINNET=1. Both are required, deliberately."
            )
        return Accumulate.mainnet()
    if network in ("testnet", "kermit"):
        return Accumulate.testnet()
    if network == "local":
        return Accumulate.local()
    raise UsageError(f"unknown network '{network}' — known: kermit, testnet, mainnet, local")


class UsageError(Exception):
    """Invalid invocation. Maps to exit code 2."""


# ---------------------------------------------------------------------------
# Verb implementations
# ---------------------------------------------------------------------------
def run_verb(verb: str, ns: argparse.Namespace, em: Emitter) -> int:
    if verb == "version":
        from . import __version__
        return em.ok({"sdk": SDK_NAME, "version": __version__, "envelope": ENVELOPE_VERSION})

    if verb == "net list":
        from . import Accumulate
        return em.ok({"networks": [
            {"id": "kermit", "endpoint": Accumulate.TESTNET_ENDPOINT, "faucet": True, "default": True},
            {"id": "testnet", "endpoint": Accumulate.TESTNET_ENDPOINT, "faucet": True, "default": False},
            {"id": "mainnet", "endpoint": Accumulate.MAINNET_ENDPOINT, "faucet": False,
             "default": False, "requiresOptIn": True},
            {"id": "local", "endpoint": "http://localhost:26660", "faucet": True, "default": False},
        ]})

    if verb == "keys generate":
        algorithm = (getattr(ns, "algorithm", None) or "ed25519").lower()
        if algorithm != "ed25519":
            raise UsageError(f"unsupported algorithm '{algorithm}' — only ed25519 is supported")
        from .crypto.ed25519 import Ed25519KeyPair
        kp = Ed25519KeyPair.generate()
        return em.ok({
            "algorithm": "ed25519",
            "publicKey": kp.public_key_bytes().hex(),
            "liteIdentity": kp.derive_lite_identity_url(),
            "liteTokenAccount": kp.derive_lite_token_account_url("ACME"),
            # The private key is returned on stdout only because the caller asked
            # to generate one; it is never written to disk or logged.
            "privateKey": kp.private_key_bytes().hex() if hasattr(kp, "private_key_bytes") else None,
        })

    if verb == "tx build":
        params: Dict[str, Any] = {}
        for raw in (getattr(ns, "param", None) or []):
            if "=" not in raw:
                raise UsageError(f"--param must be key=value, got '{raw}'")
            k, v = raw.split("=", 1)
            params[k] = v  # coerced below, per the builder signature

        from . import TxBody

        builder = None if ns.op.startswith("_") else getattr(TxBody, ns.op, None)
        if builder is None or not callable(builder):
            ops = sorted(m for m in dir(TxBody) if not m.startswith("_"))
            raise UsageError(
                "unknown transaction op '" + str(ns.op) + "' -- available: " + ", ".join(ops)
            )
        # argv is all strings. Coerce ONLY where the builder annotates an int:
        # blanket-coercing every numeric-looking value turned send_tokens'
        # `amount` (declared str) into a number and the node rejected the
        # envelope with "cannot unmarshal number ... of type string".
        import inspect as _inspect
        try:
            _sig = _inspect.signature(builder)
            for _name, _p in _sig.parameters.items():
                if _name in params and _p.annotation in (int, "int"):
                    try:
                        params[_name] = int(params[_name])
                    except ValueError:
                        raise UsageError("--param " + _name + " must be an integer")
        except (TypeError, ValueError):
            pass
        try:
            body = builder(**params)
        except TypeError as e:
            import inspect as _inspect
            raise UsageError(
                "bad parameters for '" + str(ns.op) + str(_inspect.signature(builder)) + "': " + str(e)
            )

        out_path = getattr(ns, "out", None)
        if out_path:
            with open(out_path, "w", encoding="utf-8") as fh:
                json.dump(body, fh)
        return em.ok({"op": ns.op, "params": params, "body": body, "signed": False,
                      "out": out_path,
                      "note": "unsigned body; sign it with `tx sign --body <file>`, then `tx submit`"})

    # ---- network-touching verbs ----
    client = resolve_client(ns.network)
    try:
        if verb == "query":
            return em.ok({"url": ns.url, "account": client.query(ns.url)})

        if verb == "balance":
            res = client.query(ns.url)
            data = res.get("data") if isinstance(res, dict) else None
            balance = None
            if isinstance(data, dict):
                balance = data.get("balance")
            return em.ok({"url": ns.url, "balance": balance, "raw": res})

        if verb == "chain":
            # query_chain takes (url, chain_name, range_options) — not start/count
            # keywords. `main` is the chain every account has.
            from . import RangeOptions

            rng = RangeOptions(start=ns.start, count=ns.count)
            return em.ok({"url": ns.url, "chain": ns.chain, "start": ns.start, "count": ns.count,
                          "entries": client.query_chain(ns.url, ns.chain, range_options=rng)})

        if verb == "faucet":
            return em.ok({"url": ns.url, "result": client.faucet(ns.url)})

        if verb == "credits estimate":
            # The oracle is never scaled; credits are derived from it.
            info = client.query("acc://dn.acme/oracle")
            oracle = None
            if isinstance(info, dict):
                oracle = (info.get("data") or {}).get("price") if isinstance(info.get("data"), dict) else None
            return em.ok({"url": ns.url, "acme": ns.amount, "oraclePrice": oracle,
                          "note": "credits = acme * oraclePrice / 1e8 (oracle is unscaled)"})

        if verb == "tx status":
            return em.ok({"txid": ns.txid, "status": client.query_transaction(ns.txid)})

        if verb == "tx wait":
            deadline = time.monotonic() + max(1, int(ns.timeout))
            last: Any = None
            while time.monotonic() < deadline:
                last = client.query_transaction(ns.txid)
                status = None
                if isinstance(last, dict):
                    status = ((last.get("status") or {}).get("code")
                              if isinstance(last.get("status"), dict) else None)
                if status in ("delivered", "failed"):
                    return em.ok({"txid": ns.txid, "final": True, "status": status, "raw": last})
                time.sleep(1)
            return em.fail(f"timed out waiting for {ns.txid} to reach a final state",
                           code="ACC_NETWORK_UNAVAILABLE", exit_code=EXIT_FAILED)

        if verb == "net status":
            # `get_version_info()` only reports the CONFIGURED endpoints — it makes
            # no request, so reporting reachability from it would always claim
            # "reachable" even with nothing listening. Do a real round-trip.
            #
            # A protocol-level rejection still proves the node answered, so only a
            # transport failure counts as unreachable. That distinction is the
            # whole point of exit code 3.
            info = client.get_version_info()
            try:
                probe = client.query("acc://dn.acme")
                return em.ok({"network": ns.network, "endpoint": client.endpoint,
                              "reachable": True, "endpoints": info, "probe": probe})
            except Exception as e:  # noqa: BLE001
                raw = f"{type(e).__name__}: {e}"
                if classify(raw) == "ACC_NETWORK_UNAVAILABLE":
                    return em.fail(raw, code="ACC_NETWORK_UNAVAILABLE", exit_code=EXIT_NETWORK)
                # The node responded, just not with a result.
                return em.ok({"network": ns.network, "endpoint": client.endpoint,
                              "reachable": True, "endpoints": info, "probeError": raw})

        if verb == "tx sign":
            # The ONLY verb that signs. Requires an explicit key source and never
            # reads an ambient default.
            private_hex = load_private_key(ns)
            from .crypto.ed25519 import Ed25519KeyPair
            from . import SmartSigner

            with open(ns.body, "r", encoding="utf-8") as fh:
                body = json.load(fh)
            keypair = Ed25519KeyPair.from_private_hex(private_hex)
            # Delegate to the SDK signer. Signing bytes are consensus-visible, and
            # a second hand-rolled implementation is exactly how they drift.
            envelope = SmartSigner(client, keypair, ns.signer).sign_and_build(ns.principal, body)
            out_path = getattr(ns, "out", None)
            if out_path:
                with open(out_path, "w", encoding="utf-8") as fh:
                    json.dump(envelope, fh)
            return em.ok({"signed": True, "principal": ns.principal, "signer": ns.signer,
                          "envelope": envelope, "out": out_path})

        if verb == "tx submit":
            # Deliberately does NOT sign -- and no longer pretends to. It used to
            # take --key-file/--key-env and never use them. Sign with `tx sign`.
            with open(ns.envelope, "r", encoding="utf-8") as fh:
                envelope = json.load(fh)
            # Use the same submit path the SDK signer uses (client.submit, V3).
            # execute_direct is the V2 shape and rejects a sign_and_build envelope
            # with a bare -32802 Validation Error.
            return em.ok({"submitted": True, "result": client.submit(envelope)})

        raise UsageError(f"unknown verb '{verb}'")
    finally:
        try:
            client.close()
        except Exception:
            pass


# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------
def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="accumulate", add_help=False,
                                description="Accumulate SDK CLI (envelope v1)")
    p.add_argument("--json", action="store_true")
    p.add_argument("--network", default=DEFAULT_NETWORK)
    p.add_argument("--help", "-h", action="store_true", dest="help")
    p.add_argument("--version", action="store_true", dest="show_version")
    p.add_argument("rest", nargs=argparse.REMAINDER)
    return p


# Verbs whose name is two words, so argv parsing knows to consume a second token.
TWO_WORD = {"credits estimate", "tx build", "tx sign", "tx submit", "tx wait", "tx status",
            "keys generate", "net list", "net status"}
GROUPS = {"credits", "tx", "keys", "net"}


def parse_verb(tokens: List[str]) -> Tuple[str, List[str]]:
    if not tokens:
        raise UsageError("no verb given — run `accumulate --help --json` for the command tree")
    head = tokens[0]
    if head in GROUPS:
        if len(tokens) < 2:
            raise UsageError(f"'{head}' is a command group; it needs a subcommand "
                             f"(e.g. `{head} " + ("estimate" if head == "credits" else "list") + "`)")
        verb = f"{head} {tokens[1]}"
        if verb not in TWO_WORD:
            raise UsageError(f"unknown subcommand '{tokens[1]}' for group '{head}'")
        return verb, tokens[2:]
    known = {v["name"] for v in VERBS}
    if head not in known:
        raise UsageError(f"unknown verb '{head}' — run `accumulate --help --json` for the command tree")
    return head, tokens[1:]


def parse_verb_args(verb: str, tokens: List[str]) -> argparse.Namespace:
    spec = next(v for v in VERBS if v["name"] == verb)
    sub = argparse.ArgumentParser(prog=f"accumulate {verb}", add_help=False)
    for a in spec["args"]:
        sub.add_argument(a["name"])
    for f in spec["flags"]:
        dest = f["name"].lstrip("-").replace("-", "_")
        if f.get("repeatable"):
            sub.add_argument(f["name"], action="append", dest=dest)
        elif f["type"] == "integer":
            sub.add_argument(f["name"], type=int, dest=dest, default=f.get("default"))
        elif f["type"] == "number":
            sub.add_argument(f["name"], type=float, dest=dest, default=f.get("default"))
        else:
            sub.add_argument(f["name"], dest=dest, default=f.get("default"))
    try:
        ns, extra = sub.parse_known_args(tokens)
    except SystemExit:
        # argparse exits on error; convert to our usage contract instead.
        raise UsageError(f"invalid arguments for '{verb}'")
    if extra:
        raise UsageError(f"unexpected arguments for '{verb}': {' '.join(extra)}")
    for a in spec["args"]:
        if a.get("required") and getattr(ns, a["name"], None) in (None, ""):
            raise UsageError(f"'{verb}' requires <{a['name']}>")
    for f in spec["flags"]:
        dest = f["name"].lstrip("-").replace("-", "_")
        if f.get("required") and getattr(ns, dest, None) is None:
            raise UsageError(f"'{verb}' requires {f['name']}")
    return ns


def main(argv: Optional[List[str]] = None) -> int:
    started = time.monotonic()
    argv = list(sys.argv[1:] if argv is None else argv)
    as_json = "--json" in argv

    parser = build_parser()
    try:
        top, _ = parser.parse_known_args(argv)
    except SystemExit:
        return Emitter(as_json, None, started).fail("could not parse arguments", code="ACC_USAGE")

    em = Emitter(as_json, top.network, started)

    if top.help or (not top.rest and not top.show_version):
        if as_json:
            return em.ok(command_tree())
        sys.stdout.write("accumulate — Accumulate SDK CLI\n\n")
        for v in VERBS:
            sys.stdout.write(f"  {v['name']:<20} {v['summary']}\n")
        sys.stdout.write("\nRun with --json --help for the machine-readable command tree.\n")
        return EXIT_OK

    if top.show_version and not top.rest:
        from . import __version__
        return em.ok({"sdk": SDK_NAME, "version": __version__, "envelope": ENVELOPE_VERSION})

    tokens = [t for t in top.rest if t != "--json"]
    try:
        verb, rest = parse_verb(tokens)
        ns = parse_verb_args(verb, rest)
        ns.network = top.network
        return run_verb(verb, ns, em)
    except UsageError as e:
        return em.fail(str(e), code="ACC_USAGE")
    except FileNotFoundError as e:
        return em.fail(f"file not found: {e}", code="ACC_USAGE")
    except KeyboardInterrupt:
        return em.fail("interrupted", code="ACC_NETWORK_UNAVAILABLE", exit_code=EXIT_NETWORK)
    except Exception as e:  # noqa: BLE001 — every failure must still produce an envelope
        raw = f"{type(e).__name__}: {e}"
        code = classify(raw)
        exit_code = EXIT_NETWORK if code == "ACC_NETWORK_UNAVAILABLE" else EXIT_FAILED
        return em.fail(raw, code=code, exit_code=exit_code)


if __name__ == "__main__":
    sys.exit(main())
