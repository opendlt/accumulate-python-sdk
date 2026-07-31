# Changelog

## [2.3.4] - 2026-07-31

### Added
- **M-of-N co-signing.** `SmartSigner.sign_existing` appends a signature to an EXISTING
  envelope, and the CLI exposes it as `accumulate tx sign --envelope <file>`.
  This is what a signature threshold actually needs: signing the same body twice
  derives a new `initiator` and produces a *different* transaction, so neither
  copy ever reaches the threshold. Verified on Kermit: a 2-of-2 transaction
  built, signed, co-signed and delivered entirely through the CLI.

### Fixed
- `tx submit` now inspects the **per-message status** in the response. A 200 with
  no JSON-RPC error does not mean the transaction was accepted — a rejected
  envelope reports `failed: true` inside the result, and reporting that as success
  is the "submitted != delivered" trap that makes an agent believe a write landed.

## [2.3.3] - 2026-07-30

### Added
- **`tx sign`** — the CLI can now sign. It is the ONLY verb that signs, requires an
  explicit `--key-file`/`--key-env`, and delegates to the SDK's own signer so the
  produced bytes match the library path exactly (they are consensus-visible).
- `tx build` now emits a **real transaction body** via `TxBody` and rejects unknown
  ops. It previously echoed `{op, params}` back, so a typo exited 0 and only
  surfaced at submit — or never.
- `--out` on `tx build`/`tx sign`, so build -> sign -> submit composes through files.
- Op and parameter names accept either `snake_case` or `camelCase`.

### Fixed
- **`tx submit` no longer claims to sign.** It accepted `--key-file`/`--key-env`
  and never used them, advertising a capability that did not exist. Those flags are
  gone and it now declares `signs: false`; the envelope must already be signed.

## [2.3.2] - 2026-07-30

### Added
- **Structured CLI** (`accumulate`): 13 verbs, `--json` emits exactly one envelope
  object on stdout, canonical `ACC_*` error codes with a `retryable` flag, and exit
  codes 0/1/2/3 an agent can branch on without parsing. `accumulate --help --json`
  returns the whole command tree. Defaults to testnet; mainnet requires both
  `--network mainnet` and `ACCUMULATE_ALLOW_MAINNET=1`.
  Conforms to `CLI-SPEC.md`; verified by a shared conformance suite across all five SDKs.
- `llms.txt` and `AGENTS.md` now document the CLI.

## [2.3.1] - 2026-07-29

### Added
- Canonical Accumulate error catalog in `llms-full.txt`: every error code with its
  category, whether a retry is productive (`retryable`), likely causes, the concrete
  fix, and the Python type to catch. Each operation now lists the errors it can raise.
- `.devcontainer/devcontainer.json` pinning this repo's toolchain, defaulting to the
  Kermit testnet and carrying no credentials.

### Fixed
- `AGENTS.md` setup, test and layout paths now match this repository's actual root.
  They previously instructed agents to `cd` into a subdirectory that does not exist
  in a fresh clone, so the very first setup command failed.

## [2.3.0] - 2026-07-28

### Added
- `Amount.token(whole, precision)` / `to_token(precision)` for **custom tokens**. Custom tokens declare their own precision at creation; the wire format is always base units. Previously `Amount` covered only ACME and credits, so issuing a custom token meant hand-computing a power of ten — and issuing `1000` against a precision-8 token mints `0.00001` tokens, not 1000, while the transaction succeeds either way.

### Changed
- Fleet version alignment: all five Accumulate SDKs now ship 2.3.0 with the same `Amount` surface.

All notable changes to the opendlt-accumulate Python SDK will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.1.0] - 2026-02-27

### Added
- Binary encoding for lockAccount, burnCredits, transferCredits, updateAccountAuth, updateKey, and writeDataTo transaction types
- `_encode_account_auth_operation` encoder for UpdateAccountAuth operations
- WriteDataTo support in body hash computation

### Fixed
- Envelope format now wraps transaction in an array to match v3 API spec
- `add_credits` and `burn_tokens` TxBody methods accept flexible amount types

## [2.0.4] - 2026-02-10

### Added
- New `example_14_low_level_adi_creation.py` — complete ADI creation flow using only
  raw binary encoding (no SmartSigner or TxBody), with inline annotations showing where
  convenience methods could replace 20+ lines with 2-4 lines
- Convenience method reference tables in all documentation files
- SDK API levels documentation (QuickStart / SmartSigner+TxBody / Raw Binary Encoding)
  explaining what each convenience method does under the hood

### Fixed
- Resolved all 31 xfailed tests — incorrect factory data types in `mk_minimal_valid_body()`
  for SendTokens, AddCredits, UpdateKeyPage, TransferCredits, UpdateAccountAuth,
  NetworkMaintenance, and CreateLiteDataAccount
- Fixed `_restore_field_types()` in transaction builder base to handle `Optional[bytes]`,
  aliased Pydantic fields, and nested `List[Union[BaseModel,...]]` with type discriminators
- Fixed `build_envelope()` missing `signatures` key in output
- Fixed `validation.py` using wrong field name `newKey` instead of `newKeyHash` for UpdateKey
- Deleted orphaned tests for removed legacy client modules (api_client, json_rpc_client,
  client_compat, generated_client, client_mock, client_test)
- Deleted orphaned integration tests using removed `Accumulate.describe()`/`.call()` methods
- Deleted orphaned example smoke tests for removed example scripts
- Removed xfail stubs for 6 unimplemented signature types (placeholder, not useful)

### Changed
- Removed legacy client modules: `api_client.py`, `client.py`, `json_rpc_client.py`,
  `generated_client.py`, `client_compat.py`, `client_mock.py`, `client_test.py` —
  all functionality is covered by `facade.py` + `v2/` + `v3/`
- All documentation files updated with correct git clone URL, package name disambiguation,
  and SmartSigner/TxBody/QuickStart explanations
- Examples 01 and 02 annotated with inline comments explaining what convenience methods
  do under the hood and referencing example_14 for the raw approach
- Test suite: 2354 passed, 14 skipped (legitimate env/dep skips), 0 xfailed, 0 failed

## [2.0.3] - 2026-02-09

### Fixed
- Fixed psutil import crash for pip users (lazy import for optional dependency)
- Fixed all README.md files (correct pip package name, imports, method names)
- Fixed version mismatch between _version.py and __init__.py

### Changed
- Consolidated tool/, tools/, scripts/ into tooling/
- Moved internal/debug examples out of examples/ into tooling/internal-examples/
- Removed stale unified/unified/ directory and site/ duplicate
- Removed .coverage and .env.local from repo tracking

## [2.0.2] - 2026-02-07

### Fixed
- Fixed and verified all v3 examples against Kermit public testnet
- Removed duplicate custom tokens example
- Updated all examples to use Kermit testnet endpoints

## [2.0.0] - 2025-12-31

### Added

#### Multi-Signature Support
- RCD1 (Factom-style) signature support with proper public key hash computation
- BTC (Bitcoin secp256k1) signature support with compressed public keys
- BTCLegacy signature support for legacy Bitcoin compatibility
- ETH (Ethereum secp256k1) signature support with Keccak-256 hashing
- RSA-SHA256 signature support (2048-4096 bit keys)
- ECDSA-SHA256 (P-256/secp256r1) signature support
- TypedData (EIP-712) signature support for Ethereum typed data

#### Cryptographic Key Pairs
- `Secp256k1KeyPair` for BTC/ETH operations with compressed/uncompressed support
- `RsaKeyPair` with PKCS#1 DER encoding/decoding
- `EcdsaKeyPair` for P-256 curve operations
- `RCD1KeyPair` for Factom-compatible signing
- Unified key pair interface for polymorphic key handling

#### Smart Signing API
- `SmartSigner` class for automatic signer version tracking
- `sign_submit_and_wait()` method for complete transaction lifecycle
- `add_key()` helper for key page operations
- Automatic retry logic for transient network errors

#### Transaction Builders (TxBody)
- `create_token()` for custom token issuer creation
- `create_key_page()` for key page creation
- `create_key_book()` for key book creation
- `issue_tokens()` / `issue_tokens_single()` for token issuance
- `send_tokens_single()` convenience method for single-recipient transfers
- `add_credits()` for credit purchase operations

#### Protocol Types
- Complete signature type hierarchy matching Go core
- Vote, Memo, and Data fields on all signature types
- TransactionHeader with Metadata, Expire, HoldUntil, and Authorities fields
- Proper enum values for all 16 signature types
- 103 protocol types with full validation
- 14 protocol enumerations with proper serialization

#### Enterprise Features
- WebSocket streaming with automatic reconnection
- High-performance request batching and connection pooling
- Circuit breaker pattern for fault tolerance
- Transaction replay for guaranteed delivery
- Prometheus and JSON metrics exporters

### Changed
- Signature type enum values now match Go protocol exactly
- Binary encoding for signatures uses correct field ordering
- Transaction hash computation matches Go core implementation
- Public key hash computation varies by signature type (as per protocol)
- WriteData uses `doubleHash` entry type (matching Go protocol)

### Fixed
- ETH signature public key hash uses Keccak-256 (not SHA-256)
- RSA signatures include full public key in hash (not truncated)
- RCD1 signatures use double-SHA256 for public key hash
- Transaction ID extraction from multi-response arrays
- Status parsing handles both string and map formats

### Security
- Secure keystore with AES-256 encryption and PBKDF2 key derivation
- No hardcoded keys or secrets in library code
- Test vectors use well-known public test data only
- Removed all debug files that printed sensitive data

## [0.1.0] - 2025-09-01

### Added
- Initial release of Python SDK
- Ed25519 cryptography with bit-for-bit compatible signing
- LID/LTA derivation matching Go/TypeScript implementations
- Transaction builders for common Accumulate v3 operations
- Unified v2+v3 JSON-RPC client
- Comprehensive test suite with cross-language validation
- Golden file test harness for encoding compatibility
- Working examples for all common workflows
