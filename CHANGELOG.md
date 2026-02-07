# Changelog

All notable changes to the opendlt-accumulate Python SDK will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
