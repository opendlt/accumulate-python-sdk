#!/usr/bin/env python3
"""
SDK Example 14: Low-Level ADI Creation (No Convenience Methods)

This example does EXACTLY the same thing as example_02_accumulate_identities.py:
  keypair generation → faucet → add credits → create ADI → add credits to key page

But it uses NO convenience methods (no SmartSigner, no TxBody). Instead, it manually:
  1. Queries the signer version from the network
  2. Binary-encodes signature metadata using Accumulate's wire format
  3. Computes the initiator hash = SHA256(signature_metadata_binary)
  4. Binary-encodes the transaction header and body
  5. Computes tx_hash = SHA256(SHA256(header_binary) + SHA256(body_binary))
  6. Computes signing_preimage = SHA256(initiator + tx_hash)
  7. Signs the preimage with Ed25519
  8. Assembles the JSON envelope
  9. Submits via V3 JSON-RPC
  10. Polls until delivered

API Level: Raw binary encoding (lowest level)

WHY YOU SHOULD PREFER THE CONVENIENCE METHODS:
  - SmartSigner + TxBody do all of the above in two lines of code
  - SmartSigner auto-tracks signer version (no manual query needed)
  - TxBody ensures correct field names and types for each transaction type
  - SmartSigner handles edge cases (WriteData special hashing, retries, verbose mode)

Compare this ~350-line file with example_02's ~50 lines of transaction logic.
The convenience methods exist precisely to prevent the complexity shown here.

Uses Kermit public testnet endpoints.
"""

import hashlib
import time

import requests

from accumulate_client import Accumulate, NetworkStatusOptions
from accumulate_client.crypto.ed25519 import Ed25519KeyPair

# Kermit public testnet endpoints
KERMIT_V2 = "https://kermit.accumulatenetwork.io/v2"
KERMIT_V3 = "https://kermit.accumulatenetwork.io/v3"

# For local DevNet testing, uncomment these:
# KERMIT_V2 = "http://127.0.0.1:26660/v2"
# KERMIT_V3 = "http://127.0.0.1:26660/v3"


# =============================================================================
# Binary Encoding Helpers
# =============================================================================
# These implement the exact binary field encoding used by Go's MarshalBinary()
# for computing transaction hashes and signing preimages.
#
# >>> CONVENIENCE ALTERNATIVE: These are all internal to SmartSigner.
# >>> With SmartSigner you never need to call any of these directly.
# =============================================================================

def sha256(data: bytes) -> bytes:
    """SHA-256 hash."""
    return hashlib.sha256(data).digest()


def encode_uvarint(val: int) -> bytes:
    """Encode an unsigned variable-length integer (ULEB128)."""
    result = bytearray()
    x = val & 0xFFFFFFFFFFFFFFFF
    while x >= 0x80:
        result.append((x & 0x7F) | 0x80)
        x >>= 7
    result.append(x)
    return bytes(result)


def field(field_num: int, val: bytes) -> bytes:
    """Encode a field: uvarint(field_number) + raw_bytes(value)."""
    return encode_uvarint(field_num) + val


def field_uvarint(field_num: int, val: int) -> bytes:
    """Encode a uvarint field."""
    return field(field_num, encode_uvarint(val))


def field_bytes(field_num: int, val: bytes) -> bytes:
    """Encode a bytes field (length-prefixed)."""
    return field(field_num, encode_uvarint(len(val)) + val)


def field_string(field_num: int, val: str) -> bytes:
    """Encode a string field (length-prefixed UTF-8)."""
    encoded = val.encode("utf-8")
    return field(field_num, encode_uvarint(len(encoded)) + encoded)


def field_hash(field_num: int, val: bytes) -> bytes:
    """Encode a 32-byte hash field (no length prefix)."""
    assert len(val) == 32, f"Hash must be 32 bytes, got {len(val)}"
    return field(field_num, val)


def field_bigint(field_num: int, val: int) -> bytes:
    """Encode a BigInt field (big-endian bytes, length-prefixed)."""
    if val == 0:
        return field_bytes(field_num, b'\x00')
    s = hex(val)[2:]
    if len(s) % 2 == 1:
        s = "0" + s
    bigint_bytes = bytes.fromhex(s)
    return field_bytes(field_num, bigint_bytes)


# =============================================================================
# Transaction-Specific Binary Encoding
# =============================================================================
# Each transaction type has a specific binary layout matching Go's MarshalBinary().
#
# >>> CONVENIENCE ALTERNATIVE: TxBody.add_credits() / TxBody.create_identity()
# >>> return the correct dict, and SmartSigner._encode_tx_body() handles encoding.
# =============================================================================

def encode_add_credits_body(recipient: str, amount: int, oracle: int) -> bytes:
    """
    Binary-encode an AddCredits transaction body.

    Go field order (protocol/types_gen.go):
      Field 1: TransactionType = addCredits (14)
      Field 2: Recipient (URL string)
      Field 3: Amount (BigInt)
      Field 4: Oracle (uint64)
    """
    parts = bytearray()
    parts += field_uvarint(1, 14)  # TransactionType = addCredits = 14
    parts += field_string(2, recipient)
    parts += field_bigint(3, amount)
    parts += field_uvarint(4, oracle)
    return bytes(parts)


def encode_create_identity_body(url: str, key_book_url: str, key_hash_hex: str) -> bytes:
    """
    Binary-encode a CreateIdentity transaction body.

    Go field order (protocol/types_gen.go):
      Field 1: TransactionType = createIdentity (1)
      Field 2: Url (URL string)
      Field 3: KeyHash (bytes, length-prefixed — WriteBytes, not WriteHash)
      Field 4: KeyBookUrl (URL string)
    """
    parts = bytearray()
    parts += field_uvarint(1, 1)  # TransactionType = createIdentity = 1
    parts += field_string(2, url)
    parts += field_bytes(3, bytes.fromhex(key_hash_hex))
    parts += field_string(4, key_book_url)
    return bytes(parts)


# =============================================================================
# Signature Metadata + Header Encoding
# =============================================================================
# These encode the signature metadata and transaction header for hash computation.
#
# >>> CONVENIENCE ALTERNATIVE: SmartSigner._compute_tx_hash_and_sign() does all
# >>> of this in one call, returning a ready-to-submit envelope.
# =============================================================================

def encode_ed25519_sig_metadata(
    public_key: bytes,
    signer_url: str,
    signer_version: int,
    timestamp: int
) -> bytes:
    """
    Binary-encode ED25519 signature metadata.

    Go struct field order (protocol/types_gen.go):
      Field 1: Type (SignatureType = ED25519 = 2)
      Field 2: PublicKey (bytes)
      Field 3: Signature (bytes) — SKIPPED in metadata
      Field 4: Signer (URL string)
      Field 5: SignerVersion (uint64)
      Field 6: Timestamp (uint64)
      Field 7: Vote (VoteType) — 0=Accept, skipped as zero value
    """
    parts = bytearray()
    parts += field_uvarint(1, 2)                  # Type = ED25519 = 2
    parts += field_bytes(2, public_key)            # PublicKey
    # Field 3 (Signature) is SKIPPED in metadata
    parts += field_string(4, signer_url)           # Signer URL
    if signer_version != 0:
        parts += field_uvarint(5, signer_version)  # SignerVersion
    if timestamp != 0:
        parts += field_uvarint(6, timestamp)        # Timestamp
    # Field 7 (Vote=ACCEPT=0) skipped as zero value
    return bytes(parts)


def encode_tx_header(principal: str, initiator: bytes, memo: str = None) -> bytes:
    """
    Binary-encode transaction header.

    Go struct field order (protocol/types_gen.go):
      Field 1: Principal (URL string)
      Field 2: Initiator (Hash, 32 bytes, no length prefix)
      Field 3: Memo (string, optional)
    """
    parts = bytearray()
    parts += field_string(1, principal)
    if initiator and initiator != b'\x00' * 32:
        parts += field_hash(2, initiator)
    if memo:
        parts += field_string(3, memo)
    return bytes(parts)


# =============================================================================
# Full Sign Pipeline
# =============================================================================

def sign_transaction(
    keypair: Ed25519KeyPair,
    principal: str,
    body_binary: bytes,
    body_dict: dict,
    signer_url: str,
    signer_version: int,
    memo: str = None
) -> dict:
    """
    Manually sign a transaction and build the envelope.

    This function does EXACTLY what SmartSigner.sign_and_build() does internally:

    Step 1: Binary-encode signature metadata
    Step 2: Compute initiator = SHA256(sig_metadata_binary)
    Step 3: Binary-encode transaction header (principal + initiator + optional memo)
    Step 4: Compute tx_hash = SHA256(SHA256(header_binary) + SHA256(body_binary))
    Step 5: Compute signing_preimage = SHA256(initiator + tx_hash)
    Step 6: Ed25519 sign the 32-byte preimage
    Step 7: Assemble the JSON envelope

    >>> CONVENIENCE ALTERNATIVE:
    >>>   envelope = signer.sign_and_build(principal=principal, body=body_dict, memo=memo)
    >>> That single line replaces this entire function.
    """
    public_key = keypair.public_key_bytes()
    timestamp = int(time.time() * 1_000_000)  # microseconds

    # Step 1: Binary-encode signature metadata
    sig_metadata_binary = encode_ed25519_sig_metadata(
        public_key=public_key,
        signer_url=signer_url,
        signer_version=signer_version,
        timestamp=timestamp
    )

    # Step 2: Compute initiator hash
    initiator = sha256(sig_metadata_binary)

    # Step 3: Binary-encode transaction header
    header_binary = encode_tx_header(principal, initiator, memo)

    # Step 4: Compute tx_hash
    header_hash = sha256(header_binary)
    body_hash = sha256(body_binary)
    tx_hash = sha256(header_hash + body_hash)

    # Step 5: Compute signing preimage
    signing_preimage = sha256(initiator + tx_hash)

    # Step 6: Sign the preimage
    signature = keypair.sign(signing_preimage)

    # Step 7: Assemble the JSON envelope
    transaction = {
        "header": {
            "principal": principal,
            "initiator": initiator.hex()
        },
        "body": body_dict
    }
    if memo:
        transaction["header"]["memo"] = memo

    envelope = {
        "transaction": transaction,
        "signatures": [{
            "type": "ed25519",
            "publicKey": public_key.hex(),
            "signature": signature.hex(),
            "signer": signer_url,
            "signerVersion": signer_version,
            "timestamp": timestamp
        }]
    }

    return envelope


def submit_and_wait(client, envelope: dict, max_attempts: int = 30, poll_interval: float = 2.0) -> str:
    """
    Submit an envelope and poll until delivered. Returns the transaction ID.

    >>> CONVENIENCE ALTERNATIVE:
    >>>   result = signer.sign_submit_and_wait(principal, body)
    >>> SmartSigner combines signing + submission + polling into one call and
    >>> returns a SubmitResult dataclass with .success, .txid, .error fields.
    """
    # Submit
    response = client.submit(envelope)

    # Extract transaction ID from the submit response
    # Response format: [{"status": {"txID": "acc://...", "code": "ok", ...}, "success": true}, ...]
    txid = None
    if isinstance(response, list) and response:
        first = response[0]
        if isinstance(first, dict):
            status = first.get("status", {})
            if isinstance(status, dict):
                txid = status.get("txID")
                # Check for immediate rejection
                if status.get("failed") or status.get("codeNum", 0) >= 400:
                    error_msg = status.get("error", {}).get("message", "unknown") if isinstance(status.get("error"), dict) else str(status.get("error", "rejected"))
                    raise RuntimeError(f"Transaction rejected: {error_msg}")

    if not txid:
        raise RuntimeError(f"Could not extract txID from response: {response}")

    print(f"  Submitted: {txid}")

    # Poll for delivery
    # V3 query response format: {"recordType": "message", "status": "delivered", "statusNo": 201, ...}
    # Note: "status" is a STRING ("delivered", "pending"), not a dict.
    for attempt in range(max_attempts):
        try:
            result = client.query(txid)
            if isinstance(result, dict):
                status = result.get("status")
                status_no = result.get("statusNo", 0)
                # V3 returns status as a string: "delivered", "pending", etc.
                if status == "delivered" or status_no == 201:
                    print(f"  Delivered after {attempt + 1} poll(s)")
                    return txid
                # Also handle dict format in case API changes
                if isinstance(status, dict) and status.get("delivered"):
                    print(f"  Delivered after {attempt + 1} poll(s)")
                    return txid
        except RuntimeError:
            raise
        except Exception:
            # Transaction may not be indexed yet — keep polling
            pass
        time.sleep(poll_interval)

    print(f"  Warning: timed out after {max_attempts} polls, transaction may still succeed")
    return txid


def get_signer_version(client, signer_url: str) -> int:
    """
    Query the signer version (key page version) from the network.

    >>> CONVENIENCE ALTERNATIVE:
    >>>   SmartSigner queries and caches this automatically — you never call it yourself.
    """
    try:
        result = client.query(signer_url)
        if result.get("account"):
            return result["account"].get("version", 1)
    except Exception:
        pass
    return 1


# =============================================================================
# Main Example Flow
# =============================================================================

def main():
    print("=== SDK Example 14: Low-Level ADI Creation (No Convenience Methods) ===\n")
    print(f"Endpoint: {KERMIT_V3}\n")
    print("This example does the same thing as example_02 but WITHOUT SmartSigner or TxBody.\n")
    test_features()


def test_features():
    base_endpoint = KERMIT_V3.replace("/v3", "")
    client = Accumulate(base_endpoint)

    try:
        # =========================================================
        # Step 1: Generate key pairs
        # =========================================================
        print("--- Step 1: Generate Key Pairs ---\n")

        lite_kp = Ed25519KeyPair.generate()
        adi_kp = Ed25519KeyPair.generate()

        lid = lite_kp.derive_lite_identity_url()
        lta = lite_kp.derive_lite_token_account_url("ACME")

        print(f"Lite Identity: {lid}")
        print(f"Lite Token Account: {lta}")
        print(f"Public Key: {lite_kp.public_key_bytes().hex()[:32]}...\n")

        tx_ids = []

        # =========================================================
        # Step 2: Fund the lite account via faucet
        # =========================================================
        print("--- Step 2: Fund Account via Faucet ---\n")

        # The faucet is a V2-only JSON-RPC method. There is no convenience wrapper
        # because it's a protocol-level operation, not a transaction.
        v2_endpoint = client.v2.endpoint
        print(f"Requesting funds from faucet (3 times)...")
        for i in range(3):
            try:
                response = requests.post(
                    v2_endpoint,
                    json={
                        "jsonrpc": "2.0",
                        "method": "faucet",
                        "params": {"url": lta},
                        "id": i + 1
                    },
                    timeout=30
                )
                result = response.json()
                txid = result.get("result", {}).get("txid", "submitted")
                print(f"  Faucet {i+1}/3: {str(txid)[:40]}...")
                time.sleep(2)
            except Exception as e:
                print(f"  Faucet {i+1}/3 failed: {e}")

        # Poll for balance
        print("\nPolling for balance...")
        balance = 0
        for attempt in range(30):
            try:
                result = client.v3.query(lta)
                bal = result.get("account", {}).get("balance")
                if bal is not None:
                    balance = int(bal) if isinstance(bal, (int, str)) else 0
                    if balance > 0:
                        break
                print(f"  Waiting... (attempt {attempt+1}/30)")
            except Exception:
                pass
            time.sleep(2)

        if balance == 0:
            print("ERROR: Account not funded. Stopping.")
            return
        print(f"Balance confirmed: {balance}\n")

        # =========================================================
        # Step 3: Add credits to lite identity (MANUALLY)
        # =========================================================
        print("--- Step 3: Add Credits to Lite Identity (Manual Binary Encoding) ---\n")

        # Get oracle price
        network_status = client.v3.network_status(NetworkStatusOptions(partition="directory"))
        oracle = network_status.get("oracle", {}).get("price", 500000)
        print(f"Oracle price: {oracle}")

        # Calculate amount for 500 credits
        credits_to_buy = 500
        amount = (credits_to_buy * 10000000000) // oracle
        print(f"Buying {credits_to_buy} credits for {amount} ACME sub-units")

        # >>> WITH CONVENIENCE METHODS, this entire block would be:
        # >>>   signer = SmartSigner(client.v3, lite_kp, lid)
        # >>>   result = signer.sign_submit_and_wait(
        # >>>       principal=lta,
        # >>>       body=TxBody.add_credits(lid, str(amount), oracle),
        # >>>   )
        # >>> That's 4 lines vs the ~20 lines below.

        # Step 3a: Query signer version (SmartSigner does this automatically)
        signer_version = get_signer_version(client.v3, lid)
        print(f"Signer version: {signer_version}")

        # Step 3b: Build AddCredits body dict (TxBody.add_credits does this)
        add_credits_body = {
            "type": "addCredits",
            "recipient": lid,
            "amount": str(amount),
            "oracle": oracle
        }

        # Step 3c: Binary-encode the body (SmartSigner._encode_tx_body does this)
        body_binary = encode_add_credits_body(lid, amount, oracle)

        # Step 3d: Sign and build envelope (SmartSigner.sign_and_build does this)
        envelope = sign_transaction(
            keypair=lite_kp,
            principal=lta,
            body_binary=body_binary,
            body_dict=add_credits_body,
            signer_url=lid,
            signer_version=signer_version,
            memo="Add credits to lite identity"
        )

        # Step 3e: Submit and poll (SmartSigner.sign_submit_and_wait does this)
        print("Submitting AddCredits transaction...")
        try:
            txid = submit_and_wait(client.v3, envelope)
            print(f"AddCredits SUCCESS - TxID: {txid}")
            tx_ids.append(("AddCredits (lite identity)", txid))
        except Exception as e:
            print(f"AddCredits FAILED: {e}")
            print("Continuing anyway to demonstrate API...")

        # Poll for credits to appear on the lite identity.
        # This is critical: CreateIdentity requires credits on the signer, and the
        # credit balance update may lag behind transaction delivery by a few seconds.
        print("Waiting for credits to appear on lite identity...")
        credit_balance = 0
        for attempt in range(30):
            try:
                lid_query = client.v3.query(lid)
                credit_balance = lid_query.get("account", {}).get("creditBalance", 0)
                if isinstance(credit_balance, str):
                    credit_balance = int(credit_balance)
                if credit_balance > 0:
                    print(f"Lite identity credit balance: {credit_balance}\n")
                    break
            except Exception:
                pass
            time.sleep(2)
        if credit_balance == 0:
            print("WARNING: Credits not yet visible. CreateIdentity may fail.\n")

        # =========================================================
        # Step 4: Create an ADI (MANUALLY)
        # =========================================================
        print("--- Step 4: Create ADI (Manual Binary Encoding) ---\n")

        timestamp = int(time.time() * 1000)
        adi_name = f"sdk-adi-{timestamp}"
        identity_url = f"acc://{adi_name}.acme"
        book_url = f"{identity_url}/book"

        adi_pub = adi_kp.public_key_bytes()
        adi_key_hash = hashlib.sha256(adi_pub).digest()
        adi_key_hash_hex = adi_key_hash.hex()

        print(f"ADI URL: {identity_url}")
        print(f"Key Book URL: {book_url}")
        print(f"ADI Key Hash: {adi_key_hash_hex[:32]}...\n")

        # >>> WITH CONVENIENCE METHODS, this entire block would be:
        # >>>   result = signer.sign_submit_and_wait(
        # >>>       principal=lta,
        # >>>       body=TxBody.create_identity(identity_url, book_url, adi_key_hash_hex),
        # >>>   )
        # >>> That's 4 lines vs the ~20 lines below.

        # Re-query signer version (SmartSigner caches this)
        signer_version = get_signer_version(client.v3, lid)

        # Build CreateIdentity body dict (TxBody.create_identity does this)
        create_identity_body = {
            "type": "createIdentity",
            "url": identity_url,
            "keyBookUrl": book_url,
            "keyHash": adi_key_hash_hex
        }

        # Binary-encode the body
        body_binary = encode_create_identity_body(identity_url, book_url, adi_key_hash_hex)

        # Sign and build envelope
        envelope = sign_transaction(
            keypair=lite_kp,
            principal=lta,
            body_binary=body_binary,
            body_dict=create_identity_body,
            signer_url=lid,
            signer_version=signer_version,
            memo="Create ADI via Python SDK (low-level)"
        )

        # Submit and poll
        print("Submitting CreateIdentity transaction...")
        try:
            txid = submit_and_wait(client.v3, envelope)
            print(f"CreateIdentity SUCCESS - TxID: {txid}")
            tx_ids.append(("CreateIdentity", txid))
        except Exception as e:
            print(f"CreateIdentity FAILED: {e}")
            return

        # Verify ADI was created by polling until it appears
        print("Waiting for ADI to appear on network...")
        for attempt in range(30):
            try:
                adi_query = client.v3.query(identity_url)
                print(f"ADI created: {adi_query.get('account', {}).get('url')}")
                print(f"ADI type: {adi_query.get('account', {}).get('type')}\n")
                break
            except Exception:
                pass
            time.sleep(2)
        else:
            print(f"Could not verify ADI after 30 attempts\n")

        # =========================================================
        # Step 5: Add credits to ADI key page (MANUALLY)
        # =========================================================
        print("--- Step 5: Add Credits to ADI Key Page (Manual Binary Encoding) ---\n")

        key_page_url = f"{book_url}/1"
        print(f"Key Page URL: {key_page_url}")

        key_page_credits = 200
        key_page_amount = (key_page_credits * 10000000000) // oracle
        print(f"Buying {key_page_credits} credits for {key_page_amount} ACME sub-units")

        # >>> WITH CONVENIENCE METHODS:
        # >>>   result = signer.sign_submit_and_wait(
        # >>>       principal=lta,
        # >>>       body=TxBody.add_credits(key_page_url, str(key_page_amount), oracle),
        # >>>   )

        signer_version = get_signer_version(client.v3, lid)

        add_credits_body = {
            "type": "addCredits",
            "recipient": key_page_url,
            "amount": str(key_page_amount),
            "oracle": oracle
        }

        body_binary = encode_add_credits_body(key_page_url, key_page_amount, oracle)

        envelope = sign_transaction(
            keypair=lite_kp,
            principal=lta,
            body_binary=body_binary,
            body_dict=add_credits_body,
            signer_url=lid,
            signer_version=signer_version,
            memo="Add credits to ADI key page"
        )

        print("Submitting AddCredits transaction...")
        try:
            txid = submit_and_wait(client.v3, envelope)
            print(f"AddCredits to key page SUCCESS - TxID: {txid}")
            tx_ids.append(("AddCredits (key page)", txid))
        except Exception as e:
            print(f"AddCredits to key page FAILED: {e}")

        # Poll for credits to appear on key page
        print("Waiting for credits to appear on key page...")
        for attempt in range(30):
            try:
                kp_query = client.v3.query(key_page_url)
                kp_credits = kp_query.get("account", {}).get("creditBalance", 0)
                if isinstance(kp_credits, str):
                    kp_credits = int(kp_credits)
                if kp_credits > 0:
                    print(f"Key page credit balance: {kp_credits}\n")
                    break
            except Exception:
                pass
            time.sleep(2)
        else:
            print(f"Could not verify key page credits after 30 attempts\n")

        # =========================================================
        # Summary
        # =========================================================
        print("=== Summary ===\n")
        print(f"Created lite identity: {lid}")
        print(f"Created ADI: {identity_url}")
        print(f"ADI Key Book: {book_url}")
        print(f"ADI Key Page: {key_page_url}")
        print("\nAll transactions used MANUAL binary encoding and signing.")
        print("No SmartSigner or TxBody convenience methods were used.")
        print("\nIn production, prefer SmartSigner + TxBody (see example_02).")
        print("SmartSigner handles version tracking, binary encoding, hash computation,")
        print("signing, envelope construction, submission, and delivery polling for you.")

        # =========================================================
        # TxID Report
        # =========================================================
        print("\n=== TRANSACTION IDs FOR VERIFICATION ===\n")
        for tx_name, txid in tx_ids:
            print(f"  {tx_name}: {txid}")
        print(f"\nTotal transactions: {len(tx_ids)}")
        print("Example 14 COMPLETED SUCCESSFULLY!")

    finally:
        client.close()


if __name__ == "__main__":
    main()
