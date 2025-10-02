"""
Transaction validation for Accumulate Protocol.

Provides comprehensive validation for transaction bodies and envelopes
with exact parity to the Go implementation.

Reference: C:/Accumulate_Stuff/accumulate/protocol/validate.go
"""

from __future__ import annotations
from typing import Any, List
import re

from ..runtime.url import AccountUrl
from ..runtime.errors import AccumulateError


class ValidationError(ValueError):
    """Transaction validation specific errors."""

    def __init__(self, message: str, issues: List[str] = None):
        """
        Initialize validation error.

        Args:
            message: Primary error message
            issues: List of specific validation issues
        """
        super().__init__(message)
        self.issues = issues or []

    def __str__(self) -> str:
        """Return detailed error message including issues."""
        base_message = super().__str__()
        if self.issues:
            return f"{base_message}: {'; '.join(self.issues)}"
        return base_message


def validate_tx_body(body: Any) -> None:
    """
    Validate a transaction body.

    Args:
        body: Transaction body to validate

    Raises:
        ValidationError: If validation fails
    """
    if body is None:
        raise ValidationError("Transaction body cannot be None")

    issues = []

    # Get body class name for type-specific validation
    body_type = body.__class__.__name__

    # Validate required fields based on Pydantic model
    if hasattr(body.__class__, 'model_fields'):
        # Pydantic v2
        for field_name, field_info in body.__class__.model_fields.items():
            if field_info.is_required():
                value = getattr(body, field_name, None)
                if value is None:
                    issues.append(f"Required field '{field_name}' is missing")

    # Type-specific validation
    if body_type.endswith('Body'):
        tx_type = body_type[:-4]  # Remove 'Body' suffix
        _validate_by_transaction_type(body, tx_type, issues)

    # URL validation
    _validate_urls_in_body(body, issues)

    # Amount validation
    _validate_amounts_in_body(body, issues)

    if issues:
        raise ValidationError("Transaction body validation failed", issues)


def validate_envelope(envelope: Any) -> None:
    """
    Validate a transaction envelope.

    Args:
        envelope: Transaction envelope to validate

    Raises:
        ValidationError: If validation fails
    """
    if envelope is None:
        raise ValidationError("Transaction envelope cannot be None")

    issues = []

    # Validate header
    if hasattr(envelope, 'header'):
        _validate_header(envelope.header, issues)

    # Validate body
    if hasattr(envelope, 'body'):
        try:
            validate_tx_body(envelope.body)
        except ValidationError as e:
            issues.extend(e.issues)

    # Validate signatures
    if hasattr(envelope, 'signatures'):
        _validate_signatures(envelope.signatures, issues)

    if issues:
        raise ValidationError("Transaction envelope validation failed", issues)


def _validate_by_transaction_type(body: Any, tx_type: str, issues: List[str]) -> None:
    """Validate based on specific transaction type."""

    # Token transaction validations
    if tx_type in ('SendTokens', 'IssueTokens'):
        if hasattr(body, 'amount'):
            amount = getattr(body, 'amount', 0)
            if amount <= 0:
                issues.append(f"{tx_type} amount must be positive")

    elif tx_type == 'BurnTokens':
        if hasattr(body, 'amount'):
            amount = getattr(body, 'amount', 0)
            if amount <= 0:
                issues.append("BurnTokens amount must be positive")

    # Credit transaction validations
    elif tx_type in ('AddCredits', 'TransferCredits'):
        if hasattr(body, 'amount'):
            amount = getattr(body, 'amount', 0)
            if amount <= 0:
                issues.append(f"{tx_type} amount must be positive")

    # Key operations validations
    elif tx_type == 'UpdateKeyPage':
        if hasattr(body, 'operation'):
            operation = getattr(body, 'operation', None)
            if operation is None:
                issues.append("UpdateKeyPage operation is required")

    elif tx_type == 'CreateKeyPage':
        if hasattr(body, 'keys'):
            keys = getattr(body, 'keys', [])
            if not keys:
                issues.append("CreateKeyPage must specify at least one key")

    # Data validations
    elif tx_type in ('WriteData', 'WriteDataTo'):
        if hasattr(body, 'data'):
            data = getattr(body, 'data', None)
            if not data:
                issues.append(f"{tx_type} data cannot be empty")

    # Add transaction type specific validation
    if hasattr(body, 'type'):
        tx_type = getattr(body, 'type', '').lower()
        if tx_type == 'sendtokens':
            # Validate SendTokens specific fields
            amount = getattr(body, 'amount', None)
            if amount is None or amount <= 0:
                issues.append("SendTokens amount must be positive")

            to_url = getattr(body, 'to', None)
            if not to_url:
                issues.append("SendTokens 'to' field is required")

        elif tx_type == 'writedata':
            # Validate WriteData specific fields
            data = getattr(body, 'data', None)
            if not data:
                issues.append("WriteData data cannot be empty")

        elif tx_type == 'createdataaccount':
            # Validate CreateDataAccount specific fields
            url = getattr(body, 'url', None)
            if not url:
                issues.append("CreateDataAccount url is required")


def _validate_header(header: Any, issues: List[str]) -> None:
    """Validate transaction header."""
    if header is None:
        issues.append("Transaction header is required")
        return

    # Validate header fields based on Go protocol.TransactionHeader structure
    if not hasattr(header, 'principal') and 'principal' not in header:
        issues.append("Transaction header must have 'principal' field")

    if not hasattr(header, 'initiator') and 'initiator' not in header:
        issues.append("Transaction header must have 'initiator' field")

    # Validate principal URL format
    principal = getattr(header, 'principal', None) or header.get('principal') if isinstance(header, dict) else None
    if principal and isinstance(principal, str) and not principal.startswith('acc://'):
        issues.append("Transaction principal must be a valid Accumulate URL")

    # Validate authorities if present
    authorities = getattr(header, 'authorities', None) or header.get('authorities') if isinstance(header, dict) else None
    if authorities:
        if not isinstance(authorities, list):
            issues.append("Transaction authorities must be a list")
        else:
            for i, auth in enumerate(authorities):
                if isinstance(auth, str) and not auth.startswith('acc://'):
                    issues.append(f"Authority {i} must be a valid Accumulate URL")


def _validate_signatures(signatures: List[Any], issues: List[str]) -> None:
    """Validate transaction signatures."""
    if not signatures:
        issues.append("At least one signature is required")
        return

    for i, sig in enumerate(signatures):
        if not sig:
            issues.append(f"Signature {i} is empty")
            continue

        # Validate signature structure based on Go protocol.Signature interface
        if isinstance(sig, dict):
            # Validate dictionary signature structure
            if 'type' not in sig:
                issues.append(f"Signature {i} must have 'type' field")
            elif sig['type'].lower() not in ['ed25519', 'legacyed25519', 'btc', 'eth', 'rcd1', 'delegated']:
                issues.append(f"Signature {i} has invalid type: {sig['type']}")

            if 'signature' not in sig:
                issues.append(f"Signature {i} must have 'signature' field")

            if sig.get('type', '').lower() != 'delegated' and 'publicKey' not in sig:
                issues.append(f"Signature {i} must have 'publicKey' field")

            if 'signer' in sig:
                signer = sig['signer']
                if isinstance(signer, dict) and 'url' in signer:
                    signer_url = signer['url']
                elif isinstance(signer, str):
                    signer_url = signer
                else:
                    signer_url = None

                if signer_url and not signer_url.startswith('acc://'):
                    issues.append(f"Signature {i} signer must be a valid Accumulate URL")

        elif hasattr(sig, 'type'):
            # Validate object signature structure
            if not hasattr(sig, 'signature'):
                issues.append(f"Signature {i} must have signature field")

            if sig.type != 'delegated' and not hasattr(sig, 'public_key'):
                issues.append(f"Signature {i} must have public_key field")


def _validate_urls_in_body(body: Any, issues: List[str]) -> None:
    """Validate AccountUrl fields in transaction body."""
    for field_name in dir(body):
        if field_name.startswith('_'):
            continue
        # Skip Pydantic model metadata to avoid deprecation warnings
        if field_name in ('model_fields', 'model_computed_fields', 'model_config'):
            continue

        value = getattr(body, field_name, None)
        if isinstance(value, AccountUrl):
            if not _is_valid_account_url(value):
                issues.append(f"Invalid AccountUrl in field '{field_name}': {value}")
        elif isinstance(value, str) and ('url' in field_name.lower() or field_name in ('origin', 'to', 'recipient')):
            if not _is_valid_account_url_string(value):
                issues.append(f"Invalid URL format in field '{field_name}': {value}")


def _validate_amounts_in_body(body: Any, issues: List[str]) -> None:
    """Validate amount fields in transaction body."""
    for field_name in dir(body):
        if field_name.startswith('_'):
            continue
        # Skip Pydantic model metadata to avoid deprecation warnings
        if field_name in ('model_fields', 'model_computed_fields', 'model_config'):
            continue

        if 'amount' in field_name.lower() or field_name in ('balance', 'limit', 'fee'):
            value = getattr(body, field_name, None)
            if isinstance(value, (int, float)) and value < 0:
                issues.append(f"Negative amount not allowed in field '{field_name}': {value}")


def _is_valid_account_url(url: AccountUrl) -> bool:
    """Check if AccountUrl is valid."""
    try:
        url_str = str(url)
        return _is_valid_account_url_string(url_str)
    except Exception:
        return False


def _is_valid_account_url_string(url_str: str) -> bool:
    """Check if URL string has valid format."""
    if not url_str or not isinstance(url_str, str):
        return False
    if not url_str.startswith('acc://'):
        return False
    if url_str == 'acc://':
        return False

    # Basic pattern validation
    pattern = r'^acc://[a-zA-Z0-9][a-zA-Z0-9\-\._]*[a-zA-Z0-9](?:/[a-zA-Z0-9][a-zA-Z0-9\-\._]*[a-zA-Z0-9])*/?$'
    return bool(re.match(pattern, url_str))


def validate_builder_fields(builder: Any) -> None:
    """
    Validate builder fields when transaction schema is incomplete.

    This function provides validation for builders when transaction body
    classes have no field definitions. It implements transaction-specific
    validation rules based on the builder type and field values.

    Args:
        builder: Transaction builder instance to validate

    Raises:
        ValidationError: If validation fails with detailed issues
    """
    issues = []
    tx_type = builder.tx_type
    fields = builder._fields

    # SendTokens validation
    if tx_type == 'SendTokens':
        # Required fields
        if 'to' not in fields:
            issues.append("Required field 'to' is missing")
        else:
            to_field = fields['to']
            if isinstance(to_field, list):
                # Validate each recipient in the list
                for i, recipient in enumerate(to_field):
                    if isinstance(recipient, dict):
                        if 'url' in recipient and isinstance(recipient['url'], str):
                            if not _is_valid_account_url_string(recipient['url']):
                                issues.append(f"Invalid URL format in to[{i}].url: {recipient['url']}")
                    else:
                        issues.append(f"SendTokens to[{i}] must be a dictionary")
            elif isinstance(to_field, str):
                # Single recipient as string (legacy format)
                if not _is_valid_account_url_string(to_field):
                    issues.append(f"Invalid URL format in field 'to': {to_field}")

        # SendTokens amount validation - check top-level amount if present
        if 'amount' in fields:
            amount = fields['amount']
            if not isinstance(amount, (int, float)):
                issues.append(f"Field 'amount' must be a number, got {type(amount).__name__}")
            elif amount <= 0:
                issues.append(f"Field 'amount' must be positive, got {amount}")

    # CreateIdentity validation
    elif tx_type == 'CreateIdentity':
        if 'url' not in fields:
            issues.append("Required field 'url' is missing")
        else:
            if not _is_valid_account_url_string(fields['url']):
                issues.append(f"Invalid URL format in field 'url': {fields['url']}")

    # WriteData validation
    elif tx_type == 'WriteData':
        if 'data' not in fields:
            issues.append("Required field 'data' is missing")
        else:
            data = fields['data']
            if isinstance(data, bytes) and len(data) == 0:
                issues.append("Field 'data' cannot be empty")

    # AddCredits validation
    elif tx_type == 'AddCredits':
        # AddCredits should have required fields
        required_fields = ['recipient', 'amount']
        for field in required_fields:
            if field not in fields:
                issues.append(f"Required field '{field}' is missing")

    # CreateTokenAccount validation
    elif tx_type == 'CreateTokenAccount':
        if 'url' not in fields:
            issues.append("Required field 'url' is missing")
        else:
            if not _is_valid_account_url_string(fields['url']):
                issues.append(f"Invalid URL format in field 'url': {fields['url']}")

    # CreateDataAccount validation
    elif tx_type == 'CreateDataAccount':
        if 'url' not in fields:
            issues.append("Required field 'url' is missing")
        else:
            if not _is_valid_account_url_string(fields['url']):
                issues.append(f"Invalid URL format in field 'url': {fields['url']}")

    # BurnTokens validation
    elif tx_type == 'BurnTokens':
        if 'amount' not in fields:
            issues.append("Required field 'amount' is missing")
        else:
            amount = fields['amount']
            if not isinstance(amount, (int, float)):
                issues.append(f"Field 'amount' must be a number, got {type(amount).__name__}")
            elif amount <= 0:
                issues.append(f"Field 'amount' must be positive, got {amount}")

    # IssueTokens validation
    elif tx_type == 'IssueTokens':
        if 'recipient' not in fields:
            issues.append("Required field 'recipient' is missing")
        else:
            if not _is_valid_account_url_string(fields['recipient']):
                issues.append(f"Invalid URL format in field 'recipient': {fields['recipient']}")

    # UpdateKey validation
    elif tx_type == 'UpdateKey':
        if 'newKey' not in fields:
            issues.append("Required field 'newKey' is missing")

    # UpdateKeyPage validation
    elif tx_type == 'UpdateKeyPage':
        if 'operation' in fields:
            operation = fields['operation']
            if operation == 'update':
                if 'key' in fields and 'newKey' not in fields:
                    issues.append("Field 'newKey' is required when operation is 'update'")

    # CreateKeyPage validation
    elif tx_type == 'CreateKeyPage':
        if 'keys' not in fields:
            issues.append("Required field 'keys' is missing")
        else:
            keys = fields['keys']
            if isinstance(keys, list) and len(keys) == 0:
                issues.append("Field 'keys' cannot be empty - at least one key is required")

    # General amount validation for any transaction with amount field
    for field_name, field_value in fields.items():
        if 'amount' in field_name.lower() and isinstance(field_value, (int, float)):
            if field_value < 0:
                issues.append(f"Negative amount not allowed in field '{field_name}': {field_value}")

    # General URL validation for any field containing 'url' or common URL field names
    for field_name, field_value in fields.items():
        if ('url' in field_name.lower() or field_name in ('to', 'origin', 'recipient')) and isinstance(field_value, str):
            if not _is_valid_account_url_string(field_value):
                issues.append(f"Invalid URL format in field '{field_name}': {field_value}")

    if issues:
        raise ValidationError("Builder validation failed", issues)


def validate_field(field: str, value: Any) -> None:
    """
    Validate individual transaction field.

    Args:
        field: Field name to validate
        value: Field value to validate

    Raises:
        ValidationError: If validation fails
    """
    if field == "url":
        if not isinstance(value, str):
            raise ValidationError(f"URL field must be string, got {type(value).__name__}")
        if not value.startswith("acc://"):
            raise ValidationError(f"URL must start with 'acc://', got: {value}")
        if len(value) <= 6:  # "acc://" is 6 chars
            raise ValidationError(f"URL must have domain after 'acc://', got: {value}")
        if len(value) >= 256:
            raise ValidationError(f"URL too long (max 255 chars), got {len(value)} chars")

    elif field == "amount":
        if not isinstance(value, (int, float)):
            raise ValidationError(f"Amount must be numeric, got {type(value).__name__}")
        if isinstance(value, float) and value != int(value):
            raise ValidationError(f"Amount must be integer, got fractional: {value}")
        if value <= 0:
            raise ValidationError(f"Amount must be positive, got: {value}")
        if value >= 2**64:
            raise ValidationError(f"Amount too large (max 2^64-1), got: {value}")

    elif field == "key":
        if value is None:
            raise ValidationError("Key cannot be None")
        if not isinstance(value, bytes):
            raise ValidationError(f"Key must be bytes, got {type(value).__name__}")
        if len(value) != 32:
            raise ValidationError(f"Key must be 32 bytes, got {len(value)} bytes")

    elif field == "threshold":
        if not isinstance(value, int):
            raise ValidationError(f"Threshold must be integer, got {type(value).__name__}")
        if value <= 0:
            raise ValidationError(f"Threshold must be positive, got: {value}")
        if value >= 256:
            raise ValidationError(f"Threshold too high (max 255), got: {value}")

    elif field == "memo":
        if value is not None:
            if not isinstance(value, str):
                raise ValidationError(f"Memo must be string or None, got {type(value).__name__}")
            if len(value) >= 256:
                raise ValidationError(f"Memo too long (max 255 chars), got {len(value)} chars")


def validate_transaction(tx: Dict[str, Any]) -> None:
    """
    Validate complete transaction dictionary.

    Args:
        tx: Transaction dictionary to validate

    Raises:
        ValidationError: If validation fails
    """
    if not isinstance(tx, dict):
        raise ValidationError(f"Transaction must be dictionary, got {type(tx).__name__}")

    if "type" not in tx:
        raise ValidationError("Transaction must have 'type' field")

    tx_type = tx["type"]

    # Validate based on transaction type
    if tx_type == "SendTokens":
        if "from" not in tx:
            raise ValidationError("SendTokens transaction must have 'from' field")
        validate_field("url", tx["from"])

        if "to" not in tx:
            raise ValidationError("SendTokens transaction must have 'to' field")

        to_list = tx["to"]
        if not isinstance(to_list, list):
            raise ValidationError("SendTokens 'to' field must be list")
        if not to_list:
            raise ValidationError("SendTokens 'to' field cannot be empty")

        for output in to_list:
            if not isinstance(output, dict):
                raise ValidationError("SendTokens output must be dictionary")
            if "url" not in output:
                raise ValidationError("SendTokens output must have 'url' field")
            if "amount" not in output:
                raise ValidationError("SendTokens output must have 'amount' field")
            validate_field("url", output["url"])
            validate_field("amount", output["amount"])

    elif tx_type == "CreateIdentity":
        if "url" in tx:
            validate_field("url", tx["url"])

    elif tx_type == "WriteData":
        if "data" not in tx:
            raise ValidationError("WriteData transaction must have 'data' field")
        data = tx["data"]
        if not isinstance(data, bytes):
            raise ValidationError(f"WriteData 'data' field must be bytes, got {type(data).__name__}")
        if len(data) == 0:
            raise ValidationError("WriteData 'data' field cannot be empty")

    # General field validation
    for field_name, field_value in tx.items():
        if field_name in ("url", "from", "to", "recipient") and isinstance(field_value, str):
            validate_field("url", field_value)
        elif field_name == "amount" and isinstance(field_value, (int, float)):
            validate_field("amount", field_value)


def validate_signature(sig: Dict[str, Any]) -> None:
    """
    Validate signature dictionary.

    Args:
        sig: Signature dictionary to validate

    Raises:
        ValidationError: If validation fails
    """
    if not isinstance(sig, dict):
        raise ValidationError(f"Signature must be dictionary, got {type(sig).__name__}")

    if "type" not in sig:
        raise ValidationError("Signature must have 'type' field")

    sig_type = sig["type"]

    if sig_type == "ed25519":
        if "publicKey" not in sig:
            raise ValidationError("Ed25519 signature must have 'publicKey' field")
        if "signature" not in sig:
            raise ValidationError("Ed25519 signature must have 'signature' field")

        public_key = sig["publicKey"]
        signature = sig["signature"]

        if isinstance(public_key, bytes) and len(public_key) != 32:
            raise ValidationError(f"Ed25519 public key must be 32 bytes, got {len(public_key)}")
        if isinstance(signature, bytes) and len(signature) != 64:
            raise ValidationError(f"Ed25519 signature must be 64 bytes, got {len(signature)}")

        if "signer" in sig:
            validate_field("url", sig["signer"])


__all__ = [
    "ValidationError",
    "validate_tx_body",
    "validate_envelope",
    "validate_field",
    "validate_transaction",
    "validate_signature"
]