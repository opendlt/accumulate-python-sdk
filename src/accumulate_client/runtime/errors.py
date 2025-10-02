"""
Accumulate Error Model

This module provides the error handling framework for the Accumulate Python SDK,
matching the error codes and behaviors from the Go implementation.
"""

from __future__ import annotations
from typing import Optional, Dict, Any, List
from enum import IntEnum


class ErrorCode(IntEnum):
    """Accumulate error codes matching the Go implementation."""

    # Success
    OK = 0

    # General errors (1-99)
    UNKNOWN = 1
    INTERNAL = 2
    INVALID_URL = 3
    NOT_FOUND = 4
    UNAUTHORIZED = 5
    CONFLICT = 6

    # Encoding errors (100-199)
    ENCODING_ERROR = 100
    INVALID_JSON = 101
    INVALID_BINARY = 102
    MARSHAL_ERROR = 103
    UNMARSHAL_ERROR = 104

    # Network errors (200-299)
    NETWORK_ERROR = 200
    CONNECTION_FAILED = 201
    TIMEOUT = 202
    RATE_LIMITED = 203
    SERVICE_UNAVAILABLE = 204

    # Authentication errors (300-399)
    UNAUTHENTICATED = 300
    FORBIDDEN = 301
    INVALID_SIGNATURE = 302
    INSUFFICIENT_CREDITS = 303
    INVALID_PRINCIPAL = 304

    # Transaction errors (400-499)
    INVALID_TRANSACTION = 400
    TRANSACTION_FAILED = 401
    INSUFFICIENT_BALANCE = 402
    ACCOUNT_DOES_NOT_EXIST = 403
    WRONG_PARTITION = 404
    DELIVER_TX_FAILED = 405

    # Validation errors (500-599)
    MISSING_SIGNATURE = 500
    INVALID_SIGNATURE_SET = 501
    INVALID_AUTHORITY = 502
    INSUFFICIENT_AUTHORITIES = 503
    DUPLICATE_TRANSACTION = 504

    # Chain errors (600-699)
    INVALID_CHAIN = 600
    CHAIN_NOT_FOUND = 601
    INVALID_ENTRY = 602
    DUPLICATE_ENTRY = 603

    # Key/Account errors (700-799)
    INVALID_KEY = 700
    KEY_NOT_FOUND = 701
    INVALID_KEY_PAGE = 702
    INVALID_KEY_BOOK = 703
    PAGE_FULL = 704


class AccumulateError(Exception):
    """
    Base class for all Accumulate errors.

    Provides structured error information matching the Go error model.
    """

    def __init__(self, message: str, code: ErrorCode = ErrorCode.UNKNOWN,
                 details: Optional[Dict[str, Any]] = None, cause: Optional[Exception] = None):
        """
        Initialize an Accumulate error.

        Args:
            message: Error message
            code: Error code
            details: Additional error details
            cause: Underlying exception that caused this error
        """
        super().__init__(message)
        self.message = message
        self.code = code
        self.details = details or {}
        self.cause = cause

    def __str__(self) -> str:
        """String representation of the error."""
        parts = [f"[{self.code.name}] {self.message}"]
        if self.details:
            parts.append(f"Details: {self.details}")
        if self.cause:
            parts.append(f"Caused by: {self.cause}")
        return " | ".join(parts)

    def to_dict(self) -> Dict[str, Any]:
        """Convert error to dictionary representation."""
        result = {
            "code": self.code.value,
            "message": self.message,
        }
        if self.details:
            result["details"] = self.details
        if self.cause:
            result["cause"] = str(self.cause)
        return result

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'AccumulateError':
        """Create error from dictionary representation."""
        code = ErrorCode(data.get("code", ErrorCode.UNKNOWN))
        message = data.get("message", "Unknown error")
        details = data.get("details")
        return cls(message, code, details)


class NetworkError(AccumulateError):
    """Network-related errors."""

    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None, cause: Optional[Exception] = None):
        super().__init__(message, ErrorCode.NETWORK_ERROR, details, cause)


class ConnectionError(NetworkError):
    """Connection failures."""

    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None, cause: Optional[Exception] = None):
        super().__init__(message, details, cause)
        self.code = ErrorCode.CONNECTION_FAILED


class TimeoutError(NetworkError):
    """Request timeouts."""

    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None, cause: Optional[Exception] = None):
        super().__init__(message, details, cause)
        self.code = ErrorCode.TIMEOUT


class AuthenticationError(AccumulateError):
    """Authentication and authorization errors."""

    def __init__(self, message: str, code: ErrorCode = ErrorCode.UNAUTHENTICATED,
                 details: Optional[Dict[str, Any]] = None, cause: Optional[Exception] = None):
        super().__init__(message, code, details, cause)


class ValidationError(AccumulateError):
    """Transaction and data validation errors."""

    def __init__(self, message: str, code: ErrorCode = ErrorCode.INVALID_TRANSACTION,
                 details: Optional[Dict[str, Any]] = None, cause: Optional[Exception] = None):
        super().__init__(message, code, details, cause)


class TransactionError(AccumulateError):
    """Transaction execution errors."""

    def __init__(self, message: str, code: ErrorCode = ErrorCode.TRANSACTION_FAILED,
                 details: Optional[Dict[str, Any]] = None, cause: Optional[Exception] = None):
        super().__init__(message, code, details, cause)


class InsufficientBalanceError(TransactionError):
    """Insufficient account balance."""

    def __init__(self, message: str = "Insufficient balance",
                 details: Optional[Dict[str, Any]] = None, cause: Optional[Exception] = None):
        super().__init__(message, ErrorCode.INSUFFICIENT_BALANCE, details, cause)


class InsufficientCreditsError(TransactionError):
    """Insufficient credits for transaction."""

    def __init__(self, message: str = "Insufficient credits",
                 details: Optional[Dict[str, Any]] = None, cause: Optional[Exception] = None):
        super().__init__(message, ErrorCode.INSUFFICIENT_CREDITS, details, cause)


class AccountNotFoundError(AccumulateError):
    """Account does not exist."""

    def __init__(self, message: str = "Account not found",
                 details: Optional[Dict[str, Any]] = None, cause: Optional[Exception] = None):
        super().__init__(message, ErrorCode.ACCOUNT_DOES_NOT_EXIST, details, cause)


class InvalidSignatureError(ValidationError):
    """Invalid signature."""

    def __init__(self, message: str = "Invalid signature",
                 details: Optional[Dict[str, Any]] = None, cause: Optional[Exception] = None):
        super().__init__(message, ErrorCode.INVALID_SIGNATURE, details, cause)


class MissingSignatureError(ValidationError):
    """Missing required signature."""

    def __init__(self, message: str = "Missing signature",
                 details: Optional[Dict[str, Any]] = None, cause: Optional[Exception] = None):
        super().__init__(message, ErrorCode.MISSING_SIGNATURE, details, cause)


class EncodingError(AccumulateError):
    """Data encoding/decoding errors."""

    def __init__(self, message: str, code: ErrorCode = ErrorCode.ENCODING_ERROR,
                 details: Optional[Dict[str, Any]] = None, cause: Optional[Exception] = None):
        super().__init__(message, code, details, cause)


class MarshalError(EncodingError):
    """Data marshaling error."""

    def __init__(self, message: str = "Marshal error",
                 details: Optional[Dict[str, Any]] = None, cause: Optional[Exception] = None):
        super().__init__(message, ErrorCode.MARSHAL_ERROR, details, cause)


class UnmarshalError(EncodingError):
    """Data unmarshaling error."""

    def __init__(self, message: str = "Unmarshal error",
                 details: Optional[Dict[str, Any]] = None, cause: Optional[Exception] = None):
        super().__init__(message, ErrorCode.UNMARSHAL_ERROR, details, cause)


class InvalidURLError(AccumulateError):
    """Invalid URL format."""

    def __init__(self, message: str = "Invalid URL",
                 details: Optional[Dict[str, Any]] = None, cause: Optional[Exception] = None):
        super().__init__(message, ErrorCode.INVALID_URL, details, cause)


def error_from_response(response: Dict[str, Any]) -> Optional[AccumulateError]:
    """
    Create an appropriate error from an API response.

    Args:
        response: API response containing error information

    Returns:
        Appropriate error instance or None if no error
    """
    if "error" not in response:
        return None

    error_data = response["error"]
    if isinstance(error_data, str):
        return AccumulateError(error_data)

    if not isinstance(error_data, dict):
        return AccumulateError(str(error_data))

    message = error_data.get("message", "Unknown error")
    code_value = error_data.get("code", ErrorCode.UNKNOWN)
    details = error_data.get("data")

    # Try to map to specific error code
    try:
        code = ErrorCode(code_value)
    except ValueError:
        code = ErrorCode.UNKNOWN

    # Create specific error types based on code
    if code == ErrorCode.NETWORK_ERROR:
        return NetworkError(message, details)
    elif code == ErrorCode.CONNECTION_FAILED:
        return ConnectionError(message, details)
    elif code == ErrorCode.TIMEOUT:
        return TimeoutError(message, details)
    elif code in (ErrorCode.UNAUTHENTICATED, ErrorCode.FORBIDDEN, ErrorCode.INVALID_PRINCIPAL):
        return AuthenticationError(message, code, details)
    elif code in (ErrorCode.INVALID_TRANSACTION, ErrorCode.MISSING_SIGNATURE, ErrorCode.INVALID_SIGNATURE_SET):
        return ValidationError(message, code, details)
    elif code == ErrorCode.TRANSACTION_FAILED:
        return TransactionError(message, code, details)
    elif code == ErrorCode.INSUFFICIENT_BALANCE:
        return InsufficientBalanceError(message, details)
    elif code == ErrorCode.INSUFFICIENT_CREDITS:
        return InsufficientCreditsError(message, details)
    elif code == ErrorCode.ACCOUNT_DOES_NOT_EXIST:
        return AccountNotFoundError(message, details)
    elif code == ErrorCode.INVALID_SIGNATURE:
        return InvalidSignatureError(message, details)
    elif code == ErrorCode.MISSING_SIGNATURE:
        return MissingSignatureError(message, details)
    elif code in (ErrorCode.ENCODING_ERROR, ErrorCode.INVALID_JSON, ErrorCode.INVALID_BINARY):
        return EncodingError(message, code, details)
    elif code == ErrorCode.MARSHAL_ERROR:
        return MarshalError(message, details)
    elif code == ErrorCode.UNMARSHAL_ERROR:
        return UnmarshalError(message, details)
    elif code == ErrorCode.INVALID_URL:
        return InvalidURLError(message, details)
    else:
        return AccumulateError(message, code, details)


class ErrorHandler:
    """
    Utility class for handling and categorizing errors.
    """

    @staticmethod
    def is_retryable(error: Exception) -> bool:
        """
        Check if an error is retryable.

        Args:
            error: Exception to check

        Returns:
            True if the error should be retried
        """
        if isinstance(error, AccumulateError):
            # Network errors and timeouts are retryable
            if error.code in (ErrorCode.NETWORK_ERROR, ErrorCode.CONNECTION_FAILED,
                             ErrorCode.TIMEOUT, ErrorCode.SERVICE_UNAVAILABLE):
                return True
            # Rate limiting is retryable
            if error.code == ErrorCode.RATE_LIMITED:
                return True
            # Internal errors might be transient
            if error.code == ErrorCode.INTERNAL:
                return True
            # Validation and authentication errors are not retryable
            return False

        # Network-related standard library exceptions are retryable
        import socket
        import ssl
        if isinstance(error, (socket.timeout, socket.gaierror, ssl.SSLError, ConnectionError)):
            return True

        return False

    @staticmethod
    def should_wait_for_tx(error: Exception) -> bool:
        """
        Check if we should wait for a transaction instead of failing.

        Args:
            error: Exception to check

        Returns:
            True if we should wait for the transaction
        """
        if isinstance(error, AccumulateError):
            # Transaction might be pending
            if error.code in (ErrorCode.DELIVER_TX_FAILED, ErrorCode.WRONG_PARTITION):
                return True
        return False

    @staticmethod
    def extract_tx_hash(error: Exception) -> Optional[str]:
        """
        Extract transaction hash from error details if available.

        Args:
            error: Exception to examine

        Returns:
            Transaction hash if found
        """
        if isinstance(error, AccumulateError) and error.details:
            return error.details.get("txHash") or error.details.get("transaction_hash")
        return None


# Re-export key error types for convenience
__all__ = [
    "ErrorCode",
    "AccumulateError",
    "NetworkError",
    "ConnectionError",
    "TimeoutError",
    "AuthenticationError",
    "ValidationError",
    "TransactionError",
    "InsufficientBalanceError",
    "InsufficientCreditsError",
    "AccountNotFoundError",
    "InvalidSignatureError",
    "MissingSignatureError",
    "EncodingError",
    "MarshalError",
    "UnmarshalError",
    "InvalidURLError",
    "error_from_response",
    "ErrorHandler"
]