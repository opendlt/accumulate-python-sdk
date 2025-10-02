"""
Fee calculation utilities for Accumulate Protocol.

Implements the fee schedule and calculation logic based on the Go implementation.
Reference: C:/Accumulate_Stuff/accumulate/protocol/fee_schedule.go
"""

from typing import Dict, Any, Optional
import math


# Fee constants (in credits, where 1 credit = $0.0001)
class FeeConstants:
    """Fee constants from the Go implementation."""

    # Basic fees
    FAILED_MAXIMUM = 100  # $0.01
    SIGNATURE = 1  # $0.0001

    # Account creation fees
    CREATE_IDENTITY = 50000  # $5.00
    CREATE_DIRECTORY = 1000  # $0.10
    CREATE_ACCOUNT = 2500  # $0.25

    # Transfer fees
    TRANSFER_TOKENS = 300  # $0.03
    TRANSFER_TOKENS_EXTRA = 100  # $0.01 per additional recipient

    # Token fees
    CREATE_TOKEN = 500000  # $50.00

    # General fees
    GENERAL_TINY = 1  # $0.0001
    GENERAL_SMALL = 10  # $0.001

    # Key management fees
    CREATE_KEY_PAGE = 10000  # $1.00
    CREATE_KEY_PAGE_EXTRA = 100  # $0.01 per additional key

    # Data fees (per 256-byte chunk)
    DATA = 10  # $0.001 / 256 bytes
    SCRATCH_DATA = 1  # $0.0001 / 256 bytes

    # Authorization fees
    UPDATE_AUTH = 300  # $0.03
    UPDATE_AUTH_EXTRA = 100  # $0.01 per additional operation

    # Credit purchase minimum
    MINIMUM_CREDIT_PURCHASE = 100  # $0.01


class FeeCalculator:
    """Calculate transaction fees based on the Accumulate fee schedule."""

    def __init__(self):
        self.constants = FeeConstants()

    def estimate_transaction_fee(self, tx_type: str, tx_body: Dict[str, Any]) -> int:
        """
        Estimate the fee for a transaction.

        Args:
            tx_type: Transaction type name
            tx_body: Transaction body data

        Returns:
            Estimated fee in credits
        """
        # Calculate data size fee component
        data_chunks = self._calculate_data_chunks(tx_body)

        # Base fee calculation by transaction type
        base_fee = self._calculate_base_fee(tx_type, tx_body)

        # Add data size surcharge
        if tx_type in ["WriteData", "WriteDataTo"]:
            # Data transactions have different fee structure
            return self._calculate_data_fee(tx_type, tx_body, data_chunks)
        else:
            # Most transactions have base fee + data surcharge
            return base_fee + (self.constants.DATA * max(0, data_chunks - 1))

    def _calculate_base_fee(self, tx_type: str, tx_body: Dict[str, Any]) -> int:
        """Calculate the base fee for a transaction type."""

        if tx_type == "CreateToken":
            return self.constants.CREATE_TOKEN

        elif tx_type == "CreateIdentity":
            return self._calculate_identity_fee(tx_body)

        elif tx_type in ["CreateTokenAccount", "CreateDataAccount"]:
            return self.constants.CREATE_ACCOUNT

        elif tx_type == "SendTokens":
            recipients = tx_body.get("to", [])
            if not isinstance(recipients, list):
                recipients = [recipients]
            extra_recipients = max(0, len(recipients) - 1)
            return self.constants.TRANSFER_TOKENS + (self.constants.TRANSFER_TOKENS_EXTRA * extra_recipients)

        elif tx_type == "IssueTokens":
            recipients = tx_body.get("to", [])
            if not isinstance(recipients, list):
                recipients = [recipients]
            extra_recipients = max(0, len(recipients) - 1)
            return self.constants.TRANSFER_TOKENS + (self.constants.TRANSFER_TOKENS_EXTRA * extra_recipients)

        elif tx_type == "CreateLiteTokenAccount":
            return self.constants.TRANSFER_TOKENS

        elif tx_type == "CreateKeyBook":
            return self.constants.CREATE_KEY_PAGE

        elif tx_type == "CreateKeyPage":
            keys = tx_body.get("keys", [])
            extra_keys = max(0, len(keys) - 1)
            return self.constants.CREATE_KEY_PAGE + (self.constants.CREATE_KEY_PAGE_EXTRA * extra_keys)

        elif tx_type == "UpdateKeyPage":
            operations = tx_body.get("operation", [])
            if not isinstance(operations, list):
                operations = [operations]
            extra_operations = max(0, len(operations) - 1)
            return self.constants.UPDATE_AUTH + (self.constants.UPDATE_AUTH_EXTRA * extra_operations)

        elif tx_type == "UpdateAccountAuth":
            operations = tx_body.get("operations", [])
            extra_operations = max(0, len(operations) - 1)
            return self.constants.UPDATE_AUTH + (self.constants.UPDATE_AUTH_EXTRA * extra_operations)

        elif tx_type == "UpdateKey":
            return self.constants.UPDATE_AUTH

        elif tx_type in ["BurnTokens", "LockAccount"]:
            return self.constants.GENERAL_SMALL

        elif tx_type == "TransferCredits":
            return self.constants.GENERAL_TINY

        elif tx_type in ["AddCredits", "BurnCredits", "AcmeFaucet", "ActivateProtocolVersion", "NetworkMaintenance"]:
            return 0  # Free transactions

        else:
            # Default for unknown transaction types
            return self.constants.GENERAL_SMALL

    def _calculate_identity_fee(self, tx_body: Dict[str, Any]) -> int:
        """Calculate fee for CreateIdentity transactions."""
        # Base identity creation fee
        return self.constants.CREATE_IDENTITY

    def _calculate_data_fee(self, tx_type: str, tx_body: Dict[str, Any], data_chunks: int) -> int:
        """Calculate fee for data transactions."""

        if tx_type == "WriteData":
            is_scratch = tx_body.get("scratch", False)
            write_to_state = tx_body.get("writeToState", False)

            if is_scratch:
                fee = self.constants.SCRATCH_DATA * data_chunks
            else:
                fee = self.constants.DATA * data_chunks

            if write_to_state:
                fee *= 2

            return fee

        elif tx_type == "WriteDataTo":
            return self.constants.DATA * data_chunks

        else:
            return self.constants.DATA * data_chunks

    def _calculate_data_chunks(self, tx_body: Dict[str, Any]) -> int:
        """
        Calculate the number of 256-byte chunks for fee calculation.

        This is a simplified version - in practice you'd serialize the entire transaction.
        """
        # Estimate transaction size based on content
        estimated_size = 100  # Base transaction overhead

        # Add size estimates for various fields
        if "data" in tx_body:
            data = tx_body["data"]
            if isinstance(data, bytes):
                estimated_size += len(data)
            elif isinstance(data, str):
                estimated_size += len(data.encode('utf-8'))

        # Add size for other fields (simplified)
        for key, value in tx_body.items():
            if isinstance(value, str):
                estimated_size += len(value)
            elif isinstance(value, (list, dict)):
                estimated_size += len(str(value))  # Rough estimate

        # Calculate chunks (round up)
        chunks = math.ceil(estimated_size / 256)
        return max(1, chunks)  # At least 1 chunk

    def estimate_signature_fee(self, signature_data: Optional[Dict[str, Any]] = None) -> int:
        """
        Estimate the fee for a signature.

        Args:
            signature_data: Signature metadata (optional)

        Returns:
            Estimated signature fee in credits
        """
        base_fee = self.constants.SIGNATURE

        if signature_data:
            # Calculate signature size chunks
            sig_size = len(str(signature_data))  # Rough estimate
            chunks = math.ceil(sig_size / 256)

            # Base fee + extra chunk fees
            fee = base_fee + (base_fee * max(0, chunks - 1))

            # Add delegation fees if applicable
            if signature_data.get("type") == "delegated":
                fee += base_fee  # Extra fee for delegation

            return fee

        return base_fee


def estimate_fees(tx_type: str, tx_body: Dict[str, Any], network_params: Optional[Dict[str, Any]] = None) -> Dict[str, int]:
    """
    Convenience function to estimate all fees for a transaction.

    Args:
        tx_type: Transaction type name
        tx_body: Transaction body data
        network_params: Network parameters (optional, for future use)

    Returns:
        Dictionary with fee breakdown
    """
    calculator = FeeCalculator()

    tx_fee = calculator.estimate_transaction_fee(tx_type, tx_body)
    sig_fee = calculator.estimate_signature_fee()

    return {
        "transaction": tx_fee,
        "signature": sig_fee,
        "total": tx_fee + sig_fee
    }


__all__ = [
    "FeeConstants",
    "FeeCalculator",
    "estimate_fees"
]