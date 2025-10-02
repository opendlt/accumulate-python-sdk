"""
Transaction execution infrastructure for Accumulate Protocol.

Provides high-level functions for signing and submitting transactions
with exact parity to the Go implementation.

Reference: C:/Accumulate_Stuff/accumulate/cmd/accumulated/run/client.go
"""

from __future__ import annotations
from typing import Any, Dict, Optional, Union
import time

from ..runtime.url import AccountUrl
from ..runtime.errors import AccumulateError
from ..signers.signer import Signer
from .codec import hash_transaction, serialize_for_signature


class ExecuteError(AccumulateError):
    """Transaction execution specific errors."""
    pass


def sign_and_submit(
    client,
    envelope: Any,
    signer: Signer,
    *,
    wait: bool = True,
    timeout_s: int = 30
) -> Dict[str, Any]:
    """
    Sign a transaction envelope and submit it to the network.

    Args:
        client: AccumulateClient instance
        envelope: Transaction envelope to sign and submit
        signer: Signer to use for signing
        wait: Whether to wait for transaction completion
        timeout_s: Timeout in seconds for waiting

    Returns:
        Transaction receipt or transaction ID

    Raises:
        ExecuteError: If signing or submission fails
    """
    try:
        # Compute transaction hash for signing
        tx_hash = hash_transaction(envelope)

        # Create signature
        signature_data = signer.to_accumulate_signature(
            tx_hash,
            transaction_hash=tx_hash.hex()
        )

        # Attach signature to envelope
        if hasattr(envelope, 'signatures'):
            # Object-style envelope
            if not envelope.signatures:
                envelope.signatures = []
            envelope.signatures.append(signature_data)
        elif isinstance(envelope, dict):
            # Dictionary-style envelope
            if 'signatures' not in envelope:
                envelope['signatures'] = []
            envelope['signatures'].append(signature_data)
        else:
            # Handle other envelope formats - the current implementation
            # supports object and dict formats which cover the expected use cases
            raise ExecuteError("Unknown envelope signature format")

        # Submit via client
        if hasattr(client, 'submit_transaction'):
            result = client.submit_transaction(envelope)
        elif hasattr(client, 'submit'):
            result = client.submit(envelope)
        else:
            raise ExecuteError("Client does not have submit method")

        # Extract transaction ID
        if isinstance(result, dict):
            tx_id = result.get('txid') or result.get('transactionHash')
        elif isinstance(result, list) and len(result) > 0:
            # Handle list responses from submit()
            first_result = result[0]
            if isinstance(first_result, dict):
                tx_id = first_result.get('txid') or first_result.get('transactionHash')
            else:
                tx_id = str(first_result)
        else:
            tx_id = str(result)

        if not wait:
            return {'txid': tx_id}

        # Wait for completion
        return wait_for_completion(client, tx_id, timeout_s)

    except Exception as e:
        raise ExecuteError(f"Failed to sign and submit transaction: {e}")


def wait_for_completion(client, tx_id: str, timeout_s: int) -> Dict[str, Any]:
    """
    Wait for transaction completion.

    Args:
        client: AccumulateClient instance
        tx_id: Transaction ID to wait for
        timeout_s: Timeout in seconds

    Returns:
        Transaction receipt

    Raises:
        ExecuteError: If timeout or transaction fails
    """
    start_time = time.time()

    while time.time() - start_time < timeout_s:
        try:
            if hasattr(client, 'get_transaction'):
                result = client.get_transaction(tx_id)
            elif hasattr(client, 'query_tx'):
                result = client.query_tx(tx_id)
            else:
                # Fallback: assume completion
                return {'txid': tx_id, 'status': 'pending'}

            if isinstance(result, dict):
                status = result.get('status')
                if status in ('delivered', 'completed', 'confirmed'):
                    return result
                elif status in ('failed', 'rejected'):
                    raise ExecuteError(f"Transaction failed: {result.get('error', 'Unknown error')}")

            time.sleep(1)

        except Exception as e:
            if 'not found' in str(e).lower():
                time.sleep(1)
                continue
            raise ExecuteError(f"Error waiting for transaction: {e}")

    raise ExecuteError(f"Transaction {tx_id} timed out after {timeout_s} seconds")


def build_sign_submit(
    client,
    tx_type: Union[str, int],
    signer: Signer,
    *,
    wait: bool = True,
    timeout_s: int = 30,
    **kwargs
) -> Dict[str, Any]:
    """
    Build, sign, and submit a transaction in one call.

    Args:
        client: AccumulateClient instance
        tx_type: Transaction type (string name or enum value)
        signer: Signer to use
        wait: Whether to wait for completion
        timeout_s: Timeout for waiting
        **kwargs: Transaction parameters

    Returns:
        Transaction receipt or transaction ID

    Raises:
        ExecuteError: If any step fails
    """
    try:
        # Import here to avoid circular dependencies
        from . import builders

        # Get builder for transaction type
        builder = builders.get_builder_for(tx_type)

        # Set fields from kwargs
        for key, value in kwargs.items():
            # Convert snake_case to camelCase if needed
            field_name = _snake_to_camel(key)
            builder.with_field(field_name, value)

        # Build envelope with defaults
        envelope = builder.build_envelope(
            origin=kwargs.get('origin') or signer.get_signer_url(),
            timestamp=kwargs.get('timestamp'),
            memo=kwargs.get('memo'),
            signer_hint=kwargs.get('signer_hint')
        )

        # Sign and submit
        return sign_and_submit(
            client, envelope, signer,
            wait=wait, timeout_s=timeout_s
        )

    except Exception as e:
        raise ExecuteError(f"Failed to build, sign, and submit transaction: {e}")


def _snake_to_camel(snake_str: str) -> str:
    """Convert snake_case to camelCase."""
    components = snake_str.split('_')
    return components[0] + ''.join(word.capitalize() for word in components[1:])


__all__ = [
    "ExecuteError",
    "sign_and_submit",
    "wait_for_completion",
    "build_sign_submit"
]