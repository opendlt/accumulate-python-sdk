"""
Test-compatible AccumulateClient implementation.

This module provides a client implementation that matches the interface
expected by test_client_public_api.py while maintaining real functionality.
"""

import json
from typing import Any, Dict, Optional
import requests
from .runtime.errors import AccumulateError


class AccumulateClient:
    """
    Test-compatible AccumulateClient with requests.Session support.

    This implementation provides the exact interface expected by the test suite
    while maintaining real JSON-RPC functionality.
    """

    def __init__(self, server_url: str):
        """
        Initialize the client.

        Args:
            server_url: Server URL (e.g., "http://test.example.com")
        """
        self.server_url = server_url
        self.session = requests.Session()

    def close(self):
        """Close the client session."""
        if self.session:
            self.session.close()

    def call(self, method: str, params: Optional[Dict[str, Any]] = None) -> Any:
        """
        Make a JSON-RPC call.

        Args:
            method: RPC method name
            params: Method parameters

        Returns:
            Method result or None if no result field

        Raises:
            Exception: On JSON-RPC errors or HTTP errors
        """
        if params is None:
            params = {}

        payload = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": method,
            "params": params
        }

        headers = {"Content-Type": "application/json"}

        response = self.session.post(
            self.server_url,
            json=payload,
            headers=headers
        )

        # Let HTTP errors bubble up
        response.raise_for_status()

        response_data = response.json()

        if "error" in response_data:
            error = response_data["error"]
            if isinstance(error, dict):
                message = error.get("message", str(error))
                code = error.get("code")
            else:
                message = str(error)
                code = None
            raise Exception(f"JSON-RPC Error ({code}): {message}")

        return response_data.get("result")

    # ==== Core API Methods ====

    def describe(self) -> Any:
        """Query node description."""
        return self.call("describe")

    def status(self) -> Any:
        """Query node status."""
        return self.call("status")

    def version(self) -> Any:
        """Query node version."""
        return self.call("version")

    def faucet(self, params: Dict[str, Any]) -> Any:
        """Request tokens from faucet."""
        return self.call("faucet", params)

    # ==== Execute Methods ====

    def execute(self, params: Dict[str, Any]) -> Any:
        """Execute a transaction."""
        return self.call("execute", params)

    def execute_add_credits(self, params: Dict[str, Any]) -> Any:
        """Execute add credits transaction."""
        return self.call("add-credits", params)

    def execute_send_tokens(self, params: Dict[str, Any]) -> Any:
        """Execute send tokens transaction."""
        return self.call("send-tokens", params)

    def execute_create_identity(self, params: Dict[str, Any]) -> Any:
        """Execute create identity transaction."""
        return self.call("create-identity", params)

    def execute_create_token_account(self, params: Dict[str, Any]) -> Any:
        """Execute create token account transaction."""
        return self.call("create-token-account", params)

    def execute_burn_tokens(self, params: Dict[str, Any]) -> Any:
        """Execute burn tokens transaction."""
        return self.call("burn-tokens", params)

    def execute_create_adi(self, params: Dict[str, Any]) -> Any:
        """Execute create ADI transaction."""
        return self.call("create-adi", params)

    def execute_create_data_account(self, params: Dict[str, Any]) -> Any:
        """Execute create data account transaction."""
        return self.call("create-data-account", params)

    def execute_create_key_book(self, params: Dict[str, Any]) -> Any:
        """Execute create key book transaction."""
        return self.call("create-key-book", params)

    def execute_create_key_page(self, params: Dict[str, Any]) -> Any:
        """Execute create key page transaction."""
        return self.call("create-key-page", params)

    def execute_create_token(self, params: Dict[str, Any]) -> Any:
        """Execute create token transaction."""
        return self.call("create-token", params)

    def execute_direct(self, params: Dict[str, Any]) -> Any:
        """Execute direct transaction."""
        return self.call("execute-direct", params)

    def execute_issue_tokens(self, params: Dict[str, Any]) -> Any:
        """Execute issue tokens transaction."""
        return self.call("issue-tokens", params)

    def execute_local(self, params: Dict[str, Any]) -> Any:
        """Execute local transaction."""
        return self.call("execute-local", params)

    def execute_update_account_auth(self, params: Dict[str, Any]) -> Any:
        """Execute update account auth transaction."""
        return self.call("update-account-auth", params)

    def execute_update_key(self, params: Dict[str, Any]) -> Any:
        """Execute update key transaction."""
        return self.call("update-key", params)

    def execute_update_key_page(self, params: Dict[str, Any]) -> Any:
        """Execute update key page transaction."""
        return self.call("update-key-page", params)

    def execute_write_data(self, params: Dict[str, Any]) -> Any:
        """Execute write data transaction."""
        return self.call("write-data", params)

    def execute_write_data_to(self, params: Dict[str, Any]) -> Any:
        """Execute write data to transaction."""
        return self.call("write-data-to", params)

    # ==== Query Methods ====

    def query(self, params: Optional[Dict[str, Any]] = None) -> Any:
        """Query account or transaction."""
        return self.call("query", params or {})

    def query_tx(self, params: Dict[str, Any]) -> Any:
        """Query transaction by ID."""
        return self.call("query-tx", params)

    def query_tx_history(self, params: Dict[str, Any]) -> Any:
        """Query transaction history."""
        return self.call("query-tx-history", params)

    def query_data(self, params: Dict[str, Any]) -> Any:
        """Query data entry."""
        return self.call("query-data", params)

    def query_directory(self, params: Dict[str, Any]) -> Any:
        """Query directory entries."""
        return self.call("query-directory", params)

    def query_data_set(self, params: Dict[str, Any]) -> Any:
        """Query data entry set."""
        return self.call("query-data-set", params)

    def query_key_page_index(self, params: Dict[str, Any]) -> Any:
        """Query key page index."""
        return self.call("query-key-index", params)

    def query_major_blocks(self, params: Dict[str, Any]) -> Any:
        """Query major blocks."""
        return self.call("query-major-blocks", params)

    def query_minor_blocks(self, params: Dict[str, Any]) -> Any:
        """Query minor blocks."""
        return self.call("query-minor-blocks", params)

    def query_synth(self, params: Dict[str, Any]) -> Any:
        """Query synthetic transactions."""
        return self.call("query-synth", params)

    def query_tx_local(self, params: Dict[str, Any]) -> Any:
        """Query transaction locally."""
        return self.call("query-tx-local", params)

    def metrics(self, params: Dict[str, Any]) -> Any:
        """Query network metrics."""
        return self.call("metrics", params)

    # ==== V3 API Methods ====

    def query_block(self, params: Dict[str, Any]) -> Any:
        """Query block information."""
        return self.call("query-block", params)

    def query_chain(self, params: Dict[str, Any]) -> Any:
        """Query chain information."""
        return self.call("query-chain", params)

    def submit(self, params: Dict[str, Any]) -> Any:
        """Submit transaction envelope."""
        return self.call("submit", params)

    def submit_multi(self, params: Dict[str, Any]) -> Any:
        """Submit multiple transaction envelopes."""
        return self.call("submit-multi", params)


__all__ = ["AccumulateClient"]