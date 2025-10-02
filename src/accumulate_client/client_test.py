"""
Client module that provides the interface expected by test_client_public_api.py

This module creates the necessary structure for the test patches to work.
"""

import requests
from .client_compat import AccumulateClient

# Export the requests module so tests can patch accumulate_client.client.requests
__all__ = ["AccumulateClient", "requests"]