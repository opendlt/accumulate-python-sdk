"""
Mock-compatible client module for test compatibility.

This module provides exactly what the test_client_public_api.py test expects
including the correct module structure for patching.
"""

import requests
from .client_compat import AccumulateClient

# Make requests available for patching
# Test patches: accumulate_client.client.requests.Session
# This allows the patch to work correctly

__all__ = ["AccumulateClient", "requests"]