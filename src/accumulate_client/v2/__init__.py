"""
Accumulate V2 API client.

Provides dedicated V2 API client for legacy API compatibility.
V2 API is being deprecated in favor of V3, but remains available
for backward compatibility.
"""

from .client import AccumulateV2Client, V2ApiError

__all__ = [
    "AccumulateV2Client",
    "V2ApiError",
]
