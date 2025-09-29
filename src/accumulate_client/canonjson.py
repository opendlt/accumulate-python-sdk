"""
Canonical JSON - 1:1 mapping to Dart json_canonical.dart

Implements exact canonical JSON encoding semantics matching Dart canonicalJsonString().
Sorts object keys lexicographically and encodes with no extra whitespace so hashes
are stable across languages.
"""

import json
from typing import Any, Dict, List, Union


def dumps_canonical(obj: Any) -> str:
    """
    Encode object as canonical JSON string.

    Maps to: Dart json_canonical.dart:5-7 String canonicalJsonString(dynamic value)

    Deterministic key order (sorted by raw UTF-16 code units, like Dart).
    No extra whitespace for stable cross-language hashing.
    Recursively applies canonicalization to nested objects and arrays.

    Args:
        obj: Object to encode (dict, list, str, int, float, bool, None)

    Returns:
        Canonical JSON string with sorted keys and no extra whitespace
    """
    return json.dumps(_canonicalize(obj), separators=(',', ':'), ensure_ascii=False, sort_keys=True)


def _canonicalize(v: Any) -> Any:
    """
    Recursively canonicalize a value.

    Maps to: Dart json_canonical.dart:9-23 dynamic _canonicalize(dynamic v)

    - Maps: Sort keys lexicographically, recursively canonicalize values
    - Lists: Recursively canonicalize elements, preserve order
    - Primitives: Pass through unchanged (numbers, strings, bool, null)

    Args:
        v: Value to canonicalize

    Returns:
        Canonicalized value ready for JSON encoding
    """
    if isinstance(v, dict):
        # Maps to: Dart json_canonical.dart:10-16
        # Sort keys lexicographically (Python's sort() matches Dart's ..sort())
        keys = sorted(str(k) for k in v.keys())
        out = {}
        for k in keys:
            # Find original key that matches string representation
            original_key = next(orig_k for orig_k in v.keys() if str(orig_k) == k)
            out[k] = _canonicalize(v[original_key])
        return out
    elif isinstance(v, list):
        # Maps to: Dart json_canonical.dart:17-18
        # Recursively canonicalize elements, preserve array order
        return [_canonicalize(item) for item in v]
    else:
        # Maps to: Dart json_canonical.dart:19-22
        # Numbers/strings/bool/null pass through unchanged
        return v