"""
Request types and pagination support for the Accumulate client.

Provides common request patterns and pagination functionality.
"""

from dataclasses import dataclass
from typing import Optional, Dict, Any, List
import requests


# Re-export requests.Session for compatibility with tests
Session = requests.Session


@dataclass
class Pagination:
    """Pagination parameters for API requests."""
    count: Optional[int] = None
    start: Optional[int] = None
    limit: Optional[int] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for API requests."""
        result = {}
        if self.count is not None:
            result['count'] = self.count
        if self.start is not None:
            result['start'] = self.start
        if self.limit is not None:
            result['limit'] = self.limit
        return result


@dataclass
class QueryRequest:
    """Base query request."""
    url: str
    pagination: Optional[Pagination] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for API requests."""
        result = {'url': self.url}
        if self.pagination:
            result.update(self.pagination.to_dict())
        return result


@dataclass
class ExecuteRequest:
    """Base execute request."""
    envelope: Dict[str, Any]

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for API requests."""
        return {'envelope': self.envelope}


# Export classes
__all__ = [
    'Session',
    'Pagination',
    'QueryRequest',
    'ExecuteRequest'
]