"""
V3 API Receipt model.

Matches Go ``api.Receipt`` (pkg/api/v3/types.yml), which wraps a
``merkle.Receipt`` with block context. Query results are plain dicts; use
``Receipt.from_dict`` to read the receipt portion with typed access.
"""

from __future__ import annotations
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class Receipt(BaseModel):
    """A receipt together with the block it was produced against.

    Besides the embedded merkle receipt (``start``, ``end``, ``anchor``,
    ``entries``), a v3 receipt reports:

    - ``local_block`` / ``local_block_time`` / ``major_block``: where it anchors.
    - ``for_height``: the minor block height it was produced against; 0 means current state.
    - ``complete``: it terminates at a directory root, so no second call is needed.
    - ``partition``: when not complete, whose BPT root it terminates at
      (feed this to ``anchor_receipt``).
    - ``starts_at_main_state``: set only on historical receipts; the receipt starts at a
      plain hash of the account's main state, and the account served beside it is that state
      as of ``for_height``. Without it the receipt starts at the account's whole BPT entry
      and no account body is served.
    """
    start: Optional[str] = None
    start_index: Optional[int] = Field(default=None, alias="startIndex")
    end: Optional[str] = None
    end_index: Optional[int] = Field(default=None, alias="endIndex")
    anchor: Optional[str] = None
    entries: List[Dict[str, Any]] = Field(default_factory=list)
    local_block: int = Field(default=0, alias="localBlock")
    local_block_time: Optional[str] = Field(default=None, alias="localBlockTime")
    major_block: int = Field(default=0, alias="majorBlock")
    for_height: int = Field(default=0, alias="forHeight")
    complete: bool = False
    partition: Optional[str] = None
    starts_at_main_state: bool = Field(default=False, alias="startsAtMainState")

    model_config = {"populate_by_name": True, "extra": "allow"}

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Receipt":
        """Build from a receipt dict as returned by the v3 API."""
        return cls.model_validate(data)
