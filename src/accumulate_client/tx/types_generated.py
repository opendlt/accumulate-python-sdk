"""
Generated transaction and type models from Accumulate protocol schema.

This file is auto-generated. Do not edit manually.
Use gen_types_from_manifest.py to regenerate.
"""

from enum import Enum
from typing import List, Optional, Dict, Any, Union
from pydantic import BaseModel, Field, field_validator
import re
import json


# Helper functions
def model_to_canonical_json(obj: BaseModel) -> bytes:
    """Convert Pydantic model to canonical JSON bytes."""
    data = obj.model_dump(exclude_none=True, by_alias=True)
    # Convert bytes to hex
    data = _normalize_bytes_to_hex(data)
    # Sort keys and compact format
    json_str = json.dumps(data, sort_keys=True, separators=(',', ':'))
    return json_str.encode('utf-8')


def dict_to_model(tx_type: str, data_dict: Dict[str, Any]):
    """Convert dict to the appropriate model type."""
    from ._type_index import lookup_tx_model

    model_cls = lookup_tx_model(tx_type)
    if not model_cls:
        raise ValueError(f"Unknown transaction type: {tx_type}")

    # Normalize hex strings to bytes where needed
    normalized_data = _normalize_hex_to_bytes(data_dict, model_cls)

    return model_cls.model_validate(normalized_data)


def _normalize_bytes_to_hex(data):
    """Recursively convert bytes to hex strings."""
    if isinstance(data, bytes):
        return data.hex()
    elif isinstance(data, dict):
        return {k: _normalize_bytes_to_hex(v) for k, v in data.items()}
    elif isinstance(data, list):
        return [_normalize_bytes_to_hex(item) for item in data]
    return data


def _normalize_hex_to_bytes(data, model_cls):
    """Recursively convert hex strings to bytes for bytes fields."""
    # This would need field introspection - simplified for now
    return data


class TransactionType(str, Enum):
    """Transaction type enumeration"""
    CREATEIDENTITY = "createIdentity"
    SENDTOKENS = "sendTokens"
    CREATEDATAACCOUNT = "createDataAccount"
    WRITEDATA = "writeData"
    ADDCREDITS = "addCredits"
    UPDATEKEYPAGE = "updateKeyPage"
    CREATEKEYBOOK = "createKeyBook"

class Url(BaseModel):
    """Accumulate URL"""
    url: str = Field(description="URL string")

class AcmeFaucet(BaseModel):
    """ACME faucet transaction"""
    url: str = Field(description="Target account URL")

class AddCredits(BaseModel):
    """Add credits to an account"""
    amount: int = Field(description="Amount to add")
    oracle: Optional[float] = Field(default=None, description="Oracle price")
    recipient: str = Field(description="Recipient account URL")

class BlockValidatorAnchor(BaseModel):
    """Block validator anchor transaction"""
    minorBlocks: List[bytes] = Field(description="Minor block hashes")
    rootChainAnchor: bytes = Field(description="Root chain anchor")
    source: str = Field(description="Source URL")
    stateTreeAnchor: bytes = Field(description="State tree anchor")

class BurnCredits(BaseModel):
    """Burn credits"""
    amount: int = Field(description="Amount to burn")

class BurnTokens(BaseModel):
    """Burn tokens"""
    amount: int = Field(description="Amount to burn")

class CreateDataAccount(BaseModel):
    """Create a data account"""
    keyBook: Optional[str] = Field(default=None, description="Key book URL")
    url: str = Field(description="Data account URL to create")

class CreateIdentity(BaseModel):
    """Create an identity"""
    keyBook: Optional[str] = Field(default=None, description="Key book URL")
    keyPage: Optional[str] = Field(default=None, description="Key page URL")
    url: str = Field(description="Identity URL to create")

class CreateKeyBook(BaseModel):
    """Create a key book"""
    pages: Optional[int] = Field(default=None, description="Number of pages")
    url: str = Field(description="Key book URL to create")

class CreateKeyPage(BaseModel):
    """Create a key page"""
    keys: List[bytes] = Field(description="Key data")

class CreateLiteTokenAccount(BaseModel):
    """Create a lite token account"""
    pass

class CreateToken(BaseModel):
    """Create a new token"""
    precision: int = Field(description="Token precision")
    symbol: str = Field(description="Token symbol")
    url: str = Field(description="Token URL to create")

class CreateTokenAccount(BaseModel):
    """Create a token account"""
    keyBook: Optional[str] = Field(default=None, description="Key book URL")
    tokenUrl: str = Field(description="Token URL")
    url: str = Field(description="Token account URL to create")

class DirectoryAnchor(BaseModel):
    """Directory anchor transaction"""
    rootChainAnchor: bytes = Field(description="Root chain anchor")
    source: str = Field(description="Source URL")
    stateTreeAnchor: bytes = Field(description="State tree anchor")

class IssueTokens(BaseModel):
    """Issue tokens"""
    amount: int = Field(description="Amount to issue")
    recipient: str = Field(description="Recipient account URL")

class LockAccount(BaseModel):
    """Lock account"""
    height: int = Field(description="Block height to lock until")

class NetworkMaintenance(BaseModel):
    """Network maintenance transaction"""
    operation: str = Field(description="Maintenance operation")
    target: str = Field(description="Target account URL")

class RemoteTransaction(BaseModel):
    """Remote transaction"""
    hash: bytes = Field(description="Transaction hash")

class SendTokens(BaseModel):
    """Send tokens between accounts"""
    amount: int = Field(description="Amount to send in atomic units")
    meta: Optional[bytes] = Field(default=None, description="Optional metadata")
    to: str = Field(description="Recipient account URL")

class SyntheticBurnTokens(BaseModel):
    """Synthetic burn tokens transaction"""
    amount: int = Field(description="Amount to burn")
    cause: bytes = Field(description="Causation hash")

class SyntheticCreateIdentity(BaseModel):
    """Synthetic create identity transaction"""
    cause: bytes = Field(description="Causation hash")
    url: str = Field(description="Identity URL to create")

class SyntheticDepositCredits(BaseModel):
    """Synthetic deposit credits transaction"""
    amount: int = Field(description="Amount to deposit")
    cause: bytes = Field(description="Causation hash")

class SyntheticDepositTokens(BaseModel):
    """Synthetic deposit tokens transaction"""
    amount: int = Field(description="Amount to deposit")
    cause: bytes = Field(description="Causation hash")
    token: str = Field(description="Token URL")

class SyntheticForwardTransaction(BaseModel):
    """Synthetic forward transaction"""
    cause: bytes = Field(description="Causation hash")
    envelope: bytes = Field(description="Transaction envelope")

class SyntheticWriteData(BaseModel):
    """Synthetic write data transaction"""
    cause: bytes = Field(description="Causation hash")
    data: bytes = Field(description="Data to write")

class SystemGenesis(BaseModel):
    """System genesis transaction"""
    networkName: str = Field(description="Network name")
    version: str = Field(description="System version")

class SystemWriteData(BaseModel):
    """System write data transaction"""
    data: bytes = Field(description="System data")

class TransferCredits(BaseModel):
    """Transfer credits"""
    amount: int = Field(description="Amount to transfer")
    to: str = Field(description="Recipient account URL")

class UpdateAccountAuth(BaseModel):
    """Update account authorization"""
    authority: str = Field(description="Authority URL")
    operations: List[str] = Field(description="Authorized operations")

class UpdateKey(BaseModel):
    """Update a key"""
    newKeyHash: bytes = Field(description="New key hash")

class UpdateKeyPage(BaseModel):
    """Update a key page"""
    key: bytes = Field(description="Key data")
    newKey: Optional[bytes] = Field(default=None, description="New key data for update operations")
    operation: str = Field(description="Operation type (add, remove, update)")

class WriteData(BaseModel):
    """Write data to a data account"""
    data: bytes = Field(description="Data to write")
    scratch: Optional[bool] = Field(default=None, description="Whether to write to scratch space")

class WriteDataTo(BaseModel):
    """Write data to a specific account"""
    data: bytes = Field(description="Data to write")
    recipient: str = Field(description="Recipient data account URL")

