# Transaction type definitions for Accumulate Protocol
# Complete implementation with all fields matching Go protocol/types_gen.go

from __future__ import annotations
from pydantic import BaseModel, Field
from typing import Optional, List, Union, Any, Dict
from datetime import datetime

from .enums import (
    TransactionType,
    ExecutorVersion,
    KeyPageOperationType,
    AccountAuthOperationType,
    NetworkMaintenanceOperationType,
    DataEntryType,
    VoteType,
)
from .runtime.url import AccountUrl


# =============================================================================
# Supporting Types (referenced by transaction bodies)
# =============================================================================

class DataEntry(BaseModel):
    """Base data entry type."""
    type: Optional[str] = None
    data: Optional[List[bytes]] = None

    model_config = {"populate_by_name": True}


class AccumulateDataEntry(DataEntry):
    """Accumulate format data entry."""
    type: str = "dataEntry"
    data: List[bytes] = Field(default_factory=list)


class DoubleHashDataEntry(DataEntry):
    """Double-hash format data entry."""
    type: str = "doubleHashDataEntry"
    data: List[bytes] = Field(default_factory=list)


class TokenRecipient(BaseModel):
    """Token recipient with URL and amount."""
    url: str
    amount: int

    model_config = {"populate_by_name": True}


class CreditRecipient(BaseModel):
    """Credit recipient with URL and amount."""
    url: str
    amount: int

    model_config = {"populate_by_name": True}


class KeySpecParams(BaseModel):
    """Key specification parameters for key pages."""
    key_hash: Optional[bytes] = Field(None, alias="keyHash")
    delegate: Optional[str] = None

    model_config = {"populate_by_name": True}


# =============================================================================
# Key Page Operations
# =============================================================================

class AddKeyOperation(BaseModel):
    """Add a key to a key page."""
    type: str = "add"
    entry: KeySpecParams

    model_config = {"populate_by_name": True}


class RemoveKeyOperation(BaseModel):
    """Remove a key from a key page."""
    type: str = "remove"
    entry: KeySpecParams

    model_config = {"populate_by_name": True}


class UpdateKeyOperation(BaseModel):
    """Update a key on a key page."""
    type: str = "update"
    old_entry: KeySpecParams = Field(..., alias="oldEntry")
    new_entry: KeySpecParams = Field(..., alias="newEntry")

    model_config = {"populate_by_name": True}


class SetThresholdKeyPageOperation(BaseModel):
    """Set the accept threshold for a key page."""
    type: str = "setThreshold"
    threshold: int

    model_config = {"populate_by_name": True}


class SetRejectThresholdKeyPageOperation(BaseModel):
    """Set the reject threshold for a key page."""
    type: str = "setRejectThreshold"
    threshold: int

    model_config = {"populate_by_name": True}


class SetResponseThresholdKeyPageOperation(BaseModel):
    """Set the response threshold for a key page."""
    type: str = "setResponseThreshold"
    threshold: int

    model_config = {"populate_by_name": True}


class UpdateAllowedKeyPageOperation(BaseModel):
    """Update allowed/denied transaction types for a key page."""
    type: str = "updateAllowed"
    allow: Optional[List[int]] = None
    deny: Optional[List[int]] = None

    model_config = {"populate_by_name": True}


KeyPageOperation = Union[
    AddKeyOperation,
    RemoveKeyOperation,
    UpdateKeyOperation,
    SetThresholdKeyPageOperation,
    SetRejectThresholdKeyPageOperation,
    SetResponseThresholdKeyPageOperation,
    UpdateAllowedKeyPageOperation,
]


# =============================================================================
# Account Auth Operations
# =============================================================================

class AddAccountAuthorityOperation(BaseModel):
    """Add an authority to an account."""
    type: str = "addAuthority"
    authority: str

    model_config = {"populate_by_name": True}


class RemoveAccountAuthorityOperation(BaseModel):
    """Remove an authority from an account."""
    type: str = "removeAuthority"
    authority: str

    model_config = {"populate_by_name": True}


class EnableAccountAuthOperation(BaseModel):
    """Enable authorization for an authority."""
    type: str = "enable"
    authority: str

    model_config = {"populate_by_name": True}


class DisableAccountAuthOperation(BaseModel):
    """Disable authorization for an authority."""
    type: str = "disable"
    authority: str

    model_config = {"populate_by_name": True}


AccountAuthOperation = Union[
    AddAccountAuthorityOperation,
    RemoveAccountAuthorityOperation,
    EnableAccountAuthOperation,
    DisableAccountAuthOperation,
]


# =============================================================================
# Network Maintenance Operations
# =============================================================================

class PendingTransactionGCOperation(BaseModel):
    """Garbage collection of pending transactions."""
    type: str = "pendingTransactionGC"

    model_config = {"populate_by_name": True}


NetworkMaintenanceOperation = Union[PendingTransactionGCOperation]


# =============================================================================
# Transaction Headers
# =============================================================================

class TxHeaderBase(BaseModel):
    """Base class for transaction headers."""

    model_config = {"populate_by_name": True}


class SyntheticCreateIdentityHeader(TxHeaderBase):
    """Header for SyntheticCreateIdentity transaction."""
    pass


class SyntheticWriteDataHeader(TxHeaderBase):
    """Header for SyntheticWriteData transaction."""
    pass


class SyntheticDepositTokensHeader(TxHeaderBase):
    """Header for SyntheticDepositTokens transaction."""
    pass


class SyntheticDepositCreditsHeader(TxHeaderBase):
    """Header for SyntheticDepositCredits transaction."""
    pass


class SyntheticBurnTokensHeader(TxHeaderBase):
    """Header for SyntheticBurnTokens transaction."""
    pass


class SyntheticForwardTransactionHeader(TxHeaderBase):
    """Header for SyntheticForwardTransaction transaction."""
    pass


class SystemGenesisHeader(TxHeaderBase):
    """Header for SystemGenesis transaction."""
    pass


class BlockValidatorAnchorHeader(TxHeaderBase):
    """Header for BlockValidatorAnchor transaction."""
    pass


class DirectoryAnchorHeader(TxHeaderBase):
    """Header for DirectoryAnchor transaction."""
    pass


class SystemWriteDataHeader(TxHeaderBase):
    """Header for SystemWriteData transaction."""
    pass


class CreateIdentityHeader(TxHeaderBase):
    """Header for CreateIdentity transaction."""
    pass


class CreateTokenAccountHeader(TxHeaderBase):
    """Header for CreateTokenAccount transaction."""
    pass


class SendTokensHeader(TxHeaderBase):
    """Header for SendTokens transaction."""
    pass


class CreateDataAccountHeader(TxHeaderBase):
    """Header for CreateDataAccount transaction."""
    pass


class WriteDataHeader(TxHeaderBase):
    """Header for WriteData transaction."""
    pass


class WriteDataToHeader(TxHeaderBase):
    """Header for WriteDataTo transaction."""
    pass


class AcmeFaucetHeader(TxHeaderBase):
    """Header for AcmeFaucet transaction."""
    pass


class CreateTokenHeader(TxHeaderBase):
    """Header for CreateToken transaction."""
    pass


class IssueTokensHeader(TxHeaderBase):
    """Header for IssueTokens transaction."""
    pass


class BurnTokensHeader(TxHeaderBase):
    """Header for BurnTokens transaction."""
    pass


class CreateLiteTokenAccountHeader(TxHeaderBase):
    """Header for CreateLiteTokenAccount transaction."""
    pass


class CreateKeyPageHeader(TxHeaderBase):
    """Header for CreateKeyPage transaction."""
    pass


class CreateKeyBookHeader(TxHeaderBase):
    """Header for CreateKeyBook transaction."""
    pass


class AddCreditsHeader(TxHeaderBase):
    """Header for AddCredits transaction."""
    pass


class BurnCreditsHeader(TxHeaderBase):
    """Header for BurnCredits transaction."""
    pass


class TransferCreditsHeader(TxHeaderBase):
    """Header for TransferCredits transaction."""
    pass


class UpdateKeyPageHeader(TxHeaderBase):
    """Header for UpdateKeyPage transaction."""
    pass


class LockAccountHeader(TxHeaderBase):
    """Header for LockAccount transaction."""
    pass


class UpdateAccountAuthHeader(TxHeaderBase):
    """Header for UpdateAccountAuth transaction."""
    pass


class UpdateKeyHeader(TxHeaderBase):
    """Header for UpdateKey transaction."""
    pass


class NetworkMaintenanceHeader(TxHeaderBase):
    """Header for NetworkMaintenance transaction."""
    pass


class ActivateProtocolVersionHeader(TxHeaderBase):
    """Header for ActivateProtocolVersion transaction."""
    pass


class RemoteTransactionHeader(TxHeaderBase):
    """Header for RemoteTransaction transaction."""
    pass


# =============================================================================
# User Transaction Bodies
# =============================================================================

class CreateIdentityBody(BaseModel):
    """
    Body for CreateIdentity transaction.

    Creates a new ADI (Accumulate Digital Identifier).
    """
    type: str = "createIdentity"
    url: str  # The identity URL to create
    key_hash: Optional[bytes] = Field(None, alias="keyHash")
    key_book_url: Optional[str] = Field(None, alias="keyBookUrl")
    authorities: Optional[List[str]] = None

    model_config = {"populate_by_name": True}


class CreateTokenAccountBody(BaseModel):
    """
    Body for CreateTokenAccount transaction.

    Creates a new token account under an ADI.
    """
    type: str = "createTokenAccount"
    url: str  # Account URL to create
    token_url: str = Field(..., alias="tokenUrl")  # Token type URL (e.g., acc://ACME)
    authorities: Optional[List[str]] = None
    proof: Optional[Dict[str, Any]] = None  # Token issuer proof for custom tokens

    model_config = {"populate_by_name": True}


class SendTokensBody(BaseModel):
    """
    Body for SendTokens transaction.

    Sends tokens from one account to one or more recipients.
    """
    type: str = "sendTokens"
    to: List[TokenRecipient]  # List of recipients with amounts
    hash: Optional[bytes] = None  # Optional metadata hash
    meta: Optional[bytes] = None  # Optional metadata

    model_config = {"populate_by_name": True}


class CreateDataAccountBody(BaseModel):
    """
    Body for CreateDataAccount transaction.

    Creates a new data account under an ADI.
    """
    type: str = "createDataAccount"
    url: str  # Data account URL to create
    key_book_url: Optional[str] = Field(None, alias="keyBookUrl")  # Key book for the account
    scratch: Optional[bool] = None  # Whether this is a scratch data account
    authorities: Optional[List[str]] = None

    model_config = {"populate_by_name": True}


class WriteDataBody(BaseModel):
    """
    Body for WriteData transaction.

    Writes data to a data account.
    """
    type: str = "writeData"
    entry: Optional[DataEntry] = None  # Data entry to write
    data: Optional[bytes] = None  # Legacy: raw data bytes (converted to entry)
    scratch: Optional[bool] = None  # Write to scratch chain
    write_to_state: Optional[bool] = Field(None, alias="writeToState")

    model_config = {"populate_by_name": True}

    def model_post_init(self, __context: Any) -> None:
        """Convert legacy 'data' field to 'entry' if needed."""
        if self.entry is None and self.data is not None:
            # Convert raw data bytes to AccumulateDataEntry
            object.__setattr__(self, 'entry', AccumulateDataEntry(data=[self.data]))


class WriteDataToBody(BaseModel):
    """
    Body for WriteDataTo transaction.

    Writes data to another account's data chain.
    """
    type: str = "writeDataTo"
    recipient: str  # Target account URL
    entry: Optional[DataEntry] = None  # Data entry to write
    data: Optional[bytes] = None  # Legacy: raw data bytes (converted to entry)
    scratch: Optional[bool] = None  # Write to scratch chain
    entry_hash: Optional[bytes] = Field(None, alias="entryHash")
    write_to_state: Optional[bool] = Field(None, alias="writeToState")

    model_config = {"populate_by_name": True}

    def model_post_init(self, __context: Any) -> None:
        """Convert legacy 'data' field to 'entry' if needed."""
        if self.entry is None and self.data is not None:
            # Convert raw data bytes to AccumulateDataEntry
            object.__setattr__(self, 'entry', AccumulateDataEntry(data=[self.data]))


class AcmeFaucetBody(BaseModel):
    """
    Body for AcmeFaucet transaction.

    Requests tokens from the ACME faucet (testnet/devnet only).
    """
    type: str = "acmeFaucet"
    url: str  # Account URL to receive tokens

    model_config = {"populate_by_name": True}


class CreateTokenBody(BaseModel):
    """
    Body for CreateToken transaction.

    Creates a new token issuer account.
    """
    type: str = "createToken"
    url: str  # Token issuer URL to create
    symbol: str  # Token symbol (e.g., "ACME")
    precision: int  # Decimal precision (e.g., 8 for ACME)
    properties: Optional[str] = None  # Optional properties URL
    supply_limit: Optional[int] = Field(None, alias="supplyLimit")  # Maximum supply
    authorities: Optional[List[str]] = None

    model_config = {"populate_by_name": True}


class IssueTokensBody(BaseModel):
    """
    Body for IssueTokens transaction.

    Issues new tokens from a token issuer.
    """
    type: str = "issueTokens"
    recipient: Optional[str] = None  # Single recipient URL
    amount: Optional[int] = None  # Amount for single recipient
    to: Optional[List[TokenRecipient]] = None  # Multiple recipients

    model_config = {"populate_by_name": True}


class BurnTokensBody(BaseModel):
    """
    Body for BurnTokens transaction.

    Burns tokens from a token account.
    """
    type: str = "burnTokens"
    amount: int  # Amount to burn

    model_config = {"populate_by_name": True}


class CreateLiteTokenAccountBody(BaseModel):
    """
    Body for CreateLiteTokenAccount transaction.

    Creates a lite token account (implicit creation).
    """
    type: str = "createLiteTokenAccount"
    # No additional fields - lite accounts are created implicitly

    model_config = {"populate_by_name": True}


class CreateKeyPageBody(BaseModel):
    """
    Body for CreateKeyPage transaction.

    Creates a new key page in a key book.
    """
    type: str = "createKeyPage"
    keys: List[KeySpecParams]  # Initial keys for the page

    model_config = {"populate_by_name": True}


class CreateKeyBookBody(BaseModel):
    """
    Body for CreateKeyBook transaction.

    Creates a new key book for an ADI.
    """
    type: str = "createKeyBook"
    url: str  # Key book URL to create
    public_key_hash: Optional[bytes] = Field(None, alias="publicKeyHash")  # Initial key hash
    authorities: Optional[List[str]] = None

    model_config = {"populate_by_name": True}


class AddCreditsBody(BaseModel):
    """
    Body for AddCredits transaction.

    Converts ACME tokens to credits.
    """
    type: str = "addCredits"
    recipient: str  # Key page URL to receive credits
    amount: int  # ACME amount (in smallest units)
    oracle: Optional[int] = None  # Optional oracle price override

    model_config = {"populate_by_name": True}


class BurnCreditsBody(BaseModel):
    """
    Body for BurnCredits transaction.

    Burns credits from a key page.
    """
    type: str = "burnCredits"
    amount: int  # Credits to burn

    model_config = {"populate_by_name": True}


class TransferCreditsBody(BaseModel):
    """
    Body for TransferCredits transaction.

    Transfers credits between key pages.
    """
    type: str = "transferCredits"
    to: List[CreditRecipient]  # Recipients with amounts

    model_config = {"populate_by_name": True}


class UpdateKeyPageBody(BaseModel):
    """
    Body for UpdateKeyPage transaction.

    Modifies a key page's keys or thresholds.
    """
    type: str = "updateKeyPage"
    operation: List[KeyPageOperation]  # Operations to perform

    model_config = {"populate_by_name": True}


class LockAccountBody(BaseModel):
    """
    Body for LockAccount transaction.

    Locks an account until a specific major block.
    """
    type: str = "lockAccount"
    height: int  # Major block height when account will be released

    model_config = {"populate_by_name": True}


class UpdateAccountAuthBody(BaseModel):
    """
    Body for UpdateAccountAuth transaction.

    Modifies an account's authorities.
    """
    type: str = "updateAccountAuth"
    operations: List[AccountAuthOperation]  # Operations to perform

    model_config = {"populate_by_name": True}


class UpdateKeyBody(BaseModel):
    """
    Body for UpdateKey transaction.

    Updates a key on a key page (single key rotation).
    """
    type: str = "updateKey"
    new_key_hash: bytes = Field(..., alias="newKeyHash")

    model_config = {"populate_by_name": True}


class NetworkMaintenanceBody(BaseModel):
    """
    Body for NetworkMaintenance transaction.

    Performs network maintenance operations (operator only).
    """
    type: str = "networkMaintenance"
    operations: List[NetworkMaintenanceOperation]

    model_config = {"populate_by_name": True}


class ActivateProtocolVersionBody(BaseModel):
    """
    Body for ActivateProtocolVersion transaction.

    Activates a new protocol version (operator only).
    """
    type: str = "activateProtocolVersion"
    version: ExecutorVersion

    model_config = {"populate_by_name": True}


class RemoteTransactionBody(BaseModel):
    """
    Body for RemoteTransaction transaction.

    References a transaction on another partition.
    """
    type: str = "remote"
    hash: Optional[bytes] = None  # Transaction hash

    model_config = {"populate_by_name": True}


# =============================================================================
# Synthetic Transaction Bodies
# =============================================================================

class SyntheticCreateIdentityBody(BaseModel):
    """
    Body for SyntheticCreateIdentity transaction.

    System-generated transaction for cross-partition identity creation.
    """
    type: str = "syntheticCreateIdentity"
    cause: str  # Cause transaction ID
    initiator: str  # Initiator account URL
    fee_refund: int = Field(default=0, alias="feeRefund")
    index: int = 0  # Synthetic transaction index
    accounts: List[Dict[str, Any]] = Field(default_factory=list)  # Accounts to create

    model_config = {"populate_by_name": True}


class SyntheticWriteDataBody(BaseModel):
    """
    Body for SyntheticWriteData transaction.

    System-generated transaction for cross-partition data writes.
    """
    type: str = "syntheticWriteData"
    cause: str  # Cause transaction ID
    initiator: str  # Initiator account URL
    fee_refund: int = Field(default=0, alias="feeRefund")
    index: int = 0
    entry: DataEntry  # Data entry to write

    model_config = {"populate_by_name": True}


class SyntheticDepositTokensBody(BaseModel):
    """
    Body for SyntheticDepositTokens transaction.

    System-generated transaction for cross-partition token deposits.
    """
    type: str = "syntheticDepositTokens"
    cause: str  # Cause transaction ID
    initiator: str  # Initiator account URL
    fee_refund: int = Field(default=0, alias="feeRefund")
    index: int = 0
    token: str  # Token URL
    amount: int  # Amount to deposit
    is_issuer: bool = Field(default=False, alias="isIssuer")
    is_refund: bool = Field(default=False, alias="isRefund")

    model_config = {"populate_by_name": True}


class SyntheticDepositCreditsBody(BaseModel):
    """
    Body for SyntheticDepositCredits transaction.

    System-generated transaction for cross-partition credit deposits.
    """
    type: str = "syntheticDepositCredits"
    cause: str  # Cause transaction ID
    initiator: str  # Initiator account URL
    fee_refund: int = Field(default=0, alias="feeRefund")
    index: int = 0
    amount: int  # Credits to deposit
    acme_refund_amount: Optional[int] = Field(None, alias="acmeRefundAmount")
    is_refund: bool = Field(default=False, alias="isRefund")

    model_config = {"populate_by_name": True}


class SyntheticBurnTokensBody(BaseModel):
    """
    Body for SyntheticBurnTokens transaction.

    System-generated transaction for cross-partition token burns.
    """
    type: str = "syntheticBurnTokens"
    cause: str  # Cause transaction ID
    initiator: str  # Initiator account URL
    fee_refund: int = Field(default=0, alias="feeRefund")
    index: int = 0
    amount: int  # Amount to burn
    is_refund: bool = Field(default=False, alias="isRefund")

    model_config = {"populate_by_name": True}


class SyntheticForwardTransactionBody(BaseModel):
    """
    Body for SyntheticForwardTransaction transaction.

    System-generated transaction for forwarding transactions between partitions.
    """
    type: str = "syntheticForwardTransaction"
    signatures: List[Dict[str, Any]] = Field(default_factory=list)
    transaction: Optional[Dict[str, Any]] = None

    model_config = {"populate_by_name": True}


# =============================================================================
# System Transaction Bodies
# =============================================================================

class SystemGenesisBody(BaseModel):
    """
    Body for SystemGenesis transaction.

    System-generated genesis transaction.
    """
    type: str = "systemGenesis"
    # No additional fields

    model_config = {"populate_by_name": True}


class BlockValidatorAnchorBody(BaseModel):
    """
    Body for BlockValidatorAnchor transaction.

    Anchors a block validator partition's state.
    """
    type: str = "blockValidatorAnchor"
    source: str  # Source partition URL
    major_block_index: int = Field(..., alias="majorBlockIndex")
    minor_block_index: int = Field(..., alias="minorBlockIndex")
    root_chain_index: int = Field(..., alias="rootChainIndex")
    root_chain_anchor: bytes = Field(..., alias="rootChainAnchor")
    state_tree_anchor: bytes = Field(..., alias="stateTreeAnchor")
    acme_burnt: int = Field(default=0, alias="acmeBurnt")

    model_config = {"populate_by_name": True}


class DirectoryAnchorBody(BaseModel):
    """
    Body for DirectoryAnchor transaction.

    Anchors the directory network's state.
    """
    type: str = "directoryAnchor"
    source: str  # Source partition URL
    major_block_index: int = Field(..., alias="majorBlockIndex")
    minor_block_index: int = Field(..., alias="minorBlockIndex")
    root_chain_index: int = Field(..., alias="rootChainIndex")
    root_chain_anchor: bytes = Field(..., alias="rootChainAnchor")
    state_tree_anchor: bytes = Field(..., alias="stateTreeAnchor")
    updates: List[Dict[str, Any]] = Field(default_factory=list)
    receipts: List[Dict[str, Any]] = Field(default_factory=list)
    make_major_block: int = Field(default=0, alias="makeMajorBlock")
    make_major_block_time: Optional[datetime] = Field(None, alias="makeMajorBlockTime")

    model_config = {"populate_by_name": True}


class SystemWriteDataBody(BaseModel):
    """
    Body for SystemWriteData transaction.

    System-generated data write transaction.
    """
    type: str = "systemWriteData"
    entry: DataEntry
    write_to_state: Optional[bool] = Field(None, alias="writeToState")

    model_config = {"populate_by_name": True}


# =============================================================================
# Full Transaction Types (Header + Body)
# =============================================================================

class SyntheticCreateIdentity(BaseModel):
    """Transaction: SyntheticCreateIdentity"""
    header: SyntheticCreateIdentityHeader
    body: SyntheticCreateIdentityBody


class SyntheticWriteData(BaseModel):
    """Transaction: SyntheticWriteData"""
    header: SyntheticWriteDataHeader
    body: SyntheticWriteDataBody


class SyntheticDepositTokens(BaseModel):
    """Transaction: SyntheticDepositTokens"""
    header: SyntheticDepositTokensHeader
    body: SyntheticDepositTokensBody


class SyntheticDepositCredits(BaseModel):
    """Transaction: SyntheticDepositCredits"""
    header: SyntheticDepositCreditsHeader
    body: SyntheticDepositCreditsBody


class SyntheticBurnTokens(BaseModel):
    """Transaction: SyntheticBurnTokens"""
    header: SyntheticBurnTokensHeader
    body: SyntheticBurnTokensBody


class SyntheticForwardTransaction(BaseModel):
    """Transaction: SyntheticForwardTransaction"""
    header: SyntheticForwardTransactionHeader
    body: SyntheticForwardTransactionBody


class SystemGenesis(BaseModel):
    """Transaction: SystemGenesis"""
    header: SystemGenesisHeader
    body: SystemGenesisBody


class BlockValidatorAnchor(BaseModel):
    """Transaction: BlockValidatorAnchor"""
    header: BlockValidatorAnchorHeader
    body: BlockValidatorAnchorBody


class DirectoryAnchor(BaseModel):
    """Transaction: DirectoryAnchor"""
    header: DirectoryAnchorHeader
    body: DirectoryAnchorBody


class SystemWriteData(BaseModel):
    """Transaction: SystemWriteData"""
    header: SystemWriteDataHeader
    body: SystemWriteDataBody


class CreateIdentity(BaseModel):
    """Transaction: CreateIdentity"""
    header: CreateIdentityHeader
    body: CreateIdentityBody


class CreateTokenAccount(BaseModel):
    """Transaction: CreateTokenAccount"""
    header: CreateTokenAccountHeader
    body: CreateTokenAccountBody


class SendTokens(BaseModel):
    """Transaction: SendTokens"""
    header: SendTokensHeader
    body: SendTokensBody


class CreateDataAccount(BaseModel):
    """Transaction: CreateDataAccount"""
    header: CreateDataAccountHeader
    body: CreateDataAccountBody


class WriteData(BaseModel):
    """Transaction: WriteData"""
    header: WriteDataHeader
    body: WriteDataBody


class WriteDataTo(BaseModel):
    """Transaction: WriteDataTo"""
    header: WriteDataToHeader
    body: WriteDataToBody


class AcmeFaucet(BaseModel):
    """Transaction: AcmeFaucet"""
    header: AcmeFaucetHeader
    body: AcmeFaucetBody


class CreateToken(BaseModel):
    """Transaction: CreateToken"""
    header: CreateTokenHeader
    body: CreateTokenBody


class IssueTokens(BaseModel):
    """Transaction: IssueTokens"""
    header: IssueTokensHeader
    body: IssueTokensBody


class BurnTokens(BaseModel):
    """Transaction: BurnTokens"""
    header: BurnTokensHeader
    body: BurnTokensBody


class CreateLiteTokenAccount(BaseModel):
    """Transaction: CreateLiteTokenAccount"""
    header: CreateLiteTokenAccountHeader
    body: CreateLiteTokenAccountBody


class CreateKeyPage(BaseModel):
    """Transaction: CreateKeyPage"""
    header: CreateKeyPageHeader
    body: CreateKeyPageBody


class CreateKeyBook(BaseModel):
    """Transaction: CreateKeyBook"""
    header: CreateKeyBookHeader
    body: CreateKeyBookBody


class AddCredits(BaseModel):
    """Transaction: AddCredits"""
    header: AddCreditsHeader
    body: AddCreditsBody


class BurnCredits(BaseModel):
    """Transaction: BurnCredits"""
    header: BurnCreditsHeader
    body: BurnCreditsBody


class TransferCredits(BaseModel):
    """Transaction: TransferCredits"""
    header: TransferCreditsHeader
    body: TransferCreditsBody


class UpdateKeyPage(BaseModel):
    """Transaction: UpdateKeyPage"""
    header: UpdateKeyPageHeader
    body: UpdateKeyPageBody


class LockAccount(BaseModel):
    """Transaction: LockAccount"""
    header: LockAccountHeader
    body: LockAccountBody


class UpdateAccountAuth(BaseModel):
    """Transaction: UpdateAccountAuth"""
    header: UpdateAccountAuthHeader
    body: UpdateAccountAuthBody


class UpdateKey(BaseModel):
    """Transaction: UpdateKey"""
    header: UpdateKeyHeader
    body: UpdateKeyBody


class NetworkMaintenance(BaseModel):
    """Transaction: NetworkMaintenance"""
    header: NetworkMaintenanceHeader
    body: NetworkMaintenanceBody


class ActivateProtocolVersion(BaseModel):
    """Transaction: ActivateProtocolVersion"""
    header: ActivateProtocolVersionHeader
    body: ActivateProtocolVersionBody


class RemoteTransaction(BaseModel):
    """Transaction: RemoteTransaction"""
    header: RemoteTransactionHeader
    body: RemoteTransactionBody


# =============================================================================
# Union Types
# =============================================================================

TxBody = Union[
    SyntheticCreateIdentityBody,
    SyntheticWriteDataBody,
    SyntheticDepositTokensBody,
    SyntheticDepositCreditsBody,
    SyntheticBurnTokensBody,
    SyntheticForwardTransactionBody,
    SystemGenesisBody,
    BlockValidatorAnchorBody,
    DirectoryAnchorBody,
    SystemWriteDataBody,
    CreateIdentityBody,
    CreateTokenAccountBody,
    SendTokensBody,
    CreateDataAccountBody,
    WriteDataBody,
    WriteDataToBody,
    AcmeFaucetBody,
    CreateTokenBody,
    IssueTokensBody,
    BurnTokensBody,
    CreateLiteTokenAccountBody,
    CreateKeyPageBody,
    CreateKeyBookBody,
    AddCreditsBody,
    BurnCreditsBody,
    TransferCreditsBody,
    UpdateKeyPageBody,
    LockAccountBody,
    UpdateAccountAuthBody,
    UpdateKeyBody,
    NetworkMaintenanceBody,
    ActivateProtocolVersionBody,
    RemoteTransactionBody,
]


# =============================================================================
# Transaction Type Registry
# =============================================================================

TRANSACTION_TYPE_TO_BODY = {
    TransactionType.CREATEIDENTITY: CreateIdentityBody,
    TransactionType.CREATETOKENACCOUNT: CreateTokenAccountBody,
    TransactionType.SENDTOKENS: SendTokensBody,
    TransactionType.CREATEDATAACCOUNT: CreateDataAccountBody,
    TransactionType.WRITEDATA: WriteDataBody,
    TransactionType.WRITEDATATO: WriteDataToBody,
    TransactionType.ACMEFAUCET: AcmeFaucetBody,
    TransactionType.CREATETOKEN: CreateTokenBody,
    TransactionType.ISSUETOKENS: IssueTokensBody,
    TransactionType.BURNTOKENS: BurnTokensBody,
    TransactionType.CREATELITETOKENACCOUNT: CreateLiteTokenAccountBody,
    TransactionType.CREATEKEYPAGE: CreateKeyPageBody,
    TransactionType.CREATEKEYBOOK: CreateKeyBookBody,
    TransactionType.ADDCREDITS: AddCreditsBody,
    TransactionType.BURNCREDITS: BurnCreditsBody,
    TransactionType.TRANSFERCREDITS: TransferCreditsBody,
    TransactionType.UPDATEKEYPAGE: UpdateKeyPageBody,
    TransactionType.LOCKACCOUNT: LockAccountBody,
    TransactionType.UPDATEACCOUNTAUTH: UpdateAccountAuthBody,
    TransactionType.UPDATEKEY: UpdateKeyBody,
    TransactionType.NETWORKMAINTENANCE: NetworkMaintenanceBody,
    TransactionType.ACTIVATEPROTOCOLVERSION: ActivateProtocolVersionBody,
    TransactionType.REMOTE: RemoteTransactionBody,
    TransactionType.SYNTHETICCREATEIDENTITY: SyntheticCreateIdentityBody,
    TransactionType.SYNTHETICWRITEDATA: SyntheticWriteDataBody,
    TransactionType.SYNTHETICDEPOSITTOKENS: SyntheticDepositTokensBody,
    TransactionType.SYNTHETICDEPOSITCREDITS: SyntheticDepositCreditsBody,
    TransactionType.SYNTHETICBURNTOKENS: SyntheticBurnTokensBody,
    TransactionType.SYNTHETICFORWARDTRANSACTION: SyntheticForwardTransactionBody,
    TransactionType.SYSTEMGENESIS: SystemGenesisBody,
    TransactionType.DIRECTORYANCHOR: DirectoryAnchorBody,
    TransactionType.BLOCKVALIDATORANCHOR: BlockValidatorAnchorBody,
    TransactionType.SYSTEMWRITEDATA: SystemWriteDataBody,
}


def get_body_class(tx_type: TransactionType) -> type:
    """
    Get the body class for a transaction type.

    Args:
        tx_type: Transaction type enum value

    Returns:
        The corresponding body class

    Raises:
        ValueError: If transaction type is unknown
    """
    body_class = TRANSACTION_TYPE_TO_BODY.get(tx_type)
    if body_class is None:
        raise ValueError(f"Unknown transaction type: {tx_type}")
    return body_class


# =============================================================================
# Legacy Compatibility Aliases (from types.py)
# =============================================================================

# These aliases maintain backward compatibility with tests and older code
# that reference the *Transaction naming convention

class CreateIdentityTransaction(CreateIdentityBody):
    """Legacy alias for CreateIdentityBody."""
    pass


class CreateTokenAccountTransaction(CreateTokenAccountBody):
    """Legacy alias for CreateTokenAccountBody."""
    pass


class SendTokensTransaction(SendTokensBody):
    """Legacy alias for SendTokensBody."""
    pass


class WriteDataTransaction(WriteDataBody):
    """Legacy alias for WriteDataBody."""
    pass


class AddCreditsTransaction(AddCreditsBody):
    """Legacy alias for AddCreditsBody."""
    pass


# =============================================================================
# Exports
# =============================================================================

__all__ = [
    # Supporting types
    "DataEntry",
    "AccumulateDataEntry",
    "DoubleHashDataEntry",
    "TokenRecipient",
    "CreditRecipient",
    "KeySpecParams",
    # Key page operations
    "AddKeyOperation",
    "RemoveKeyOperation",
    "UpdateKeyOperation",
    "SetThresholdKeyPageOperation",
    "SetRejectThresholdKeyPageOperation",
    "SetResponseThresholdKeyPageOperation",
    "UpdateAllowedKeyPageOperation",
    "KeyPageOperation",
    # Account auth operations
    "AddAccountAuthorityOperation",
    "RemoveAccountAuthorityOperation",
    "EnableAccountAuthOperation",
    "DisableAccountAuthOperation",
    "AccountAuthOperation",
    # Network maintenance operations
    "PendingTransactionGCOperation",
    "NetworkMaintenanceOperation",
    # Union type
    "TxBody",
    # Headers
    "TxHeaderBase",
    "SyntheticCreateIdentityHeader",
    "SyntheticWriteDataHeader",
    "SyntheticDepositTokensHeader",
    "SyntheticDepositCreditsHeader",
    "SyntheticBurnTokensHeader",
    "SyntheticForwardTransactionHeader",
    "SystemGenesisHeader",
    "BlockValidatorAnchorHeader",
    "DirectoryAnchorHeader",
    "SystemWriteDataHeader",
    "CreateIdentityHeader",
    "CreateTokenAccountHeader",
    "SendTokensHeader",
    "CreateDataAccountHeader",
    "WriteDataHeader",
    "WriteDataToHeader",
    "AcmeFaucetHeader",
    "CreateTokenHeader",
    "IssueTokensHeader",
    "BurnTokensHeader",
    "CreateLiteTokenAccountHeader",
    "CreateKeyPageHeader",
    "CreateKeyBookHeader",
    "AddCreditsHeader",
    "BurnCreditsHeader",
    "TransferCreditsHeader",
    "UpdateKeyPageHeader",
    "LockAccountHeader",
    "UpdateAccountAuthHeader",
    "UpdateKeyHeader",
    "NetworkMaintenanceHeader",
    "ActivateProtocolVersionHeader",
    "RemoteTransactionHeader",
    # Full transactions
    "SyntheticCreateIdentity",
    "SyntheticCreateIdentityBody",
    "SyntheticWriteData",
    "SyntheticWriteDataBody",
    "SyntheticDepositTokens",
    "SyntheticDepositTokensBody",
    "SyntheticDepositCredits",
    "SyntheticDepositCreditsBody",
    "SyntheticBurnTokens",
    "SyntheticBurnTokensBody",
    "SyntheticForwardTransaction",
    "SyntheticForwardTransactionBody",
    "SystemGenesis",
    "SystemGenesisBody",
    "BlockValidatorAnchor",
    "BlockValidatorAnchorBody",
    "DirectoryAnchor",
    "DirectoryAnchorBody",
    "SystemWriteData",
    "SystemWriteDataBody",
    "CreateIdentity",
    "CreateIdentityBody",
    "CreateTokenAccount",
    "CreateTokenAccountBody",
    "SendTokens",
    "SendTokensBody",
    "CreateDataAccount",
    "CreateDataAccountBody",
    "WriteData",
    "WriteDataBody",
    "WriteDataTo",
    "WriteDataToBody",
    "AcmeFaucet",
    "AcmeFaucetBody",
    "CreateToken",
    "CreateTokenBody",
    "IssueTokens",
    "IssueTokensBody",
    "BurnTokens",
    "BurnTokensBody",
    "CreateLiteTokenAccount",
    "CreateLiteTokenAccountBody",
    "CreateKeyPage",
    "CreateKeyPageBody",
    "CreateKeyBook",
    "CreateKeyBookBody",
    "AddCredits",
    "AddCreditsBody",
    "BurnCredits",
    "BurnCreditsBody",
    "TransferCredits",
    "TransferCreditsBody",
    "UpdateKeyPage",
    "UpdateKeyPageBody",
    "LockAccount",
    "LockAccountBody",
    "UpdateAccountAuth",
    "UpdateAccountAuthBody",
    "UpdateKey",
    "UpdateKeyBody",
    "NetworkMaintenance",
    "NetworkMaintenanceBody",
    "ActivateProtocolVersion",
    "ActivateProtocolVersionBody",
    "RemoteTransaction",
    "RemoteTransactionBody",
    # Registry
    "TRANSACTION_TYPE_TO_BODY",
    "get_body_class",
    # Legacy compatibility aliases
    "CreateIdentityTransaction",
    "CreateTokenAccountTransaction",
    "SendTokensTransaction",
    "WriteDataTransaction",
    "AddCreditsTransaction",
]
