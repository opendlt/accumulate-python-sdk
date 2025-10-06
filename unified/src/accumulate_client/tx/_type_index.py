"""
Type registry and lookup helpers for generated Accumulate types.

This file is auto-generated. Do not edit manually.
Use gen_types_from_manifest.py to regenerate.
"""

from .types_generated import (
    AcmeFaucet,
    AddCredits,
    BlockValidatorAnchor,
    BurnCredits,
    BurnTokens,
    CreateDataAccount,
    CreateIdentity,
    CreateKeyBook,
    CreateKeyPage,
    CreateLiteTokenAccount,
    CreateToken,
    CreateTokenAccount,
    DirectoryAnchor,
    IssueTokens,
    LockAccount,
    NetworkMaintenance,
    RemoteTransaction,
    SendTokens,
    SyntheticBurnTokens,
    SyntheticCreateIdentity,
    SyntheticDepositCredits,
    SyntheticDepositTokens,
    SyntheticForwardTransaction,
    SyntheticWriteData,
    SystemGenesis,
    SystemWriteData,
    TransactionType,
    TransferCredits,
    UpdateAccountAuth,
    UpdateKey,
    UpdateKeyPage,
    Url,
    WriteData,
    WriteDataTo
)

# Transaction model registry
TX_MODEL_REGISTRY = {
    "AcmeFaucet": AcmeFaucet,
    "AddCredits": AddCredits,
    "BlockValidatorAnchor": BlockValidatorAnchor,
    "BurnCredits": BurnCredits,
    "BurnTokens": BurnTokens,
    "CreateDataAccount": CreateDataAccount,
    "CreateIdentity": CreateIdentity,
    "CreateKeyBook": CreateKeyBook,
    "CreateKeyPage": CreateKeyPage,
    "CreateLiteTokenAccount": CreateLiteTokenAccount,
    "CreateToken": CreateToken,
    "CreateTokenAccount": CreateTokenAccount,
    "DirectoryAnchor": DirectoryAnchor,
    "IssueTokens": IssueTokens,
    "LockAccount": LockAccount,
    "NetworkMaintenance": NetworkMaintenance,
    "RemoteTransaction": RemoteTransaction,
    "SendTokens": SendTokens,
    "SyntheticBurnTokens": SyntheticBurnTokens,
    "SyntheticCreateIdentity": SyntheticCreateIdentity,
    "SyntheticDepositCredits": SyntheticDepositCredits,
    "SyntheticDepositTokens": SyntheticDepositTokens,
    "SyntheticForwardTransaction": SyntheticForwardTransaction,
    "SyntheticWriteData": SyntheticWriteData,
    "SystemGenesis": SystemGenesis,
    "SystemWriteData": SystemWriteData,
    "TransferCredits": TransferCredits,
    "UpdateAccountAuth": UpdateAccountAuth,
    "UpdateKey": UpdateKey,
    "UpdateKeyPage": UpdateKeyPage,
    "WriteData": WriteData,
    "WriteDataTo": WriteDataTo,
}


def lookup_tx_model(tx_type: str):
    """Look up transaction model class by name."""
    return TX_MODEL_REGISTRY.get(tx_type)


# All type registry for general lookup
ALL_TYPES_REGISTRY = {
    "AcmeFaucet": AcmeFaucet,
    "AddCredits": AddCredits,
    "BlockValidatorAnchor": BlockValidatorAnchor,
    "BurnCredits": BurnCredits,
    "BurnTokens": BurnTokens,
    "CreateDataAccount": CreateDataAccount,
    "CreateIdentity": CreateIdentity,
    "CreateKeyBook": CreateKeyBook,
    "CreateKeyPage": CreateKeyPage,
    "CreateLiteTokenAccount": CreateLiteTokenAccount,
    "CreateToken": CreateToken,
    "CreateTokenAccount": CreateTokenAccount,
    "DirectoryAnchor": DirectoryAnchor,
    "IssueTokens": IssueTokens,
    "LockAccount": LockAccount,
    "NetworkMaintenance": NetworkMaintenance,
    "RemoteTransaction": RemoteTransaction,
    "SendTokens": SendTokens,
    "SyntheticBurnTokens": SyntheticBurnTokens,
    "SyntheticCreateIdentity": SyntheticCreateIdentity,
    "SyntheticDepositCredits": SyntheticDepositCredits,
    "SyntheticDepositTokens": SyntheticDepositTokens,
    "SyntheticForwardTransaction": SyntheticForwardTransaction,
    "SyntheticWriteData": SyntheticWriteData,
    "SystemGenesis": SystemGenesis,
    "SystemWriteData": SystemWriteData,
    "TransactionType": TransactionType,
    "TransferCredits": TransferCredits,
    "UpdateAccountAuth": UpdateAccountAuth,
    "UpdateKey": UpdateKey,
    "UpdateKeyPage": UpdateKeyPage,
    "Url": Url,
    "WriteData": WriteData,
    "WriteDataTo": WriteDataTo,
}


def lookup_type(type_name: str):
    """Look up any type by name."""
    return ALL_TYPES_REGISTRY.get(type_name)
