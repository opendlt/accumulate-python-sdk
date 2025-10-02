"""
System transaction builders for Accumulate Protocol.

Provides builders for system-level transactions with ergonomic interfaces
and exact parity to the Go implementation.

Reference: C:/Accumulate_Stuff/accumulate/protocol/system.go
"""

from __future__ import annotations
from typing import Union, Dict, Any, List

from ...runtime.url import AccountUrl
from ...transactions import (
    NetworkMaintenanceBody, SystemGenesisBody, SystemWriteDataBody,
    DirectoryAnchorBody, BlockValidatorAnchorBody
)
from .base import BaseTxBuilder


class NetworkMaintenanceBuilder(BaseTxBuilder[NetworkMaintenanceBody]):
    """Builder for NetworkMaintenance transactions."""

    @property
    def tx_type(self) -> str:
        return "NetworkMaintenance"

    @property
    def body_cls(self):
        return NetworkMaintenanceBody

    def operation(self, operation: str) -> NetworkMaintenanceBuilder:
        """Set the maintenance operation type."""
        return self.with_field('operation', operation)

    def target(self, target_url: Union[str, AccountUrl]) -> NetworkMaintenanceBuilder:
        """Set the target for the maintenance operation."""
        return self.with_field('target', target_url)


class SystemGenesisBuilder(BaseTxBuilder[SystemGenesisBody]):
    """Builder for SystemGenesis transactions."""

    @property
    def tx_type(self) -> str:
        return "SystemGenesis"

    @property
    def body_cls(self):
        return SystemGenesisBody

    def network_name(self, name: str) -> SystemGenesisBuilder:
        """Set the network name."""
        return self.with_field('networkName', name)

    def version(self, version: str) -> SystemGenesisBuilder:
        """Set the protocol version."""
        return self.with_field('version', version)

    def globals(self, globals_dict: Dict[str, Any]) -> SystemGenesisBuilder:
        """Set the global network parameters."""
        return self.with_field('globals', globals_dict)


class SystemWriteDataBuilder(BaseTxBuilder[SystemWriteDataBody]):
    """Builder for SystemWriteData transactions."""

    @property
    def tx_type(self) -> str:
        return "SystemWriteData"

    @property
    def body_cls(self):
        return SystemWriteDataBody

    def data(self, data: bytes) -> SystemWriteDataBuilder:
        """Set the system data to write."""
        return self.with_field('data', data)

    def write_to_state(self, state: bool = True) -> SystemWriteDataBuilder:
        """Set whether to write to state."""
        return self.with_field('writeToState', state)


class DirectoryAnchorBuilder(BaseTxBuilder[DirectoryAnchorBody]):
    """Builder for DirectoryAnchor transactions."""

    @property
    def tx_type(self) -> str:
        return "DirectoryAnchor"

    @property
    def body_cls(self):
        return DirectoryAnchorBody

    def source(self, source_url: Union[str, AccountUrl]) -> DirectoryAnchorBuilder:
        """Set the source directory URL."""
        return self.with_field('source', source_url)

    def root_chain_anchor(self, anchor: bytes) -> DirectoryAnchorBuilder:
        """Set the root chain anchor."""
        return self.with_field('rootChainAnchor', anchor)

    def state_tree_anchor(self, anchor: bytes) -> DirectoryAnchorBuilder:
        """Set the state tree anchor."""
        return self.with_field('stateTreeAnchor', anchor)


class BlockValidatorAnchorBuilder(BaseTxBuilder[BlockValidatorAnchorBody]):
    """Builder for BlockValidatorAnchor transactions."""

    @property
    def tx_type(self) -> str:
        return "BlockValidatorAnchor"

    @property
    def body_cls(self):
        return BlockValidatorAnchorBody

    def source(self, source_url: Union[str, AccountUrl]) -> BlockValidatorAnchorBuilder:
        """Set the source validator URL."""
        return self.with_field('source', source_url)

    def root_chain_anchor(self, anchor: bytes) -> BlockValidatorAnchorBuilder:
        """Set the root chain anchor."""
        return self.with_field('rootChainAnchor', anchor)

    def state_tree_anchor(self, anchor: bytes) -> BlockValidatorAnchorBuilder:
        """Set the state tree anchor."""
        return self.with_field('stateTreeAnchor', anchor)

    def minor_blocks(self, blocks: List[bytes]) -> BlockValidatorAnchorBuilder:
        """Set the minor block anchors."""
        return self.with_field('minorBlocks', blocks)


__all__ = [
    "NetworkMaintenanceBuilder",
    "SystemGenesisBuilder",
    "SystemWriteDataBuilder",
    "DirectoryAnchorBuilder",
    "BlockValidatorAnchorBuilder"
]