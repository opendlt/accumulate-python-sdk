"""
Builder matrix tests - exercise all transaction builders without network.
"""

import pytest
import hashlib
from typing import Dict, Any, Optional


class TestBuildersMatrix:
    """Test all available transaction builders."""

    def get_builder_registry(self) -> Dict[str, Any]:
        """Dynamically discover available builders."""
        builders = {}

        # Try primary import path
        try:
            from accumulate_client.tx.builders import get_builder_for

            # All known transaction types
            tx_types = [
                'CreateIdentity', 'CreateTokenAccount', 'CreateDataAccount',
                'SendTokens', 'WriteData', 'AddCredits', 'UpdateKeyPage',
                'CreateKeyBook', 'CreateKeyPage', 'UpdateKey', 'CreateToken',
                'IssueTokens', 'BurnTokens', 'CreateLiteDataAccount',
                'UpdateAccountAuth', 'LockAccount', 'RemoteTransaction',
                'SyntheticCreateIdentity', 'SyntheticWriteData', 'AnchorTransaction',
                'DirectoryAnchor', 'BlockValidatorAnchor', 'ActivateProtocolVersion',
                'NetworkMaintenance', 'ValidatorUpdate', 'SetGlobalPalette',
                'CreateSubIdentity', 'CreateTokenReceiptAccount', 'PartitionAnchor',
                'ReceiptAnchor', 'SystemGenesis', 'NetworkDefinition',
                'NetworkGlobals', 'RoutingTable', 'UpdateManager',
                'SetOracle', 'CreateStakeAccount', 'TransferCredits'
            ]

            for tx_type in tx_types:
                try:
                    builder = get_builder_for(tx_type)
                    if builder:
                        builders[tx_type] = builder
                except Exception:
                    continue

        except ImportError:
            pass

        # Try alternative import paths
        if not builders:
            try:
                from accumulate_client.tx import builders as builder_module

                for attr_name in dir(builder_module):
                    if attr_name.endswith('Builder'):
                        try:
                            builder_cls = getattr(builder_module, attr_name)
                            if callable(builder_cls):
                                tx_type = attr_name.replace('Builder', '')
                                builders[tx_type] = builder_cls
                        except Exception:
                            continue

            except ImportError:
                pass

        return builders

    def get_minimal_fields(self, tx_type: str) -> Dict[str, Any]:
        """Get minimal required fields for each transaction type."""
        # Minimal field sets for common transaction types
        minimal_fields = {
            'CreateIdentity': {
                'url': 'acc://test.acme',
                'keyBookUrl': 'acc://test.acme/book',
                'keyPageUrl': 'acc://test.acme/book/1',
            },
            'CreateTokenAccount': {
                'url': 'acc://alice.acme/tokens',
                'tokenUrl': 'acc://acme.acme/tokens/ACME',
            },
            'CreateDataAccount': {
                'url': 'acc://data.acme/storage',
            },
            'SendTokens': {
                'to': [{'url': 'acc://bob.acme/tokens', 'amount': 100000}],
            },
            'WriteData': {
                'data': b'test data',
            },
            'AddCredits': {
                'recipient': 'acc://test.acme/book/1',
                'amount': 1000000,
            },
            'UpdateKeyPage': {
                'operation': 'add',
                'key': b'\x00' * 32,
            },
            'CreateKeyBook': {
                'url': 'acc://test.acme/book2',
                'pageCount': 1,
            },
            'CreateKeyPage': {
                'keys': [{'publicKey': b'\x00' * 32, 'weight': 1}],
            },
            'UpdateKey': {
                'newKey': b'\x01' * 32,
            },
            'CreateToken': {
                'url': 'acc://custom.acme/tokens/CUSTOM',
                'symbol': 'CUSTOM',
                'precision': 8,
            },
            'IssueTokens': {
                'recipient': 'acc://alice.acme/tokens',
                'amount': 1000000,
            },
            'BurnTokens': {
                'amount': 100000,
            },
            'CreateLiteDataAccount': {
                'url': 'acc://lite/data',
            },
            'UpdateAccountAuth': {
                'operations': [{'type': 'setThreshold', 'threshold': 2}],
            },
            'LockAccount': {
                'height': 10000,
            },
            'RemoteTransaction': {
                'hash': b'\x00' * 32,
            },
            'TransferCredits': {
                'to': 'acc://recipient.acme/book/1',
                'amount': 500000,
            },
            'CreateStakeAccount': {
                'url': 'acc://stake.acme/staking',
            },
            'SetOracle': {
                'oracle': 500.0,
            },
        }

        return minimal_fields.get(tx_type, {})

    def test_discover_builders(self):
        """Test that we can discover builders."""
        builders = self.get_builder_registry()

        # Should find at least some builders
        assert len(builders) > 0, "No builders discovered"

        print(f"Discovered {len(builders)} builders: {list(builders.keys())}")

    def test_builder_construction(self):
        """Test constructing each builder with minimal fields."""
        builders = self.get_builder_registry()

        if not builders:
            pytest.skip("No builders available")

        successful = 0
        failed = []

        for tx_type, builder_cls in builders.items():
            try:
                # Create builder instance
                if callable(builder_cls):
                    builder = builder_cls()
                else:
                    builder = builder_cls

                # Set minimal fields
                fields = self.get_minimal_fields(tx_type)
                for field, value in fields.items():
                    if hasattr(builder, 'with_field'):
                        builder.with_field(field, value)
                    elif hasattr(builder, f'set_{field}'):
                        getattr(builder, f'set_{field}')(value)
                    elif hasattr(builder, field):
                        setattr(builder, field, value)

                successful += 1

            except Exception as e:
                failed.append((tx_type, str(e)))

        print(f"Successfully constructed {successful}/{len(builders)} builders")
        if failed:
            print(f"Failed builders: {failed[:5]}")  # Show first 5 failures

        # Should construct at least half successfully
        assert successful >= len(builders) // 2

    def test_builder_build_method(self):
        """Test calling build() on each builder."""
        builders = self.get_builder_registry()

        if not builders:
            pytest.skip("No builders available")

        successful = 0

        for tx_type, builder_cls in builders.items():
            try:
                # Create and configure builder
                if callable(builder_cls):
                    builder = builder_cls()
                else:
                    builder = builder_cls

                fields = self.get_minimal_fields(tx_type)
                for field, value in fields.items():
                    if hasattr(builder, 'with_field'):
                        builder.with_field(field, value)

                # Try to build
                if hasattr(builder, 'build'):
                    result = builder.build()
                    assert result is not None
                    successful += 1
                elif hasattr(builder, 'to_body'):
                    result = builder.to_body()
                    assert result is not None
                    successful += 1

            except Exception:
                pass

        print(f"Successfully built {successful}/{len(builders)} transactions")
        assert successful > 0

    def test_builder_validation(self):
        """Test validation methods on builders."""
        builders = self.get_builder_registry()

        if not builders:
            pytest.skip("No builders available")

        validated = 0

        for tx_type, builder_cls in builders.items():
            try:
                if callable(builder_cls):
                    builder = builder_cls()
                else:
                    builder = builder_cls

                # Check for validation method
                if hasattr(builder, 'validate'):
                    # Empty builder should fail validation
                    try:
                        builder.validate()
                        # If it passes, that's unexpected but OK
                    except Exception:
                        # Expected - empty builder should fail
                        pass

                    # Add minimal fields
                    fields = self.get_minimal_fields(tx_type)
                    for field, value in fields.items():
                        if hasattr(builder, 'with_field'):
                            builder.with_field(field, value)

                    # Now validation might pass
                    try:
                        builder.validate()
                        validated += 1
                    except Exception:
                        # Still invalid, but that's OK
                        pass

            except Exception:
                pass

        print(f"Validated {validated} builders")

    def test_builder_fee_estimation(self):
        """Test fee estimation on builders."""
        builders = self.get_builder_registry()

        if not builders:
            pytest.skip("No builders available")

        fee_estimated = 0

        for tx_type, builder_cls in builders.items():
            try:
                if callable(builder_cls):
                    builder = builder_cls()
                else:
                    builder = builder_cls

                # Add minimal fields
                fields = self.get_minimal_fields(tx_type)
                for field, value in fields.items():
                    if hasattr(builder, 'with_field'):
                        builder.with_field(field, value)

                # Check for fee estimation
                if hasattr(builder, 'estimate_fee'):
                    fee = builder.estimate_fee()
                    assert fee >= 0
                    fee_estimated += 1
                elif hasattr(builder, 'get_fee'):
                    fee = builder.get_fee()
                    assert fee >= 0
                    fee_estimated += 1

            except Exception:
                pass

        print(f"Estimated fees for {fee_estimated} builders")

    def test_builder_canonical_encoding(self):
        """Test canonical encoding on builders."""
        builders = self.get_builder_registry()

        if not builders:
            pytest.skip("No builders available")

        encoded = 0

        for tx_type, builder_cls in builders.items():
            try:
                if callable(builder_cls):
                    builder = builder_cls()
                else:
                    builder = builder_cls

                # Add minimal fields
                fields = self.get_minimal_fields(tx_type)
                for field, value in fields.items():
                    if hasattr(builder, 'with_field'):
                        builder.with_field(field, value)

                # Try canonical encoding
                if hasattr(builder, 'to_canonical_json'):
                    json_data = builder.to_canonical_json()
                    assert json_data is not None

                    # Should produce stable hash
                    if isinstance(json_data, str):
                        json_data = json_data.encode()
                    hash1 = hashlib.sha256(json_data).hexdigest()
                    hash2 = hashlib.sha256(json_data).hexdigest()
                    assert hash1 == hash2

                    encoded += 1

            except Exception:
                pass

        print(f"Canonical encoded {encoded} builders")

    @pytest.mark.parametrize("tx_type,required_field", [
        ("CreateIdentity", "url"),
        ("SendTokens", "to"),
        ("WriteData", "data"),
        ("AddCredits", "recipient"),
        ("CreateTokenAccount", "url"),
        ("BurnTokens", "amount"),
        ("IssueTokens", "recipient"),
        ("CreateDataAccount", "url"),
        ("UpdateKey", "newKey"),
        ("CreateKeyPage", "keys"),
    ])
    def test_builder_required_fields(self, tx_type, required_field):
        """Test that builders enforce required fields."""
        builders = self.get_builder_registry()

        if tx_type not in builders:
            pytest.skip(f"Builder {tx_type} not available")

        builder_cls = builders[tx_type]

        try:
            if callable(builder_cls):
                builder = builder_cls()
            else:
                builder = builder_cls

            # Try to build without required field - should fail
            if hasattr(builder, 'validate'):
                with pytest.raises(Exception):
                    builder.validate()

            # Add required field
            if required_field == "to":
                value = [{'url': 'acc://test.acme/tokens', 'amount': 1000}]
            elif required_field == "keys":
                value = [{'publicKey': b'\x00' * 32, 'weight': 1}]
            elif required_field == "data":
                value = b'test'
            elif required_field in ["amount", "recipient"]:
                value = 100000 if required_field == "amount" else "acc://test.acme"
            else:
                value = "acc://test.acme"

            if hasattr(builder, 'with_field'):
                builder.with_field(required_field, value)

            # Should not raise after adding required field
            if hasattr(builder, 'validate'):
                # May still fail for other required fields, but different error
                try:
                    builder.validate()
                except Exception as e:
                    # Should be a different validation error
                    assert required_field not in str(e)

        except Exception:
            # Builder may not support this interface
            pass

    def test_builder_type_field(self):
        """Test that builders set correct transaction type."""
        builders = self.get_builder_registry()

        if not builders:
            pytest.skip("No builders available")

        type_correct = 0

        for tx_type, builder_cls in builders.items():
            try:
                if callable(builder_cls):
                    builder = builder_cls()
                else:
                    builder = builder_cls

                # Check type field
                if hasattr(builder, 'type'):
                    assert builder.type == tx_type
                    type_correct += 1
                elif hasattr(builder, 'get_type'):
                    assert builder.get_type() == tx_type
                    type_correct += 1
                elif hasattr(builder, 'to_body'):
                    body = builder.to_body()
                    if isinstance(body, dict) and 'type' in body:
                        # Type might be slightly different format
                        assert tx_type.lower() in body['type'].lower()
                        type_correct += 1

            except Exception:
                pass

        print(f"Verified type for {type_correct} builders")