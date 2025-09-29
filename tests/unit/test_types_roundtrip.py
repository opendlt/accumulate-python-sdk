#!/usr/bin/env python3

"""Unit tests for types.py imports and basic type functionality"""

import pytest
from datetime import datetime
from enum import Enum
from typing import Optional, List, Dict, Any, Union
from dataclasses import dataclass, field
import base64

# Import all modules from types.py to ensure they're covered
import accumulate_client.types


class TestTypesImports:
    """Test that all imports in types.py are usable"""

    def test_base64_import(self):
        """Test base64 functionality"""
        # Test that base64 import works
        test_data = b"Hello, World!"
        encoded = base64.b64encode(test_data)
        decoded = base64.b64decode(encoded)
        assert decoded == test_data

    def test_datetime_import(self):
        """Test datetime functionality"""
        # Test that datetime import works
        now = datetime.now()
        assert isinstance(now, datetime)

        # Test datetime creation
        specific_time = datetime(2023, 12, 25, 10, 30, 45)
        assert specific_time.year == 2023
        assert specific_time.month == 12
        assert specific_time.day == 25

    def test_enum_import(self):
        """Test enum functionality"""
        # Test that Enum import works
        class TestEnum(Enum):
            VALUE1 = "test1"
            VALUE2 = "test2"

        assert TestEnum.VALUE1.value == "test1"
        assert TestEnum.VALUE2.value == "test2"
        assert len(TestEnum) == 2

    def test_typing_imports(self):
        """Test typing module functionality"""
        # Test Optional
        def process_optional(value: Optional[str] = None) -> str:
            return value or "default"

        assert process_optional() == "default"
        assert process_optional("test") == "test"

        # Test List
        test_list: List[int] = [1, 2, 3]
        assert len(test_list) == 3
        assert all(isinstance(x, int) for x in test_list)

        # Test Dict
        test_dict: Dict[str, Any] = {"key": "value", "number": 42}
        assert test_dict["key"] == "value"
        assert test_dict["number"] == 42

        # Test Union
        def process_union(value: Union[str, int]) -> str:
            return str(value)

        assert process_union("test") == "test"
        assert process_union(42) == "42"

    def test_dataclass_functionality(self):
        """Test dataclass functionality"""
        # Test dataclass creation
        @dataclass
        class TestDataClass:
            name: str
            value: int = field(default=0)
            optional_field: Optional[str] = field(default=None)

        # Test basic dataclass
        instance = TestDataClass("test")
        assert instance.name == "test"
        assert instance.value == 0
        assert instance.optional_field is None

        # Test dataclass with all fields
        instance2 = TestDataClass("test2", 42, "optional")
        assert instance2.name == "test2"
        assert instance2.value == 42
        assert instance2.optional_field == "optional"

    def test_complex_type_combinations(self):
        """Test complex combinations of imported types"""
        # Test complex dataclass with various types
        @dataclass
        class ComplexDataClass:
            timestamp: datetime = field(default_factory=datetime.now)
            data_list: List[Dict[str, Any]] = field(default_factory=list)
            encoded_data: Optional[str] = field(default=None)
            metadata: Dict[str, Union[str, int, bool]] = field(default_factory=dict)

        instance = ComplexDataClass()
        assert isinstance(instance.timestamp, datetime)
        assert isinstance(instance.data_list, list)
        assert instance.encoded_data is None
        assert isinstance(instance.metadata, dict)

        # Test setting values
        instance.data_list.append({"key": "value"})
        instance.encoded_data = base64.b64encode(b"test").decode()
        instance.metadata["string"] = "value"
        instance.metadata["number"] = 42
        instance.metadata["boolean"] = True

        assert len(instance.data_list) == 1
        assert instance.data_list[0]["key"] == "value"
        assert base64.b64decode(instance.encoded_data) == b"test"
        assert instance.metadata["string"] == "value"
        assert instance.metadata["number"] == 42
        assert instance.metadata["boolean"] is True

    def test_enum_with_dataclass(self):
        """Test enum combined with dataclass"""
        class Status(Enum):
            PENDING = "pending"
            ACTIVE = "active"
            INACTIVE = "inactive"

        @dataclass
        class Record:
            id: str
            status: Status
            created_at: datetime = field(default_factory=datetime.now)
            tags: List[str] = field(default_factory=list)

        record = Record("test-id", Status.PENDING)
        assert record.id == "test-id"
        assert record.status == Status.PENDING
        assert isinstance(record.created_at, datetime)
        assert isinstance(record.tags, list)

    def test_base64_roundtrip(self):
        """Test base64 encode/decode roundtrip"""
        test_cases = [
            b"",
            b"a",
            b"hello",
            b"Hello, World!",
            b"This is a test with special chars: !@#$%^&*()",
            bytes(range(256))  # All possible byte values
        ]

        for original in test_cases:
            encoded = base64.b64encode(original)
            decoded = base64.b64decode(encoded)
            assert decoded == original

    def test_datetime_serialization(self):
        """Test datetime serialization patterns common in APIs"""
        # Test ISO format
        dt = datetime(2023, 12, 25, 10, 30, 45, 123456)
        iso_string = dt.isoformat()
        parsed_dt = datetime.fromisoformat(iso_string)
        assert parsed_dt == dt

        # Test timestamp
        timestamp = dt.timestamp()
        from_timestamp = datetime.fromtimestamp(timestamp)
        # Note: microseconds might be lost in timestamp conversion
        assert abs((from_timestamp - dt).total_seconds()) < 1

    def test_typing_annotations(self):
        """Test that typing annotations work correctly"""
        # Test function with complex annotations
        def process_data(
            items: List[Dict[str, Any]],
            filter_func: Optional[callable] = None,
            metadata: Dict[str, Union[str, int]] = None
        ) -> Dict[str, Any]:
            if metadata is None:
                metadata = {}

            processed = items.copy() if filter_func is None else [
                item for item in items if filter_func(item)
            ]

            return {
                "items": processed,
                "count": len(processed),
                "metadata": metadata
            }

        test_items = [
            {"id": 1, "name": "item1"},
            {"id": 2, "name": "item2"},
            {"id": 3, "name": "item3"}
        ]

        result = process_data(test_items)
        assert result["count"] == 3
        assert len(result["items"]) == 3

        # With filter
        result_filtered = process_data(
            test_items,
            lambda x: x["id"] > 1,
            {"source": "test", "version": 1}
        )
        assert result_filtered["count"] == 2
        assert result_filtered["metadata"]["source"] == "test"
        assert result_filtered["metadata"]["version"] == 1

    def test_types_module_import(self):
        """Test that types module imports correctly"""
        # Test that we can import the types module
        import accumulate_client.types as types_module

        # The module should exist and have the expected docstring
        assert hasattr(types_module, '__doc__')
        assert "Type definitions for Accumulate API" in types_module.__doc__

    def test_all_imports_accessible(self):
        """Test that all imports from types.py are accessible"""
        # Import the module and verify all expected attributes exist
        import accumulate_client.types as types_module

        # These should all be accessible after import
        import base64 as b64
        from datetime import datetime as dt
        from enum import Enum as En
        from typing import Optional as Opt, List as L, Dict as D, Any as A, Union as U
        from dataclasses import dataclass as dc, field as f

        # Verify they are the same objects
        assert b64 is base64
        assert dt is datetime
        assert En is Enum
        assert Opt is Optional
        assert L is List
        assert D is Dict
        assert A is Any
        assert U is Union
        assert dc is dataclass
        assert f is field