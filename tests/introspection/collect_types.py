#!/usr/bin/env python3

"""
Type Collection and Introspection

Discovers all protocol types, classes, and enums in the accumulate_client package
and generates a comprehensive manifest for coverage validation.
"""

import inspect
import json
import os
import sys
from dataclasses import fields as dataclass_fields
from dataclasses import is_dataclass
from enum import Enum
from typing import Any, Dict, List


def collect_types_from_module(module) -> Dict[str, Dict[str, Any]]:
    """Extract all serializable types from a module"""
    types_info = {}

    for name, obj in inspect.getmembers(module):
        if name.startswith("_"):
            continue

        type_info = analyze_type(name, obj)
        if type_info:
            types_info[name] = type_info

    return types_info


def analyze_type(name: str, obj: Any) -> Dict[str, Any]:
    """Analyze a type to extract its serialization-relevant properties"""

    # Skip non-types
    if not inspect.isclass(obj):
        return None

    type_info = {
        "name": name,
        "module": getattr(obj, "__module__", "unknown"),
        "type_category": None,
        "fields": [],
        "methods": [],
        "is_serializable": False,
    }

    # Analyze dataclasses
    if is_dataclass(obj):
        type_info["type_category"] = "dataclass"
        type_info["is_serializable"] = True

        # Get dataclass fields
        try:
            fields = dataclass_fields(obj)
            for field in fields:
                field_info = {
                    "name": field.name,
                    "type": str(field.type),
                    "required": field.default == field.default_factory == None,
                    "default": str(field.default)
                    if field.default is not field.default_factory
                    else None,
                }
                type_info["fields"].append(field_info)
        except Exception as e:
            type_info["fields_error"] = str(e)

    # Analyze enums
    elif issubclass(obj, Enum):
        type_info["type_category"] = "enum"
        type_info["is_serializable"] = True

        # Get enum values
        try:
            for enum_member in obj:
                field_info = {
                    "name": enum_member.name,
                    "value": enum_member.value,
                    "type": "enum_member",
                }
                type_info["fields"].append(field_info)
        except Exception as e:
            type_info["fields_error"] = str(e)

    # Analyze regular classes
    else:
        type_info["type_category"] = "class"

        # Check if class has serialization methods
        has_encode = hasattr(obj, "encode") or any(
            hasattr(obj, m) for m in ["marshal_binary", "to_dict", "to_json"]
        )
        has_decode = (
            hasattr(obj, "decode") or hasattr(obj, "from_dict") or hasattr(obj, "from_json")
        )

        type_info["is_serializable"] = has_encode or has_decode

        # Get public methods that might be related to serialization
        serialization_methods = []
        for method_name in dir(obj):
            if not method_name.startswith("_"):
                method = getattr(obj, method_name, None)
                if callable(method):
                    # Check for serialization-related method names
                    if any(
                        keyword in method_name.lower()
                        for keyword in [
                            "encode",
                            "decode",
                            "marshal",
                            "unmarshal",
                            "serialize",
                            "deserialize",
                            "to_dict",
                            "from_dict",
                            "to_json",
                            "from_json",
                            "to_bytes",
                            "from_bytes",
                        ]
                    ):
                        try:
                            sig = inspect.signature(method)
                            method_info = {
                                "name": method_name,
                                "signature": str(sig),
                                "is_classmethod": isinstance(
                                    inspect.getattr_static(obj, method_name), classmethod
                                ),
                                "is_staticmethod": isinstance(
                                    inspect.getattr_static(obj, method_name), staticmethod
                                ),
                            }
                            serialization_methods.append(method_info)
                        except Exception:
                            serialization_methods.append(
                                {"name": method_name, "signature": "unknown"}
                            )

        type_info["methods"] = serialization_methods

        # Try to get type hints for __init__ to understand fields
        try:
            init_method = getattr(obj, "__init__", None)
            if init_method:
                sig = inspect.signature(init_method)
                for param_name, param in sig.parameters.items():
                    if param_name != "self":
                        field_info = {
                            "name": param_name,
                            "type": str(param.annotation)
                            if param.annotation != param.empty
                            else "Any",
                            "required": param.default == param.empty,
                            "default": str(param.default) if param.default != param.empty else None,
                        }
                        type_info["fields"].append(field_info)
        except Exception as e:
            type_info["init_analysis_error"] = str(e)

    return type_info


def discover_all_modules(package_path: str) -> List[str]:
    """Discover all Python modules in a package"""
    modules = []

    for root, dirs, files in os.walk(package_path):
        # Skip test directories
        dirs[:] = [d for d in dirs if not d.startswith("test") and d != "__pycache__"]

        for file in files:
            if file.endswith(".py") and not file.startswith("_"):
                module_path = os.path.join(root, file)
                rel_path = os.path.relpath(module_path, package_path)
                module_name = rel_path.replace(os.sep, ".").rstrip(".py")
                modules.append(module_name)

    return modules


def load_module_safely(module_name: str, package_path: str):
    """Safely load a module by name"""
    try:
        # Try importing from the package
        full_module_name = f"accumulate_client.{module_name}"
        module = __import__(full_module_name, fromlist=[""])
        return module
    except ImportError as e:
        print(f"Warning: Could not import {full_module_name}: {e}")
        return None


def main():
    """Main type collection function"""

    # Get the source directory
    script_dir = os.path.dirname(os.path.abspath(__file__))
    repo_root = os.path.join(script_dir, "..", "..")
    src_dir = os.path.join(repo_root, "src")
    accumulate_client_dir = os.path.join(src_dir, "accumulate_client")

    # Add src to Python path
    sys.path.insert(0, src_dir)

    manifest = {
        "generated_at": "2025-09-29T12:00:00Z",
        "package": "accumulate_client",
        "types": {},
        "summary": {
            "total_types": 0,
            "serializable_types": 0,
            "dataclasses": 0,
            "enums": 0,
            "classes": 0,
        },
    }

    # Discover modules
    modules = discover_all_modules(accumulate_client_dir)
    print(f"Discovered modules: {modules}")

    # Collect types from each module
    for module_name in modules:
        print(f"Analyzing module: {module_name}")

        module = load_module_safely(module_name, accumulate_client_dir)
        if module:
            module_types = collect_types_from_module(module)

            for type_name, type_info in module_types.items():
                full_name = f"{module_name}.{type_name}"
                manifest["types"][full_name] = type_info

                # Update summary
                manifest["summary"]["total_types"] += 1
                if type_info["is_serializable"]:
                    manifest["summary"]["serializable_types"] += 1

                if type_info["type_category"] == "dataclass":
                    manifest["summary"]["dataclasses"] += 1
                elif type_info["type_category"] == "enum":
                    manifest["summary"]["enums"] += 1
                elif type_info["type_category"] == "class":
                    manifest["summary"]["classes"] += 1

    # Also analyze the main accumulate_client module
    try:
        import accumulate_client

        main_module_types = collect_types_from_module(accumulate_client)
        for type_name, type_info in main_module_types.items():
            full_name = f"accumulate_client.{type_name}"
            if full_name not in manifest["types"]:  # Avoid duplicates
                manifest["types"][full_name] = type_info
                manifest["summary"]["total_types"] += 1
                if type_info["is_serializable"]:
                    manifest["summary"]["serializable_types"] += 1
    except ImportError as e:
        print(f"Warning: Could not import main accumulate_client module: {e}")

    # Generate report
    print("\nType Collection Summary:")
    print(f"  Total types found: {manifest['summary']['total_types']}")
    print(f"  Serializable types: {manifest['summary']['serializable_types']}")
    print(f"  Dataclasses: {manifest['summary']['dataclasses']}")
    print(f"  Enums: {manifest['summary']['enums']}")
    print(f"  Classes: {manifest['summary']['classes']}")

    print("\nSerializable types found:")
    for type_name, type_info in manifest["types"].items():
        if type_info["is_serializable"]:
            category = type_info["type_category"]
            fields_count = len(type_info["fields"])
            methods_count = len(type_info["methods"])
            print(
                f"  - {type_name} ({category}): {fields_count} fields, {methods_count} serialization methods"
            )

    # Output JSON manifest
    manifest_path = os.path.join(script_dir, "type_manifest.json")
    with open(manifest_path, "w") as f:
        json.dump(manifest, f, indent=2, sort_keys=True)

    print(f"\nManifest written to: {manifest_path}")
    return manifest


if __name__ == "__main__":
    main()
