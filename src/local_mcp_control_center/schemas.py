"""Small dependency-free JSON-schema validator for the MCP boundary.

The MCP SDK validates the generated function models for normal protocol calls,
but the broker is also called by the GUI, CLI, and tests.  Keeping a compact
validator here makes the broker the authoritative input-validation boundary as
well as the authoritative policy boundary.
"""

from __future__ import annotations

from typing import Any


def _type_matches(value: Any, expected: str) -> bool:
    if expected == "object":
        return isinstance(value, dict)
    if expected == "array":
        return isinstance(value, list)
    if expected == "string":
        return isinstance(value, str)
    if expected == "integer":
        return isinstance(value, int) and not isinstance(value, bool)
    if expected == "number":
        return isinstance(value, (int, float)) and not isinstance(value, bool)
    if expected == "boolean":
        return isinstance(value, bool)
    if expected == "null":
        return value is None
    return True


def validate_schema(schema: dict[str, Any], value: Any, *, path: str = "$", root: bool = True) -> None:
    """Validate the supported JSON Schema subset or raise ``ValueError``.

    The supported subset deliberately covers the schemas used by this project:
    object/array/scalar types, required properties, enums, and bounded values.
    It is not intended to become a general schema interpreter.
    """

    if not isinstance(schema, dict):
        raise ValueError(f"{path}: schema must be an object")

    if "oneOf" in schema:
        alternatives = schema.get("oneOf")
        if not isinstance(alternatives, list):
            raise ValueError(f"{path}: oneOf must be a list")
        matches = 0
        for alternative in alternatives:
            try:
                validate_schema(alternative, value, path=path, root=root)
            except ValueError:
                continue
            matches += 1
        if matches != 1:
            raise ValueError(f"{path}: exactly one schema alternative must match")

    if "not" in schema:
        try:
            validate_schema(schema["not"], value, path=path, root=root)
        except ValueError:
            pass
        else:
            raise ValueError(f"{path}: value matches a forbidden schema")

    expected_type = schema.get("type")
    if isinstance(expected_type, list):
        if not any(_type_matches(value, candidate) for candidate in expected_type):
            raise ValueError(f"{path}: expected one of {expected_type}")
    elif isinstance(expected_type, str) and not _type_matches(value, expected_type):
        raise ValueError(f"{path}: expected {expected_type}")

    if "enum" in schema and value not in schema["enum"]:
        raise ValueError(f"{path}: value is not one of the allowed options")

    if isinstance(value, str):
        if "minLength" in schema and len(value) < int(schema["minLength"]):
            raise ValueError(f"{path}: text is shorter than the minimum length")
        if "maxLength" in schema and len(value) > int(schema["maxLength"]):
            raise ValueError(f"{path}: text is longer than the maximum length")

    if isinstance(value, (int, float)) and not isinstance(value, bool):
        if "minimum" in schema and value < schema["minimum"]:
            raise ValueError(f"{path}: value is below the minimum")
        if "maximum" in schema and value > schema["maximum"]:
            raise ValueError(f"{path}: value is above the maximum")

    if isinstance(value, list):
        if "minItems" in schema and len(value) < int(schema["minItems"]):
            raise ValueError(f"{path}: list contains too few items")
        if "maxItems" in schema and len(value) > int(schema["maxItems"]):
            raise ValueError(f"{path}: list contains too many items")
        item_schema = schema.get("items")
        if isinstance(item_schema, dict):
            for index, item in enumerate(value):
                validate_schema(item_schema, item, path=f"{path}[{index}]", root=False)

    if isinstance(value, dict):
        properties = schema.get("properties", {})
        if not isinstance(properties, dict):
            raise ValueError(f"{path}: schema properties must be an object")
        for name in schema.get("required", []):
            if name not in value:
                raise ValueError(f"{path}.{name}: field is required")
        if schema.get("additionalProperties", True) is False:
            unknown = sorted(set(value) - set(properties))
            if unknown:
                raise ValueError(f"{path}: unknown field(s): {', '.join(unknown)}")
        for name, item in value.items():
            item_schema = properties.get(name)
            if isinstance(item_schema, dict):
                validate_schema(item_schema, item, path=f"{path}.{name}", root=False)


def validate_tool_args(tool_name: str, args: dict[str, Any]) -> None:
    """Validate one broker request using the live registry schema."""

    from .registry import TOOL_BY_NAME

    definition = TOOL_BY_NAME.get(tool_name)
    if definition is None:
        raise ValueError(f"unknown tool: {tool_name}")
    if not isinstance(args, dict):
        raise ValueError("tool arguments must be an object")
    schema = definition.schema
    if schema:
        validate_schema(schema, args)
