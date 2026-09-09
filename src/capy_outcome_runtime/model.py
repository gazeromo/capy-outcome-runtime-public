"""Small, strict contracts shared by publication and invocation."""

from __future__ import annotations

import json
import re
import tomllib
from dataclasses import asdict, dataclass
from pathlib import Path, PurePosixPath
from typing import Any


CAPABILITY_ID = re.compile(r"[a-z][a-z0-9_]*(?:\.[a-z][a-z0-9_]*)+")
CONNECTION_NAME = re.compile(r"[a-z][a-z0-9_]{0,63}")
ALLOWED_SIDE_EFFECTS = {
    "read_only", "state_change", "artifact_generation",
    "scope_state_mutation", "external_effect",
}
ALLOWED_VISIBILITY = {"private", "shared", "link"}
SUPPORTED_CONNECTION_CONTRACTS = {"fedex.rates/v1": {"quote"}, "fedex.rates/v2": {"quote"}}


class RuntimeFailure(RuntimeError):
    """A causal, stable failure safe to expose to the controller."""

    def __init__(
        self,
        code: str,
        detail: str | None = None,
        *,
        safe_facts: dict[str, Any] | None = None,
    ):
        super().__init__(code if detail is None else f"{code}: {detail}")
        self.code = code
        self.detail = detail
        self.safe_facts = dict(safe_facts or {})


def _strings(value: Any, field: str) -> tuple[str, ...]:
    if not isinstance(value, list) or not all(
        isinstance(item, str) and item and "\x00" not in item for item in value
    ):
        raise RuntimeFailure("CAPABILITY_DESCRIPTOR_INVALID", field)
    if len(value) != len(set(value)):
        raise RuntimeFailure("CAPABILITY_DESCRIPTOR_INVALID", field)
    return tuple(value)


def _schema(value: Any, field: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise RuntimeFailure("CAPABILITY_DESCRIPTOR_INVALID", field)
    try:
        json.dumps(value, sort_keys=True, separators=(",", ":"))
    except (TypeError, ValueError) as exc:
        raise RuntimeFailure("CAPABILITY_DESCRIPTOR_INVALID", field) from exc
    _validate_schema_definition(value)
    return value


def _validate_schema_definition(schema: dict[str, Any]) -> None:
    expected = schema.get("type")
    if expected not in {"object", "array", "string", "integer", "number", "boolean", "null"}:
        raise RuntimeFailure("CAPABILITY_DESCRIPTOR_INVALID", "schema")
    allowed = {"type", "enum"}
    if "enum" in schema and (not isinstance(schema["enum"], list) or not schema["enum"]):
        raise RuntimeFailure("CAPABILITY_DESCRIPTOR_INVALID", "schema")
    if expected == "object":
        allowed |= {"properties", "required", "additionalProperties"}
        properties = schema.get("properties", {})
        required = schema.get("required", [])
        additional = schema.get("additionalProperties", True)
        if (
            not isinstance(properties, dict)
            or not isinstance(required, list)
            or not all(isinstance(item, str) for item in required)
            or len(required) != len(set(required))
            or not set(required) <= set(properties)
            or type(additional) is not bool
        ):
            raise RuntimeFailure("CAPABILITY_DESCRIPTOR_INVALID", "schema")
        for child in properties.values():
            if not isinstance(child, dict):
                raise RuntimeFailure("CAPABILITY_DESCRIPTOR_INVALID", "schema")
            _validate_schema_definition(child)
    elif expected == "array":
        allowed |= {"items", "minItems", "maxItems"}
        if "items" in schema:
            if not isinstance(schema["items"], dict):
                raise RuntimeFailure("CAPABILITY_DESCRIPTOR_INVALID", "schema")
            _validate_schema_definition(schema["items"])
        for name in ("minItems", "maxItems"):
            if name in schema and (type(schema[name]) is not int or schema[name] < 0):
                raise RuntimeFailure("CAPABILITY_DESCRIPTOR_INVALID", "schema")
    elif expected == "string":
        allowed |= {"minLength", "maxLength", "pattern"}
        for name in ("minLength", "maxLength"):
            if name in schema and (type(schema[name]) is not int or schema[name] < 0):
                raise RuntimeFailure("CAPABILITY_DESCRIPTOR_INVALID", "schema")
        if "pattern" in schema:
            try:
                re.compile(schema["pattern"])
            except (TypeError, re.error) as exc:
                raise RuntimeFailure("CAPABILITY_DESCRIPTOR_INVALID", "schema") from exc
    elif expected in {"integer", "number"}:
        allowed |= {"minimum", "maximum"}
        for name in ("minimum", "maximum"):
            if name in schema and (
                not isinstance(schema[name], (int, float)) or isinstance(schema[name], bool)
            ):
                raise RuntimeFailure("CAPABILITY_DESCRIPTOR_INVALID", "schema")
    if set(schema) - allowed:
        raise RuntimeFailure("CAPABILITY_DESCRIPTOR_INVALID", "schema")


def validate_json(value: Any, schema: dict[str, Any], code: str, path: str = "$") -> None:
    """Validate the intentionally small JSON-Schema subset used by V0 scripts."""

    expected = schema.get("type")
    checks = {
        "object": lambda item: isinstance(item, dict),
        "array": lambda item: isinstance(item, list),
        "string": lambda item: isinstance(item, str),
        "integer": lambda item: type(item) is int,
        "number": lambda item: type(item) in {int, float},
        "boolean": lambda item: type(item) is bool,
        "null": lambda item: item is None,
    }
    if expected not in checks or not checks[expected](value):
        raise RuntimeFailure(code, path)
    if "enum" in schema and value not in schema["enum"]:
        raise RuntimeFailure(code, path)
    if expected == "object":
        properties = schema.get("properties", {})
        required = schema.get("required", [])
        additional = schema.get("additionalProperties", True)
        missing = [item for item in required if item not in value]
        if missing:
            raise RuntimeFailure(code, f"{path}.{missing[0]}")
        if not additional:
            unknown = sorted(set(value) - set(properties))
            if unknown:
                raise RuntimeFailure(code, f"{path}.{unknown[0]}")
        for name, child in properties.items():
            if name in value:
                validate_json(value[name], child, code, f"{path}.{name}")
    elif expected == "array":
        if len(value) < schema.get("minItems", 0) or len(value) > schema.get("maxItems", len(value)):
            raise RuntimeFailure(code, path)
        if "items" in schema:
            child = schema["items"]
            for index, item in enumerate(value):
                validate_json(item, child, code, f"{path}[{index}]")
    elif expected == "string":
        if len(value) < schema.get("minLength", 0) or len(value) > schema.get("maxLength", len(value)):
            raise RuntimeFailure(code, path)
        if "pattern" in schema and re.search(schema["pattern"], value) is None:
            raise RuntimeFailure(code, path)
    elif expected in {"integer", "number"}:
        if value < schema.get("minimum", value) or value > schema.get("maximum", value):
            raise RuntimeFailure(code, path)


@dataclass(frozen=True)
class ConnectionRequirement:
    name: str
    contract: str
    operations: tuple[str, ...]
    required: bool


@dataclass(frozen=True)
class ResourceRequirement:
    name: str
    required: bool
    min_items: int
    max_items: int


@dataclass(frozen=True)
class CapabilityDescriptor:
    schema: str
    id: str
    name: str
    description: str
    entrypoint: str
    side_effect: str
    visibility: str
    timeout_seconds: int
    memory_mb: int
    connections: tuple[str, ...]
    state_required: bool
    input_schema: dict[str, Any]
    result_schema: dict[str, Any]
    connection_requirements: tuple[ConnectionRequirement, ...] = ()
    resource_requirements: tuple[ResourceRequirement, ...] = ()

    @classmethod
    def from_toml(cls, path: Path) -> "CapabilityDescriptor":
        try:
            raw = tomllib.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, tomllib.TOMLDecodeError) as exc:
            raise RuntimeFailure("CAPABILITY_DESCRIPTOR_INVALID") from exc
        legacy_expected = {
            "schema",
            "id",
            "name",
            "description",
            "entrypoint",
            "side_effect",
            "visibility",
            "timeout_seconds",
            "memory_mb",
            "connections",
            "state_required",
            "input_schema",
            "result_schema",
        }
        dev_expected = legacy_expected - {"visibility"} | {"resources"}
        schema_name = raw.get("schema")
        if (
            (schema_name == "capy.script/dev-v0" and set(raw) != dev_expected)
            or (schema_name != "capy.script/dev-v0" and set(raw) != legacy_expected)
        ):
            raise RuntimeFailure("CAPABILITY_DESCRIPTOR_INVALID", "fields")
        scalar_fields = ("schema", "id", "name", "description", "entrypoint", "side_effect")
        if schema_name != "capy.script/dev-v0":
            scalar_fields += ("visibility",)
        if not all(
            isinstance(raw[field], str)
            and raw[field]
            and "\x00" not in raw[field]
            and "\n" not in raw[field]
            for field in scalar_fields
        ):
            raise RuntimeFailure("CAPABILITY_DESCRIPTOR_INVALID", "scalar")
        entrypoint = PurePosixPath(raw["entrypoint"])
        if entrypoint.is_absolute() or ".." in entrypoint.parts or str(entrypoint) in {"", "."}:
            raise RuntimeFailure("CAPABILITY_DESCRIPTOR_INVALID", "entrypoint")
        if (
            raw["schema"] not in {"capy.script/v0", "capy.script/v1", "capy.script/dev-v0"}
            or len(raw["id"]) > 128
            or not CAPABILITY_ID.fullmatch(raw["id"])
            or raw["side_effect"] not in ALLOWED_SIDE_EFFECTS
            or (schema_name != "capy.script/dev-v0" and raw["visibility"] not in ALLOWED_VISIBILITY)
            or type(raw["timeout_seconds"]) is not int
            or not 1 <= raw["timeout_seconds"] <= 900
            or type(raw["memory_mb"]) is not int
            or not 32 <= raw["memory_mb"] <= 4096
            or type(raw["state_required"]) is not bool
        ):
            raise RuntimeFailure("CAPABILITY_DESCRIPTOR_INVALID")
        requirements: tuple[ConnectionRequirement, ...] = ()
        resource_requirements: tuple[ResourceRequirement, ...] = ()
        if raw["schema"] == "capy.script/v0":
            connections = _strings(raw["connections"], "connections")
            if not all(CONNECTION_NAME.fullmatch(item) for item in connections):
                raise RuntimeFailure("CAPABILITY_DESCRIPTOR_INVALID", "connections")
        else:
            source = raw["connections"]
            if not isinstance(source, list):
                raise RuntimeFailure("CAPABILITY_DESCRIPTOR_INVALID", "connections")
            parsed = []
            for item in source:
                if not isinstance(item, dict) or set(item) != {"name", "contract", "operations", "required"}:
                    raise RuntimeFailure("CAPABILITY_DESCRIPTOR_INVALID", "connections")
                operations = _strings(item["operations"], "connections.operations")
                if (
                    not isinstance(item["name"], str)
                    or CONNECTION_NAME.fullmatch(item["name"]) is None
                    or item["contract"] not in SUPPORTED_CONNECTION_CONTRACTS
                    or not operations
                    or any(operation not in SUPPORTED_CONNECTION_CONTRACTS[item["contract"]] for operation in operations)
                    or type(item["required"]) is not bool
                ):
                    raise RuntimeFailure("CAPABILITY_DESCRIPTOR_INVALID", "connections")
                parsed.append(ConnectionRequirement(item["name"], item["contract"], operations, item["required"]))
            if len({item.name for item in parsed}) != len(parsed):
                raise RuntimeFailure("CAPABILITY_DESCRIPTOR_INVALID", "connections")
            requirements = tuple(parsed)
            connections = tuple(item.name for item in requirements)
        if schema_name == "capy.script/dev-v0":
            resources = raw["resources"]
            if not isinstance(resources, list):
                raise RuntimeFailure("CAPABILITY_DESCRIPTOR_INVALID", "resources")
            parsed_resources = []
            for item in resources:
                if not isinstance(item, dict) or set(item) != {"name", "required", "min_items", "max_items"}:
                    raise RuntimeFailure("CAPABILITY_DESCRIPTOR_INVALID", "resources")
                if (
                    not isinstance(item["name"], str)
                    or CONNECTION_NAME.fullmatch(item["name"]) is None
                    or type(item["required"]) is not bool
                    or type(item["min_items"]) is not int
                    or type(item["max_items"]) is not int
                    or item["min_items"] < 0
                    or item["max_items"] < item["min_items"]
                    or item["max_items"] > 100
                    or (item["required"] and item["min_items"] < 1)
                ):
                    raise RuntimeFailure("CAPABILITY_DESCRIPTOR_INVALID", "resources")
                parsed_resources.append(ResourceRequirement(**item))
            if len({item.name for item in parsed_resources}) != len(parsed_resources):
                raise RuntimeFailure("CAPABILITY_DESCRIPTOR_INVALID", "resources")
            resource_requirements = tuple(parsed_resources)
            if raw["state_required"] and raw["side_effect"] not in {"scope_state_mutation", "external_effect"}:
                raise RuntimeFailure("CAPABILITY_DESCRIPTOR_INVALID", "state_required")
        return cls(
            schema=raw["schema"],
            id=raw["id"],
            name=raw["name"],
            description=raw["description"],
            entrypoint=str(entrypoint),
            side_effect=raw["side_effect"],
            visibility=raw.get("visibility", "private"),
            timeout_seconds=raw["timeout_seconds"],
            memory_mb=raw["memory_mb"],
            connections=connections,
            state_required=raw["state_required"],
            input_schema=_schema(raw["input_schema"], "input_schema"),
            result_schema=_schema(raw["result_schema"], "result_schema"),
            connection_requirements=requirements,
            resource_requirements=resource_requirements,
        )

    def canonical_json(self) -> str:
        value = asdict(self)
        value["connections"] = list(self.connections)
        value["connection_requirements"] = [
            {**asdict(item), "operations": list(item.operations)}
            for item in self.connection_requirements
        ]
        value["resource_requirements"] = [asdict(item) for item in self.resource_requirements]
        return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)

    @classmethod
    def from_json(cls, value: str) -> "CapabilityDescriptor":
        raw = json.loads(value)
        raw["connections"] = tuple(raw["connections"])
        raw["connection_requirements"] = tuple(
            ConnectionRequirement(
                item["name"], item["contract"], tuple(item["operations"]), item["required"]
            )
            for item in raw.get("connection_requirements", [])
        )
        raw["resource_requirements"] = tuple(
            ResourceRequirement(**item) for item in raw.get("resource_requirements", [])
        )
        return cls(**raw)
