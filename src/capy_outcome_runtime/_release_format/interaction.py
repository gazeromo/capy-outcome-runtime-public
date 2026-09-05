"""Descriptor and portable interaction validation (independent, no DevKit import)."""
from __future__ import annotations

import json
import math
import re
import tomllib

from . import codec
from .constants import EXECUTION_CONTRACT, INTERACTION_CONTRACT

_DESCRIPTOR_FIELDS = {
    "schema", "id", "name", "description", "entrypoint", "side_effect",
    "timeout_seconds", "memory_mb", "state_required", "resources", "connections",
    "input_schema", "result_schema",
}
_SIDE_EFFECTS = {"read_only", "artifact_generation", "scope_state_mutation", "external_effect"}
_ID_RE = re.compile(r"[a-z][a-z0-9_]*(?:\.[a-z][a-z0-9_]*)+\Z")
_SLOT_RE = re.compile(r"[a-z][a-z0-9_]*\Z")
_CONTRACT_RE = re.compile(r"[a-z][a-z0-9_.\-]*/v[0-9]+\Z")
_ARTIFACT_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z")

_TOP_FIELDS = {"schema", "application_id", "title", "purpose", "not_for", "operation", "boundaries"}
_OP_FIELDS = {
    "operation_id", "title", "user_outcome", "description", "request_fields",
    "resource_fields", "examples", "common_misunderstandings", "result",
}
_REQ_FIELDS = {
    "field_id", "label", "description", "required", "input_kind", "safe_default",
    "examples", "clarification_question",
}
_RES_FIELDS = {
    "slot", "label", "description", "required", "minimum_count", "maximum_count",
    "input_kind", "examples", "clarification_question",
}
_RESULT_FIELDS = {"presentation", "facts", "artifacts"}
_FACT_FIELDS = {"path", "label"}
_ART_FIELDS = {"filename", "label"}
_BOUNDARY_FIELDS = {"boundary_id", "request_class", "explanation", "nearest_operation_ids"}
_INPUT_KINDS = {"text", "long_text", "number", "boolean", "choice"}
_SCALAR_TYPES = {"string", "integer", "number", "boolean"}


class InteractionError(ValueError):
    pass


def _fail(msg: str):
    raise InteractionError(msg)


def _checked_text(value, field: str, maximum: int) -> str:
    if not isinstance(value, str) or not 1 <= len(value) <= maximum:
        _fail(f"text:{field}")
    if value != value.strip():
        _fail(f"trim:{field}")
    if "\x00" in value:
        _fail(f"nul:{field}")
    for ch in value:
        o = ord(ch)
        if 0xD800 <= o <= 0xDFFF:
            _fail(f"surrogate:{field}")
    return value


def _checked_text_list(value, field: str, max_items: int) -> list:
    if not isinstance(value, list) or not 1 <= len(value) <= max_items:
        _fail(f"list:{field}")
    out = []
    for i, item in enumerate(value):
        out.append(_checked_text(item, f"{field}[{i}]", 500))
    return out


def _bounded_depth(value, depth: int = 0):
    if depth > 16:
        _fail("nesting")
    if isinstance(value, dict):
        for child in value.values():
            _bounded_depth(child, depth + 1)
    elif isinstance(value, list):
        for child in value:
            _bounded_depth(child, depth + 1)
    elif isinstance(value, float) and not math.isfinite(value):
        _fail("number")


def _dotted(value, what: str) -> str:
    if not isinstance(value, str) or len(value) > 128 or _ID_RE.fullmatch(value) is None:
        _fail(f"id:{what}")
    return value


def _seg_path(value, what: str) -> str:
    if not isinstance(value, str) or not value or len(value) > 256:
        _fail(f"path:{what}")
    for seg in value.split("."):
        if _SLOT_RE.fullmatch(seg) is None:
            _fail(f"segment:{what}")
    return value


def _exact(obj, fields: set, what: str) -> dict:
    if not isinstance(obj, dict) or set(obj) != fields:
        _fail(f"fields:{what}")
    return obj


# ---- JSON schema subset ----

_SCHEMA_TYPES = {
    "object": dict, "array": list, "string": str,
    "integer": int, "number": (int, float), "boolean": bool, "null": type(None),
}
_SCHEMA_KEYS = {
    "type", "required", "additionalProperties", "properties", "items", "enum",
    "minItems", "maxItems", "minLength", "maxLength", "minimum", "maximum", "pattern",
}


def check_json_schema(schema, path: str = "$"):
    if not isinstance(schema, dict) or not isinstance(schema.get("type"), str):
        _fail(f"schema:{path}")
    unknown = set(schema) - _SCHEMA_KEYS
    if unknown or schema["type"] not in _SCHEMA_TYPES:
        _fail(f"schema-unsupported:{path}")
    if "enum" in schema and (not isinstance(schema["enum"], list) or not schema["enum"]):
        _fail(f"schema-enum:{path}")
    kind = schema["type"]
    if kind == "object":
        props = schema.get("properties", {})
        req = schema.get("required", [])
        if not isinstance(props, dict) or not isinstance(req, list):
            _fail(f"schema-object:{path}")
        if any(not isinstance(x, str) for x in req) or not set(req) <= set(props):
            _fail(f"schema-required:{path}")
        if not isinstance(schema.get("additionalProperties", True), bool):
            _fail(f"schema-additional:{path}")
        for name, child in props.items():
            check_json_schema(child, f"{path}.properties.{name}")
    if kind == "array" and "items" in schema:
        check_json_schema(schema["items"], f"{path}.items")
    for key in ("minItems", "maxItems", "minLength", "maxLength"):
        if key in schema and (type(schema[key]) is not int or schema[key] < 0):
            _fail(f"schema-bound:{path}.{key}")
    for key in ("minimum", "maximum"):
        if key in schema and (not isinstance(schema[key], (int, float)) or isinstance(schema[key], bool)):
            _fail(f"schema-range:{path}.{key}")
    if "pattern" in schema:
        try:
            re.compile(schema["pattern"])
        except Exception as e:
            raise InteractionError(f"schema-pattern:{path}") from e


def validate_against_schema(value, schema, what: str = "$"):
    kind = schema["type"]
    exp = _SCHEMA_TYPES[kind]
    ok = isinstance(value, exp)
    if kind in ("integer", "number") and isinstance(value, bool):
        ok = False
    if not ok:
        _fail(f"value-type:{what}")
    if "enum" in schema and value not in schema["enum"]:
        _fail(f"value-enum:{what}")
    if kind == "object":
        props = schema.get("properties", {})
        missing = set(schema.get("required", [])) - set(value)
        if missing:
            _fail(f"value-missing:{what}.{sorted(missing)[0]}")
        extra = set(value) - set(props)
        if extra and schema.get("additionalProperties", True) is False:
            _fail(f"value-extra:{what}.{sorted(extra)[0]}")
        for name in set(value) & set(props):
            validate_against_schema(value[name], props[name], f"{what}.{name}")
    elif kind == "array":
        if len(value) < schema.get("minItems", 0) or len(value) > schema.get("maxItems", len(value)):
            _fail(f"value-array-bound:{what}")
        if "items" in schema:
            for i, item in enumerate(value):
                validate_against_schema(item, schema["items"], f"{what}[{i}]")
    elif kind == "string":
        if len(value) < schema.get("minLength", 0) or len(value) > schema.get("maxLength", len(value)):
            _fail(f"value-string-bound:{what}")
        if "pattern" in schema and re.search(schema["pattern"], value) is None:
            _fail(f"value-pattern:{what}")
    elif kind in ("integer", "number"):
        if value < schema.get("minimum", value) or value > schema.get("maximum", value):
            _fail(f"value-range:{what}")


# ---- Descriptor ----

def parse_descriptor(raw: bytes) -> dict:
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as e:
        raise InteractionError("descriptor-unicode") from e
    try:
        value = tomllib.loads(text)
    except tomllib.TOMLDecodeError as e:
        raise InteractionError("descriptor-toml") from e
    if set(value) != _DESCRIPTOR_FIELDS:
        missing = sorted(_DESCRIPTOR_FIELDS - set(value))
        extra = sorted(set(value) - _DESCRIPTOR_FIELDS)
        if missing:
            raise InteractionError(f"descriptor-missing:{missing[0]}")
        raise InteractionError(f"descriptor-unknown:{extra[0]}")
    if value["schema"] != EXECUTION_CONTRACT:
        raise InteractionError("descriptor-schema")
    if not isinstance(value["id"], str) or _ID_RE.fullmatch(value["id"]) is None:
        raise InteractionError("descriptor-id")
    for field in ("name", "description"):
        v = value[field]
        if not isinstance(v, str) or not v.strip() or len(v) > 512:
            raise InteractionError(f"descriptor-text:{field}")
    ep = value["entrypoint"]
    if not isinstance(ep, str) or ep != ep.strip() or "/" in ep or "\\" in ep or ep in ("", ".", ".."):
        raise InteractionError("descriptor-entrypoint")
    # Entrypoint must look like a safe python file; existence checked by caller.
    if not codec.is_safe_basename_inner_part(ep) or not ep.endswith(".py"):
        raise InteractionError("descriptor-entrypoint-name")
    if value["side_effect"] not in _SIDE_EFFECTS:
        raise InteractionError("descriptor-side-effect")
    for field, lo, hi in (("timeout_seconds", 1, 300), ("memory_mb", 32, 2048)):
        item = value[field]
        if type(item) is not int or not lo <= item <= hi:
            raise InteractionError(f"descriptor-limit:{field}")
    if type(value["state_required"]) is not bool:
        raise InteractionError("descriptor-state-type")
    if value["state_required"] and value["side_effect"] not in {"scope_state_mutation", "external_effect"}:
        raise InteractionError("descriptor-state-mismatch")
    _check_decls(value["resources"], "RESOURCE", {"name", "required", "min_items", "max_items"})
    for item in value["resources"]:
        if type(item["required"]) is not bool or any(type(item[k]) is not int for k in ("min_items", "max_items")):
            raise InteractionError(f"descriptor-resource-type:{item.get('name')}")
        if item["min_items"] < 0 or item["max_items"] < item["min_items"] or item["max_items"] > 100:
            raise InteractionError(f"descriptor-resource-count:{item['name']}")
        if item["required"] and item["min_items"] < 1:
            raise InteractionError(f"descriptor-resource-required:{item['name']}")
    _check_decls(value["connections"], "CONNECTION", {"name", "contract", "operations", "required"})
    for item in value["connections"]:
        if (not isinstance(item["contract"], str) or _CONTRACT_RE.fullmatch(item["contract"]) is None
                or not isinstance(item["operations"], list) or not item["operations"]
                or len(set(item["operations"])) != len(item["operations"])
                or any(not isinstance(op, str) or _SLOT_RE.fullmatch(op) is None for op in item["operations"])
                or type(item["required"]) is not bool):
            raise InteractionError(f"descriptor-connection:{item.get('name')}")
    check_json_schema(value["input_schema"], "input_schema")
    check_json_schema(value["result_schema"], "result_schema")
    return value


def _check_decls(value, prefix: str, fields: set):
    if not isinstance(value, list):
        raise InteractionError(f"{prefix}-list")
    seen: set[str] = set()
    for item in value:
        if not isinstance(item, dict) or set(item) != fields:
            raise InteractionError(f"{prefix}-fields")
        name = item.get("name")
        if not isinstance(name, str) or _SLOT_RE.fullmatch(name) is None or name in seen:
            raise InteractionError(f"{prefix}-name:{name}")
        seen.add(name)


# ---- Interaction file ----

def _input_leaves(schema: dict) -> dict:
    if schema.get("type") != "object" or schema.get("additionalProperties") is not False:
        _fail("input-shape")
    leaves: dict[str, tuple[dict, bool]] = {}

    def visit(node: dict, prefix: tuple, eff_required: bool):
        if node.get("type") == "object":
            if node.get("additionalProperties") is not False:
                _fail(f"input-shape:{'.'.join(prefix) or 'input_schema'}")
            props = node.get("properties", {})
            if not isinstance(props, dict):
                _fail("input-shape-props")
            if prefix and not props:
                _fail(f"input-shape-empty:{'.'.join(prefix)}")
            required = set(node.get("required", []))
            for name, child in props.items():
                if _SLOT_RE.fullmatch(name) is None:
                    _fail(f"input-shape-name:{name}")
                visit(child, (*prefix, name), eff_required and name in required)
            return
        path = ".".join(prefix)
        if node.get("type") not in _SCALAR_TYPES:
            _fail(f"input-scalar:{path or 'input_schema'}")
        if node.get("type") == "string" and "enum" in node:
            choices = node["enum"]
            if any(not isinstance(c, str) for c in choices) or len(set(choices)) != len(choices):
                _fail(f"input-enum:{path}")
        leaves[path] = (node, eff_required)

    visit(schema, (), True)
    return leaves


def _expected_kind(schema: dict) -> set[str]:
    kind = schema["type"]
    if kind == "string":
        return {"choice"} if "enum" in schema else {"text", "long_text"}
    if kind in ("integer", "number"):
        return {"number"}
    return {"boolean"}


def _check_request_fields(value, leaves: dict):
    if not isinstance(value, list) or len(value) > 64:
        _fail("request-fields-list")
    seen: set[str] = set()
    for i, raw in enumerate(value):
        item = _exact(raw, _REQ_FIELDS, f"request_fields[{i}]")
        fid = _seg_path(item["field_id"], "field_id")
        if fid in seen:
            _fail(f"field-dup:{fid}")
        seen.add(fid)
        if fid not in leaves:
            _fail(f"field-unknown:{fid}")
        schema, required = leaves[fid]
        if type(item["required"]) is not bool or item["required"] is not required:
            _fail(f"required-mismatch:{fid}")
        if (not isinstance(item["input_kind"], str) or item["input_kind"] not in _INPUT_KINDS
                or item["input_kind"] not in _expected_kind(schema)):
            _fail(f"kind-mismatch:{fid}")
        default = item["safe_default"]
        if required and default is not None:
            _fail(f"default-required:{fid}")
        if default is not None:
            try:
                validate_against_schema(default, schema, f"default:{fid}")
            except InteractionError:
                _fail(f"default-invalid:{fid}")
        _checked_text(item["label"], f"request_fields[{i}].label", 120)
        _checked_text(item["description"], f"request_fields[{i}].description", 1000)
        _checked_text(item["clarification_question"], f"request_fields[{i}].clarification_question", 500)
        _checked_text_list(item["examples"], f"request_fields[{i}].examples", 16)
    missing = set(leaves) - seen
    if missing:
        _fail(f"field-missing:{sorted(missing)[0]}")


def _check_resource_fields(value, resources: list):
    if not isinstance(value, list) or len(value) > 16:
        _fail("resource-fields-list")
    expected = {item["name"]: item for item in resources}
    seen: set[str] = set()
    for i, raw in enumerate(value):
        item = _exact(raw, _RES_FIELDS, f"resource_fields[{i}]")
        slot = item["slot"]
        if not isinstance(slot, str) or _SLOT_RE.fullmatch(slot) is None or slot not in expected:
            _fail(f"resource-unknown:{slot}")
        if slot in seen:
            _fail(f"resource-dup:{slot}")
        seen.add(slot)
        rule = expected[slot]
        if (type(item["required"]) is not bool or type(item["minimum_count"]) is not int
                or type(item["maximum_count"]) is not int
                or item["required"] is not rule["required"]
                or item["minimum_count"] != rule["min_items"]
                or item["maximum_count"] != rule["max_items"]
                or item["input_kind"] != "file"):
            _fail(f"resource-mismatch:{slot}")
        _checked_text(item["label"], f"resource_fields[{i}].label", 120)
        _checked_text(item["description"], f"resource_fields[{i}].description", 1000)
        _checked_text(item["clarification_question"], f"resource_fields[{i}].clarification_question", 500)
        _checked_text_list(item["examples"], f"resource_fields[{i}].examples", 16)
    missing = set(expected) - seen
    if missing:
        _fail(f"resource-missing:{sorted(missing)[0]}")


def _resolve_result_path(schema: dict, path: str):
    node = schema
    for seg in path.split("."):
        if node.get("type") != "object":
            return None
        props = node.get("properties", {})
        if not isinstance(props, dict) or seg not in props:
            return None
        node = props[seg]
    return node


def _artifact_filenames(schema: dict):
    props = schema.get("properties", {})
    node = props.get("artifact_filenames") if isinstance(props, dict) else None
    if not isinstance(node, dict) or node.get("type") != "array":
        return None
    items = node.get("items")
    if not isinstance(items, dict) or items.get("type") != "string":
        return None
    values = items.get("enum")
    if (not isinstance(values, list) or not values
            or any(not isinstance(x, str) or not x or x != x.strip() for x in values)
            or len(set(values)) != len(values)):
        return None
    return values


def _check_result(value, descriptor: dict):
    item = _exact(value, _RESULT_FIELDS, "operation.result")
    pres = item["presentation"]
    if not isinstance(pres, str) or pres not in {"facts", "artifact_result"}:
        _fail("presentation")
    facts = item["facts"]
    artifacts = item["artifacts"]
    if not isinstance(facts, list) or len(facts) > 64 or not isinstance(artifacts, list) or len(artifacts) > 32:
        _fail("result-lists")
    seen: set[str] = set()
    for i, raw in enumerate(facts):
        fact = _exact(raw, _FACT_FIELDS, f"facts[{i}]")
        path = _seg_path(fact["path"], "fact-path")
        if path in seen:
            _fail(f"fact-dup:{path}")
        seen.add(path)
        node = _resolve_result_path(descriptor["result_schema"], path)
        if node is None or node.get("type") not in _SCALAR_TYPES:
            _fail(f"fact-unknown:{path}")
        _checked_text(fact["label"], f"facts[{i}].label", 120)
    observed: list[str] = []
    for i, raw in enumerate(artifacts):
        art = _exact(raw, _ART_FIELDS, f"artifacts[{i}]")
        fn = art["filename"]
        if not isinstance(fn, str) or _ARTIFACT_RE.fullmatch(fn) is None or fn in observed:
            _fail(f"artifact-bad:{fn}")
        observed.append(fn)
        _checked_text(art["label"], f"artifacts[{i}].label", 120)
    side = descriptor["side_effect"]
    expected = _artifact_filenames(descriptor["result_schema"])
    if side == "read_only":
        if observed:
            _fail(f"artifact-readonly:{observed[0]}")
    elif side == "artifact_generation":
        if expected is None or observed != expected:
            _fail("artifact-mismatch")
    if pres != ("artifact_result" if observed else "facts"):
        _fail("presentation-mismatch")
    if not facts and not artifacts:
        _fail("result-empty")


def validate_interaction_document(doc: dict, descriptor: dict) -> dict:
    _bounded_depth(doc)
    document = _exact(doc, _TOP_FIELDS, "top-level")
    if document["schema"] != INTERACTION_CONTRACT:
        _fail("schema")
    app_id = _dotted(document["application_id"], "application_id")
    if app_id != descriptor["id"]:
        _fail("application-mismatch")
    if descriptor["state_required"]:
        _fail("state-unsupported")
    if descriptor["connections"]:
        _fail("connections-unsupported")
    if descriptor["side_effect"] not in {"read_only", "artifact_generation"}:
        _fail("side-effect-unsupported")
    _checked_text(document["title"], "title", 120)
    _checked_text(document["purpose"], "purpose", 1000)
    _checked_text_list(document["not_for"], "not_for", 32)
    operation = _exact(document["operation"], _OP_FIELDS, "operation")
    op_id = _dotted(operation["operation_id"], "operation_id")
    _checked_text(operation["title"], "operation.title", 120)
    _checked_text(operation["user_outcome"], "operation.user_outcome", 500)
    _checked_text(operation["description"], "operation.description", 1000)
    _checked_text_list(operation["examples"], "operation.examples", 16)
    _checked_text_list(operation["common_misunderstandings"], "operation.common_misunderstandings", 16)
    _check_request_fields(operation["request_fields"], _input_leaves(descriptor["input_schema"]))
    _check_resource_fields(operation["resource_fields"], descriptor["resources"])
    _check_result(operation["result"], descriptor)
    boundaries = document["boundaries"]
    if not isinstance(boundaries, list) or not 1 <= len(boundaries) <= 32:
        _fail("boundaries-list")
    seen_b: set[str] = set()
    for i, raw in enumerate(boundaries):
        b = _exact(raw, _BOUNDARY_FIELDS, f"boundaries[{i}]")
        bid = _dotted(b["boundary_id"], "boundary_id")
        if bid in seen_b:
            _fail(f"boundary-dup:{bid}")
        seen_b.add(bid)
        _checked_text(b["request_class"], f"boundaries[{i}].request_class", 1000)
        _checked_text(b["explanation"], f"boundaries[{i}].explanation", 1000)
        nearest = b["nearest_operation_ids"]
        if not isinstance(nearest, list) or not nearest or any(x != op_id for x in nearest):
            _fail(f"boundary-nearest:{bid}")
    try:
        canonical = json.dumps(
            document, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
        ).encode("utf-8")
    except (TypeError, ValueError) as e:
        raise InteractionError("canonical") from e
    return {"application_id": app_id, "operation_id": op_id, "canonical_bytes": canonical, "document": document}


def load_interaction_from_bytes(source_bytes: bytes, descriptor: dict) -> dict:
    if not source_bytes or len(source_bytes) > 64 * 1024:
        _fail("source-size")
    try:
        text = source_bytes.decode("utf-8")
    except UnicodeDecodeError as e:
        raise InteractionError("interaction-unicode") from e

    # Strict duplicate-key and nonfinite detection.
    class _Dup(Exception):
        pass

    def _hook(pairs):
        obj = {}
        for k, v in pairs:
            if k in obj:
                raise _Dup(k)
            obj[k] = v
        return obj

    def _const(_s):
        raise ValueError("non-finite")

    try:
        doc = json.loads(text, object_pairs_hook=_hook, parse_constant=_const)
    except _Dup as e:
        raise InteractionError("interaction-dup") from e
    except (json.JSONDecodeError, ValueError) as e:
        raise InteractionError("interaction-json") from e
    return validate_interaction_document(doc, descriptor)
