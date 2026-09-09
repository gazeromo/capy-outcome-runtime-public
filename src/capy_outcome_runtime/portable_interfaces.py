"""Pure projection and no-JavaScript form handling for accepted portable apps.

Human prose is always data. This module grants no installation or workspace
access; callers must resolve current authority before using these helpers.
"""
from __future__ import annotations

import copy
import hashlib
import html
import json
import math
import re
from typing import Any

from ._release_format.interaction import (
    InteractionError, check_json_schema, load_interaction_from_bytes,
    validate_against_schema,
)
from .model import RuntimeFailure

SCHEMA = "capy.application-interaction/v0"
FORM_MARKER = "__portable_form"
PRESENCE_PREFIX = "__present__."
INPUT_PREFIX = "input."
_MISSING = object()


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False).encode("utf-8")


def _node(schema: dict, path: str) -> dict:
    for part in path.split("."):
        schema = schema["properties"][part]
    return schema


def _active_ancestors(schema: dict, path: str) -> bool:
    """Whether every object ancestor must exist even with no submitted leaves."""
    for part in path.split(".")[:-1]:
        if part not in schema.get("required", []):
            return False
        schema = schema["properties"][part]
    return True


def project_portable(execution: dict, interaction: dict, import_id: str) -> dict:
    """Validate portable meaning and bind a private contract to exact identity."""
    try:
        # RuntimeStore names these resource_requirements; pre-install import
        # validation uses the parsed descriptor's resources. Normalize the
        # machine declaration only, never infer counts from interaction prose.
        execution = dict(execution)
        if "resource_requirements" in execution:
            if "resources" in execution and execution["resources"] != execution["resource_requirements"]:
                raise ValueError("conflicting resource declarations")
            execution["resources"] = execution["resource_requirements"]
        if type(execution["state_required"]) is not bool or not isinstance(execution["connections"], list):
            raise ValueError("execution state or connections")
        resources = execution["resources"]
        if not isinstance(resources, list):
            raise ValueError("resource declarations")
        names = set()
        for resource in resources:
            if not isinstance(resource, dict) or set(resource) != {"name", "required", "min_items", "max_items"}:
                raise ValueError("resource shape")
            name = resource["name"]
            if not isinstance(name, str) or re.fullmatch(r"[a-z][a-z0-9_]*", name) is None or name in names:
                raise ValueError("resource name")
            names.add(name)
            if (type(resource["required"]) is not bool
                    or type(resource["min_items"]) is not int or type(resource["max_items"]) is not int
                    or not 0 <= resource["min_items"] <= resource["max_items"] <= 100
                    or (resource["required"] and resource["min_items"] < 1)):
                raise ValueError("resource counts")
        if not isinstance(import_id, str) or not import_id or len(import_id) > 256:
            raise ValueError("import identity")
        version = execution["version_digest"]
        if not isinstance(version, str) or re.fullmatch(r"[0-9a-f]{64}", version) is None:
            raise ValueError("version identity")
        check_json_schema(execution["input_schema"])
        check_json_schema(execution["result_schema"])
        validated = load_interaction_from_bytes(_canonical(interaction), execution)
        source = validated["document"]
        interaction_sha = hashlib.sha256(validated["canonical_bytes"]).hexdigest()
    except (InteractionError, KeyError, TypeError, ValueError, UnicodeError, RecursionError) as exc:
        raise RuntimeFailure("PORTABLE_INTERACTION_INVALID") from exc
    op = source["operation"]
    human_fields = []
    for field in op["request_fields"]:
        schema = _node(execution["input_schema"], field["field_id"])
        human_fields.append({
            **copy.deepcopy(field), "semantic": "enforced", "schema": copy.deepcopy(schema),
            "default_active": _active_ancestors(execution["input_schema"], field["field_id"]),
            **({"choices": copy.deepcopy(schema["enum"])} if "enum" in schema else {}),
        })
    for field in op["resource_fields"]:
        human_fields.append({**copy.deepcopy(field), "field_id": field["slot"],
                             "semantic": "enforced", "safe_default": None})
    # A resource and scalar sharing a form name cannot be represented safely.
    if len({f["field_id"] for f in human_fields}) != len(human_fields):
        raise RuntimeFailure("PORTABLE_INTERFACE_FIELD_COLLISION")
    result = op["result"]
    operation = {
        "operation_id": op["operation_id"], "capability_id": execution["id"],
        "title": op["title"], "user_outcome": op["user_outcome"],
        "description": op["description"], "human_fields": human_fields,
        "request_schema": copy.deepcopy(execution["input_schema"]),
        "result_schema": copy.deepcopy(execution["result_schema"]),
        "resources": copy.deepcopy(execution["resources"]), "context_fields": [],
        "safe_defaults": {f["field_id"]: copy.deepcopy(f["safe_default"])
                          for f in human_fields if f["safe_default"] is not None},
        "authority": {"required_role": "current active workspace member with the exact software binding",
                      "policy": "runtime scope plus current membership and exact software binding"},
        "effects": {"effect_class": execution["side_effect"],
                    "state_effect": "read_only", "source_behavior": (
                        "publisher-managed read-only connections" if execution["connections"]
                        else "no declared connections")},
        "examples": copy.deepcopy(op["examples"]),
        "common_misunderstandings": copy.deepcopy(op["common_misunderstandings"]),
        "result": {"presentation": result["presentation"],
                   "facts": [f["path"] for f in result["facts"]],
                   "artifacts": [a["filename"] for a in result["artifacts"]],
                   "fact_labels": {f["path"]: f["label"] for f in result["facts"]},
                   "artifact_labels": {a["filename"]: a["label"] for a in result["artifacts"]}},
    }
    contract = {
        "schema": SCHEMA, "application_id": source["application_id"],
        "application_version": version,
        "portable_import": {"import_id": import_id, "interaction_sha256": interaction_sha},
        **{key: copy.deepcopy(source[key]) for key in ("title", "purpose", "not_for", "boundaries")},
        "operations": [operation],
    }
    contract["digest"] = hashlib.sha256(_canonical(contract)).hexdigest()
    return contract


def _scalar(raw: str, schema: dict) -> Any:
    kind = schema["type"]
    if kind == "string":
        return raw
    if kind == "boolean":
        if raw not in {"true", "false"}:
            raise ValueError("boolean")
        return raw == "true"
    if kind == "integer":
        if re.fullmatch(r"-?(?:0|[1-9][0-9]*)", raw) is None:
            raise ValueError("integer")
        return int(raw)
    # JSON numeric syntax, not Python's whitespace, NaN or Infinity extensions.
    if re.fullmatch(r"-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?", raw) is None:
        raise ValueError("number")
    value = json.loads(raw)
    if isinstance(value, float) and not math.isfinite(value):
        raise ValueError("finite number")
    return value


def parse_portable_request(operation: dict, fields: dict[str, str]) -> dict:
    """Assemble and validate exact scalar request; uploads stay with the caller.

    Direct callers omit absent keys. Browser forms use a marker and optional
    Include checkboxes because HTML otherwise submits untouched empty controls.
    Defaults apply only within objects that are required or explicitly activated.
    """
    scalar_fields = {f["field_id"]: f for f in operation["human_fields"] if f["input_kind"] != "file"}
    allowed = set(scalar_fields) | {FORM_MARKER} | {
        PRESENCE_PREFIX + key for key, field in scalar_fields.items() if not field["required"]
    }
    if (not isinstance(fields, dict) or set(fields) - allowed
            or any(not isinstance(v, str) for v in fields.values())):
        raise RuntimeFailure("APPLICATION_INTERFACE_FIELD_UNKNOWN")
    browser = FORM_MARKER in fields
    if (browser and fields[FORM_MARKER] != "1") or any(
        key.startswith(PRESENCE_PREFIX) and (not browser or value != "1")
        for key, value in fields.items()
    ):
        raise RuntimeFailure("APPLICATION_INTERFACE_FIELD_INVALID")
    explicit = {}
    try:
        for key, field in scalar_fields.items():
            included = not browser or field["required"] or PRESENCE_PREFIX + key in fields
            if browser and PRESENCE_PREFIX + key in fields and key not in fields:
                raise ValueError("included field missing")
            if key in fields and included:
                explicit[key] = _scalar(fields[key], _node(operation["request_schema"], key))

        def assemble(schema: dict, prefix: str = "") -> dict:
            result = {}
            for name, child in schema.get("properties", {}).items():
                path = prefix + name
                if child["type"] == "object":
                    active = name in schema.get("required", []) or any(
                        key.startswith(path + ".") for key in explicit
                    )
                    if active:
                        result[name] = assemble(child, path + ".")
                elif path in explicit:
                    result[name] = explicit[path]
                elif scalar_fields[path]["safe_default"] is not None:
                    result[name] = copy.deepcopy(scalar_fields[path]["safe_default"])
            return result

        request = assemble(operation["request_schema"])
        validate_against_schema(request, operation["request_schema"])
        return request
    except (InteractionError, ValueError, TypeError, KeyError, OverflowError) as exc:
        raise RuntimeFailure("APPLICATION_INTERFACE_FIELD_INVALID") from exc


def render_portable_fields(fields: list[dict]) -> str:
    """Render escaped controls with app names isolated from runtime metadata.

    The HTTP adapter strips INPUT_PREFIX from submitted app scalar/file names
    before calling parse_portable_request or checking resource declarations.
    Contract field IDs and the pure parser API retain their original identities.
    """
    esc = lambda value: html.escape(str(value), quote=True)
    parts = [f'<input type="hidden" name="{FORM_MARKER}" value="1">']
    for field in fields:
        key, label = esc(field["field_id"]), esc(field["label"])
        control_name = esc(INPUT_PREFIX + field["field_id"])
        kind = field["input_kind"]
        # HTML 'required' forbids empty text, whereas schema requiredness
        # only requires presence. Preserve schema-valid empty strings.
        schema = field.get("schema", {})
        permits_empty = schema.get("type") == "string" and schema.get("minLength", 0) == 0
        if "enum" in schema:
            permits_empty = "" in schema["enum"]
        required = ' required' if field["required"] and not permits_empty else ''
        default = field.get("safe_default")
        default = "" if default is None else (str(default).lower() if type(default) is bool else str(default))
        value = esc(default)
        presence = ""
        if not field["required"] and kind != "file":
            checked = ' checked' if field.get("safe_default") is not None and field.get("default_active", True) else ''
            presence = (f'<label><input type="checkbox" name="{PRESENCE_PREFIX}{key}" value="1"{checked}>'
                        f' Include {label}</label>')
        if kind == "file":
            multiple = ' multiple' if field["maximum_count"] > 1 else ''
            control = f'<input id="portable-{key}" type="file" name="{control_name}"{required}{multiple}>'
            control += f'<small>Files: {field["minimum_count"]}–{field["maximum_count"]}.</small>'
        elif kind == "long_text":
            control = f'<textarea id="portable-{key}" name="{control_name}"{required}>{value}</textarea>'
        elif kind in {"choice", "boolean"}:
            choices = field.get("choices", []) if kind == "choice" else ["true", "false"]
            options = '<option value="">Choose a value</option>'
            for choice in choices:
                selected = ' selected' if str(choice) == default else ''
                options += f'<option value="{esc(choice)}"{selected}>{esc(choice)}</option>'
            control = f'<select id="portable-{key}" name="{control_name}"{required}>{options}</select>'
        else:
            numeric = kind == "number"
            step = (' step="1"' if field.get("schema", {}).get("type") == "integer" else ' step="any"') if numeric else ''
            control = (f'<input id="portable-{key}" type="{"number" if numeric else "text"}"'
                       f' name="{control_name}" value="{value}"{required}{step}>')
        parts.append(f'<div class="field">{presence}<label for="portable-{key}">{label}'
                     f'{" (required)" if field["required"] else " (optional)"}</label>{control}'
                     f'<small>{esc(field["description"])}</small></div>')
    return "".join(parts)


def project_portable_result(operation: dict, result: dict, artifacts: list[dict]) -> tuple[dict, list[dict]]:
    """Allowlist declared scalar paths and artifacts after exact result validation.

    Artifact authorization and digest verification remain runtime responsibilities.
    Returned fact keys retain their dotted paths and map directly to fact_labels.
    """
    try:
        _canonical(result)  # Reject non-finite values, including undeclared ones.
        validate_against_schema(result, operation["result_schema"])
        facts = {}
        for path in operation["result"]["facts"]:
            value = result
            for segment in path.split("."):
                value = value.get(segment, _MISSING) if isinstance(value, dict) else _MISSING
            if value is not _MISSING:
                if type(value) not in {str, int, float, bool}:
                    raise ValueError("non-scalar fact")
                facts[path] = value
        allowed = set(operation["result"]["artifacts"])
        projected = [copy.deepcopy(a) for a in artifacts if a.get("filename") in allowed]
        if len({a["filename"] for a in projected}) != len(projected):
            raise ValueError("duplicate artifact")
        return facts, projected
    except (InteractionError, ValueError, TypeError, KeyError, UnicodeError) as exc:
        raise RuntimeFailure("APPLICATION_INTERFACE_RESULT_INVALID") from exc
