"""Locally validated semantic action protocol and bounded Luna/OpenRouter adapter."""

from __future__ import annotations

import copy
import hashlib
import json
import os
import re
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

from .model import RuntimeFailure, validate_json


TURN_SCHEMA = "capy.chat-turn/v0"
MODEL = "openai/gpt-5.6-luna"
ENDPOINT = "https://openrouter.ai/api/v1/chat/completions"
LEGACY_DECISION_FIELDS = {
    "schema", "action", "message", "capability_id", "input", "resources", "gap"
}
DECISION_FIELDS = LEGACY_DECISION_FIELDS | {"clarification"}
REPAIRABLE_PROPOSAL_CODES = {
    "SEMANTIC_PROVIDER_RESPONSE_INVALID",
    "SEMANTIC_DECISION_INVALID",
}
MAX_PROPOSAL_CONTENT_BYTES = 64 * 1024


def _safe_identifier(value: Any, limit: int = 200) -> str | int | None:
    if type(value) is int:
        return value
    if not isinstance(value, str) or not 1 <= len(value) <= limit:
        return None
    return value if re.fullmatch(r"[A-Za-z0-9._:/@-]+", value) else None


def safe_provider_envelope_facts(raw: bytes, response: Any) -> dict[str, Any]:
    """Return bounded envelope structure without retaining provider prose."""

    status = getattr(response, "status", None)
    headers = getattr(response, "headers", {}) or {}
    request_id = None
    for name in ("x-request-id", "x-openrouter-request-id", "request-id"):
        try:
            request_id = _safe_identifier(headers.get(name))
        except AttributeError:
            request_id = None
        if request_id is not None:
            break
    facts: dict[str, Any] = {
        "provider_http_status": status if type(status) is int else 200,
        "provider_response_bytes": len(raw),
        "provider_response_sha256": hashlib.sha256(raw).hexdigest(),
        "provider_request_id": request_id,
    }
    try:
        retry_after = headers.get("retry-after")
    except AttributeError:
        retry_after = None
    if isinstance(retry_after, str) and retry_after.isdigit():
        facts["provider_retry_after_seconds"] = min(int(retry_after), 3600)
    try:
        envelope = json.loads(raw)
    except (TypeError, ValueError, json.JSONDecodeError):
        facts["provider_envelope"] = {"top_level_type": "invalid_json"}
        return facts
    shape: dict[str, Any] = {"top_level_type": type(envelope).__name__}
    if not isinstance(envelope, dict):
        facts["provider_envelope"] = shape
        return facts
    shape["top_level_keys"] = sorted(str(key)[:80] for key in envelope)[:32]
    error = envelope.get("error")
    shape["error_present"] = "error" in envelope
    shape["error_type"] = type(error).__name__
    if isinstance(error, dict):
        shape["error_code"] = _safe_identifier(error.get("code"))
        shape["error_kind"] = _safe_identifier(error.get("type"))
    choices = envelope.get("choices")
    shape["choices_type"] = type(choices).__name__
    shape["choices_count"] = len(choices) if isinstance(choices, list) else None
    if isinstance(choices, list) and choices and isinstance(choices[0], dict):
        first = choices[0]
        shape["first_choice_keys"] = sorted(str(key)[:80] for key in first)[:24]
        shape["finish_reason"] = _safe_identifier(first.get("finish_reason"))
        message = first.get("message")
        shape["message_type"] = type(message).__name__
        if isinstance(message, dict):
            shape["message_keys"] = sorted(str(key)[:80] for key in message)[:24]
            content = message.get("content")
            shape["content_type"] = type(content).__name__
            shape["content_bytes"] = len(content.encode()) if isinstance(content, str) else None
            shape["refusal_present"] = message.get("refusal") is not None
            shape["tool_calls_present"] = bool(message.get("tool_calls"))
    shape["model_identity"] = _safe_identifier(envelope.get("model"))
    shape["provider_routing_identity"] = _safe_identifier(envelope.get("provider"))
    shape["usage_present"] = isinstance(envelope.get("usage"), dict)
    if isinstance(envelope.get("usage"), dict):
        facts["provider_usage"] = {
            key: envelope["usage"][key]
            for key in ("prompt_tokens", "completion_tokens", "total_tokens", "cost")
            if type(envelope["usage"].get(key)) in {int, float}
        }
    facts["provider_envelope"] = shape
    return facts


def extract_single_json_object(content: Any, error_code: str) -> dict[str, Any]:
    """Extract one unambiguous bounded object from an ordinary model response."""

    if (
        not isinstance(content, str)
        or not content.strip()
        or len(content.encode("utf-8")) > MAX_PROPOSAL_CONTENT_BYTES
    ):
        raise RuntimeFailure(error_code)
    text = content.strip()

    def parse(candidate: str) -> dict[str, Any] | None:
        try:
            value = json.loads(candidate)
        except (TypeError, ValueError, json.JSONDecodeError):
            return None
        return value if isinstance(value, dict) else None

    direct = parse(text)
    if direct is not None:
        return direct

    fenced = list(re.finditer(r"```(?:json)?\s*(.*?)\s*```", text, re.IGNORECASE | re.DOTALL))
    if len(fenced) == 1:
        outside = (text[:fenced[0].start()] + text[fenced[0].end():]).strip()
        candidate = parse(fenced[0].group(1))
        if candidate is not None and "{" not in outside and "}" not in outside and "```" not in outside:
            return candidate

    start = text.find("{")
    if start >= 0:
        try:
            value, consumed = json.JSONDecoder().raw_decode(text[start:])
        except (TypeError, ValueError, json.JSONDecodeError):
            value, consumed = None, 0
        prefix = text[:start]
        suffix = text[start + consumed:]
        if (
            isinstance(value, dict)
            and "{" not in prefix
            and "}" not in prefix
            and "{" not in suffix
            and "}" not in suffix
            and "```" not in prefix
            and "```" not in suffix
        ):
            return value
    raise RuntimeFailure(error_code)


def _semantic_attempt_receipt(facts: dict[str, Any], error_code: str | None) -> dict[str, Any]:
    return {
        "error_code": error_code,
        "provider_http_status": facts.get("provider_http_status"),
        "provider_response_bytes": facts.get("provider_response_bytes") or facts.get("response_bytes"),
        "provider_response_sha256": facts.get("provider_response_sha256") or facts.get("response_sha256"),
        "provider_request_id": facts.get("provider_request_id"),
        "provider_envelope": facts.get("provider_envelope"),
        "usage": facts.get("provider_usage") or {
            key: facts[key]
            for key in ("prompt_tokens", "completion_tokens", "total_tokens", "cost")
            if type(facts.get(key)) in {int, float}
        },
    }


@dataclass(frozen=True)
class SemanticResult:
    decision: dict[str, Any]
    provider: str
    model: str
    usage: dict[str, Any]


class SemanticAdapter(Protocol):
    name: str
    model: str

    def decide(self, request: dict[str, Any]) -> SemanticResult: ...


def validate_decision(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict) or frozenset(value) not in {
        frozenset(LEGACY_DECISION_FIELDS), frozenset(DECISION_FIELDS)
    }:
        raise RuntimeFailure("SEMANTIC_DECISION_INVALID")
    if value.get("schema") != TURN_SCHEMA or value.get("action") not in {
        "answer", "invoke", "clarify", "capability_gap"
    }:
        raise RuntimeFailure("SEMANTIC_DECISION_INVALID")
    if not isinstance(value.get("message"), str) or not 1 <= len(value["message"]) <= 4000:
        raise RuntimeFailure("SEMANTIC_DECISION_INVALID")
    action = value["action"]
    clarification = value.get("clarification")
    if action == "invoke":
        if (
            not isinstance(value["capability_id"], str)
            or not isinstance(value["input"], dict)
            or not isinstance(value["resources"], list)
            or not all(isinstance(item, str) for item in value["resources"])
            or len(value["resources"]) != len(set(value["resources"]))
            or value["gap"] is not None
            or clarification is not None
        ):
            raise RuntimeFailure("SEMANTIC_DECISION_INVALID")
    elif action == "capability_gap":
        gap = value["gap"]
        if (
            value["capability_id"] is not None
            or value["input"] != {}
            or value["resources"] != []
            or not isinstance(gap, dict)
            or set(gap) != {"needed_ability", "desired_result", "missing_information"}
            or not all(isinstance(gap.get(key), str) and gap[key] for key in ("needed_ability", "desired_result"))
            or not isinstance(gap.get("missing_information"), list)
            or not all(isinstance(item, str) for item in gap["missing_information"])
            or clarification is not None
        ):
            raise RuntimeFailure("SEMANTIC_DECISION_INVALID")
    elif action == "clarify":
        if (
            not isinstance(value["capability_id"], str)
            or value["input"] != {}
            or value["resources"] != []
            or value["gap"] is not None
            or not isinstance(clarification, dict)
            or set(clarification) != {"missing_input_fields"}
            or not isinstance(clarification["missing_input_fields"], list)
            or not clarification["missing_input_fields"]
            or not all(
                isinstance(item, str) and item
                for item in clarification["missing_input_fields"]
            )
            or len(clarification["missing_input_fields"])
            != len(set(clarification["missing_input_fields"]))
        ):
            raise RuntimeFailure("SEMANTIC_DECISION_INVALID")
    elif (
        value["capability_id"] is not None
        or value["input"] != {}
        or value["resources"] != []
        or value["gap"] is not None
        or clarification is not None
    ):
        raise RuntimeFailure("SEMANTIC_DECISION_INVALID")
    return value


def validate_decision_for_world(value: Any, world: dict[str, Any]) -> dict[str, Any]:
    """Apply the live-world semantic shape without treating it as authority."""

    decision = validate_decision(value)
    if decision["action"] == "clarify":
        capabilities = {item["id"]: item for item in world.get("capabilities", [])}
        capability = capabilities.get(decision["capability_id"])
        if capability is None:
            raise RuntimeFailure("TURN_CAPABILITY_NOT_IN_WORLD")
        input_schema = capability.get("input_schema")
        if not isinstance(input_schema, dict) or input_schema.get("type") != "object":
            raise RuntimeFailure("SEMANTIC_DECISION_CLARIFICATION_INVALID")
        properties = input_schema.get("properties")
        required = input_schema.get("required")
        if not isinstance(properties, dict) or not isinstance(required, list):
            raise RuntimeFailure("SEMANTIC_DECISION_CLARIFICATION_INVALID")
        missing = decision["clarification"]["missing_input_fields"]
        if any(field not in properties or field not in required for field in missing):
            raise RuntimeFailure("SEMANTIC_DECISION_CLARIFICATION_INVALID")
        return decision
    if decision["action"] != "invoke":
        return decision
    capabilities = {item["id"]: item for item in world.get("capabilities", [])}
    capability = capabilities.get(decision["capability_id"])
    if capability is None:
        raise RuntimeFailure("TURN_CAPABILITY_NOT_IN_WORLD")
    validate_json(
        decision["input"],
        capability["input_schema"],
        "SEMANTIC_DECISION_INPUT_SCHEMA_MISMATCH",
    )
    visible = {item["handle"] for item in world.get("resources", [])}
    if not set(decision["resources"]) <= visible:
        raise RuntimeFailure("TURN_RESOURCE_NOT_VISIBLE")
    return decision


def decision_schema_for_world(world: dict[str, Any]) -> dict[str, Any]:
    """Build strict action branches from the exact current capability world."""

    resource_handles = [item["handle"] for item in world.get("resources", [])]

    def object_branch(properties: dict[str, Any]) -> dict[str, Any]:
        return {
            "type": "object",
            "additionalProperties": False,
            "required": [
                "schema", "action", "message", "capability_id", "input", "resources", "gap",
                "clarification",
            ],
            "properties": properties,
        }

    common = {
        "schema": {"type": "string", "const": TURN_SCHEMA},
        "message": {"type": "string", "minLength": 1, "maxLength": 4000},
    }
    empty_input = {"type": "object", "properties": {}, "additionalProperties": False}
    empty_resources = {"type": "array", "items": {"type": "string", "enum": []}}
    null = {"type": "null"}
    branches = []
    branches.append(object_branch({
        **common,
        "action": {"type": "string", "const": "answer"},
        "capability_id": null,
        "input": empty_input,
        "resources": empty_resources,
        "gap": null,
        "clarification": null,
    }))
    for capability in world.get("capabilities", []):
        required_fields = list(capability.get("input_schema", {}).get("required", []))
        if not required_fields:
            continue
        branches.append(object_branch({
            **common,
            "action": {"type": "string", "const": "clarify"},
            "capability_id": {"type": "string", "const": capability["id"]},
            "input": empty_input,
            "resources": empty_resources,
            "gap": null,
            "clarification": {
                "type": "object",
                "additionalProperties": False,
                "required": ["missing_input_fields"],
                "properties": {
                    "missing_input_fields": {
                        "type": "array",
                        "minItems": 1,
                        "items": {"type": "string", "enum": required_fields},
                    }
                },
            },
        }))
    gap_schema = {
        "type": "object",
        "additionalProperties": False,
        "required": ["needed_ability", "desired_result", "missing_information"],
        "properties": {
            "needed_ability": {"type": "string"},
            "desired_result": {"type": "string"},
            "missing_information": {
                "type": "array",
                "items": {"type": "string"},
                "description": (
                    "Owner-supplied facts or files still required to perform the requested outcome. "
                    "Software or capability absence is not missing information. Use [] when the visible "
                    "resources already provide the requested inputs."
                ),
            },
        },
    }
    branches.append(object_branch({
        **common,
        "action": {"type": "string", "const": "capability_gap"},
        "capability_id": null,
        "input": empty_input,
        "resources": empty_resources,
        "gap": gap_schema,
        "clarification": null,
    }))
    for capability in world.get("capabilities", []):
        branches.append(object_branch({
            **common,
            "action": {"type": "string", "const": "invoke"},
            "capability_id": {"type": "string", "const": capability["id"]},
            "input": capability["input_schema"],
            "resources": {
                "type": "array",
                "items": {"type": "string", "enum": resource_handles},
            },
            "gap": null,
            "clarification": null,
        }))
    return {"oneOf": branches}


def provider_decision_schema_for_world(world: dict[str, Any]) -> dict[str, Any]:
    """Return a root-object schema accepted by structured-output providers.

    Relational authority remains in ``validate_decision_for_world``. This
    provider schema narrows every field and embeds the live capability input
    schemas without using a top-level union.
    """

    capabilities = world.get("capabilities", [])
    resource_handles = [item["handle"] for item in world.get("resources", [])]
    capability_ids = [item["id"] for item in capabilities]
    clarification_fields = sorted({
        field
        for item in capabilities
        for field in item.get("input_schema", {}).get("required", [])
    })
    input_schemas = [
        {"type": "object", "properties": {}, "additionalProperties": False},
        *[_provider_input_schema(item) for item in capabilities],
    ]
    gap_schema = {
        "type": "object",
        "additionalProperties": False,
        "required": ["needed_ability", "desired_result", "missing_information"],
        "properties": {
            "needed_ability": {"type": "string"},
            "desired_result": {"type": "string"},
            "missing_information": {
                "type": "array",
                "items": {"type": "string"},
                "description": (
                    "Owner-supplied facts or files still required to perform the requested outcome. "
                    "Software or capability absence is not missing information. Use [] when the visible "
                    "resources already provide the requested inputs."
                ),
            },
        },
    }
    return {
        "type": "object",
        "additionalProperties": False,
        "required": [
            "schema", "action", "message", "capability_id", "input", "resources", "gap",
            "clarification",
        ],
        "properties": {
            "schema": {"type": "string", "const": TURN_SCHEMA},
            "action": {
                "type": "string",
                "enum": ["answer", "invoke", "clarify", "capability_gap"],
                "description": "Choose exactly one action and obey its field invariants.",
            },
            "message": {
                "type": "string",
                "minLength": 1,
                "maxLength": 4000,
                "description": "A non-empty bounded owner-facing sentence for this decision.",
            },
            "capability_id": {
                "description": "Non-null only for invoke or clarify; null for all other actions.",
                "anyOf": [
                    {"type": "null"},
                    {"type": "string", "enum": capability_ids},
                ]
            },
            "input": {
                "description": "Capability input only for invoke; otherwise exactly {}.",
                "anyOf": input_schemas,
            },
            "resources": {
                "type": "array",
                "items": {"type": "string", "enum": resource_handles},
                "description": "Visible resource handles only for invoke; otherwise exactly [].",
            },
            "gap": {
                "description": "Gap object only for capability_gap; null for all other actions.",
                "anyOf": [{"type": "null"}, gap_schema],
            },
            "clarification": {
                "description": (
                    "For clarify only: one target capability's non-empty unique missing required "
                    "top-level input fields. Null for every other action."
                ),
                "anyOf": [
                    {"type": "null"},
                    {
                        "type": "object",
                        "additionalProperties": False,
                        "required": ["missing_input_fields"],
                        "properties": {
                            "missing_input_fields": {
                                "type": "array",
                                "minItems": 1,
                                "items": {"type": "string", "enum": clarification_fields},
                            }
                        },
                    },
                ],
            },
        },
    }


def _provider_input_schema(capability: dict[str, Any]) -> dict[str, Any]:
    """Recursively project an immutable descriptor into provider-strict form.

    Structured-output providers require every declared object property to be
    required. Descriptor-optional properties are therefore represented as
    value-or-null on the wire and removed again before trusted validation.
    """

    return _provider_strict_schema(capability["input_schema"])


def _provider_strict_schema(schema: dict[str, Any]) -> dict[str, Any]:
    projected = copy.deepcopy(schema)
    if projected.get("type") == "object":
        properties = projected.get("properties", {})
        originally_required = set(projected.get("required", []))
        strict_properties = {}
        for name, child in properties.items():
            strict_child = _provider_strict_schema(child)
            strict_properties[name] = (
                strict_child
                if name in originally_required
                else {"anyOf": [strict_child, {"type": "null"}]}
            )
        projected["properties"] = strict_properties
        projected["required"] = list(properties)
        projected["additionalProperties"] = False
    elif projected.get("type") == "array" and isinstance(projected.get("items"), dict):
        projected["items"] = _provider_strict_schema(projected["items"])
    return projected


def normalize_provider_decision_for_world(
    value: Any, world: dict[str, Any]
) -> dict[str, Any]:
    """Remove provider-only null placeholders, then apply live-world validation."""

    decision = validate_decision(value)
    if decision["action"] != "invoke":
        return validate_decision_for_world(decision, world)
    capability = next(
        (item for item in world.get("capabilities", []) if item["id"] == decision["capability_id"]),
        None,
    )
    if capability is None:
        raise RuntimeFailure("TURN_CAPABILITY_NOT_IN_WORLD")
    normalized = copy.deepcopy(decision)
    normalized["input"] = _remove_optional_nulls(
        normalized["input"], capability["input_schema"]
    )
    return validate_decision_for_world(normalized, world)


def _remove_optional_nulls(value: Any, schema: dict[str, Any]) -> Any:
    if schema.get("type") == "object" and isinstance(value, dict):
        properties = schema.get("properties", {})
        required = set(schema.get("required", []))
        result = {}
        for name, child in value.items():
            if name in properties and child is None and name not in required:
                continue
            result[name] = (
                _remove_optional_nulls(child, properties[name])
                if name in properties else child
            )
        return result
    if schema.get("type") == "array" and isinstance(value, list) and isinstance(schema.get("items"), dict):
        return [_remove_optional_nulls(item, schema["items"]) for item in value]
    return value


def _normalize_route_projection(value: Any) -> Any:
    """Defer input clarification from the input-free route to the exact operation stage."""

    if not isinstance(value, dict):
        return value
    if (
        value.get("action") == "clarify"
        and isinstance(value.get("capability_id"), str)
        and value.get("input") == {}
        and value.get("resources") == []
        and value.get("gap") is None
        and value.get("clarification") is None
    ):
        normalized = copy.deepcopy(value)
        normalized["action"] = "invoke"
        return normalized
    return value


def _safe_decision_shape(value: Any) -> dict[str, Any]:
    """Return only bounded structural facts, never model-authored prose or input values."""

    if not isinstance(value, dict):
        return {"type": type(value).__name__}
    action = value.get("action")
    capability_id = value.get("capability_id")
    input_value = value.get("input")
    return {
        "type": "object",
        "keys": sorted(str(key)[:80] for key in value)[:24],
        "action": action if action in {"answer", "invoke", "clarify", "capability_gap"} else "invalid",
        "capability_id": capability_id if isinstance(capability_id, str) and len(capability_id) <= 200 else None,
        "input_keys": sorted(str(key)[:80] for key in value.get("input", {}))[:32]
        if isinstance(value.get("input"), dict) else None,
        "input_shape": _safe_value_shape(input_value, depth=0),
        "resource_count": len(value.get("resources", []))
        if isinstance(value.get("resources"), list) else None,
        "gap_type": type(value.get("gap")).__name__,
        "clarification_type": type(value.get("clarification")).__name__,
    }


def _safe_value_shape(value: Any, *, depth: int) -> Any:
    if depth >= 4:
        return {"type": type(value).__name__}
    if isinstance(value, dict):
        return {
            "type": "object",
            "fields": {
                str(key)[:80]: _safe_value_shape(item, depth=depth + 1)
                for key, item in sorted(value.items(), key=lambda pair: str(pair[0]))[:32]
            },
        }
    if isinstance(value, list):
        return {
            "type": "array", "count": len(value),
            "item_types": sorted({type(item).__name__ for item in value})[:8],
        }
    return {"type": type(value).__name__}


class FixtureAdapter:
    name = "fixture"
    model = "fixture"

    def __init__(self, decisions: list[dict[str, Any]]):
        self.decisions = list(decisions)
        self.calls: list[dict[str, Any]] = []

    def decide(self, request: dict[str, Any]) -> SemanticResult:
        self.calls.append(request)
        if not self.decisions:
            raise RuntimeFailure("SEMANTIC_PROVIDER_ERROR")
        return SemanticResult(validate_decision(self.decisions.pop(0)), self.name, self.model, {})


class OpenRouterLunaAdapter:
    name = "openrouter"
    model = MODEL
    # Provider-enforced structured output is not an authority boundary.  One
    # ordinary response is parsed and validated locally before trusted code may
    # select an exact operation.
    two_stage_operations = False

    def __init__(self, credential: Path, timeout_seconds: int = 60, opener=None):
        self.credential = credential
        self.timeout_seconds = timeout_seconds
        self.opener = opener or urllib.request.urlopen

    def _credential(self) -> str:
        try:
            metadata = self.credential.lstat()
            value = self.credential.read_text(encoding="utf-8").strip()
        except OSError as exc:
            raise RuntimeFailure("SEMANTIC_CREDENTIAL_UNAVAILABLE") from exc
        if (
            self.credential.is_symlink()
            or not self.credential.is_file()
            or metadata.st_mode & 0o777 not in {0o400, 0o440, 0o600}
            or not value
        ):
            raise RuntimeFailure("SEMANTIC_CREDENTIAL_INVALID")
        return value

    def decide(self, request: dict[str, Any]) -> SemanticResult:
        return self._decide_with_repair(request)

    def _decide_with_repair(self, request: dict[str, Any], **kwargs: Any) -> SemanticResult:
        try:
            return self._one_attempt_result(self._decide_once(request, **kwargs))
        except RuntimeFailure as exc:
            if exc.code not in REPAIRABLE_PROPOSAL_CODES:
                raise
            first_code = exc.code
            first_receipt = _semantic_attempt_receipt(exc.safe_facts, exc.code)
        try:
            repaired = self._decide_once(request, repair_code=first_code, **kwargs)
        except RuntimeFailure as second:
            facts = dict(second.safe_facts)
            receipts = [first_receipt, _semantic_attempt_receipt(facts, second.code)]
            totals = self._sum_attempt_usage(receipts)
            facts.update({
                **totals,
                "semantic_attempt_count": 2,
                "semantic_retry_used": True,
                "semantic_attempts": receipts,
            })
            raise RuntimeFailure(second.code, second.detail, safe_facts=facts) from second
        receipts = [first_receipt, _semantic_attempt_receipt(repaired.usage, None)]
        usage = dict(repaired.usage)
        usage.update(self._sum_attempt_usage(receipts))
        usage.update({
            "semantic_attempt_count": 2,
            "semantic_retry_used": True,
            "semantic_attempts": receipts,
        })
        return SemanticResult(repaired.decision, repaired.provider, repaired.model, usage)

    @staticmethod
    def _sum_attempt_usage(receipts: list[dict[str, Any]]) -> dict[str, Any]:
        totals: dict[str, Any] = {}
        for field in ("prompt_tokens", "completion_tokens", "total_tokens", "cost"):
            values = [
                receipt.get("usage", {}).get(field)
                for receipt in receipts
                if type(receipt.get("usage", {}).get(field)) in {int, float}
            ]
            if values:
                totals[field] = sum(values)
        return totals

    @staticmethod
    def _one_attempt_result(result: SemanticResult) -> SemanticResult:
        usage = dict(result.usage)
        usage.update({
            "semantic_attempt_count": 1,
            "semantic_retry_used": False,
            "semantic_attempts": [_semantic_attempt_receipt(result.usage, None)],
        })
        return SemanticResult(result.decision, result.provider, result.model, usage)

    def decide_route(self, request: dict[str, Any]) -> SemanticResult:
        """Select the outcome/action without asking for operation arguments."""

        route_world = copy.deepcopy(request["world"])
        for capability in route_world.get("capabilities", []):
            capability["input_schema"] = {
                "type": "object", "properties": {}, "additionalProperties": False,
            }
        # Kept for compatibility with recorded two-stage jobs. New production
        # requests use the single locally validated proposal path.
        return self._decide_with_repair(
            request, schema_world=route_world, route_only=True
        )

    def decide_operation(
        self, request: dict[str, Any], route_decision: dict[str, Any]
    ) -> SemanticResult:
        """Produce input against exactly one already selected operation schema."""

        capability_id = route_decision.get("capability_id")
        narrowed = copy.deepcopy(request)
        capabilities = [
            item for item in narrowed.get("world", {}).get("capabilities", [])
            if item.get("id") == capability_id
        ]
        if len(capabilities) != 1:
            raise RuntimeFailure("TURN_CAPABILITY_NOT_IN_WORLD")
        narrowed["world"]["capabilities"] = capabilities
        narrowed["conversation"] = [
            *narrowed.get("conversation", []),
            {
                "role": "semantic_route",
                "decision": {
                    key: copy.deepcopy(route_decision.get(key))
                    for key in (
                        "schema", "action", "message", "capability_id", "resources",
                        "gap", "clarification",
                    )
                },
            },
        ]
        return self.decide(narrowed)

    def _decide_once(
        self, request: dict[str, Any], *, schema_world: dict[str, Any] | None = None,
        route_only: bool = False, repair_code: str | None = None,
    ) -> SemanticResult:
        if set(request) != {"schema", "owner_message", "conversation", "world"} or request["schema"] != "capy.semantic-request/v0":
            raise RuntimeFailure("SEMANTIC_REQUEST_INVALID")
        request = _narrow_interaction_contracts(request)
        if schema_world is not None:
            schema_world = _narrow_interaction_contracts({
                **request, "world": schema_world,
            })["world"]
        validation_world = schema_world or request["world"]
        system = system_instruction()
        if repair_code is not None:
            system += (
                " The previous response was rejected before execution because its JSON syntax or outer "
                "decision shape was invalid. Re-evaluate the original request and return one corrected "
                "object. Do not repeat, quote, or discuss the previous response."
            )
        payload = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": json.dumps(request, ensure_ascii=False, sort_keys=True, separators=(",", ":"))},
            ],
            "max_completion_tokens": 800,
        }
        request_bytes = json.dumps(
            request, ensure_ascii=False, sort_keys=True, separators=(",", ":")
        ).encode()
        prompt_bytes = json.dumps(
            payload["messages"], ensure_ascii=False, sort_keys=True, separators=(",", ":")
        ).encode()
        request_facts = {
            "semantic_request_sha256": hashlib.sha256(request_bytes).hexdigest(),
            "semantic_request_bytes": len(request_bytes),
            "prompt_sha256": hashlib.sha256(prompt_bytes).hexdigest(),
            "prompt_bytes": len(prompt_bytes),
        }
        credential = self._credential()
        wire = urllib.request.Request(
            ENDPOINT,
            data=json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode(),
            headers={
                "Authorization": f"Bearer {credential}",
                "Content-Type": "application/json",
                "User-Agent": "capy-outcome-runtime-m2/0.1",
            },
            method="POST",
        )
        try:
            with self.opener(wire, timeout=self.timeout_seconds) as response:
                raw = response.read(128 * 1024 + 1)
                envelope_facts = safe_provider_envelope_facts(raw, response)
        except urllib.error.HTTPError as exc:
            code = "SEMANTIC_PROVIDER_RATE_LIMIT" if exc.code == 429 else (
                "SEMANTIC_PROVIDER_TEMPORARY" if 500 <= exc.code <= 599 else "SEMANTIC_PROVIDER_HTTP"
            )
            retry_after = None
            if exc.headers is not None:
                value = exc.headers.get("retry-after")
                if isinstance(value, str) and value.isdigit():
                    retry_after = min(int(value), 3600)
            exc.close()
            raise RuntimeFailure(
                code, str(exc.code),
                safe_facts={
                    **request_facts, "provider_http_status": exc.code,
                    "provider_retry_after_seconds": retry_after,
                },
            ) from exc
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            raise RuntimeFailure("SEMANTIC_PROVIDER_ERROR", safe_facts=request_facts) from exc
        finally:
            credential = ""
        if len(raw) > 128 * 1024:
            raise RuntimeFailure(
                "SEMANTIC_PROVIDER_RESPONSE_TOO_LARGE",
                safe_facts={
                    **request_facts,
                    **envelope_facts,
                    "semantic_response_sha256": hashlib.sha256(raw).hexdigest(),
                    "semantic_response_bytes": len(raw),
                },
            )
        envelope = envelope_facts.get("provider_envelope") or {}
        if envelope.get("error_present") is True:
            provider_code = envelope.get("error_code")
            if provider_code in {429, "429"}:
                code = "SEMANTIC_PROVIDER_RATE_LIMIT"
            elif provider_code in {500, 502, 503, 504, "500", "502", "503", "504"}:
                code = "SEMANTIC_PROVIDER_TEMPORARY"
            else:
                code = "SEMANTIC_PROVIDER_ERROR_ENVELOPE"
            raise RuntimeFailure(code, safe_facts={
                **request_facts, **envelope_facts,
                "semantic_response_sha256": hashlib.sha256(raw).hexdigest(),
                "semantic_response_bytes": len(raw),
            })
        try:
            provider_response = json.loads(raw)
            content = provider_response["choices"][0]["message"]["content"]
            parsed_content = extract_single_json_object(
                content, "SEMANTIC_PROVIDER_RESPONSE_INVALID"
            )
            if route_only:
                parsed_content = _normalize_route_projection(parsed_content)
            decision = normalize_provider_decision_for_world(
                parsed_content, validation_world
            )
        except RuntimeFailure as exc:
            raise RuntimeFailure(
                exc.code,
                exc.detail,
                safe_facts={
                    **request_facts,
                    **envelope_facts,
                    "semantic_response_sha256": hashlib.sha256(raw).hexdigest(),
                    "semantic_response_bytes": len(raw),
                    "semantic_failure_shape": _safe_decision_shape(
                        parsed_content if "parsed_content" in locals() else None
                    ),
                },
            ) from exc
        except (KeyError, IndexError, TypeError, ValueError, json.JSONDecodeError) as exc:
            raise RuntimeFailure(
                "SEMANTIC_PROVIDER_RESPONSE_INVALID",
                safe_facts={
                    **request_facts,
                    **envelope_facts,
                    "semantic_response_sha256": hashlib.sha256(raw).hexdigest(),
                    "semantic_response_bytes": len(raw),
                },
            ) from exc
        raw_usage = provider_response.get("usage") or {}
        usage = {
            key: raw_usage[key]
            for key in ("prompt_tokens", "completion_tokens", "total_tokens", "cost")
            if type(raw_usage.get(key)) in {int, float}
        }
        response_bytes = content.encode("utf-8")
        usage.update({
            "semantic_request_sha256": hashlib.sha256(request_bytes).hexdigest(),
            "semantic_request_bytes": len(request_bytes),
            "prompt_sha256": hashlib.sha256(prompt_bytes).hexdigest(),
            "prompt_bytes": len(prompt_bytes),
            "response_sha256": hashlib.sha256(response_bytes).hexdigest(),
            "response_bytes": len(response_bytes),
            **envelope_facts,
        })
        return SemanticResult(decision, self.name, provider_response.get("model") or self.model, usage)


def system_instruction() -> str:
    """Return the stable domain-neutral Luna instruction used for prompt receipts."""

    return (
        "You are Capy's bounded outcome-language component. Return exactly one compact JSON object and "
        "nothing else: no markdown fence, commentary, preface, or suffix. The object must contain exactly "
        "schema, action, message, capability_id, input, resources, gap, and clarification. Set schema exactly "
        "to capy.chat-turn/v0. Set action to exactly one of answer, invoke, clarify, or capability_gap. Respond inside "
        "the message field in the owner's language when practical. "
        "Use only the supplied conversation, current world, and exact interaction contract when present. "
        "The contract is authoritative for purpose, human fields, enforced constraints versus preferences, "
        "authority, effects, source behavior, results, boundaries, and nearby installed operations. "
        "You have no shell, Git, source, logs, browser, "
        "arbitrary filesystem, other-scope data, or credentials. Invoke only an exact currently bound capability "
        "and only visible resource handles. Use capability_gap when software is absent or the request is outside "
        "the installed contract, including FedEx. Never propose building software, invoking Codex, creating a "
        "repository or Git authority, publishing software, or retrying with newly built software. "
        "Never claim that software ran, an artifact exists, state changed, or an external action happened. "
        "Mandatory field invariants: answer uses capability_id=null, input={}, resources=[], gap=null, "
        "clarification=null. Clarify uses one bound capability_id, input={}, resources=[], gap=null, and a "
        "non-empty unique clarification.missing_input_fields list containing only required top-level fields "
        "that the owner has not supplied. Copy those names exactly from that capability's input_schema.required; "
        "when a nested value is missing, list its required top-level parent object, never a dotted path. "
        "Invoke uses clarification=null. "
        "capability_gap uses capability_id=null, input={}, resources=[], and one non-null gap object even when "
        "attachments are visible; invoke uses one bound capability_id, its exact input, only selected visible "
        "resource handles, and gap=null. For capability_gap, missing_information lists only owner facts or files "
        "still needed to perform the request. Missing software belongs in needed_ability, never in "
        "missing_information. When the visible resources already supply the requested inputs, use "
        "missing_information=[]. When clarification is required, identify the exact material information "
        "missing from the visible application contract. When an owner replies after clarification, combine the "
        "conversation with the current message and reuse an already visible required resource instead of asking "
        "for reattachment. When installed application operations are exposed as separate capabilities, select "
        "the exact existing operation that directly completes the requested outcome instead of reporting missing "
        "software. Do not choose a list or status operation as a preparatory lookup for a requested mutation; the "
        "application adapter resolves bounded selectors against visible state. Choose a creation operation only "
        "when the owner requests a new object. A request that changes criteria, behavior, focus, or attention for "
        "a referred existing object must use that application's update operation, not create. Resolve ordinary references from "
        "the visible conversation into the operation's bounded selector fields; never invent an exact object ID."
    )


def _narrow_interaction_contracts(request: dict[str, Any]) -> dict[str, Any]:
    """Expose at most one relevant detailed contract to the semantic provider."""

    world = request.get("world")
    if not isinstance(world, dict) or not isinstance(world.get("applications"), list):
        return request
    text = str(request.get("owner_message", "")).casefold()
    if any(word in text for word in ("invoice", "proforma", "csv", "excel", "spreadsheet")):
        wanted = "documents.proforma_invoice"
    elif any(word in text for word in (
        "watch", "encar", "jetta", "vehicle", "car", "mileage", "kilomet", "telegram",
    )):
        wanted = "vehicles.encar_watcher"
    else:
        wanted = None
    narrowed = copy.deepcopy(request)
    narrowed["world"]["applications"] = [
        item for item in narrowed["world"]["applications"]
        if item.get("application_id") == wanted
    ] if wanted else []
    return narrowed
