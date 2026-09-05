"""Trusted internal operation projection and dispatch for installed applications."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Any, Protocol

from .access import ActorContext
from .model import RuntimeFailure
from .store import canonical_json


@dataclass(frozen=True)
class OperationDescriptor:
    application_id: str
    application_version: str
    operation_id: str
    capability_id: str
    description: str
    input_schema: dict[str, Any]
    effect_class: str
    authority_policy: str
    source_behavior: str
    idempotency_policy: str
    safe_error_catalog: dict[str, str]
    result_schema: dict[str, Any]
    target_receipt_policy: str
    state_effect_policy: str
    presentation_kind: str

    def world_projection(self, maintainer_principal_id: str) -> dict[str, Any]:
        return {
            "id": self.capability_id,
            "version_digest": self.application_version,
            "description": self.description,
            "input_schema": self.input_schema,
            "result_schema": self.result_schema,
            "side_effect": self.effect_class,
            "connections": [],
            "resource_requirements": [],
            "state_required": True,
            "state_available": True,
            "source": "accepted-private-team-application-operation",
            "shared_by": maintainer_principal_id,
            "maintained_by": maintainer_principal_id,
            "available_to_members": True,
            "application_id": self.application_id,
            "operation_id": self.operation_id,
            "authority_policy": self.authority_policy,
            "source_behavior": self.source_behavior,
            "idempotency_policy": self.idempotency_policy,
            "target_receipt_policy": self.target_receipt_policy,
            "state_effect_policy": self.state_effect_policy,
            "presentation_kind": self.presentation_kind,
        }


@dataclass(frozen=True)
class OperationContext:
    actor: ActorContext
    conversation_id: str
    owner_text: str
    conversation: tuple[dict[str, str], ...]
    idempotency_key: str


class OperationAdapter(Protocol):
    application_id: str

    def descriptors(self, actor: ActorContext) -> list[OperationDescriptor]: ...

    def maintainer_principal_id(self, actor: ActorContext) -> str: ...

    def invoke(
        self,
        context: OperationContext,
        descriptor: OperationDescriptor,
        value: dict[str, Any],
    ) -> dict[str, Any]: ...


class ApplicationOperationRegistry:
    """Private registry; it is neither a public protocol nor an SDK contract."""

    def __init__(self, adapters: list[OperationAdapter]):
        self.adapters = {adapter.application_id: adapter for adapter in adapters}
        if len(self.adapters) != len(adapters):
            raise RuntimeFailure("APPLICATION_OPERATION_REGISTRY_INVALID")

    def _current(self, actor: ActorContext) -> dict[str, tuple[OperationAdapter, OperationDescriptor]]:
        result: dict[str, tuple[OperationAdapter, OperationDescriptor]] = {}
        for application_id in sorted(self.adapters):
            adapter = self.adapters[application_id]
            for descriptor in adapter.descriptors(actor):
                if (
                    descriptor.application_id != application_id
                    or descriptor.capability_id in result
                    or descriptor.effect_class not in {"read_only", "stateful_internal"}
                    or descriptor.target_receipt_policy not in {"none", "result_watch_id", "adapter_selected_watch"}
                    or descriptor.state_effect_policy not in {"read_only", "creates_state", "mutates_state"}
                ):
                    raise RuntimeFailure("APPLICATION_OPERATION_REGISTRY_INVALID")
                result[descriptor.capability_id] = (adapter, descriptor)
        return result

    def world_capabilities(self, actor: ActorContext) -> list[dict[str, Any]]:
        result = []
        for capability_id, (adapter, descriptor) in self._current(actor).items():
            result.append(
                descriptor.world_projection(adapter.maintainer_principal_id(actor))
            )
        return sorted(result, key=lambda item: item["id"])

    def has(self, actor: ActorContext, capability_id: str) -> bool:
        return capability_id in self._current(actor)

    def invoke(
        self,
        context: OperationContext,
        capability_id: str,
        expected_version: str,
        value: dict[str, Any],
    ) -> dict[str, Any]:
        current = self._current(context.actor)
        selected = current.get(capability_id)
        if selected is None:
            raise RuntimeFailure("APPLICATION_OPERATION_STALE")
        adapter, descriptor = selected
        if descriptor.application_version != expected_version:
            raise RuntimeFailure("APPLICATION_OPERATION_STALE")
        try:
            outcome = adapter.invoke(context, descriptor, value)
        except RuntimeFailure as exc:
            mapped = descriptor.safe_error_catalog.get(exc.code)
            if mapped is None:
                raise
            safe_facts = dict(exc.safe_facts)
            safe_facts.setdefault("application_calls", 1)
            safe_facts.setdefault(
                "source_calls", None if descriptor.operation_id == "watch.check_now" else 0
            )
            safe_facts.setdefault(
                "effect_count", None if descriptor.effect_class != "read_only" else 0
            )
            safe_facts.setdefault("execution_phase", "pre_execution")
            raise RuntimeFailure(mapped, safe_facts=safe_facts) from exc
        if (
            not isinstance(outcome, dict)
            or set(outcome) != {
                "result", "text", "source_checked", "state_changed", "effect_count",
                "target_receipt", "execution_phase",
            }
            or not isinstance(outcome["result"], dict)
            or not isinstance(outcome["text"], str)
            or type(outcome["source_checked"]) is not bool
            or type(outcome["state_changed"]) is not bool
            or type(outcome["effect_count"]) is not int
            or outcome["execution_phase"] != "completed"
            or not self._result_valid(descriptor, outcome)
        ):
            raise RuntimeFailure("APPLICATION_INVALID_RESPONSE", safe_facts={
                "application_calls": 1,
                "source_calls": (
                    1 if isinstance(outcome, dict) and outcome.get("source_checked") is True
                    else 0 if isinstance(outcome, dict) and outcome.get("source_checked") is False
                    else None
                ),
                "effect_count": outcome.get("effect_count") if isinstance(outcome, dict) else None,
                "execution_phase": "executed_result_invalid",
            })
        receipt = hashlib.sha256(canonical_json({
            "application_id": descriptor.application_id,
            "application_version": descriptor.application_version,
            "operation_id": descriptor.operation_id,
            "idempotency_key": context.idempotency_key,
            "result": outcome["result"],
            "source_checked": outcome["source_checked"],
            "state_changed": outcome["state_changed"],
            "effect_count": outcome["effect_count"],
            "target_receipt": outcome["target_receipt"],
            "execution_phase": outcome["execution_phase"],
        })).hexdigest()
        return {
            "application_id": descriptor.application_id,
            "application_version": descriptor.application_version,
            "operation_id": descriptor.operation_id,
            "operation_receipt": receipt,
            "presentation_kind": descriptor.presentation_kind,
            **outcome,
        }

    @staticmethod
    def _result_valid(descriptor: OperationDescriptor, outcome: dict[str, Any]) -> bool:
        if not _matches_schema(outcome["result"], descriptor.result_schema):
            return False
        target = outcome["target_receipt"]
        if descriptor.target_receipt_policy == "none":
            if target is not None:
                return False
        elif not isinstance(target, dict) or not isinstance(target.get("watch_id"), str):
            return False
        elif descriptor.target_receipt_policy == "result_watch_id" and outcome["result"].get("watch_id") != target["watch_id"]:
            return False
        changed = outcome["state_changed"]
        if descriptor.state_effect_policy == "read_only" and changed:
            return False
        if descriptor.state_effect_policy in {"creates_state", "mutates_state"} and not changed:
            return False
        return True


def _matches_schema(value: Any, schema: dict[str, Any]) -> bool:
    """Validate the small, private descriptor-schema subset used by V0R."""
    expected = schema.get("type")
    if expected == "object":
        if not isinstance(value, dict):
            return False
        properties = schema.get("properties", {})
        if schema.get("additionalProperties") is False and set(value) - set(properties):
            return False
        if any(key not in value for key in schema.get("required", [])):
            return False
        return all(key not in properties or _matches_schema(item, properties[key]) for key, item in value.items())
    if expected == "string" and not isinstance(value, str):
        return False
    if expected == "integer" and type(value) is not int:
        return False
    if expected == "boolean" and type(value) is not bool:
        return False
    if "enum" in schema and value not in schema["enum"]:
        return False
    return True
