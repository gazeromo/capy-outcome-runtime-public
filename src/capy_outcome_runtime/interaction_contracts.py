"""Private, exact human interaction contracts for installed applications."""

from __future__ import annotations

import copy
import hashlib
from typing import Any

from .model import RuntimeFailure
from .store import canonical_json


SCHEMA = "capy.application-interaction/v0"
WATCHER_ID = "vehicles.encar_watcher"
PROFORMA_ID = "documents.proforma_invoice"


def _field(
    field_id: str,
    label: str,
    description: str,
    *,
    required: bool,
    kind: str = "text",
    semantic: str = "enforced",
    default: Any = None,
    examples: tuple[str, ...] = (),
) -> dict[str, Any]:
    return {
        "field_id": field_id,
        "label": label,
        "description": description,
        "required": required,
        "input_kind": kind,
        "semantic": semantic,
        "safe_default": default,
        "examples": list(examples),
        "clarification_question": f"What {label} should I use?",
    }


def _watcher_contract(capabilities: list[dict[str, Any]]) -> dict[str, Any] | None:
    projected = [item for item in capabilities if item.get("application_id") == WATCHER_ID]
    if not projected:
        return None
    versions = {item.get("version_digest") for item in projected}
    if len(versions) != 1:
        raise RuntimeFailure("INTERACTION_CONTRACT_VERSION_MISMATCH")
    by_operation = {item.get("operation_id"): item for item in projected}
    expected = {
        "watch.create", "watch.list", "watch.listings", "watch.status", "watch.pause", "watch.resume",
        "watch.update", "watch.delete", "watch.check_now",
    }
    if set(by_operation) != expected:
        raise RuntimeFailure("INTERACTION_CONTRACT_OPERATION_MISMATCH")

    selector = [
        _field(
            "selector", "watch to use",
            "Describe one visible watch by make, model, visibility, ownership, or person; Capy resolves its internal identity.",
            required=True, examples=("my Volkswagen Jetta watch", "the team Genesis G70 watch"),
        )
    ]
    create = [
        _field("hard_filters.source", "vehicle source", "The installed application supports Encar.", required=True, kind="choice", default="encar", examples=("Encar",)),
        _field("hard_filters.make", "make", "Vehicle manufacturer enforced by the source query.", required=True, examples=("Volkswagen",)),
        _field("hard_filters.model", "model", "Vehicle model enforced by the source query.", required=True, examples=("Jetta",)),
        _field("hard_filters.min_year", "earliest year", "Inclusive earliest model year.", required=True, kind="number", examples=("2020",)),
        _field("hard_filters.max_year", "latest year", "Inclusive latest model year.", required=True, kind="number", examples=("2024",)),
        _field(
            "attention_intent", "attention preferences",
            "Optional judgment guidance such as low price or mileage; it is not a hard source filter.",
            required=False, kind="long_text", semantic="preference",
            default="Highlight matching listings that materially deserve attention.",
            examples=("Prefer lower price and mileage",),
        ),
    ]
    update = selector + [
        _field("changes.min_year", "earliest year", "Optional inclusive earliest year.", required=False, kind="number"),
        _field("changes.max_year", "latest year", "Optional inclusive latest year.", required=False, kind="number"),
        _field("changes.attention_intent", "attention preferences", "Optional judgment guidance, not a hard filter.", required=False, kind="long_text", semantic="preference"),
    ]

    def operation(
        operation_id: str,
        title: str,
        outcome: str,
        fields: list[dict[str, Any]],
        examples: tuple[str, ...],
        misunderstandings: tuple[str, ...] = (),
        context_fields: tuple[dict[str, Any], ...] = (),
    ) -> dict[str, Any]:
        execution = by_operation[operation_id]
        mutating = execution["state_effect_policy"] != "read_only"
        return {
            "operation_id": operation_id,
            "capability_id": execution["id"],
            "title": title,
            "user_outcome": outcome,
            "description": execution["description"],
            "human_fields": copy.deepcopy(fields),
            "context_fields": copy.deepcopy(list(context_fields)),
            "safe_defaults": {
                item["field_id"]: item["safe_default"]
                for item in fields if item["safe_default"] is not None
            },
            "authority": {
                "required_role": "current active workspace member with access to the selected watch; team-watch mutation may require owner or creator authority" if mutating else "current active workspace member with visibility",
                "policy": execution["authority_policy"],
            },
            "effects": {
                "effect_class": execution["side_effect"],
                "state_effect": execution["state_effect_policy"],
                "source_behavior": execution["source_behavior"],
            },
            "examples": list(examples),
            "common_misunderstandings": list(misunderstandings),
            "result": {
                "presentation": execution["presentation_kind"],
                "facts": list(execution["result_schema"].get("properties", {})),
                "artifacts": [],
            },
        }

    return {
        "schema": SCHEMA,
        "application_id": WATCHER_ID,
        "application_version": versions.pop(),
        "title": "Encar vehicle watcher",
        "purpose": "Keep an ongoing watch for matching Encar vehicle listings in the current Personal or Team workspace.",
        "not_for": [
            "one-time market search", "seller contact or purchase", "external alert delivery",
            "arbitrary schedules", "hard price or mileage filtering",
        ],
        "operations": [
            operation("watch.create", "Create a watch", "Start one ongoing watch.", create,
                      ("Watch Volkswagen Jetta from 2020 through 2024.",),
                      (
                          "Creation does not immediately contact the source.",
                          "The current workspace determines whether the watch is Personal or Team; it is not a form field.",
                      ), ({
                          "field_id": "visibility",
                          "source": "current_workspace",
                          "mapping": {"personal": "personal", "team": "team"},
                      },)),
            operation("watch.list", "List watches", "See watches visible to you.", [
                _field("scope", "watch scope", "Personal, team, or all visible watches.", required=False, kind="choice", default="all", examples=("all",))
            ], ("Show my vehicle watches.",)),
            operation("watch.listings", "View listings", "See stored current listings and review history for one watch.", selector,
                      ("Show the listings from my Jetta watch.",),
                      ("Opening listings does not run a new source check.",)),
            operation("watch.status", "View watch status", "Read stored state and schedule.", selector, ("What is the status of my Jetta watch?",)),
            operation("watch.pause", "Pause a watch", "Pause one manageable watch.", selector, ("Pause my Jetta watch.",)),
            operation("watch.resume", "Resume a watch", "Resume one manageable watch.", selector, ("Resume the team G70 watch.",)),
            operation("watch.update", "Update a watch", "Change supported years or attention preferences.", update, ("Prefer lower-mileage listings for my Jetta watch.",)),
            operation("watch.delete", "Delete a watch", "Delete one manageable watch.", selector, ("Delete my Jetta watch.",)),
            operation("watch.check_now", "Check now", "Contact the source once for one active manageable watch.", selector, ("Check my Jetta watch now.",)),
        ],
        "boundaries": [
            {"boundary_id": "watch.one_time_search", "request_class": "one-time vehicle search", "explanation": "This is an ongoing watcher, not a general search tool.", "nearest_operation_ids": ["watch.create", "watch.check_now"]},
            {"boundary_id": "watch.hard_price_mileage", "request_class": "hard price or mileage limits", "explanation": "Price and mileage can guide attention only; they are not enforced source-query filters.", "nearest_operation_ids": ["watch.create", "watch.update"]},
            {"boundary_id": "watch.external_delivery", "request_class": "Telegram, email, or other external delivery", "explanation": "Results remain inside Capy.", "nearest_operation_ids": ["watch.status", "watch.list"]},
            {"boundary_id": "watch.seller_action", "request_class": "seller contact, reservation, or purchase", "explanation": "The watcher observes listings and cannot transact.", "nearest_operation_ids": ["watch.listings"]},
            {"boundary_id": "watch.arbitrary_schedule", "request_class": "custom schedule", "explanation": "The accepted shared schedule is fixed.", "nearest_operation_ids": ["watch.status"]},
        ],
    }


def _proforma_contract(capabilities: list[dict[str, Any]]) -> dict[str, Any] | None:
    execution = next((item for item in capabilities if item.get("id") == PROFORMA_ID), None)
    if execution is None:
        return None
    profile = execution.get("application_profile")
    if not isinstance(profile, dict):
        raise RuntimeFailure("INTERACTION_CONTRACT_PROFILE_REQUIRED")
    fields = [
        *[
            _field(item["name"], item["label"], f"Required {item['label']}.", required=True)
            for item in profile["owner_fields"]["required"]
        ],
        *[
            _field(item["name"], item["label"], f"Optional {item['label']}.", required=False, kind="long_text")
            for item in profile["owner_fields"]["optional"]
        ],
        _field(
            "line_items", "line-item CSV",
            "Exactly one CSV with columns sku, description, quantity, unit_price in that order.",
            required=True, kind="file", examples=("line-items.csv",),
        ),
    ]
    return {
        "schema": SCHEMA,
        "application_id": PROFORMA_ID,
        "application_version": execution["version_digest"],
        "title": "Proforma invoice",
        "purpose": profile["purpose"],
        "not_for": ["Excel input", "email or external delivery", "payment", "editing arbitrary documents"],
        "operations": [{
            "operation_id": "invoice.generate",
            "capability_id": execution["id"],
            "title": "Generate a proforma invoice",
            "user_outcome": "Prepare one verified proforma invoice.",
            "description": execution["description"],
            "human_fields": fields,
            "resources": [profile["resource_contract"]],
            "safe_defaults": {},
            "authority": {
                "required_role": "current active member with the exact team software binding",
                "policy": "runtime scope plus current team membership and exact software binding",
            },
            "effects": {
                "effect_class": execution["side_effect"],
                "state_effect": "verified internal artifact generation",
                "source_behavior": "No external source or network call.",
            },
            "examples": ["Prepare proforma invoice PI-2026-004 from this line-item CSV."],
            "common_misunderstandings": ["Excel files are not accepted.", "Generating an invoice does not email it."],
            "result": {
                "presentation": "artifact_result",
                "facts": profile["result_contract"]["facts"],
                "artifacts": profile["result_contract"]["verified_artifacts"],
            },
        }],
        "boundaries": [
            {"boundary_id": "invoice.excel", "request_class": "Excel input", "explanation": "Convert the source to the exact CSV shape first.", "nearest_operation_ids": ["invoice.generate"]},
            {"boundary_id": "invoice.external_send", "request_class": "email or external sending", "explanation": "Generate the verified artifacts, then use separately authorized delivery software.", "nearest_operation_ids": ["invoice.generate"]},
        ],
    }


class InteractionContractRegistry:
    """Build and validate human contracts against current execution truth."""

    def for_world(self, capabilities: list[dict[str, Any]]) -> list[dict[str, Any]]:
        contracts = [
            item for item in (_watcher_contract(capabilities), _proforma_contract(capabilities))
            if item is not None
        ]
        from .portable_interfaces import project_portable
        portable = [
            project_portable(item, item["portable_interaction"], item["import_id"])
            for item in capabilities if "portable_interaction" in item
        ]
        return [self.validate(item, capabilities) for item in contracts] + portable

    @staticmethod
    def validate(contract: dict[str, Any], capabilities: list[dict[str, Any]]) -> dict[str, Any]:
        value = copy.deepcopy(contract)
        if value.get("schema") != SCHEMA or not isinstance(value.get("operations"), list):
            raise RuntimeFailure("INTERACTION_CONTRACT_INVALID")
        executions = {item["id"]: item for item in capabilities}
        operation_ids: set[str] = set()
        for operation in value["operations"]:
            operation_id = operation.get("operation_id")
            if not isinstance(operation_id, str) or operation_id in operation_ids:
                raise RuntimeFailure("INTERACTION_CONTRACT_INVALID")
            operation_ids.add(operation_id)
            execution = executions.get(operation.get("capability_id"))
            if execution is None:
                raise RuntimeFailure("INTERACTION_CONTRACT_UNKNOWN_OPERATION")
            if execution["version_digest"] != value.get("application_version"):
                raise RuntimeFailure("INTERACTION_CONTRACT_VERSION_MISMATCH")
            if value["application_id"] == WATCHER_ID and (
                execution.get("application_id") != WATCHER_ID
                or execution.get("operation_id") != operation_id
            ):
                raise RuntimeFailure("INTERACTION_CONTRACT_UNKNOWN_OPERATION")
            effects = operation.get("effects") or {}
            if effects.get("effect_class") != execution["side_effect"]:
                raise RuntimeFailure("INTERACTION_CONTRACT_EFFECT_MISMATCH")
            if value["application_id"] == WATCHER_ID and (
                effects.get("state_effect") != execution["state_effect_policy"]
                or effects.get("source_behavior") != execution["source_behavior"]
                or operation.get("authority", {}).get("policy") != execution["authority_policy"]
            ):
                raise RuntimeFailure("INTERACTION_CONTRACT_EFFECT_MISMATCH")
            if value["application_id"] == PROFORMA_ID and (
                effects.get("state_effect") != "verified internal artifact generation"
                or effects.get("source_behavior") != "No external source or network call."
                or operation.get("authority", {}).get("policy")
                != "runtime scope plus current team membership and exact software binding"
            ):
                raise RuntimeFailure("INTERACTION_CONTRACT_EFFECT_MISMATCH")
            if (
                not operation.get("examples")
                or not operation.get("authority", {}).get("required_role")
                or not operation.get("user_outcome")
            ):
                raise RuntimeFailure("INTERACTION_CONTRACT_INVALID")
            schema = execution["input_schema"]
            required_paths = set(_required_paths(schema))
            declared: set[str] = set()
            for field in operation.get("human_fields", []):
                field_id = field.get("field_id")
                resource = field_id == "line_items" and any(
                    item.get("name") == "line_items"
                    for item in execution.get("resource_requirements", [])
                )
                if not resource and not _schema_has_path(schema, field_id):
                    raise RuntimeFailure("INTERACTION_CONTRACT_UNKNOWN_FIELD")
                if type(field.get("required")) is not bool or field["required"] != (
                    field_id in required_paths or resource
                ):
                    raise RuntimeFailure("INTERACTION_CONTRACT_REQUIRED_FIELD_MISMATCH")
                declared.add(field_id)
            for field in operation.get("context_fields", []):
                field_id = field.get("field_id")
                if not _schema_has_path(schema, field_id) or field_id not in required_paths:
                    raise RuntimeFailure("INTERACTION_CONTRACT_UNKNOWN_FIELD")
                if field.get("source") != "current_workspace":
                    raise RuntimeFailure("INTERACTION_CONTRACT_INVALID")
                declared.add(field_id)
            if any(
                path not in declared and not any(item.startswith(path + ".") for item in declared)
                for path in _required_paths(schema) if path != "operation"
            ):
                raise RuntimeFailure("INTERACTION_CONTRACT_REQUIRED_FIELD_MISSING")
            result = execution["result_schema"].get("properties", {})
            if any(item not in result for item in operation["result"]["facts"]):
                raise RuntimeFailure("INTERACTION_CONTRACT_UNKNOWN_RESULT_FACT")
            available_artifacts = result.get("artifact_filenames", {}).get("items", {}).get("enum", [])
            if any(item not in available_artifacts for item in operation["result"]["artifacts"]):
                raise RuntimeFailure("INTERACTION_CONTRACT_UNKNOWN_RESULT_FACT")
        for boundary in value.get("boundaries", []):
            if (
                not boundary.get("explanation")
                or not boundary.get("nearest_operation_ids")
                or any(item not in operation_ids for item in boundary.get("nearest_operation_ids", []))
            ):
                raise RuntimeFailure("INTERACTION_CONTRACT_UNKNOWN_OPERATION")
        value["digest"] = hashlib.sha256(canonical_json({
            key: item for key, item in value.items() if key != "digest"
        })).hexdigest()
        return value


def _schema_has_path(schema: dict[str, Any], path: Any) -> bool:
    if not isinstance(path, str) or not path:
        return False
    current = schema
    for part in path.split("."):
        properties = current.get("properties", {})
        if part not in properties:
            return False
        current = properties[part]
    return True


def _required_paths(schema: dict[str, Any], prefix: str = "") -> list[str]:
    paths: list[str] = []
    for name in schema.get("required", []):
        child = schema.get("properties", {}).get(name, {})
        path = f"{prefix}.{name}" if prefix else name
        nested = _required_paths(child, path) if child.get("type") == "object" else []
        paths.extend(nested or [path])
    return paths
