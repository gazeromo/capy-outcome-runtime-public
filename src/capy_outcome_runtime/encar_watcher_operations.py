"""Internal operation descriptors for the accepted Encar watcher application."""

from __future__ import annotations

import re
import unicodedata
from typing import Any

from .access import ActorContext
from .application_operations import OperationContext, OperationDescriptor
from .encar_watcher_runtime import APP_ID, EncarWatcherRuntime
from .model import RuntimeFailure


CAPABILITY_PREFIX = f"{APP_ID}.watch"
SAFE_ERRORS = {
    "ENCAR_WATCHER_NOT_FOUND": "APPLICATION_TARGET_NOT_FOUND",
    "ENCAR_WATCHER_FORBIDDEN": "APPLICATION_ACCESS_DENIED",
    "ENCAR_WATCHER_INVALID_AUTHORITY": "APPLICATION_ACCESS_DENIED",
    "ENCAR_WATCHER_AUTHORITY_DENIED": "APPLICATION_ACCESS_DENIED",
    "ENCAR_WATCHER_MEMBERSHIP_REVOKED": "APPLICATION_ACCESS_DENIED",
    "ENCAR_WATCHER_MEMBERSHIP_UNAVAILABLE": "APPLICATION_ACCESS_DENIED",
    "ENCAR_WATCHER_NOT_INSTALLED": "APPLICATION_UNAVAILABLE",
    "ENCAR_WATCHER_COMMAND_TIMEOUT": "APPLICATION_TIMEOUT",
    "ENCAR_WATCHER_COMMAND_INVALID": "APPLICATION_INVALID_RESPONSE",
    "ENCAR_WATCHER_COMMAND_FAILED": "APPLICATION_INVALID_RESPONSE",
    "ENCAR_WATCHER_INTERNAL_ERROR": "APPLICATION_INVALID_RESPONSE",
    "ENCAR_WATCHER_SOURCE_FAILURE": "APPLICATION_SOURCE_UNAVAILABLE",
    "ENCAR_WATCHER_STATUS_UNAVAILABLE": "APPLICATION_STATE_UNAVAILABLE",
    "ENCAR_WATCHER_INVALID_REQUEST": "APPLICATION_INPUT_INVALID",
    "ENCAR_WATCHER_INPUT_INVALID": "APPLICATION_INPUT_INVALID",
    "ENCAR_WATCHER_WATCH_NOT_ACTIVE": "APPLICATION_INPUT_INVALID",
    "ENCAR_WATCHER_DATABASE_BUSY": "APPLICATION_STATE_UNAVAILABLE",
}


def operation_schema(operation: str, properties: dict[str, Any], required: list[str]) -> dict[str, Any]:
    return {
        "type": "object",
        "additionalProperties": False,
        "required": ["operation", *required],
        "properties": {
            "operation": {"type": "string", "enum": [operation]},
            **properties,
        },
    }


SELECTOR = {
    "type": "object",
    "additionalProperties": False,
    "properties": {
        "watch_id": {"type": "string", "minLength": 1},
        "make": {"type": "string", "minLength": 1},
        "model": {"type": "string", "minLength": 1},
        "visibility": {"type": "string", "enum": ["personal", "team"]},
        "ownership_scope": {"type": "string", "enum": ["mine", "team"]},
        "person_name": {"type": "string", "minLength": 1},
    },
}

MAKE_ALIASES = {
    "volkswagen": "volkswagen", "vw": "volkswagen", "volks wagen": "volkswagen",
    "volkswagen ag": "volkswagen", "폭스바겐": "volkswagen",
    "genesis": "genesis", "제네시스": "genesis",
}
MODEL_ALIASES = {
    "jetta": "jetta", "джетта": "jetta", "제타": "jetta",
    "passat": "passat", "пассат": "passat", "파사트": "passat",
    "g70": "g70", "g 70": "g70", "g-70": "g70",
}


def result_schema(required: list[str], properties: dict[str, Any] | None = None) -> dict[str, Any]:
    return {
        "type": "object", "required": required,
        "properties": properties or {key: {} for key in required},
    }


class EncarWatcherOperationAdapter:
    application_id = APP_ID

    def __init__(self, runtime: EncarWatcherRuntime):
        self.runtime = runtime

    def maintainer_principal_id(self, actor: ActorContext) -> str:
        return self.runtime.installation(actor)["maintainer_principal_id"]

    def descriptors(self, actor: ActorContext) -> list[OperationDescriptor]:
        try:
            installation = self.runtime.installation(actor)
        except RuntimeFailure as exc:
            if exc.code == "ENCAR_WATCHER_NOT_INSTALLED":
                return []
            raise
        version = installation["artifact_digest"]

        def descriptor(
            operation: str,
            description: str,
            schema: dict[str, Any],
            effect: str,
            source: str,
            presentation: str,
            result: dict[str, Any],
            target_policy: str,
            state_policy: str,
        ) -> OperationDescriptor:
            return OperationDescriptor(
                APP_ID,
                version,
                operation,
                f"{CAPABILITY_PREFIX}.{operation.removeprefix('watch.')}",
                description,
                schema,
                effect,
                "current Access actor plus current application visibility and mutation policy",
                source,
                "turn-bound idempotency; exact replay must not duplicate a transition",
                dict(SAFE_ERRORS),
                result,
                target_policy,
                state_policy,
                presentation,
            )

        hard_filters = {
            "type": "object",
            "additionalProperties": False,
            "required": ["source", "make", "model", "min_year", "max_year"],
            "properties": {
                "source": {"type": "string", "enum": ["encar"]},
                "make": {"type": "string", "minLength": 1},
                "model": {"type": "string", "minLength": 1},
                "min_year": {"type": "integer"},
                "max_year": {"type": "integer"},
            },
        }
        create = operation_schema("watch.create", {
            "visibility": {"type": "string", "enum": ["personal", "team"]},
            "hard_filters": hard_filters,
            "attention_intent": {"type": "string", "minLength": 1},
        }, ["visibility", "hard_filters"])
        selector = {"selector": SELECTOR}
        changes = {
            "type": "object",
            "additionalProperties": False,
            "properties": {
                "min_year": {"type": "integer"},
                "max_year": {"type": "integer"},
                "attention_intent": {"type": "string", "minLength": 1},
            },
        }
        return [
            descriptor(
                "watch.create",
                "Create one new personal or team Encar vehicle watch when the request asks to create or start a new watch, using exact make, model, inclusive years, and attention intent. Do not use this to change an existing watch. This does not contact sellers or send external notifications.",
                create,
                "stateful_internal",
                "No source call during creation; the shared timer establishes the baseline later.",
                "watch_create",
                result_schema(["watch_id"], {"watch_id": {"type": "string"}}),
                "result_watch_id", "creates_state",
            ),
            descriptor(
                "watch.status",
                "Read stored status and schedule for one caller-visible vehicle watch. Use selector fields from the request or conversation; omit unknown selector fields. This never checks Encar/EimCar.",
                operation_schema("watch.status", selector, ["selector"]),
                "read_only",
                "Stored state only; zero source calls.",
                "watch_status",
                result_schema(["watch"], {"watch": {"type": "object"}}),
                "adapter_selected_watch", "read_only",
            ),
            descriptor(
                "watch.list",
                "List caller-visible active vehicle watches. Scope personal means watches created by this person; team means team-visible watches; all means both. Omitted scope defaults to all caller-visible watches. This never checks Encar/EimCar.",
                operation_schema("watch.list", {
                    "scope": {"type": "string", "enum": ["personal", "team", "all"]},
                }, []),
                "read_only",
                "Stored state only; zero source calls.",
                "watch_list",
                result_schema(["watches", "scope"]),
                "none", "read_only",
            ),
            descriptor(
                "watch.listings",
                "Read the stored current listing snapshot and candidate history for exactly one caller-visible watch. This never checks Encar/EimCar and cannot contact a seller or purchase a vehicle.",
                operation_schema("watch.listings", selector, ["selector"]),
                "read_only",
                "Stored application state only; zero source calls.",
                "watch_listings",
                result_schema(
                    ["watch", "snapshot", "current_listings", "history", "limit"],
                    {
                        "watch": {"type": "object"},
                        "snapshot": {},
                        "current_listings": {"type": "array"},
                        "history": {"type": "array"},
                        "limit": {"type": "integer"},
                    },
                ),
                "adapter_selected_watch", "read_only",
            ),
            descriptor(
                "watch.pause",
                "Pause exactly one caller-manageable vehicle watch selected from current visible state. Ambiguous or missing selectors do not mutate anything.",
                operation_schema("watch.pause", selector, ["selector"]),
                "stateful_internal",
                "Zero source calls.",
                "watch_transition",
                result_schema(["watch_id"], {"watch_id": {"type": "string"}}),
                "result_watch_id", "mutates_state",
            ),
            descriptor(
                "watch.resume",
                "Resume exactly one caller-manageable paused vehicle watch selected from current visible state. Ambiguous or missing selectors do not mutate anything.",
                operation_schema("watch.resume", selector, ["selector"]),
                "stateful_internal",
                "Zero source calls.",
                "watch_transition",
                result_schema(["watch_id"], {"watch_id": {"type": "string"}}),
                "result_watch_id", "mutates_state",
            ),
            descriptor(
                "watch.update",
                "Change an existing caller-manageable watch, including its inclusive years and/or what listings deserve attention. Use this for requests about my/our existing watch even when phrased as alerting or focus preferences. Mileage filters are not supported. Ambiguous or missing selectors do not mutate anything.",
                operation_schema("watch.update", {"selector": SELECTOR, "changes": changes}, ["selector", "changes"]),
                "stateful_internal",
                "Zero source calls; changing the source query clears only its stored baseline.",
                "watch_update",
                result_schema(["watch_id"], {"watch_id": {"type": "string"}}),
                "result_watch_id", "mutates_state",
            ),
            descriptor(
                "watch.delete",
                "Delete exactly one caller-manageable vehicle watch. Ambiguous or missing selectors do not mutate anything.",
                operation_schema("watch.delete", selector, ["selector"]),
                "stateful_internal",
                "Zero source calls.",
                "watch_delete",
                result_schema(["watch_id"], {"watch_id": {"type": "string"}}),
                "result_watch_id", "mutates_state",
            ),
            descriptor(
                "watch.check_now",
                "Run one immediate fixture-or-configured-source check for exactly one caller-manageable active watch. This is the only interactive lifecycle operation that checks the vehicle source.",
                operation_schema("watch.check_now", selector, ["selector"]),
                "stateful_internal",
                "Exactly one logical application source check; pagination may use bounded HTTP requests.",
                "watch_check_now",
                result_schema(
                    ["query_key", "status", "source_calls", "http_requests", "candidates_created", "total_hits"],
                    {
                        "query_key": {"type": "string"}, "status": {"type": "string"},
                        "source_calls": {"type": "integer"}, "http_requests": {"type": "integer"},
                        "candidates_created": {"type": "integer"}, "total_hits": {"type": "integer"},
                    },
                ),
                "adapter_selected_watch", "mutates_state",
            ),
        ]

    @staticmethod
    def _canonical(field: str, value: Any) -> str:
        normalized = " ".join(unicodedata.normalize("NFKC", str(value)).strip().casefold().split())
        return (MAKE_ALIASES if field == "make" else MODEL_ALIASES).get(normalized, normalized)

    @classmethod
    def _match(cls, watches: list[dict[str, Any]], selector: dict[str, Any], actor: ActorContext) -> dict[str, Any]:
        if not isinstance(selector, dict) or set(selector) - {
            "watch_id", "make", "model", "visibility", "ownership_scope", "person_name"
        }:
            raise RuntimeFailure("APPLICATION_INPUT_INVALID")
        if selector.get("person_name") and selector.get("ownership_scope"):
            name = str(selector["person_name"]).strip().casefold()
            if (
                selector.get("ownership_scope") == "mine"
                and name == actor.principal_display_name.strip().casefold()
            ):
                selector = dict(selector)
                selector.pop("person_name")
            elif selector.get("ownership_scope") == "team":
                # A named person is the narrower selector inside the visible
                # team universe.  Personal visibility is still denied below
                # before any application execution.
                selector = dict(selector)
                selector.pop("ownership_scope")
            else:
                raise RuntimeFailure("APPLICATION_INPUT_INVALID")
        if selector.get("person_name"):
            name = str(selector["person_name"]).strip().casefold()
            if name != actor.principal_display_name.strip().casefold():
                if selector.get("visibility") == "personal":
                    raise RuntimeFailure("APPLICATION_ACCESS_DENIED", safe_facts={
                        "application_calls": 0, "source_calls": 0, "effect_count": 0,
                        "execution_phase": "pre_execution",
                    })
                matches_by_name = [item for item in watches if str(item.get("creator_display_name", "")).strip().casefold() == name]
                watches = matches_by_name
            else:
                watches = [item for item in watches if item["creator_principal_id"] == actor.principal_id]
        elif selector.get("ownership_scope") == "mine":
            watches = [item for item in watches if item["creator_principal_id"] == actor.principal_id]
        elif selector.get("ownership_scope") == "team":
            watches = [item for item in watches if item["visibility"] == "team"]
        matches = list(watches)
        if selector.get("watch_id"):
            matches = [item for item in matches if item["id"] == selector["watch_id"]]
        if selector.get("visibility"):
            matches = [item for item in matches if item["visibility"] == selector["visibility"]]
        for field in ("make", "model"):
            if selector.get(field):
                wanted = cls._canonical(field, selector[field])
                matches = [
                    item for item in matches
                    if cls._canonical(field, item["filters"].get(field, "")) == wanted
                ]
        if not matches:
            raise RuntimeFailure(
                "APPLICATION_TARGET_NOT_FOUND",
                safe_facts={"application_calls": 0, "source_calls": 0, "effect_count": 0, "execution_phase": "pre_execution"},
            )
        if len(matches) > 1:
            raise RuntimeFailure(
                "APPLICATION_TARGET_AMBIGUOUS",
                safe_facts={"application_calls": 0, "source_calls": 0, "effect_count": 0, "execution_phase": "pre_execution"},
            )
        return matches[0]

    @staticmethod
    def _public_watch(watch: dict[str, Any]) -> dict[str, Any]:
        return {
            key: watch.get(key)
            for key in (
                "id", "visibility", "filters", "status", "baseline_at", "last_checked_at",
                "next_check_at", "schedule_seconds", "pause_reason",
            )
        }

    @staticmethod
    def _public_listings_result(value: Any) -> dict[str, Any]:
        if not isinstance(value, dict) or set(value) != {
            "watch", "snapshot", "current_listings", "history", "limit"
        }:
            raise RuntimeFailure("APPLICATION_INVALID_RESPONSE")
        watch = value["watch"]
        if not isinstance(watch, dict) or set(watch) != {
            "filters", "status", "last_checked_at", "baseline_at"
        } or not isinstance(watch.get("filters"), dict):
            raise RuntimeFailure("APPLICATION_INVALID_RESPONSE")
        filters = watch["filters"]
        if (
            set(filters) - {"source", "make", "model", "min_year", "max_year"}
            or filters.get("source") != "encar"
            or not all(isinstance(filters.get(key), str) and filters[key] for key in ("make", "model"))
        ):
            raise RuntimeFailure("APPLICATION_INVALID_RESPONSE")
        snapshot = value["snapshot"]
        if snapshot is not None and (
            not isinstance(snapshot, dict)
            or set(snapshot) != {"observed_at", "total_hits"}
            or not isinstance(snapshot.get("observed_at"), str)
            or not isinstance(snapshot.get("total_hits"), int)
            or isinstance(snapshot.get("total_hits"), bool)
            or snapshot["total_hits"] < 0
        ):
            raise RuntimeFailure("APPLICATION_INVALID_RESPONSE")
        if value["limit"] != 100:
            raise RuntimeFailure("APPLICATION_INVALID_RESPONSE")
        item_fields = {
            "title", "make", "model", "vehicle_date", "price", "mileage",
            "catalog_url", "first_seen_at", "last_seen_at", "disposition",
        }
        dispositions = {
            "notified", "selected_for_notification", "ignored", "pending_review", "unchanged"
        }

        def items(name: str, *, current: bool) -> list[dict[str, Any]]:
            source = value[name]
            if not isinstance(source, list) or len(source) > 100:
                raise RuntimeFailure("APPLICATION_INVALID_RESPONSE")
            allowed = item_fields | ({"last_matched_at"} if current else set())
            projected = []
            for item in source:
                if not isinstance(item, dict) or set(item) != allowed:
                    raise RuntimeFailure("APPLICATION_INVALID_RESPONSE")
                url = item.get("catalog_url")
                if url is not None and (
                    not isinstance(url, str)
                    or not re.fullmatch(r"https://eimcar\.ru/catalog/[^/?#]+", url)
                ):
                    raise RuntimeFailure("APPLICATION_INVALID_RESPONSE")
                if item.get("disposition") not in dispositions:
                    raise RuntimeFailure("APPLICATION_INVALID_RESPONSE")
                if any(
                    field != "catalog_url" and value is not None
                    and (isinstance(value, bool) or not isinstance(value, (str, int, float)))
                    for field, value in item.items()
                    if field not in {"disposition"}
                ):
                    raise RuntimeFailure("APPLICATION_INVALID_RESPONSE")
                if any(isinstance(value, str) and len(value) > 1000 for value in item.values()):
                    raise RuntimeFailure("APPLICATION_INVALID_RESPONSE")
                projected.append({key: item.get(key) for key in allowed})
            return projected

        return {
            "watch": {
                "filters": dict(watch["filters"]), "status": watch.get("status"),
                "last_checked_at": watch.get("last_checked_at"),
                "baseline_at": watch.get("baseline_at"),
            },
            "snapshot": dict(snapshot) if snapshot is not None else None,
            "current_listings": items("current_listings", current=True),
            "history": items("history", current=False),
            "limit": 100,
        }

    def invoke(
        self,
        context: OperationContext,
        descriptor: OperationDescriptor,
        value: dict[str, Any],
    ) -> dict[str, Any]:
        if value.get("operation") != descriptor.operation_id:
            raise RuntimeFailure("APPLICATION_INPUT_INVALID")
        operation = descriptor.operation_id
        if operation == "watch.create":
            value = dict(value)
            value.setdefault(
                "attention_intent",
                "Highlight matching listings that materially deserve attention.",
            )
            result = self.runtime.invoke_from_chat(
                context.actor,
                context.conversation_id,
                value,
                context.idempotency_key,
                owner_request=context.owner_text,
            )
            return self._outcome(
                result,
                "Your Encar vehicle watch is active. Its first successful shared-timer check establishes a silent baseline.",
                source=False,
                changed=True,
                target_receipt={"watch_id": result["watch_id"], "selection": "created"},
            )

        watches = self.runtime.stored_watches(context.actor)
        if operation == "watch.list":
            # The absence of a scope means every watch already visible to this
            # actor.  This is a read-only, application-owned default and never
            # broadens the runtime's privacy-filtered state.
            scope = value.get("scope", "all")
            if scope == "personal":
                watches = [
                    item for item in watches
                    if item["creator_principal_id"] == context.actor.principal_id
                    and item["visibility"] == "personal"
                ]
            elif scope == "team":
                watches = [item for item in watches if item["visibility"] == "team"]
            elif scope != "all":
                raise RuntimeFailure("APPLICATION_INPUT_INVALID")
            public = [self._public_watch(item) for item in watches]
            lines = ["Your visible vehicle watches:"]
            if not public:
                lines = ["You do not currently have any visible vehicle watches in that scope."]
            else:
                for item in public:
                    filters = item["filters"] or {}
                    lines.append(
                        f"- {filters.get('make')} {filters.get('model')} "
                        f"{filters.get('min_year')}–{filters.get('max_year')}: {item.get('status')} "
                        f"({item.get('visibility')})"
                    )
            lines.append("This list used stored application state and did not check the vehicle source.")
            return self._outcome({"watches": public, "scope": scope}, "\n".join(lines), source=False, changed=False, target_receipt=None)

        watch = self._match(watches, value.get("selector"), context.actor)
        if operation == "watch.listings":
            result = self.runtime.command(
                context.actor,
                operation,
                {"watch_id": watch["id"], "limit": 100},
                conversation_id=context.conversation_id,
                idempotency_key=context.idempotency_key,
            )
            try:
                result = self._public_listings_result(result)
            except RuntimeFailure as exc:
                raise RuntimeFailure("APPLICATION_INVALID_RESPONSE", safe_facts={
                    "application_calls": 1, "source_calls": 0, "effect_count": 0,
                    "execution_phase": "executed_result_invalid",
                }) from exc
            return self._outcome(
                result,
                "Stored listings for the selected vehicle watch. No source check was run.",
                source=False,
                changed=False,
                target_receipt={"watch_id": watch["id"], "selection": "visible_state"},
            )
        if operation == "watch.status":
            public = self._public_watch(watch)
            filters = public["filters"] or {}
            lines = [
                f"Your {filters.get('make')} {filters.get('model')} "
                f"{filters.get('min_year')}–{filters.get('max_year')} watch is {public.get('status')}.",
                f"Visibility: {public.get('visibility')}.",
                "Baseline: established." if public.get("baseline_at") else "Baseline: waiting for the first successful check.",
            ]
            if public.get("last_checked_at"):
                lines.append(f"Last checked: {public['last_checked_at']}.")
            if public.get("next_check_at") is not None:
                lines.append(f"Next scheduled check: {public['next_check_at']}.")
            lines.append(f"Schedule: every {int(public.get('schedule_seconds') or 0) // 60} minutes.")
            lines.append("This status read used stored application state and did not check the vehicle source.")
            return self._outcome({"watch": public}, "\n".join(lines), source=False, changed=False, target_receipt={"watch_id": watch["id"], "selection": "visible_state"})

        args: dict[str, Any] = {"watch_id": watch["id"]}
        if operation == "watch.pause":
            args["reason"] = "paused by natural request"
        elif operation == "watch.update":
            changes = value.get("changes")
            if not isinstance(changes, dict) or not changes:
                raise RuntimeFailure("APPLICATION_INPUT_INVALID")
            if set(changes) - {"min_year", "max_year", "attention_intent"}:
                raise RuntimeFailure("APPLICATION_INPUT_INVALID")
            if "attention_intent" in changes:
                args["attention_intent"] = changes["attention_intent"]
            if "min_year" in changes or "max_year" in changes:
                filters = dict(watch["filters"])
                filters["min_year"] = changes.get("min_year", filters["min_year"])
                filters["max_year"] = changes.get("max_year", filters["max_year"])
                args["filters"] = filters
        result = self.runtime.command(
            context.actor,
            operation,
            args,
            conversation_id=context.conversation_id,
            idempotency_key=context.idempotency_key,
        )
        if not isinstance(result, dict):
            raise RuntimeFailure("APPLICATION_INVALID_RESPONSE", safe_facts={
                "application_calls": 1, "source_calls": None if operation == "watch.check_now" else 0,
                "effect_count": 0, "execution_phase": "executed_result_invalid",
            })
        source = operation == "watch.check_now"
        verbs = {
            "watch.pause": "paused",
            "watch.resume": "resumed",
            "watch.update": "updated",
            "watch.delete": "deleted",
            "watch.check_now": "checked now",
        }
        return self._outcome(
            result,
            f"The selected vehicle watch was {verbs[operation]}.",
            source=source,
            changed=True,
            target_receipt={"watch_id": watch["id"], "selection": "visible_state"},
        )

    @staticmethod
    def _outcome(
        result: dict[str, Any],
        text: str,
        *,
        source: bool,
        changed: bool,
        target_receipt: dict[str, Any] | None,
    ) -> dict[str, Any]:
        return {
            "result": result,
            "text": text,
            "source_checked": source,
            "state_changed": changed,
            "effect_count": 0,
            "target_receipt": target_receipt,
            "execution_phase": "completed",
        }
