"""Deterministic default interfaces over exact installed application contracts."""

from __future__ import annotations

import hashlib
import hmac
import secrets
import threading
from contextlib import nullcontext
from typing import Any, Callable

from .access import ActorContext
from .application_operations import ApplicationOperationRegistry, OperationContext
from .chat import ChatStore
from .interaction_contracts import PROFORMA_ID, WATCHER_ID
from .model import RuntimeFailure
from .runtime import OutcomeRuntime
from .store import RuntimeStore, canonical_json


META_FIELDS = {
    "csrf", "application_version", "contract_digest", "workspace_membership_id",
    "submission",
}


def watcher_interface_authority(
    watcher_runtime: Any, actor: ActorContext, watch_id: str
) -> dict[str, Any]:
    """Project current watch manageability without changing app operations."""

    matches = [
        item for item in watcher_runtime.stored_watches(actor)
        if item.get("id") == watch_id
    ]
    if len(matches) != 1:
        raise RuntimeFailure("APPLICATION_INTERFACE_TARGET_STALE")
    watch = matches[0]
    manageable = (
        actor.membership_kind == "owner"
        or watch.get("creator_principal_id") == actor.principal_id
    )
    explanation = (
        "You can manage this watch."
        if manageable
        else "You can view this team watch. Only its creator or a team owner can manage it."
    )
    return {"manageable": manageable, "explanation": explanation}


class ContractDerivedInterfaceService:
    """Maps trusted form controls to current exact operations without a model call."""

    def __init__(
        self,
        runtime_store: RuntimeStore,
        chat_store: ChatStore,
        runtime: OutcomeRuntime,
        operations: ApplicationOperationRegistry | None,
        contract_resolver: Callable[[ActorContext, str], dict[str, Any]],
        authority_guard: Callable[[ActorContext], Any] | None = None,
        watch_authority_resolver: Callable[[ActorContext, str], dict[str, Any]] | None = None,
        watch_state_resolver: Callable[[ActorContext, str], dict[str, Any] | None] | None = None,
    ):
        self.runtime_store = runtime_store
        self.chat_store = chat_store
        self.runtime = runtime
        self.operations = operations
        self.contract_resolver = contract_resolver
        self.authority_guard = authority_guard or nullcontext
        self.watch_authority_resolver = watch_authority_resolver
        self.watch_state_resolver = watch_state_resolver
        self._reference_key = secrets.token_bytes(32)
        self._activity_lock = threading.RLock()

    def page(self, actor: ActorContext, application_id: str) -> dict[str, Any]:
        with self.authority_guard(actor) as current:
            return self._page(current, application_id)

    def _page(self, actor: ActorContext, application_id: str) -> dict[str, Any]:
        contract = self.contract_resolver(actor, application_id)
        watches: list[dict[str, Any]] = []
        read_receipt = None
        if application_id == WATCHER_ID:
            outcome = self._watcher_invoke(
                actor, contract, "watch.list", {"operation": "watch.list"},
                idempotency_key="interface-read-" + secrets.token_hex(12),
            )
            watches = []
            for item in outcome["result"]["watches"]:
                authority = (
                    self.watch_authority_resolver(actor, item["id"])
                    if self.watch_authority_resolver is not None
                    else {
                        "manageable": actor.membership_kind == "owner"
                        or actor.workspace_kind == "personal",
                        "explanation": (
                            "You can manage this watch."
                            if actor.membership_kind == "owner"
                            or actor.workspace_kind == "personal"
                            else "You can view this team watch. Only its creator or a team owner can manage it."
                        ),
                    }
                )
                watches.append({
                    **item,
                    "reference": self._watch_reference(actor, contract, item["id"]),
                    "authority": authority,
                })
            read_receipt = outcome["operation_receipt"]
        return {"contract": contract, "watches": watches, "read_receipt": read_receipt}

    def submit(
        self,
        actor: ActorContext,
        application_id: str,
        operation_id: str,
        fields: dict[str, str],
        files: dict[str, tuple[str, str, bytes]],
    ) -> dict[str, Any]:
        with self.authority_guard(actor) as current:
            with self._activity_lock:
                return self._submit(current, application_id, operation_id, fields, files)

    def _submit(
        self,
        actor: ActorContext,
        application_id: str,
        operation_id: str,
        fields: dict[str, str],
        files: dict[str, tuple[str, str, bytes]],
    ) -> dict[str, Any]:
        contract = self.contract_resolver(actor, application_id)
        self._validate_binding(actor, contract, fields)
        operation = next(
            (item for item in contract["operations"] if item["operation_id"] == operation_id),
            None,
        )
        if operation is None:
            raise RuntimeFailure("APPLICATION_INTERFACE_OPERATION_UNKNOWN")
        allowed = META_FIELDS | {
            ("input." if contract.get("portable_import") else "") + item["field_id"]
            for item in operation["human_fields"]
        }
        if contract.get("portable_import"):
            allowed |= {"__portable_form"} | {
                "__present__." + item["field_id"] for item in operation["human_fields"]
                if item["input_kind"] != "file"
            }
        if not contract.get("portable_import") and operation_id.startswith("watch.") and operation_id not in {"watch.create", "watch.list"}:
            allowed.add("watch_ref")
        if not contract.get("portable_import") and operation_id == "watch.delete":
            allowed.add("confirm")
        if not contract.get("portable_import") and any(isinstance(value, list) for value in files.values()):
            raise RuntimeFailure("HTTP_FORM_INVALID")
        if set(fields) - allowed or set(files) - allowed:
            raise RuntimeFailure("APPLICATION_INTERFACE_FIELD_UNKNOWN")
        if not contract.get("portable_import") and operation_id == "watch.delete" and fields.get("confirm") != "delete":
            raise RuntimeFailure("APPLICATION_INTERFACE_CONFIRMATION_REQUIRED")
        submission = fields.get("submission", "")
        if not 16 <= len(submission) <= 128 or not submission.isascii():
            raise RuntimeFailure("APPLICATION_INTERFACE_SUBMISSION_INVALID")

        activity = self.runtime_store.begin_interface_activity(
            scope_id=actor.execution_scope_id,
            principal_id=actor.principal_id,
            membership_id=actor.membership_id,
            team_id=actor.team_id,
            application_id=application_id,
            application_version=contract["application_version"],
            contract_digest=contract["digest"],
            operation_id=operation_id,
            submission=submission,
            request_digest=self._activity_request_digest(fields, files),
        )
        if activity["status"] == "succeeded":
            return self._activity_projection(activity)
        if activity["status"] == "failed":
            raise RuntimeFailure(
                activity.get("error_code") or "APPLICATION_INTERFACE_ACTIVITY_FAILED"
            )

        try:
            if contract.get("portable_import"):
                return self._submit_portable(actor, contract, operation, fields, files, activity)
            request: dict[str, Any] = (
                {"operation": operation_id} if application_id == WATCHER_ID else {}
            )
            selector_operation = operation_id in {
                "watch.status", "watch.pause", "watch.resume", "watch.update",
                "watch.delete", "watch.check_now",
            }
            if selector_operation:
                watch = self._resolve_watch(actor, contract, fields.get("watch_ref", ""))
                request["selector"] = {"watch_id": watch["id"]}
            for field in operation["human_fields"]:
                field_id = field["field_id"]
                if field_id in {"selector", "line_items"}:
                    continue
                raw = fields.get(field_id, "").strip()
                if not raw and field.get("safe_default") is not None:
                    raw = str(field["safe_default"])
                if not raw:
                    if field["required"]:
                        raise RuntimeFailure("APPLICATION_INTERFACE_REQUIRED_FIELD_MISSING")
                    continue
                value: Any = raw
                if field["input_kind"] == "number":
                    try:
                        value = int(raw)
                    except ValueError as exc:
                        raise RuntimeFailure("APPLICATION_INTERFACE_FIELD_INVALID") from exc
                self._set_path(request, field_id, value)
            for context in operation.get("context_fields", []):
                if context.get("source") != "current_workspace":
                    raise RuntimeFailure("APPLICATION_INTERFACE_CONTEXT_INVALID")
                try:
                    value = context["mapping"][actor.workspace_kind]
                except KeyError as exc:
                    raise RuntimeFailure("APPLICATION_INTERFACE_CONTEXT_INVALID") from exc
                self._set_path(request, context["field_id"], value)

            if application_id == WATCHER_ID:
                if files:
                    raise RuntimeFailure("APPLICATION_INTERFACE_FILE_UNKNOWN")
                outcome = self._watcher_invoke(
                    actor, contract, operation_id, request, submission
                )
                human_result = self._human_watcher_result(outcome["result"])
                watch_id = outcome["result"].get("watch_id")
                if (
                    isinstance(watch_id, str)
                    and operation_id != "watch.delete"
                    and self.watch_state_resolver is not None
                    and operation.get("result", {}).get("presentation") in {
                        "watch_create", "watch_status", "watch_transition",
                        "watch_update", "watch_check_now",
                    }
                ):
                    # The operation has already succeeded. Presentation enrichment
                    # is deliberately best-effort and must never change that truth.
                    try:
                        resolved = self.watch_state_resolver(actor, watch_id)
                    except RuntimeFailure:
                        resolved = None
                    projection = self._watch_presentation_projection(resolved)
                    if projection is not None:
                        human_result = {**human_result, "watch": projection}
                completed = self.runtime_store.finish_interface_activity(
                    activity["id"],
                    status="succeeded",
                    summary=outcome["text"],
                    result=human_result,
                    artifacts=[],
                    receipt=outcome["operation_receipt"],
                    source_checked=outcome["source_checked"],
                    state_changed=outcome["state_changed"],
                )
                return self._activity_projection(completed)
            if application_id != PROFORMA_ID or operation_id != "invoice.generate":
                raise RuntimeFailure("APPLICATION_INTERFACE_OPERATION_UNKNOWN")
            if set(files) != {"line_items"}:
                raise RuntimeFailure("APPLICATION_INTERFACE_REQUIRED_FILE_MISSING")
            filename, _media_type, payload = files["line_items"]
            if not filename.lower().endswith(".csv"):
                raise RuntimeFailure("APPLICATION_INTERFACE_FILE_INVALID")
            # Resource persistence happens only after every page, authority, field,
            # operation, and file-shape check above has passed.
            digest = self.runtime_store.add_resource(actor.execution_scope_id, filename, payload)
            result = self.runtime.invoke(
                actor.execution_scope_id,
                operation["capability_id"],
                request,
                resource_digests=[digest],
                resource_bindings={"line_items": [digest]},
                expected_version_digest=contract["application_version"],
                idempotency_key=submission,
                initiator=actor.initiator(),
            )
            completed = self.runtime_store.finish_interface_activity(
                activity["id"],
                status="succeeded",
                invocation_id=result.invocation_id,
                summary="Your verified proforma invoice is ready.",
                result=result.result,
                artifacts=list(result.artifacts),
                receipt=result.receipt,
                source_checked=False,
                state_changed=True,
            )
            return self._activity_projection(completed)
        except RuntimeFailure as exc:
            self.runtime_store.finish_interface_activity(
                activity["id"], status="failed", error_code=exc.code,
                invocation_id=exc.safe_facts.get("invocation_id"),
            )
            raise

    def _submit_portable(self, actor, contract, operation, fields, files, activity):
        from .portable_interfaces import parse_portable_request, project_portable_result
        request = parse_portable_request(
            operation, {
                (key.removeprefix("input.") if key.startswith("input.") else key): value
                for key, value in fields.items() if key not in META_FIELDS
            }
        )
        files = {key.removeprefix("input."): value for key, value in files.items()}
        resources = {item["name"]: item for item in operation["resources"]}
        if set(files) - set(resources):
            raise RuntimeFailure("APPLICATION_INTERFACE_FILE_UNKNOWN")
        selected = {}
        for name, resource in resources.items():
            value = files.get(name, [])
            items = value if isinstance(value, list) else [value]
            if not resource["min_items"] <= len(items) <= resource["max_items"]:
                raise RuntimeFailure("APPLICATION_INTERFACE_RESOURCE_COUNT_INVALID")
            for filename, _media, payload in items:
                if (not filename or filename in {".", ".."} or len(filename) > 255
                    or any(char in filename for char in "/\\\x00\r\n")
                    or not isinstance(payload, bytes) or len(payload) > 64 * 1024 * 1024):
                    raise RuntimeFailure("APPLICATION_INTERFACE_FILE_INVALID")
            selected[name] = items
        bindings = {
            name: [self.runtime_store.add_resource(actor.execution_scope_id, filename, payload)
                   for filename, _media, payload in items]
            for name, items in selected.items()
        }
        started = []
        try:
            result = self.runtime.invoke(
                actor.execution_scope_id, operation["capability_id"], request,
                resource_digests=[digest for values in bindings.values() for digest in values],
                resource_bindings=bindings,
                expected_version_digest=contract["application_version"],
                idempotency_key=fields["submission"], initiator=actor.initiator(),
                on_invocation_started=started.append,
            )
        except RuntimeFailure as exc:
            if started:
                exc.safe_facts.update(application_invoked=True, invocation_id=started[0])
            raise
        facts, artifacts = project_portable_result(operation, result.result, list(result.artifacts))
        completed = self.runtime_store.finish_interface_activity(
            activity["id"], status="succeeded", invocation_id=result.invocation_id,
            summary=operation["user_outcome"], result=facts, artifacts=artifacts,
            receipt=result.receipt, source_checked=False,
            state_changed=bool(artifacts),
        )
        return self._activity_projection(completed)

    def activity(
        self, actor: ActorContext, application_id: str, activity_id: str
    ) -> dict[str, Any]:
        with self.authority_guard(actor) as current:
            contract = self.contract_resolver(current, application_id)
            activity = self.runtime_store.interface_activity(activity_id)
            if (
                activity["principal_id"] != current.principal_id
                or activity["membership_id"] != current.membership_id
                or activity["team_id"] != current.team_id
                or activity["scope_id"] != current.execution_scope_id
                or activity["application_id"] != application_id
                or activity["application_version"] != contract["application_version"]
                or activity["contract_digest"] != contract["digest"]
                or activity["status"] not in {"succeeded", "failed", "running"}
            ):
                raise RuntimeFailure("APPLICATION_INTERFACE_ACTIVITY_DENIED")
            return self._activity_projection(activity)

    def latest_activity(self, actor, application_id):
        """Latest attempt, independent of successful adoption evidence."""
        with self.authority_guard(actor) as current:
            contract = self.contract_resolver(current, application_id)
            with self.runtime_store.connect() as db:
                row = db.execute("""SELECT id FROM interface_activities WHERE principal_id=? AND membership_id=?
                    AND team_id=? AND scope_id=? AND application_id=? AND application_version=?
                    AND contract_digest=? ORDER BY created_at DESC,rowid DESC LIMIT 1""",
                    (current.principal_id, current.membership_id, current.team_id,
                     current.execution_scope_id, application_id, contract['application_version'], contract['digest'])).fetchone()
            return self.activity(current, application_id, row['id']) if row else None

    def watcher_listings(self, actor: ActorContext, reference: str) -> dict[str, Any]:
        """Resolve one opaque, workspace-bound watch reference and read its app projection."""
        with self.authority_guard(actor) as current:
            contract = self.contract_resolver(current, WATCHER_ID)
            watch = self._resolve_watch(current, contract, reference)
            outcome = self._watcher_invoke(
                current,
                contract,
                "watch.listings",
                {"operation": "watch.listings", "selector": {"watch_id": watch["id"]}},
                "interface-listings-" + secrets.token_hex(12),
            )
            return {
                "contract": contract,
                "reference": reference,
                "watch": watch,
                "result": outcome["result"],
                "operation_receipt": outcome["operation_receipt"],
            }

    @staticmethod
    def _activity_request_digest(
        fields: dict[str, str], files: dict[str, tuple[str, str, bytes]]
    ) -> str:
        def identity(entry):
            return {"filename": entry[0], "media_type": entry[1], "size": len(entry[2]),
                    "digest": hashlib.sha256(entry[2]).hexdigest()}
        value = {
            "fields": {
                key: item for key, item in fields.items()
                if key not in {"csrf", "submission"}
            },
            "files": {
                key: ([identity(entry) for entry in item] if isinstance(item, list) else identity(item))
                for key, item in files.items()
            },
        }
        return hashlib.sha256(canonical_json(value)).hexdigest()

    @staticmethod
    def _activity_projection(activity: dict[str, Any]) -> dict[str, Any]:
        return {
            "activity_id": activity["id"],
            "status": activity["status"],
            "application_id": activity["application_id"],
            "application_version": activity["application_version"],
            "operation_id": activity["operation_id"],
            "summary": activity.get("summary") or ("The application operation completed." if activity["status"] == "succeeded" else "No confirmed result."),
            "operation_receipt": activity.get("receipt"),
            "invocation_id": activity.get("invocation_id"),
            "result": activity.get("result") or {},
            "artifacts": activity.get("artifacts") or [],
            "source_checked": bool(activity.get("source_checked")),
            "state_changed": bool(activity.get("state_changed")),
            "created_at": activity["created_at"],
            "completed_at": activity.get("completed_at"),
        }

    def artifact(
        self, actor: ActorContext, invocation_id: str, digest: str, filename: str | None = None
    ) -> tuple[Any, str]:
        with self.authority_guard(actor) as current:
            return self._artifact(current, invocation_id, digest, filename)

    def _artifact(
        self, actor: ActorContext, invocation_id: str, digest: str, filename: str | None = None
    ) -> tuple[Any, str]:
        invocation = self.runtime_store.invocation(invocation_id)
        contract = self.contract_resolver(actor, invocation["capability_id"])
        if (
            invocation["scope_id"] != actor.execution_scope_id
            or invocation["capability_id"] != contract["application_id"]
            or invocation["version_digest"] != contract["application_version"]
            or invocation["status"] != "succeeded"
        ):
            raise RuntimeFailure("APPLICATION_INTERFACE_ARTIFACT_DENIED")
        artifacts = invocation.get("artifacts") or []
        matches = [item for item in artifacts if item.get("digest") == digest
                   and (filename is None or item.get("filename") == filename)]
        if len(matches) != 1:
            raise RuntimeFailure("APPLICATION_INTERFACE_ARTIFACT_DENIED")
        match = matches[0]
        if match is None:
            raise RuntimeFailure("APPLICATION_INTERFACE_ARTIFACT_DENIED")
        operation = contract["operations"][0]
        if match.get("filename") not in operation["result"]["artifacts"]:
            raise RuntimeFailure("APPLICATION_INTERFACE_ARTIFACT_DENIED")
        path, _stored_name = self.runtime_store.resource(actor.execution_scope_id, digest)
        return path, match["filename"]

    def _watcher_invoke(
        self,
        actor: ActorContext,
        contract: dict[str, Any],
        operation_id: str,
        request: dict[str, Any],
        idempotency_key: str,
    ) -> dict[str, Any]:
        if self.operations is None:
            raise RuntimeFailure("APPLICATION_UNAVAILABLE")
        operation = next(
            (item for item in contract["operations"] if item["operation_id"] == operation_id),
            None,
        )
        if operation is None:
            raise RuntimeFailure("APPLICATION_INTERFACE_OPERATION_UNKNOWN")
        conversations = self.chat_store.list_conversations(actor)
        conversation_id = conversations[0]["id"] if conversations else "application-interface"
        if not conversations and operation_id == "watch.create":
            conversation_id = self.chat_store.create_conversation(actor, "Application activity")
        return self.operations.invoke(
            OperationContext(actor, conversation_id, operation["title"], (), idempotency_key),
            operation["capability_id"], contract["application_version"], request,
        )

    def _resolve_watch(
        self, actor: ActorContext, contract: dict[str, Any], reference: str
    ) -> dict[str, Any]:
        outcome = self._watcher_invoke(
            actor, contract, "watch.list", {"operation": "watch.list"},
            "interface-selector-" + secrets.token_hex(12),
        )
        matches = [
            item for item in outcome["result"]["watches"]
            if hmac.compare_digest(self._watch_reference(actor, contract, item["id"]), reference)
        ]
        if len(matches) != 1:
            raise RuntimeFailure("APPLICATION_INTERFACE_TARGET_STALE")
        return matches[0]

    def _watch_reference(
        self, actor: ActorContext, contract: dict[str, Any], watch_id: str
    ) -> str:
        payload = canonical_json({
            "application_id": WATCHER_ID,
            "application_version": contract["application_version"],
            "contract_digest": contract["digest"],
            "membership_id": actor.membership_id,
            "principal_id": actor.principal_id,
            "team_id": actor.team_id,
            "watch_id": watch_id,
        })
        return hmac.new(self._reference_key, payload, hashlib.sha256).hexdigest()

    @staticmethod
    def _validate_binding(
        actor: ActorContext, contract: dict[str, Any], fields: dict[str, str]
    ) -> None:
        if (
            fields.get("application_version") != contract["application_version"]
            or fields.get("contract_digest") != contract["digest"]
            or fields.get("workspace_membership_id") != actor.membership_id
        ):
            raise RuntimeFailure("APPLICATION_INTERFACE_STALE")

    @staticmethod
    def _set_path(target: dict[str, Any], path: str, value: Any) -> None:
        current = target
        parts = path.split(".")
        for part in parts[:-1]:
            existing = current.setdefault(part, {})
            if not isinstance(existing, dict):
                raise RuntimeFailure("APPLICATION_INTERFACE_FIELD_INVALID")
            current = existing
        current[parts[-1]] = value

    @classmethod
    def _human_watcher_result(cls, value: Any) -> Any:
        """Remove application-internal identities from the human result panel."""
        if isinstance(value, dict):
            return {
                key: cls._human_watcher_result(item)
                for key, item in value.items()
                if key not in {
                    "id", "watch_id", "creator_membership_id", "creator_principal_id"
                }
            }
        if isinstance(value, list):
            return [cls._human_watcher_result(item) for item in value]
        return value

    @staticmethod
    def _watch_presentation_projection(value: Any) -> dict[str, Any] | None:
        """Allowlist only facts consumed by the human watch presenter."""

        if not isinstance(value, dict):
            return None
        filters = value.get("filters") or value.get("hard_filters")
        if not isinstance(filters, dict):
            return None
        projected_filters = {
            key: filters[key]
            for key in ("make", "model", "min_year", "max_year")
            if key in filters
        }
        projection = {
            "filters": projected_filters,
            **{
                key: value[key]
                for key in (
                    "status", "schedule_seconds", "baseline_at",
                    "baseline_pending", "baseline_established",
                )
                if key in value
            },
        }
        return projection
