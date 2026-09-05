"""Trusted chat turn controller: model proposes; current world revalidates."""

from __future__ import annotations

import hashlib
import json
import re
import traceback
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Literal

from .access import ActorContext
from .application_operations import ApplicationOperationRegistry, OperationContext
from .interaction_contracts import InteractionContractRegistry
from .chat import ChatStore
from .encar_watcher_build import (
    NONTECHNICAL_SUMMARY as ENCAR_WATCHER_SUMMARY,
    is_exact_gap as is_exact_encar_watcher_gap,
    specification as encar_watcher_specification,
    validate_specification as validate_encar_watcher_specification,
)
from .generic_build import GenericBuildRequest
from .model import RuntimeFailure
from .runtime import OutcomeRuntime
from .semantic import SemanticResult, TURN_SCHEMA, SemanticAdapter, validate_decision_for_world
from .semantic_dispatch import SemanticDispatchStore
from .store import RuntimeStore
from .world import WorldBuilder, WorldSnapshot


ProblemCategory = Literal[
    "USER_INPUT",
    "ACCESS_DENIED",
    "CAPY_SETUP",
    "TEMPORARY_EXTERNAL",
    "SOFTWARE_PROBLEM",
    "INTERNAL_PROBLEM",
]
ProblemResponsibility = Literal["user_input", "capy", "external_provider", "software"]
ProblemRetryability = bool | Literal["after_input_change"]


@dataclass(frozen=True)
class ProblemPresentation:
    """Bounded controller-owned wording for a stable machine-known failure."""

    category: ProblemCategory
    title: str
    explanation: str
    next_action: str
    retryable: ProblemRetryability
    responsible_party: ProblemResponsibility


PROBLEM_PRESENTATIONS: dict[str, ProblemPresentation] = {
    "SCOPE_EXECUTION_IDENTITY_UNKNOWN": ProblemPresentation(
        category="CAPY_SETUP",
        title="Capy could not run this software for your team membership.",
        explanation="Your file was not processed and no invoice was created.",
        next_action=(
            "Changing the file or retrying will not fix this. "
            "Capy setup must be repaired."
        ),
        retryable=False,
        responsible_party="capy",
    ),
    "PROFORMA_CSV_HEADER_INVALID": ProblemPresentation(
        category="USER_INPUT",
        title="The uploaded CSV does not match the format accepted by the invoice software.",
        explanation="No invoice was created.",
        next_action=(
            "Use exactly these columns in this order: "
            "sku, description, quantity, unit_price. "
            "Then retry with the corrected file."
        ),
        retryable="after_input_change",
        responsible_party="user_input",
    ),
    "SEMANTIC_PROVIDER_ERROR": ProblemPresentation(
        category="TEMPORARY_EXTERNAL",
        title="The language service is temporarily unavailable.",
        explanation="Capy did not select or run software for this request.",
        next_action="Retry the request in a moment.",
        retryable=True,
        responsible_party="external_provider",
    ),
    "SEMANTIC_PROVIDER_HTTP": ProblemPresentation(
        category="TEMPORARY_EXTERNAL",
        title="The language service temporarily rejected the request.",
        explanation="Capy did not select or run software for this request.",
        next_action="Retry the request in a moment.",
        retryable=True,
        responsible_party="external_provider",
    ),
    "SEMANTIC_PROVIDER_RATE_LIMIT": ProblemPresentation(
        category="TEMPORARY_EXTERNAL",
        title="The language service is temporarily busy.",
        explanation="Capy exhausted its bounded delayed recovery window. No software or external action ran.",
        next_action="Try again later. The problem reference contains the safe attempt history.",
        retryable=True,
        responsible_party="external_provider",
    ),
    "SEMANTIC_PROVIDER_TEMPORARY": ProblemPresentation(
        category="TEMPORARY_EXTERNAL",
        title="The language service is temporarily unavailable.",
        explanation="Capy exhausted its bounded delayed recovery window. No software or external action ran.",
        next_action="Try again later.",
        retryable=True,
        responsible_party="external_provider",
    ),
    "SEMANTIC_PROVIDER_ERROR_ENVELOPE": ProblemPresentation(
        category="TEMPORARY_EXTERNAL",
        title="The language service rejected the request.",
        explanation="Capy did not select or run software for this request.",
        next_action="Contact the Capy operator with the problem reference.",
        retryable=False,
        responsible_party="external_provider",
    ),
    "SEMANTIC_PROVIDER_RECOVERY_EXPIRED": ProblemPresentation(
        category="TEMPORARY_EXTERNAL",
        title="The language-service recovery window ended.",
        explanation="Capy did not select or run software for this request.",
        next_action="Submit a new request if you still want this outcome.",
        retryable=True,
        responsible_party="external_provider",
    ),
    "SEMANTIC_PROVIDER_RESPONSE_INVALID": ProblemPresentation(
        category="TEMPORARY_EXTERNAL",
        title="The language service returned an unusable response.",
        explanation="Capy did not select or run software for this request.",
        next_action="Retry the request. If it repeats, contact the Capy operator with the problem reference.",
        retryable=True,
        responsible_party="external_provider",
    ),
    "SEMANTIC_DECISION_INVALID": ProblemPresentation(
        category="TEMPORARY_EXTERNAL",
        title="The language service returned an unusable action.",
        explanation="Capy did not select or run software for this request.",
        next_action="Retry the request. If it repeats, contact the Capy operator with the problem reference.",
        retryable=True,
        responsible_party="external_provider",
    ),
    "SEMANTIC_PROVIDER_IDENTITY_MISMATCH": ProblemPresentation(
        category="CAPY_SETUP",
        title="Capy could not verify the configured language service.",
        explanation="No software or external action ran.",
        next_action="Contact the Capy operator with the problem reference.",
        retryable=False,
        responsible_party="capy",
    ),
    "APPLICATION_OPERATION_STALE": ProblemPresentation(
        category="TEMPORARY_EXTERNAL",
        title="The installed software changed before Capy could run it.",
        explanation="The requested operation was not run against stale software authority.",
        next_action="Retry so Capy can use the current installed software.",
        retryable=True,
        responsible_party="capy",
    ),
    "APPLICATION_TARGET_NOT_FOUND": ProblemPresentation(
        category="USER_INPUT",
        title="Capy could not find one visible watch matching that description.",
        explanation="No watch was changed and the vehicle source was not checked.",
        next_action="Name the make or model of a watch visible to you, or ask Capy to list your watches.",
        retryable=False,
        responsible_party="user_input",
    ),
    "APPLICATION_TARGET_AMBIGUOUS": ProblemPresentation(
        category="USER_INPUT",
        title="More than one visible watch matches that description.",
        explanation="Capy did not choose a watch, change state, or check the vehicle source.",
        next_action="Specify the make, model, years, or visibility of the watch you mean.",
        retryable=False,
        responsible_party="user_input",
    ),
    "APPLICATION_ACCESS_DENIED": ProblemPresentation(
        category="ACCESS_DENIED",
        title="You cannot use that operation on the selected watch.",
        explanation="No watch was changed and the vehicle source was not checked.",
        next_action="Choose a watch you manage or ask a team owner to perform this operation.",
        retryable=False,
        responsible_party="user_input",
    ),
    "ACCESS_MEMBERSHIP_REVOKED": ProblemPresentation(
        category="ACCESS_DENIED",
        title="This team membership was revoked before Capy could complete the request.",
        explanation="No application operation was authorized after revocation.",
        next_action="Ask a team owner to restore access, then submit a new request.",
        retryable=False,
        responsible_party="user_input",
    ),
    "ACCESS_ACTIVE_MEMBERSHIP_REQUIRED": ProblemPresentation(
        category="ACCESS_DENIED",
        title="An active team membership is required for this request.",
        explanation="Capy did not authorize an application operation.",
        next_action="Join or switch to an active team membership, then submit a new request.",
        retryable=False,
        responsible_party="user_input",
    ),
    "APPLICATION_INPUT_INVALID": ProblemPresentation(
        category="USER_INPUT",
        title="The selected software cannot apply those watch changes.",
        explanation="No watch was changed and the vehicle source was not checked.",
        next_action="Use the supported years or attention-intent fields, or ask what the watch supports.",
        retryable="after_input_change",
        responsible_party="user_input",
    ),
    "APPLICATION_TIMEOUT": ProblemPresentation(
        category="TEMPORARY_EXTERNAL",
        title="The selected software did not respond in time.",
        explanation="Capy could not verify a completed result or effect.",
        next_action="Retry the request. If it repeats, contact the Capy operator with the problem reference.",
        retryable=True,
        responsible_party="software",
    ),
    "APPLICATION_SOURCE_UNAVAILABLE": ProblemPresentation(
        category="TEMPORARY_EXTERNAL",
        title="The vehicle source is temporarily unavailable.",
        explanation="The watch remains stored, but this check did not complete.",
        next_action="Retry the check later.",
        retryable=True,
        responsible_party="external_provider",
    ),
    "APPLICATION_STATE_UNAVAILABLE": ProblemPresentation(
        category="SOFTWARE_PROBLEM",
        title="The selected software could not safely read its current state.",
        explanation="No watch result or change is claimed.",
        next_action="Retry once. If it repeats, contact the Capy operator with the problem reference.",
        retryable=True,
        responsible_party="software",
    ),
    "APPLICATION_INVALID_RESPONSE": ProblemPresentation(
        category="SOFTWARE_PROBLEM",
        title="The selected software returned an invalid result.",
        explanation="Capy did not claim a watch result or completed effect.",
        next_action="Contact the Capy operator with the problem reference.",
        retryable=False,
        responsible_party="software",
    ),
    "APPLICATION_UNAVAILABLE": ProblemPresentation(
        category="SOFTWARE_PROBLEM",
        title="The selected team software is unavailable.",
        explanation="No watch operation or source check completed.",
        next_action="Contact the Capy operator with the problem reference.",
        retryable=False,
        responsible_party="software",
    ),
}

INTERNAL_PROBLEM = ProblemPresentation(
    category="INTERNAL_PROBLEM",
    title="Capy encountered an internal problem and did not complete this request.",
    explanation="No result or external action should be assumed.",
    next_action="Contact the Capy operator with the problem reference.",
    retryable=False,
    responsible_party="capy",
)


def present_problem(error_code: str) -> ProblemPresentation:
    """Return deterministic safe copy without asking the model to reinterpret an error."""

    return PROBLEM_PRESENTATIONS.get(error_code, INTERNAL_PROBLEM)


class ProductController:
    def __init__(
        self,
        runtime_store: RuntimeStore,
        chat_store: ChatStore,
        runtime: OutcomeRuntime,
        world: WorldBuilder,
        semantic: SemanticAdapter,
        builder: Any | None = None,
        generic_build_coordinator: Any | None = None,
        encar_watcher_runtime: Any | None = None,
        application_operations: ApplicationOperationRegistry | None = None,
        semantic_dispatch: SemanticDispatchStore | None = None,
        actor_resolver: Any | None = None,
        interaction_contracts: InteractionContractRegistry | None = None,
    ):
        self.runtime_store = runtime_store
        self.chat_store = chat_store
        self.runtime = runtime
        self.world = world
        self.semantic = semantic
        self.builder = builder
        self.generic_build_coordinator = generic_build_coordinator
        self.encar_watcher_runtime = encar_watcher_runtime
        self.application_operations = application_operations
        self.semantic_dispatch = semantic_dispatch
        self.actor_resolver = actor_resolver
        self.interaction_contracts = interaction_contracts

    def application_contracts(self, actor: ActorContext) -> list[dict[str, Any]]:
        """Return exact contracts for software visible in the actor's current world."""

        return list(self.world.build(actor, []).value.get("applications", []))

    def application_contract(
        self, actor: ActorContext, application_id: str
    ) -> dict[str, Any]:
        matches = [
            item for item in self.application_contracts(actor)
            if item["application_id"] == application_id
        ]
        if len(matches) != 1:
            raise RuntimeFailure("APPLICATION_CONTRACT_NOT_AVAILABLE")
        return matches[0]

    def approve_build(
        self,
        authority: str | ActorContext,
        gap_id: str,
        specification: dict[str, Any] | None = None,
        *,
        proposal_digest: str | None = None,
    ) -> dict[str, Any]:
        scope_id = self._scope(authority)
        proposal = self.chat_store.build_proposal_for_gap(authority, gap_id)
        gap = self.chat_store.gap(scope_id, gap_id)
        if proposal is None and is_exact_encar_watcher_gap(gap):
            if not isinstance(authority, ActorContext) or authority.membership_kind != "owner":
                raise RuntimeFailure("BUILD_APPROVAL_OWNER_REQUIRED")
            if specification is not None or proposal_digest is not None:
                raise RuntimeFailure("BUILD_PROPOSAL_RAW_SPEC_FORBIDDEN")
            return self.chat_store.create_build_proposal(
                authority,
                gap_id,
                encar_watcher_specification(),
                dict(ENCAR_WATCHER_SUMMARY),
            )
        if self.builder is None:
            raise RuntimeFailure("BUILDER_UNAVAILABLE")
        if proposal is not None:
            if isinstance(authority, ActorContext) and authority.membership_kind != "owner":
                raise RuntimeFailure("BUILD_APPROVAL_OWNER_REQUIRED")
            if specification is not None:
                raise RuntimeFailure("BUILD_PROPOSAL_RAW_SPEC_FORBIDDEN")
            if proposal_digest is None:
                raise RuntimeFailure("BUILD_PROPOSAL_DIGEST_REQUIRED")
            proposal = self.chat_store.begin_build_proposal_approval(
                authority, gap_id, proposal_digest
            )
            if proposal["status"] == "APPROVED":
                build = self.chat_store.build(proposal["approved_build_id"], scope_id)
                if proposal["specification"].get("application") != "vehicles.encar_watcher":
                    self._run_generic_build_coordinator(build, proposal)
                return build
            try:
                if proposal["specification"].get("application") == "vehicles.encar_watcher":
                    validate_encar_watcher_specification(proposal["specification"])
                    build = self.builder.approve_encar_watcher(
                        scope_id, gap_id, proposal["specification"]
                    )
                else:
                    build = self.builder.approve_with_spec(
                        scope_id, gap_id, proposal["specification"]
                    )
            except Exception as exc:
                code = exc.code if isinstance(exc, RuntimeFailure) else "BUILD_APPROVAL_FAILED"
                self.chat_store.finish_build_proposal_approval(
                    proposal["id"], error_code=code
                )
                raise
            self.chat_store.finish_build_proposal_approval(
                proposal["id"], build_id=build["id"]
            )
            if proposal["specification"].get("application") != "vehicles.encar_watcher":
                self._run_generic_build_coordinator(build, proposal)
            return build
        if specification is not None:
            return self.builder.approve_with_spec(scope_id, gap_id, specification)
        return self.builder.approve(scope_id, gap_id)

    def register_build_proposal(
        self,
        authority: str | ActorContext,
        gap_id: str,
        specification: dict[str, Any],
        summary: dict[str, str],
        *,
        blocked_reason: str | None = None,
    ) -> dict[str, Any]:
        """Record a trusted internal proposal; this is deliberately not a web endpoint."""

        required_summary = {
            "reads", "produces", "external_connection", "persistent_state", "changes"
        }
        if (
            not isinstance(summary, dict)
            or set(summary) != required_summary
            or not all(isinstance(value, str) and value.strip() for value in summary.values())
            or not isinstance(specification, dict)
            or (blocked_reason is not None and not blocked_reason.strip())
        ):
            raise RuntimeFailure("BUILD_PROPOSAL_INVALID")
        if blocked_reason is None:
            if self.builder is None:
                raise RuntimeFailure("BUILDER_UNAVAILABLE")
            self.builder._validate_supervised_specification(specification)
        return self.chat_store.create_build_proposal(
            authority,
            gap_id,
            specification,
            {key: value.strip() for key, value in summary.items()},
            blocked_reason=blocked_reason.strip() if blocked_reason is not None else None,
        )

    def _run_generic_build_coordinator(
        self, build: dict[str, Any], proposal: dict[str, Any]
    ) -> None:
        coordinator = self.generic_build_coordinator
        if coordinator is None or self.chat_store.generic_build_outcome(build["id"]) is not None:
            return
        provenance: dict[str, Any] = {
            "input_resource_digests": list(build["resources"]),
            "proposal_digest": proposal["proposal_digest"],
        }
        classification = "ORCHESTRATION_FAILED"
        detail: str | None = None
        try:
            current = {
                item["digest"] for item in self.chat_store.visible_resources(
                    build["scope_id"], build["conversation_id"]
                )
            }
            for digest in build["resources"]:
                if digest not in current:
                    raise RuntimeFailure("ATTACHMENTS_CHANGED")
                try:
                    path, _filename = self.runtime_store.resource(build["scope_id"], digest)
                    payload_digest = hashlib.sha256(path.read_bytes()).hexdigest()
                except OSError as exc:
                    raise RuntimeFailure("ATTACHMENTS_CHANGED") from exc
                if payload_digest != digest:
                    raise RuntimeFailure("ATTACHMENTS_CHANGED")
            packet_path, _markdown_path = self.builder.packet_paths(build["id"])
            packet_bytes = packet_path.read_bytes()
            if hashlib.sha256(packet_bytes).hexdigest() != build["packet_digest"]:
                raise RuntimeFailure("BUILD_PACKET_DIGEST_MISMATCH")
            packet = json.loads(packet_bytes)
            outcome = coordinator.run(GenericBuildRequest(build["id"], packet))
            classification = str(getattr(outcome, "classification", "ORCHESTRATION_FAILED"))
            detail_value = getattr(outcome, "detail", None)
            detail = str(detail_value) if detail_value is not None else None
            candidate = getattr(outcome, "candidate", None)
            if candidate is not None:
                provenance["candidate"] = {
                    "repository": candidate.repository,
                    "commit": candidate.commit,
                    "tree": candidate.tree,
                    "archive_digest": candidate.archive_digest,
                }
            publication = getattr(outcome, "publication", None)
            if publication is not None:
                provenance["publication"] = self._safe_provenance_mapping(
                    dict(publication.identity)
                )
            retry = getattr(outcome, "retry_result", None)
            if isinstance(retry, dict):
                for key in ("invocation_id", "invocation_receipt_sha256"):
                    if isinstance(retry.get(key), str):
                        provenance[key] = retry[key]
                semantic_decision = retry.get("semantic_decision")
                if (
                    isinstance(retry.get("turn_id"), str)
                    and isinstance(retry.get("scope_id"), str)
                    and isinstance(retry.get("semantic_provider"), str)
                    and isinstance(retry.get("semantic_model"), str)
                    and isinstance(semantic_decision, dict)
                ):
                    provenance["semantic_retry"] = {
                        "turn_id": retry["turn_id"],
                        "scope_id": retry["scope_id"],
                        "provider": retry["semantic_provider"],
                        "model": retry["semantic_model"],
                        "action": semantic_decision.get("action"),
                        "capability_id": semantic_decision.get("capability_id"),
                        "resources": semantic_decision.get("resources"),
                    }
                receipt = retry.get("invocation_receipt") or retry.get("receipt")
                if isinstance(receipt, dict):
                    provenance["invocation_receipt"] = self._safe_provenance_mapping(receipt)
                shared_host_proof = retry.get("shared_host_proof")
                if isinstance(shared_host_proof, dict):
                    provenance["shared_host_proof"] = self._safe_provenance_mapping(
                        shared_host_proof
                    )
        except RuntimeFailure as exc:
            classification = exc.code
            detail = exc.code
        except Exception as exc:
            classification = "ORCHESTRATION_FAILED"
            detail = type(exc).__name__
        self.chat_store.record_generic_build_outcome(
            build["id"], classification, provenance, detail
        )

    @classmethod
    def _safe_provenance_mapping(cls, value: dict[str, Any]) -> dict[str, Any]:
        allowed = {
            "schema", "status", "failure_code", "invocation_id", "capability_id",
            "version_digest", "input_digest", "output_digest", "result_digest",
            "artifact_digests", "application_archive_digest", "archive_digest",
            "publication_identity_digest", "devkit_wheel_digest",
            "devkit_environment_digest", "candidate_commit", "candidate_tree",
            "acceptance_digest", "cleanup", "connection_receipts", "contract",
            "operation", "request_digest", "response_digest", "commit", "tree",
            "repository", "id", "scope_id", "idempotency_key", "started_at",
            "completed_at", "processes_remaining", "mounts_remaining",
            "temporary_files_remaining",
            "launcher", "restart_reread_without_reexecution", "provider", "model",
            "turn_id", "action", "resources", "candidate_commit", "candidate_tree",
            "application_archive_sha256", "acceptance_receipt_sha256",
            "publication_identity_sha256", "result_sha256", "artifacts",
            "resource_bindings", "digest", "filename", "size_bytes",
        }
        safe: dict[str, Any] = {}
        for key, item in value.items():
            if not isinstance(key, str) or key not in allowed:
                continue
            if isinstance(item, dict):
                safe[key] = cls._safe_provenance_mapping(item)
            elif isinstance(item, list):
                safe[key] = [
                    cls._safe_provenance_mapping(entry) if isinstance(entry, dict) else entry
                    for entry in item
                    if isinstance(entry, (str, int, float, bool, type(None), dict))
                ]
            elif isinstance(item, (str, int, float, bool, type(None))):
                safe[key] = item
        return safe

    def retry_build(self, build_id: str) -> str:
        if self.builder is None:
            raise RuntimeFailure("BUILDER_UNAVAILABLE")
        build = self.chat_store.build(build_id)
        if build["status"] != "PUBLISHED":
            raise RuntimeFailure("BUILD_STATE_CONFLICT")
        gap = self.chat_store.gap(build["scope_id"], build["gap_id"])
        snapshot = self.snapshot(build["scope_id"], build["conversation_id"])
        turn_id = self.chat_store.begin_build_retry(
            build_id,
            build["scope_id"], build["conversation_id"],
            build["original_owner_message_id"], snapshot.digest,
            self.semantic.name, self.semantic.model,
        )
        request = {
            "schema": "capy.semantic-request/v0",
            "owner_message": gap["original_message"],
            "conversation": self.chat_store.context(
                build["scope_id"], build["conversation_id"]
            ),
            "world": snapshot.value,
        }
        try:
            installed = {
                item["id"]: item for item in snapshot.value["capabilities"]
            }
            published = build["published_binding"] or {}
            capability = installed.get(build["candidate_capability_id"])
            if (
                capability is None
                or published.get("capability_id") != build["candidate_capability_id"]
                or published.get("version_digest") != capability["version_digest"]
            ):
                raise RuntimeFailure("BUILD_RETRY_AUTHORITY_MISMATCH")
            unavailable_connections = self._unavailable_connections(capability)
            if unavailable_connections:
                self._finish_connection_required(
                    build["scope_id"], build["conversation_id"], turn_id,
                    {
                        "schema": TURN_SCHEMA,
                        "action": "invoke",
                        "message": "",
                        "capability_id": build["candidate_capability_id"],
                        "input": {},
                        "resources": list(build["resources"]),
                        "gap": None,
                    },
                    snapshot,
                    {},
                    unavailable_connections,
                )
                self.chat_store.transition_build(
                    build_id, {"RETRYING"}, "COMPLETED", retry_turn_id=turn_id
                )
                return turn_id
            semantic = self.semantic.decide(request)
            if semantic.provider != self.semantic.name or semantic.model != self.semantic.model:
                raise RuntimeFailure("SEMANTIC_PROVIDER_IDENTITY_MISMATCH")
            decision = validate_decision_for_world(semantic.decision, snapshot.value)
            if decision["action"] != "invoke":
                raise RuntimeFailure("BUILD_RETRY_DID_NOT_INVOKE")
            expected_resources = list(build["resources"])
            if (
                decision["capability_id"] != build["candidate_capability_id"]
                or decision["resources"] != expected_resources
                or published.get("capability_id") != decision["capability_id"]
                or published.get("version_digest")
                != installed[decision["capability_id"]]["version_digest"]
            ):
                raise RuntimeFailure("BUILD_RETRY_AUTHORITY_MISMATCH")
            self._invoke(
                build["scope_id"], build["conversation_id"], turn_id,
                decision, snapshot, semantic.usage,
                idempotency_key=f"build-retry:{build_id}",
            )
            self.chat_store.transition_build(
                build_id, {"RETRYING"}, "COMPLETED", retry_turn_id=turn_id
            )
        except Exception as exc:
            code = exc.code if isinstance(exc, RuntimeFailure) else "BUILD_RETRY_FAILED"
            try:
                self.chat_store.finish_turn(turn_id, "problem", error_code=code)
            except RuntimeFailure:
                pass
            self.chat_store.transition_build(
                build_id, {"RETRYING"}, "BLOCKED",
                retry_turn_id=turn_id, terminal_error=code,
            )
            raise
        return turn_id

    @staticmethod
    def _scope(authority: str | ActorContext) -> str:
        return authority.execution_scope_id if isinstance(authority, ActorContext) else authority

    def snapshot(self, authority: str | ActorContext, conversation_id: str) -> WorldSnapshot:
        return self.world.build(
            authority, self.chat_store.visible_resources(authority, conversation_id)
        )

    def provide_chat_semantic(self, payload: dict[str, Any]) -> dict[str, Any]:
        transport = payload.get("transport", "monolithic")
        stage = payload.get("stage", "decision")
        dispatch_usage = None
        if transport == "two_stage" and stage == "route":
            semantic = self.semantic.decide_route(payload["request"])
        elif transport == "two_stage" and stage == "operation_input":
            route = payload["route_result"]
            semantic = self.semantic.decide_operation(
                payload["request"], route["decision"]
            )
            dispatch_usage = semantic.usage
            if (
                semantic.decision.get("action") in {"invoke", "clarify"}
                and semantic.decision.get("capability_id")
                != route["decision"]["capability_id"]
            ):
                raise RuntimeFailure("TURN_CAPABILITY_NOT_IN_WORLD")
            semantic = SemanticResult(
                semantic.decision, semantic.provider, semantic.model,
                self._combined_semantic_usage(
                    route.get("usage") or {}, semantic.usage
                ),
            )
        else:
            semantic = self.semantic.decide(payload["request"])
        response = {
            "decision": semantic.decision,
            "provider": semantic.provider,
            "model": semantic.model,
            "usage": semantic.usage,
        }
        if dispatch_usage is not None:
            response["dispatch_usage"] = dispatch_usage
        return response

    @staticmethod
    def _combined_semantic_usage(
        route_usage: dict[str, Any], operation_usage: dict[str, Any]
    ) -> dict[str, Any]:
        combined = dict(operation_usage)
        for field in ("prompt_tokens", "completion_tokens", "total_tokens", "cost"):
            left = route_usage.get(field)
            right = operation_usage.get(field)
            if type(left) in {int, float} or type(right) in {int, float}:
                combined[field] = (left or 0) + (right or 0)
        combined["semantic_provider_call_count"] = 2
        combined["semantic_transport"] = "route_then_operation_input"
        combined["semantic_stage_receipts"] = [
            {
                "stage": "route",
                "request_sha256": route_usage.get("semantic_request_sha256"),
                "response_sha256": route_usage.get("response_sha256"),
                "provider_request_id": route_usage.get("provider_request_id"),
                "total_tokens": route_usage.get("total_tokens"),
                "cost": route_usage.get("cost"),
            },
            {
                "stage": "operation_input",
                "request_sha256": operation_usage.get("semantic_request_sha256"),
                "response_sha256": operation_usage.get("response_sha256"),
                "provider_request_id": operation_usage.get("provider_request_id"),
                "total_tokens": operation_usage.get("total_tokens"),
                "cost": operation_usage.get("cost"),
            },
        ]
        return combined

    def consume_chat_semantic(self, job: dict[str, Any], result: dict[str, Any]) -> None:
        payload = job["payload"]
        turn = self.chat_store.turn(payload["turn_id"])
        if turn["status"] != "working":
            return
        if self.actor_resolver is None:
            raise RuntimeFailure("SEMANTIC_DISPATCH_ACTOR_RESOLVER_UNAVAILABLE")
        actor = self.actor_resolver(payload["client_id"], payload["membership_id"])
        snapshot = WorldSnapshot(payload["request"]["world"], payload["world_digest"])
        decision = None
        semantic_usage: dict[str, Any] = {}
        try:
            if (
                payload.get("transport") == "two_stage"
                and payload.get("stage") == "route"
                and result.get("decision", {}).get("action") == "invoke"
            ):
                self.semantic_dispatch.enqueue(
                    "chat_turn", f"chat:{payload['turn_id']}:operation_input",
                    {
                        **payload,
                        "stage": "operation_input",
                        "route_result": result,
                    },
                )
                return
            semantic = SemanticResult(
                result["decision"], result["provider"], result["model"], result.get("usage") or {}
            )
            semantic_usage = semantic.usage
            model_calls = int(semantic_usage.get("semantic_attempt_count") or job["attempt_count"])
            if semantic.provider != self.semantic.name or semantic.model != self.semantic.model:
                raise RuntimeFailure("SEMANTIC_PROVIDER_IDENTITY_MISMATCH")
            decision = validate_decision_for_world(semantic.decision, snapshot.value)
            self._apply_semantic_decision(
                actor, payload["conversation_id"], payload["turn_id"], decision,
                snapshot, semantic, payload.get("resources") or [], payload["request"]["owner_message"],
            )
        except Exception as exc:
            code = exc.code if isinstance(exc, RuntimeFailure) else "TURN_INTERNAL_ERROR"
            presentation = present_problem(code)
            self.chat_store.record_problem_incident(
                payload["turn_id"], payload["conversation_id"],
                self._problem_incident_facts(
                    exc=exc, code=code, component="semantic_dispatch_consumer",
                    turn_id=payload["turn_id"], snapshot=snapshot, decision=decision,
                    semantic_usage=semantic_usage, model_calls=model_calls,
                ),
            )
            self.chat_store.append_message(
                actor, payload["conversation_id"], "assistant", presentation.title,
                kind="problem", state="PROBLEM",
                metadata=self._problem_metadata(code, presentation, payload["turn_id"], decision, snapshot),
            )
            self.chat_store.finish_turn(
                payload["turn_id"], "problem",
                action=self._recorded_action(
                    decision, "The controller did not complete this proposed invocation."
                ) if decision is not None else None,
                error_code=code, usage=semantic_usage,
            )

    def consume_chat_semantic_failure(self, job: dict[str, Any]) -> None:
        payload = job["payload"]
        turn = self.chat_store.turn(payload["turn_id"])
        if turn["status"] != "working":
            return
        if self.actor_resolver is None:
            raise RuntimeFailure("SEMANTIC_DISPATCH_ACTOR_RESOLVER_UNAVAILABLE")
        actor = self.actor_resolver(payload["client_id"], payload["membership_id"])
        attempts = list(job["attempts"])
        route_result = payload.get("route_result")
        if isinstance(route_result, dict):
            route_usage = route_result.get("usage") or {}
            attempts.insert(0, {
                "attempt": 1,
                "stage": "route",
                "outcome": "success",
                "model_calls": int(route_usage.get("semantic_attempt_count") or 1),
                "semantic_attempts": route_usage.get("semantic_attempts"),
                "request_sha256": route_usage.get("semantic_request_sha256"),
                "response_sha256": route_usage.get("response_sha256"),
                "provider_request_id": route_usage.get("provider_request_id"),
                "prompt_tokens": route_usage.get("prompt_tokens"),
                "completion_tokens": route_usage.get("completion_tokens"),
                "total_tokens": route_usage.get("total_tokens"),
                "cost": route_usage.get("cost"),
            })
        last = attempts[-1] if attempts else {}
        model_calls = sum(
            int(item["model_calls"])
            if type(item.get("model_calls")) is int
            else (0 if item.get("outcome") == "recovery_expired" else 1)
            for item in attempts
        )
        safe_facts = {
            "semantic_attempt_count": model_calls,
            "semantic_retry_used": model_calls > 1,
            "semantic_attempts": attempts,
            "model_calls": model_calls,
            "provider_http_status": last.get("provider_http_status"),
            "provider_response_sha256": last.get("provider_response_sha256"),
            "provider_response_bytes": last.get("provider_response_bytes"),
            "provider_request_id": last.get("provider_request_id"),
            "provider_envelope": {"error_code": last.get("provider_error_code")},
            "semantic_failure_shape": last.get("semantic_failure_shape"),
            "application_calls": 0, "source_calls": 0, "effect_count": 0,
            "execution_phase": "pre_execution",
        }
        exc = RuntimeFailure(job["error_code"] or "SEMANTIC_PROVIDER_ERROR", safe_facts=safe_facts)
        snapshot = WorldSnapshot(payload["request"]["world"], payload["world_digest"])
        code = exc.code
        presentation = present_problem(code)
        self.chat_store.record_problem_incident(
            payload["turn_id"], payload["conversation_id"],
            self._problem_incident_facts(
                exc=exc, code=code, component="semantic_dispatch", turn_id=payload["turn_id"],
                snapshot=snapshot, decision=None, semantic_usage={},
                model_calls=model_calls,
            ),
        )
        self.chat_store.append_message(
            actor, payload["conversation_id"], "assistant", presentation.title,
            kind="problem", state="PROBLEM",
            metadata=self._problem_metadata(code, presentation, payload["turn_id"], None, snapshot),
        )
        self.chat_store.finish_turn(
            payload["turn_id"], "problem", error_code=code,
            usage={
                "semantic_attempt_count": model_calls,
                "semantic_attempts": attempts,
            },
        )

    def _apply_semantic_decision(
        self,
        authority: str | ActorContext,
        conversation_id: str,
        turn_id: str,
        decision: dict[str, Any],
        snapshot: WorldSnapshot,
        semantic: SemanticResult,
        resources: list[dict[str, Any]],
        owner_text: str,
    ) -> None:
        contract = self._contract_for_request(owner_text, snapshot)
        if contract is not None:
            partial = self._partial_support(owner_text, contract)
            if partial is not None:
                message, boundary_ids, alternatives = partial
                metadata = {
                    "disposition": "unsupported",
                    "support_level": "partial",
                    "application_id": contract["application_id"],
                    "application_version": contract["application_version"],
                    "interaction_contract_digest": contract["digest"],
                    "unsupported_boundary_ids": boundary_ids,
                    "nearest_operation_ids": alternatives,
                    "application_calls": 0,
                    "state_changed": False,
                    "executable_approval": False,
                    "source": "controller_interaction_contract",
                }
                self.chat_store.append_message(
                    authority, conversation_id, "assistant", message,
                    kind="unsupported", state="UNSUPPORTED", metadata=metadata,
                )
                self.chat_store.finish_turn(
                    turn_id, "done", action={**metadata, "message": message},
                    usage=semantic.usage,
                )
                return
            guidance = self._contract_guidance(owner_text, contract)
            if guidance is not None:
                disposition, message, boundary_ids, alternatives = guidance
                metadata = {
                    "disposition": disposition,
                    "application_id": contract["application_id"],
                    "application_version": contract["application_version"],
                    "interaction_contract_digest": contract["digest"],
                    "unsupported_boundary_ids": boundary_ids,
                    "nearest_operation_ids": alternatives,
                    "application_calls": 0,
                    "state_changed": False,
                    "source": "controller_interaction_contract",
                }
                self.chat_store.append_message(
                    authority, conversation_id, "assistant", message,
                    kind=disposition,
                    state="UNSUPPORTED" if disposition == "unsupported" else "DONE",
                    metadata=metadata,
                )
                self.chat_store.finish_turn(
                    turn_id, "done", action={**metadata, "message": message},
                    usage=semantic.usage,
                )
                return
            if (
                contract["application_id"] == "documents.proforma_invoice"
                and any(word in owner_text.casefold() for word in ("prepare", "generate", "create", "make"))
                and not snapshot.value.get("resources")
            ):
                message = (
                    "I need one line-item CSV before the invoice application can run. "
                    "Upload exactly one CSV with columns sku, description, quantity, unit_price in that order. "
                    "No invoice or artifact has been created."
                )
                metadata = {
                    "disposition": "clarify",
                    "missing_input_fields": ["line_items"],
                    "field_labels": ["line-item CSV"],
                    "title": "One file is needed",
                    "next_action": "Upload the CSV in this conversation and continue.",
                    "resource_statement": "The application accepts exactly one CSV.",
                    "effect_statement": "No application operation or external effect has run.",
                    "application_id": contract["application_id"],
                    "application_version": contract["application_version"],
                    "interaction_contract_digest": contract["digest"],
                    "application_calls": 0,
                }
                self.chat_store.append_message(
                    authority, conversation_id, "assistant", message,
                    kind="clarify", state="NEEDS YOU", metadata=metadata,
                )
                self.chat_store.finish_turn(
                    turn_id, "needs_you", action={**metadata, "message": message},
                    usage=semantic.usage,
                )
                return
        action = decision["action"]
        if action == "answer":
            message = self._world_answer(snapshot)
            self.chat_store.append_message(
                authority, conversation_id, "assistant", message, kind="answer",
                metadata={"world_digest": snapshot.digest, "source": "controller_world"},
            )
            self.chat_store.finish_turn(
                turn_id, "done", action=self._recorded_action(decision, message), usage=semantic.usage,
            )
        elif action == "clarify":
            metadata = {
                **self._contract_clarification_metadata(decision, snapshot, owner_text),
                "world_digest": snapshot.digest, "provider": semantic.provider,
                "model": semantic.model, "source": "controller_structured_clarification",
            }
            message = self._clarification_text(metadata)
            self.chat_store.append_message(
                authority, conversation_id, "assistant", message, kind="clarify",
                state="NEEDS YOU", metadata=metadata,
            )
            self.chat_store.finish_turn(
                turn_id, "needs_you", action=self._recorded_action(decision, message), usage=semantic.usage,
            )
        elif action == "capability_gap":
            gap = decision["gap"]
            message = (
                "That request is outside the software currently installed and authorized for this team. "
                "See Applications for real nearby operations. No software construction, repository, Git authority, "
                "Codex process, application call, or external action was started."
            )
            gap_id = self.chat_store.create_gap(
                conversation_id, turn_id, owner_text,
                [item["digest"] for item in resources], snapshot.digest,
                gap["needed_ability"], gap["desired_result"], gap["missing_information"],
            )
            self.chat_store.append_message(
                authority, conversation_id, "assistant", message, kind="gap",
                state="UNSUPPORTED", metadata={
                    "gap_id": gap_id, "disposition": "unsupported",
                    "application_calls": 0, "state_changed": False, **gap,
                },
            )
            self.chat_store.finish_turn(
                turn_id, "software_missing",
                action=self._recorded_action({**decision, "gap": gap}, message),
                gap_id=gap_id, usage=semantic.usage,
            )
        elif action == "invoke":
            self._invoke(authority, conversation_id, turn_id, decision, snapshot, semantic.usage)
        else:
            raise RuntimeFailure("SEMANTIC_DECISION_INVALID")

    def _contract_clarification_metadata(
        self, decision: dict[str, Any], snapshot: WorldSnapshot, owner_text: str
    ) -> dict[str, Any]:
        contract = self._contract_for_capability(decision["capability_id"], snapshot)
        if contract is None:
            return self._clarification_metadata(decision, snapshot)
        operation = next(
            item for item in contract["operations"]
            if item["capability_id"] == decision["capability_id"]
        )
        missing = set(decision["clarification"]["missing_input_fields"])
        fields = [
            item for item in operation["human_fields"]
            if item["required"] and (
                item["field_id"] in missing
                or item["field_id"].split(".", 1)[0] in missing
            )
        ]
        if contract["application_id"] == "vehicles.encar_watcher":
            text = owner_text.casefold()
            years = re.findall(r"\b(?:19|20)\d{2}\b", text)
            fields = [
                item for item in fields
                if not (
                    item["field_id"] == "visibility" and any(value in text for value in ("personal", "team"))
                    or item["field_id"] == "hard_filters.source" and "encar" in text
                    or item["field_id"] == "hard_filters.make" and any(value in text for value in ("volkswagen", "vw", "genesis", "폭스바겐", "제네시스"))
                    or item["field_id"] == "hard_filters.model" and any(value in text for value in ("jetta", "g70", "passat", "제타", "파사트"))
                    or item["field_id"] in {"hard_filters.min_year", "hard_filters.max_year"} and len(years) >= 2
                )
            ]
        if not fields:
            return self._clarification_metadata(decision, snapshot)
        labels = [item["label"].capitalize() for item in fields]
        invoice = contract["application_id"] == "documents.proforma_invoice"
        return {
            "title": "I need a little more information before using this application.",
            "capability_id": decision["capability_id"],
            "version_digest": contract["application_version"],
            "missing_input_fields": [item["field_id"] for item in fields],
            "field_labels": labels,
            "next_action": "Reply with " + ", ".join(labels) + ".",
            "resource_statement": (
                "Your attached CSV will remain available."
                if invoice and snapshot.value.get("resources")
                else "Current visible conversation resources are preserved."
            ),
            "effect_statement": (
                "No invoice has been created yet."
                if invoice else "No application operation or external effect has run."
            ),
            "disposition": "clarify",
            "interaction_contract_digest": contract["digest"],
        }

    @staticmethod
    def _contract_for_capability(
        capability_id: str, snapshot: WorldSnapshot
    ) -> dict[str, Any] | None:
        for contract in snapshot.value.get("applications", []):
            if any(
                operation["capability_id"] == capability_id
                for operation in contract["operations"]
            ):
                return contract
        return None

    @staticmethod
    def _contract_for_request(
        owner_text: str, snapshot: WorldSnapshot
    ) -> dict[str, Any] | None:
        text = owner_text.casefold()
        if any(word in text for word in ("invoice", "proforma", "csv", "excel", "spreadsheet")):
            wanted = "documents.proforma_invoice"
        elif any(word in text for word in (
            "watch", "encar", "jetta", "vehicle", "car", "mileage", "kilomet", "telegram",
        )):
            wanted = "vehicles.encar_watcher"
        else:
            return None
        return next(
            (
                item for item in snapshot.value.get("applications", [])
                if item["application_id"] == wanted
            ),
            None,
        )

    @staticmethod
    def _partial_support(
        owner_text: str, contract: dict[str, Any]
    ) -> tuple[str, list[str], list[str]] | None:
        if contract["application_id"] != "vehicles.encar_watcher":
            return None
        text = owner_text.casefold()
        hard_words = ("below", "under", "maximum", "max ", "hard filter", "no more than")
        constrained = any(word in text for word in ("price", "₩", "won", "mileage", " km", "kilomet"))
        already_explicit = any(phrase in text for phrase in (
            "as preferences", "as attention preferences", "attention preference",
        ))
        if not constrained or already_explicit or not any(word in text for word in hard_words):
            return None
        return (
            "The current Encar watcher can enforce make, model, and model-year range. "
            "It cannot enforce price or mileage as hard filters. It can use low price and low mileage "
            "only as attention preferences. No watch has been created or changed. If that reduced behavior "
            "is acceptable, send a new explicit request asking to create the watch with those preferences.",
            ["watch.hard_price_mileage"],
            ["watch.create", "watch.update"],
        )

    @staticmethod
    def _contract_guidance(
        owner_text: str, contract: dict[str, Any]
    ) -> tuple[str, str, list[str], list[str]] | None:
        text = owner_text.casefold()
        if contract["application_id"] == "documents.proforma_invoice":
            if any(word in text for word in ("excel", ".xlsx", "spreadsheet")):
                return (
                    "unsupported",
                    "The installed invoice application does not accept Excel. It accepts exactly one CSV "
                    "with columns sku, description, quantity, unit_price in that order. It can generate "
                    "verified HTML and JSON artifacts, but it does not send them externally.",
                    ["invoice.excel"], ["invoice.generate"],
                )
            if "column" in text or "csv" in text and any(word in text for word in ("accept", "need", "format", "required")):
                return (
                    "explain",
                    "The application requires exactly one CSV with these columns in this order: "
                    "sku, description, quantity, unit_price.",
                    [], ["invoice.generate"],
                )
            if any(word in text for word in ("email", "send", "deliver")):
                return (
                    "unsupported",
                    "The invoice application generates verified HTML and JSON artifacts inside Capy, "
                    "but it cannot email or otherwise send them externally. The nearby supported action "
                    "is to generate the invoice and use its verified artifact links.",
                    ["invoice.external_send"], ["invoice.generate"],
                )
            if any(phrase in text for phrase in (
                "what can", "what does", "what can't", "what can’t", "what is it for",
                "required field", "what information", "what artifact", "what does it return",
            )):
                operation = contract["operations"][0]
                required = ", ".join(
                    item["label"] for item in operation["human_fields"] if item["required"]
                )
                return (
                    "explain",
                    f'{contract["purpose"]} Required information is: {required}. It creates only verified '
                    "HTML and JSON artifacts inside Capy and performs no external source call, send, or payment.",
                    [], ["invoice.generate"],
                )
        if contract["application_id"] == "vehicles.encar_watcher":
            if "one-time" in text or "one time" in text or "search now" in text:
                return (
                    "unsupported",
                    "The installed software is an ongoing Encar watcher, not a general one-time market "
                    "search. Nearby supported actions are creating an ongoing watch or checking one existing "
                    "active watch now.",
                    ["watch.one_time_search"], ["watch.create", "watch.check_now"],
                )
            if any(word in text for word in ("telegram", "email", "sms", "text me")):
                return (
                    "unsupported",
                    "The watcher cannot deliver alerts through Telegram, email, SMS, or another external "
                    "channel. Results remain inside Capy; nearby supported actions are viewing stored status "
                    "or listing visible watches.",
                    ["watch.external_delivery"], ["watch.status", "watch.list"],
                )
            if any(phrase in text for phrase in (
                "what can", "what does", "what can't", "what can’t", "what is it for",
                "who may", "who can", "what information", "what does it return",
            )):
                titles = ", ".join(item["title"] for item in contract["operations"])
                return (
                    "explain",
                    f'{contract["purpose"]} Available actions are: {titles}. Make, model, and years are '
                    "enforced; price and mileage can only guide attention. Status and list use stored state. "
                    "Check now contacts the configured vehicle source. Read actions require current visibility; "
                    "mutations require current access to manage the selected watch.",
                    [], [item["operation_id"] for item in contract["operations"]],
                )
        return None

    def submit(
        self,
        authority: str | ActorContext,
        conversation_id: str,
        text: str,
        attachments: list[tuple[str, str, bytes]],
    ) -> str:
        scope_id = self._scope(authority)
        resources = []
        for filename, media_type, payload in attachments:
            digest = self.runtime_store.add_resource(scope_id, filename, payload)
            resources.append(
                {
                    "digest": digest,
                    "filename": filename,
                    "media_type": media_type,
                    "size_bytes": len(payload),
                    "relation": "attachment",
                }
            )
        owner_message_id = self.chat_store.append_message(
            authority,
            conversation_id,
            "owner",
            text,
            resources=resources,
        )
        snapshot = self.snapshot(authority, conversation_id)
        turn_id = self.chat_store.begin_turn(
            authority,
            conversation_id,
            owner_message_id,
            snapshot.digest,
            self.semantic.name,
            self.semantic.model,
        )
        request = {
            "schema": "capy.semantic-request/v0",
            "owner_message": text,
            "conversation": self.chat_store.context(authority, conversation_id),
            "world": snapshot.value,
        }
        if self.semantic_dispatch is not None:
            if not isinstance(authority, ActorContext):
                raise RuntimeFailure("SEMANTIC_DISPATCH_ACTOR_REQUIRED")
            job_id = self.semantic_dispatch.enqueue(
                "chat_turn", f"chat:{turn_id}", {
                    "turn_id": turn_id,
                    "conversation_id": conversation_id,
                    "client_id": authority.client_id,
                    "membership_id": authority.membership_id,
                    "world_digest": snapshot.digest,
                    "pre_execution_no_effect": True,
                    "transport": (
                        "two_stage" if getattr(self.semantic, "two_stage_operations", False)
                        else "monolithic"
                    ),
                    "stage": "route",
                    "request": request,
                    "resources": resources,
                },
            )
            self.chat_store.append_message(
                authority, conversation_id, "assistant",
                "Capy is waiting for the language service. No software or external action has run yet.",
                kind="working", state="WORKING",
                metadata={"semantic_dispatch_job_id": job_id, "world_digest": snapshot.digest},
            )
            return turn_id
        decision: dict[str, Any] | None = None
        semantic_usage: dict[str, Any] = {}
        incident_component = "semantic_adapter"
        model_calls = 0
        try:
            model_calls = 1
            semantic = self.semantic.decide(request)
            semantic_usage = semantic.usage
            model_calls = int(semantic_usage.get("semantic_attempt_count", 1))
            incident_component = "semantic_identity"
            if (
                semantic.provider != self.semantic.name
                or semantic.model != self.semantic.model
            ):
                raise RuntimeFailure("SEMANTIC_PROVIDER_IDENTITY_MISMATCH")
            incident_component = "semantic_validation"
            decision = validate_decision_for_world(semantic.decision, snapshot.value)
            incident_component = "controller_dispatch"
            self._apply_semantic_decision(
                authority, conversation_id, turn_id, decision, snapshot, semantic, resources, text
            )
        except Exception as exc:
            code = exc.code if isinstance(exc, RuntimeFailure) else "TURN_INTERNAL_ERROR"
            presentation = present_problem(code)
            self.chat_store.record_problem_incident(
                turn_id,
                conversation_id,
                self._problem_incident_facts(
                    exc=exc,
                    code=code,
                    component=incident_component,
                    turn_id=turn_id,
                    snapshot=snapshot,
                    decision=decision,
                    semantic_usage=semantic_usage,
                    model_calls=model_calls,
                ),
            )
            self.chat_store.append_message(
                authority,
                conversation_id,
                "assistant",
                presentation.title,
                kind="problem",
                state="PROBLEM",
                metadata=self._problem_metadata(
                    code, presentation, turn_id, decision, snapshot
                ),
            )
            try:
                action = (
                    self._recorded_action(
                        decision,
                        "The controller did not complete this proposed invocation.",
                    )
                    if decision is not None else None
                )
                self.chat_store.finish_turn(
                    turn_id,
                    "problem",
                    action=action,
                    error_code=code,
                    usage=semantic_usage,
                )
            except RuntimeFailure:
                pass
        return turn_id

    def _problem_incident_facts(
        self,
        *,
        exc: Exception,
        code: str,
        component: str,
        turn_id: str,
        snapshot: WorldSnapshot,
        decision: dict[str, Any] | None,
        semantic_usage: dict[str, Any],
        model_calls: int,
    ) -> dict[str, Any]:
        package_root = Path(__file__).resolve().parent
        frames = []
        trace_parts = []
        for frame in traceback.extract_tb(exc.__traceback__):
            path = Path(frame.filename).resolve()
            try:
                relative = path.relative_to(package_root)
            except ValueError:
                continue
            safe_frame = {
                "file": relative.as_posix(),
                "line": frame.lineno,
                "function": frame.name[:128],
            }
            frames.append(safe_frame)
            trace_parts.append(f"{safe_frame['file']}:{safe_frame['line']}:{safe_frame['function']}")
        capability = None
        if decision is not None and isinstance(decision.get("capability_id"), str):
            capability = next(
                (
                    item for item in snapshot.value.get("capabilities", [])
                    if item.get("id") == decision["capability_id"]
                ),
                None,
            )
        safe_facts = exc.safe_facts if isinstance(exc, RuntimeFailure) else {}
        request_digest = safe_facts.get("semantic_request_sha256") or semantic_usage.get(
            "semantic_request_sha256"
        )
        response_digest = safe_facts.get("semantic_response_sha256") or semantic_usage.get(
            "response_sha256"
        )
        application_selected = bool(capability and capability.get("application_id"))
        return {
            "schema": "capy.problem-incident/v0",
            "problem_reference": turn_id,
            "component": "application_operation" if application_selected else component,
            "stable_error_code": code,
            "exception_type": type(exc).__name__,
            "safe_message": (
                f"Stable runtime failure {code}."
                if isinstance(exc, RuntimeFailure)
                else f"Unexpected {type(exc).__name__}."
            ),
            "world_digest": snapshot.digest,
            "semantic_provider": self.semantic.name,
            "semantic_model": self.semantic.model,
            "semantic_request_sha256": request_digest,
            "semantic_response_sha256": response_digest,
            "semantic_failure_shape": safe_facts.get("semantic_failure_shape"),
            "provider_http_status": safe_facts.get("provider_http_status"),
            "provider_response_bytes": safe_facts.get("provider_response_bytes"),
            "provider_response_sha256": safe_facts.get("provider_response_sha256"),
            "provider_request_id": safe_facts.get("provider_request_id"),
            "provider_envelope": safe_facts.get("provider_envelope"),
            "semantic_attempt_count": safe_facts.get("semantic_attempt_count", model_calls),
            "semantic_retry_used": safe_facts.get("semantic_retry_used", model_calls > 1),
            "semantic_attempts": safe_facts.get("semantic_attempts"),
            "selected_capability_id": capability.get("id") if capability else None,
            "selected_version_digest": capability.get("version_digest") if capability else None,
            "application_id": capability.get("application_id") if capability else None,
            "operation_id": capability.get("operation_id") if capability else None,
            "runtime_release_identity": self._runtime_release_identity(),
            "model_calls": safe_facts.get("model_calls", safe_facts.get("semantic_attempt_count", model_calls)),
            "source_calls": safe_facts.get("source_calls"),
            "application_calls": safe_facts.get(
                "application_calls", 1 if application_selected else 0
            ),
            "effect_count": safe_facts.get(
                "effect_count",
                None if decision and decision.get("action") == "invoke" else 0,
            ),
            "execution_phase": safe_facts.get("execution_phase", "pre_execution"),
            "traceback_sha256": hashlib.sha256("\n".join(trace_parts).encode()).hexdigest(),
            "internal_frames": frames[-12:],
            "terminal_state": "problem",
        }

    @staticmethod
    def _runtime_release_identity() -> str:
        path = Path(__file__).resolve()
        parts = path.parts
        if "releases" in parts:
            index = parts.index("releases")
            if index + 1 < len(parts):
                return parts[index + 1]
        return "development"

    @staticmethod
    def _clarification_metadata(
        decision: dict[str, Any], snapshot: WorldSnapshot
    ) -> dict[str, Any]:
        capability = next(
            item
            for item in snapshot.value["capabilities"]
            if item["id"] == decision["capability_id"]
        )
        fields = decision["clarification"]["missing_input_fields"]
        properties = capability["input_schema"]["properties"]
        labels = []
        for field in fields:
            declared_title = properties[field].get("title")
            labels.append(
                declared_title
                if isinstance(declared_title, str) and declared_title.strip()
                else field.replace("_", " ").capitalize()
            )
        invoice = decision["capability_id"] == "documents.proforma_invoice"
        return {
            "title": (
                "I need these details before I can create the invoice:"
                if invoice else "I need these details before I can continue:"
            ),
            "capability_id": decision["capability_id"],
            "version_digest": capability["version_digest"],
            "missing_input_fields": fields,
            "field_labels": labels,
            "next_action": "Reply in this conversation with those details.",
            "resource_statement": (
                "Your attached CSV will remain available."
                if invoice and snapshot.value["resources"] else ""
            ),
            "effect_statement": (
                "No invoice has been created yet."
                if invoice else "No result has been created yet."
            ),
        }

    @staticmethod
    def _clarification_text(metadata: dict[str, Any]) -> str:
        lines = [metadata["title"]]
        lines.extend(f"- {label}" for label in metadata["field_labels"])
        lines.extend(["", metadata["next_action"]])
        if metadata["resource_statement"]:
            lines.append(metadata["resource_statement"])
        lines.append(metadata["effect_statement"])
        return "\n".join(lines)

    @staticmethod
    def _problem_metadata(
        error_code: str,
        presentation: ProblemPresentation,
        turn_id: str,
        decision: dict[str, Any] | None,
        snapshot: WorldSnapshot,
    ) -> dict[str, Any]:
        metadata: dict[str, Any] = {
            "error_code": error_code,
            **asdict(presentation),
            "problem_reference": turn_id,
        }
        if decision is None or not isinstance(decision.get("capability_id"), str):
            return metadata
        capability_id = decision["capability_id"]
        capability = next(
            (
                item
                for item in snapshot.value["capabilities"]
                if item["id"] == capability_id
            ),
            None,
        )
        if capability is not None:
            metadata["capability_id"] = capability_id
            metadata["version_digest"] = capability["version_digest"]
        return metadata

    @staticmethod
    def _encar_watcher_status_text(result: dict[str, Any]) -> str:
        matches = result.get("matches")
        query = result.get("query") or {}
        if not isinstance(matches, list) or not matches:
            return f"I couldn't find a watch for {query.get('make', '')} {query.get('model', '')} that is visible to you.".replace("  ", " ")
        lines = []
        for watch in matches:
            filters = watch.get("filters") or {}
            years = f"{filters.get('min_year')}–{filters.get('max_year')}"
            title = f"{filters.get('make')} {filters.get('model')} {years}"
            status = str(watch.get("status", "unknown")).replace("_", " ")
            lines.append(f"Your {title} watch is {status}.")
            lines.append(f"Visibility: {watch.get('visibility', 'unknown')}.")
            lines.append("Baseline: established." if watch.get("baseline_established") else "Baseline: waiting for the first successful check.")
            if watch.get("last_checked_at"):
                lines.append(f"Last checked: {watch['last_checked_at']}.")
            next_check = watch.get("next_check_at")
            if type(next_check) in {int, float}:
                stamp = datetime.fromtimestamp(next_check, timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
                lines.append(f"Next scheduled check: {stamp}.")
            schedule = watch.get("schedule_seconds")
            if type(schedule) is int and schedule > 0:
                lines.append(f"Schedule: every {schedule // 60} minutes.")
            if watch.get("pause_reason"):
                lines.append(f"Pause reason: {watch['pause_reason']}.")
        lines.append("This status read used stored application state and did not recheck the vehicle source.")
        return "\n".join(lines)

    def _invoke(
        self,
        authority: str | ActorContext,
        conversation_id: str,
        turn_id: str,
        decision: dict[str, Any],
        snapshot: WorldSnapshot,
        usage: dict[str, Any],
        idempotency_key: str | None = None,
    ) -> None:
        scope_id = self._scope(authority)
        capabilities = {item["id"]: item for item in snapshot.value["capabilities"]}
        capability = capabilities.get(decision["capability_id"])
        if capability is None:
            raise RuntimeFailure("TURN_CAPABILITY_NOT_IN_WORLD")
        if (
            self.application_operations is not None
            and isinstance(authority, ActorContext)
            and self.application_operations.has(authority, decision["capability_id"])
        ):
            if decision["resources"]:
                raise RuntimeFailure("TURN_RESOURCE_NOT_VISIBLE")
            operation_input = dict(decision["input"])
            if decision["capability_id"] == "vehicles.encar_watcher.watch.create":
                expected_visibility = (
                    "personal" if authority.workspace_kind == "personal" else "team"
                )
                supplied_visibility = operation_input.get("visibility")
                if supplied_visibility is not None and supplied_visibility != expected_visibility:
                    raise RuntimeFailure("APPLICATION_INPUT_INVALID")
                operation_input["visibility"] = expected_visibility
            executed_decision = {**decision, "input": operation_input}
            try:
                outcome = self.application_operations.invoke(
                    OperationContext(
                        actor=authority,
                        conversation_id=conversation_id,
                        owner_text=self.chat_store.context(authority, conversation_id)[-1]["text"],
                        conversation=tuple(self.chat_store.context(authority, conversation_id)),
                        idempotency_key=idempotency_key or turn_id,
                    ),
                    decision["capability_id"],
                    capability["version_digest"],
                    operation_input,
                )
            except RuntimeFailure as exc:
                if exc.code != "APPLICATION_ACCESS_DENIED":
                    raise
                self._finish_authority_required(
                    authority, conversation_id, turn_id, executed_decision, snapshot, usage,
                    exc.safe_facts,
                )
                return
            metadata = {
                "capability_id": decision["capability_id"],
                "version_digest": capability["version_digest"],
                "application_id": outcome["application_id"],
                "operation_id": outcome["operation_id"],
                "operation_receipt": outcome["operation_receipt"],
                "presentation_kind": outcome["presentation_kind"],
                "source_checked": outcome["source_checked"],
                "state_changed": outcome["state_changed"],
                "effect_count": outcome["effect_count"],
                "target_receipt": outcome["target_receipt"],
                "execution_phase": outcome["execution_phase"],
                "result": outcome["result"],
                "application_calls": 1,
                "person": snapshot.value.get("actor"),
                "team": snapshot.value.get("team"),
            }
            contract = self._contract_for_capability(decision["capability_id"], snapshot)
            if contract is not None:
                metadata.update({
                    "application_version": contract["application_version"],
                    "interaction_contract_digest": contract["digest"],
                })
            self.chat_store.record_result_and_finish_turn(
                authority,
                conversation_id,
                turn_id,
                outcome["text"],
                metadata,
                [],
                self._recorded_action(
                    executed_decision,
                    f"The trusted application operation {outcome['operation_id']} completed.",
                ),
                f"application-operation:{outcome['operation_receipt']}",
                usage,
            )
            return
        if decision["capability_id"] in {"vehicles.encar_watcher", "vehicles.encar_watcher.status"}:
            if self.encar_watcher_runtime is None or not isinstance(authority, ActorContext):
                raise RuntimeFailure("ENCAR_WATCHER_RUNTIME_UNAVAILABLE")
            if decision["resources"]:
                raise RuntimeFailure("TURN_RESOURCE_NOT_VISIBLE")
            if decision["capability_id"] == "vehicles.encar_watcher.status":
                result = self.encar_watcher_runtime.status_from_chat(
                    authority, conversation_id, decision["input"], idempotency_key or turn_id,
                )
                message = self._encar_watcher_status_text(result)
                self.chat_store.record_result_and_finish_turn(
                    authority, conversation_id, turn_id, message,
                    {
                        "capability_id": decision["capability_id"],
                        "version_digest": capability["version_digest"],
                        "result": result,
                        "person": snapshot.value.get("actor"), "team": snapshot.value.get("team"),
                        "software": {"id": "vehicles.encar_watcher", "version_digest": capability["version_digest"], "source": capability.get("source")},
                    }, [], self._recorded_action(decision, "The controller read caller-visible stored watch status without checking the source."),
                    f"encar-watcher-status:{turn_id}", usage,
                )
                return
            result = self.encar_watcher_runtime.invoke_from_chat(
                authority, conversation_id, decision["input"], idempotency_key or turn_id,
                owner_request=self.chat_store.context(authority, conversation_id)[-1]["text"],
            )
            self.chat_store.record_result_and_finish_turn(
                authority, conversation_id, turn_id,
                "Your Encar watch is active. The first successful check establishes a silent baseline; future new or materially changed listings are evaluated for attention.",
                {
                    "capability_id": decision["capability_id"],
                    "version_digest": capability["version_digest"],
                    "result": result,
                    "person": snapshot.value.get("actor"), "team": snapshot.value.get("team"),
                    "software": {"id": decision["capability_id"], "version_digest": capability["version_digest"], "source": capability.get("source")},
                }, [], self._recorded_action(decision, "The controller created the private team application watch."),
                f"encar-watcher:{result['watch_id']}", usage,
            )
            return
        if capability["side_effect"] == "external_effect":
            raise RuntimeFailure("EXTERNAL_EFFECT_APPROVAL_BOUNDARY_UNAVAILABLE")
        unavailable_connections = self._unavailable_connections(capability)
        if unavailable_connections:
            self._finish_connection_required(
                authority, conversation_id, turn_id, decision, snapshot, usage,
                unavailable_connections,
            )
            return
        visible = {item["handle"] for item in snapshot.value["resources"]}
        selected = decision["resources"]
        if not set(selected) <= visible:
            raise RuntimeFailure("TURN_RESOURCE_NOT_VISIBLE")
        completed = self.runtime.invoke(
            scope_id,
            decision["capability_id"],
            decision["input"],
            resource_digests=selected,
            expected_version_digest=capability["version_digest"],
            idempotency_key=idempotency_key,
            initiator=authority.initiator() if isinstance(authority, ActorContext) else None,
        )
        artifacts = []
        for item in completed.artifacts:
            artifacts.append(
                {
                    "digest": item["digest"],
                    "filename": item["filename"],
                    "media_type": "application/octet-stream",
                    "size_bytes": item["size_bytes"],
                    "relation": "artifact",
                }
            )
        result_text = "Done — the result was verified by the installed software."
        metadata = {
            "capability_id": decision["capability_id"],
            "version_digest": completed.receipt["version_digest"],
            "result": completed.result,
            "result_digest": completed.receipt["result_digest"],
        }
        contract = self._contract_for_capability(decision["capability_id"], snapshot)
        if contract is not None:
            operation = next(
                item for item in contract["operations"]
                if item["capability_id"] == decision["capability_id"]
            )
            metadata.update({
                "application_id": contract["application_id"],
                "application_version": contract["application_version"],
                "interaction_contract_digest": contract["digest"],
                "operation_id": operation["operation_id"],
                "application_calls": 1,
                "source_checked": False,
            })
        if "actor" in snapshot.value and "team" in snapshot.value:
            metadata.update({
                "person": snapshot.value["actor"],
                "team": snapshot.value["team"],
                "software": {
                    "id": decision["capability_id"],
                    "version_digest": completed.receipt["version_digest"],
                    "source": capability.get("source"),
                    "shared_by": capability.get("shared_by"),
                    "maintained_by": capability.get("maintained_by"),
                },
                "input_resource_digests": list(selected),
                "artifact_digests": list(completed.receipt["artifact_digests"]),
                "invocation_receipt": completed.receipt,
            })
        self.chat_store.record_result_and_finish_turn(
            authority,
            conversation_id,
            turn_id,
            result_text,
            metadata,
            artifacts,
            self._recorded_action(
                decision, "The controller revalidated and completed this invocation."
            ),
            completed.invocation_id,
            usage,
        )

    @staticmethod
    def _unavailable_connections(capability: dict[str, Any]) -> list[dict[str, str]]:
        return [
            item for item in capability["connections"] if item["status"] != "configured"
        ]

    def _finish_authority_required(
        self,
        authority: ActorContext,
        conversation_id: str,
        turn_id: str,
        decision: dict[str, Any],
        snapshot: WorldSnapshot,
        usage: dict[str, Any],
        safe_facts: dict[str, Any],
    ) -> None:
        contract = self._contract_for_capability(decision["capability_id"], snapshot)
        operation = next(
            (
                item for item in (contract or {}).get("operations", [])
                if item["capability_id"] == decision["capability_id"]
            ),
            None,
        )
        required_role = (
            operation["authority"]["required_role"]
            if operation is not None
            else "current authority to manage the selected application object"
        )
        operation_title = operation["title"] if operation is not None else "requested operation"
        alternatives = ["View watch status", "List visible watches"]
        message = (
            f"Your current {authority.membership_kind} role cannot complete {operation_title.lower()} "
            f"for the selected object. Required authority: {required_role}. No watch was changed. "
            "You can still view stored status or list the watches visible to you."
        )
        metadata = {
            "disposition": "authority_required",
            "required_role": required_role,
            "current_role": authority.membership_kind,
            "operation": operation["operation_id"] if operation is not None else None,
            "application_id": contract["application_id"] if contract is not None else None,
            "application_version": contract["application_version"] if contract is not None else None,
            "interaction_contract_digest": contract["digest"] if contract is not None else None,
            "application_calls": safe_facts.get("application_calls", 0),
            "source_calls": safe_facts.get("source_calls", 0),
            "effect_count": 0,
            "execution_phase": "authority_denied",
            "application_changed": False,
            "nearest_valid_actions": alternatives,
            "source": "controller_authority_boundary",
        }
        self.chat_store.append_message(
            authority, conversation_id, "assistant", message,
            kind="authority_required", state="NEEDS YOU", metadata=metadata,
        )
        self.chat_store.finish_turn(
            turn_id, "needs_you", action={**metadata, "message": message}, usage=usage,
        )

    def _finish_connection_required(
        self,
        authority: str | ActorContext,
        conversation_id: str,
        turn_id: str,
        decision: dict[str, Any],
        snapshot: WorldSnapshot,
        usage: dict[str, Any],
        unavailable_connections: list[dict[str, str]],
    ) -> None:
        names = ", ".join(item["name"] for item in unavailable_connections)
        message = f"A configured {names} connection is required before I can run this software."
        self.chat_store.append_message(
            authority,
            conversation_id,
            "assistant",
            message,
            kind="connection_required",
            state="NEEDS YOU",
            metadata={
                "capability_id": decision["capability_id"],
                "connections": unavailable_connections,
                "disposition": "setup_required",
                "application_calls": 0,
                "state_changed": False,
                "world_digest": snapshot.digest,
            },
        )
        self.chat_store.finish_turn(
            turn_id,
            "needs_you",
            action={
                **self._recorded_action(decision, message),
                "disposition": "setup_required",
                "application_calls": 0,
                "state_changed": False,
            },
            usage=usage,
        )

    @staticmethod
    def _recorded_action(decision: dict[str, Any], message: str) -> dict[str, Any]:
        """Persist the strict decision fields without untrusted free-form prose."""

        dispositions = {
            "answer": "explain",
            "invoke": "invoke",
            "clarify": "clarify",
            "capability_gap": "unsupported",
        }
        return {
            **decision,
            "disposition": dispositions.get(decision.get("action")),
            "message": message,
        }

    @staticmethod
    def _world_answer(snapshot: WorldSnapshot) -> str:
        capabilities = snapshot.value["capabilities"]
        resources = snapshot.value["resources"]
        available = (
            "; ".join(f'{item["id"]}: {item["description"]}' for item in capabilities)
            if capabilities
            else "no installed capabilities"
        )
        visible = (
            ", ".join(item["filename"] for item in resources)
            if resources
            else "no conversation files"
        )
        excluded = "; ".join(snapshot.value["not_accessible_by_default"])
        connections = snapshot.value.get("connections", [])
        connection_summary = (
            "; ".join(f'{item["name"]}: {item["status"]}' for item in connections)
            if connections else "no configured provider connections"
        )
        return (
            f"Current machine-derived access: {available}. "
            f"Visible in this conversation: {visible}. "
            f"Provider connections: {connection_summary}. "
            f"Not accessible by default: {excluded}."
        )
