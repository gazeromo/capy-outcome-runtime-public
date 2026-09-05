"""Thin trusted integration for the accepted ``vehicles.encar_watcher`` app.

This module is deliberately application-specific.  It is not a service SDK or
scheduler framework: it derives authority from Capy Access, invokes one private
JSON CLI, evaluates only pending watcher candidates, and delivers its outbox to
membership-scoped Capy conversations.
"""

from __future__ import annotations

import hashlib
import json
import re
import sqlite3
import subprocess
import time
import urllib.error
import urllib.request
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

from .access import AccessStore, ActorContext
from .chat import ChatStore
from .model import RuntimeFailure
from .semantic import ENDPOINT, MODEL, extract_single_json_object, safe_provider_envelope_facts
from .semantic_dispatch import SemanticDispatchStore
from .store import RuntimeStore, canonical_json, utc_now


APP_ID = "vehicles.encar_watcher"
STATUS_CAPABILITY_ID = f"{APP_ID}.status"
ACCEPTED_COMMIT = "43d9bc96e6a52d5e0d62af3eb3ed7102a2d10054"
ACCEPTED_TREE = "41b3259aca4ef5c21b25465a3c702b153b8866fb"
ACCEPTED_ARTIFACT = "5229c1e3f8bbbf0ed434fc7de4d40ba62b2b22d4b957bc0a9a4b62c9488c303e"
EXACT_JETTA_REQUEST = (
    "Create a watch for Volkswagen Jetta, years 2020–2024. "
    "Check Encar and notify me when something is worth my attention."
)
WATCHER_PROPOSAL_TRANSPORT_VERSION = "ordinary-json-v2"


@dataclass(frozen=True)
class CandidateDecision:
    decision: str
    reason: str
    confidence: float
    signals: tuple[str, ...]
    provider: str
    model: str
    request_digest: str
    response_digest: str
    usage: dict[str, Any]


class EncarWatcherLunaEvaluator:
    """Locally validate one Luna proposal, with one bounded format repair."""

    provider = "openrouter"
    model = MODEL

    def __init__(self, credential: Path, timeout_seconds: int = 60, opener=None):
        self.credential = credential
        self.timeout_seconds = timeout_seconds
        self.opener = opener or urllib.request.urlopen

    def evaluate(self, value: dict[str, Any]) -> CandidateDecision:
        try:
            first = self._evaluate_once(value)
        except RuntimeFailure as exc:
            if exc.code != "ENCAR_WATCHER_LUNA_INVALID":
                raise
            first_receipt = self._attempt_receipt(exc.safe_facts, exc.code)
        else:
            usage = dict(first.usage)
            usage.update({
                "semantic_attempt_count": 1,
                "semantic_retry_used": False,
                "semantic_attempts": [self._attempt_receipt(first.usage, None)],
            })
            return CandidateDecision(
                first.decision, first.reason, first.confidence, first.signals,
                first.provider, first.model, first.request_digest,
                first.response_digest, usage,
            )

        try:
            repaired = self._evaluate_once(value, repair=True)
        except RuntimeFailure as exc:
            facts = dict(exc.safe_facts)
            receipts = [first_receipt, self._attempt_receipt(facts, exc.code)]
            facts.update(self._summed_usage(receipts))
            facts.update({
                "semantic_attempt_count": 2,
                "semantic_retry_used": True,
                "semantic_attempts": receipts,
            })
            raise RuntimeFailure(exc.code, exc.detail, safe_facts=facts) from exc

        receipts = [first_receipt, self._attempt_receipt(repaired.usage, None)]
        usage = dict(repaired.usage)
        usage.update(self._summed_usage(receipts))
        usage.update({
            "semantic_attempt_count": 2,
            "semantic_retry_used": True,
            "semantic_attempts": receipts,
        })
        return CandidateDecision(
            repaired.decision, repaired.reason, repaired.confidence,
            repaired.signals, repaired.provider, repaired.model,
            repaired.request_digest, repaired.response_digest, usage,
        )

    @staticmethod
    def _attempt_receipt(facts: dict[str, Any], error_code: str | None) -> dict[str, Any]:
        return {
            "error_code": error_code,
            "provider_http_status": facts.get("provider_http_status"),
            "provider_response_bytes": facts.get("provider_response_bytes"),
            "provider_response_sha256": facts.get("provider_response_sha256"),
            "provider_request_id": facts.get("provider_request_id"),
            "provider_envelope": facts.get("provider_envelope"),
            "usage": facts.get("provider_usage") or {
                key: facts[key]
                for key in ("prompt_tokens", "completion_tokens", "total_tokens", "cost")
                if type(facts.get(key)) in {int, float}
            },
        }

    @staticmethod
    def _summed_usage(receipts: list[dict[str, Any]]) -> dict[str, Any]:
        totals: dict[str, Any] = {}
        for field in ("prompt_tokens", "completion_tokens", "total_tokens", "cost"):
            values = [
                receipt.get("usage", {}).get(field) for receipt in receipts
                if type(receipt.get("usage", {}).get(field)) in {int, float}
            ]
            if values:
                totals[field] = sum(values)
        return totals

    def _evaluate_once(self, value: dict[str, Any], *, repair: bool = False) -> CandidateDecision:
        raw_request = canonical_json(value)
        system = (
            "Judge only whether this one changed Encar listing deserves the watch owner's attention. "
            "Use only supplied normalized facts and attention intent. Never infer accident history, "
            "seller quality, availability, or market value. Return exactly one compact JSON object "
            "with exactly decision, reason, confidence, and signals; decision must be notify or ignore; "
            "confidence must be a number from 0 through 1; signals must be an array of at most 8 short "
            "strings. Return no markdown or prose."
        )
        if repair:
            system += (
                " Your previous response could not pass the local JSON shape check. Correct only the "
                "format and return the exact four-field object now."
            )
        payload = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": raw_request.decode("utf-8")},
            ],
            "max_completion_tokens": 350,
        }
        try:
            metadata = self.credential.lstat()
            secret = self.credential.read_text(encoding="utf-8").strip()
        except OSError as exc:
            raise RuntimeFailure("ENCAR_WATCHER_LUNA_UNAVAILABLE") from exc
        if self.credential.is_symlink() or not self.credential.is_file() or metadata.st_mode & 0o777 not in {0o400, 0o440, 0o600} or not secret:
            raise RuntimeFailure("ENCAR_WATCHER_LUNA_CREDENTIAL_INVALID")
        wire = urllib.request.Request(
            ENDPOINT, data=canonical_json(payload), method="POST",
            headers={"Authorization": f"Bearer {secret}", "Content-Type": "application/json", "User-Agent": "capy-encar-watcher-runtime/0.1"},
        )
        try:
            with self.opener(wire, timeout=self.timeout_seconds) as response:
                raw = response.read(64 * 1024 + 1)
                envelope_facts = safe_provider_envelope_facts(raw, response)
        except urllib.error.HTTPError as exc:
            code = "SEMANTIC_PROVIDER_RATE_LIMIT" if exc.code == 429 else (
                "SEMANTIC_PROVIDER_TEMPORARY" if 500 <= exc.code <= 599 else "SEMANTIC_PROVIDER_HTTP"
            )
            exc.close()
            raise RuntimeFailure(code, safe_facts={"provider_http_status": exc.code}) from exc
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            raise RuntimeFailure("SEMANTIC_PROVIDER_ERROR") from exc
        finally:
            secret = ""
        if len(raw) > 64 * 1024:
            raise RuntimeFailure("ENCAR_WATCHER_LUNA_INVALID", safe_facts=envelope_facts)
        envelope = envelope_facts.get("provider_envelope") or {}
        if envelope.get("error_present") is True:
            provider_code = envelope.get("error_code")
            code = (
                "SEMANTIC_PROVIDER_RATE_LIMIT" if provider_code in {429, "429"}
                else "SEMANTIC_PROVIDER_TEMPORARY"
                if provider_code in {500, 502, 503, 504, "500", "502", "503", "504"}
                else "SEMANTIC_PROVIDER_ERROR_ENVELOPE"
            )
            raise RuntimeFailure(code, safe_facts=envelope_facts)
        try:
            outer = json.loads(raw)
            text = outer["choices"][0]["message"]["content"]
        except (KeyError, IndexError, TypeError, ValueError, json.JSONDecodeError) as exc:
            raise RuntimeFailure("ENCAR_WATCHER_LUNA_INVALID", safe_facts=envelope_facts) from exc
        raw_usage = outer.get("usage") or {}
        usage = {
            key: raw_usage[key]
            for key in ("prompt_tokens", "completion_tokens", "total_tokens", "cost")
            if type(raw_usage.get(key)) in {int, float}
        }
        invalid_facts = dict(envelope_facts)
        if usage:
            invalid_facts["provider_usage"] = usage
        try:
            result = extract_single_json_object(text, "ENCAR_WATCHER_LUNA_INVALID")
        except RuntimeFailure as exc:
            raise RuntimeFailure(
                "ENCAR_WATCHER_LUNA_INVALID", safe_facts=invalid_facts
            ) from exc
        if (
            not isinstance(result, dict) or set(result) != {"decision", "reason", "confidence", "signals"}
            or result.get("decision") not in {"notify", "ignore"}
            or not isinstance(result.get("reason"), str) or not 1 <= len(result["reason"]) <= 500
            or type(result.get("confidence")) not in {int, float} or not 0 <= result["confidence"] <= 1
            or not isinstance(result.get("signals"), list) or len(result["signals"]) > 8
            or not all(isinstance(item, str) and 1 <= len(item) <= 80 for item in result["signals"])
        ):
            raise RuntimeFailure("ENCAR_WATCHER_LUNA_INVALID", safe_facts=invalid_facts)
        if not usage:
            usage = {"status": "unknown"}
        provider_model = outer.get("model") or self.model
        if provider_model != self.model:
            raise RuntimeFailure("ENCAR_WATCHER_LUNA_IDENTITY_MISMATCH")
        return CandidateDecision(
            result["decision"], result["reason"], float(result["confidence"]), tuple(result["signals"]),
            self.provider, provider_model,
            hashlib.sha256(raw_request).hexdigest(), hashlib.sha256(text.encode()).hexdigest(), usage,
        )


class QueuedWatcherEvaluator:
    """Application-specific client of the shared semantic lane."""

    provider = "openrouter"
    model = MODEL

    def __init__(
        self,
        store: SemanticDispatchStore,
        *,
        wait_seconds: float = 330,
        poll_seconds: float = 0.2,
        clock: Callable[[], float] = time.monotonic,
    ):
        self.store = store
        self.wait_seconds = wait_seconds
        self.poll_seconds = poll_seconds
        self.clock = clock

    def evaluate(self, value: dict[str, Any]) -> CandidateDecision:
        watch = value.get("watch") or {}
        candidate = value.get("candidate") or {}
        key = "watcher:{}:{}:{}:transport:{}".format(
            watch.get("watch_id"), candidate.get("candidate_id"), candidate.get("revision"),
            WATCHER_PROPOSAL_TRANSPORT_VERSION,
        )
        job_id = self.store.enqueue("watcher_judgment", key, {"request": value})
        deadline = self.clock() + self.wait_seconds
        while self.clock() < deadline:
            job = self.store.job(job_id)
            if job["state"] == "completed":
                if job["result"] is None:
                    raise RuntimeFailure(job["error_code"] or "SEMANTIC_PROVIDER_ERROR")
                result = job["result"]
                return CandidateDecision(
                    result["decision"], result["reason"], float(result["confidence"]),
                    tuple(result["signals"]), result["provider"], result["model"],
                    result["request_digest"], result["response_digest"], result["usage"],
                )
            if job["state"] == "failed":
                raise RuntimeFailure(job["error_code"] or "SEMANTIC_PROVIDER_ERROR")
            time.sleep(self.poll_seconds)
        raise RuntimeFailure("SEMANTIC_PROVIDER_TEMPORARY")


class EncarWatcherRuntime:
    """Trusted ActorContext adapter, scheduler lane, and notification ledger."""

    def __init__(
        self,
        runtime: RuntimeStore,
        chat: ChatStore,
        access: AccessStore,
        executable: Path,
        state_root: Path,
        evaluator: Any,
        *,
        command_runner: Callable[[dict[str, Any]], dict[str, Any]] | None = None,
    ):
        if not executable.is_absolute() or not state_root.is_absolute():
            raise RuntimeFailure("ENCAR_WATCHER_CONFIGURATION_INVALID")
        self.runtime, self.chat, self.access = runtime, chat, access
        self.executable, self.state_root, self.evaluator = executable, state_root, evaluator
        self.command_runner = command_runner
        self._initialize()

    def _initialize(self) -> None:
        with self.runtime.connect() as db:
            db.executescript("""
                CREATE TABLE IF NOT EXISTS encar_watcher_installations(
                  team_id TEXT PRIMARY KEY, application_id TEXT NOT NULL,
                  release_commit TEXT NOT NULL, release_tree TEXT NOT NULL,
                  artifact_digest TEXT NOT NULL, maintainer_principal_id TEXT NOT NULL,
                  executable TEXT NOT NULL, state_root TEXT NOT NULL, status TEXT NOT NULL,
                  installed_at TEXT NOT NULL, updated_at TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS encar_watcher_targets(
                  team_id TEXT NOT NULL, watch_id TEXT NOT NULL,
                  creator_membership_id TEXT NOT NULL, conversation_id TEXT NOT NULL,
                  visibility TEXT NOT NULL, created_at TEXT NOT NULL,
                  PRIMARY KEY(team_id,watch_id));
                CREATE TABLE IF NOT EXISTS encar_watcher_decisions(
                  team_id TEXT NOT NULL, candidate_id TEXT NOT NULL, watch_id TEXT NOT NULL, decision TEXT NOT NULL,
                  reason TEXT NOT NULL, confidence REAL NOT NULL, signals_json TEXT NOT NULL,
                  provider TEXT NOT NULL, model TEXT NOT NULL, request_digest TEXT NOT NULL,
                  response_digest TEXT NOT NULL, usage_json TEXT NOT NULL, created_at TEXT NOT NULL,
                  PRIMARY KEY(team_id,candidate_id));
            """)
        with self.chat.connect() as db:
            db.executescript("""
                CREATE TABLE IF NOT EXISTS encar_watcher_delivery_ledger(
                  application_id TEXT NOT NULL, source_event_id TEXT NOT NULL,
                  recipient_membership_id TEXT NOT NULL, team_id TEXT NOT NULL,
                  conversation_id TEXT NOT NULL, message_id TEXT NOT NULL UNIQUE,
                  payload_digest TEXT NOT NULL, delivered_at TEXT NOT NULL,
                  PRIMARY KEY(application_id,source_event_id,recipient_membership_id));
            """)

    def install(self, actor: ActorContext) -> dict[str, Any]:
        actor = self._current(actor)
        if actor.membership_kind != "owner":
            raise RuntimeFailure("ENCAR_WATCHER_INSTALL_OWNER_REQUIRED")
        health = self._command(actor, "health", {}, conversation_id="scheduler", idempotency_key="install-health")
        if not health.get("healthy"):
            raise RuntimeFailure("ENCAR_WATCHER_HEALTH_FAILED")
        stamp = utc_now()
        with self.runtime.connect() as db:
            db.execute(
                """INSERT INTO encar_watcher_installations VALUES(?,?,?,?,?,?,?,?,?,?,?)
                   ON CONFLICT(team_id) DO UPDATE SET
                     application_id=excluded.application_id,
                     release_commit=excluded.release_commit,
                     release_tree=excluded.release_tree,
                     artifact_digest=excluded.artifact_digest,
                     maintainer_principal_id=excluded.maintainer_principal_id,
                     executable=excluded.executable,state_root=excluded.state_root,
                     status='active',updated_at=excluded.updated_at""",
                (actor.team_id, APP_ID, ACCEPTED_COMMIT, ACCEPTED_TREE, ACCEPTED_ARTIFACT,
                 actor.principal_id, str(self.executable), str(self.state_root), "active", stamp, stamp),
            )
        return self.installation(actor)

    def installation(self, actor: ActorContext) -> dict[str, Any]:
        actor = self._current(actor)
        with self.runtime.connect() as db:
            row = db.execute("SELECT * FROM encar_watcher_installations WHERE team_id=? AND status='active'", (actor.team_id,)).fetchone()
        if row is None:
            raise RuntimeFailure("ENCAR_WATCHER_NOT_INSTALLED")
        return dict(row)

    def world_capabilities(self, actor: ActorContext) -> list[dict[str, Any]]:
        actor = self._current(actor)
        try:
            installed = self.installation(actor)
        except RuntimeFailure as exc:
            if exc.code == "ENCAR_WATCHER_NOT_INSTALLED":
                return []
            raise
        shared = {
            "version_digest": installed["artifact_digest"],
            "result_schema": {"type": "object"}, "resource_requirements": [],
            "connections": [], "state_required": True, "state_available": True,
            "source": "accepted-private-team-application",
            "shared_by": installed["maintainer_principal_id"],
            "maintained_by": installed["maintainer_principal_id"],
            "available_to_members": True,
        }
        return [{
            "id": APP_ID, "version_digest": installed["artifact_digest"],
            "description": "Create and manage private scheduled Encar vehicle watches for this team.",
            "input_schema": {
                "type": "object", "additionalProperties": False,
                "required": ["operation", "visibility", "hard_filters", "attention_intent"],
                "properties": {
                    "operation": {"type": "string", "enum": ["watch.create"]},
                    "visibility": {"type": "string", "enum": ["personal", "team"]},
                    "hard_filters": {
                        "type": "object", "additionalProperties": False,
                        "required": ["source", "make", "model", "min_year", "max_year"],
                        "properties": {
                            "source": {"type": "string", "enum": ["encar"]},
                            "make": {"type": "string"}, "model": {"type": "string"},
                            "min_year": {"type": "integer"}, "max_year": {"type": "integer"},
                        },
                    },
                    "attention_intent": {"type": "string"},
                },
            },
            "side_effect": "stateful_internal", **shared,
        }, {
            "id": STATUS_CAPABILITY_ID,
            "description": "Read the current status of the caller's visible Encar vehicle watches without checking the source.",
            "input_schema": {
                "type": "object", "additionalProperties": False,
                "required": ["operation", "make", "model"],
                "properties": {
                    "operation": {"type": "string", "enum": ["watch.status"]},
                    "make": {"type": "string", "minLength": 1},
                    "model": {"type": "string", "minLength": 1},
                },
            },
            "side_effect": "read_only", **shared,
        }]

    def invoke_from_chat(
        self, actor: ActorContext, conversation_id: str, value: dict[str, Any], idempotency_key: str,
        *, owner_request: str | None = None,
    ) -> dict[str, Any]:
        actor = self._current(actor)
        self.installation(actor)
        expected = {"operation", "visibility", "hard_filters", "attention_intent"}
        if set(value) != expected or value.get("operation") != "watch.create":
            raise RuntimeFailure("ENCAR_WATCHER_INPUT_INVALID")
        filters = value["hard_filters"]
        result = self._command(actor, "watch.create", {
            "visibility": value["visibility"], "filters": filters,
            "owner_request": owner_request or (EXACT_JETTA_REQUEST if filters == {"source": "encar", "make": "Volkswagen", "model": "Jetta", "min_year": 2020, "max_year": 2024} else value["attention_intent"]),
            "attention_intent": value["attention_intent"], "schedule_seconds": 900,
        }, conversation_id=conversation_id, idempotency_key=idempotency_key)
        with self.runtime.connect() as db:
            db.execute(
                """INSERT INTO encar_watcher_targets VALUES(?,?,?,?,?,?)
                   ON CONFLICT(team_id,watch_id) DO NOTHING""",
                (actor.team_id, result["watch_id"], actor.membership_id, conversation_id, value["visibility"], utc_now()),
            )
        return {**result, "application_id": APP_ID, "schedule_seconds": 900, "notification_channel": "Capy chat"}

    def status_from_chat(
        self, actor: ActorContext, conversation_id: str, value: dict[str, Any], idempotency_key: str,
    ) -> dict[str, Any]:
        """Return only caller-visible stored watch state; never perform source work."""

        actor = self._current(actor)
        self.installation(actor)
        if (
            set(value) != {"operation", "make", "model"}
            or value.get("operation") != "watch.status"
            or not isinstance(value.get("make"), str)
            or not isinstance(value.get("model"), str)
        ):
            raise RuntimeFailure("ENCAR_WATCHER_INPUT_INVALID")
        make = value["make"].strip()
        model = value["model"].strip()
        if not make or not model:
            raise RuntimeFailure("ENCAR_WATCHER_INPUT_INVALID")
        visible = self.stored_watches(actor)
        matches = []
        for watch in visible:
            filters = watch["filters"]
            if str(filters.get("make", "")).casefold() != make.casefold() or str(filters.get("model", "")).casefold() != model.casefold():
                continue
            matches.append({
                "watch_id": watch["id"], "status": watch["status"],
                "visibility": watch["visibility"], "filters": filters,
                "baseline_established": watch.get("baseline_at") is not None,
                "baseline_at": watch.get("baseline_at"),
                "last_checked_at": watch.get("last_checked_at"),
                "next_check_at": watch.get("next_check_at"),
                "schedule_seconds": watch.get("schedule_seconds"),
                "pause_reason": watch.get("pause_reason"),
            })
        return {
            "application_id": APP_ID, "operation": "watch.status",
            "query": {"make": make, "model": model}, "matches": matches,
            "source_checked": False,
        }

    def stored_watches(self, actor: ActorContext) -> list[dict[str, Any]]:
        """Read current caller-visible watch rows without application or source work."""

        actor = self._current(actor)
        self.installation(actor)
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", actor.team_id):
            raise RuntimeFailure("ENCAR_WATCHER_AUTHORITY_DENIED")
        candidate = self.state_root / actor.team_id / APP_ID / "state.sqlite3"
        try:
            root = self.state_root.resolve(strict=True)
            database = candidate.resolve(strict=True)
        except OSError as exc:
            raise RuntimeFailure("ENCAR_WATCHER_STATUS_UNAVAILABLE") from exc
        if not database.is_relative_to(root) or candidate.is_symlink() or not database.is_file():
            raise RuntimeFailure("ENCAR_WATCHER_STATUS_UNAVAILABLE")
        try:
            db = sqlite3.connect(database.as_uri() + "?mode=ro", uri=True, timeout=5)
            db.row_factory = sqlite3.Row
            db.execute("PRAGMA query_only=ON")
            if actor.membership_kind == "owner":
                rows = db.execute(
                    "SELECT * FROM watches WHERE deleted_at IS NULL ORDER BY created_at,id"
                ).fetchall()
            else:
                rows = db.execute(
                    """SELECT * FROM watches WHERE deleted_at IS NULL
                       AND (visibility='team' OR creator_principal_id=?)
                       ORDER BY created_at,id""",
                    (actor.principal_id,),
                ).fetchall()
        except sqlite3.Error as exc:
            raise RuntimeFailure("ENCAR_WATCHER_STATUS_UNAVAILABLE") from exc
        finally:
            if "db" in locals():
                db.close()
        visible = []
        for row in rows:
            watch = dict(row)
            filters = watch.get("filters_json")
            if isinstance(filters, str):
                try:
                    filters = json.loads(filters)
                except json.JSONDecodeError:
                    raise RuntimeFailure("ENCAR_WATCHER_STATUS_UNAVAILABLE")
            if not isinstance(filters, dict):
                raise RuntimeFailure("ENCAR_WATCHER_STATUS_UNAVAILABLE")
            watch["filters"] = filters
            watch.pop("filters_json", None)
            visible.append(watch)
        return visible

    def command(self, actor: ActorContext, operation: str, args: dict[str, Any], *, conversation_id: str, idempotency_key: str) -> dict[str, Any]:
        actor = self._current(actor)
        self.installation(actor)
        return self._command(actor, operation, args, conversation_id=conversation_id, idempotency_key=idempotency_key)

    def run_due(self, *, crash_after_delivery: bool = False) -> dict[str, Any]:
        """One bounded dispatcher invocation covering every active installation."""
        with self.runtime.connect() as db:
            teams = [row["team_id"] for row in db.execute("SELECT team_id FROM encar_watcher_installations WHERE status='active' ORDER BY team_id")]
        receipts = []
        for team_id in teams:
            system_actor = self._system_actor(team_id)
            self._reconcile_memberships(team_id, system_actor)
            check = self._command(system_actor, "check_due", {}, conversation_id="scheduler", idempotency_key=f"due:{uuid.uuid4().hex}")
            evaluated = self._evaluate_pending(system_actor)
            delivered = self._deliver_pending_team(team_id, crash_after_delivery=crash_after_delivery)
            receipts.append({"team_id": team_id, "check": check, "evaluated": evaluated, "delivered": delivered})
        return {"application_id": APP_ID, "shared_dispatcher": True, "teams": receipts}

    def _evaluate_pending(self, actor: ActorContext) -> int:
        pending = self._command(actor, "candidate.list_pending", {}, conversation_id="scheduler", idempotency_key=f"candidates:{uuid.uuid4().hex}")["candidates"]
        count = 0
        for candidate in pending:
            with self.runtime.connect() as db:
                stored = db.execute("SELECT * FROM encar_watcher_decisions WHERE team_id=? AND candidate_id=?", (actor.team_id, candidate["id"])).fetchone()
            if stored is None:
                watch = self._command(actor, "watch.get", {"watch_id": candidate["watch_id"]}, conversation_id="scheduler", idempotency_key=f"watch:{candidate['watch_id']}")["watch"]
                bounded = {
                    "schema": "capy.encar-attention-request/v0", "application_id": APP_ID,
                    "release": {"commit": ACCEPTED_COMMIT, "artifact_digest": ACCEPTED_ARTIFACT},
                    "watch": {"watch_id": watch["id"], "attention_intent": watch["attention_intent"], "hard_filters": watch["filters_json"]},
                    "candidate": {"candidate_id": candidate["id"], "listing_id": candidate["listing_id"], "revision": candidate["revision"], "classification": "new_or_materially_changed", "facts": candidate["facts_json"]},
                }
                decision = self.evaluator.evaluate(bounded)
                with self.runtime.connect() as db:
                    db.execute(
                        """INSERT OR IGNORE INTO encar_watcher_decisions VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                        (actor.team_id, candidate["id"], candidate["watch_id"], decision.decision, decision.reason, decision.confidence,
                         canonical_json(list(decision.signals)).decode(), decision.provider, decision.model,
                         decision.request_digest, decision.response_digest, canonical_json(decision.usage).decode(), utc_now()),
                    )
                selected = decision.decision
            else:
                selected = stored["decision"]
            self._command(actor, "candidate.record_decision", {"candidate_id": candidate["id"], "decision": selected}, conversation_id="scheduler", idempotency_key=f"decision:{candidate['id']}")
            count += 1
        return count

    def _deliver_pending_team(self, team_id: str, *, crash_after_delivery: bool) -> int:
        with self.runtime.connect() as db:
            active = [row["id"] for row in db.execute(
                "SELECT id FROM access_memberships WHERE team_id=? AND status='active' ORDER BY joined_at,id",
                (team_id,),
            )]
        total = 0
        for membership_id in active:
            total += self._deliver_pending(
                self._actor_for_membership(team_id, membership_id),
                crash_after_delivery=crash_after_delivery,
            )
        return total

    def _deliver_pending(self, actor: ActorContext, *, crash_after_delivery: bool) -> int:
        pending = self._command(actor, "notification.list_pending", {}, conversation_id="scheduler", idempotency_key=f"notifications:{uuid.uuid4().hex}")["notifications"]
        delivered = 0
        for event in pending:
            candidate_id = event["payload_json"]["candidate_id"]
            with self.runtime.connect() as db:
                decision = db.execute("SELECT * FROM encar_watcher_decisions WHERE team_id=? AND candidate_id=?", (actor.team_id, candidate_id)).fetchone()
                target = db.execute(
                    """SELECT t.* FROM encar_watcher_targets t
                       JOIN encar_watcher_decisions d ON d.team_id=t.team_id AND d.watch_id=t.watch_id
                       WHERE t.team_id=? AND d.candidate_id=?""", (actor.team_id, candidate_id)
                ).fetchone()
            if decision is None:
                raise RuntimeFailure("ENCAR_WATCHER_DELIVERY_TARGET_MISSING")
            if target is None:
                # Preserve orphaned historical application events for explicit
                # reconciliation, but do not let one undeliverable event block
                # current watches or guess a conversation/visibility target.
                continue
            recipients = self._recipients(actor.team_id, dict(target))
            for recipient, conversation_id in recipients:
                text = self._notification_text(event["payload_json"]["facts"], decision)
                self._insert_delivery(recipient, conversation_id, event["event_id"], text, event["payload_json"], decision)
                delivered += 1
            if crash_after_delivery:
                raise RuntimeFailure("ENCAR_WATCHER_TEST_CRASH_AFTER_DELIVERY")
            self._command(actor, "notification.ack", {"event_id": event["event_id"]}, conversation_id="scheduler", idempotency_key=f"ack:{event['event_id']}")
        return delivered

    def _recipients(self, team_id: str, target: dict[str, Any]) -> list[tuple[ActorContext, str]]:
        with self.runtime.connect() as db:
            memberships = db.execute(
                """SELECT m.id FROM access_memberships m JOIN access_principals p ON p.id=m.principal_id
                   WHERE m.team_id=? AND m.status='active' AND p.status='active' ORDER BY m.joined_at,m.id""", (team_id,)
            ).fetchall()
        wanted = {target["creator_membership_id"]} if target["visibility"] == "personal" else {row["id"] for row in memberships}
        result = []
        for membership_id in sorted(wanted):
            member = self._actor_for_membership(team_id, membership_id)
            conversation = target["conversation_id"] if membership_id == target["creator_membership_id"] else self._notification_conversation(member)
            result.append((member, conversation))
        return result

    def _insert_delivery(self, actor: ActorContext, conversation_id: str, event_id: str, text: str, payload: dict[str, Any], decision: Any) -> str:
        payload_digest = hashlib.sha256(canonical_json(payload)).hexdigest()
        message_id, stamp = uuid.uuid4().hex, utc_now()
        metadata = {
            "application_id": APP_ID, "source_event_id": event_id,
            "decision": decision["decision"], "reason": decision["reason"],
            "confidence": decision["confidence"], "provider": decision["provider"], "model": decision["model"],
        }
        with self.chat.connect() as db:
            self.chat._conversation(db, actor, conversation_id)
            old = db.execute(
                "SELECT message_id FROM encar_watcher_delivery_ledger WHERE application_id=? AND source_event_id=? AND recipient_membership_id=?",
                (APP_ID, event_id, actor.membership_id),
            ).fetchone()
            if old is not None:
                return old["message_id"]
            db.execute("INSERT INTO messages VALUES(?,?, 'assistant',?, 'watcher_notification','DONE',?,?)", (message_id, conversation_id, text, canonical_json(metadata).decode(), stamp))
            db.execute(
                "INSERT INTO encar_watcher_delivery_ledger VALUES(?,?,?,?,?,?,?,?)",
                (APP_ID, event_id, actor.membership_id, actor.team_id, conversation_id, message_id, payload_digest, stamp),
            )
            db.execute("UPDATE conversations SET updated_at=? WHERE id=?", (stamp, conversation_id))
        return message_id

    @staticmethod
    def _notification_text(facts: dict[str, Any], decision: Any) -> str:
        title = facts.get("title") or "A watched Encar listing"
        details = [str(item) for item in (facts.get("vehicle_date"), title) if item]
        lines = ["A watched vehicle may be worth a look", " ".join(details)]
        if facts.get("price") is not None: lines.append(f"Price: {facts['price']}")
        if facts.get("mileage") is not None: lines.append(f"Mileage: {facts['mileage']}")
        lines.extend([str(decision["reason"]), str(facts.get("catalog_url") or "")])
        return "\n".join(line for line in lines if line)

    def _command(self, actor: ActorContext, operation: str, args: dict[str, Any], *, conversation_id: str, idempotency_key: str) -> dict[str, Any]:
        request = {"operation": operation, "args": args, "authority": {
            "team_id": actor.team_id, "principal_id": actor.principal_id,
            "membership_id": actor.membership_id, "execution_scope_id": actor.execution_scope_id,
            "conversation_id": conversation_id, "idempotency_key": idempotency_key,
            "role": "owner" if actor.membership_kind == "owner" else "member", "member_status": "active",
        }}
        executed_unknown = {
            "application_calls": 1,
            "source_calls": None if operation == "watch.check_now" else 0,
            "effect_count": 0 if operation in {"watch.status", "watch.list", "watch.listings"} else None,
            "execution_phase": "executed_result_invalid",
        }
        if self.command_runner is not None:
            try:
                response = self.command_runner(request)
            except RuntimeFailure as exc:
                if exc.code in {
                    "ENCAR_WATCHER_COMMAND_TIMEOUT", "ENCAR_WATCHER_COMMAND_INVALID"
                }:
                    raise RuntimeFailure(
                        exc.code, exc.detail, safe_facts={**exc.safe_facts, **executed_unknown}
                    ) from exc
                raise
        else:
            release_root = self.executable.parent.parent
            try:
                completed = subprocess.run(
                    [str(self.executable)], input=canonical_json(request), stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE, timeout=180, check=False,
                    cwd=release_root,
                    env={"CAPY_TEAM_STATE_ROOT": str(self.state_root), "PYTHONPATH": str(release_root), "PATH": "/usr/bin:/bin"},
                )
            except subprocess.TimeoutExpired as exc:
                raise RuntimeFailure(
                    "ENCAR_WATCHER_COMMAND_TIMEOUT", safe_facts=executed_unknown
                ) from exc
            try: response = json.loads(completed.stdout)
            except json.JSONDecodeError as exc:
                raise RuntimeFailure(
                    "ENCAR_WATCHER_COMMAND_INVALID", safe_facts=executed_unknown
                ) from exc
        if not isinstance(response, dict) or response.get("ok") is not True or not isinstance(response.get("result"), dict):
            code = response.get("error", {}).get("code") if isinstance(response, dict) else None
            stable = f"ENCAR_WATCHER_{str(code or 'COMMAND_FAILED').upper()}"
            facts = (
                executed_unknown
                if stable in {"ENCAR_WATCHER_COMMAND_FAILED", "ENCAR_WATCHER_INTERNAL_ERROR"}
                else None
            )
            raise RuntimeFailure(stable, safe_facts=facts)
        return response["result"]

    def _current(self, actor: ActorContext) -> ActorContext:
        current = self.access.resolve_actor(actor.client_id, actor.membership_id)
        if current.team_id != actor.team_id or current.principal_id != actor.principal_id:
            raise RuntimeFailure("ENCAR_WATCHER_AUTHORITY_DENIED")
        return current

    def install_team(self, team_id: str) -> dict[str, Any]:
        """Trusted deployment entrypoint; resolves, rather than accepts, owner authority."""
        with self.runtime.connect() as db:
            row = db.execute(
                """SELECT m.id membership_id,c.id client_id FROM access_memberships m
                   JOIN access_clients c ON c.principal_id=m.principal_id AND c.status='active'
                   WHERE m.team_id=? AND m.kind='owner' AND m.status='active'
                   ORDER BY m.joined_at,c.created_at LIMIT 1""",
                (team_id,),
            ).fetchone()
        if row is None:
            raise RuntimeFailure("ENCAR_WATCHER_INSTALL_OWNER_REQUIRED")
        return self.install(self.access.resolve_actor(row["client_id"], row["membership_id"]))

    def _system_actor(self, team_id: str) -> ActorContext:
        with self.runtime.connect() as db:
            row = db.execute(
                """SELECT m.id FROM access_memberships m JOIN encar_watcher_installations i ON i.team_id=m.team_id
                   WHERE m.team_id=? AND m.principal_id=i.maintainer_principal_id AND m.status='active' LIMIT 1""", (team_id,)
            ).fetchone()
        if row is None: raise RuntimeFailure("ENCAR_WATCHER_MAINTAINER_UNAVAILABLE")
        return self._actor_for_membership(team_id, row["id"])

    def _actor_for_membership(self, team_id: str, membership_id: str) -> ActorContext:
        with self.runtime.connect() as db:
            row = db.execute(
                """SELECT a.id authority_id,p.id principal_id,p.display_name principal_display_name,
                          m.id membership_id,m.kind membership_kind,t.id team_id,
                          CASE WHEN w.principal_id IS NULL THEN t.name ELSE 'Personal' END team_name,
                          m.execution_scope_id,
                          CASE WHEN w.principal_id IS NULL THEN 'team' ELSE 'personal' END workspace_kind
                   FROM access_memberships m JOIN access_principals p ON p.id=m.principal_id
                   JOIN access_teams t ON t.id=m.team_id JOIN access_authorities a ON a.singleton=1
                   LEFT JOIN access_personal_workspaces w ON w.membership_id=m.id
                   WHERE m.id=? AND m.team_id=? AND m.status='active'""", (membership_id, team_id)
            ).fetchone()
        if row is None: raise RuntimeFailure("ENCAR_WATCHER_MEMBERSHIP_UNAVAILABLE")
        return ActorContext(client_id="capy-watcher-scheduler", **dict(row))

    def _notification_conversation(self, actor: ActorContext) -> str:
        items = self.chat.list_conversations(actor)
        return items[0]["id"] if items else self.chat.create_conversation(actor, "Encar watch notifications")

    def _reconcile_memberships(self, team_id: str, actor: ActorContext) -> None:
        with self.runtime.connect() as db:
            rows = db.execute("SELECT id,principal_id,kind,execution_scope_id,status FROM access_memberships WHERE team_id=?", (team_id,)).fetchall()
        for row in rows:
            request = {"operation": "health", "args": {}, "authority": {
                "team_id": team_id, "principal_id": row["principal_id"], "membership_id": row["id"],
                "execution_scope_id": row["execution_scope_id"], "conversation_id": "scheduler",
                "idempotency_key": f"reconcile:{row['id']}:{row['status']}",
                "role": "owner" if row["kind"] == "owner" else "member", "member_status": row["status"],
            }}
            response = self.command_runner(request) if self.command_runner is not None else None
            if response is None:
                release_root = self.executable.parent.parent
                completed = subprocess.run([str(self.executable)], input=canonical_json(request), stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=60, check=False, cwd=release_root, env={"CAPY_TEAM_STATE_ROOT": str(self.state_root), "PYTHONPATH": str(release_root), "PATH": "/usr/bin:/bin"})
                try: response = json.loads(completed.stdout)
                except json.JSONDecodeError as exc: raise RuntimeFailure("ENCAR_WATCHER_COMMAND_INVALID") from exc
            if response.get("ok") is not True: raise RuntimeFailure("ENCAR_WATCHER_RECONCILIATION_FAILED")
