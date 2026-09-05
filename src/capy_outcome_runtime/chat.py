"""Durable product/control state for conversations, turns, resources, and gaps."""

from __future__ import annotations

import hashlib
import json
import re
import secrets
import sqlite3
import uuid
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterator

from .access import ActorContext
from .model import RuntimeFailure
from .store import canonical_json, utc_now


class ChatStore:
    def __init__(self, database: Path):
        database.parent.mkdir(parents=True, exist_ok=True)
        self.database = database
        self._initialize()
        self.database.chmod(0o600)
        self.recover_interrupted_turns()
        self.recover_interrupted_build_retries()
        self.recover_interrupted_build_proposal_approvals()
        self.recover_expired_build_leases()

    @contextmanager
    def connect(self) -> Iterator[sqlite3.Connection]:
        db = sqlite3.connect(self.database)
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA foreign_keys = ON")
        try:
            yield db
        except BaseException:
            db.rollback()
            raise
        else:
            db.commit()
        finally:
            db.close()

    def _initialize(self) -> None:
        with self.connect() as db:
            db.executescript(
                """
                PRAGMA journal_mode = WAL;
                CREATE TABLE IF NOT EXISTS conversations (
                    id TEXT PRIMARY KEY, scope_id TEXT NOT NULL, title TEXT,
                    status TEXT NOT NULL, created_at TEXT NOT NULL, updated_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS messages (
                    id TEXT PRIMARY KEY, conversation_id TEXT NOT NULL REFERENCES conversations(id),
                    role TEXT NOT NULL, text TEXT NOT NULL, kind TEXT NOT NULL,
                    state TEXT NOT NULL, metadata_json TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS message_resources (
                    message_id TEXT NOT NULL REFERENCES messages(id), scope_id TEXT NOT NULL,
                    digest TEXT NOT NULL, filename TEXT NOT NULL, media_type TEXT NOT NULL,
                    size_bytes INTEGER NOT NULL, relation TEXT NOT NULL,
                    PRIMARY KEY(message_id, digest, relation)
                );
                CREATE TABLE IF NOT EXISTS turns (
                    id TEXT PRIMARY KEY, conversation_id TEXT NOT NULL REFERENCES conversations(id),
                    owner_message_id TEXT NOT NULL REFERENCES messages(id), world_digest TEXT NOT NULL,
                    adapter TEXT NOT NULL, model TEXT NOT NULL, status TEXT NOT NULL,
                    action_json TEXT, invocation_id TEXT, gap_id TEXT, error_code TEXT,
                    usage_json TEXT NOT NULL, created_at TEXT NOT NULL, completed_at TEXT
                );
                CREATE TABLE IF NOT EXISTS capability_gaps (
                    id TEXT PRIMARY KEY, conversation_id TEXT NOT NULL REFERENCES conversations(id),
                    turn_id TEXT NOT NULL REFERENCES turns(id), original_message TEXT NOT NULL,
                    resources_json TEXT NOT NULL, world_digest TEXT NOT NULL,
                    needed_ability TEXT NOT NULL, desired_result TEXT NOT NULL,
                    missing_information_json TEXT NOT NULL, status TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS sessions (
                    id TEXT PRIMARY KEY, scope_id TEXT NOT NULL, csrf_token TEXT NOT NULL,
                    expires_at TEXT NOT NULL, created_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS build_requests (
                    id TEXT PRIMARY KEY,
                    gap_id TEXT NOT NULL UNIQUE REFERENCES capability_gaps(id),
                    conversation_id TEXT NOT NULL REFERENCES conversations(id),
                    scope_id TEXT NOT NULL,
                    original_owner_message_id TEXT NOT NULL REFERENCES messages(id),
                    original_turn_id TEXT NOT NULL REFERENCES turns(id),
                    original_world_digest TEXT NOT NULL,
                    resources_json TEXT NOT NULL,
                    needed_ability TEXT NOT NULL,
                    desired_result TEXT NOT NULL,
                    missing_information_json TEXT NOT NULL,
                    side_effect_ceiling TEXT NOT NULL,
                    packet_digest TEXT NOT NULL,
                    status TEXT NOT NULL,
                    builder_id TEXT,
                    lease_id TEXT,
                    lease_expires_at TEXT,
                    builder_session_id TEXT,
                    candidate_repository TEXT,
                    candidate_commit TEXT,
                    candidate_tree TEXT,
                    candidate_archive_digest TEXT,
                    candidate_capability_id TEXT,
                    candidate_version_digest TEXT,
                    acceptance_digest TEXT,
                    previous_binding_json TEXT,
                    published_binding_json TEXT,
                    retry_turn_id TEXT,
                    terminal_error TEXT,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS build_proposals (
                    id TEXT PRIMARY KEY,
                    gap_id TEXT NOT NULL UNIQUE REFERENCES capability_gaps(id),
                    conversation_id TEXT NOT NULL REFERENCES conversations(id),
                    scope_id TEXT NOT NULL,
                    resources_json TEXT NOT NULL,
                    world_digest TEXT NOT NULL,
                    needed_ability TEXT NOT NULL,
                    desired_result TEXT NOT NULL,
                    specification_json TEXT NOT NULL,
                    summary_json TEXT NOT NULL,
                    proposal_digest TEXT NOT NULL UNIQUE,
                    status TEXT NOT NULL,
                    blocked_reason TEXT,
                    approved_build_id TEXT,
                    terminal_error TEXT,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS build_events (
                    id TEXT PRIMARY KEY,
                    build_id TEXT NOT NULL REFERENCES build_requests(id),
                    status TEXT NOT NULL,
                    detail_json TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS generic_build_outcomes (
                    build_id TEXT PRIMARY KEY REFERENCES build_requests(id),
                    conversation_id TEXT NOT NULL REFERENCES conversations(id),
                    scope_id TEXT NOT NULL,
                    classification TEXT NOT NULL,
                    detail TEXT,
                    provenance_json TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS publication_receipts (
                    build_id TEXT PRIMARY KEY REFERENCES build_requests(id),
                    receipt_json TEXT NOT NULL,
                    receipt_digest TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS binding_history (
                    id TEXT PRIMARY KEY,
                    build_id TEXT NOT NULL REFERENCES build_requests(id),
                    scope_id TEXT NOT NULL,
                    capability_id TEXT NOT NULL,
                    operation TEXT NOT NULL,
                    previous_binding_json TEXT,
                    new_binding_json TEXT,
                    receipt_json TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS problem_incidents (
                    problem_reference TEXT PRIMARY KEY REFERENCES turns(id),
                    turn_id TEXT NOT NULL UNIQUE REFERENCES turns(id),
                    conversation_id TEXT NOT NULL REFERENCES conversations(id),
                    facts_json TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS message_submissions (
                    submission_id TEXT PRIMARY KEY,
                    conversation_id TEXT NOT NULL REFERENCES conversations(id),
                    scope_id TEXT NOT NULL,
                    principal_id TEXT NOT NULL,
                    membership_id TEXT NOT NULL,
                    status TEXT NOT NULL CHECK(status IN ('claimed','completed')),
                    turn_id TEXT REFERENCES turns(id),
                    created_at TEXT NOT NULL,
                    completed_at TEXT
                );
                CREATE TABLE IF NOT EXISTS problem_render_incidents (
                    id TEXT PRIMARY KEY,
                    problem_reference TEXT NOT NULL REFERENCES problem_incidents(problem_reference),
                    facts_json TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS message_conversation_order
                    ON messages(conversation_id, created_at, id);
                CREATE INDEX IF NOT EXISTS turn_conversation_order
                    ON turns(conversation_id, created_at, id);
                CREATE INDEX IF NOT EXISTS build_conversation_order
                    ON build_requests(conversation_id, created_at, id);
                CREATE INDEX IF NOT EXISTS proposal_conversation_order
                    ON build_proposals(conversation_id, created_at, id);
                CREATE INDEX IF NOT EXISTS problem_incident_conversation_order
                    ON problem_incidents(conversation_id, created_at, problem_reference);
                """
            )
            columns = {row["name"] for row in db.execute("PRAGMA table_info(conversations)")}
            for name in ("principal_id", "membership_id", "team_id"):
                if name not in columns:
                    db.execute(f"ALTER TABLE conversations ADD COLUMN {name} TEXT")
            if "workspace_kind" not in columns:
                db.execute(
                    "ALTER TABLE conversations ADD COLUMN workspace_kind TEXT NOT NULL DEFAULT 'team'"
                )
            columns = {row["name"] for row in db.execute("PRAGMA table_info(conversations)")}
            if "creator_principal_id" in columns:
                db.execute(
                    """UPDATE conversations SET principal_id=creator_principal_id
                       WHERE principal_id IS NULL AND creator_principal_id IS NOT NULL"""
                )
            if "execution_scope_id" in columns:
                conflict = db.execute(
                    """SELECT 1 FROM conversations
                       WHERE execution_scope_id IS NOT NULL AND scope_id != execution_scope_id
                       LIMIT 1"""
                ).fetchone()
                if conflict is not None:
                    raise RuntimeFailure("CONVERSATION_SCOPE_MIGRATION_CONFLICT")

    def create_session(self, scope_id: str, lifetime_seconds: int = 86400) -> dict[str, str]:
        now = datetime.now(timezone.utc)
        value = {
            "id": secrets.token_urlsafe(32),
            "scope_id": scope_id,
            "csrf_token": secrets.token_urlsafe(24),
            "expires_at": (now + timedelta(seconds=lifetime_seconds)).isoformat().replace("+00:00", "Z"),
            "created_at": now.isoformat().replace("+00:00", "Z"),
        }
        with self.connect() as db:
            db.execute("INSERT INTO sessions VALUES (?, ?, ?, ?, ?)", tuple(value.values()))
        return value

    def session(self, session_id: str) -> dict[str, str] | None:
        with self.connect() as db:
            row = db.execute("SELECT * FROM sessions WHERE id = ?", (session_id,)).fetchone()
        if row is None:
            return None
        if datetime.fromisoformat(row["expires_at"].replace("Z", "+00:00")) <= datetime.now(timezone.utc):
            return None
        return dict(row)

    @staticmethod
    def _scope(authority: str | ActorContext) -> str:
        return authority.execution_scope_id if isinstance(authority, ActorContext) else authority

    @staticmethod
    def _actor_values(authority: str | ActorContext) -> tuple[str | None, str | None, str | None]:
        if isinstance(authority, ActorContext):
            return authority.principal_id, authority.membership_id, authority.team_id
        return None, None, None

    def create_conversation(self, authority: str | ActorContext, title: str | None = None) -> str:
        conversation_id = uuid.uuid4().hex
        now = utc_now()
        scope_id = self._scope(authority)
        principal_id, membership_id, team_id = self._actor_values(authority)
        with self.connect() as db:
            db.execute(
                """INSERT INTO conversations
                   (id, scope_id, title, status, created_at, updated_at,
                    principal_id, membership_id, team_id, workspace_kind)
                   VALUES (?, ?, ?, 'active', ?, ?, ?, ?, ?, ?)""",
                (
                    conversation_id, scope_id, title, now, now, principal_id,
                    membership_id, team_id,
                    authority.workspace_kind if isinstance(authority, ActorContext) else "team",
                ),
            )
        return conversation_id

    def _conversation(
        self, db: sqlite3.Connection, authority: str | ActorContext, conversation_id: str
    ) -> sqlite3.Row:
        if isinstance(authority, ActorContext):
            row = db.execute(
                """SELECT * FROM conversations WHERE id=? AND scope_id=?
                   AND principal_id=? AND membership_id=? AND team_id=?""",
                (
                    conversation_id, authority.execution_scope_id, authority.principal_id,
                    authority.membership_id, authority.team_id,
                ),
            ).fetchone()
        else:
            row = db.execute(
                "SELECT * FROM conversations WHERE id = ? AND scope_id = ?",
                (conversation_id, authority),
            ).fetchone()
        if row is None:
            raise RuntimeFailure("CONVERSATION_NOT_IN_SCOPE")
        return row

    def conversation_authority(self, conversation_id: str) -> dict[str, str]:
        with self.connect() as db:
            row = db.execute(
                """SELECT scope_id, principal_id, membership_id, team_id, workspace_kind FROM conversations
                   WHERE id=? AND principal_id IS NOT NULL AND membership_id IS NOT NULL AND team_id IS NOT NULL""",
                (conversation_id,),
            ).fetchone()
        if row is None:
            raise RuntimeFailure("CONVERSATION_NOT_IN_SCOPE")
        return dict(row)

    def adopt_legacy_owner(self, actor: ActorContext) -> int:
        """Bind pre-access owner conversations in place; safe to repeat after restart."""
        with self.connect() as db:
            changed = db.execute(
                """UPDATE conversations SET principal_id=?, membership_id=?, team_id=?
                   WHERE scope_id=? AND principal_id IS NULL AND membership_id IS NULL AND team_id IS NULL""",
                (actor.principal_id, actor.membership_id, actor.team_id, actor.execution_scope_id),
            ).rowcount
        return changed

    def list_conversations(self, authority: str | ActorContext) -> list[dict[str, Any]]:
        with self.connect() as db:
            if isinstance(authority, ActorContext):
                rows = db.execute(
                    """SELECT * FROM conversations WHERE scope_id=? AND principal_id=?
                       AND membership_id=? AND team_id=? ORDER BY updated_at DESC, id""",
                    (
                        authority.execution_scope_id, authority.principal_id,
                        authority.membership_id, authority.team_id,
                    ),
                ).fetchall()
            else:
                rows = db.execute(
                    "SELECT * FROM conversations WHERE scope_id = ? ORDER BY updated_at DESC, id",
                    (authority,),
                ).fetchall()
        return [dict(row) for row in rows]

    def append_message(
        self,
        authority: str | ActorContext,
        conversation_id: str,
        role: str,
        text: str,
        *,
        kind: str = "text",
        state: str = "DONE",
        metadata: dict[str, Any] | None = None,
        resources: list[dict[str, Any]] | None = None,
    ) -> str:
        if role not in {"owner", "assistant", "system"} or state not in {
            "WORKING", "NEEDS YOU", "DONE", "PROBLEM", "SOFTWARE MISSING", "UNSUPPORTED"
        }:
            raise RuntimeFailure("CHAT_MESSAGE_INVALID")
        if not isinstance(text, str) or len(text) > 50_000:
            raise RuntimeFailure("CHAT_MESSAGE_INVALID")
        message_id = uuid.uuid4().hex
        now = utc_now()
        scope_id = self._scope(authority)
        with self.connect() as db:
            self._conversation(db, authority, conversation_id)
            db.execute(
                "INSERT INTO messages VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    message_id,
                    conversation_id,
                    role,
                    text,
                    kind,
                    state,
                    canonical_json(metadata or {}).decode(),
                    now,
                ),
            )
            for resource in resources or []:
                db.execute(
                    "INSERT INTO message_resources VALUES (?, ?, ?, ?, ?, ?, ?)",
                    (
                        message_id,
                        scope_id,
                        resource["digest"],
                        resource["filename"],
                        resource["media_type"],
                        resource["size_bytes"],
                        resource.get("relation", "attachment"),
                    ),
                )
            db.execute(
                "UPDATE conversations SET updated_at = ?, title = COALESCE(title, ?) WHERE id = ?",
                (now, text.strip()[:80] or None, conversation_id),
            )
        return message_id

    def visible_resources(self, authority: str | ActorContext, conversation_id: str) -> list[dict[str, Any]]:
        scope_id = self._scope(authority)
        with self.connect() as db:
            self._conversation(db, authority, conversation_id)
            rows = db.execute(
                """SELECT mr.*, m.created_at, m.id AS source_message
                   FROM message_resources mr JOIN messages m ON m.id = mr.message_id
                   WHERE m.conversation_id = ? AND mr.scope_id = ?
                   ORDER BY m.created_at, mr.digest""",
                (conversation_id, scope_id),
            ).fetchall()
        seen = set()
        result = []
        for row in rows:
            if row["digest"] in seen:
                continue
            seen.add(row["digest"])
            result.append(dict(row))
        return result

    def timeline(self, authority: str | ActorContext, conversation_id: str) -> dict[str, Any]:
        with self.connect() as db:
            conversation = dict(self._conversation(db, authority, conversation_id))
            rows = db.execute(
                "SELECT * FROM messages WHERE conversation_id = ? ORDER BY created_at, rowid",
                (conversation_id,),
            ).fetchall()
            messages = []
            for row in rows:
                value = dict(row)
                value["metadata"] = json.loads(value.pop("metadata_json"))
                resources = db.execute(
                    "SELECT digest, filename, media_type, size_bytes, relation FROM message_resources WHERE message_id = ? ORDER BY relation, filename",
                    (row["id"],),
                ).fetchall()
                value["resources"] = [dict(item) for item in resources]
                messages.append(value)
        return {"conversation": conversation, "messages": messages}

    def context(self, authority: str | ActorContext, conversation_id: str, limit: int = 20) -> list[dict[str, str]]:
        timeline = self.timeline(authority, conversation_id)["messages"][-limit:]
        return [{"role": item["role"], "text": item["text"]} for item in timeline]

    def begin_turn(
        self,
        authority: str | ActorContext,
        conversation_id: str,
        owner_message_id: str,
        world_digest: str,
        adapter: str,
        model: str,
    ) -> str:
        turn_id = uuid.uuid4().hex
        with self.connect() as db:
            self._conversation(db, authority, conversation_id)
            owner = db.execute(
                "SELECT 1 FROM messages WHERE id = ? AND conversation_id = ? AND role = 'owner'",
                (owner_message_id, conversation_id),
            ).fetchone()
            if owner is None:
                raise RuntimeFailure("TURN_OWNER_MESSAGE_INVALID")
            db.execute(
                "INSERT INTO turns VALUES (?, ?, ?, ?, ?, ?, 'working', NULL, NULL, NULL, NULL, '{}', ?, NULL)",
                (turn_id, conversation_id, owner_message_id, world_digest, adapter, model, utc_now()),
            )
        return turn_id

    def begin_build_retry(
        self,
        build_id: str,
        authority: str | ActorContext,
        conversation_id: str,
        owner_message_id: str,
        world_digest: str,
        adapter: str,
        model: str,
    ) -> str:
        """Durably link the retry turn before exposing RETRYING state."""

        turn_id = uuid.uuid4().hex
        now = utc_now()
        scope_id = self._scope(authority)
        with self.connect() as db:
            self._conversation(db, authority, conversation_id)
            owner = db.execute(
                "SELECT 1 FROM messages WHERE id=? AND conversation_id=? AND role='owner'",
                (owner_message_id, conversation_id),
            ).fetchone()
            if owner is None:
                raise RuntimeFailure("TURN_OWNER_MESSAGE_INVALID")
            changed = db.execute(
                """UPDATE build_requests SET status='RETRYING', retry_turn_id=?,
                          terminal_error=NULL, updated_at=?
                   WHERE id=? AND scope_id=? AND conversation_id=? AND status='PUBLISHED'""",
                (turn_id, now, build_id, scope_id, conversation_id),
            ).rowcount
            if changed != 1:
                raise RuntimeFailure("BUILD_STATE_CONFLICT")
            db.execute(
                "INSERT INTO turns VALUES (?, ?, ?, ?, ?, ?, 'working', NULL, NULL, NULL, NULL, '{}', ?, NULL)",
                (turn_id, conversation_id, owner_message_id, world_digest, adapter, model, now),
            )
            db.execute(
                "INSERT INTO build_events VALUES (?, ?, 'RETRYING', '{}', ?)",
                (uuid.uuid4().hex, build_id, now),
            )
        return turn_id

    def finish_turn(
        self,
        turn_id: str,
        status: str,
        *,
        action: dict[str, Any] | None = None,
        invocation_id: str | None = None,
        gap_id: str | None = None,
        error_code: str | None = None,
        usage: dict[str, Any] | None = None,
    ) -> None:
        if status not in {"done", "needs_you", "software_missing", "problem"}:
            raise RuntimeFailure("TURN_STATUS_INVALID")
        with self.connect() as db:
            changed = db.execute(
                """UPDATE turns SET status=?, action_json=?, invocation_id=?, gap_id=?,
                          error_code=?, usage_json=?, completed_at=?
                   WHERE id=? AND status='working'""",
                (
                    status,
                    canonical_json(action).decode() if action is not None else None,
                    invocation_id,
                    gap_id,
                    error_code,
                    canonical_json(usage or {}).decode(),
                    utc_now(),
                    turn_id,
                ),
            ).rowcount
        if changed != 1:
            raise RuntimeFailure("TURN_STATE_CONFLICT")

    def turn(self, turn_id: str) -> dict[str, Any]:
        """Return one durable semantic turn with decoded bounded evidence."""

        with self.connect() as db:
            row = db.execute("SELECT * FROM turns WHERE id=?", (turn_id,)).fetchone()
        if row is None:
            raise RuntimeFailure("TURN_UNKNOWN")
        value = dict(row)
        for field in ("action_json", "usage_json"):
            decoded = field.removesuffix("_json")
            value[decoded] = json.loads(value.pop(field)) if value.get(field) else None
        return value

    def record_problem_incident(
        self,
        turn_id: str,
        conversation_id: str,
        facts: dict[str, Any],
    ) -> None:
        """Persist one bounded private operator incident before exposing its reference."""

        required = {
            "schema", "problem_reference", "component", "stable_error_code",
            "exception_type", "safe_message", "world_digest", "semantic_provider",
            "semantic_model", "semantic_request_sha256", "semantic_response_sha256",
            "selected_capability_id", "selected_version_digest", "application_id",
            "operation_id", "runtime_release_identity", "model_calls", "source_calls",
            "application_calls", "effect_count", "traceback_sha256", "internal_frames",
            "terminal_state", "semantic_failure_shape",
            "provider_http_status", "provider_response_bytes", "provider_response_sha256",
            "provider_request_id", "provider_envelope",
            "semantic_attempt_count", "semantic_retry_used", "semantic_attempts",
            "execution_phase",
        }
        if (
            set(facts) != required
            or facts.get("schema") != "capy.problem-incident/v0"
            or facts.get("problem_reference") != turn_id
            or not isinstance(facts.get("internal_frames"), list)
            or len(facts["internal_frames"]) > 12
        ):
            raise RuntimeFailure("PROBLEM_INCIDENT_INVALID")
        payload = canonical_json(facts).decode()
        if len(payload.encode()) > 16_384:
            raise RuntimeFailure("PROBLEM_INCIDENT_INVALID")
        with self.connect() as db:
            turn = db.execute(
                "SELECT 1 FROM turns WHERE id=? AND conversation_id=?",
                (turn_id, conversation_id),
            ).fetchone()
            if turn is None:
                raise RuntimeFailure("PROBLEM_INCIDENT_INVALID")
            db.execute(
                """INSERT INTO problem_incidents
                   (problem_reference, turn_id, conversation_id, facts_json, created_at)
                   VALUES (?, ?, ?, ?, ?)""",
                (turn_id, turn_id, conversation_id, payload, utc_now()),
            )

    def problem_incident(self, problem_reference: str) -> dict[str, Any]:
        with self.connect() as db:
            row = db.execute(
                "SELECT facts_json, created_at FROM problem_incidents WHERE problem_reference=?",
                (problem_reference,),
            ).fetchone()
        if row is None:
            raise RuntimeFailure("PROBLEM_REFERENCE_UNKNOWN")
        value = json.loads(row["facts_json"])
        value["recorded_at"] = row["created_at"]
        return value

    def claim_message_submission(
        self,
        actor: ActorContext,
        conversation_id: str,
        submission_id: str,
    ) -> bool:
        if not re.fullmatch(r"[0-9a-f]{32}", submission_id):
            raise RuntimeFailure("CHAT_SUBMISSION_INVALID")
        with self.connect() as db:
            self._conversation(db, actor, conversation_id)
            existing = db.execute(
                "SELECT 1 FROM message_submissions WHERE submission_id=?",
                (submission_id,),
            ).fetchone()
            if existing is not None:
                return False
            db.execute(
                """INSERT INTO message_submissions
                   (submission_id, conversation_id, scope_id, principal_id, membership_id,
                    status, turn_id, created_at, completed_at)
                   VALUES (?, ?, ?, ?, ?, 'claimed', NULL, ?, NULL)""",
                (
                    submission_id, conversation_id, actor.execution_scope_id,
                    actor.principal_id, actor.membership_id, utc_now(),
                ),
            )
        return True

    def complete_message_submission(self, submission_id: str, turn_id: str) -> None:
        with self.connect() as db:
            changed = db.execute(
                """UPDATE message_submissions SET status='completed', turn_id=?, completed_at=?
                   WHERE submission_id=? AND status='claimed'""",
                (turn_id, utc_now(), submission_id),
            ).rowcount
        if changed != 1:
            raise RuntimeFailure("CHAT_SUBMISSION_STATE_CONFLICT")

    def record_problem_render_incident(
        self,
        problem_reference: str,
        facts: dict[str, Any],
    ) -> str:
        if (
            set(facts) != {"schema", "component", "exception_type", "traceback_sha256", "internal_frames"}
            or facts.get("schema") != "capy.problem-render-incident/v0"
            or not isinstance(facts.get("internal_frames"), list)
            or len(facts["internal_frames"]) > 12
        ):
            raise RuntimeFailure("PROBLEM_RENDER_INCIDENT_INVALID")
        incident_id = uuid.uuid4().hex
        with self.connect() as db:
            exists = db.execute(
                "SELECT 1 FROM problem_incidents WHERE problem_reference=?",
                (problem_reference,),
            ).fetchone()
            if exists is None:
                raise RuntimeFailure("PROBLEM_REFERENCE_UNKNOWN")
            db.execute(
                "INSERT INTO problem_render_incidents VALUES (?, ?, ?, ?)",
                (incident_id, problem_reference, canonical_json(facts).decode(), utc_now()),
            )
        return incident_id

    def record_result_and_finish_turn(
        self,
        authority: str | ActorContext,
        conversation_id: str,
        turn_id: str,
        text: str,
        metadata: dict[str, Any],
        resources: list[dict[str, Any]],
        action: dict[str, Any],
        invocation_id: str,
        usage: dict[str, Any],
    ) -> str:
        """Commit one result card and its completed turn as a single fact."""

        message_id = uuid.uuid4().hex
        now = utc_now()
        scope_id = self._scope(authority)
        with self.connect() as db:
            self._conversation(db, authority, conversation_id)
            changed = db.execute(
                """UPDATE turns SET status='done', action_json=?, invocation_id=?,
                          error_code=NULL, usage_json=?, completed_at=?
                   WHERE id=? AND conversation_id=? AND status='working'""",
                (
                    canonical_json(action).decode(), invocation_id,
                    canonical_json(usage).decode(), now, turn_id, conversation_id,
                ),
            ).rowcount
            if changed != 1:
                raise RuntimeFailure("TURN_STATE_CONFLICT")
            db.execute(
                "INSERT INTO messages VALUES (?, ?, 'assistant', ?, 'result', 'DONE', ?, ?)",
                (message_id, conversation_id, text, canonical_json(metadata).decode(), now),
            )
            for resource in resources:
                db.execute(
                    "INSERT INTO message_resources VALUES (?, ?, ?, ?, ?, ?, ?)",
                    (
                        message_id, scope_id, resource["digest"], resource["filename"],
                        resource["media_type"], resource["size_bytes"],
                        resource.get("relation", "artifact"),
                    ),
                )
            db.execute(
                "UPDATE conversations SET updated_at=? WHERE id=?",
                (now, conversation_id),
            )
        return message_id

    def create_gap(
        self,
        conversation_id: str,
        turn_id: str,
        original_message: str,
        resources: list[str],
        world_digest: str,
        needed_ability: str,
        desired_result: str,
        missing_information: list[str],
    ) -> str:
        gap_id = uuid.uuid4().hex
        with self.connect() as db:
            db.execute(
                "INSERT INTO capability_gaps VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'open', ?)",
                (
                    gap_id,
                    conversation_id,
                    turn_id,
                    original_message,
                    canonical_json(resources).decode(),
                    world_digest,
                    needed_ability,
                    desired_result,
                    canonical_json(missing_information).decode(),
                    utc_now(),
                ),
            )
        return gap_id

    def gap(self, scope_id: str, gap_id: str) -> dict[str, Any]:
        with self.connect() as db:
            row = db.execute(
                """SELECT g.*, t.owner_message_id
                   FROM capability_gaps g
                   JOIN conversations c ON c.id = g.conversation_id
                   JOIN turns t ON t.id = g.turn_id
                   WHERE g.id = ? AND c.scope_id = ?""",
                (gap_id, scope_id),
            ).fetchone()
        if row is None:
            raise RuntimeFailure("CAPABILITY_GAP_NOT_IN_SCOPE")
        value = dict(row)
        value["resources"] = json.loads(value.pop("resources_json"))
        value["missing_information"] = json.loads(value.pop("missing_information_json"))
        return value

    def create_build_proposal(
        self,
        authority: str | ActorContext,
        gap_id: str,
        specification: dict[str, Any],
        summary: dict[str, str],
        *,
        blocked_reason: str | None = None,
    ) -> dict[str, Any]:
        """Persist one immutable trusted proposal bound to the exact gap facts."""

        scope_id = self._scope(authority)
        gap = self.gap(scope_id, gap_id)
        now = utc_now()
        proposal_id = uuid.uuid4().hex
        bound = {
            "schema": "capy.build-proposal/v0",
            "gap_id": gap_id,
            "conversation_id": gap["conversation_id"],
            "scope_id": scope_id,
            "resources": list(gap["resources"]),
            "world_digest": gap["world_digest"],
            "needed_ability": gap["needed_ability"],
            "desired_result": gap["desired_result"],
            "specification": specification,
            "summary": summary,
            "approvable": blocked_reason is None,
            "blocked_reason": blocked_reason,
        }
        proposal_digest = hashlib.sha256(canonical_json(bound)).hexdigest()
        status = "APPROVABLE" if blocked_reason is None else "BLOCKED"
        with self.connect() as db:
            self._conversation(db, authority, gap["conversation_id"])
            db.execute(
                """INSERT OR IGNORE INTO build_proposals
                   (id, gap_id, conversation_id, scope_id, resources_json,
                    world_digest, needed_ability, desired_result, specification_json,
                    summary_json, proposal_digest, status, blocked_reason,
                    approved_build_id, terminal_error, created_at, updated_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, NULL, ?, ?)""",
                (
                    proposal_id, gap_id, gap["conversation_id"], scope_id,
                    canonical_json(gap["resources"]).decode(), gap["world_digest"],
                    gap["needed_ability"], gap["desired_result"],
                    canonical_json(specification).decode(), canonical_json(summary).decode(),
                    proposal_digest, status, blocked_reason, now, now,
                ),
            )
            row = db.execute(
                "SELECT * FROM build_proposals WHERE gap_id=?", (gap_id,)
            ).fetchone()
        proposal = self._decode_build_proposal(row)
        if proposal["proposal_digest"] != proposal_digest:
            raise RuntimeFailure("BUILD_PROPOSAL_CONFLICT")
        return proposal

    @staticmethod
    def _decode_build_proposal(row: sqlite3.Row) -> dict[str, Any]:
        value = dict(row)
        value["resources"] = json.loads(value.pop("resources_json"))
        value["specification"] = json.loads(value.pop("specification_json"))
        value["summary"] = json.loads(value.pop("summary_json"))
        return value

    def build_proposal_for_gap(
        self, authority: str | ActorContext, gap_id: str
    ) -> dict[str, Any] | None:
        scope_id = self._scope(authority)
        with self.connect() as db:
            row = db.execute(
                """SELECT p.* FROM build_proposals p
                   JOIN conversations c ON c.id=p.conversation_id
                   WHERE p.gap_id=? AND p.scope_id=? AND c.scope_id=?""",
                (gap_id, scope_id, scope_id),
            ).fetchone()
        return None if row is None else self._decode_build_proposal(row)

    def build_proposals_for_conversation(
        self, authority: str | ActorContext, conversation_id: str
    ) -> list[dict[str, Any]]:
        scope_id = self._scope(authority)
        with self.connect() as db:
            self._conversation(db, authority, conversation_id)
            rows = db.execute(
                """SELECT * FROM build_proposals
                   WHERE conversation_id=? AND scope_id=? ORDER BY created_at, id""",
                (conversation_id, scope_id),
            ).fetchall()
        return [self._decode_build_proposal(row) for row in rows]

    def begin_build_proposal_approval(
        self, authority: str | ActorContext, gap_id: str, proposal_digest: str
    ) -> dict[str, Any]:
        """Consume the single owner approval for an exact immutable proposal."""

        scope_id = self._scope(authority)
        now = utc_now()
        with self.connect() as db:
            row = db.execute(
                "SELECT * FROM build_proposals WHERE gap_id=? AND scope_id=?",
                (gap_id, scope_id),
            ).fetchone()
            if row is None:
                raise RuntimeFailure("BUILD_PROPOSAL_REQUIRED")
            proposal = self._decode_build_proposal(row)
            if proposal["proposal_digest"] != proposal_digest:
                raise RuntimeFailure("BUILD_PROPOSAL_DIGEST_MISMATCH")
            if proposal["status"] == "APPROVED":
                return proposal
            if proposal["status"] != "APPROVABLE":
                raise RuntimeFailure("BUILD_PROPOSAL_NOT_APPROVABLE")
            changed = db.execute(
                """UPDATE build_proposals SET status='APPROVING', updated_at=?
                   WHERE id=? AND status='APPROVABLE'""",
                (now, proposal["id"]),
            ).rowcount
            if changed != 1:
                raise RuntimeFailure("BUILD_PROPOSAL_STATE_CONFLICT")
            row = db.execute(
                "SELECT * FROM build_proposals WHERE id=?", (proposal["id"],)
            ).fetchone()
        return self._decode_build_proposal(row)

    def finish_build_proposal_approval(
        self, proposal_id: str, *, build_id: str | None = None, error_code: str | None = None
    ) -> dict[str, Any]:
        if (build_id is None) == (error_code is None):
            raise RuntimeFailure("BUILD_PROPOSAL_RESULT_INVALID")
        status = "APPROVED" if build_id is not None else "FAILED"
        with self.connect() as db:
            changed = db.execute(
                """UPDATE build_proposals SET status=?, approved_build_id=?,
                          terminal_error=?, updated_at=?
                   WHERE id=? AND status='APPROVING'""",
                (status, build_id, error_code, utc_now(), proposal_id),
            ).rowcount
            if changed != 1:
                raise RuntimeFailure("BUILD_PROPOSAL_STATE_CONFLICT")
            row = db.execute(
                "SELECT * FROM build_proposals WHERE id=?", (proposal_id,)
            ).fetchone()
        return self._decode_build_proposal(row)

    def recover_interrupted_build_proposal_approvals(self) -> int:
        """Terminalize approvals whose trusted handoff was interrupted by restart."""

        with self.connect() as db:
            now = utc_now()
            completed = db.execute(
                """UPDATE build_proposals
                   SET status='APPROVED',
                       approved_build_id=(
                           SELECT id FROM build_requests
                           WHERE build_requests.gap_id=build_proposals.gap_id
                       ),
                       terminal_error=NULL, updated_at=?
                   WHERE status='APPROVING'
                     AND EXISTS (
                         SELECT 1 FROM build_requests
                         WHERE build_requests.gap_id=build_proposals.gap_id
                     )""",
                (now,),
            ).rowcount
            failed = db.execute(
                """UPDATE build_proposals SET status='FAILED',
                          terminal_error='BUILD_APPROVAL_INTERRUPTED', updated_at=?
                   WHERE status='APPROVING'""",
                (now,),
            ).rowcount
        return completed + failed

    def create_build_request(self, value: dict[str, Any]) -> dict[str, Any]:
        fields = (
            "id", "gap_id", "conversation_id", "scope_id",
            "original_owner_message_id", "original_turn_id", "original_world_digest",
            "resources_json", "needed_ability", "desired_result",
            "missing_information_json", "side_effect_ceiling", "packet_digest",
            "status", "created_at", "updated_at",
        )
        with self.connect() as db:
            self._conversation(db, value["scope_id"], value["conversation_id"])
            db.execute(
                f"INSERT OR IGNORE INTO build_requests ({','.join(fields)}) VALUES ({','.join('?' for _ in fields)})",
                tuple(value[field] for field in fields),
            )
            row = db.execute(
                "SELECT * FROM build_requests WHERE gap_id = ?", (value["gap_id"],)
            ).fetchone()
        return self._decode_build(row)

    @staticmethod
    def _decode_build(row: sqlite3.Row) -> dict[str, Any]:
        value = dict(row)
        for field in (
            "resources_json", "missing_information_json", "previous_binding_json",
            "published_binding_json",
        ):
            decoded = field.removesuffix("_json")
            value[decoded] = json.loads(value.pop(field)) if value[field] is not None else None
        return value

    def build(self, build_id: str, scope_id: str | None = None) -> dict[str, Any]:
        with self.connect() as db:
            if scope_id is None:
                row = db.execute("SELECT * FROM build_requests WHERE id = ?", (build_id,)).fetchone()
            else:
                row = db.execute(
                    "SELECT * FROM build_requests WHERE id = ? AND scope_id = ?",
                    (build_id, scope_id),
                ).fetchone()
        if row is None:
            raise RuntimeFailure("BUILD_REQUEST_UNKNOWN")
        return self._decode_build(row)

    def builds_for_conversation(self, authority: str | ActorContext, conversation_id: str) -> list[dict[str, Any]]:
        self.recover_expired_build_leases()
        with self.connect() as db:
            self._conversation(db, authority, conversation_id)
            rows = db.execute(
                "SELECT * FROM build_requests WHERE conversation_id = ? ORDER BY created_at, id",
                (conversation_id,),
            ).fetchall()
        return [self._decode_build(row) for row in rows]

    def transition_build(
        self,
        build_id: str,
        expected: set[str],
        status: str,
        **fields: Any,
    ) -> dict[str, Any]:
        allowed = {
            "builder_id", "lease_id", "lease_expires_at", "builder_session_id",
            "candidate_repository", "candidate_commit", "candidate_tree",
            "candidate_archive_digest", "candidate_capability_id",
            "candidate_version_digest", "acceptance_digest", "previous_binding_json",
            "published_binding_json", "retry_turn_id", "terminal_error",
        }
        if set(fields) - allowed:
            raise RuntimeFailure("BUILD_UPDATE_INVALID")
        assignments = ["status = ?", "updated_at = ?"] + [f"{name} = ?" for name in fields]
        parameters = [status, utc_now(), *fields.values(), build_id, *sorted(expected)]
        placeholders = ",".join("?" for _ in expected)
        with self.connect() as db:
            changed = db.execute(
                f"UPDATE build_requests SET {','.join(assignments)} WHERE id = ? AND status IN ({placeholders})",
                parameters,
            ).rowcount
            if changed != 1:
                raise RuntimeFailure("BUILD_STATE_CONFLICT")
            db.execute(
                "INSERT INTO build_events VALUES (?, ?, ?, ?, ?)",
                (uuid.uuid4().hex, build_id, status, canonical_json({}).decode(), utc_now()),
            )
            row = db.execute("SELECT * FROM build_requests WHERE id = ?", (build_id,)).fetchone()
        return self._decode_build(row)

    def record_generic_build_outcome(
        self,
        build_id: str,
        classification: str,
        provenance: dict[str, Any],
        detail: str | None = None,
    ) -> dict[str, Any]:
        """Persist exactly one terminal coordinator judgment for owner rendering."""

        build = self.build(build_id)
        encoded = canonical_json(provenance).decode()
        with self.connect() as db:
            db.execute(
                """INSERT OR IGNORE INTO generic_build_outcomes
                   (build_id, conversation_id, scope_id, classification, detail,
                    provenance_json, created_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (
                    build_id, build["conversation_id"], build["scope_id"],
                    classification, detail, encoded, utc_now(),
                ),
            )
            row = db.execute(
                "SELECT * FROM generic_build_outcomes WHERE build_id=?", (build_id,)
            ).fetchone()
        value = dict(row)
        value["provenance"] = json.loads(value.pop("provenance_json"))
        if (
            value["classification"] != classification
            or value["detail"] != detail
            or value["provenance"] != provenance
        ):
            raise RuntimeFailure("GENERIC_BUILD_OUTCOME_CONFLICT")
        return value

    def generic_build_outcome(self, build_id: str) -> dict[str, Any] | None:
        with self.connect() as db:
            row = db.execute(
                "SELECT * FROM generic_build_outcomes WHERE build_id=?", (build_id,)
            ).fetchone()
        if row is None:
            return None
        value = dict(row)
        value["provenance"] = json.loads(value.pop("provenance_json"))
        return value

    def generic_build_outcomes_for_conversation(
        self, authority: str | ActorContext, conversation_id: str
    ) -> list[dict[str, Any]]:
        scope_id = self._scope(authority)
        with self.connect() as db:
            self._conversation(db, authority, conversation_id)
            rows = db.execute(
                """SELECT * FROM generic_build_outcomes
                   WHERE conversation_id=? AND scope_id=? ORDER BY created_at, build_id""",
                (conversation_id, scope_id),
            ).fetchall()
        result = []
        for row in rows:
            value = dict(row)
            value["provenance"] = json.loads(value.pop("provenance_json"))
            result.append(value)
        return result

    def record_publication(self, build_id: str, receipt: dict[str, Any], digest: str) -> None:
        encoded = canonical_json(receipt).decode()
        with self.connect() as db:
            existing = db.execute(
                "SELECT receipt_digest FROM publication_receipts WHERE build_id = ?", (build_id,)
            ).fetchone()
            if existing is not None and existing["receipt_digest"] != digest:
                raise RuntimeFailure("PUBLICATION_RECEIPT_CONFLICT")
            db.execute(
                "INSERT OR IGNORE INTO publication_receipts VALUES (?, ?, ?, ?)",
                (build_id, encoded, digest, utc_now()),
            )

    def publication(self, build_id: str) -> dict[str, Any] | None:
        with self.connect() as db:
            row = db.execute(
                "SELECT receipt_json, receipt_digest FROM publication_receipts WHERE build_id = ?",
                (build_id,),
            ).fetchone()
        if row is None:
            return None
        return {"receipt": json.loads(row["receipt_json"]), "digest": row["receipt_digest"]}

    def record_binding_history(
        self,
        build_id: str,
        scope_id: str,
        capability_id: str,
        operation: str,
        previous: dict[str, Any] | None,
        new: dict[str, Any] | None,
        receipt: dict[str, Any],
    ) -> str:
        history_id = uuid.uuid4().hex
        encoded_receipt = canonical_json(receipt).decode()
        with self.connect() as db:
            existing = db.execute(
                "SELECT id, receipt_json FROM binding_history WHERE build_id = ? AND operation = ?",
                (build_id, operation),
            ).fetchone()
            if existing is not None:
                if existing["receipt_json"] != encoded_receipt:
                    raise RuntimeFailure("BINDING_HISTORY_CONFLICT")
                return existing["id"]
            db.execute(
                "INSERT INTO binding_history VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    history_id, build_id, scope_id, capability_id, operation,
                    canonical_json(previous).decode() if previous is not None else None,
                    canonical_json(new).decode() if new is not None else None,
                    encoded_receipt, utc_now(),
                ),
            )
        return history_id

    def recover_expired_build_leases(self) -> int:
        now = utc_now()
        with self.connect() as db:
            rows = db.execute(
                "SELECT id FROM build_requests WHERE status = 'BUILDING' AND lease_expires_at <= ?",
                (now,),
            ).fetchall()
            for row in rows:
                db.execute(
                    """UPDATE build_requests
                       SET status='APPROVED_WAITING_FOR_BUILDER', builder_id=NULL,
                           lease_id=NULL, lease_expires_at=NULL, updated_at=? WHERE id=?""",
                    (now, row["id"]),
                )
        return len(rows)

    def recover_interrupted_build_retries(self) -> int:
        """Return interrupted retries to a truthful resumable state."""

        with self.connect() as db:
            rows = db.execute(
                """SELECT b.id, b.retry_turn_id, t.status AS turn_status
                   FROM build_requests b
                   LEFT JOIN turns t ON t.id = b.retry_turn_id
                   WHERE b.status = 'RETRYING'"""
            ).fetchall()
            now = utc_now()
            for row in rows:
                if row["turn_status"] == "done":
                    status = "COMPLETED"
                    retry_turn_id = row["retry_turn_id"]
                else:
                    status = "PUBLISHED"
                    retry_turn_id = None
                db.execute(
                    "UPDATE build_requests SET status=?, retry_turn_id=?, updated_at=? WHERE id=? AND status='RETRYING'",
                    (status, retry_turn_id, now, row["id"]),
                )
                db.execute(
                    "INSERT INTO build_events VALUES (?, ?, ?, ?, ?)",
                    (
                        uuid.uuid4().hex, row["id"], status,
                        canonical_json({"recovered_from": "RETRYING"}).decode(), now,
                    ),
                )
        return len(rows)

    def recover_interrupted_turns(self) -> int:
        with self.connect() as db:
            has_dispatch = db.execute(
                "SELECT 1 FROM sqlite_master WHERE type='table' AND name='semantic_dispatch_jobs'"
            ).fetchone() is not None
            if has_dispatch:
                rows = db.execute(
                    """SELECT id, conversation_id, world_digest, adapter, model FROM turns
                       WHERE status='working' AND NOT EXISTS (
                           SELECT 1 FROM semantic_dispatch_jobs j
                           WHERE (
                               j.consumer_key='chat:' || turns.id
                               OR j.consumer_key LIKE 'chat:' || turns.id || ':%'
                           )
                           AND j.state IN ('queued','retry_wait','provider_running','result_ready','failed')
                       )"""
                ).fetchall()
            else:
                rows = db.execute(
                    """SELECT id, conversation_id, world_digest, adapter, model
                       FROM turns WHERE status = 'working'"""
                ).fetchall()
            now = utc_now()
            for row in rows:
                incident = {
                    "schema": "capy.problem-incident/v0",
                    "problem_reference": row["id"],
                    "component": "turn_recovery",
                    "stable_error_code": "TURN_INTERRUPTED",
                    "exception_type": None,
                    "safe_message": "The turn was interrupted before terminal commit.",
                    "world_digest": row["world_digest"],
                    "semantic_provider": row["adapter"],
                    "semantic_model": row["model"],
                    "semantic_request_sha256": None,
                    "semantic_response_sha256": None,
                    "semantic_failure_shape": None,
                    "provider_http_status": None,
                    "provider_response_bytes": None,
                    "provider_response_sha256": None,
                    "provider_request_id": None,
                    "provider_envelope": None,
                    "semantic_attempt_count": 0,
                    "semantic_retry_used": False,
                    "semantic_attempts": None,
                    "selected_capability_id": None,
                    "selected_version_digest": None,
                    "application_id": None,
                    "operation_id": None,
                    "runtime_release_identity": self._runtime_release_identity(),
                    "model_calls": None,
                    "source_calls": None,
                    "application_calls": None,
                    "effect_count": None,
                    "execution_phase": "pre_execution",
                    "traceback_sha256": hashlib.sha256(b"").hexdigest(),
                    "internal_frames": [],
                    "terminal_state": "problem",
                }
                db.execute(
                    """INSERT INTO problem_incidents
                       (problem_reference, turn_id, conversation_id, facts_json, created_at)
                       VALUES (?, ?, ?, ?, ?)""",
                    (
                        row["id"], row["id"], row["conversation_id"],
                        canonical_json(incident).decode(), now,
                    ),
                )
                db.execute(
                    "UPDATE turns SET status='problem', error_code='TURN_INTERRUPTED', completed_at=? WHERE id=?",
                    (now, row["id"]),
                )
                db.execute(
                    "INSERT INTO messages VALUES (?, ?, 'assistant', ?, 'problem', 'PROBLEM', '{}', ?)",
                    (
                        uuid.uuid4().hex,
                        row["conversation_id"],
                        "The previous turn was interrupted before it completed. Please send it again.",
                        now,
                    ),
                )
        return len(rows)

    @staticmethod
    def _runtime_release_identity() -> str:
        path = Path(__file__).resolve()
        parts = path.parts
        if "releases" in parts:
            index = parts.index("releases")
            if index + 1 < len(parts):
                return parts[index + 1]
        return "development"
