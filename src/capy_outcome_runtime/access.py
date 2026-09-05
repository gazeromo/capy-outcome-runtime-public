"""Local claim-based authority for browser clients and team memberships."""

from __future__ import annotations

import hashlib
import json
import secrets
import sqlite3
import threading
import unicodedata
import uuid
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Iterator

from .model import RuntimeFailure
from .store import RuntimeStore, canonical_json, utc_now


CLAIM_TTLS = {
    "bootstrap_owner": timedelta(minutes=30),
    "join_team": timedelta(hours=24),
    "attach_client": timedelta(minutes=10),
}


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _future(delta: timedelta) -> str:
    return (datetime.now(timezone.utc) + delta).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _active(timestamp: str) -> bool:
    return datetime.fromisoformat(timestamp.replace("Z", "+00:00")) > datetime.now(timezone.utc)


def _display_name(value: str | None) -> str:
    if not isinstance(value, str):
        raise RuntimeFailure("ACCESS_DISPLAY_NAME_INVALID")
    value = value.strip()
    if not 1 <= len(value) <= 100 or "\x00" in value:
        raise RuntimeFailure("ACCESS_DISPLAY_NAME_INVALID")
    if any(unicodedata.category(char) in {"Cc", "Cf", "Cs"} for char in value):
        raise RuntimeFailure("ACCESS_DISPLAY_NAME_INVALID")
    return value


@dataclass(frozen=True)
class ActorContext:
    authority_id: str
    principal_id: str
    principal_display_name: str
    client_id: str
    membership_id: str
    membership_kind: str
    team_id: str
    team_name: str
    execution_scope_id: str
    workspace_kind: str = "team"

    def initiator(self) -> dict[str, str]:
        return {
            "authority_id": self.authority_id,
            "principal_id": self.principal_id,
            "membership_id": self.membership_id,
            "team_id": self.team_id,
            "execution_scope_id": self.execution_scope_id,
        }


@dataclass(frozen=True)
class AuthenticatedClient:
    actor: ActorContext
    csrf_token: str
    client_label: str


@dataclass(frozen=True)
class ClaimPreview:
    claim_id: str
    claim_type: str
    title: str
    needs_display_name: bool
    expires_at: str
    target_principal_id: str | None = None


@dataclass(frozen=True)
class Redemption:
    actor: ActorContext
    credential: str | None
    created_principal: bool
    created_membership: bool
    created_client: bool


class AccessStore:
    """Own the single local authority in RuntimeStore.control.sqlite3."""

    def __init__(self, runtime: RuntimeStore):
        self.runtime = runtime
        self._authority_lock = threading.RLock()
        self._membership_reconciler: Callable[[str], Any] | None = None
        self._personal_workspace_reconciler: Callable[[ActorContext], Any] | None = None
        self._initialize()

    def set_membership_reconciler(self, reconciler: Callable[[str], Any]) -> None:
        """Install the product's synchronous derived-binding reconciler."""
        self._membership_reconciler = reconciler

    def set_personal_workspace_reconciler(
        self, reconciler: Callable[[ActorContext], Any]
    ) -> None:
        """Install exact application projection for new Personal workspaces."""
        self._personal_workspace_reconciler = reconciler

    def _initialize(self) -> None:
        with self.runtime.connect() as db:
            db.executescript(
                """
                CREATE TABLE IF NOT EXISTS access_authorities (
                    singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
                    id TEXT UNIQUE NOT NULL,
                    created_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS access_principals (
                    id TEXT PRIMARY KEY,
                    authority_id TEXT NOT NULL,
                    display_name TEXT NOT NULL,
                    status TEXT NOT NULL CHECK(status IN ('active','disabled')),
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS access_teams (
                    id TEXT PRIMARY KEY,
                    authority_id TEXT NOT NULL,
                    name TEXT NOT NULL,
                    status TEXT NOT NULL CHECK(status IN ('active','disabled')),
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    UNIQUE(authority_id, name)
                );
                CREATE TABLE IF NOT EXISTS access_memberships (
                    id TEXT PRIMARY KEY,
                    principal_id TEXT NOT NULL REFERENCES access_principals(id),
                    team_id TEXT NOT NULL REFERENCES access_teams(id),
                    kind TEXT NOT NULL CHECK(kind IN ('owner','member')),
                    execution_scope_id TEXT UNIQUE NOT NULL REFERENCES scopes(id),
                    status TEXT NOT NULL CHECK(status IN ('active','revoked')),
                    joined_at TEXT NOT NULL,
                    revoked_at TEXT,
                    UNIQUE(principal_id, team_id)
                );
                CREATE TABLE IF NOT EXISTS access_clients (
                    id TEXT PRIMARY KEY,
                    principal_id TEXT NOT NULL REFERENCES access_principals(id),
                    credential_digest TEXT UNIQUE NOT NULL,
                    csrf_token TEXT NOT NULL,
                    label TEXT NOT NULL,
                    active_membership_id TEXT NOT NULL REFERENCES access_memberships(id),
                    status TEXT NOT NULL CHECK(status IN ('active','revoked')),
                    created_at TEXT NOT NULL,
                    last_seen_at TEXT NOT NULL,
                    revoked_at TEXT
                );
                CREATE TABLE IF NOT EXISTS access_claims (
                    id TEXT PRIMARY KEY,
                    authority_id TEXT NOT NULL,
                    claim_type TEXT NOT NULL CHECK(claim_type IN ('bootstrap_owner','join_team','attach_client')),
                    token_digest TEXT UNIQUE NOT NULL,
                    issued_by_principal_id TEXT,
                    issued_by_membership_id TEXT,
                    payload_json TEXT NOT NULL,
                    expires_at TEXT NOT NULL,
                    consumed_at TEXT,
                    consumed_by_principal_id TEXT,
                    consumed_by_client_id TEXT,
                    revoked_at TEXT,
                    created_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS access_memberships_principal
                    ON access_memberships(principal_id, status);
                CREATE INDEX IF NOT EXISTS access_clients_principal
                    ON access_clients(principal_id, status);
                CREATE TABLE IF NOT EXISTS access_personal_workspaces (
                    principal_id TEXT PRIMARY KEY REFERENCES access_principals(id),
                    team_id TEXT UNIQUE NOT NULL REFERENCES access_teams(id),
                    membership_id TEXT UNIQUE NOT NULL REFERENCES access_memberships(id),
                    created_at TEXT NOT NULL
                );
                """
            )
            principals = db.execute(
                "SELECT id, authority_id FROM access_principals ORDER BY created_at, id"
            ).fetchall()
            for principal in principals:
                membership_id, created = self._ensure_personal_workspace(
                    db, principal["id"], principal["authority_id"]
                )
                if created:
                    db.execute(
                        "UPDATE access_clients SET active_membership_id=? WHERE principal_id=? AND status='active'",
                        (membership_id, principal["id"]),
                    )

    def ensure_authority(self) -> str:
        with self.runtime.connect() as db:
            row = db.execute("SELECT id FROM access_authorities WHERE singleton=1").fetchone()
            if row is not None:
                return row["id"]
            authority_id = "authority-" + uuid.uuid4().hex
            db.execute(
                "INSERT OR IGNORE INTO access_authorities VALUES (1, ?, ?)",
                (authority_id, utc_now()),
            )
            row = db.execute("SELECT id FROM access_authorities WHERE singleton=1").fetchone()
        return row["id"]

    def _claim(
        self,
        claim_type: str,
        payload: dict[str, str],
        *,
        issuer: ActorContext | None = None,
        ttl: timedelta | None = None,
    ) -> dict[str, str]:
        if claim_type not in CLAIM_TTLS:
            raise RuntimeFailure("ACCESS_CLAIM_TYPE_INVALID")
        token = secrets.token_urlsafe(32)
        claim_id = "claim-" + uuid.uuid4().hex
        authority_id = self.ensure_authority()
        now = utc_now()
        expires_at = _future(ttl or CLAIM_TTLS[claim_type])
        with self.runtime.connect() as db:
            db.execute(
                """INSERT INTO access_claims
                   (id, authority_id, claim_type, token_digest, issued_by_principal_id,
                    issued_by_membership_id, payload_json, expires_at, created_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    claim_id, authority_id, claim_type, _digest(token),
                    issuer.principal_id if issuer else None,
                    issuer.membership_id if issuer else None,
                    canonical_json(payload).decode(),
                    expires_at, now,
                ),
            )
        return {"id": claim_id, "token": token, "expires_at": expires_at}

    def create_bootstrap_claim(
        self, team_name: str = "Cosmain", legacy_scope_id: str = "owner", *, ttl: timedelta | None = None
    ) -> dict[str, str]:
        team_name = _display_name(team_name)
        with self.runtime.connect() as db:
            if db.execute("SELECT 1 FROM access_principals LIMIT 1").fetchone() is not None:
                raise RuntimeFailure("ACCESS_ALREADY_INITIALIZED")
            db.execute("INSERT OR IGNORE INTO scopes(id, created_at) VALUES (?, ?)", (legacy_scope_id, utc_now()))
        return self._claim(
            "bootstrap_owner", {"team_name": team_name, "legacy_scope_id": legacy_scope_id}, ttl=ttl
        )

    def create_join_team_claim(self, actor: ActorContext, *, ttl: timedelta | None = None) -> dict[str, str]:
        actor = self._require_current_actor(actor)
        if actor.workspace_kind != "team" or actor.membership_kind != "owner":
            raise RuntimeFailure("ACCESS_OWNER_REQUIRED")
        return self._claim(
            "join_team", {"team_id": actor.team_id, "membership_kind": "member"},
            issuer=actor, ttl=ttl,
        )

    def create_attach_client_claim(self, actor: ActorContext, *, ttl: timedelta | None = None) -> dict[str, str]:
        actor = self._require_current_actor(actor)
        return self._claim(
            "attach_client", {"principal_id": actor.principal_id, "membership_id": actor.membership_id},
            issuer=actor, ttl=ttl,
        )

    @staticmethod
    def _valid_claim(row: sqlite3.Row | None) -> sqlite3.Row:
        if row is None or row["consumed_at"] or row["revoked_at"] or not _active(row["expires_at"]):
            raise RuntimeFailure("ACCESS_CLAIM_INVALID")
        return row

    @staticmethod
    def _payload(row: sqlite3.Row) -> dict[str, str]:
        try:
            payload = json.loads(row["payload_json"])
        except (TypeError, ValueError, json.JSONDecodeError) as exc:
            raise RuntimeFailure("ACCESS_CLAIM_INVALID") from exc
        expected = {
            "bootstrap_owner": {"team_name", "legacy_scope_id"},
            "join_team": {"team_id", "membership_kind"},
            "attach_client": {"principal_id", "membership_id"},
        }[row["claim_type"]]
        if (
            not isinstance(payload, dict)
            or set(payload) != expected
            or not all(isinstance(value, str) and value for value in payload.values())
        ):
            raise RuntimeFailure("ACCESS_CLAIM_INVALID")
        return payload

    def inspect_claim(self, token: str) -> ClaimPreview:
        with self.runtime.connect() as db:
            row = self._valid_claim(
                db.execute("SELECT * FROM access_claims WHERE token_digest=?", (_digest(token),)).fetchone()
            )
            payload = self._payload(row)
            if row["claim_type"] == "bootstrap_owner":
                title = f"Set up the first {payload['team_name']} owner"
                needs_name = True
            elif row["claim_type"] == "join_team":
                team = db.execute("SELECT name FROM access_teams WHERE id=?", (payload["team_id"],)).fetchone()
                if team is None:
                    raise RuntimeFailure("ACCESS_CLAIM_INVALID")
                title = f"Join {team['name']}"
                needs_name = True
            else:
                principal = db.execute(
                    "SELECT display_name FROM access_principals WHERE id=?", (payload["principal_id"],)
                ).fetchone()
                if principal is None:
                    raise RuntimeFailure("ACCESS_CLAIM_INVALID")
                title = f"Link this browser to {principal['display_name']}"
                needs_name = False
        return ClaimPreview(
            row["id"], row["claim_type"], title, needs_name, row["expires_at"],
            payload.get("principal_id") if row["claim_type"] == "attach_client" else None,
        )

    @staticmethod
    def _new_principal(db: sqlite3.Connection, authority_id: str, display_name: str) -> str:
        principal_id = "principal-" + uuid.uuid4().hex
        now = utc_now()
        db.execute(
            "INSERT INTO access_principals VALUES (?, ?, ?, 'active', ?, ?)",
            (principal_id, authority_id, _display_name(display_name), now, now),
        )
        return principal_id

    @staticmethod
    def _new_membership(
        db: sqlite3.Connection, principal_id: str, team_id: str, kind: str, scope_id: str | None = None
    ) -> str:
        membership_id = "membership-" + uuid.uuid4().hex
        scope_id = scope_id or ("m-" + secrets.token_hex(16))
        now = utc_now()
        db.execute("INSERT OR IGNORE INTO scopes(id, created_at) VALUES (?, ?)", (scope_id, now))
        db.execute(
            "INSERT INTO access_memberships VALUES (?, ?, ?, ?, ?, 'active', ?, NULL)",
            (membership_id, principal_id, team_id, kind, scope_id, now),
        )
        return membership_id

    @classmethod
    def _ensure_personal_workspace(
        cls,
        db: sqlite3.Connection,
        principal_id: str,
        authority_id: str,
        *,
        scope_id: str | None = None,
    ) -> tuple[str, bool]:
        existing = db.execute(
            "SELECT membership_id FROM access_personal_workspaces WHERE principal_id=?",
            (principal_id,),
        ).fetchone()
        if existing is not None:
            return existing["membership_id"], False
        team_id = "personal-" + uuid.uuid4().hex
        membership_id = "membership-" + uuid.uuid4().hex
        scope_id = scope_id or ("p-" + secrets.token_hex(16))
        now = utc_now()
        db.execute("INSERT OR IGNORE INTO scopes(id, created_at) VALUES (?, ?)", (scope_id, now))
        db.execute(
            "INSERT INTO access_teams VALUES (?, ?, ?, 'active', ?, ?)",
            (team_id, authority_id, f"Personal {principal_id}", now, now),
        )
        db.execute(
            "INSERT INTO access_memberships VALUES (?, ?, ?, 'owner', ?, 'active', ?, NULL)",
            (membership_id, principal_id, team_id, scope_id, now),
        )
        db.execute(
            "INSERT INTO access_personal_workspaces VALUES (?, ?, ?, ?)",
            (principal_id, team_id, membership_id, now),
        )
        return membership_id, True

    @staticmethod
    def _personal_membership(db: sqlite3.Connection, principal_id: str) -> str:
        row = db.execute(
            "SELECT membership_id FROM access_personal_workspaces WHERE principal_id=?",
            (principal_id,),
        ).fetchone()
        if row is None:
            raise RuntimeFailure("ACCESS_PERSONAL_WORKSPACE_REQUIRED")
        return row["membership_id"]

    @staticmethod
    def _new_client(db: sqlite3.Connection, principal_id: str, membership_id: str, label: str) -> tuple[str, str]:
        credential = secrets.token_urlsafe(32)
        client_id = "client-" + uuid.uuid4().hex
        now = utc_now()
        db.execute(
            """INSERT INTO access_clients
               VALUES (?, ?, ?, ?, ?, ?, 'active', ?, ?, NULL)""",
            (
                client_id, principal_id, _digest(credential), secrets.token_urlsafe(24),
                (_display_name(label) if label else "Browser")[:100],
                AccessStore._personal_membership(db, principal_id), now, now,
            ),
        )
        return client_id, credential

    @staticmethod
    def _client_row(db: sqlite3.Connection, credential: str | None) -> sqlite3.Row | None:
        if not credential:
            return None
        return db.execute(
            "SELECT * FROM access_clients WHERE credential_digest=? AND status='active'", (_digest(credential),)
        ).fetchone()

    def redeem_claim(
        self,
        token: str,
        *,
        display_name: str | None = None,
        current_credential: str | None = None,
        client_label: str = "Browser",
    ) -> Redemption:
        created_principal = created_membership = created_client = created_personal = False
        credential: str | None = None
        with self.runtime.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            row = self._valid_claim(
                db.execute("SELECT * FROM access_claims WHERE token_digest=?", (_digest(token),)).fetchone()
            )
            payload = self._payload(row)
            current = self._client_row(db, current_credential)
            claim_type = row["claim_type"]
            if claim_type == "bootstrap_owner":
                if current is not None or db.execute("SELECT 1 FROM access_principals LIMIT 1").fetchone():
                    raise RuntimeFailure("ACCESS_BOOTSTRAP_DENIED")
                principal_id = self._new_principal(db, row["authority_id"], display_name or "")
                created_principal = True
                team_id = "team-" + uuid.uuid4().hex
                now = utc_now()
                db.execute(
                    "INSERT INTO access_teams VALUES (?, ?, ?, 'active', ?, ?)",
                    (team_id, row["authority_id"], payload["team_name"], now, now),
                )
                membership_id = self._new_membership(db, principal_id, team_id, "owner")
                created_membership = True
                personal_membership_id, created_personal = self._ensure_personal_workspace(
                    db,
                    principal_id,
                    row["authority_id"],
                    scope_id=payload["legacy_scope_id"],
                )
                client_id, credential = self._new_client(db, principal_id, membership_id, client_label)
                created_client = True
                membership_id = personal_membership_id
            elif claim_type == "join_team":
                team = db.execute(
                    "SELECT 1 FROM access_teams WHERE id=? AND status='active'", (payload.get("team_id"),)
                ).fetchone()
                if team is None or payload.get("membership_kind") != "member":
                    raise RuntimeFailure("ACCESS_CLAIM_INVALID")
                if current is None:
                    principal_id = self._new_principal(db, row["authority_id"], display_name or "")
                    created_principal = True
                    personal_membership_id, created_personal = self._ensure_personal_workspace(
                        db, principal_id, row["authority_id"]
                    )
                else:
                    principal_id = current["principal_id"]
                existing = db.execute(
                    "SELECT * FROM access_memberships WHERE principal_id=? AND team_id=?",
                    (principal_id, payload["team_id"]),
                ).fetchone()
                if existing is not None and existing["status"] != "active":
                    raise RuntimeFailure("ACCESS_MEMBERSHIP_REVOKED")
                if existing is None:
                    membership_id = self._new_membership(db, principal_id, payload["team_id"], "member")
                    created_membership = True
                else:
                    membership_id = existing["id"]
                if current is None:
                    client_id, credential = self._new_client(db, principal_id, membership_id, client_label)
                    created_client = True
                    membership_id = personal_membership_id
                else:
                    client_id = current["id"]
                    membership_id = current["active_membership_id"]
            elif claim_type == "attach_client":
                membership = db.execute(
                    """SELECT m.* FROM access_memberships m JOIN access_principals p ON p.id=m.principal_id
                       JOIN access_teams t ON t.id=m.team_id
                       WHERE m.id=? AND m.principal_id=? AND m.status='active'
                         AND p.status='active' AND t.status='active'""",
                    (payload.get("membership_id"), payload.get("principal_id")),
                ).fetchone()
                if membership is None:
                    raise RuntimeFailure("ACCESS_CLAIM_INVALID")
                principal_id = membership["principal_id"]
                membership_id = membership["id"]
                if current is not None and current["principal_id"] != principal_id:
                    raise RuntimeFailure("ACCESS_ATTACH_PRINCIPAL_MISMATCH")
                if current is None:
                    client_id, credential = self._new_client(db, principal_id, membership_id, client_label)
                    created_client = True
                    membership_id = self._personal_membership(db, principal_id)
                else:
                    client_id = current["id"]
            else:
                raise RuntimeFailure("ACCESS_CLAIM_INVALID")
            changed = db.execute(
                """UPDATE access_claims SET consumed_at=?, consumed_by_principal_id=?, consumed_by_client_id=?
                   WHERE id=? AND consumed_at IS NULL AND revoked_at IS NULL""",
                (utc_now(), principal_id, client_id, row["id"]),
            ).rowcount
            if changed != 1:
                raise RuntimeFailure("ACCESS_CLAIM_INVALID")
        actor = self.resolve_actor(client_id, membership_id)
        if self._membership_reconciler is not None and created_membership:
            if claim_type == "join_team":
                self._membership_reconciler(payload["team_id"])
            elif actor.workspace_kind == "team":
                self._membership_reconciler(actor.team_id)
        if created_personal and self._personal_workspace_reconciler is not None:
            personal_id = self._personal_membership_for_principal(principal_id)
            self._personal_workspace_reconciler(self.resolve_actor(client_id, personal_id))
        return Redemption(actor, credential, created_principal, created_membership, created_client)

    @staticmethod
    def _actor_query() -> str:
        return """SELECT a.id AS authority_id, p.id AS principal_id,
                         p.display_name AS principal_display_name, c.id AS client_id,
                         m.id AS membership_id, m.kind AS membership_kind,
                         t.id AS team_id,
                         CASE WHEN w.principal_id IS NULL THEN t.name ELSE 'Personal' END AS team_name,
                         m.execution_scope_id,
                         CASE WHEN w.principal_id IS NULL THEN 'team' ELSE 'personal' END AS workspace_kind
                  FROM access_clients c
                  JOIN access_principals p ON p.id=c.principal_id
                  JOIN access_memberships m ON m.id=? AND m.principal_id=p.id
                  JOIN access_teams t ON t.id=m.team_id
                  LEFT JOIN access_personal_workspaces w
                    ON w.membership_id=m.id AND w.principal_id=p.id
                  JOIN access_authorities a ON a.singleton=1 AND a.id=p.authority_id
                  WHERE c.id=? AND c.status='active' AND p.status='active'
                    AND m.status='active' AND t.status='active'"""

    def resolve_actor(self, client_id: str, membership_id: str | None = None) -> ActorContext:
        with self.runtime.connect() as db:
            client = db.execute("SELECT * FROM access_clients WHERE id=?", (client_id,)).fetchone()
            if client is None:
                raise RuntimeFailure("ACCESS_CLIENT_INVALID")
            selected = membership_id or client["active_membership_id"]
            row = db.execute(self._actor_query(), (selected, client_id)).fetchone()
        if row is None:
            raise RuntimeFailure("ACCESS_AUTHORITY_DENIED")
        return ActorContext(**dict(row))

    def _require_current_actor(self, actor: ActorContext) -> ActorContext:
        with self.runtime.connect() as db:
            client = db.execute(
                "SELECT active_membership_id FROM access_clients WHERE id=? AND status='active'",
                (actor.client_id,),
            ).fetchone()
        if client is None or client["active_membership_id"] != actor.membership_id:
            raise RuntimeFailure("ACCESS_ACTIVE_MEMBERSHIP_REQUIRED")
        return self.resolve_actor(actor.client_id, actor.membership_id)

    @contextmanager
    def guarded_actor(self, actor: ActorContext) -> Iterator[ActorContext]:
        """Linearize an operation with client/workspace revocation in this server."""
        with self._authority_lock:
            current = self._require_current_actor(actor)
            if (
                current.authority_id != actor.authority_id
                or current.principal_id != actor.principal_id
                or current.team_id != actor.team_id
                or current.execution_scope_id != actor.execution_scope_id
                or current.workspace_kind != actor.workspace_kind
            ):
                raise RuntimeFailure("ACCESS_AUTHORITY_DENIED")
            yield current

    @contextmanager
    def authority_transition_guard(self) -> Iterator[None]:
        """Serialize other authority transitions with guarded execution."""
        with self._authority_lock:
            yield

    def authenticate_client(self, credential: str) -> AuthenticatedClient:
        with self.runtime.connect() as db:
            row = db.execute(
                "SELECT * FROM access_clients WHERE credential_digest=? AND status='active'", (_digest(credential),)
            ).fetchone()
            if row is None:
                raise RuntimeFailure("ACCESS_CLIENT_INVALID")
            actor_row = db.execute(self._actor_query(), (row["active_membership_id"], row["id"])).fetchone()
            if actor_row is None:
                raise RuntimeFailure("ACCESS_AUTHORITY_DENIED")
            db.execute("UPDATE access_clients SET last_seen_at=? WHERE id=?", (utc_now(), row["id"]))
        return AuthenticatedClient(ActorContext(**dict(actor_row)), row["csrf_token"], row["label"])

    def activate_membership(self, actor: ActorContext, membership_id: str) -> ActorContext:
        with self._authority_lock:
            target = self.resolve_actor(actor.client_id, membership_id)
            with self.runtime.connect() as db:
                db.execute("UPDATE access_clients SET active_membership_id=? WHERE id=?", (membership_id, actor.client_id))
            return target

    def _personal_membership_for_principal(self, principal_id: str) -> str:
        with self.runtime.connect() as db:
            return self._personal_membership(db, principal_id)

    def workspaces(self, actor: ActorContext) -> list[ActorContext]:
        """Return Personal first, then every active team membership for this person."""
        current = self.resolve_actor(actor.client_id, actor.membership_id)
        with self.runtime.connect() as db:
            rows = db.execute(
                """SELECT m.id FROM access_memberships m
                   JOIN access_teams t ON t.id=m.team_id
                   LEFT JOIN access_personal_workspaces w ON w.membership_id=m.id
                   WHERE m.principal_id=? AND m.status='active' AND t.status='active'
                   ORDER BY CASE WHEN w.membership_id IS NULL THEN 1 ELSE 0 END,
                            CASE WHEN w.membership_id IS NULL THEN t.name ELSE '' END, m.id""",
                (current.principal_id,),
            ).fetchall()
        return [self.resolve_actor(current.client_id, row["id"]) for row in rows]

    def personal_workspace_actors(self) -> list[ActorContext]:
        with self.runtime.connect() as db:
            rows = db.execute(
                """SELECT w.membership_id, MIN(c.id) AS client_id
                   FROM access_personal_workspaces w
                   JOIN access_clients c ON c.principal_id=w.principal_id AND c.status='active'
                   GROUP BY w.membership_id ORDER BY w.principal_id"""
            ).fetchall()
        return [self.resolve_actor(row["client_id"], row["membership_id"]) for row in rows]

    def revoke_claim(self, actor: ActorContext, claim_id: str) -> None:
        actor = self.resolve_actor(actor.client_id, actor.membership_id)
        with self.runtime.connect() as db:
            changed = db.execute(
                """UPDATE access_claims SET revoked_at=? WHERE id=? AND issued_by_principal_id=?
                   AND consumed_at IS NULL AND revoked_at IS NULL""",
                (utc_now(), claim_id, actor.principal_id),
            ).rowcount
        if changed != 1:
            raise RuntimeFailure("ACCESS_CLAIM_REVOKE_DENIED")

    def revoke_client(self, actor: ActorContext, client_id: str) -> None:
        with self._authority_lock:
            actor = self.resolve_actor(actor.client_id, actor.membership_id)
            with self.runtime.connect() as db:
                changed = db.execute(
                    """UPDATE access_clients SET status='revoked', revoked_at=?
                       WHERE id=? AND principal_id=? AND status='active'""",
                    (utc_now(), client_id, actor.principal_id),
                ).rowcount
            if changed != 1:
                raise RuntimeFailure("ACCESS_CLIENT_REVOKE_DENIED")

    def revoke_membership(self, actor: ActorContext, membership_id: str) -> None:
        with self._authority_lock:
            actor = self.resolve_actor(actor.client_id, actor.membership_id)
            with self.runtime.connect() as db:
                target = db.execute("SELECT * FROM access_memberships WHERE id=?", (membership_id,)).fetchone()
                personal = db.execute(
                    "SELECT 1 FROM access_personal_workspaces WHERE membership_id=?", (membership_id,)
                ).fetchone()
                if (
                    personal is not None
                    or actor.workspace_kind != "team"
                    or target is None
                    or target["team_id"] != actor.team_id
                    or actor.membership_kind != "owner"
                ):
                    raise RuntimeFailure("ACCESS_MEMBERSHIP_REVOKE_DENIED")
                if target["kind"] == "owner":
                    owners = db.execute(
                        "SELECT COUNT(*) FROM access_memberships WHERE team_id=? AND kind='owner' AND status='active'",
                        (target["team_id"],),
                    ).fetchone()[0]
                    if owners <= 1:
                        raise RuntimeFailure("ACCESS_LAST_OWNER")
                changed = db.execute(
                    "UPDATE access_memberships SET status='revoked', revoked_at=? WHERE id=? AND status='active'",
                    (utc_now(), membership_id),
                ).rowcount
                personal_membership = self._personal_membership(db, target["principal_id"])
                db.execute(
                    "UPDATE access_clients SET active_membership_id=? WHERE active_membership_id=? AND status='active'",
                    (personal_membership, membership_id),
                )
            if changed != 1:
                raise RuntimeFailure("ACCESS_MEMBERSHIP_REVOKE_DENIED")
            if self._membership_reconciler is not None:
                self._membership_reconciler(actor.team_id)

    def overview(self, actor: ActorContext) -> dict[str, Any]:
        actor = self.resolve_actor(actor.client_id, actor.membership_id)
        with self.runtime.connect() as db:
            memberships = [dict(row) for row in db.execute(
                """SELECT m.id, m.kind, m.status, m.execution_scope_id, t.id AS team_id,
                          CASE WHEN w.principal_id IS NULL THEN t.name ELSE 'Personal' END AS team_name,
                          CASE WHEN w.principal_id IS NULL THEN 'team' ELSE 'personal' END AS workspace_kind
                   FROM access_memberships m JOIN access_teams t ON t.id=m.team_id
                   LEFT JOIN access_personal_workspaces w ON w.membership_id=m.id
                   WHERE m.principal_id=? ORDER BY m.joined_at, m.id""", (actor.principal_id,)
            )]
            clients = [dict(row) for row in db.execute(
                "SELECT id, label, status, created_at, last_seen_at FROM access_clients WHERE principal_id=? ORDER BY created_at, id",
                (actor.principal_id,),
            )]
            members = [dict(row) for row in db.execute(
                """SELECT m.id, m.kind, m.status, p.display_name FROM access_memberships m
                   JOIN access_principals p ON p.id=m.principal_id WHERE m.team_id=? ORDER BY m.joined_at, m.id""",
                (actor.team_id,),
            )]
            claims = [dict(row) for row in db.execute(
                """SELECT id, claim_type, expires_at, consumed_at, revoked_at FROM access_claims
                   WHERE issued_by_principal_id=? ORDER BY created_at DESC""", (actor.principal_id,),
            )]
        return {"actor": actor, "memberships": memberships, "clients": clients, "members": members, "claims": claims}

    def counts(self) -> dict[str, int]:
        with self.runtime.connect() as db:
            return {
                name: db.execute(f"SELECT COUNT(*) FROM access_{name}").fetchone()[0]
                for name in ("authorities", "principals", "teams", "memberships", "clients", "claims")
            }
