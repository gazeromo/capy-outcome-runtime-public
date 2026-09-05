"""Team-shared software control derived from canonical Capy Access authority."""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from typing import Any

from .access import AccessStore, ActorContext
from .model import RuntimeFailure
from .store import RuntimeStore, canonical_json, sha256, utc_now


@dataclass(frozen=True)
class TeamSoftwareShare:
    team_id: str
    capability_id: str
    version_digest: str
    shared_by_principal_id: str
    maintained_by_principal_id: str
    status: str


@dataclass(frozen=True)
class TeamSoftwareProjection:
    capability_id: str
    version_digest: str
    source: str
    shared_by: str
    maintained_by: str
    available_to_members: int


@dataclass(frozen=True)
class ReconciliationResult:
    team_id: str
    bindings_added: int
    bindings_removed: int

    @property
    def changes(self) -> int:
        return self.bindings_added + self.bindings_removed


class TeamSoftwareStore:
    """Own only software shares and their derived per-membership bindings."""

    def __init__(self, runtime: RuntimeStore, access: AccessStore):
        self.runtime = runtime
        self.access = access
        self._initialize()

    def _initialize(self) -> None:
        with self.runtime.connect() as db:
            db.executescript(
                """
                CREATE TABLE IF NOT EXISTS team_software (
                    team_id TEXT NOT NULL REFERENCES access_teams(id),
                    capability_id TEXT NOT NULL,
                    version_digest TEXT NOT NULL,
                    shared_by_principal_id TEXT NOT NULL REFERENCES access_principals(id),
                    maintained_by_principal_id TEXT NOT NULL REFERENCES access_principals(id),
                    status TEXT NOT NULL CHECK(status IN ('active','revoked')),
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    PRIMARY KEY(team_id, capability_id),
                    FOREIGN KEY(capability_id, version_digest)
                        REFERENCES capability_versions(capability_id, version_digest)
                );
                CREATE TABLE IF NOT EXISTS team_binding_receipts (
                    id TEXT PRIMARY KEY,
                    membership_id TEXT NOT NULL REFERENCES access_memberships(id),
                    capability_id TEXT NOT NULL,
                    version_digest TEXT NOT NULL,
                    runtime_scope_id TEXT NOT NULL REFERENCES scopes(id),
                    operation TEXT NOT NULL CHECK(operation IN ('bind','unbind')),
                    binding_receipt_json TEXT NOT NULL,
                    receipt_digest TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    UNIQUE(membership_id, capability_id, version_digest, operation)
                );
                CREATE INDEX IF NOT EXISTS team_software_status
                    ON team_software(team_id, status, capability_id);
                """
            )

    def _current_actor(self, actor: ActorContext) -> ActorContext:
        current = self.access.resolve_actor(actor.client_id, actor.membership_id)
        if current != actor:
            raise RuntimeFailure("ACTOR_CONTEXT_STALE")
        return current

    def _require_owner(self, actor: ActorContext) -> ActorContext:
        actor = self._current_actor(actor)
        if actor.membership_kind != "owner":
            raise RuntimeFailure("TEAM_SOFTWARE_OWNER_REQUIRED")
        return actor

    def share_software(
        self,
        actor: ActorContext,
        capability_id: str,
        version_digest: str,
        *,
        maintained_by_principal_id: str | None = None,
    ) -> TeamSoftwareShare:
        with self.access.authority_transition_guard():
            return self._share_software(
                actor, capability_id, version_digest,
                maintained_by_principal_id=maintained_by_principal_id,
            )

    def _share_software(
        self,
        actor: ActorContext,
        capability_id: str,
        version_digest: str,
        *,
        maintained_by_principal_id: str | None = None,
    ) -> TeamSoftwareShare:
        actor = self._require_owner(actor)
        maintained_by = maintained_by_principal_id or actor.principal_id
        descriptor = self.runtime.descriptor(capability_id, version_digest)
        publication = self.runtime.execution_release(capability_id, version_digest)
        if descriptor.id != capability_id or publication["version_digest"] != version_digest:
            raise RuntimeFailure("TEAM_SOFTWARE_IDENTITY_INVALID")
        now = utc_now()
        with self.runtime.connect() as db:
            maintainer = db.execute(
                """SELECT 1 FROM access_memberships
                   WHERE team_id=? AND principal_id=? AND status='active'""",
                (actor.team_id, maintained_by),
            ).fetchone()
            if maintainer is None:
                raise RuntimeFailure("TEAM_SOFTWARE_MAINTAINER_INVALID")
            existing = db.execute(
                "SELECT * FROM team_software WHERE team_id=? AND capability_id=?",
                (actor.team_id, capability_id),
            ).fetchone()
            if existing is not None and (
                existing["version_digest"] != version_digest
                or existing["shared_by_principal_id"] != actor.principal_id
                or existing["maintained_by_principal_id"] != maintained_by
            ):
                raise RuntimeFailure("TEAM_SOFTWARE_SHARE_CONFLICT")
            db.execute(
                """INSERT INTO team_software
                   VALUES (?, ?, ?, ?, ?, 'active', ?, ?)
                   ON CONFLICT(team_id, capability_id)
                   DO UPDATE SET status='active', updated_at=excluded.updated_at""",
                (
                    actor.team_id, capability_id, version_digest, actor.principal_id,
                    maintained_by, now, now,
                ),
            )
        self.reconcile_team(actor.team_id)
        return self.share(actor, capability_id)

    def revoke_software(self, actor: ActorContext, capability_id: str) -> None:
        with self.access.authority_transition_guard():
            self._revoke_software(actor, capability_id)

    def _revoke_software(self, actor: ActorContext, capability_id: str) -> None:
        actor = self._require_owner(actor)
        with self.runtime.connect() as db:
            changed = db.execute(
                """UPDATE team_software SET status='revoked', updated_at=?
                   WHERE team_id=? AND capability_id=? AND status='active'""",
                (utc_now(), actor.team_id, capability_id),
            ).rowcount
        if changed != 1:
            raise RuntimeFailure("TEAM_SOFTWARE_UNKNOWN")
        self.reconcile_team(actor.team_id)

    def reconcile_all(self) -> ReconciliationResult:
        with self.runtime.connect() as db:
            team_ids = [row["id"] for row in db.execute(
                "SELECT id FROM access_teams ORDER BY id"
            ).fetchall()]
        added = removed = 0
        for team_id in team_ids:
            result = self.reconcile_team(team_id)
            added += result.bindings_added
            removed += result.bindings_removed
        return ReconciliationResult("*", added, removed)

    def reconcile_team(self, team_id: str) -> ReconciliationResult:
        with self.runtime.connect() as db:
            team = db.execute("SELECT status FROM access_teams WHERE id=?", (team_id,)).fetchone()
            if team is None:
                raise RuntimeFailure("TEAM_SOFTWARE_TEAM_UNKNOWN")
            memberships = db.execute(
                "SELECT * FROM access_memberships WHERE team_id=? ORDER BY joined_at, id",
                (team_id,),
            ).fetchall()
            software = db.execute(
                "SELECT * FROM team_software WHERE team_id=? ORDER BY capability_id",
                (team_id,),
            ).fetchall()
        added = removed = 0
        for membership in memberships:
            for shared in software:
                scope_id = membership["execution_scope_id"]
                capability_id = shared["capability_id"]
                version = shared["version_digest"]
                current = self.runtime.binding_or_none(scope_id, capability_id)
                desired = (
                    team["status"] == "active"
                    and membership["status"] == "active"
                    and shared["status"] == "active"
                )
                if desired:
                    if current is not None and (
                        current.version_digest != version or current.connections != {}
                    ):
                        raise RuntimeFailure("TEAM_BINDING_VERSION_CONFLICT")
                    if current is None:
                        self.runtime.bind(scope_id, capability_id, version, {})
                        added += 1
                    self._record_binding_receipt(membership, shared, "bind")
                elif current is not None:
                    if current.version_digest != version or current.connections != {}:
                        raise RuntimeFailure("TEAM_BINDING_VERSION_CONFLICT")
                    self.runtime.unbind(scope_id, capability_id)
                    self._record_binding_receipt(membership, shared, "unbind")
                    removed += 1
        return ReconciliationResult(team_id, added, removed)

    def _record_binding_receipt(self, membership: Any, software: Any, operation: str) -> None:
        publication = self.runtime.execution_release(
            software["capability_id"], software["version_digest"]
        )
        receipt = {
            "schema": "capy.team-binding-receipt/v0",
            "team_id": software["team_id"],
            "membership_id": membership["id"],
            "principal_id": membership["principal_id"],
            "runtime_scope_id": membership["execution_scope_id"],
            "capability_id": software["capability_id"],
            "version_digest": software["version_digest"],
            "application_archive_digest": publication["archive_digest"],
            "devkit_environment_digest": publication["environment_digest"],
            "operation": operation,
        }
        encoded = canonical_json(receipt)
        with self.runtime.connect() as db:
            db.execute(
                """INSERT OR IGNORE INTO team_binding_receipts
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    uuid.uuid4().hex, membership["id"], software["capability_id"],
                    software["version_digest"], membership["execution_scope_id"],
                    operation, encoded.decode(), sha256(encoded), utc_now(),
                ),
            )

    def share(self, actor: ActorContext, capability_id: str) -> TeamSoftwareShare:
        actor = self._current_actor(actor)
        with self.runtime.connect() as db:
            row = db.execute(
                """SELECT team_id, capability_id, version_digest,
                          shared_by_principal_id, maintained_by_principal_id, status
                   FROM team_software WHERE team_id=? AND capability_id=? AND status='active'""",
                (actor.team_id, capability_id),
            ).fetchone()
        if row is None:
            raise RuntimeFailure("TEAM_SOFTWARE_UNKNOWN")
        return TeamSoftwareShare(**dict(row))

    def software_for_actor(self, actor: ActorContext) -> list[TeamSoftwareProjection]:
        actor = self._current_actor(actor)
        with self.runtime.connect() as db:
            rows = db.execute(
                """SELECT s.capability_id, s.version_digest,
                          sharer.display_name AS shared_by,
                          maintainer.display_name AS maintained_by,
                          (SELECT COUNT(*) FROM access_memberships m
                           WHERE m.team_id=s.team_id AND m.status='active') AS available_to_members
                   FROM team_software s
                   JOIN access_principals sharer ON sharer.id=s.shared_by_principal_id
                   JOIN access_principals maintainer ON maintainer.id=s.maintained_by_principal_id
                   WHERE s.team_id=? AND s.status='active' ORDER BY s.capability_id""",
                (actor.team_id,),
            ).fetchall()
        projections = []
        for row in rows:
            binding = self.runtime.binding_or_none(actor.execution_scope_id, row["capability_id"])
            if binding is None or binding.version_digest != row["version_digest"]:
                raise RuntimeFailure("TEAM_BINDING_MISSING")
            projections.append(TeamSoftwareProjection(
                capability_id=row["capability_id"], version_digest=row["version_digest"],
                source="team", shared_by=row["shared_by"], maintained_by=row["maintained_by"],
                available_to_members=row["available_to_members"],
            ))
        return projections

    def counts(self, team_id: str) -> dict[str, int]:
        with self.runtime.connect() as db:
            return {
                "team_software": db.execute(
                    "SELECT COUNT(*) FROM team_software WHERE team_id=? AND status='active'",
                    (team_id,),
                ).fetchone()[0],
                "binding_receipts": db.execute(
                    """SELECT COUNT(*) FROM team_binding_receipts r
                       JOIN access_memberships m ON m.id=r.membership_id
                       WHERE m.team_id=? AND r.operation='bind'""",
                    (team_id,),
                ).fetchone()[0],
            }
