"""Publisher-owned connection control, local secret custody, and broker protocol."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import secrets
import socket
import stat
import tempfile
import threading
import time
import urllib.parse
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any, BinaryIO, Callable, Protocol

from .model import RuntimeFailure
from .store import RuntimeStore, canonical_json, sha256, utc_now


SAFE_ID = re.compile(r"[a-z0-9][a-z0-9._:-]{0,127}")
MAX_CALL_BYTES = 256 * 1024
MAX_RESULT_BYTES = 4 * 1024 * 1024
GRANT_TTL_SECONDS = 120
BROKER_OPERATION_POLICY = {"fedex.rates/v1": frozenset({"quote"}), "fedex.rates/v2": frozenset({"quote"})}


class SecretResolver(Protocol):
    def resolve(self, reference: str) -> dict[str, Any]: ...


class LocalSecretResolver:
    """Root-owned regular JSON files addressed by opaque secret references."""

    def __init__(self, root: Path, *, expected_owner_uid: int = 0):
        self.root = Path(os.path.abspath(root))
        self.expected_owner_uid = expected_owner_uid

    def _validate_root(self, *, create: bool = False) -> None:
        if create:
            self.root.mkdir(parents=True, exist_ok=True, mode=0o700)
        try:
            metadata = self.root.lstat()
        except OSError as exc:
            raise RuntimeFailure("CONNECTION_UNAVAILABLE") from exc
        if (
            self.root.is_symlink()
            or not stat.S_ISDIR(metadata.st_mode)
            or metadata.st_uid != self.expected_owner_uid
        ):
            raise RuntimeFailure("CONNECTION_UNAVAILABLE")
        if create:
            self.root.chmod(0o700)
        elif stat.S_IMODE(metadata.st_mode) != 0o700:
            raise RuntimeFailure("CONNECTION_UNAVAILABLE")

    def _path(self, reference: str) -> Path:
        if not reference.startswith("secret:") or SAFE_ID.fullmatch(reference) is None:
            raise RuntimeFailure("CONNECTION_UNAVAILABLE")
        return self.root / (reference.removeprefix("secret:") + ".json")

    def install(self, reference: str, source: BinaryIO) -> dict[str, Any]:
        self._validate_root(create=True)
        payload = source.read(MAX_CALL_BYTES + 1)
        if len(payload) > MAX_CALL_BYTES:
            raise RuntimeFailure("CONNECTION_SECRET_INVALID")
        try:
            value = json.loads(payload)
            encoded = canonical_json(value)
        except (TypeError, ValueError, json.JSONDecodeError) as exc:
            raise RuntimeFailure("CONNECTION_SECRET_INVALID") from exc
        if not isinstance(value, dict):
            raise RuntimeFailure("CONNECTION_SECRET_INVALID")
        destination = self._path(reference)
        descriptor, temporary = tempfile.mkstemp(prefix=".connection-", dir=self.root)
        try:
            os.fchmod(descriptor, 0o600)
            with os.fdopen(descriptor, "wb", closefd=True) as handle:
                handle.write(encoded)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, destination)
            destination.chmod(0o600)
            directory = os.open(self.root, os.O_RDONLY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
        finally:
            Path(temporary).unlink(missing_ok=True)
        return {"secret_reference": reference, "status": "installed"}

    def healthy(self, reference: str) -> bool:
        try:
            self._validate_root()
            path = self._path(reference)
            metadata = path.lstat()
            if (
                not stat.S_ISREG(metadata.st_mode)
                or stat.S_IMODE(metadata.st_mode) != 0o600
                or path.is_symlink()
                or metadata.st_uid != self.expected_owner_uid
            ):
                return False
            return True
        except (RuntimeFailure, OSError):
            return False

    def resolve(self, reference: str) -> dict[str, Any]:
        self._validate_root()
        path = self._path(reference)
        try:
            metadata = path.lstat()
            if (
                not stat.S_ISREG(metadata.st_mode)
                or stat.S_IMODE(metadata.st_mode) != 0o600
                or path.is_symlink()
                or metadata.st_uid != self.expected_owner_uid
            ):
                raise RuntimeFailure("CONNECTION_UNAVAILABLE")
            payload = path.read_bytes()
            value = json.loads(payload)
        except RuntimeFailure:
            raise
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            raise RuntimeFailure("CONNECTION_UNAVAILABLE") from exc
        if not isinstance(value, dict):
            raise RuntimeFailure("CONNECTION_UNAVAILABLE")
        return value


@dataclass(frozen=True)
class ConnectionInstance:
    id: str
    contract: str
    adapter_version: str
    owner_class: str
    publisher_id: str
    status: str
    display: dict[str, Any]
    secret_reference: str
    profile_reference: str


class ConnectionControl:
    """Durable non-secret connection authority inside the runtime database."""

    def __init__(self, store: RuntimeStore):
        self.store = store
        with store.connect() as db:
            db.executescript(
                """
                CREATE TABLE IF NOT EXISTS connection_instances (
                    id TEXT PRIMARY KEY, contract TEXT NOT NULL, adapter_version TEXT NOT NULL,
                    owner_class TEXT NOT NULL, publisher_id TEXT NOT NULL, status TEXT NOT NULL,
                    display_json TEXT NOT NULL, secret_reference TEXT NOT NULL,
                    profile_reference TEXT NOT NULL, created_at TEXT NOT NULL, updated_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS connection_grants (
                    id TEXT PRIMARY KEY, connection_id TEXT NOT NULL REFERENCES connection_instances(id),
                    scope_id TEXT NOT NULL REFERENCES scopes(id), contract TEXT NOT NULL,
                    operations_json TEXT NOT NULL, capability_id TEXT, version_digest TEXT,
                    status TEXT NOT NULL, created_at TEXT NOT NULL, updated_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS invocation_connection_grants (
                    token_digest TEXT PRIMARY KEY, invocation_id TEXT NOT NULL, grant_id TEXT NOT NULL,
                    connection_name TEXT NOT NULL, expected_uid INTEGER, expires_at REAL NOT NULL,
                    used_at TEXT, created_at TEXT NOT NULL, capability_id TEXT,
                    version_digest TEXT, contract TEXT, operations_json TEXT
                );
                CREATE TABLE IF NOT EXISTS application_connection_approvals (
                    workspace_id TEXT NOT NULL, capability_id TEXT NOT NULL,
                    version_digest TEXT NOT NULL, approval_json TEXT NOT NULL,
                    PRIMARY KEY(workspace_id, capability_id, version_digest)
                );
                CREATE TABLE IF NOT EXISTS derived_connection_grants (
                    grant_id TEXT PRIMARY KEY, authority_json TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS connection_receipts (
                    id TEXT PRIMARY KEY, invocation_id TEXT NOT NULL, receipt_json TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );
                """
            )
            columns = {row["name"] for row in db.execute("PRAGMA table_info(invocation_connection_grants)")}
            for name in ("capability_id", "version_digest", "contract", "operations_json", "scope_id", "connection_id"):
                if name not in columns:
                    db.execute(f"ALTER TABLE invocation_connection_grants ADD COLUMN {name} TEXT")

    def put_instance(self, instance: ConnectionInstance) -> None:
        if (
            SAFE_ID.fullmatch(instance.id) is None
            or instance.owner_class != "publisher"
            or instance.status not in {"active", "disabled"}
            or not instance.contract
            or instance.contract not in BROKER_OPERATION_POLICY
            or not instance.adapter_version
            or not instance.publisher_id
        ):
            raise RuntimeFailure("CONNECTION_INSTANCE_INVALID")
        now = utc_now()
        with self.store.connect() as db:
            db.execute(
                """INSERT INTO connection_instances VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                   ON CONFLICT(id) DO UPDATE SET contract=excluded.contract,
                   adapter_version=excluded.adapter_version, owner_class=excluded.owner_class,
                   publisher_id=excluded.publisher_id, status=excluded.status,
                   display_json=excluded.display_json, secret_reference=excluded.secret_reference,
                   profile_reference=excluded.profile_reference, updated_at=excluded.updated_at""",
                (
                    instance.id, instance.contract, instance.adapter_version, instance.owner_class,
                    instance.publisher_id, instance.status,
                    canonical_json(instance.display).decode(), instance.secret_reference,
                    instance.profile_reference, now, now,
                ),
            )

    def grant(
        self,
        grant_id: str,
        connection_id: str,
        scope_id: str,
        contract: str,
        operations: list[str],
        *,
        capability_id: str | None = None,
        version_digest: str | None = None,
    ) -> None:
        if (
            SAFE_ID.fullmatch(grant_id) is None
            or not operations
            or len(operations) != len(set(operations))
            or not all(isinstance(item, str) and item for item in operations)
            or contract not in BROKER_OPERATION_POLICY
            or not set(operations) <= BROKER_OPERATION_POLICY[contract]
        ):
            raise RuntimeFailure("CONNECTION_GRANT_INVALID")
        now = utc_now()
        with self.store.connect() as db:
            instance = db.execute(
                "SELECT contract FROM connection_instances WHERE id=? AND status='active'", (connection_id,)
            ).fetchone()
            if instance is None or instance["contract"] != contract:
                raise RuntimeFailure("CONNECTION_GRANT_INVALID")
            if db.execute("SELECT 1 FROM scopes WHERE id=?", (scope_id,)).fetchone() is None:
                raise RuntimeFailure("SCOPE_UNKNOWN")
            db.execute(
                """INSERT INTO connection_grants VALUES (?, ?, ?, ?, ?, ?, ?, 'active', ?, ?)
                   ON CONFLICT(id) DO UPDATE SET connection_id=excluded.connection_id,
                   scope_id=excluded.scope_id, contract=excluded.contract,
                   operations_json=excluded.operations_json, capability_id=excluded.capability_id,
                   version_digest=excluded.version_digest, status='active', updated_at=excluded.updated_at""",
                (grant_id, connection_id, scope_id, contract, canonical_json(operations).decode(), capability_id, version_digest, now, now),
            )

    def configure_application(self, workspace_id: str, capability_id: str,
                              version_digest: str, *, source_scope_id: str,
                              connections: dict[str, str]) -> None:
        """Trusted configuration only: approve exact existing grants, never labels.

        The source must belong to a current owner of this workspace. This API
        conveys no authority to application code or model-provided fields.
        """
        with self.store.transaction() as db:
            self._owner_scope(db, workspace_id, source_scope_id)
            if (not connections or not all(isinstance(k, str) and isinstance(v, str)
                                          for k, v in connections.items())):
                raise RuntimeFailure("CONNECTION_GRANT_INVALID")
            sources = {}
            for name, grant_id in connections.items():
                if db.execute("SELECT 1 FROM derived_connection_grants WHERE grant_id=?", (grant_id,)).fetchone():
                    raise RuntimeFailure("CONNECTION_OPERATION_DENIED")
                grant = self.resolve_grant(grant_id, scope_id=source_scope_id,
                                          capability_id=capability_id, version_digest=version_digest)
                sources[name] = {"grant_id": grant_id, "fingerprint": self._source_fingerprint(grant)}
            approval = dict(source_scope_id=source_scope_id, sources=sources)
            db.execute("INSERT INTO application_connection_approvals VALUES (?,?,?,?) "
                       "ON CONFLICT(workspace_id,capability_id,version_digest) DO UPDATE SET approval_json=excluded.approval_json",
                       (workspace_id, capability_id, version_digest, canonical_json(approval).decode()))

    def application_status(self, workspace_id: str, descriptor, version_digest: str) -> dict[str, Any]:
        """Non-secret setup projection; no grant IDs, profiles or custody paths."""
        requirements = [{"name": item.name, "contract": item.contract,
                         "operations": list(item.operations)}
                        for item in descriptor.connection_requirements]
        status = "configured" if not descriptor.connections else "setup_required"
        with self.store.connect() as db:
            row = db.execute("SELECT approval_json FROM application_connection_approvals WHERE workspace_id=? AND capability_id=? AND version_digest=?",
                             (workspace_id, descriptor.id, version_digest)).fetchone()
        if row is not None:
            approval = json.loads(row[0])
            try:
                with self.store.connect() as db:
                    self._owner_scope(db, workspace_id, approval["source_scope_id"])
                if set(approval["sources"]) != set(descriptor.connections):
                    raise RuntimeFailure("CONNECTION_OPERATION_DENIED")
                for item in descriptor.connection_requirements:
                    source = approval["sources"][item.name]
                    grant = self.resolve_grant(source["grant_id"], scope_id=approval["source_scope_id"],
                        capability_id=descriptor.id, version_digest=version_digest, contract=item.contract)
                    if (self._source_fingerprint(grant) != source["fingerprint"]
                            or not set(item.operations) <= set(grant["operations"])):
                        raise RuntimeFailure("CONNECTION_OPERATION_DENIED")
                status = "configured"
            except RuntimeFailure:
                status = "setup_required"
        return {"status": status, "requirements": requirements}

    @staticmethod
    def _owner_scope(db, workspace_id, source_scope_id):
        if db.execute("""SELECT 1 FROM access_memberships m JOIN access_teams t ON t.id=m.team_id
                         WHERE m.team_id=? AND m.execution_scope_id=? AND m.kind='owner'
                         AND m.status='active' AND t.status='active'""",
                      (workspace_id, source_scope_id)).fetchone() is None:
            raise RuntimeFailure("CONNECTION_OPERATION_DENIED")

    @staticmethod
    def _source_fingerprint(grant):
        return sha256(canonical_json({key: grant[key] for key in (
            "id", "connection_id", "scope_id", "contract", "operations_json",
            "capability_id", "version_digest", "updated_at")}))

    def application_bindings(self, descriptor, version_digest: str, *,
                             workspace_id: str, scope_id: str, membership_id: str,
                             preview_id: str | None = None) -> dict[str, str]:
        """Derive exact per-scope grants from persisted trusted configuration.

        All custody stays in this control store, including for isolated previews.
        Authority is checked again at invocation issue and broker consumption.
        """
        if not descriptor.connections:
            return {}
        if (descriptor.side_effect not in {"read_only", "artifact_generation"} or descriptor.state_required
                or set(descriptor.connections) != {r.name for r in descriptor.connection_requirements}):
            raise RuntimeFailure("CONNECTION_OPERATION_DENIED")
        with self.store.transaction() as db:
            row = db.execute("SELECT approval_json FROM application_connection_approvals "
                             "WHERE workspace_id=? AND capability_id=? AND version_digest=?",
                             (workspace_id, descriptor.id, version_digest)).fetchone()
            if row is None:
                raise RuntimeFailure("APPLICATION_CONNECTION_SETUP_REQUIRED")
            approval = json.loads(row[0])
            if set(approval["sources"]) != set(descriptor.connections):
                raise RuntimeFailure("APPLICATION_CONNECTION_SETUP_REQUIRED")
            self._owner_scope(db, workspace_id, approval["source_scope_id"])
            member = db.execute("SELECT * FROM access_memberships WHERE id=? AND team_id=? AND status='active'",
                                (membership_id, workspace_id)).fetchone()
            if member is None or (preview_id is None and member["execution_scope_id"] != scope_id):
                raise RuntimeFailure("CONNECTION_OPERATION_DENIED")
            if preview_id is not None and scope_id != 'preview_' + preview_id.removeprefix('prv_'):
                raise RuntimeFailure("CONNECTION_OPERATION_DENIED")
            self.store.register_scope(scope_id)
            bindings = {}
            for requirement in descriptor.connection_requirements:
                source = approval["sources"][requirement.name]
                grant = self.resolve_grant(source["grant_id"], scope_id=approval["source_scope_id"],
                    capability_id=descriptor.id, version_digest=version_digest, contract=requirement.contract)
                if (self._source_fingerprint(grant) != source["fingerprint"]
                        or not set(requirement.operations) <= set(grant["operations"])):
                    raise RuntimeFailure("CONNECTION_OPERATION_DENIED")
                authority = dict(workspace_id=workspace_id, capability_id=descriptor.id,
                                 version_digest=version_digest, scope_id=scope_id,
                                 membership_id=membership_id, preview_id=preview_id,
                                 approval=approval, connection_name=requirement.name)
                grant_id = 'derived-' + sha256(canonical_json(authority))
                self.grant(grant_id, grant["connection_id"], scope_id, requirement.contract,
                           list(requirement.operations), capability_id=descriptor.id, version_digest=version_digest)
                db.execute("INSERT OR REPLACE INTO derived_connection_grants VALUES (?,?)",
                           (grant_id, canonical_json(authority).decode()))
                bindings[requirement.name] = grant_id
            return bindings

    def check_application_binding_identity(self, bindings, descriptor, version_digest, *,
                                           workspace_id, scope_id, membership_id):
        """Check canonical projection identity without requiring provider availability."""
        if set(bindings) != set(descriptor.connections):
            raise RuntimeFailure("TEAM_BINDING_VERSION_CONFLICT")
        with self.store.connect() as db:
            for name, grant_id in bindings.items():
                row = db.execute("SELECT authority_json FROM derived_connection_grants WHERE grant_id=?", (grant_id,)).fetchone()
                if row is None:
                    raise RuntimeFailure("TEAM_BINDING_VERSION_CONFLICT")
                authority = json.loads(row[0])
                expected = dict(workspace_id=workspace_id, scope_id=scope_id, membership_id=membership_id,
                                capability_id=descriptor.id, version_digest=version_digest,
                                connection_name=name, preview_id=None)
                if any(authority.get(key) != value for key, value in expected.items()):
                    raise RuntimeFailure("TEAM_BINDING_VERSION_CONFLICT")

    def revoke_bindings(self, bindings: dict[str, str]) -> None:
        with self.store.connect() as db:
            for grant_id in bindings.values():
                db.execute("UPDATE invocation_connection_grants SET used_at=? WHERE grant_id=? AND used_at IS NULL",
                           (utc_now(), grant_id))
                db.execute("UPDATE connection_grants SET status='revoked',updated_at=? WHERE id=? "
                           "AND id IN (SELECT grant_id FROM derived_connection_grants)", (utc_now(), grant_id))

    def _validate_derived(self, grant) -> None:
        with self.store.connect() as db:
            row = db.execute("SELECT authority_json FROM derived_connection_grants WHERE grant_id=?", (grant["id"],)).fetchone()
            if row is None:
                return
            authority = json.loads(row[0])
            if any(grant[key] != authority[key] for key in ("scope_id", "capability_id", "version_digest")):
                raise RuntimeFailure("CONNECTION_OPERATION_DENIED")
            approval = authority["approval"]
            current = db.execute("SELECT approval_json FROM application_connection_approvals WHERE workspace_id=? AND capability_id=? AND version_digest=?",
                (authority["workspace_id"], authority["capability_id"], authority["version_digest"])).fetchone()
            if current is None or json.loads(current[0]) != approval:
                raise RuntimeFailure("CONNECTION_OPERATION_DENIED")
            self._owner_scope(db, authority["workspace_id"], approval["source_scope_id"])
            member = db.execute("SELECT * FROM access_memberships WHERE id=? AND team_id=? AND status='active'",
                (authority["membership_id"], authority["workspace_id"])).fetchone()
            if member is None:
                raise RuntimeFailure("CONNECTION_OPERATION_DENIED")
            if authority["preview_id"]:
                preview = db.execute("SELECT status,expires_at FROM release_previews WHERE id=?", (authority["preview_id"],)).fetchone()
                if preview is None or preview["status"] != 'ACTIVE' or preview["expires_at"] <= time.time():
                    raise RuntimeFailure("CONNECTION_OPERATION_DENIED")
            else:
                if member["execution_scope_id"] != grant["scope_id"]:
                    raise RuntimeFailure("CONNECTION_OPERATION_DENIED")
                binding = self.store.binding_or_none(grant["scope_id"], authority["capability_id"])
                if (binding is None or binding.version_digest != authority["version_digest"]
                        or binding.connections.get(authority["connection_name"]) != grant["id"]):
                    raise RuntimeFailure("CONNECTION_OPERATION_DENIED")
                # Personal workspaces have no team share; team applications must
                # retain the exact active canonical share on every broker call.
                personal = db.execute("SELECT 1 FROM access_personal_workspaces WHERE team_id=?", (authority["workspace_id"],)).fetchone()
                if personal is None and db.execute("SELECT 1 FROM team_software WHERE team_id=? AND capability_id=? AND version_digest=? AND status='active'",
                    (authority["workspace_id"], authority["capability_id"], authority["version_digest"])).fetchone() is None:
                    raise RuntimeFailure("CONNECTION_OPERATION_DENIED")
            source = approval["sources"][authority["connection_name"]]
            if db.execute("SELECT 1 FROM derived_connection_grants WHERE grant_id=?", (source["grant_id"],)).fetchone():
                raise RuntimeFailure("CONNECTION_OPERATION_DENIED")
            source_grant = self.resolve_grant(source["grant_id"], scope_id=approval["source_scope_id"],
                capability_id=authority["capability_id"], version_digest=authority["version_digest"], contract=grant["contract"])
            if (grant["connection_id"] != source_grant["connection_id"]
                    or self._source_fingerprint(source_grant) != source["fingerprint"]
                    or not set(json.loads(grant["operations_json"])) <= set(source_grant["operations"])):
                raise RuntimeFailure("CONNECTION_OPERATION_DENIED")

    def status(self, scope_id: str, grant_id: str, resolver: SecretResolver | None = None) -> str:
        try:
            record = self.resolve_grant(grant_id, scope_id=scope_id)
            if resolver is not None and not getattr(resolver, "healthy")(record["secret_reference"]):
                return "unavailable"
            return "configured"
        except RuntimeFailure:
            return "unavailable"

    def inventory(self, scope_id: str, resolver: SecretResolver | None = None) -> list[dict[str, Any]]:
        with self.store.connect() as db:
            rows = db.execute(
                """SELECT g.id, i.display_json FROM connection_grants g
                   JOIN connection_instances i ON i.id=g.connection_id
                   WHERE g.scope_id=? AND g.status='active' AND i.status='active'
                   ORDER BY g.id""",
                (scope_id,),
            ).fetchall()
        result = []
        for row in rows:
            display = json.loads(row["display_json"])
            result.append({
                "name": display.get("label", "Publisher-managed connection"),
                "status": self.status(scope_id, row["id"], resolver),
                "service": "publisher-managed",
            })
        return result

    def resolve_grant(
        self,
        grant_id: str,
        *,
        scope_id: str,
        capability_id: str | None = None,
        version_digest: str | None = None,
        contract: str | None = None,
        operation: str | None = None,
    ) -> dict[str, Any]:
        with self.store.connect() as db:
            row = db.execute(
                """SELECT g.*, i.adapter_version, i.secret_reference, i.profile_reference,
                          i.display_json, i.publisher_id
                   FROM connection_grants g JOIN connection_instances i ON i.id=g.connection_id
                   WHERE g.id=? AND g.scope_id=? AND g.status='active' AND i.status='active'""",
                (grant_id, scope_id),
            ).fetchone()
        if row is None:
            raise RuntimeFailure("CONNECTION_OPERATION_DENIED")
        self._validate_derived(row)
        operations = json.loads(row["operations_json"])
        if (
            (capability_id is not None and row["capability_id"] not in {None, capability_id})
            or (version_digest is not None and row["version_digest"] not in {None, version_digest})
            or (contract is not None and row["contract"] != contract)
            or (operation is not None and operation not in operations)
        ):
            raise RuntimeFailure("CONNECTION_OPERATION_DENIED")
        result = dict(row)
        result["operations"] = operations
        result["display"] = json.loads(row["display_json"])
        return result

    def issue_invocation_grant(
        self,
        *,
        invocation_id: str,
        grant_id: str,
        connection_name: str,
        scope_id: str,
        capability_id: str,
        version_digest: str,
        contract: str,
        operations: tuple[str, ...],
        expected_uid: int | None,
    ) -> str:
        record = self.resolve_grant(
            grant_id, scope_id=scope_id, capability_id=capability_id,
            version_digest=version_digest, contract=contract,
        )
        if not set(operations) <= set(record["operations"]):
            raise RuntimeFailure("CONNECTION_OPERATION_DENIED")
        token = secrets.token_urlsafe(32)
        with self.store.connect() as db:
            db.execute(
                """INSERT INTO invocation_connection_grants
                   (token_digest, invocation_id, grant_id, connection_name, expected_uid,
                    expires_at, used_at, created_at, capability_id, version_digest,
                    contract, operations_json, scope_id, connection_id)
                   VALUES (?, ?, ?, ?, ?, ?, NULL, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    hashlib.sha256(token.encode()).hexdigest(), invocation_id, grant_id,
                    connection_name, expected_uid, time.time() + GRANT_TTL_SECONDS, utc_now(),
                    capability_id, version_digest, contract,
                    canonical_json(list(operations)).decode(), scope_id, record["connection_id"],
                ),
            )
        return token

    def consume_invocation_grant(
        self,
        token: str,
        *,
        invocation_id: str,
        connection_name: str,
        contract: str,
        operation: str,
        peer_uid: int | None,
    ) -> dict[str, Any]:
        digest = hashlib.sha256(token.encode()).hexdigest()
        with self.store.connect() as db:
            row = db.execute(
                "SELECT * FROM invocation_connection_grants WHERE token_digest=?", (digest,)
            ).fetchone()
            invocation_operations = (
                json.loads(row["operations_json"])
                if row is not None and row["operations_json"] is not None
                else []
            )
            if (
                row is None or row["used_at"] is not None or row["expires_at"] < time.time()
                or row["invocation_id"] != invocation_id
                or row["connection_name"] != connection_name
                or (row["expected_uid"] is not None and row["expected_uid"] != peer_uid)
                or row["contract"] != contract
                or operation not in invocation_operations
            ):
                raise RuntimeFailure("CONNECTION_OPERATION_DENIED")
            changed = db.execute(
                "UPDATE invocation_connection_grants SET used_at=? WHERE token_digest=? AND used_at IS NULL",
                (utc_now(), digest),
            ).rowcount
            if changed != 1:
                raise RuntimeFailure("CONNECTION_OPERATION_DENIED")
            grant = db.execute(
                """SELECT g.*, i.adapter_version, i.secret_reference, i.profile_reference,
                          i.display_json, i.publisher_id
                   FROM connection_grants g JOIN connection_instances i ON i.id=g.connection_id
                   WHERE g.id=? AND g.status='active' AND i.status='active'""",
                (row["grant_id"],),
            ).fetchone()
        if grant is None:
            raise RuntimeFailure("CONNECTION_OPERATION_DENIED")
        self._validate_derived(grant)
        if (row["connection_id"] is None or grant["connection_id"] != row["connection_id"]
                or row["scope_id"] is None or grant["scope_id"] != row["scope_id"]
                or grant["capability_id"] not in {None, row["capability_id"]}
                or grant["version_digest"] not in {None, row["version_digest"]}):
            raise RuntimeFailure("CONNECTION_OPERATION_DENIED")
        result = dict(grant)
        grant_operations = json.loads(grant["operations_json"])
        if contract != grant["contract"] or operation not in grant_operations:
            raise RuntimeFailure("CONNECTION_OPERATION_DENIED")
        result["operations"] = invocation_operations
        result["capability_id"] = row["capability_id"]
        result["version_digest"] = row["version_digest"]
        return result

    def record_receipt(self, receipt: dict[str, Any]) -> str:
        receipt_id = "connection-receipt-" + uuid.uuid4().hex
        with self.store.connect() as db:
            db.execute(
                "INSERT INTO connection_receipts VALUES (?, ?, ?, ?)",
                (receipt_id, receipt["invocation_id"], canonical_json(receipt).decode(), utc_now()),
            )
        return receipt_id

    def receipts(self, invocation_id: str) -> list[dict[str, Any]]:
        with self.store.connect() as db:
            rows = db.execute(
                "SELECT id, receipt_json FROM connection_receipts WHERE invocation_id=? ORDER BY created_at, id",
                (invocation_id,),
            ).fetchall()
        return [{"id": row["id"], **json.loads(row["receipt_json"])} for row in rows]


class ConnectionAdapter(Protocol):
    def call(self, *, contract: str, operation: str, secret: object, profile: object, payload: object) -> dict[str, Any]: ...


class ConnectionBroker:
    """One-request-per-connection bounded Unix socket broker."""

    def __init__(
        self,
        control: ConnectionControl,
        resolver: SecretResolver,
        profiles: dict[str, dict[str, Any]],
        adapters: dict[str, ConnectionAdapter],
        *, managed_executor=None,
    ):
        self.control = control
        self.resolver = resolver
        self.profiles = profiles
        self.adapters = adapters
        self.managed_executor = managed_executor

    def handle(self, request: object, *, peer_uid: int | None = None) -> dict[str, Any]:
        if not isinstance(request, dict) or set(request) != {
            "schema", "invocation_id", "invocation_grant", "connection_name",
            "contract", "operation", "payload",
        } or request.get("schema") != "capy.connection-call/v0" or not isinstance(request.get("payload"), dict):
            raise RuntimeFailure("CONNECTION_CALL_INVALID")
        allowed = BROKER_OPERATION_POLICY.get(request["contract"])
        if allowed is None or request["operation"] not in allowed:
            raise RuntimeFailure("CONNECTION_OPERATION_DENIED")
        grant = self.control.consume_invocation_grant(
            str(request.get("invocation_grant", "")),
            invocation_id=str(request.get("invocation_id", "")),
            connection_name=str(request.get("connection_name", "")),
            contract=str(request.get("contract", "")),
            operation=str(request.get("operation", "")),
            peer_uid=peer_uid,
        )
        if request["contract"] != grant["contract"] or request["operation"] not in grant["operations"]:
            raise RuntimeFailure("CONNECTION_OPERATION_DENIED")
        started = time.monotonic()
        request_digest = sha256(canonical_json(request["payload"]))
        status = "failed"
        failure_code = None
        result: dict[str, Any] | None = None
        response_digest: str | None = None
        provider_reference: str | None = None
        try:
            if grant['adapter_version'] in {'fedex-rates-adapter/v2','fedex-rates-adapter/v3'} and self.managed_executor is not None:
                # Credentials remain inside the separate account service. The
                # broker transfers only the consumed grant identity and payload.
                secret = {}
                result = self.managed_executor(grant, request['invocation_id'], request['payload'])
            else:
                adapter = self.adapters.get(grant["adapter_version"])
                profile = self.profiles.get(grant["profile_reference"])
                if adapter is None or profile is None:
                    raise RuntimeFailure("CONNECTION_UNAVAILABLE")
                secret = self.resolver.resolve(grant["secret_reference"])
                result = adapter.call(
                    contract=request["contract"], operation=request["operation"],
                    secret=secret, profile=profile, payload=request["payload"],
                )
            if not isinstance(result, dict) or len(canonical_json(result)) > MAX_RESULT_BYTES:
                raise RuntimeFailure("CONNECTION_RESPONSE_INVALID")
            self._reject_secret_reflection(result, secret)
            response_digest = sha256(canonical_json(result))
            candidate_reference = result.get("provider_transaction_id")
            if isinstance(candidate_reference, str) and 0 < len(candidate_reference) <= 256:
                provider_reference = candidate_reference
            status = "succeeded"
        except RuntimeFailure as exc:
            failure_code = exc.code
        except Exception as exc:
            code = getattr(exc, "code", None)
            failure_code = code if isinstance(code, str) and re.fullmatch(r"[A-Z0-9_]{3,128}", code) else "CONNECTION_UNAVAILABLE"
        if failure_code is not None:
            result = None
        if failure_code == "FEDEX_PROVIDER_UNAVAILABLE":
            failure_code = "FEDEX_RATE_UNAVAILABLE"
        receipt = {
            "schema": "capy.connection-receipt/v0",
            "connection_instance_id": grant["connection_id"],
            "contract": grant["contract"],
            "adapter_version": grant["adapter_version"],
            "operation": request["operation"],
            "invocation_id": request["invocation_id"],
            "scope_id": grant["scope_id"],
            "capability_id": grant["capability_id"],
            "version_digest": grant["version_digest"],
            "request_digest": request_digest,
            "provider_endpoint_class": "fedex-rates" if grant["contract"] in {"fedex.rates/v1", "fedex.rates/v2"} else "unknown",
            "provider_status": status,
            "provider_reference": provider_reference,
            "response_digest": response_digest,
            "duration_ms": round((time.monotonic() - started) * 1000),
            "terminal_status": status,
            "failure_code": failure_code,
        }
        receipt_id = self.control.record_receipt(receipt)
        if failure_code is not None:
            return {"schema": "capy.connection-result/v0", "status": "failed", "failure_code": failure_code}
        return {"schema": "capy.connection-result/v0", "status": "ok", "result": result, "receipt_id": receipt_id}

    @staticmethod
    def _reject_secret_reflection(result: object, secret: object) -> None:
        sensitive_keys = {
            "client_id", "client_secret", "account_number", "child_key",
            "child_secret", "access_token", "authorization",
        }
        sensitive: list[str] = []
        def collect(value: object, *, sensitive_context: bool = False) -> None:
            if isinstance(value, str) and sensitive_context:
                sensitive.append(value)
            elif isinstance(value, dict):
                for key, child in value.items():
                    collect(
                        child,
                        sensitive_context=(
                            sensitive_context
                            or isinstance(key, str) and key.lower() in sensitive_keys
                        ),
                    )
            elif isinstance(value, list):
                for child in value:
                    collect(child, sensitive_context=sensitive_context)
        def representations(value: str) -> set[str]:
            encoded = value.encode("utf-8")
            return {
                value,
                json.dumps(value, ensure_ascii=False)[1:-1],
                urllib.parse.quote(value, safe=""),
                encoded.hex(),
                base64.b64encode(encoded).decode("ascii"),
                base64.urlsafe_b64encode(encoded).decode("ascii"),
            }
        collect(secret)
        forbidden = {
            variant
            for item in sensitive
            if item
            for variant in representations(item)
            if len(variant) >= 6
        }
        def inspect(value: object) -> None:
            if isinstance(value, str) and any(item in value for item in forbidden):
                raise RuntimeFailure("CONNECTION_RESPONSE_INVALID")
            if isinstance(value, dict):
                for key, child in value.items():
                    inspect(key)
                    inspect(child)
            elif isinstance(value, list):
                for child in value:
                    inspect(child)
        inspect(result)

    def serve(self, socket_path: Path, stop: threading.Event) -> None:
        socket_path.parent.mkdir(parents=True, exist_ok=True)
        socket_path.unlink(missing_ok=True)
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as server:
            server.bind(str(socket_path))
            socket_path.chmod(0o666)
            server.listen(16)
            server.settimeout(0.2)
            try:
                while not stop.is_set():
                    try:
                        connection, _ = server.accept()
                    except TimeoutError:
                        continue
                    with connection:
                        connection.settimeout(20)
                        peer_uid = self._peer_uid(connection)
                        response = self._read_and_handle(connection, peer_uid)
                        try:
                            connection.sendall(canonical_json(response) + b"\n")
                        except (BrokenPipeError, ConnectionResetError):
                            pass
            finally:
                socket_path.unlink(missing_ok=True)

    def _read_and_handle(self, connection: socket.socket, peer_uid: int | None) -> dict[str, Any]:
        payload = bytearray()
        try:
            while b"\n" not in payload:
                part = connection.recv(min(65536, MAX_CALL_BYTES + 1 - len(payload)))
                if not part:
                    break
                payload.extend(part)
                if len(payload) > MAX_CALL_BYTES:
                    raise RuntimeFailure("CONNECTION_REQUEST_TOO_LARGE")
            if not payload.endswith(b"\n") or payload.count(b"\n") != 1:
                raise RuntimeFailure("CONNECTION_CALL_INVALID")
            value = json.loads(payload[:-1])
            if value == {"schema": "capy.connection-health/v0"}:
                return {"schema": "capy.connection-health/v0", "status": "ready"}
            return self.handle(value, peer_uid=peer_uid)
        except RuntimeFailure as exc:
            return {"schema": "capy.connection-result/v0", "status": "failed", "failure_code": exc.code}
        except (ValueError, json.JSONDecodeError):
            return {"schema": "capy.connection-result/v0", "status": "failed", "failure_code": "CONNECTION_CALL_INVALID"}

    @staticmethod
    def _peer_uid(connection: socket.socket) -> int | None:
        if hasattr(socket, "SO_PEERCRED"):
            import struct
            _pid, uid, _gid = struct.unpack("3i", connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
            return uid
        return None
