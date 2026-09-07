"""SQLite control state plus immutable resource and script stores."""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import sqlite3
import stat
import sys
import tempfile
import threading
import uuid
import zipfile
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator

from .model import CapabilityDescriptor, RuntimeFailure


SCOPE_ID = re.compile(r"[a-z0-9][a-z0-9_-]{0,63}")


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def canonical_json(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode()


def sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _tree_files(root: Path) -> Iterator[tuple[str, Path, int]]:
    if not root.is_dir() or root.is_symlink():
        raise RuntimeFailure("CAPABILITY_CANDIDATE_INVALID")
    for path in sorted(root.rglob("*")):
        relative = path.relative_to(root).as_posix()
        if path.is_symlink():
            raise RuntimeFailure("CAPABILITY_CANDIDATE_SYMLINK", relative)
        if path.is_dir():
            continue
        if not path.is_file():
            raise RuntimeFailure("CAPABILITY_CANDIDATE_INVALID", relative)
        mode = stat.S_IMODE(path.stat().st_mode) & 0o111
        yield relative, path, mode


def tree_digest(root: Path) -> str:
    digest = hashlib.sha256()
    count = 0
    for relative, path, executable in _tree_files(root):
        data = path.read_bytes()
        digest.update(canonical_json({"path": relative, "executable": bool(executable), "size": len(data)}))
        digest.update(b"\0")
        digest.update(data)
        digest.update(b"\0")
        count += 1
    if not count:
        raise RuntimeFailure("CAPABILITY_CANDIDATE_EMPTY")
    return digest.hexdigest()


@dataclass(frozen=True)
class Binding:
    scope_id: str
    capability_id: str
    version_digest: str
    connections: dict[str, str]


class RuntimeStore:
    """Owns durable control truth; callers never infer bindings from paths."""

    def __init__(self, root: Path):
        self._transaction = threading.local()
        self.root = root.resolve()
        self.root.mkdir(parents=True, exist_ok=True)
        self.database = self.root / "control.sqlite3"
        self.scripts = self.root / "scripts" / "sha256"
        self.acceptance = self.root / "acceptance" / "sha256"
        self.resources = self.root / "resources" / "sha256"
        self.states = self.root / "state"
        self.invocations = self.root / "invocations"
        self.journals = self.root / "invocation-journal"
        self.archives = self.root / "application-archives" / "sha256"
        self.environments = self.root / "devkit-environments" / "sha256"
        for path in (
            self.scripts,
            self.acceptance,
            self.resources,
            self.states,
            self.invocations,
            self.journals,
            self.archives,
            self.environments,
        ):
            path.mkdir(parents=True, exist_ok=True)
        # Scope identities may traverse only the shared immutable code branch.
        # Control data, accepted receipts, resources, state, and invocation
        # projections retain their private modes and are never reached here.
        self.root.chmod(0o711)
        self.scripts.parent.chmod(0o711)
        self.scripts.chmod(0o711)
        for path in (
            self.acceptance.parent,
            self.acceptance,
            self.resources.parent,
            self.resources,
        ):
            path.chmod(0o700)
        self.states.chmod(0o711)
        self.invocations.chmod(0o711)
        self.journals.chmod(0o711)
        self.archives.parent.chmod(0o711)
        self.archives.chmod(0o711)
        self.environments.parent.chmod(0o711)
        self.environments.chmod(0o711)
        self._initialize()
        self.database.chmod(0o600)

    @contextmanager
    def connect(self) -> Iterator[sqlite3.Connection]:
        active = getattr(self._transaction, "connection", None)
        if active is not None:
            # Nested store/access/team operations share the outer atomic boundary.
            # A caught nested failure still poisons the enclosing transaction.
            try:
                yield active
            except BaseException:
                self._transaction.failed = True
                raise
            return
        connection = sqlite3.connect(self.database)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        try:
            yield connection
        except BaseException:
            connection.rollback()
            raise
        else:
            connection.commit()
        finally:
            connection.close()

    @contextmanager
    def transaction(self) -> Iterator[sqlite3.Connection]:
        """Serialize and atomically commit composed store operations in this thread."""
        if getattr(self._transaction, "connection", None) is not None:
            with self.connect() as connection:
                yield connection
            return
        with self.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            self._transaction.connection = connection
            self._transaction.failed = False
            try:
                yield connection
                if self._transaction.failed:
                    raise RuntimeFailure("TRANSACTION_ABORTED")
            finally:
                self._transaction.connection = None
                self._transaction.failed = False

    def _initialize(self) -> None:
        with self.connect() as db:
            db.executescript(
                """
                PRAGMA journal_mode = WAL;
                CREATE TABLE IF NOT EXISTS scopes (
                    id TEXT PRIMARY KEY,
                    created_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS capability_versions (
                    capability_id TEXT NOT NULL,
                    version_digest TEXT NOT NULL,
                    descriptor_json TEXT NOT NULL,
                    acceptance_digest TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    PRIMARY KEY (capability_id, version_digest)
                );
                CREATE TABLE IF NOT EXISTS bindings (
                    scope_id TEXT NOT NULL REFERENCES scopes(id),
                    capability_id TEXT NOT NULL,
                    version_digest TEXT NOT NULL,
                    connections_json TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    PRIMARY KEY (scope_id, capability_id),
                    FOREIGN KEY (capability_id, version_digest)
                        REFERENCES capability_versions(capability_id, version_digest)
                );
                CREATE TABLE IF NOT EXISTS resources (
                    scope_id TEXT NOT NULL REFERENCES scopes(id),
                    digest TEXT NOT NULL,
                    filename TEXT NOT NULL,
                    size_bytes INTEGER NOT NULL,
                    created_at TEXT NOT NULL,
                    PRIMARY KEY (scope_id, digest)
                );
                CREATE TABLE IF NOT EXISTS invocations (
                    id TEXT PRIMARY KEY,
                    scope_id TEXT NOT NULL REFERENCES scopes(id),
                    capability_id TEXT NOT NULL,
                    version_digest TEXT NOT NULL,
                    status TEXT NOT NULL,
                    request_digest TEXT NOT NULL,
                    receipt_json TEXT,
                    created_at TEXT NOT NULL,
                    completed_at TEXT
                );
                CREATE TABLE IF NOT EXISTS interface_activities (
                    id TEXT PRIMARY KEY,
                    scope_id TEXT NOT NULL REFERENCES scopes(id),
                    principal_id TEXT NOT NULL,
                    membership_id TEXT NOT NULL,
                    team_id TEXT NOT NULL,
                    application_id TEXT NOT NULL,
                    application_version TEXT NOT NULL,
                    contract_digest TEXT NOT NULL,
                    operation_id TEXT NOT NULL,
                    submission TEXT NOT NULL,
                    request_digest TEXT NOT NULL,
                    status TEXT NOT NULL CHECK(status IN ('running','succeeded','failed')),
                    invocation_id TEXT,
                    summary TEXT,
                    result_json TEXT,
                    artifacts_json TEXT,
                    receipt_json TEXT,
                    source_checked INTEGER,
                    state_changed INTEGER,
                    error_code TEXT,
                    created_at TEXT NOT NULL,
                    completed_at TEXT,
                    UNIQUE(scope_id, submission)
                );
                CREATE TABLE IF NOT EXISTS publication_intents (
                    build_id TEXT PRIMARY KEY,
                    scope_id TEXT NOT NULL REFERENCES scopes(id),
                    capability_id TEXT NOT NULL,
                    version_digest TEXT NOT NULL,
                    intent_json TEXT NOT NULL,
                    intent_digest TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    FOREIGN KEY (capability_id, version_digest)
                        REFERENCES capability_versions(capability_id, version_digest)
                );
                CREATE TABLE IF NOT EXISTS invocation_executors (
                    invocation_id TEXT PRIMARY KEY REFERENCES invocations(id),
                    executor_state TEXT NOT NULL,
                    unit_name TEXT NOT NULL,
                    machine_id_sha256 TEXT NOT NULL,
                    boot_id TEXT NOT NULL,
                    launch_nonce TEXT NOT NULL,
                    journal_path TEXT NOT NULL,
                    journal_digest TEXT NOT NULL,
                    last_unit_state TEXT,
                    terminal_receipt_digest TEXT,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS devkit_publications (
                    capability_id TEXT NOT NULL,
                    version_digest TEXT NOT NULL,
                    archive_digest TEXT NOT NULL,
                    wheel_digest TEXT NOT NULL,
                    environment_digest TEXT NOT NULL,
                    acceptance_digest TEXT NOT NULL,
                    candidate_commit TEXT NOT NULL,
                    candidate_tree TEXT NOT NULL,
                    publication_identity_digest TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    PRIMARY KEY (capability_id, version_digest),
                    FOREIGN KEY (capability_id, version_digest)
                        REFERENCES capability_versions(capability_id, version_digest)
                );
                """
            )
            columns = {row["name"] for row in db.execute("PRAGMA table_info(invocations)")}
            for name in ("idempotency_key", "result_json", "artifacts_json"):
                if name not in columns:
                    db.execute(f"ALTER TABLE invocations ADD COLUMN {name} TEXT")
            db.execute(
                """CREATE UNIQUE INDEX IF NOT EXISTS invocation_idempotency
                   ON invocations(scope_id, idempotency_key)
                   WHERE idempotency_key IS NOT NULL"""
            )

    def begin_interface_activity(
        self,
        *,
        scope_id: str,
        principal_id: str,
        membership_id: str,
        team_id: str,
        application_id: str,
        application_version: str,
        contract_digest: str,
        operation_id: str,
        submission: str,
        request_digest: str,
    ) -> dict[str, Any]:
        """Create or resolve one exact idempotent interface submission."""

        immutable = {
            "scope_id": scope_id,
            "principal_id": principal_id,
            "membership_id": membership_id,
            "team_id": team_id,
            "application_id": application_id,
            "application_version": application_version,
            "contract_digest": contract_digest,
            "operation_id": operation_id,
            "submission": submission,
            "request_digest": request_digest,
        }
        with self.connect() as db:
            row = db.execute(
                "SELECT * FROM interface_activities WHERE scope_id=? AND submission=?",
                (scope_id, submission),
            ).fetchone()
            if row is None:
                activity_id = uuid.uuid4().hex
                db.execute(
                    """INSERT INTO interface_activities
                       (id, scope_id, principal_id, membership_id, team_id,
                        application_id, application_version, contract_digest,
                        operation_id, submission, request_digest, status,
                        created_at)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'running', ?)""",
                    (activity_id, *immutable.values(), utc_now()),
                )
                row = db.execute(
                    "SELECT * FROM interface_activities WHERE id=?", (activity_id,)
                ).fetchone()
            elif any(row[key] != value for key, value in immutable.items()):
                raise RuntimeFailure("APPLICATION_INTERFACE_SUBMISSION_CONFLICT")
        return self._decode_interface_activity(row)

    def finish_interface_activity(
        self,
        activity_id: str,
        *,
        status: str,
        invocation_id: str | None = None,
        summary: str | None = None,
        result: dict[str, Any] | None = None,
        artifacts: list[dict[str, Any]] | None = None,
        receipt: Any = None,
        source_checked: bool | None = None,
        state_changed: bool | None = None,
        error_code: str | None = None,
    ) -> dict[str, Any]:
        if status not in {"succeeded", "failed"}:
            raise RuntimeFailure("APPLICATION_INTERFACE_ACTIVITY_INVALID")
        with self.connect() as db:
            row = db.execute(
                "SELECT * FROM interface_activities WHERE id=?", (activity_id,)
            ).fetchone()
            if row is None:
                raise RuntimeFailure("APPLICATION_INTERFACE_ACTIVITY_UNKNOWN")
            if row["status"] == "running":
                db.execute(
                    """UPDATE interface_activities
                       SET status=?, invocation_id=?, summary=?, result_json=?, artifacts_json=?,
                           receipt_json=?, source_checked=?, state_changed=?,
                           error_code=?, completed_at=? WHERE id=? AND status='running'""",
                    (
                        status,
                        invocation_id,
                        summary,
                        canonical_json(result).decode() if result is not None else None,
                        canonical_json(artifacts).decode() if artifacts is not None else None,
                        canonical_json(receipt).decode() if receipt is not None else None,
                        None if source_checked is None else int(source_checked),
                        None if state_changed is None else int(state_changed),
                        error_code,
                        utc_now(),
                        activity_id,
                    ),
                )
            elif row["status"] != status:
                raise RuntimeFailure("APPLICATION_INTERFACE_ACTIVITY_CONFLICT")
            row = db.execute(
                "SELECT * FROM interface_activities WHERE id=?", (activity_id,)
            ).fetchone()
        return self._decode_interface_activity(row)

    def interface_activity(self, activity_id: str) -> dict[str, Any]:
        if not re.fullmatch(r"[0-9a-f]{32}", activity_id):
            raise RuntimeFailure("APPLICATION_INTERFACE_ACTIVITY_UNKNOWN")
        with self.connect() as db:
            row = db.execute(
                "SELECT * FROM interface_activities WHERE id=?", (activity_id,)
            ).fetchone()
        if row is None:
            raise RuntimeFailure("APPLICATION_INTERFACE_ACTIVITY_UNKNOWN")
        return self._decode_interface_activity(row)

    @staticmethod
    def _decode_interface_activity(row: sqlite3.Row) -> dict[str, Any]:
        value = dict(row)
        for field in ("result_json", "artifacts_json", "receipt_json"):
            decoded = field.removesuffix("_json")
            value[decoded] = json.loads(value.pop(field)) if value.get(field) else None
        for field in ("source_checked", "state_changed"):
            if value[field] is not None:
                value[field] = bool(value[field])
        return value

    def register_scope(self, scope_id: str) -> None:
        if not SCOPE_ID.fullmatch(scope_id):
            raise RuntimeFailure("SCOPE_ID_INVALID")
        with self.connect() as db:
            db.execute("INSERT OR IGNORE INTO scopes VALUES (?, ?)", (scope_id, utc_now()))

    def publish(self, candidate: Path, acceptance_receipt: bytes) -> tuple[CapabilityDescriptor, str]:
        if not acceptance_receipt:
            raise RuntimeFailure("CAPABILITY_ACCEPTANCE_RECEIPT_INVALID")
        descriptor = CapabilityDescriptor.from_toml(candidate / "capability.toml")
        if descriptor.schema == "capy.script/dev-v0":
            raise RuntimeFailure("CAPABILITY_ACCEPTED_ARCHIVE_REQUIRED")
        return self._publish_candidate(candidate, acceptance_receipt, descriptor)

    def _publish_candidate(
        self,
        candidate: Path,
        acceptance_receipt: bytes,
        descriptor: CapabilityDescriptor,
    ) -> tuple[CapabilityDescriptor, str]:
        entrypoint = candidate / descriptor.entrypoint
        if not entrypoint.is_file() or entrypoint.is_symlink():
            raise RuntimeFailure("CAPABILITY_ENTRYPOINT_MISSING")
        digest = tree_digest(candidate)
        destination = self.scripts / digest
        if not destination.exists():
            temporary = Path(tempfile.mkdtemp(prefix=f".{digest}.", dir=self.scripts))
            try:
                for relative, source, executable in _tree_files(candidate):
                    target = temporary / relative
                    target.parent.mkdir(parents=True, exist_ok=True)
                    target.write_bytes(source.read_bytes())
                    target.chmod(0o555 if executable else 0o444)
                for directory in sorted((item for item in temporary.rglob("*") if item.is_dir()), reverse=True):
                    directory.chmod(0o555)
                temporary.chmod(0o555)
                os.replace(temporary, destination)
            finally:
                if temporary.exists():
                    shutil.rmtree(temporary)
        acceptance_digest = sha256(acceptance_receipt)
        acceptance_path = self.acceptance / acceptance_digest
        if not acceptance_path.exists():
            temporary_receipt = self.acceptance / f".{acceptance_digest}.{uuid.uuid4().hex}"
            temporary_receipt.write_bytes(acceptance_receipt)
            temporary_receipt.chmod(0o444)
            try:
                os.link(temporary_receipt, acceptance_path)
            except FileExistsError:
                pass
            finally:
                temporary_receipt.unlink(missing_ok=True)
        with self.connect() as db:
            existing = db.execute(
                "SELECT acceptance_digest FROM capability_versions WHERE capability_id = ? AND version_digest = ?",
                (descriptor.id, digest),
            ).fetchone()
            if existing is not None and existing["acceptance_digest"] != acceptance_digest:
                raise RuntimeFailure("CAPABILITY_ACCEPTANCE_RECEIPT_CONFLICT")
            db.execute(
                "INSERT OR IGNORE INTO capability_versions VALUES (?, ?, ?, ?, ?)",
                (descriptor.id, digest, descriptor.canonical_json(), acceptance_digest, utc_now()),
            )
        return descriptor, digest

    def publish_devkit_archive(
        self,
        application_archive: Path,
        acceptance_receipt: bytes,
        devkit_wheel: Path,
        *,
        expected_identity: dict[str, str],
    ) -> tuple[CapabilityDescriptor, str, dict[str, str]]:
        """Verify and immutably publish one accepted dev-v0 archive and its offline wheel."""

        try:
            archive_bytes = application_archive.read_bytes()
            wheel_bytes = devkit_wheel.read_bytes()
            receipt = json.loads(acceptance_receipt)
        except (OSError, UnicodeError, ValueError, json.JSONDecodeError) as exc:
            raise RuntimeFailure("CAPABILITY_ACCEPTANCE_RECEIPT_INVALID") from exc
        legacy_expected_fields = {
            "application_archive_sha256", "devkit_wheel_sha256",
            "acceptance_receipt_sha256", "candidate_commit", "candidate_tree",
            "devkit_commit",
        }
        generic_expected_fields = legacy_expected_fields | {"descriptor_sha256"}
        if (
            not isinstance(expected_identity, dict)
            or (
                set(expected_identity) != legacy_expected_fields
                and set(expected_identity) != generic_expected_fields
            )
            or any(not isinstance(value, str) for value in expected_identity.values())
        ):
            raise RuntimeFailure("CAPABILITY_ACCEPTED_IDENTITY_REQUIRED")
        legacy_required_receipt = {
            "schema", "application_id", "seed_commit", "candidate_commit", "candidate_tree",
            "devkit_commit", "devkit_wheel_sha256", "application_archive_sha256",
            "contract", "connection_contract", "acceptance", "friction", "judgment",
            "non_claims", "accepted_at",
        }
        generic_required_receipt = {
            "schema", "application_id", "candidate_repository", "candidate_commit",
            "candidate_tree", "contract", "devkit_commit", "devkit_wheel_sha256",
            "application_archive_sha256", "descriptor_sha256", "acceptance_profile",
            "acceptance", "accepted_at",
        }
        checks = receipt.get("acceptance")
        common_invalid = (
            not isinstance(receipt, dict)
            or receipt.get("contract") != "capy.script/dev-v0"
            or not isinstance(checks, dict)
            or set(checks) != {
                "doctor", "check", "test", "conform", "black_box_oracle",
                "secret_boundary_scan", "repeated_pack_digest",
            }
            or checks != {
                "doctor": "passed",
                "check": "passed",
                "test": "passed",
                "conform": "passed",
                "black_box_oracle": "passed",
                "secret_boundary_scan": "passed",
                "repeated_pack_digest": "matched",
            }
            or any(
                not isinstance(receipt.get(field), str)
                or re.fullmatch(r"[0-9a-f]{40}", receipt[field]) is None
                for field in ("seed_commit", "candidate_commit", "candidate_tree", "devkit_commit")
                if field in receipt
            )
        )
        legacy = receipt.get("schema") == "capy.application-acceptance/v0"
        generic = receipt.get("schema") == "capy.application-acceptance/v1"
        if common_invalid or (
            legacy and (
                set(receipt) != legacy_required_receipt
                or receipt.get("judgment") != "existing_fedex_quote_port_conforms_to_capy_script_dev_v0"
                or set(expected_identity) != legacy_expected_fields
            )
        ) or (
            generic and (
                set(receipt) != generic_required_receipt
                or set(expected_identity) != generic_expected_fields
                or not isinstance(receipt.get("candidate_repository"), str)
                or not receipt["candidate_repository"]
                or not isinstance(receipt.get("acceptance_profile"), str)
                or not receipt["acceptance_profile"]
                or re.fullmatch(r"[0-9a-f]{64}", str(receipt.get("descriptor_sha256"))) is None
            )
        ) or not (legacy or generic):
            raise RuntimeFailure("CAPABILITY_ACCEPTANCE_RECEIPT_INVALID")
        archive_digest = sha256(archive_bytes)
        wheel_digest = sha256(wheel_bytes)
        acceptance_digest = sha256(acceptance_receipt)
        if (
            archive_digest != receipt["application_archive_sha256"]
            or archive_digest != expected_identity["application_archive_sha256"]
        ):
            raise RuntimeFailure("CAPABILITY_ARCHIVE_DIGEST_MISMATCH")
        if (
            wheel_digest != receipt["devkit_wheel_sha256"]
            or wheel_digest != expected_identity["devkit_wheel_sha256"]
        ):
            raise RuntimeFailure("DEVKIT_WHEEL_DIGEST_MISMATCH")
        if (
            acceptance_digest != expected_identity["acceptance_receipt_sha256"]
            or any(
                receipt[field] != expected_identity[field]
                for field in ("candidate_commit", "candidate_tree", "devkit_commit")
            )
        ):
            raise RuntimeFailure("CAPABILITY_ACCEPTANCE_IDENTITY_MISMATCH")
        with tempfile.TemporaryDirectory(prefix="capy-devkit-import-") as temporary_text:
            candidate = Path(temporary_text) / "application"
            candidate.mkdir()
            self._extract_zip(application_archive, candidate)
            descriptor = CapabilityDescriptor.from_toml(candidate / "capability.toml")
            if (
                descriptor.schema != "capy.script/dev-v0"
                or descriptor.id != receipt["application_id"]
                or (
                    legacy and receipt["connection_contract"] not in {
                        item.contract for item in descriptor.connection_requirements
                    }
                )
            ):
                raise RuntimeFailure("CAPABILITY_ACCEPTANCE_RECEIPT_INVALID")
            descriptor_digest = sha256((candidate / "capability.toml").read_bytes())
            if generic and (
                descriptor_digest != receipt["descriptor_sha256"]
                or descriptor_digest != expected_identity["descriptor_sha256"]
            ):
                raise RuntimeFailure("CAPABILITY_DESCRIPTOR_DIGEST_MISMATCH")
            descriptor, version_digest = self._publish_candidate(
                candidate, acceptance_receipt, descriptor
            )
        environment_digest = sha256(canonical_json({
            "schema": "capy.devkit-environment/v0",
            "python": f"{sys.version_info.major}.{sys.version_info.minor}",
            "wheel_digest": wheel_digest,
        }))
        environment_root = self._install_devkit_environment(
            devkit_wheel, wheel_bytes, wheel_digest, environment_digest
        )
        archive_path = self.archives / archive_digest
        if not archive_path.exists():
            self._install_immutable_file(archive_path, archive_bytes)
        identity = {
            "schema": "capy.devkit-publication/v0",
            "application_id": descriptor.id,
            "version_digest": version_digest,
            "archive_digest": archive_digest,
            "descriptor_digest": sha256((self.scripts / version_digest / "capability.toml").read_bytes()),
            "wheel_digest": wheel_digest,
            "environment_digest": environment_digest,
            "acceptance_digest": acceptance_digest,
            "candidate_commit": receipt["candidate_commit"],
            "candidate_tree": receipt["candidate_tree"],
        }
        identity_digest = sha256(canonical_json(identity))
        with self.connect() as db:
            existing = db.execute(
                """SELECT * FROM devkit_publications
                   WHERE capability_id=? AND version_digest=?""",
                (descriptor.id, version_digest),
            ).fetchone()
            values = (
                descriptor.id, version_digest, archive_digest, wheel_digest,
                environment_digest, acceptance_digest, receipt["candidate_commit"],
                receipt["candidate_tree"], identity_digest,
            )
            if existing is not None and tuple(existing[field] for field in (
                "capability_id", "version_digest", "archive_digest", "wheel_digest",
                "environment_digest", "acceptance_digest", "candidate_commit",
                "candidate_tree", "publication_identity_digest",
            )) != values:
                raise RuntimeFailure("DEVKIT_PUBLICATION_CONFLICT")
            db.execute(
                """INSERT OR IGNORE INTO devkit_publications VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (*values, utc_now()),
            )
        return descriptor, version_digest, {
            **identity,
            "publication_identity_digest": identity_digest,
            "environment_root": str(environment_root),
        }

    @staticmethod
    def _extract_zip(source: Path, destination: Path) -> None:
        try:
            with zipfile.ZipFile(source) as archive:
                for info in archive.infolist():
                    relative = Path(info.filename)
                    mode = (info.external_attr >> 16) & 0o177777
                    if (
                        info.is_dir()
                        or relative.is_absolute()
                        or ".." in relative.parts
                        or str(relative) in {"", "."}
                        or stat.S_ISLNK(mode)
                    ):
                        raise RuntimeFailure("CAPABILITY_ARCHIVE_INVALID")
                    target = destination / relative
                    target.parent.mkdir(parents=True, exist_ok=True)
                    target.write_bytes(archive.read(info))
                    target.chmod(0o755 if mode & 0o111 else 0o644)
        except (OSError, ValueError, zipfile.BadZipFile) as exc:
            raise RuntimeFailure("CAPABILITY_ARCHIVE_INVALID") from exc

    def _install_devkit_environment(
        self,
        wheel: Path,
        wheel_bytes: bytes,
        wheel_digest: str,
        environment_digest: str,
    ) -> Path:
        root = self.environments / wheel_digest
        if root.exists():
            metadata = json.loads((root / "environment.json").read_text(encoding="utf-8"))
            if metadata.get("environment_digest") != environment_digest:
                raise RuntimeFailure("DEVKIT_ENVIRONMENT_CONFLICT")
            return root / "site-packages"
        temporary = Path(tempfile.mkdtemp(prefix=f".{wheel_digest}.", dir=self.environments))
        try:
            site_packages = temporary / "site-packages"
            site_packages.mkdir()
            self._extract_zip(wheel, site_packages)
            (temporary / "wheel.whl").write_bytes(wheel_bytes)
            (temporary / "environment.json").write_bytes(canonical_json({
                "schema": "capy.devkit-environment/v0",
                "wheel_digest": wheel_digest,
                "environment_digest": environment_digest,
                "python": f"{sys.version_info.major}.{sys.version_info.minor}",
            }))
            for path in sorted(temporary.rglob("*"), reverse=True):
                path.chmod(0o555 if path.is_dir() or path.stat().st_mode & 0o111 else 0o444)
            temporary.chmod(0o555)
            os.replace(temporary, root)
        finally:
            if temporary.exists():
                shutil.rmtree(temporary)
        return root / "site-packages"

    @staticmethod
    def _install_immutable_file(destination: Path, payload: bytes) -> None:
        temporary = destination.with_name(f".{destination.name}.{uuid.uuid4().hex}")
        temporary.write_bytes(payload)
        temporary.chmod(0o444)
        try:
            os.link(temporary, destination)
        except FileExistsError:
            pass
        finally:
            temporary.unlink(missing_ok=True)

    def devkit_publication(self, capability_id: str, version_digest: str) -> dict[str, Any]:
        with self.connect() as db:
            row = db.execute(
                "SELECT * FROM devkit_publications WHERE capability_id=? AND version_digest=?",
                (capability_id, version_digest),
            ).fetchone()
        if row is None:
            raise RuntimeFailure("DEVKIT_PUBLICATION_UNKNOWN")
        return dict(row)

    def accepted_import(self, capability_id: str, version_digest: str) -> dict[str, Any] | None:
        from .release_admission import lookup_admission
        admitted = lookup_admission(self, capability_id, version_digest)
        if admitted is not None:
            return admitted
        from .release_import import lookup_import
        return lookup_import(self, capability_id, version_digest)

    def execution_release(self, capability_id: str, version_digest: str) -> dict[str, Any]:
        """Resolve execution provenance without manufacturing legacy acceptance."""
        imported = self.accepted_import(capability_id, version_digest)
        return imported if imported is not None else self.devkit_publication(capability_id, version_digest)

    def devkit_environment(self, capability_id: str, version_digest: str) -> Path:
        imported = self.accepted_import(capability_id, version_digest)
        if imported is not None:
            if imported.get("schema") == "capy.runtime-accepted-release-admission/v0":
                from .release_admission import admitted_environment
                return admitted_environment(self, imported)
            from .release_import import imported_environment
            return imported_environment(self, imported)
        publication = self.devkit_publication(capability_id, version_digest)
        root = self.environments / publication["wheel_digest"]
        metadata_path = root / "environment.json"
        wheel_path = root / "wheel.whl"
        try:
            metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
            if (
                metadata.get("environment_digest") != publication["environment_digest"]
                or sha256(wheel_path.read_bytes()) != publication["wheel_digest"]
                or not (root / "site-packages" / "capy_script").is_dir()
            ):
                raise RuntimeFailure("DEVKIT_ENVIRONMENT_INVALID")
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            raise RuntimeFailure("DEVKIT_ENVIRONMENT_INVALID") from exc
        return root / "site-packages"

    def descriptor(self, capability_id: str, version_digest: str) -> CapabilityDescriptor:
        self.accepted_import(capability_id, version_digest)
        with self.connect() as db:
            row = db.execute(
                "SELECT descriptor_json FROM capability_versions WHERE capability_id = ? AND version_digest = ?",
                (capability_id, version_digest),
            ).fetchone()
        if row is None:
            raise RuntimeFailure("CAPABILITY_VERSION_UNKNOWN")
        return CapabilityDescriptor.from_json(row["descriptor_json"])

    def bind(self, scope_id: str, capability_id: str, version_digest: str, connections: dict[str, str]) -> None:
        descriptor = self.descriptor(capability_id, version_digest)
        if set(connections) != set(descriptor.connections) or not all(
            isinstance(value, str)
            and 0 < len(value) <= 255
            and not any(char in value for char in "\x00\r\n")
            for value in connections.values()
        ):
            raise RuntimeFailure("CAPABILITY_CONNECTION_BINDING_INVALID")
        with self.connect() as db:
            if db.execute("SELECT 1 FROM scopes WHERE id = ?", (scope_id,)).fetchone() is None:
                raise RuntimeFailure("SCOPE_UNKNOWN")
            db.execute(
                """INSERT INTO bindings VALUES (?, ?, ?, ?, ?)
                   ON CONFLICT(scope_id, capability_id) DO UPDATE SET
                     version_digest=excluded.version_digest,
                     connections_json=excluded.connections_json,
                     created_at=excluded.created_at""",
                (scope_id, capability_id, version_digest, canonical_json(connections).decode(), utc_now()),
            )

    def bind_with_publication_receipt(
        self,
        build_id: str,
        scope_id: str,
        capability_id: str,
        version_digest: str,
        connections: dict[str, str],
        receipt: dict[str, Any],
        expected_previous: Binding | None,
    ) -> dict[str, Any]:
        """Atomically make a binding visible with its complete durable receipt."""

        if not re.fullmatch(r"[0-9a-f]{32}", build_id):
            raise RuntimeFailure("BUILD_ID_INVALID")
        descriptor = self.descriptor(capability_id, version_digest)
        if set(connections) != set(descriptor.connections):
            raise RuntimeFailure("CAPABILITY_CONNECTION_BINDING_INVALID")
        required = {
            "schema", "build_id", "capability_id", "new_version",
            "acceptance_digest", "scope_id", "previous_binding", "new_binding",
            "world_digest_before", "world_digest_after", "publisher_identity", "created_at",
        }
        record = self.version_record(capability_id, version_digest)
        expected_new = {
            "scope_id": scope_id,
            "capability_id": capability_id,
            "version_digest": version_digest,
            "connections": connections,
        }
        if (
            set(receipt) != required
            or receipt.get("schema") != "capy.publication-receipt/v0"
            or receipt.get("build_id") != build_id
            or receipt.get("scope_id") != scope_id
            or receipt.get("capability_id") != capability_id
            or receipt.get("new_version") != version_digest
            or receipt.get("acceptance_digest") != record["acceptance_digest"]
            or receipt.get("previous_binding") != (
                None if expected_previous is None else {
                    "scope_id": expected_previous.scope_id,
                    "capability_id": expected_previous.capability_id,
                    "version_digest": expected_previous.version_digest,
                    "connections": expected_previous.connections,
                }
            )
            or receipt.get("new_binding") != expected_new
            or not all(
                isinstance(receipt.get(name), str)
                and re.fullmatch(r"[0-9a-f]{64}", receipt[name])
                for name in ("world_digest_before", "world_digest_after")
            )
            or not isinstance(receipt.get("publisher_identity"), str)
            or not receipt["publisher_identity"]
            or not isinstance(receipt.get("created_at"), str)
        ):
            raise RuntimeFailure("PUBLICATION_RECEIPT_INVALID")
        encoded = canonical_json(receipt).decode()
        digest = sha256(encoded.encode())
        with self.connect() as db:
            scope = db.execute("SELECT 1 FROM scopes WHERE id = ?", (scope_id,)).fetchone()
            if scope is None:
                raise RuntimeFailure("SCOPE_UNKNOWN")
            row = db.execute(
                "SELECT version_digest, connections_json FROM bindings WHERE scope_id = ? AND capability_id = ?",
                (scope_id, capability_id),
            ).fetchone()
            current = None if row is None else Binding(
                scope_id, capability_id, row["version_digest"], json.loads(row["connections_json"])
            )
            if current != expected_previous:
                raise RuntimeFailure("PUBLICATION_BINDING_CHANGED")
            existing = db.execute(
                "SELECT intent_json, intent_digest FROM publication_intents WHERE build_id = ?",
                (build_id,),
            ).fetchone()
            if existing is not None:
                if existing["intent_json"] != encoded or existing["intent_digest"] != digest:
                    raise RuntimeFailure("PUBLICATION_INTENT_CONFLICT")
            else:
                db.execute(
                    "INSERT INTO publication_intents VALUES (?, ?, ?, ?, ?, ?, ?)",
                    (build_id, scope_id, capability_id, version_digest, encoded, digest, utc_now()),
                )
            db.execute(
                """INSERT INTO bindings VALUES (?, ?, ?, ?, ?)
                   ON CONFLICT(scope_id, capability_id) DO UPDATE SET
                     version_digest=excluded.version_digest,
                     connections_json=excluded.connections_json,
                     created_at=excluded.created_at""",
                (scope_id, capability_id, version_digest, canonical_json(connections).decode(), utc_now()),
            )
        return {"receipt": receipt, "digest": digest}

    def publication_receipt(self, build_id: str) -> dict[str, Any] | None:
        with self.connect() as db:
            row = db.execute(
                "SELECT intent_json, intent_digest FROM publication_intents WHERE build_id = ?",
                (build_id,),
            ).fetchone()
        if row is None:
            return None
        return {"receipt": json.loads(row["intent_json"]), "digest": row["intent_digest"]}

    def publication_receipts(self) -> list[dict[str, Any]]:
        with self.connect() as db:
            rows = db.execute(
                "SELECT build_id, intent_json, intent_digest FROM publication_intents ORDER BY created_at, build_id"
            ).fetchall()
        return [
            {"build_id": row["build_id"], "receipt": json.loads(row["intent_json"]), "digest": row["intent_digest"]}
            for row in rows
        ]

    def binding(self, scope_id: str, capability_id: str) -> Binding:
        with self.connect() as db:
            row = db.execute(
                "SELECT * FROM bindings WHERE scope_id = ? AND capability_id = ?",
                (scope_id, capability_id),
            ).fetchone()
        if row is None:
            raise RuntimeFailure("CAPABILITY_NOT_BOUND")
        return Binding(scope_id, capability_id, row["version_digest"], json.loads(row["connections_json"]))

    def binding_or_none(self, scope_id: str, capability_id: str) -> Binding | None:
        try:
            return self.binding(scope_id, capability_id)
        except RuntimeFailure as exc:
            if exc.code == "CAPABILITY_NOT_BOUND":
                return None
            raise

    def unbind(self, scope_id: str, capability_id: str) -> bool:
        with self.connect() as db:
            if db.execute("SELECT 1 FROM scopes WHERE id = ?", (scope_id,)).fetchone() is None:
                raise RuntimeFailure("SCOPE_UNKNOWN")
            changed = db.execute(
                "DELETE FROM bindings WHERE scope_id = ? AND capability_id = ?",
                (scope_id, capability_id),
            ).rowcount
        return changed == 1

    def version_record(self, capability_id: str, version_digest: str) -> dict[str, Any]:
        with self.connect() as db:
            row = db.execute(
                """SELECT v.capability_id, v.version_digest, v.acceptance_digest, v.created_at,
                          d.archive_digest, d.wheel_digest, d.environment_digest,
                          d.candidate_commit, d.candidate_tree,
                          d.publication_identity_digest
                   FROM capability_versions v
                   LEFT JOIN devkit_publications d
                     ON d.capability_id=v.capability_id AND d.version_digest=v.version_digest
                   WHERE v.capability_id = ? AND v.version_digest = ?""",
                (capability_id, version_digest),
            ).fetchone()
        if row is None:
            raise RuntimeFailure("CAPABILITY_VERSION_UNKNOWN")
        return dict(row)

    def list_bound_capabilities(self, scope_id: str, connection_status=None) -> list[dict[str, Any]]:
        with self.connect() as db:
            rows = db.execute(
                """SELECT b.capability_id, b.version_digest, b.connections_json,
                          v.descriptor_json, v.acceptance_digest
                   FROM bindings b
                   JOIN capability_versions v
                     ON v.capability_id = b.capability_id
                    AND v.version_digest = b.version_digest
                   WHERE b.scope_id = ? ORDER BY b.capability_id""",
                (scope_id,),
            ).fetchall()
        result = []
        for row in rows:
            result.append(self._capability_projection(scope_id, row, connection_status))
        return result

    def capability_projection(
        self,
        scope_id: str,
        capability_id: str,
        version_digest: str,
        connections: dict[str, str],
        connection_status=None,
    ) -> dict[str, Any]:
        with self.connect() as db:
            row = db.execute(
                """SELECT capability_id, version_digest, descriptor_json, acceptance_digest
                   FROM capability_versions WHERE capability_id=? AND version_digest=?""",
                (capability_id, version_digest),
            ).fetchone()
        if row is None:
            raise RuntimeFailure("CAPABILITY_VERSION_UNKNOWN")
        value = dict(row)
        value["connections_json"] = canonical_json(connections).decode()
        return self._capability_projection(scope_id, value, connection_status)

    def _capability_projection(self, scope_id: str, row: Any, connection_status=None) -> dict[str, Any]:
        descriptor = CapabilityDescriptor.from_json(row["descriptor_json"])
        bindings = json.loads(row["connections_json"])
        if set(bindings) != set(descriptor.connections):
            raise RuntimeFailure("CAPABILITY_CONNECTION_BINDING_INVALID")
        connections = []
        for name in descriptor.connections:
            status = "unavailable"
            if connection_status is not None:
                candidate = connection_status(scope_id, bindings[name])
                if candidate not in {"configured", "unavailable", "unhealthy"}:
                    raise RuntimeFailure("CONNECTION_STATUS_INVALID")
                status = candidate
            connections.append({"name": name, "status": status})
        projection = {
            "id": descriptor.id,
            "name": descriptor.name,
            "description": descriptor.description,
            "version_digest": row["version_digest"],
            "acceptance_digest": row["acceptance_digest"],
            "side_effect": descriptor.side_effect,
            "input_schema": descriptor.input_schema,
            "result_schema": descriptor.result_schema,
            "resource_requirements": [
                {
                    "name": item.name,
                    "required": item.required,
                    "min_items": item.min_items,
                    "max_items": item.max_items,
                }
                for item in descriptor.resource_requirements
            ],
            "connections": connections,
            "state_required": descriptor.state_required,
            "state_available": descriptor.state_required
            and (self.states / scope_id / descriptor.id.replace(".", "_")).is_dir(),
        }
        imported = self.accepted_import(descriptor.id, row["version_digest"])
        if imported is not None:
            projection["portable_interaction"] = imported["interaction"]
            projection["import_id"] = imported["import_id"]
        return projection

    def add_resource(self, scope_id: str, filename: str, content: bytes) -> str:
        if (
            not filename
            or len(filename.encode("utf-8")) > 255
            or Path(filename).name != filename
            or any(char in filename for char in "\x00\r\n")
        ):
            raise RuntimeFailure("RESOURCE_FILENAME_INVALID")
        digest = sha256(content)
        destination = self.resources / digest
        if not destination.exists():
            temporary = self.resources / f".{digest}.{uuid.uuid4().hex}"
            temporary.write_bytes(content)
            temporary.chmod(0o444)
            os.replace(temporary, destination)
        with self.connect() as db:
            if db.execute("SELECT 1 FROM scopes WHERE id = ?", (scope_id,)).fetchone() is None:
                raise RuntimeFailure("SCOPE_UNKNOWN")
            db.execute(
                "INSERT OR IGNORE INTO resources VALUES (?, ?, ?, ?, ?)",
                (scope_id, digest, filename, len(content), utc_now()),
            )
        return digest

    def resource(self, scope_id: str, digest: str) -> tuple[Path, str]:
        with self.connect() as db:
            row = db.execute(
                "SELECT filename FROM resources WHERE scope_id = ? AND digest = ?",
                (scope_id, digest),
            ).fetchone()
        if row is None:
            raise RuntimeFailure("RESOURCE_NOT_IN_SCOPE")
        return self.resources / digest, row["filename"]

    def resource_metadata(self, scope_id: str, digest: str) -> dict[str, Any]:
        with self.connect() as db:
            row = db.execute(
                "SELECT digest, filename, size_bytes, created_at FROM resources WHERE scope_id = ? AND digest = ?",
                (scope_id, digest),
            ).fetchone()
        if row is None:
            raise RuntimeFailure("RESOURCE_NOT_IN_SCOPE")
        return dict(row)

    def state_path(self, scope_id: str, capability_id: str) -> Path:
        safe_id = capability_id.replace(".", "_")
        scope_root = self.states / scope_id
        scope_root.mkdir(exist_ok=True)
        scope_root.chmod(0o711)
        path = scope_root / safe_id
        path.mkdir(exist_ok=True)
        return path

    def begin_invocation(
        self,
        scope_id: str,
        capability_id: str,
        version_digest: str,
        request_digest: str,
        idempotency_key: str | None = None,
    ) -> tuple[str, dict[str, Any] | None]:
        if idempotency_key is not None and not re.fullmatch(r"[A-Za-z0-9:._-]{1,255}", idempotency_key):
            raise RuntimeFailure("INVOCATION_IDEMPOTENCY_KEY_INVALID")
        invocation_id = uuid.uuid4().hex
        with self.connect() as db:
            if idempotency_key is not None:
                existing = db.execute(
                    "SELECT * FROM invocations WHERE scope_id=? AND idempotency_key=?",
                    (scope_id, idempotency_key),
                ).fetchone()
                if existing is not None:
                    value = self._decode_invocation(existing)
                    if (
                        value["capability_id"] != capability_id
                        or value["version_digest"] != version_digest
                        or value["request_digest"] != request_digest
                    ):
                        raise RuntimeFailure("INVOCATION_IDEMPOTENCY_CONFLICT")
                    if value["status"] != "succeeded":
                        raise RuntimeFailure("INVOCATION_IDEMPOTENCY_IN_PROGRESS")
                    return value["id"], value
            db.execute(
                """INSERT INTO invocations
                   (id, scope_id, capability_id, version_digest, status, request_digest,
                    receipt_json, created_at, completed_at, idempotency_key, result_json, artifacts_json)
                   VALUES (?, ?, ?, ?, 'running', ?, NULL, ?, NULL, ?, NULL, NULL)""",
                (invocation_id, scope_id, capability_id, version_digest, request_digest, utc_now(), idempotency_key),
            )
        return invocation_id, None

    def finish_invocation(
        self,
        invocation_id: str,
        status: str,
        receipt: dict[str, Any],
        *,
        result: dict[str, Any] | None = None,
        artifacts: list[dict[str, Any]] | None = None,
    ) -> None:
        with self.connect() as db:
            changed = db.execute(
                """UPDATE invocations SET status=?, receipt_json=?, result_json=?, artifacts_json=?, completed_at=?
                   WHERE id=? AND status='running'""",
                (
                    status,
                    canonical_json(receipt).decode(),
                    canonical_json(result).decode() if result is not None else None,
                    canonical_json(artifacts).decode() if artifacts is not None else None,
                    utc_now(),
                    invocation_id,
                ),
            ).rowcount
            if changed == 1:
                db.execute(
                    """UPDATE invocation_executors
                       SET executor_state='FINALIZED', updated_at=?
                       WHERE invocation_id=? AND executor_state!='FINALIZED'""",
                    (utc_now(), invocation_id),
                )
        if changed != 1:
            raise RuntimeFailure("INVOCATION_STATE_CONFLICT")

    def record_executor(self, invocation_id: str, value: dict[str, str]) -> None:
        required = {
            "unit_name",
            "machine_id_sha256",
            "boot_id",
            "launch_nonce",
            "journal_path",
            "journal_digest",
        }
        if set(value) != required or not all(isinstance(item, str) and item for item in value.values()):
            raise RuntimeFailure("EXECUTOR_RECORD_INVALID")
        now = utc_now()
        with self.connect() as db:
            try:
                db.execute(
                    """INSERT INTO invocation_executors
                       (invocation_id, executor_state, unit_name, machine_id_sha256,
                        boot_id, launch_nonce, journal_path, journal_digest,
                        last_unit_state, terminal_receipt_digest, created_at, updated_at)
                       VALUES (?, 'PREPARED', ?, ?, ?, ?, ?, ?, NULL, NULL, ?, ?)""",
                    (
                        invocation_id,
                        value["unit_name"],
                        value["machine_id_sha256"],
                        value["boot_id"],
                        value["launch_nonce"],
                        value["journal_path"],
                        value["journal_digest"],
                        now,
                        now,
                    ),
                )
            except sqlite3.IntegrityError as exc:
                raise RuntimeFailure("EXECUTOR_RECORD_CONFLICT") from exc

    def update_executor(
        self,
        invocation_id: str,
        state: str,
        *,
        last_unit_state: str | None = None,
        terminal_receipt_digest: str | None = None,
    ) -> None:
        allowed = {
            "PREPARED",
            "LAUNCHED",
            "RUNNING",
            "TERMINAL_RECEIPT_AVAILABLE",
            "FINALIZED",
            "EXECUTION_UNKNOWN",
        }
        if state not in allowed:
            raise RuntimeFailure("EXECUTOR_STATE_INVALID")
        with self.connect() as db:
            changed = db.execute(
                """UPDATE invocation_executors
                   SET executor_state=?, last_unit_state=COALESCE(?, last_unit_state),
                       terminal_receipt_digest=COALESCE(?, terminal_receipt_digest),
                       updated_at=?
                   WHERE invocation_id=?""",
                (state, last_unit_state, terminal_receipt_digest, utc_now(), invocation_id),
            ).rowcount
        if changed != 1:
            raise RuntimeFailure("EXECUTOR_RECORD_UNKNOWN")

    def executor(self, invocation_id: str) -> dict[str, Any]:
        with self.connect() as db:
            row = db.execute(
                "SELECT * FROM invocation_executors WHERE invocation_id=?", (invocation_id,)
            ).fetchone()
        if row is None:
            raise RuntimeFailure("EXECUTOR_RECORD_UNKNOWN")
        return dict(row)

    def pending_executors(self) -> list[dict[str, Any]]:
        with self.connect() as db:
            rows = db.execute(
                """SELECT e.* FROM invocation_executors e
                   JOIN invocations i ON i.id=e.invocation_id
                   WHERE i.status='running' AND e.executor_state!='FINALIZED'
                   ORDER BY e.created_at, e.invocation_id"""
            ).fetchall()
        return [dict(row) for row in rows]

    def mark_execution_unknown(self, invocation_id: str, detail: str) -> None:
        receipt = {
            "schema": "capy.execution-unknown-receipt/v0",
            "invocation_id": invocation_id,
            "status": "execution_unknown",
            "detail": detail,
            "recorded_at": utc_now(),
        }
        with self.connect() as db:
            changed = db.execute(
                """UPDATE invocations SET status='execution_unknown', receipt_json=?, completed_at=?
                   WHERE id=? AND status='running'""",
                (canonical_json(receipt).decode(), utc_now(), invocation_id),
            ).rowcount
            if changed == 1:
                db.execute(
                    """UPDATE invocation_executors SET executor_state='EXECUTION_UNKNOWN',
                              last_unit_state=?, updated_at=? WHERE invocation_id=?""",
                    (detail, utc_now(), invocation_id),
                )
        if changed != 1:
            raise RuntimeFailure("INVOCATION_STATE_CONFLICT")

    def invocation(self, invocation_id: str) -> dict[str, Any]:
        with self.connect() as db:
            row = db.execute("SELECT * FROM invocations WHERE id = ?", (invocation_id,)).fetchone()
        if row is None:
            raise RuntimeFailure("INVOCATION_UNKNOWN")
        return self._decode_invocation(row)

    @staticmethod
    def _decode_invocation(row: sqlite3.Row) -> dict[str, Any]:
        value = dict(row)
        for field in ("receipt_json", "result_json", "artifacts_json"):
            decoded = field.removesuffix("_json")
            value[decoded] = json.loads(value.pop(field)) if value.get(field) else None
        return value
