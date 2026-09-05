"""Small server-rendered, local-only owner chat product for Milestone 2."""

from __future__ import annotations

import argparse
import base64
import hashlib
import html
import json
import os
import pwd
import re
import secrets
import traceback
import urllib.parse
import threading
from dataclasses import asdict, replace
from datetime import datetime, timezone
from email.parser import BytesParser
from email.policy import default
from http import HTTPStatus
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

from .access import AccessStore, ActorContext, AuthenticatedClient
from .chat import ChatStore
from .controller import ProductController
from .encar_watcher_runtime import EncarWatcherLunaEvaluator, EncarWatcherRuntime, QueuedWatcherEvaluator
from .application_operations import ApplicationOperationRegistry
from .application_interfaces import ContractDerivedInterfaceService, watcher_interface_authority
from .interaction_contracts import InteractionContractRegistry
from .encar_watcher_operations import EncarWatcherOperationAdapter
from .connections import ConnectionControl, LocalSecretResolver
from .launcher import ExecutionIdentity, SystemdTransientLauncher
from .model import RuntimeFailure
from .presentation import (
    compact_conversation_title,
    present_application_result,
    presentation_binding_is_current,
)
from .runtime import OutcomeRuntime
from .semantic import OpenRouterLunaAdapter
from .semantic_dispatch import SemanticDispatcher, SemanticDispatchStore
from .store import RuntimeStore
from .team import TeamSoftwareStore
from .ui import (
    STANDARD_SCRIPT,
    STANDARD_SCRIPT_SHA256,
    WORKBENCH_CSS,
    UIAction,
    UIArtifact,
    UIConfirmation,
    UICollection,
    UIContext,
    UIEntity,
    UIFact,
    UINavItem,
    UINotice,
    UIStatus,
    render_activity,
    render_artifacts,
    render_collection,
    render_confirmation,
    render_message,
    render_chat_workspace,
    render_empty_conversation,
    render_mobile_workspace_switcher,
    render_notice,
    render_page_header,
    render_shell,
    render_shell_action,
    render_stack,
    render_workspace_switcher,
)
from .ui.render import SafeHtml
from .ui_compatibility import (
    COMPATIBILITY_CSS,
    COMPATIBILITY_STYLESHEET,
    compatibility_body,
)
from .world import WorldBuilder


MAX_BODY = 20 * 1024 * 1024
MAX_FILES = 4
MAX_FILE = 8 * 1024 * 1024
SAFE_DIGEST = re.compile(r"[0-9a-f]{64}")
REPOSITORY_ROOT = Path(__file__).resolve().parents[2]


def read_private(path: Path) -> str:
    metadata = path.lstat()
    value = path.read_text(encoding="utf-8").strip()
    if path.is_symlink() or not path.is_file() or metadata.st_mode & 0o777 not in {0o400, 0o600} or not value:
        raise RuntimeError(f"private input is invalid: {path}")
    return value


def linux_identity(name: str) -> ExecutionIdentity:
    account = pwd.getpwnam(name)
    return ExecutionIdentity(account.pw_name, account.pw_name, account.pw_uid, account.pw_gid)


def single_member_identity_resolver(
    runtime: RuntimeStore,
    static_identities: dict[str, ExecutionIdentity],
    member_identity: ExecutionIdentity | None,
):
    """Resolve one active generated member scope to one dedicated preview identity."""

    def resolve(scope_id: str) -> ExecutionIdentity:
        if scope_id in static_identities:
            return static_identities[scope_id]
        with runtime.connect() as db:
            requested = db.execute(
                """SELECT m.principal_id FROM access_memberships m
                   JOIN access_principals p ON p.id=m.principal_id
                   JOIN access_teams t ON t.id=m.team_id
                   WHERE m.execution_scope_id=? AND m.status='active'
                     AND p.status='active' AND t.status='active'""",
                (scope_id,),
            ).fetchone()
            if requested is None:
                raise KeyError(scope_id)
            principal_scopes = {
                row["execution_scope_id"]
                for row in db.execute(
                    """SELECT m.execution_scope_id FROM access_memberships m
                       JOIN access_teams t ON t.id=m.team_id
                       WHERE m.principal_id=? AND m.status='active' AND t.status='active'""",
                    (requested["principal_id"],),
                ).fetchall()
            }
            for static_scope, identity in static_identities.items():
                if static_scope in principal_scopes:
                    return identity
            nonstatic_principals = {
                row["principal_id"]
                for row in db.execute(
                    """SELECT DISTINCT m.principal_id FROM access_memberships m
                       JOIN access_principals p ON p.id=m.principal_id
                       JOIN access_teams t ON t.id=m.team_id
                       WHERE m.status='active' AND p.status='active' AND t.status='active'"""
                ).fetchall()
                if not {
                    item["execution_scope_id"]
                    for item in db.execute(
                        "SELECT execution_scope_id FROM access_memberships WHERE principal_id=? AND status='active'",
                        (row["principal_id"],),
                    ).fetchall()
                }.intersection(static_identities)
            }
        if (
            member_identity is None
            or nonstatic_principals != {requested["principal_id"]}
        ):
            raise KeyError(scope_id)
        return member_identity

    return resolve


def accepted_identity(path: Path) -> dict[str, str]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, ValueError, json.JSONDecodeError) as exc:
        raise RuntimeFailure("CAPABILITY_ACCEPTED_IDENTITY_REQUIRED") from exc
    legacy = {
        "application_archive_sha256", "devkit_wheel_sha256",
        "acceptance_receipt_sha256", "candidate_commit", "candidate_tree",
        "devkit_commit",
    }
    if (
        not isinstance(value, dict)
        or frozenset(value) not in {frozenset(legacy), frozenset(legacy | {"descriptor_sha256"})}
        or not all(isinstance(item, str) for item in value.values())
    ):
        raise RuntimeFailure("CAPABILITY_ACCEPTED_IDENTITY_REQUIRED")
    return value


def activate_accepted_fedex(
    store: RuntimeStore,
    control: ConnectionControl,
    *,
    application_archive: Path,
    acceptance_receipt: Path,
    devkit_wheel: Path,
    expected_identity: Path,
    connection_id: str,
    grant_id: str,
) -> tuple[Any, str, dict[str, str]]:
    """Publish and atomically select the exact accepted DevKit app for owner chat."""

    descriptor, version, publication = store.publish_devkit_archive(
        application_archive,
        acceptance_receipt.read_bytes(),
        devkit_wheel,
        expected_identity=accepted_identity(expected_identity),
    )
    control.grant(
        grant_id, connection_id, "owner", "fedex.rates/v1", ["quote"],
        capability_id=descriptor.id, version_digest=version,
    )
    store.bind("owner", descriptor.id, version, {"fedex_rates": grant_id})
    return descriptor, version, publication


class Product:
    def __init__(
        self, args: argparse.Namespace, *, generic_build_coordinator: Any | None = None
    ):
        self.scope = "owner"
        self.runtime_store = RuntimeStore(args.runtime_root)
        self.access_store = AccessStore(self.runtime_store)
        self.chat_store = ChatStore(args.chat_database)
        dispatch_enabled = bool(getattr(args, "semantic_dispatch", False))
        self.semantic_dispatch_store = (
            SemanticDispatchStore(args.chat_database) if dispatch_enabled else None
        )
        self.team_software = TeamSoftwareStore(self.runtime_store, self.access_store)
        self.access_store.set_membership_reconciler(self.team_software.reconcile_team)
        identities = {
            "owner": linux_identity(args.owner_user),
            "beta": linux_identity(args.beta_user),
        }
        for scope in identities:
            self.runtime_store.register_scope(scope)
        acceptance = args.acceptance_receipt.read_bytes()
        descriptor, version = self.runtime_store.publish(args.csv_capability, acceptance)
        for scope in identities:
            self.runtime_store.bind(scope, descriptor.id, version, {})
        self.connection_control = ConnectionControl(self.runtime_store)
        fedex_descriptor, fedex_version, _fedex_publication = activate_accepted_fedex(
            self.runtime_store,
            self.connection_control,
            application_archive=args.fedex_application_archive,
            acceptance_receipt=args.fedex_acceptance_receipt,
            devkit_wheel=args.fedex_devkit_wheel,
            expected_identity=args.fedex_expected_identity,
            connection_id=args.fedex_connection_id,
            grant_id=args.fedex_grant_id,
        )
        member_user = getattr(args, "member_user", None)
        member_identity = linux_identity(member_user) if member_user else None
        identity_resolver = single_member_identity_resolver(
            self.runtime_store, identities, member_identity
        )
        launcher = SystemdTransientLauncher(identity_resolver)
        connection_status = lambda scope, grant: (
            self.connection_control.status(scope, grant)
            if args.connection_socket.exists() else "unavailable"
        )
        def connection_inventory(scope: str) -> list[dict[str, Any]]:
            items = self.connection_control.inventory(scope)
            if not args.connection_socket.exists():
                return [{**item, "status": "unavailable"} for item in items]
            return items
        runtime = OutcomeRuntime(
            self.runtime_store, launcher=launcher,
            connection_control=self.connection_control,
            broker_socket=args.connection_socket,
        )
        self.startup_reconciliation = runtime.reconcile_incomplete()
        semantic = OpenRouterLunaAdapter(args.provider_credential)
        self.encar_watcher = None
        watcher_provider = None
        watcher_executable = getattr(args, "encar_watcher_executable", None)
        watcher_state_root = getattr(args, "encar_watcher_state_root", None)
        watcher_team_id = getattr(args, "encar_watcher_team_id", None)
        if any(item is not None for item in (watcher_executable, watcher_state_root, watcher_team_id)):
            if not all(item is not None for item in (watcher_executable, watcher_state_root, watcher_team_id)):
                raise RuntimeFailure("ENCAR_WATCHER_CONFIGURATION_INVALID")
            watcher_provider = EncarWatcherLunaEvaluator(args.provider_credential)
            watcher_evaluator = (
                QueuedWatcherEvaluator(self.semantic_dispatch_store)
                if self.semantic_dispatch_store is not None else watcher_provider
            )
            self.encar_watcher = EncarWatcherRuntime(
                self.runtime_store, self.chat_store, self.access_store,
                watcher_executable, watcher_state_root,
                watcher_evaluator,
            )
            self.encar_watcher.install_team(watcher_team_id)
        self.interaction_contracts = InteractionContractRegistry()
        world = WorldBuilder(
            self.runtime_store,
            connection_status=connection_status,
            connection_inventory=connection_inventory,
            team_software=self.team_software.software_for_actor,
            team_applications=None,
            interaction_contracts=self.interaction_contracts.for_world,
        )
        application_operations = (
            ApplicationOperationRegistry([EncarWatcherOperationAdapter(self.encar_watcher)])
            if self.encar_watcher else None
        )
        if application_operations is not None:
            world.team_applications = application_operations.world_capabilities
        self.controller = ProductController(
            self.runtime_store,
            self.chat_store,
            runtime,
            world,
            semantic,
            builder=None,
            generic_build_coordinator=None,
            encar_watcher_runtime=self.encar_watcher,
            application_operations=application_operations,
            semantic_dispatch=self.semantic_dispatch_store,
            actor_resolver=self.access_store.resolve_actor,
            interaction_contracts=self.interaction_contracts,
        )
        self.application_interfaces = ContractDerivedInterfaceService(
            self.runtime_store,
            self.chat_store,
            runtime,
            application_operations,
            self.controller.application_contract,
            self.access_store.guarded_actor,
            (
                lambda actor, watch_id: watcher_interface_authority(
                    self.encar_watcher, actor, watch_id
                )
                if self.encar_watcher is not None
                else None
            ),
            (
                lambda actor, watch_id: next(
                    (
                        item for item in self.encar_watcher.stored_watches(actor)
                        if item.get("id") == watch_id
                    ),
                    None,
                )
                if self.encar_watcher is not None
                else None
            ),
        )
        self.semantic_dispatcher = None
        self.semantic_dispatch_stop = None
        self.semantic_dispatch_thread = None
        if self.semantic_dispatch_store is not None:
            providers = {"chat_turn": self.controller.provide_chat_semantic}
            consumers = {"chat_turn": self.controller.consume_chat_semantic}
            failures = {"chat_turn": self.controller.consume_chat_semantic_failure}
            if watcher_provider is not None:
                providers["watcher_judgment"] = lambda payload: asdict(
                    watcher_provider.evaluate(payload["request"])
                )
                consumers["watcher_judgment"] = lambda _job, _result: None
                failures["watcher_judgment"] = lambda _job: None
            self.semantic_dispatcher = SemanticDispatcher(
                self.semantic_dispatch_store, providers, consumers, failures
            )
            self.semantic_dispatch_stop = threading.Event()
            self.semantic_dispatch_thread = threading.Thread(
                target=self.semantic_dispatcher.serve,
                args=(self.semantic_dispatch_stop,),
                name="capy-semantic-dispatcher",
                daemon=True,
            )
            self.semantic_dispatch_thread.start()
        self.version = version
        self.fedex_version = fedex_version
        wheel = args.runtime_root / "team-acceptance" / "devkit.whl"
        wheel.parent.mkdir(parents=True, exist_ok=True)
        wheel_payload = base64.b64decode(args.invoice_devkit_wheel_base64.read_bytes())
        if wheel.exists() and wheel.read_bytes() != wheel_payload:
            raise RuntimeFailure("DEVKIT_WHEEL_DIGEST_MISMATCH")
        if not wheel.exists():
            wheel.write_bytes(wheel_payload)
            wheel.chmod(0o400)
        self.invoice_descriptor, self.invoice_version, self.invoice_publication = (
            self.runtime_store.publish_devkit_archive(
                args.invoice_application_archive,
                args.invoice_acceptance_receipt.read_bytes(),
                wheel,
                expected_identity=accepted_identity(args.invoice_expected_identity),
            )
        )
        def provision_personal_workspace(actor: ActorContext) -> None:
            try:
                identity_resolver(actor.execution_scope_id)
            except KeyError:
                return
            if self.encar_watcher is not None:
                try:
                    self.encar_watcher.installation(actor)
                except RuntimeFailure as exc:
                    if exc.code != "ENCAR_WATCHER_NOT_INSTALLED":
                        raise
                    self.encar_watcher.install(actor)
            try:
                personal_invoice = self.team_software.share(
                    actor, self.invoice_descriptor.id
                )
            except RuntimeFailure as exc:
                if exc.code != "TEAM_SOFTWARE_UNKNOWN":
                    raise
                self.team_software.share_software(
                    actor, self.invoice_descriptor.id, self.invoice_version
                )
            else:
                if personal_invoice.version_digest != self.invoice_version:
                    raise RuntimeFailure("TEAM_BINDING_VERSION_CONFLICT")

        self.access_store.set_personal_workspace_reconciler(provision_personal_workspace)
        for personal_actor in self.access_store.personal_workspace_actors():
            provision_personal_workspace(personal_actor)
        self.team_startup_reconciliation = self.team_software.reconcile_all()
        self.origin = f"http://{args.bind}:{args.port}"

    def close(self) -> None:
        if self.semantic_dispatch_stop is not None:
            self.semantic_dispatch_stop.set()
        if self.semantic_dispatch_thread is not None:
            self.semantic_dispatch_thread.join(timeout=5)


STYLE = WORKBENCH_CSS + COMPATIBILITY_CSS


from .ui.enhancements import CHAT_ENHANCEMENT, FORM_PROTECTION_ENHANCEMENT


def workbench_script_sha256(enhancement: str = "") -> str:
    return base64.b64encode(
        hashlib.sha256((STANDARD_SCRIPT + enhancement).encode("utf-8")).digest()
    ).decode("ascii")


CHAT_SCRIPT_SHA256 = workbench_script_sha256(CHAT_ENHANCEMENT)
APPLICATION_SCRIPT_SHA256 = workbench_script_sha256(FORM_PROTECTION_ENHANCEMENT)


def human_timestamp(value: object, empty: str) -> str:
    if value in {None, ""}:
        return empty
    moment: datetime | None = None
    if type(value) in {int, float}:
        try:
            moment = datetime.fromtimestamp(float(value), timezone.utc)
        except (OverflowError, OSError, ValueError):
            moment = None
    elif isinstance(value, str):
        try:
            moment = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            moment = None
    if moment is None:
        return "Recorded"
    return moment.astimezone(timezone.utc).strftime("%b %-d, %Y · %H:%M UTC")


def render_problem_card(metadata: dict[str, Any]) -> SafeHtml:
    retryable = metadata.get("retryable")
    retry_label = {
        False: "No",
        True: "Yes",
        "after_input_change": "After changing the input",
    }.get(retryable, "No")
    facts = [
        UIFact("Category", str(metadata["category"]), "technical"),
        UIFact("Retry", retry_label, "technical"),
        UIFact("Responsible", str(metadata.get("responsible_party", "capy")), "technical"),
        UIFact("Problem reference", str(metadata.get("problem_reference", "")), "technical"),
    ]
    if metadata.get("capability_id"):
        facts.append(UIFact("Application", str(metadata["capability_id"]), "technical"))
    return render_notice(UINotice(
        "error",
        str(metadata.get("title", "Request not completed")),
        " ".join(filter(None, (
            str(metadata.get("explanation", "")), str(metadata.get("next_action", "")),
        ))),
        what_did_not_happen=str(metadata.get("effect_statement") or "No result or external action should be assumed."),
        technical_details=tuple(facts),
    ))


def safe_render_incident(exc: Exception) -> dict[str, Any]:
    package_root = Path(__file__).resolve().parent
    frames = []
    parts = []
    for frame in traceback.extract_tb(exc.__traceback__):
        path = Path(frame.filename).resolve()
        try:
            relative = path.relative_to(package_root)
        except ValueError:
            continue
        value = {
            "file": relative.as_posix(),
            "line": frame.lineno,
            "function": frame.name[:128],
        }
        frames.append(value)
        parts.append(f"{value['file']}:{value['line']}:{value['function']}")
    return {
        "schema": "capy.problem-render-incident/v0",
        "component": "problem_renderer",
        "exception_type": type(exc).__name__,
        "traceback_sha256": hashlib.sha256("\n".join(parts).encode()).hexdigest(),
        "internal_frames": frames[-12:],
    }


def safe_problem_card(problem_reference: str) -> SafeHtml:
    return render_notice(UINotice(
        "error", "Capy could not display the full problem details.",
        "Contact the Capy operator with the problem reference.",
        what_did_not_happen="No result or external action should be assumed.",
        technical_details=(
            UIFact("Category", "INTERNAL_PROBLEM", "technical"),
            UIFact("Retry", "No", "technical"),
            UIFact("Responsible", "capy", "technical"),
            UIFact("Problem reference", problem_reference, "technical"),
        ),
    ))


class Handler(BaseHTTPRequestHandler):
    server: "ProductServer"

    def log_message(self, format: str, *args: Any) -> None:
        message = format % args
        message = re.sub(r"/claim/[^ ?\"]+", "/claim/[REDACTED]", message)
        message = re.sub(r"\?[^ ]+", "?[REDACTED]", message)
        print(f"web {self.address_string()} {message}")

    @property
    def product(self) -> Product:
        return self.server.product

    def send_html(
        self,
        value: str,
        status: int = 200,
        headers: dict[str, str] | None = None,
        *,
        script_sha256: str | None = STANDARD_SCRIPT_SHA256,
    ) -> None:
        payload = value.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        script_policy = (
            f"; script-src 'sha256-{script_sha256}'; connect-src 'self'"
            if script_sha256 else ""
        )
        self.send_header(
            "Content-Security-Policy",
            "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; "
            f"base-uri 'none'; frame-ancestors 'none'{script_policy}",
        )
        self.send_header("Referrer-Policy", "no-referrer")
        for name, item in (headers or {}).items():
            self.send_header(name, item)
        self.end_headers()
        self.wfile.write(payload)

    def redirect(self, location: str, headers: dict[str, str] | None = None) -> None:
        self.send_response(303)
        self.send_header("Location", location)
        self.send_header("Cache-Control", "no-store")
        for name, value in (headers or {}).items():
            self.send_header(name, value)
        self.end_headers()

    def client_credential(self) -> str | None:
        cookie = SimpleCookie(self.headers.get("Cookie", ""))
        value = cookie.get("capy_client")
        return value.value if value else None

    def authenticated(self) -> AuthenticatedClient | None:
        credential = self.client_credential()
        if credential is None:
            return None
        try:
            return self.product.access_store.authenticate_client(credential)
        except RuntimeFailure:
            return None

    def require_actor(self, conversation_id: str | None = None) -> AuthenticatedClient | None:
        authenticated = self.authenticated()
        if authenticated is None:
            self.redirect("/access-required")
            return None
        if conversation_id:
            binding = self.product.chat_store.conversation_authority(conversation_id)
            actor = self.product.access_store.resolve_actor(
                authenticated.actor.client_id, binding["membership_id"]
            )
            if (
                actor.principal_id != binding["principal_id"]
                or actor.team_id != binding["team_id"]
                or actor.execution_scope_id != binding["scope_id"]
            ):
                raise RuntimeFailure("CONVERSATION_NOT_IN_SCOPE")
            authenticated = AuthenticatedClient(actor, authenticated.csrf_token, authenticated.client_label)
        return authenticated

    def body(self) -> bytes:
        try:
            length = int(self.headers.get("Content-Length", "-1"))
        except ValueError as exc:
            raise RuntimeFailure("HTTP_BODY_INVALID") from exc
        if not 0 <= length <= MAX_BODY:
            raise RuntimeFailure("HTTP_BODY_TOO_LARGE")
        payload = self.rfile.read(length)
        if len(payload) != length:
            raise RuntimeFailure("HTTP_BODY_INVALID")
        return payload

    def urlencoded(self) -> dict[str, str]:
        if self.headers.get_content_type() != "application/x-www-form-urlencoded":
            raise RuntimeFailure("HTTP_FORM_INVALID")
        values = urllib.parse.parse_qs(self.body().decode("utf-8"), strict_parsing=True)
        if any(len(items) != 1 for items in values.values()):
            raise RuntimeFailure("HTTP_FORM_INVALID")
        return {key: items[0] for key, items in values.items()}

    def multipart(self) -> tuple[dict[str, str], list[tuple[str, str, bytes]]]:
        content_type = self.headers.get("Content-Type", "")
        if not content_type.startswith("multipart/form-data;"):
            raise RuntimeFailure("HTTP_FORM_INVALID")
        message = BytesParser(policy=default).parsebytes(
            b"Content-Type: " + content_type.encode("ascii") + b"\r\nMIME-Version: 1.0\r\n\r\n" + self.body()
        )
        fields: dict[str, str] = {}
        files = []
        for part in message.iter_parts():
            name = part.get_param("name", header="content-disposition")
            filename = part.get_filename()
            payload = part.get_payload(decode=True) or b""
            if filename is None:
                fields[name] = payload.decode("utf-8")
                continue
            # Browsers submit an untouched file input as filename="" with no
            # payload.  That is the absence of an upload, not an invalid one.
            if filename == "" and payload == b"":
                continue
            safe = Path(filename).name
            if (
                not safe
                or safe != filename
                or any(char in safe for char in "\x00\r\n")
                or len(payload) > MAX_FILE
            ):
                raise RuntimeFailure("UPLOAD_INVALID")
            files.append((safe, part.get_content_type(), payload))
        if len(files) > MAX_FILES:
            raise RuntimeFailure("UPLOAD_TOO_MANY_FILES")
        return fields, files

    def multipart_named(self) -> tuple[dict[str, str], dict[str, tuple[str, str, bytes]]]:
        """Parse one exact application form without losing file-field identity."""
        content_type = self.headers.get("Content-Type", "")
        if (not content_type.startswith("multipart/form-data;") or not content_type.isascii()
            or any(char in content_type for char in "\r\n")):
            raise RuntimeFailure("HTTP_FORM_INVALID")
        message = BytesParser(policy=default).parsebytes(
            b"Content-Type: " + content_type.encode("ascii", "strict")
            + b"\r\nMIME-Version: 1.0\r\n\r\n" + self.body()
        )
        if not message.is_multipart() or message.defects:
            raise RuntimeFailure("HTTP_FORM_INVALID")
        fields: dict[str, str] = {}
        files: dict[str, tuple[str, str, bytes]] = {}
        for part in message.iter_parts():
            if part.is_multipart() or part.defects or part.get_content_disposition() != "form-data":
                raise RuntimeFailure("HTTP_FORM_INVALID")
            name = part.get_param("name", header="content-disposition")
            if not isinstance(name, str) or not name or name in fields:
                raise RuntimeFailure("HTTP_FORM_INVALID")
            filename = part.get_filename()
            payload = part.get_payload(decode=True) or b""
            if part.defects or len(part.get_all("Content-Disposition", [])) != 1:
                raise RuntimeFailure("HTTP_FORM_INVALID")
            if filename is None:
                if name in files:
                    raise RuntimeFailure("HTTP_FORM_INVALID")
                try:
                    fields[name] = payload.decode("utf-8")
                except UnicodeError as exc:
                    raise RuntimeFailure("HTTP_FORM_INVALID") from exc
                continue
            if filename == "" and payload == b"":
                continue
            safe = Path(filename).name
            if (
                not safe or safe != filename or any(char in safe for char in "\x00\r\n")
                or len(payload) > MAX_FILE
            ):
                raise RuntimeFailure("UPLOAD_INVALID")
            entry = (safe, part.get_content_type(), payload)
            if name in files:
                prior = files[name]
                files[name] = (prior if isinstance(prior, list) else [prior]) + [entry]
            else:
                files[name] = entry
        if sum(len(value) if isinstance(value, list) else 1 for value in files.values()) > MAX_FILES:
            raise RuntimeFailure("UPLOAD_TOO_MANY_FILES")
        return fields, files

    def require_origin(self) -> None:
        origin = self.headers.get("Origin")
        if origin == self.product.origin:
            return
        expected_host = urllib.parse.urlsplit(self.product.origin).netloc
        sandboxed_same_origin = (
            origin == "null"
            and self.headers.get("Host") == expected_host
            and self.headers.get("Sec-Fetch-Site") == "same-origin"
            and self.headers.get("Sec-Fetch-Mode") == "navigate"
        )
        if not sandboxed_same_origin:
            raise RuntimeFailure("HTTP_ORIGIN_DENIED")

    def require_post(self, authenticated: AuthenticatedClient, csrf: str) -> None:
        self.require_origin()
        if not secrets.compare_digest(csrf, authenticated.csrf_token):
            raise RuntimeFailure("HTTP_CSRF_DENIED")

    def do_GET(self) -> None:
        parsed = urllib.parse.urlsplit(self.path)
        if parsed.path == "/health":
            self.send_html("ok")
            return
        if parsed.path == "/login":
            self.redirect("/access-required")
            return
        if parsed.path == "/access-required":
            self.send_html(self.access_required_page())
            return
        try:
            if parsed.path.startswith("/claim/"):
                token = parsed.path.removeprefix("/claim/")
                preview = self.product.access_store.inspect_claim(token)
                self.send_html(self.claim_page(token, preview))
                return
            query = urllib.parse.parse_qs(parsed.query)
            if parsed.path == "/":
                conversation = query.get("conversation", [None])[0]
                authenticated = self.require_actor(conversation)
                if authenticated is not None:
                    self.send_html(
                        self.chat_page(authenticated, conversation),
                        script_sha256=CHAT_SCRIPT_SHA256,
                    )
            elif parsed.path == "/access":
                authenticated = self.require_actor()
                if authenticated is not None:
                    self.send_html(self.access_page(authenticated))
            elif parsed.path == "/team":
                authenticated = self.require_actor()
                if authenticated is not None:
                    self.send_html(self.team_page(authenticated))
            elif parsed.path == "/world":
                conversation = query.get("conversation", [""])[0]
                authenticated = self.require_actor(conversation)
                if authenticated is not None:
                    snapshot = self.product.controller.snapshot(authenticated.actor, conversation)
                    self.send_html(self.world_page(authenticated, conversation, snapshot.value, snapshot.digest))
            elif parsed.path == "/applications":
                authenticated = self.require_actor()
                if authenticated is not None:
                    requested = query.get("workspace", [None])[0]
                    if requested and requested != authenticated.actor.membership_id:
                        target = self.product.access_store.resolve_actor(
                            authenticated.actor.client_id, requested
                        )
                        if target.principal_id != authenticated.actor.principal_id:
                            raise RuntimeFailure("ACCESS_AUTHORITY_DENIED")
                        self.send_html(self.workspace_handoff_page(
                            authenticated, target, parsed.path + "?" + parsed.query
                        ))
                        return
                    self.send_html(self.applications_page(authenticated))
            elif re.fullmatch(r"/applications/[^/]+/listings/[0-9a-f]{64}", parsed.path):
                parts = parsed.path.split("/")
                application_id = urllib.parse.unquote(parts[2])
                reference = parts[4]
                authenticated = self.require_actor()
                if authenticated is not None:
                    requested = query.get("workspace", [None])[0]
                    if requested and requested != authenticated.actor.membership_id:
                        target = self.product.access_store.resolve_actor(
                            authenticated.actor.client_id, requested
                        )
                        if target.principal_id != authenticated.actor.principal_id:
                            raise RuntimeFailure("ACCESS_AUTHORITY_DENIED")
                        self.send_html(self.workspace_handoff_page(
                            authenticated, target, parsed.path + "?" + parsed.query,
                            application_id=application_id,
                        ))
                        return
                    if application_id != "vehicles.encar_watcher":
                        raise RuntimeFailure("INTERACTION_CONTRACT_UNKNOWN_APPLICATION")
                    page = self.product.application_interfaces.watcher_listings(
                        authenticated.actor, reference
                    )
                    self.send_html(self.watcher_listings_page(authenticated, page))
            elif re.fullmatch(r"/applications/[^/]+/activity/[0-9a-f]{32}", parsed.path):
                parts = parsed.path.split("/")
                application_id = urllib.parse.unquote(parts[2])
                activity_id = parts[4]
                authenticated = self.require_actor()
                if authenticated is not None:
                    result = self.product.application_interfaces.activity(
                        authenticated.actor, application_id, activity_id
                    )
                    self.send_html(
                        self.application_activity_page(
                            authenticated, application_id, result
                        )
                    )
            elif parsed.path.startswith("/applications/"):
                application_id = urllib.parse.unquote(parsed.path.removeprefix("/applications/"))
                authenticated = self.require_actor()
                if authenticated is not None:
                    requested = query.get("workspace", [None])[0]
                    if requested and requested != authenticated.actor.membership_id:
                        target = self.product.access_store.resolve_actor(
                            authenticated.actor.client_id, requested
                        )
                        if target.principal_id != authenticated.actor.principal_id:
                            raise RuntimeFailure("ACCESS_AUTHORITY_DENIED")
                        self.send_html(self.workspace_handoff_page(
                            authenticated, target, parsed.path + "?" + parsed.query,
                            application_id=application_id,
                        ))
                        return
                    self.send_html(
                        self.application_page(authenticated, application_id),
                        script_sha256=APPLICATION_SCRIPT_SHA256,
                    )
            elif parsed.path.startswith("/application-artifact/"):
                parts = parsed.path.split("/")
                if len(parts) != 4:
                    raise RuntimeFailure("APPLICATION_INTERFACE_ARTIFACT_DENIED")
                authenticated = self.require_actor()
                if authenticated is not None:
                    names = query.get("filename", [])
                    if len(names) > 1 or set(query) - {"filename"}:
                        raise RuntimeFailure("APPLICATION_INTERFACE_ARTIFACT_DENIED")
                    self.application_artifact(authenticated.actor, parts[2], parts[3], names[0] if names else None)
            elif parsed.path.startswith("/resource/"):
                digest = parsed.path.removeprefix("/resource/")
                conversation = query.get("conversation", [""])[0]
                authenticated = self.require_actor(conversation)
                if authenticated is not None:
                    self.download(authenticated.actor, conversation, digest)
            else:
                self.send_error(404)
        except RuntimeFailure:
            self.send_error(404)

    def do_POST(self) -> None:
        parsed = urllib.parse.urlsplit(self.path)
        application_context: tuple[AuthenticatedClient, str] | None = None
        try:
            if parsed.path.startswith("/claim/"):
                self.require_origin()
                form = self.urlencoded()
                token = parsed.path.removeprefix("/claim/")
                redemption = self.product.access_store.redeem_claim(
                    token,
                    display_name=form.get("display_name"),
                    current_credential=self.client_credential(),
                    client_label=form.get("client_label", "Browser"),
                )
                if redemption.actor.membership_kind == "owner" and redemption.actor.execution_scope_id == "owner":
                    self.product.chat_store.adopt_legacy_owner(redemption.actor)
                headers = {}
                if redemption.credential is not None:
                    secure = "; Secure" if self.product.origin.startswith("https://") else ""
                    headers["Set-Cookie"] = (
                        f"capy_client={redemption.credential}; HttpOnly; SameSite=Strict; Path=/{secure}"
                    )
                self.redirect("/", headers)
                return
            authenticated = self.require_actor()
            if authenticated is None:
                return
            if parsed.path == "/conversations":
                form = self.urlencoded()
                self.require_post(authenticated, form.get("csrf", ""))
                workspace = self.product.access_store.resolve_actor(
                    authenticated.actor.client_id,
                    form.get("workspace", authenticated.actor.membership_id),
                )
                if workspace.principal_id != authenticated.actor.principal_id:
                    raise RuntimeFailure("ACCESS_AUTHORITY_DENIED")
                conversation = self.product.chat_store.create_conversation(workspace)
                self.redirect("/?conversation=" + conversation)
            elif parsed.path == "/workspaces/activate":
                form = self.urlencoded()
                self.require_post(authenticated, form.get("csrf", ""))
                self.product.access_store.activate_membership(
                    authenticated.actor, form.get("workspace", "")
                )
                return_to = form.get("return_to", "/")
                target = urllib.parse.urlsplit(return_to)
                if (
                    not return_to.startswith("/")
                    or return_to.startswith("//")
                    or target.scheme or target.netloc
                    or (target.path != "/" and not target.path.startswith("/applications"))
                ):
                    return_to = "/"
                self.redirect(return_to)
            elif parsed.path == "/messages":
                fields, files = self.multipart()
                self.require_post(authenticated, fields.get("csrf", ""))
                text = fields.get("text", "").strip()
                conversation = fields.get("conversation", "")
                if not text:
                    raise RuntimeFailure("CHAT_MESSAGE_INVALID")
                exact = self.require_actor(conversation)
                if exact is None:
                    return
                submission = fields.get("submission", "")
                if self.product.chat_store.claim_message_submission(
                    exact.actor, conversation, submission
                ):
                    turn_id = self.product.controller.submit(
                        exact.actor, conversation, text, files
                    )
                    self.product.chat_store.complete_message_submission(submission, turn_id)
                self.redirect("/?conversation=" + urllib.parse.quote(conversation))
            elif parsed.path.startswith("/applications/") and "/operations/" in parsed.path:
                prefix, operation_id = parsed.path.rsplit("/operations/", 1)
                application_id = urllib.parse.unquote(prefix.removeprefix("/applications/"))
                operation_id = urllib.parse.unquote(operation_id)
                application_context = (authenticated, application_id)
                fields, files = self.multipart_named()
                self.require_post(authenticated, fields.get("csrf", ""))
                result = self.product.application_interfaces.submit(
                    authenticated.actor, application_id, operation_id, fields, files
                )
                self.redirect(
                    f"/applications/{urllib.parse.quote(application_id, safe='')}/activity/"
                    + urllib.parse.quote(result["activity_id"], safe="")
                )
            elif parsed.path == "/access/invitations":
                form = self.urlencoded()
                self.require_post(authenticated, form.get("csrf", ""))
                claim = self.product.access_store.create_join_team_claim(authenticated.actor)
                self.send_html(self.link_page("Invite teammate", claim["token"], authenticated))
            elif parsed.path == "/access/device-links":
                form = self.urlencoded()
                self.require_post(authenticated, form.get("csrf", ""))
                claim = self.product.access_store.create_attach_client_claim(authenticated.actor)
                self.send_html(self.link_page("Link another device", claim["token"], authenticated))
            elif parsed.path == "/access/memberships/activate":
                form = self.urlencoded()
                self.require_post(authenticated, form.get("csrf", ""))
                self.product.access_store.activate_membership(authenticated.actor, form.get("membership_id", ""))
                self.redirect("/access")
            elif parsed.path == "/access/clients/revoke":
                form = self.urlencoded()
                self.require_post(authenticated, form.get("csrf", ""))
                self.product.access_store.revoke_client(authenticated.actor, form.get("client_id", ""))
                self.redirect("/access")
            elif parsed.path == "/access/memberships/revoke":
                form = self.urlencoded()
                self.require_post(authenticated, form.get("csrf", ""))
                self.product.access_store.revoke_membership(authenticated.actor, form.get("membership_id", ""))
                self.redirect("/access")
            elif parsed.path == "/access/claims/revoke":
                form = self.urlencoded()
                self.require_post(authenticated, form.get("csrf", ""))
                self.product.access_store.revoke_claim(authenticated.actor, form.get("claim_id", ""))
                self.redirect("/access")
            elif parsed.path == "/team/software/share":
                form = self.urlencoded()
                self.require_post(authenticated, form.get("csrf", ""))
                self.product.team_software.share_software(
                    authenticated.actor,
                    self.product.invoice_descriptor.id,
                    self.product.invoice_version,
                )
                self.redirect("/team")
            elif parsed.path == "/team/software/revoke":
                form = self.urlencoded()
                self.require_post(authenticated, form.get("csrf", ""))
                self.product.team_software.revoke_software(
                    authenticated.actor, self.product.invoice_descriptor.id
                )
                self.redirect("/team")
            else:
                self.send_error(404)
        except RuntimeFailure as exc:
            if application_context is not None:
                current, application_id = application_context
                self.send_html(
                    self.application_error_page(current, application_id, exc),
                    status=(403 if exc.code == "APPLICATION_ACCESS_DENIED" else 409),
                )
            else:
                self.send_html(
                    f"<h1>Request could not be accepted</h1><p>{html.escape(exc.code)}</p>",
                    status=400,
                )

    def access_required_page(self) -> str:
        return f"<!doctype html><meta charset=utf-8><title>Capy access required</title><style>{STYLE}</style><div class=login><h1>Capy</h1><p>This browser is not connected to Capy.</p><p>Open a Capy invitation or device-link URL.</p></div>"

    def claim_page(self, token: str, preview: Any) -> str:
        authenticated = self.authenticated()
        if (
            preview.claim_type == "attach_client"
            and authenticated is not None
            and authenticated.actor.principal_id == preview.target_principal_id
        ):
            return f'<!doctype html><meta charset=utf-8><title>Capy access</title><style>{STYLE}</style><div class=login><h1>{html.escape(preview.title)}</h1><p>This browser is already linked.</p><p><a href=/access>View access</a></p></div>'
        name = (
            '<label>Your name<input name=display_name autocomplete=name required maxlength=100></label>'
            if preview.needs_display_name and authenticated is None else ""
        )
        return f'<!doctype html><meta charset=utf-8><title>Capy access</title><style>{STYLE}</style><div class=login><h1>{html.escape(preview.title)}</h1><form method=post action="/claim/{urllib.parse.quote(token)}">{name}<label>Browser label<input name=client_label value="Browser" maxlength=100></label><button>Continue</button></form></div>'

    def link_page(self, title: str, token: str, authenticated: AuthenticatedClient) -> str:
        url = self.product.origin.rstrip("/") + "/claim/" + token
        return f'<!doctype html><meta charset=utf-8><title>{html.escape(title)}</title><style>{STYLE}</style><div class=login><a href=/access>← Access</a><h1>{html.escape(title)}</h1><p>This one-time URL is shown only now.</p><pre>{html.escape(url)}</pre></div>'

    def access_page(self, authenticated: AuthenticatedClient) -> str:
        overview = self.product.access_store.overview(authenticated.actor)
        actor = overview["actor"]
        csrf = html.escape(authenticated.csrf_token)
        memberships = []
        for item in overview["memberships"]:
            action = ""
            if item["status"] == "active" and item["id"] != actor.membership_id:
                action = f'<form method=post action=/access/memberships/activate><input type=hidden name=csrf value="{csrf}"><input type=hidden name=membership_id value="{html.escape(item["id"])}"><button class=secondary>Use workspace</button></form>'
            memberships.append(
                f'<div class=card><strong>{html.escape(item["team_name"])}</strong> · {html.escape(item["kind"])} · {html.escape(item["status"])}{action}</div>'
            )
        clients = []
        for item in overview["clients"]:
            action = ""
            if item["status"] == "active":
                action = f'<form method=post action=/access/clients/revoke><input type=hidden name=csrf value="{csrf}"><input type=hidden name=client_id value="{html.escape(item["id"])}"><button class=secondary>Revoke</button></form>'
            clients.append(f'<div class=card>{html.escape(item["label"])} · {html.escape(item["status"])}{action}</div>')
        members = ""
        if actor.workspace_kind == "team" and actor.membership_kind == "owner":
            rows = []
            for item in overview["members"]:
                action = ""
                if item["status"] == "active" and item["id"] != actor.membership_id:
                    action = f'<form method=post action=/access/memberships/revoke><input type=hidden name=csrf value="{csrf}"><input type=hidden name=membership_id value="{html.escape(item["id"])}"><button class=secondary>Revoke member</button></form>'
                rows.append(f'<div class=card>{html.escape(item["display_name"])} · {html.escape(item["kind"])} · {html.escape(item["status"])}{action}</div>')
            members = f'<h2>Team members</h2>{"".join(rows)}<form method=post action=/access/invitations><input type=hidden name=csrf value="{csrf}"><button>Invite teammate</button></form>'
        team_link = " · <a href=/team>Team software</a>" if actor.workspace_kind == "team" else ""
        return f'''<!doctype html><meta charset=utf-8><title>Capy access</title><style>{STYLE}</style><div class=login style="max-width:760px;margin-top:5vh"><a href=/>← Capy</a>{team_link}<h1>Access</h1><p>{html.escape(actor.principal_display_name)} · {html.escape(actor.team_name)}</p><h2>Workspaces</h2>{"".join(memberships)}<h2>Authorized clients</h2>{"".join(clients)}<form method=post action=/access/device-links><input type=hidden name=csrf value="{csrf}"><button>Link another device</button></form>{members}</div>'''

    def team_page(self, authenticated: AuthenticatedClient) -> str:
        actor = authenticated.actor
        if actor.workspace_kind != "team":
            return '<!doctype html><meta charset=utf-8><title>Team software</title><style>' + STYLE + '</style><div class=login><a href=/access>← Access</a><h1>Select a team workspace</h1><p>Team software is managed from an active Team workspace. Personal software remains private to you.</p></div>'
        csrf = html.escape(authenticated.csrf_token)
        try:
            shares = self.product.team_software.software_for_actor(actor)
        except RuntimeFailure as exc:
            if exc.code != "TEAM_BINDING_MISSING":
                raise
            shares = []
        rows = "".join(
            f'<div class=card><strong>{html.escape(item.capability_id)}</strong><br>{html.escape(item.version_digest)}<br>Shared by {html.escape(item.shared_by)} · Maintained by {html.escape(item.maintained_by)}</div>'
            for item in shares
        ) or '<p>No team software is shared yet.</p>'
        actions = ""
        if actor.membership_kind == "owner":
            if shares:
                actions = f'<form method=post action=/team/software/revoke><input type=hidden name=csrf value="{csrf}"><button>Revoke Proforma invoice</button></form>'
            else:
                actions = f'<form method=post action=/team/software/share><input type=hidden name=csrf value="{csrf}"><button>Share Proforma invoice with {html.escape(actor.team_name)}</button></form>'
        return f'<!doctype html><meta charset=utf-8><title>Team software</title><style>{STYLE}</style><div class=login style="max-width:760px;margin-top:5vh"><a href=/access>← Access</a><h1>{html.escape(actor.team_name)} software</h1>{rows}{actions}</div>'

    @staticmethod
    def application_href(application_id: str, membership_id: str) -> str:
        application = urllib.parse.quote(application_id, safe="")
        workspace = urllib.parse.quote(membership_id, safe="")
        return f"/applications/{application}?workspace={workspace}"

    @staticmethod
    def watcher_listings_href(reference: str, membership_id: str) -> str:
        workspace = urllib.parse.quote(membership_id, safe="")
        return f"/applications/vehicles.encar_watcher/listings/{reference}?workspace={workspace}"

    @staticmethod
    def application_title(application_id: str, fallback: str) -> str:
        return {
            "vehicles.encar_watcher": "Vehicle Watcher",
            "documents.proforma_invoice": "Proforma Invoice",
        }.get(application_id, fallback)

    def current_application_contract(
        self, authenticated: AuthenticatedClient, application_id: str
    ) -> dict[str, Any] | None:
        controller = getattr(self.product, "controller", None)
        try:
            if controller is not None:
                return controller.application_contract(authenticated.actor, application_id)
            interfaces = getattr(self.product, "application_interfaces", None)
            if interfaces is not None:
                return interfaces.contract_resolver(authenticated.actor, application_id)
        except RuntimeFailure:
            return None
        return None

    def workspace_picker(self, authenticated: AuthenticatedClient) -> str:
        actor = authenticated.actor
        access_store = getattr(self.product, "access_store", None)
        workspaces = access_store.workspaces(actor) if access_store is not None else [actor]
        options = "".join(
            f'<option value="{html.escape(item.membership_id)}"'
            f'{" selected" if item.membership_id == actor.membership_id else ""}>'
            f'{html.escape("Personal" if item.workspace_kind == "personal" else item.team_name)}</option>'
            for item in workspaces
        )
        workspace_name = "Personal" if actor.workspace_kind == "personal" else actor.team_name
        return (
            '<form class=workspace-picker aria-label="Working in current workspace" method=post action=/workspaces/activate>'
            f'<input type=hidden name=csrf value="{html.escape(authenticated.csrf_token)}">'
            '<span class=workspace-label>Current workspace</span>'
            f'<strong class=workspace-name>{html.escape(workspace_name)} · {html.escape(actor.workspace_kind.title())}</strong>'
            f'<label><span class=skip-link>Choose workspace</span><select name=workspace>{options}</select></label>'
            '<button class="secondary workspace-submit">Use workspace</button></form>'
        )

    def navigation(
        self,
        authenticated: AuthenticatedClient,
        active: str,
        selected: str | None,
        *,
        include_workspace_picker: bool = True,
    ) -> str:
        actor = authenticated.actor
        controller = getattr(self.product, "controller", None)
        applications = controller.application_contracts(actor) if controller is not None else []
        app_links = "".join(
            f'<a class="nav-link app-shortcut" href="{self.application_href(item["application_id"], actor.membership_id)}"'
            f'{" aria-current=page" if active == item["application_id"] else ""}>{html.escape(self.application_title(item["application_id"], item["title"]))}</a>'
            for item in applications
        )
        conversations = self.product.chat_store.list_conversations(actor)[:12]
        conversation_links = "".join(
            f'<a class=conversation href="/?conversation={urllib.parse.quote(item["id"], safe="")}"'
            f'{" aria-current=page" if item["id"] == selected else ""}>'
            f'{html.escape(compact_conversation_title(item.get("title")))}</a>'
            for item in conversations
        ) or '<p class=identity>No conversations yet</p>'
        return (
            '<div class=nav-content>'
            f'{self.workspace_picker(authenticated) if include_workspace_picker else self.mobile_workspace_switcher(authenticated)}'
            '<nav aria-label="Primary"><div class=nav-section>'
            f'<a class=nav-link href=/{" aria-current=page" if active == "chat" else ""}>Chat</a>'
            f'<a class=nav-link href="/applications?workspace={urllib.parse.quote(actor.membership_id, safe="")}"{" aria-current=page" if active == "applications" else ""}>Applications</a>'
            f'{app_links}</div></nav>'
            '<form class=new-conversation method=post action=/conversations>'
            f'<input type=hidden name=csrf value="{html.escape(authenticated.csrf_token)}">'
            f'<input type=hidden name=workspace value="{html.escape(actor.membership_id)}">'
            '<button class=secondary>＋ New conversation</button></form>'
            f'<div class=nav-heading>Recent chats</div><nav aria-label="Recent chats">{conversation_links}</nav>'
            '<div class=sidebar-footer><a class=nav-link href=/access>Access</a>'
            f'<div class=identity><strong>{html.escape(actor.principal_display_name)}</strong>{html.escape(authenticated.client_label)}</div></div>'
            '</div>'
        )

    def mobile_workspace_switcher(self, authenticated: AuthenticatedClient) -> str:
        actor = authenticated.actor
        access_store = getattr(self.product, "access_store", None)
        if access_store is None:
            return ""
        buttons = "".join(
            '<form method=post action=/workspaces/activate>'
            f'<input type=hidden name=csrf value="{html.escape(authenticated.csrf_token)}">'
            f'<input type=hidden name=workspace value="{html.escape(item.membership_id)}">'
            f'<button class=secondary>{html.escape("Personal" if item.workspace_kind == "personal" else item.team_name)}</button></form>'
            for item in access_store.workspaces(actor)
        )
        return f'<div class=mobile-workspaces><div class=nav-heading>Switch workspace</div>{buttons}</div>'

    def product_shell(
        self,
        authenticated: AuthenticatedClient,
        *,
        title: str,
        active: str,
        body: SafeHtml,
        selected: str | None = None,
        application: bool = False,
        enhancement: str = "none",
    ) -> str:
        actor = authenticated.actor
        workspace_name = "Personal" if actor.workspace_kind == "personal" else actor.team_name
        controller = getattr(self.product, "controller", None)
        applications = controller.application_contracts(actor) if controller is not None else []
        conversations = self.product.chat_store.list_conversations(actor)[:12]
        navigation_items = (
            UINavItem("chat", "Chat", "/", current=active == "chat"),
            UINavItem(
                "applications", "Applications",
                f'/applications?workspace={urllib.parse.quote(actor.membership_id, safe="")}',
                current=active == "applications",
            ),
        )
        application_items = tuple(
            UINavItem(
                f'app-{index}',
                self.application_title(item["application_id"], item["title"]),
                self.application_href(item["application_id"], actor.membership_id),
                current=active == item["application_id"],
                compact=True,
            )
            for index, item in enumerate(applications)
        )
        recent_items = tuple(
            UINavItem(
                f'recent-{index}', compact_conversation_title(item.get("title")),
                f'/?conversation={urllib.parse.quote(item["id"], safe="")}',
                current=item["id"] == selected, compact=True,
            )
            for index, item in enumerate(conversations)
        )
        context = UIContext(
            principal_display_name=actor.principal_display_name,
            workspace_display_name=workspace_name,
            workspace_kind=actor.workspace_kind,
            current_destination=active.replace(".", "-") if active else "chat",
            navigation_items=navigation_items,
            recent_items=recent_items,
            application_items=application_items,
            current_application=title if application else None,
            current_conversation=selected,
            client_label=authenticated.client_label,
        )
        access_store = getattr(self.product, "access_store", None)
        available = access_store.workspaces(actor) if access_store is not None else [actor]
        workspaces = tuple(
            (
                item.membership_id,
                "Personal" if item.workspace_kind == "personal" else item.team_name,
            )
            for item in available
        )
        workspace = render_workspace_switcher(
            workspaces,
            current_membership_id=actor.membership_id,
            current_name=workspace_name,
            workspace_kind=actor.workspace_kind,
            csrf_token=authenticated.csrf_token,
        )
        mobile_workspace = render_mobile_workspace_switcher(
            workspaces, csrf_token=authenticated.csrf_token
        )
        new_item = render_shell_action(UIAction(
            "new-conversation", "New conversation", method="POST",
            form_action="/conversations", hierarchy="secondary",
            form_fields=(("csrf", authenticated.csrf_token), ("workspace", actor.membership_id)),
        ))
        account = render_shell_action(UIAction("access", "Access", href="/access", hierarchy="quiet"))
        if not isinstance(body, SafeHtml):
            raise TypeError("product body must be trusted renderer or compatibility output")
        return str(render_shell(
            context,
            title=title,
            body=body,
            workspace_switcher=workspace,
            mobile_workspace_switcher=mobile_workspace,
            new_item_action=new_item,
            account_item=account,
            stylesheet_extension=COMPATIBILITY_STYLESHEET if application else None,
            main_wide=application,
            enhancement=enhancement,
        ))

    def result_card(
        self,
        authenticated: AuthenticatedClient,
        metadata: dict[str, Any],
        *,
        artifacts: tuple[UIArtifact, ...] = (),
    ) -> SafeHtml:
        workspace_name = (
            "Personal" if authenticated.actor.workspace_kind == "personal"
            else authenticated.actor.team_name
        )
        application_id = metadata.get("application_id")
        contract = (
            self.current_application_contract(authenticated, application_id)
            if isinstance(application_id, str) else None
        )
        if contract and contract.get("portable_import"):
            operation = next((item for item in contract["operations"]
                              if item["operation_id"] == metadata.get("operation_id")), None)
            if (operation is not None
                and metadata.get("application_version") == contract["application_version"]
                and metadata.get("interaction_contract_digest") == contract["digest"]):
                facts = metadata.get("result") or {}
                labels = operation["result"].get("fact_labels", {})
                rows = "".join(
                    f'<dt>{html.escape(str(labels.get(name, name)))}</dt>'
                    f'<dd>{html.escape(str(facts[name]))}</dd>'
                    for name in operation["result"]["facts"] if name in facts
                )
                links = "".join(
                    f'<a href="{html.escape(item.href or "")}">{html.escape(item.label)}</a>'
                    for item in artifacts
                )
                return compatibility_body(
                    '<section class="interface-section"><h2>Completed</h2>'
                    f'<p>{html.escape(contract["title"])}</p><dl>{rows}</dl>{links}</section>'
                )
        if contract is None or not presentation_binding_is_current(metadata, contract):
            presentation = present_application_result(
                {}, application_href=None, workspace_name=workspace_name
            )
        else:
            result = metadata.get("result") if isinstance(metadata.get("result"), dict) else {}
            target = metadata.get("target_receipt") if isinstance(metadata.get("target_receipt"), dict) else {}
            watch_id = result.get("watch_id") or target.get("watch_id")
            resolved_watch = None
            if isinstance(watch_id, str) and self.product.encar_watcher is not None:
                try:
                    resolved_watch = next(
                        (
                            item for item in self.product.encar_watcher.stored_watches(authenticated.actor)
                            if item.get("id") == watch_id
                        ),
                        None,
                    )
                except RuntimeFailure:
                    # Durable history remains visible when optional local state is
                    # temporarily unavailable; the presenter fails conservatively.
                    resolved_watch = None
            presentation = present_application_result(
                metadata,
                application_href=self.application_href(
                    application_id, authenticated.actor.membership_id
                ),
                workspace_name=workspace_name,
                resolved_watch=resolved_watch,
            )
        return render_activity(replace(presentation, artifacts=artifacts))

    def workspace_handoff_page(
        self,
        authenticated: AuthenticatedClient,
        target: ActorContext,
        return_to: str,
        *,
        application_id: str | None = None,
    ) -> str:
        target_name = "Personal" if target.workspace_kind == "personal" else target.team_name
        body = render_stack(
            render_page_header("Workspace check", "Open this application in the right workspace"),
            render_notice(UINotice(
                "info", "Workspace switch required",
                f"This conversation belongs to {target_name}. Switch before opening the application so Capy cannot show it in a different workspace.",
                what_did_not_happen="The application has not been opened in another workspace.",
                next_action=UIAction(
                    "switch-workspace", f"Switch to {target_name} and continue",
                    method="POST", form_action="/workspaces/activate", hierarchy="primary",
                    form_fields=(("csrf", authenticated.csrf_token), ("workspace", target.membership_id), ("return_to", return_to)),
                ),
            ))
        )
        return self.product_shell(
            authenticated,
            title="Confirm workspace",
            active=application_id or "applications",
            body=body,
            application=True,
        )

    @staticmethod
    def superseded_working_message(messages: list[dict[str, Any]], index: int) -> bool:
        message = messages[index]
        if message.get("role") != "assistant" or message.get("state") != "WORKING":
            return False
        for later in messages[index + 1:]:
            if later.get("role") == "owner":
                return False
            if later.get("role") == "assistant" and later.get("state") != "WORKING":
                return True
        return False

    def chat_page(self, authenticated: AuthenticatedClient, selected: str | None) -> str:
        actor = authenticated.actor
        conversations = self.product.chat_store.list_conversations(actor)
        if selected is None and conversations:
            selected = conversations[0]["id"]
        if selected is None:
            return self.product_shell(
                authenticated,
                title="Chat",
                active="chat",
                body=render_empty_conversation(),
            )
        timeline = self.product.chat_store.timeline(actor, selected)
        builds = self.product.chat_store.builds_for_conversation(actor, selected)
        builds_by_gap = {item["gap_id"]: item for item in builds}
        generic_outcomes = self.product.chat_store.generic_build_outcomes_for_conversation(
            actor, selected
        )
        generic_outcomes_by_build = {item["build_id"]: item for item in generic_outcomes}
        proposals = self.product.chat_store.build_proposals_for_conversation(actor, selected)
        proposals_by_gap = {item["gap_id"]: item for item in proposals}
        rendered = []
        messages = timeline["messages"]
        for index, message in enumerate(messages):
            if self.superseded_working_message(messages, index):
                continue
            metadata = message["metadata"]
            cards: list[SafeHtml] = []
            if message["kind"] == "result":
                artifacts = tuple(
                    UIArtifact(
                        str(resource["filename"]),
                        f'/resource/{resource["digest"]}?conversation={urllib.parse.quote(selected, safe="")}',
                    )
                    for resource in message["resources"]
                )
                cards.append(self.result_card(authenticated, metadata, artifacts=artifacts))
            if message["kind"] == "clarify" and metadata.get("missing_input_fields"):
                labels = ", ".join(str(label) for label in metadata.get("field_labels", []))
                explanation = " ".join(filter(None, (
                    f"Needed: {labels}." if labels else "",
                    str(metadata.get("next_action", "")),
                    str(metadata.get("resource_statement", "")),
                )))
                cards.append(render_notice(UINotice(
                    "info", str(metadata.get("title", "Details needed")), explanation,
                    what_did_not_happen=str(metadata.get("effect_statement") or "No operation has run yet."),
                )))
            if message["kind"] == "problem" and metadata.get("category"):
                problem_reference = str(metadata.get("problem_reference", ""))
                try:
                    cards.append(render_problem_card(metadata))
                except Exception as exc:
                    facts = safe_render_incident(exc)
                    try:
                        self.product.chat_store.record_problem_render_incident(
                            problem_reference, facts
                        )
                    except Exception:
                        pass
                    cards.append(safe_problem_card(problem_reference))
            if message["kind"] == "gap":
                gap_id = metadata.get("gap_id", "")
                build = builds_by_gap.get(gap_id)
                proposal = proposals_by_gap.get(gap_id)
                proposal_facts: list[UIFact] = []
                if proposal is not None:
                    summary = proposal["summary"]
                    proposal_facts = [
                        UIFact("Historical software proposal", proposal["status"], "technical"),
                        UIFact("Reads", summary["reads"], "technical"),
                        UIFact("Produces", summary["produces"], "technical"),
                        UIFact("External connection", summary["external_connection"], "technical"),
                        UIFact("Persistent state", summary["persistent_state"], "technical"),
                        UIFact("Changes", summary["changes"], "technical"),
                    ]
                    if proposal["status"] == "BLOCKED":
                        proposal_facts.append(UIFact(
                            "Build boundary", str(proposal["blocked_reason"]), "technical"
                        ))
                    elif proposal["status"] == "FAILED":
                        proposal_facts.append(UIFact(
                            "Problem reference", str(proposal["terminal_error"]), "technical"
                        ))
                cards.append(render_notice(UINotice(
                    "unsupported",
                    "Not supported by the software currently available to this team",
                    f'{metadata.get("needed_ability", "")} See installed applications for nearby supported operations.',
                    what_did_not_happen="No unsupported operation or external action ran.",
                    next_action=UIAction(
                        "view-installed-applications", "View installed applications",
                        href="/applications", hierarchy="primary",
                    ),
                    technical_details=tuple(proposal_facts),
                )))
            if message["kind"] != "result":
                for resource in message["resources"]:
                    href = f'/resource/{resource["digest"]}?conversation={urllib.parse.quote(selected, safe="")}'
                    cards.append(render_artifacts((UIArtifact(
                        f'{resource["filename"]} · {resource["size_bytes"]} bytes', href,
                    ),)))
            display_text = (
                ""
                if message["kind"] == "clarify" and metadata.get("missing_input_fields")
                else ("" if message["kind"] == "problem" else message["text"])
            )
            if message["role"] == "assistant" and message["state"] == "WORKING":
                rendered.append(render_message(
                    "assistant", "No application or external action has run yet.", working=True
                ))
            else:
                rendered.append(render_message(
                    "user" if message["role"] == "owner" else "assistant",
                    str(display_text),
                    supplements=tuple(cards),
                ))
        labels = {
            "APPROVED_WAITING_FOR_BUILDER": "Build approved — waiting for the software builder",
            "BUILDING": "Building software",
            "CANDIDATE_SUBMITTED": "Verifying candidate",
            "ACCEPTING": "Verifying candidate",
            "CANDIDATE_REJECTED": "Candidate failed verification",
            "PUBLISHED": "Software installed — retrying your request",
            "RETRYING": "Retrying",
            "COMPLETED": "Done",
            "BLOCKED": "Build blocked",
            "CANCELLED": "Build cancelled",
        }
        generic_labels = {
            "COMPLETED": "New software verified — result returned",
            "BUILDER_FAILED": "Software builder failed",
            "BUILDER_TIMEOUT": "Software builder timed out",
            "NO_PUSH": "Software builder returned no candidate",
            "CANDIDATE_REJECTED": "Candidate failed independent verification",
            "ORACLE_FAILED": "Independent verification could not reach a judgment",
            "CANCELLED": "Build cancelled",
            "ATTACHMENTS_CHANGED": "Attachments changed before the build started",
            "CLEANUP_FAILED": "Builder authority cleanup could not be verified",
            "PUBLICATION_FAILED": "Verified software could not be published",
            "RETRY_FAILED": "Software was published but the request retry failed",
            "ORCHESTRATION_FAILED": "Build orchestration failed",
        }
        for build in builds:
            generic = generic_outcomes_by_build.get(build["id"])
            title = labels.get(build["status"], build["status"])
            explanation = "Software build state recorded for this conversation."
            facts: list[UIFact] = []
            kind = "info"
            if build["status"] in {"BLOCKED", "CANDIDATE_REJECTED"}:
                kind = "error"
                explanation = "The build did not complete. No software result should be assumed."
                if build.get("terminal_error"):
                    facts.append(UIFact("Problem reference", str(build["terminal_error"]), "technical"))
            if generic is not None:
                classification = generic["classification"]
                title = generic_labels.get(classification, classification)
                facts.append(UIFact("Build classification", str(classification), "technical"))
                provenance = generic.get("provenance")
                if provenance:
                    encoded = json.dumps(provenance, ensure_ascii=False, sort_keys=True)
                    facts.append(UIFact(
                        "Provenance receipt",
                        hashlib.sha256(encoded.encode("utf-8")).hexdigest(),
                        "technical",
                    ))
                    candidate = provenance.get("candidate") if isinstance(provenance, dict) else None
                    if isinstance(candidate, dict):
                        for key in ("repository", "ref", "commit"):
                            value = candidate.get(key)
                            if isinstance(value, str) and value:
                                facts.append(UIFact(
                                    f"Candidate {key}", value[:512], "technical"
                                ))
                    pending = [provenance]
                    while pending:
                        value = pending.pop()
                        if isinstance(value, dict):
                            invocation_id = value.get("invocation_id")
                            if isinstance(invocation_id, str) and invocation_id:
                                facts.append(UIFact(
                                    "Retry invocation", invocation_id[:512], "technical"
                                ))
                                break
                            pending.extend(value.values())
                        elif isinstance(value, list):
                            pending.extend(value)
                if classification != "COMPLETED":
                    kind = "error"
                    explanation = "No verified software result should be assumed."
                    if generic.get("detail"):
                        facts.append(UIFact("Problem reference", str(generic["detail"]), "technical"))
            rendered.append(render_message(
                "assistant", "", supplements=(render_notice(UINotice(
                    kind, str(title), explanation,
                    what_did_not_happen=(
                        "No verified software result should be assumed."
                        if kind == "error" else None
                    ),
                    technical_details=tuple(facts),
                )),)
            ))
        latest_is_working = bool(
            timeline["messages"] and timeline["messages"][-1]["state"] == "WORKING"
        )
        body = render_chat_workspace(
            header=render_page_header(
                "Conversation",
                compact_conversation_title(timeline["conversation"]["title"]),
            ),
            messages=rendered,
            active=latest_is_working,
            csrf_token=authenticated.csrf_token,
            conversation_id=selected,
            submission_id=secrets.token_hex(16),
        )
        return self.product_shell(
            authenticated,
            title=compact_conversation_title(timeline["conversation"]["title"]),
            active="chat",
            selected=selected,
            body=body,
            enhancement="chat",
        )

    def applications_page(self, authenticated: AuthenticatedClient) -> str:
        applications = self.product.controller.application_contracts(authenticated.actor)
        entities = tuple(
            UIEntity(
                reference=f'application-{index}',
                title=self.application_title(item["application_id"], item["title"]),
                subtitle=item["purpose"],
                primary_facts=(UIFact(
                    "Available operations",
                    str(len(item["operations"])),
                    importance="primary",
                    sort_value=len(item["operations"]),
                ),),
                primary_action=UIAction(
                    f'open-application-{index}', "Open application",
                    href=self.application_href(item["application_id"], authenticated.actor.membership_id),
                    hierarchy="primary",
                ),
            )
            for index, item in enumerate(applications)
        )
        collection = UICollection(
            title="Installed applications",
            count=len(entities),
            entities=entities,
            empty_state=UINotice(
                "empty", "No applications installed",
                "No contract-aware applications are installed and authorized for this workspace.",
                what_did_not_happen="No source check or external action ran.",
            ),
        )
        body = render_stack(
            render_page_header(
                "Applications", "Installed applications",
                "Open the software available in this workspace. Opening an application uses stored state and does not run a source check.",
            ), render_collection(collection)
        )
        return self.product_shell(
            authenticated, title="Applications", active="applications", body=body,
            application=True,
        )

    def application_page(
        self,
        authenticated: AuthenticatedClient,
        application_id: str,
        result: dict[str, Any] | None = None,
    ) -> str:
        page = self.product.application_interfaces.page(authenticated.actor, application_id)
        contract = page["contract"]
        display_title = self.application_title(application_id, contract["title"])
        operation_titles = {
            item["operation_id"]: item["title"] for item in contract["operations"]
        }
        operations = []
        for operation in contract["operations"]:
            required = [item for item in operation["human_fields"] if item["required"]]
            optional = [item for item in operation["human_fields"] if not item["required"]]
            required_html = "".join(
                f'<li><strong>{html.escape(item["label"])}</strong> — {html.escape(item["description"])}</li>'
                for item in required
            ) or '<li>None</li>'
            optional_html = "".join(
                f'<li><strong>{html.escape(item["label"])}</strong> — {html.escape(item["description"])}</li>'
                for item in optional
            ) or '<li>None</li>'
            defaults = "".join(
                f'<li>{html.escape(next(item["label"] for item in operation["human_fields"] if item["field_id"] == field_id))}: {html.escape(str(value))}</li>'
                for field_id, value in operation["safe_defaults"].items()
            ) or '<li>No implicit defaults</li>'
            examples = "".join(
                f'<li>{html.escape(value)}</li>' for value in operation["examples"]
            ) or '<li>No example provided</li>'
            misunderstandings = "".join(
                f'<li>{html.escape(value)}</li>'
                for value in operation["common_misunderstandings"]
            ) or '<li>None recorded</li>'
            facts = ", ".join(
                str(value).replace("_", " ") for value in operation["result"]["facts"]
            ) or "a verified completion result"
            artifacts = ", ".join(operation["result"]["artifacts"]) or "none"
            operations.append(
                '<section class=card>'
                f'<h2>{html.escape(operation["title"])}</h2>'
                f'<p>{html.escape(operation["user_outcome"])}</p>'
                f'<h3>Required information</h3><ul>{required_html}</ul>'
                f'<h3>Optional information</h3><ul>{optional_html}</ul>'
                f'<h3>Safe defaults</h3><ul>{defaults}</ul>'
                f'<p><strong>Authority</strong><br>{html.escape(operation["authority"]["required_role"])}</p>'
                f'<p><strong>Effect</strong><br>{html.escape(operation["effects"]["state_effect"])}</p>'
                f'<p><strong>External/source behavior</strong><br>{html.escape(operation["effects"]["source_behavior"])}</p>'
                f'<p><strong>Verified result</strong><br>Facts: {html.escape(facts)}<br>Artifacts: {html.escape(artifacts)}</p>'
                f'<h3>Examples</h3><ul>{examples}</ul>'
                f'<h3>Common misunderstandings</h3><ul>{misunderstandings}</ul>'
                '</section>'
            )
        boundaries = "".join(
            '<li>'
            f'<strong>{html.escape(item["request_class"])}</strong> — '
            f'{html.escape(item["explanation"])} Nearby: '
            f'{html.escape(", ".join(operation_titles[operation_id] for operation_id in item["nearest_operation_ids"]))}.'
            '</li>'
            for item in contract["boundaries"]
        )
        not_for = "".join(f'<li>{html.escape(item)}</li>' for item in contract["not_for"])
        interface = self.application_interface(authenticated, page, result)
        workspace_name = "Personal" if authenticated.actor.workspace_kind == "personal" else authenticated.actor.team_name
        body = (
            str(render_page_header(
                "Application", display_title,
                f'{contract["purpose"]} {workspace_name} is the current workspace.',
            )) +
            f'{interface}'
            '<details class=about-panel><summary>About this application</summary>'
            f'<p><strong>Exact installed version</strong><br><code>{html.escape(contract["application_version"])}</code></p>'
            f'<h2>What it is not for</h2><ul>{not_for}</ul>'
            f'<h2>Supported operations</h2>{"".join(operations)}'
            f'<h2>Unsupported boundaries and nearest alternatives</h2><ul>{boundaries}</ul>'
            '</details>'
        )
        return self.product_shell(
            authenticated, title=display_title, active=application_id,
            body=compatibility_body(body),
            application=True, enhancement="form-protection",
        )

    def application_activity_page(
        self,
        authenticated: AuthenticatedClient,
        application_id: str,
        result: dict[str, Any],
    ) -> str:
        contract = self.current_application_contract(authenticated, application_id)
        if contract is None:
            raise RuntimeFailure("INTERACTION_CONTRACT_UNKNOWN_APPLICATION")
        operation = next(
            (
                item for item in contract["operations"]
                if item["operation_id"] == result.get("operation_id")
            ),
            None,
        )
        result_metadata = dict(result)
        if operation is not None:
            result_metadata["interaction_contract_digest"] = contract["digest"]
            result_metadata["presentation_kind"] = operation["result"]["presentation"]
        artifacts = tuple(
            UIArtifact(
                str(item["filename"]),
                f'/application-artifact/{urllib.parse.quote(str(result.get("invocation_id", "")), safe="")}/'
                f'{urllib.parse.quote(str(item["digest"]), safe="")}?filename={urllib.parse.quote(str(item["filename"]), safe="")}',
            )
            for item in result.get("artifacts", [])
        )
        body = render_stack(
            render_page_header("Application result", "Completed application activity"),
            self.result_card(authenticated, result_metadata, artifacts=artifacts),
        )
        return self.product_shell(
            authenticated, title="Application result", active=application_id, body=body,
            application=True,
        )

    def watcher_listings_page(
        self, authenticated: AuthenticatedClient, page: dict[str, Any]
    ) -> str:
        result = page["result"]
        watch = page["watch"]
        filters = watch.get("filters") or {}
        name = " ".join(
            str(value) for value in (filters.get("make"), filters.get("model")) if value
        ) or "Vehicle watch"
        years = "–".join(
            str(value) for value in (filters.get("min_year"), filters.get("max_year"))
            if value is not None
        )
        snapshot = result.get("snapshot")
        current = result.get("current_listings") if isinstance(result.get("current_listings"), list) else []
        history = result.get("history") if isinstance(result.get("history"), list) else []

        def number(value: Any, suffix: str = "") -> str:
            if isinstance(value, bool) or value is None:
                return "Not recorded"
            if isinstance(value, (int, float)):
                return f"{value:,.0f}{suffix}"
            return f"{value}{suffix}"

        def disposition(value: Any) -> str:
            return {
                "notified": "Notified",
                "selected_for_notification": "Selected for notification",
                "ignored": "Ignored",
                "pending_review": "Pending review",
                "unchanged": "Unchanged",
            }.get(str(value), "Stored")

        def catalog_link(value: Any) -> str:
            if not isinstance(value, str):
                return '<span class=muted>Catalog link unavailable</span>'
            parsed = urllib.parse.urlsplit(value)
            if (
                parsed.scheme != "https" or parsed.netloc != "eimcar.ru"
                or not parsed.path.startswith("/catalog/") or parsed.query or parsed.fragment
            ):
                return '<span class=muted>Catalog link unavailable</span>'
            return (
                f'<a class="button secondary" href="{html.escape(value)}" '
                'target=_blank rel="noopener noreferrer">Open on EimCar</a>'
            )

        def listing_card(item: dict[str, Any], *, historical: bool) -> str:
            title = item.get("title") or "Vehicle listing"
            seen_label = "Observed" if historical else "First seen"
            seen = human_timestamp(item.get("first_seen_at"), "Not recorded")
            last = human_timestamp(item.get("last_seen_at"), "Not recorded")
            return (
                '<article class=listing-card>'
                f'<span class=disposition>{html.escape(disposition(item.get("disposition")))}</span>'
                f'<h3>{html.escape(str(title))}</h3>'
                '<div class=listing-facts>'
                f'<div><span>Vehicle date</span>{html.escape(str(item.get("vehicle_date") or "Not recorded"))}</div>'
                f'<div><span>Price</span>{html.escape(number(item.get("price")))}</div>'
                f'<div><span>Mileage</span>{html.escape(number(item.get("mileage"), " km"))}</div>'
                f'<div><span>{seen_label}</span>{html.escape(seen)}</div>'
                f'<div><span>Last seen</span>{html.escape(last)}</div>'
                '</div>'
                f'{catalog_link(item.get("catalog_url"))}</article>'
            )

        if snapshot is None:
            current_html = (
                '<p class=notice>The current listing snapshot will be available after this watch’s '
                'next successful check. Existing history is shown below.</p>'
            )
            snapshot_text = "Waiting for the next successful check"
        elif current:
            current_html = '<div class=listing-grid>' + "".join(
                listing_card(item, historical=False) for item in current if isinstance(item, dict)
            ) + '</div>'
            snapshot_text = human_timestamp(snapshot.get("observed_at"), "Recorded")
        else:
            current_html = '<p class=notice>No listings matched in the latest stored check.</p>'
            snapshot_text = human_timestamp(snapshot.get("observed_at"), "Recorded")
        history_html = (
            '<div class=listing-grid>' + "".join(
                listing_card(item, historical=True) for item in history if isinstance(item, dict)
            ) + '</div>'
            if history else '<p class=notice>No reviewed listing changes are stored yet.</p>'
        )
        back = self.application_href("vehicles.encar_watcher", authenticated.actor.membership_id)
        total = snapshot.get("total_hits") if isinstance(snapshot, dict) else None
        count_text = (
            f'{len(current)} shown · {number(total)} matched'
            if total is not None else f'{len(current)} stored'
        )
        workspace = "Personal" if authenticated.actor.workspace_kind == "personal" else authenticated.actor.team_name
        body = (
            str(render_page_header(
                "Vehicle Watcher", f"{name} listings", f"{years} · {workspace} workspace",
                status=UIStatus(str(watch.get("status", "stored")).replace("_", " ").title(), "success"),
                return_action=UIAction("return-to-application", "Back to Vehicle Watcher", href=back, hierarchy="quiet"),
            )) +
            '<div class=listing-summary>'
            f'<span><strong>Watch</strong> {html.escape(str(watch.get("status", "stored")).title())}</span>'
            f'<span><strong>Latest snapshot</strong> {html.escape(snapshot_text)}</span>'
            f'<span><strong>Current listings</strong> {html.escape(count_text)}</span>'
            '</div>'
            '<p class=notice>This page uses stored application state. Opening or refreshing it does not check the vehicle source.</p>'
            '<section class=interface-section><h2>Current listings</h2>'
            f'{current_html}</section>'
            '<section class=interface-section><h2>Review history</h2>'
            '<p>Material listing changes that were notified, ignored, or are awaiting review.</p>'
            f'{history_html}</section>'
        )
        return self.product_shell(
            authenticated, title=f"{name} listings", active="vehicles.encar_watcher",
            body=compatibility_body(body), application=True,
        )

    def application_error_page(
        self,
        authenticated: AuthenticatedClient,
        application_id: str,
        exc: RuntimeFailure,
    ) -> str:
        application_path = self.application_href(
            application_id, authenticated.actor.membership_id
        )
        if exc.safe_facts.get("application_invoked") is True:
            code = exc.code if re.fullmatch(r"[A-Z][A-Z0-9_]{0,127}", exc.code) else "APPLICATION_FAILED"
            what, why, next_step = (
                "No successful result was produced.",
                f"The application ran and reported {code}.",
                "Review the input and the application guidance before trying again.",
            )
        elif exc.code == "APPLICATION_ACCESS_DENIED":
            what, why, next_step = (
                "The requested change was not made.",
                "Your current workspace role can view this item but cannot manage it.",
                "Ask the watch creator or a team owner to make this change.",
            )
        elif exc.code in {
            "APPLICATION_INTERFACE_STALE",
            "APPLICATION_INTERFACE_TARGET_STALE",
            "APPLICATION_INTERFACE_ACTIVITY_DENIED",
        }:
            what, why, next_step = (
                "No application operation ran.",
                "This page is out of date or belongs to a different current workspace.",
                "Reload the application to use current information and authority.",
            )
        else:
            what, why, next_step = (
                "No additional application operation ran.",
                "The submitted information could not be accepted safely.",
                "Return to the application and review the current form guidance.",
            )
        kind = "permission" if exc.code == "APPLICATION_ACCESS_DENIED" else (
            "stale" if "STALE" in exc.code else "error"
        )
        notice = UINotice(
            kind,
            "This action was not completed",
            f"{why} {next_step}",
            what_did_not_happen=what,
            next_action=UIAction(
                "reload-application", "Reload application", href=application_path,
                hierarchy="primary",
            ),
        )
        body = render_stack(
            render_page_header("Application", "This action was not completed"),
            render_notice(notice),
        )
        if not hasattr(self, "server"):
            return f'<!doctype html><meta charset=utf-8><style>{STYLE}</style>{body}'
        return self.product_shell(
            authenticated, title="Application request not completed",
            active=application_id, body=body, application=True,
        )

    def application_interface(
        self,
        authenticated: AuthenticatedClient,
        page: dict[str, Any],
        result: dict[str, Any] | None,
    ) -> str:
        contract = page["contract"]
        result_metadata = None
        if result:
            result_metadata = dict(result)
            operation = next(
                (
                    item for item in contract["operations"]
                    if item["operation_id"] == result.get("operation_id")
                ),
                None,
            )
            if operation is not None:
                result_metadata["interaction_contract_digest"] = contract["digest"]
                result_metadata["presentation_kind"] = operation["result"]["presentation"]
        result_html = self.result_card(authenticated, result_metadata) if result_metadata else ""
        if contract["application_id"] == "vehicles.encar_watcher":
            rows = []
            for watch in page["watches"]:
                filters = watch.get("filters") or {}
                label = (
                    f'{filters.get("make", "Vehicle")} {filters.get("model", "watch")} · '
                    f'{filters.get("min_year", "?")}–{filters.get("max_year", "?")} · '
                    f'{str(watch.get("visibility", "")).title()} · '
                    f'{str(watch.get("status", "")).title()}'
                )
                schedule = int(watch.get("schedule_seconds") or 0) // 60
                details = (
                    f'<p>Status: {html.escape(str(watch.get("status", "stored")).replace("_", " ").title())}<br>'
                    f'Last checked: {html.escape(human_timestamp(watch.get("last_checked_at"), "Not yet"))}<br>'
                    f'Next check: {html.escape(human_timestamp(watch.get("next_check_at"), "Not scheduled"))}<br>'
                    f'Schedule: every {schedule} minutes</p>'
                )
                buttons = []
                buttons.append(
                    f'<a class=button href="{self.watcher_listings_href(watch["reference"], authenticated.actor.membership_id)}">View listings</a>'
                )
                authority = watch["authority"]
                if not authority["manageable"]:
                    buttons.append(
                        '<button class=secondary type=button disabled title="Not available with your current role">Manage unavailable</button>'
                    )
                    buttons.append(
                        f'<p class=authority-note>{html.escape(authority["explanation"])}</p>'
                    )
                elif watch.get("status") == "paused":
                    buttons.append(self.watch_action_form(authenticated, contract, watch, "watch.resume", "Resume"))
                else:
                    buttons.append(self.watch_action_form(authenticated, contract, watch, "watch.pause", "Pause"))
                    buttons.append(self.watch_action_form(authenticated, contract, watch, "watch.check_now", "Check now"))
                if authority["manageable"]:
                    buttons.append(self.watch_update_form(authenticated, contract, watch))
                    buttons.append(self.watch_action_form(authenticated, contract, watch, "watch.delete", "Delete", confirm=True))
                rows.append(
                    f'<article class="card watch-row"><h3>{html.escape(label)}</h3>{details}'
                    f'<div class=interface-actions>{"".join(buttons)}</div></article>'
                )
            collection = "".join(rows) or '<p>You have no visible vehicle watches in this workspace.</p>'
            create = next(item for item in contract["operations"] if item["operation_id"] == "watch.create")
            return (
                f'{result_html}<section class=interface-section><h2>Your watches</h2>'
                '<p>Stored application state only. Opening this page does not check the vehicle source.</p>'
                f'{collection}<details class=technical><summary>Technical details</summary>'
                f'<p>Read receipt: <code>{html.escape(str(page["read_receipt"]))}</code></p></details></section>'
                '<section class=interface-section><h2>Create watch</h2>'
                f'<form data-protect-draft method=post enctype=multipart/form-data action="{self.operation_path(contract, "watch.create")}">'
                f'{self.interface_hidden(authenticated, contract)}{self.render_fields(create["human_fields"])}'
                '<p><strong>Visibility</strong><br>Derived from the current workspace shown above.</p>'
                '<button>Create watch</button></form></section>'
            )
        operation = contract["operations"][0]
        if contract.get("portable_import"):
            from .portable_interfaces import render_portable_fields
            return (
                f'{result_html}<section class=interface-section>'
                f'<h2>{html.escape(operation["title"])}</h2>'
                f'<p>{html.escape(operation["description"])}</p>'
                f'<form data-protect-draft method=post enctype=multipart/form-data action="{self.operation_path(contract, operation["operation_id"])}">'
                f'{self.interface_hidden(authenticated, contract)}'
                f'{render_portable_fields(operation["human_fields"])}'
                '<button>Run application</button></form></section>'
            )
        resource = operation["resources"][0]
        columns = ",".join(resource["accepted_columns_in_order"])
        external_boundary = next(
            item for item in contract["boundaries"]
            if item["boundary_id"] == "invoice.external_send"
        )
        excel_boundary = next(
            item for item in contract["boundaries"]
            if item["boundary_id"] == "invoice.excel"
        )
        return (
            f'{result_html}<section class=interface-section><h2>{html.escape(operation["title"])}</h2>'
            f'<p><strong>Accepted:</strong> {resource["minimum_count"]} '
            f'{html.escape(resource["format"])} file<br>'
            f'<strong>Not accepted:</strong> {html.escape(excel_boundary["request_class"]) }<br>'
            f'<strong>External behavior:</strong> {html.escape(operation["effects"]["source_behavior"])}<br>'
            f'<strong>{html.escape(external_boundary["request_class"].title())}:</strong> not supported</p>'
            '<p><strong>Required CSV columns, in this order:</strong></p>'
            f'<pre>{html.escape(columns)}</pre>'
            f'<form data-protect-draft method=post enctype=multipart/form-data action="{self.operation_path(contract, operation["operation_id"])}">'
            f'{self.interface_hidden(authenticated, contract)}{self.render_fields(operation["human_fields"])}'
            '<button>Generate invoice</button></form></section>'
        )

    @staticmethod
    def operation_path(contract: dict[str, Any], operation_id: str) -> str:
        app = urllib.parse.quote(contract["application_id"], safe="")
        operation = urllib.parse.quote(operation_id, safe="")
        return f"/applications/{app}/operations/{operation}"

    def interface_hidden(
        self, authenticated: AuthenticatedClient, contract: dict[str, Any]
    ) -> str:
        values = {
            "csrf": authenticated.csrf_token,
            "application_version": contract["application_version"],
            "contract_digest": contract["digest"],
            "workspace_membership_id": authenticated.actor.membership_id,
            "submission": secrets.token_hex(16),
        }
        return "".join(
            f'<input type=hidden name="{html.escape(name)}" value="{html.escape(value)}">'
            for name, value in values.items()
        )

    def render_fields(self, fields: list[dict[str, Any]]) -> str:
        rendered = []
        for field in fields:
            if field["field_id"] == "selector":
                continue
            field_id = html.escape(field["field_id"])
            label = html.escape(field["label"])
            description = html.escape(field["description"])
            required = " required" if field["required"] else ""
            default_value = field.get("safe_default")
            value = f' value="{html.escape(str(default_value))}"' if default_value is not None else ""
            if field["input_kind"] == "long_text":
                control = f'<textarea name="{field_id}"{required}>{html.escape(str(default_value or ""))}</textarea>'
            elif field["input_kind"] == "number":
                control = f'<input type=number name="{field_id}"{required}{value}>'
            elif field["input_kind"] == "file":
                control = f'<input type=file name="{field_id}" accept=".csv,text/csv"{required}>'
            elif field["input_kind"] == "choice" and field["field_id"] == "hard_filters.source":
                selected = html.escape(str(default_value or ""))
                control = f'<select name="{field_id}" required><option value="{selected}">{selected.title()}</option></select>'
            elif field["input_kind"] == "choice":
                control = f'<input name="{field_id}"{required}{value}>'
            else:
                input_type = "date" if field["field_id"] == "issue_date" else "text"
                control = f'<input type={input_type} name="{field_id}"{required}{value}>'
            semantic = "Preference, not enforced" if field.get("semantic") == "preference" else "Enforced input"
            rendered.append(
                f'<label class=interface-field><strong>{label}</strong>{control}'
                f'<small>{description} · {html.escape(semantic)}</small></label>'
            )
        return "".join(rendered)

    def watch_action_form(
        self,
        authenticated: AuthenticatedClient,
        contract: dict[str, Any],
        watch: dict[str, Any],
        operation_id: str,
        label: str,
        *,
        confirm: bool = False,
    ) -> str:
        if confirm:
            values = (
                ("csrf", authenticated.csrf_token),
                ("application_version", contract["application_version"]),
                ("contract_digest", contract["digest"]),
                ("workspace_membership_id", authenticated.actor.membership_id),
                ("submission", secrets.token_hex(16)),
                ("watch_ref", watch["reference"]),
            )
            return str(render_confirmation(UIConfirmation(
                title="Delete this saved item",
                consequence="This removes the saved item from this workspace. Historical activity remains available.",
                preserved_facts=(UIFact("Reference", str(watch["reference"]), importance="technical"),),
                confirm_label=f"Confirm {label.lower()}",
                cancel_label="Cancel",
                danger_level="destructive",
                form_action=self.operation_path(contract, operation_id),
                form_fields=values,
            )))
        return (
            f'<form method=post enctype=multipart/form-data action="{self.operation_path(contract, operation_id)}">'
            f'{self.interface_hidden(authenticated, contract)}'
            f'<input type=hidden name=watch_ref value="{html.escape(watch["reference"])}">'
            f'<button class=secondary>{html.escape(label)}</button></form>'
        )

    def watch_update_form(
        self, authenticated: AuthenticatedClient, contract: dict[str, Any], watch: dict[str, Any]
    ) -> str:
        operation = next(item for item in contract["operations"] if item["operation_id"] == "watch.update")
        fields = [item for item in operation["human_fields"] if item["field_id"] != "selector"]
        return (
            '<details><summary>Update</summary>'
            f'<form data-protect-draft method=post enctype=multipart/form-data action="{self.operation_path(contract, "watch.update")}">'
            f'{self.interface_hidden(authenticated, contract)}'
            f'<input type=hidden name=watch_ref value="{html.escape(watch["reference"])}">'
            f'{self.render_fields(fields)}<button class=secondary>Save changes</button></form></details>'
        )

    def application_artifact(
        self, actor: ActorContext, invocation_id: str, digest: str, requested_filename: str | None = None
    ) -> None:
        if not SAFE_DIGEST.fullmatch(digest) or not re.fullmatch(r"[0-9a-f]{32}", invocation_id):
            raise RuntimeFailure("APPLICATION_INTERFACE_ARTIFACT_DENIED")
        path, filename = self.product.application_interfaces.artifact(actor, invocation_id, digest, requested_filename)
        if path.is_symlink() or not path.is_file():
            raise RuntimeFailure("RESOURCE_BYTES_INVALID")
        payload = path.read_bytes()
        if hashlib.sha256(payload).hexdigest() != digest:
            raise RuntimeFailure("RESOURCE_BYTES_INVALID")
        self.send_response(200)
        self.send_header("Content-Type", "application/octet-stream")
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Disposition", f"attachment; filename*=UTF-8''{urllib.parse.quote(filename, safe='')}")
        self.end_headers()
        self.wfile.write(payload)

    def world_page(self, authenticated: AuthenticatedClient, conversation: str, value: dict[str, Any], digest: str) -> str:
        self.product.chat_store.timeline(authenticated.actor, conversation)
        payload = html.escape(json.dumps(value, ensure_ascii=False, indent=2))
        return f'<!doctype html><meta charset=utf-8><title>What Capy can access</title><style>{STYLE}</style><div class=login style="max-width:760px;margin-top:5vh"><a href="/?conversation={conversation}">← Conversation</a><h1>What Capy can access</h1><p>Snapshot digest: <code>{digest}</code></p><pre>{payload}</pre></div>'

    def download(self, actor: ActorContext, conversation: str, digest: str) -> None:
        if not SAFE_DIGEST.fullmatch(digest):
            raise RuntimeFailure("RESOURCE_NOT_IN_SCOPE")
        visible = {item["digest"] for item in self.product.chat_store.visible_resources(actor, conversation)}
        if digest not in visible:
            raise RuntimeFailure("RESOURCE_NOT_IN_SCOPE")
        path, filename = self.product.runtime_store.resource(actor.execution_scope_id, digest)
        if path.is_symlink() or not path.is_file():
            raise RuntimeFailure("RESOURCE_BYTES_INVALID")
        payload = path.read_bytes()
        if hashlib.sha256(payload).hexdigest() != digest:
            raise RuntimeFailure("RESOURCE_BYTES_INVALID")
        self.send_response(200)
        self.send_header("Content-Type", "application/octet-stream")
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("X-Content-Type-Options", "nosniff")
        encoded = urllib.parse.quote(filename, safe="")
        self.send_header("Content-Disposition", f"attachment; filename*=UTF-8''{encoded}")
        self.end_headers()
        self.wfile.write(payload)


class ProductServer(ThreadingHTTPServer):
    def __init__(self, address, product: Product):
        super().__init__(address, Handler)
        self.product = product


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--bind", default="127.0.0.1")
    parser.add_argument("--port", default=18820, type=int)
    parser.add_argument("--runtime-root", required=True, type=Path)
    parser.add_argument("--chat-database", required=True, type=Path)
    parser.add_argument("--csv-capability", required=True, type=Path)
    parser.add_argument("--acceptance-receipt", required=True, type=Path)
    parser.add_argument("--fedex-application-archive", required=True, type=Path)
    parser.add_argument("--fedex-acceptance-receipt", required=True, type=Path)
    parser.add_argument("--fedex-devkit-wheel", required=True, type=Path)
    parser.add_argument("--fedex-expected-identity", required=True, type=Path)
    parser.add_argument("--fedex-connection-id", default="cosmain-fedex-rates")
    parser.add_argument("--fedex-grant-id", default="owner-cosmain-fedex-quote")
    parser.add_argument(
        "--invoice-application-archive", type=Path,
        default=REPOSITORY_ROOT / "acceptance/fixtures/documents.proforma_invoice/documents.proforma_invoice.zip",
    )
    parser.add_argument(
        "--invoice-acceptance-receipt", type=Path,
        default=REPOSITORY_ROOT / "acceptance/documents.proforma_invoice/ACCEPTANCE-RECEIPT.json",
    )
    parser.add_argument(
        "--invoice-devkit-wheel-base64", type=Path,
        default=REPOSITORY_ROOT / "acceptance/fixtures/documents.proforma_invoice/capy_script_devkit-0.0.0-py3-none-any.whl.base64",
    )
    parser.add_argument(
        "--invoice-expected-identity", type=Path,
        default=REPOSITORY_ROOT / "acceptance/documents.proforma_invoice/EXPECTED-IDENTITY.json",
    )
    parser.add_argument("--provider-credential", required=True, type=Path)
    parser.add_argument("--connection-socket", required=True, type=Path)
    parser.add_argument(
        "--scripts-repository", type=Path,
        default=Path("/opt/capy-scripts/current"),
    )
    parser.add_argument("--builder-scratch", type=Path)
    parser.add_argument("--owner-user", default="capy-p06-alpha")
    parser.add_argument("--beta-user", default="capy-p06-beta")
    parser.add_argument("--member-user")
    parser.add_argument("--builder-user", default="capy-builder")
    parser.add_argument("--encar-watcher-executable", type=Path)
    parser.add_argument("--encar-watcher-state-root", type=Path)
    parser.add_argument("--encar-watcher-team-id")
    parser.add_argument("--semantic-dispatch", action="store_true")
    args = parser.parse_args()
    if args.bind != "127.0.0.1" or not 1 <= args.port <= 65535:
        raise SystemExit("local owner bind is required")
    product = Product(args)
    server = ProductServer((args.bind, args.port), product)
    print(json.dumps({
        "status": "ready", "bind": args.bind, "port": args.port,
        "csv_version": product.version, "fedex_version": product.fedex_version,
    }, sort_keys=True), flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
        product.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
