"""Revalidating invocation gate and bounded short-lived process runner."""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

from .connections import ConnectionControl
from .executor import RUNNER_VERSION, atomic_json
from .launcher import ExecutionIdentity, Launcher, LocalProcessLauncher
from .model import RuntimeFailure, validate_json
from .store import RuntimeStore, canonical_json, sha256, utc_now


MAX_RESULT_BYTES = 1024 * 1024
MAX_ARTIFACT_BYTES = 64 * 1024 * 1024
RUNTIME_VERSION = "capy.outcome-runtime/v0-devkit-fit"


@dataclass(frozen=True)
class InvocationResult:
    invocation_id: str
    result: dict[str, Any]
    artifacts: tuple[dict[str, Any], ...]
    receipt: dict[str, Any]


class OutcomeRuntime:
    """Executes only exact published versions selected by scope bindings."""

    def __init__(
        self,
        store: RuntimeStore,
        *,
        launcher: Launcher | None = None,
        credential_resolver: Callable[[str, str], Path] | None = None,
        connection_control: ConnectionControl | None = None,
        broker_socket: Path | None = None,
        script_sdk_root: Path | None = None,
        stop_hook: Callable[[str, str], None] | None = None,
    ):
        self.store = store
        self.launcher = launcher or LocalProcessLauncher()
        self.credential_resolver = credential_resolver
        self.connection_control = connection_control
        self.broker_socket = broker_socket
        self.script_sdk_root = script_sdk_root
        self.stop_hook = stop_hook

    def invoke(
        self,
        scope_id: str,
        capability_id: str,
        request: dict[str, Any],
        *,
        resource_digests: list[str] | None = None,
        expected_version_digest: str | None = None,
        idempotency_key: str | None = None,
        resource_bindings: dict[str, list[str]] | None = None,
        on_invocation_started: Callable[[str], None] | None = None,
        initiator: dict[str, str] | None = None,
    ) -> InvocationResult:
        if not isinstance(request, dict):
            raise RuntimeFailure("INVOCATION_INPUT_INVALID")
        initiator_fields = {
            "authority_id", "principal_id", "membership_id", "team_id", "execution_scope_id"
        }
        if initiator is not None and (
            not isinstance(initiator, dict)
            or set(initiator) != initiator_fields
            or not all(isinstance(value, str) and value for value in initiator.values())
            or initiator["execution_scope_id"] != scope_id
        ):
            raise RuntimeFailure("INVOCATION_INITIATOR_INVALID")
        try:
            request_bytes = canonical_json(request)
        except (TypeError, ValueError) as exc:
            raise RuntimeFailure("INVOCATION_INPUT_INVALID") from exc
        binding = self.store.binding(scope_id, capability_id)
        if (
            expected_version_digest is not None
            and binding.version_digest != expected_version_digest
        ):
            raise RuntimeFailure("INVOCATION_VERSION_CHANGED")
        descriptor = self.store.descriptor(capability_id, binding.version_digest)
        validate_json(request, descriptor.input_schema, "INVOCATION_INPUT_SCHEMA_MISMATCH")
        if descriptor.side_effect == "external_effect":
            raise RuntimeFailure("EXTERNAL_EFFECT_APPROVAL_BOUNDARY_UNAVAILABLE")
        try:
            identity = self.launcher.execution_identity(scope_id)
        except (KeyError, ValueError) as exc:
            raise RuntimeFailure("SCOPE_EXECUTION_IDENTITY_UNKNOWN") from exc
        selected_connections: list[dict[str, Any]] = []
        requirements = {item.name: item for item in descriptor.connection_requirements}
        for name in descriptor.connections:
            if name in requirements:
                if self.connection_control is None or self.broker_socket is None:
                    raise RuntimeFailure("CONNECTION_UNAVAILABLE", name)
                requirement = requirements[name]
                grant = self.connection_control.resolve_grant(
                    binding.connections[name], scope_id=scope_id,
                    capability_id=descriptor.id, version_digest=binding.version_digest,
                    contract=requirement.contract,
                )
                if not set(requirement.operations) <= set(grant["operations"]):
                    raise RuntimeFailure("CONNECTION_OPERATION_DENIED", name)
                selected_connections.append({
                    "name": name, "grant_id": binding.connections[name],
                    "contract": requirement.contract, "operations": requirement.operations,
                })
                continue
            if self.credential_resolver is None:
                raise RuntimeFailure("CONNECTION_UNAVAILABLE", name)
            try:
                source = self.credential_resolver(scope_id, binding.connections[name])
                valid = source.is_file() and not source.is_symlink() and not source.stat().st_mode & 0o077
            except OSError as exc:
                raise RuntimeFailure("CONNECTION_CREDENTIAL_INVALID", name) from exc
            if not valid:
                raise RuntimeFailure("CONNECTION_CREDENTIAL_INVALID", name)
            selected_connections.append({"name": name, "credential": source})
        requested_resources = resource_digests or []
        slot_by_digest: dict[str, str] = {}
        if descriptor.schema == "capy.script/dev-v0":
            declared_slots = {item.name: item for item in descriptor.resource_requirements}
            if resource_bindings is None:
                if len(declared_slots) == 1:
                    only_slot = next(iter(declared_slots))
                    resource_bindings = {only_slot: list(requested_resources)}
                elif requested_resources:
                    raise RuntimeFailure("INVOCATION_RESOURCE_BINDING_REQUIRED")
                else:
                    resource_bindings = {}
            if (
                not isinstance(resource_bindings, dict)
                or set(resource_bindings) - set(declared_slots)
                or any(
                    not isinstance(values, list) or not all(isinstance(item, str) for item in values)
                    for values in resource_bindings.values()
                )
            ):
                raise RuntimeFailure("INVOCATION_RESOURCE_BINDING_INVALID")
            flattened = []
            for name, requirement in declared_slots.items():
                values = resource_bindings.get(name, [])
                if not requirement.min_items <= len(values) <= requirement.max_items:
                    raise RuntimeFailure("INVOCATION_RESOURCE_COUNT_MISMATCH", name)
                flattened.extend(values)
                slot_by_digest.update({digest: name for digest in values})
            if requested_resources and requested_resources != flattened:
                raise RuntimeFailure("INVOCATION_RESOURCE_BINDING_INVALID")
            requested_resources = flattened
        if len(requested_resources) != len(set(requested_resources)):
            raise RuntimeFailure("INVOCATION_RESOURCE_DUPLICATE")
        selected_resources = []
        for digest in requested_resources:
            path, filename = self.store.resource(scope_id, digest)
            try:
                if path.is_symlink() or not path.is_file():
                    raise RuntimeFailure("RESOURCE_BYTES_INVALID")
                payload = path.read_bytes()
                if sha256(payload) != digest:
                    raise RuntimeFailure("RESOURCE_BYTES_INVALID")
            except OSError as exc:
                raise RuntimeFailure("RESOURCE_BYTES_INVALID") from exc
            selected_resources.append((digest, payload, filename, slot_by_digest.get(digest)))
        request_digest = sha256(canonical_json({
            "input": request,
            "resource_digests": requested_resources,
            "connections": sorted(item["name"] for item in selected_connections),
        }))
        invocation_id, existing = self.store.begin_invocation(
            scope_id, capability_id, binding.version_digest, request_digest, idempotency_key
        )
        if existing is not None:
            return InvocationResult(
                invocation_id,
                existing["result"],
                tuple(existing["artifacts"] or []),
                existing["receipt"],
            )
        for item in selected_connections:
            if "grant_id" in item:
                item["invocation_grant"] = self.connection_control.issue_invocation_grant(
                    invocation_id=invocation_id, grant_id=item["grant_id"],
                    connection_name=item["name"], scope_id=scope_id,
                    capability_id=descriptor.id, version_digest=binding.version_digest,
                    contract=item["contract"], operations=item["operations"],
                    expected_uid=identity.uid if identity is not None else None,
                )
        if on_invocation_started is not None:
            on_invocation_started(invocation_id)
        self._stop("after_invocation_row_allocation", invocation_id)
        started = time.monotonic()
        try:
            result, artifacts = self._run(
                invocation_id,
                scope_id,
                descriptor,
                binding.version_digest,
                request_bytes,
                selected_resources,
                selected_connections,
                identity,
                initiator,
            )
            persisted = self.store.invocation(invocation_id)
            if persisted["status"] == "succeeded":
                return InvocationResult(
                    invocation_id,
                    persisted["result"],
                    tuple(persisted["artifacts"] or []),
                    persisted["receipt"],
                )
            receipt = {
                "schema": "capy.invocation-receipt/v0",
                "invocation_id": invocation_id,
                "scope_id": scope_id,
                "capability_id": capability_id,
                "version_digest": binding.version_digest,
                "request_digest": request_digest,
                "resource_digests": sorted(item[0] for item in selected_resources),
                "connections": sorted(item["name"] for item in selected_connections),
                "connection_receipts": [
                    item["id"] for item in self.connection_control.receipts(invocation_id)
                ] if self.connection_control is not None else [],
                "result_digest": sha256(canonical_json(result)),
                "artifact_digests": sorted(item["digest"] for item in artifacts),
                "status": "succeeded",
                "duration_ms": round((time.monotonic() - started) * 1000),
                "completed_at": utc_now(),
                **({"initiator": dict(initiator)} if initiator is not None else {}),
            }
            self.store.finish_invocation(
                invocation_id, "succeeded", receipt, result=result, artifacts=artifacts
            )
            return InvocationResult(invocation_id, result, tuple(artifacts), receipt)
        except RuntimeFailure as exc:
            if exc.code == "INVOCATION_EXECUTION_UNKNOWN":
                raise
            if self.store.invocation(invocation_id)["status"] != "running":
                raise
            devkit_facts, cleanup = self._devkit_failure_context(
                descriptor, binding.version_digest, invocation_id
            )
            receipt = {
                "schema": "capy.invocation-receipt/v0",
                "invocation_id": invocation_id,
                "scope_id": scope_id,
                "capability_id": capability_id,
                "version_digest": binding.version_digest,
                "request_digest": request_digest,
                "resource_digests": sorted(item[0] for item in selected_resources),
                "connections": sorted(item["name"] for item in selected_connections),
                "connection_receipts": [
                    item["id"] for item in self.connection_control.receipts(invocation_id)
                ] if self.connection_control is not None else [],
                "status": "failed",
                "failure_code": exc.code,
                "duration_ms": round((time.monotonic() - started) * 1000),
                "completed_at": utc_now(),
                **({"initiator": dict(initiator)} if initiator is not None else {}),
                **devkit_facts,
                **({"cleanup": cleanup} if cleanup is not None else {}),
            }
            self.store.finish_invocation(invocation_id, "failed", receipt)
            raise
        except Exception as exc:
            devkit_facts, cleanup = self._devkit_failure_context(
                descriptor, binding.version_digest, invocation_id
            )
            receipt = {
                "schema": "capy.invocation-receipt/v0",
                "invocation_id": invocation_id,
                "scope_id": scope_id,
                "capability_id": capability_id,
                "version_digest": binding.version_digest,
                "request_digest": request_digest,
                "resource_digests": sorted(item[0] for item in selected_resources),
                "connections": sorted(item["name"] for item in selected_connections),
                "connection_receipts": [
                    item["id"] for item in self.connection_control.receipts(invocation_id)
                ] if self.connection_control is not None else [],
                "status": "failed",
                "failure_code": "INVOCATION_INTERNAL_ERROR",
                "duration_ms": round((time.monotonic() - started) * 1000),
                "completed_at": utc_now(),
                **({"initiator": dict(initiator)} if initiator is not None else {}),
                **devkit_facts,
                **({"cleanup": cleanup} if cleanup is not None else {}),
            }
            self.store.finish_invocation(invocation_id, "failed", receipt)
            raise RuntimeFailure("INVOCATION_INTERNAL_ERROR") from exc

    def _stop(self, stage: str, invocation_id: str) -> None:
        if self.stop_hook is not None:
            self.stop_hook(stage, invocation_id)

    def _run(
        self,
        invocation_id: str,
        scope_id: str,
        descriptor: Any,
        version_digest: str,
        request_bytes: bytes,
        resources: list[tuple[str, bytes, str, str | None]],
        connections: list[dict[str, Any]],
        identity: ExecutionIdentity | None,
        initiator: dict[str, str] | None,
    ) -> tuple[dict[str, Any], list[dict[str, Any]]]:
        journal = self.store.journals / invocation_id
        journal.mkdir(mode=0o700)
        self._own(journal, 0o700, identity)
        resource_root = journal / "resources"
        credential_root = journal / "credentials"
        output_root = journal / "output-staging"
        for path in (resource_root, credential_root, output_root):
            path.mkdir(mode=0o700)
            self._own(path, 0o700, identity)
        resource_manifest = []
        for resource_digest, payload, filename, slot in resources:
            target = resource_root / resource_digest
            target.write_bytes(payload)
            self._own(target, 0o400, identity)
            item = {"digest": resource_digest, "filename": filename, "path": str(target)}
            if descriptor.schema == "capy.script/dev-v0":
                item["slot"] = slot
            resource_manifest.append(item)
        legacy_manifest = {}
        broker_handles = {}
        for item in connections:
            name = item["name"]
            if "credential" in item:
                target = credential_root / name
                shutil.copyfile(item["credential"], target)
                self._own(target, 0o400, identity)
                legacy_manifest[name] = str(target)
            else:
                broker_handles[name] = {
                    "contract": item["contract"],
                    "operations": list(item["operations"]),
                    "socket_path": str(self.broker_socket),
                    "invocation_grant": item["invocation_grant"],
                }
        connection_manifest = (
            {"schema": "capy.connection-manifest/v0", "invocation_id": invocation_id, "connections": broker_handles}
            if broker_handles else legacy_manifest
        )
        script_root = self.store.scripts / version_digest
        entrypoint = script_root / descriptor.entrypoint
        if not entrypoint.is_file():
            raise RuntimeFailure("CAPABILITY_VERSION_CORRUPT")
        state_path = self.store.state_path(scope_id, descriptor.id) if descriptor.state_required else None
        if state_path is not None:
            self._own(state_path, 0o700, identity)
        unit_name = f"capy-outcome-invocation-{invocation_id}"
        launch_nonce = uuid.uuid4().hex
        sdk_root = None
        devkit_publication = None
        if descriptor.schema == "capy.script/dev-v0":
            devkit_publication = self.store.execution_release(descriptor.id, version_digest)
            sdk_root = self.store.devkit_environment(descriptor.id, version_digest)
        elif descriptor.schema == "capy.script/v1":
            sdk_root = self.script_sdk_root
        spec = {
            "schema": "capy.executor-spec/v0",
            "invocation_id": invocation_id,
            "scope_id": scope_id,
            "capability_id": descriptor.id,
            "version_digest": version_digest,
            "request_digest": sha256(canonical_json({
                "input": json.loads(request_bytes),
                "resource_digests": [item[0] for item in resources],
                "connections": sorted(item["name"] for item in connections),
            })),
            "resource_digests": [item[0] for item in resources],
            "connection_names": sorted(item["name"] for item in connections),
            "state_required": descriptor.state_required,
            "state_path": str(state_path) if state_path is not None else None,
            "timeout_seconds": descriptor.timeout_seconds,
            "memory_mb": descriptor.memory_mb,
            "unit_name": unit_name,
            "machine_id_sha256": self.launcher.machine_id_sha256(),
            "boot_id": self.launcher.boot_id(),
            "runner_version": RUNNER_VERSION,
            "launch_nonce": launch_nonce,
            "journal_path_identity": sha256(str(journal).encode()),
            "created_at": utc_now(),
            "python": sys.executable,
            "script_root": str(script_root),
            "entrypoint": str(entrypoint),
            "script_sdk_root": str(sdk_root) if sdk_root else None,
            "resource_slots": [item.name for item in descriptor.resource_requirements],
            "application_archive_digest": (
                devkit_publication["archive_digest"] if devkit_publication else None
            ),
            "devkit_wheel_digest": (
                devkit_publication["wheel_digest"] if devkit_publication else None
            ),
            "devkit_environment_digest": (
                devkit_publication["environment_digest"] if devkit_publication else None
            ),
            "publication_identity_digest": (
                devkit_publication.get("publication_identity_digest") if devkit_publication else None
            ),
        }
        if devkit_publication and devkit_publication.get("import_identity_digest"):
            spec["import_identity_digest"] = devkit_publication["import_identity_digest"]
        if initiator is not None:
            spec["initiator"] = dict(initiator)
        spec_payload = atomic_json(journal / "executor-spec.json", spec)
        atomic_json(journal / "request.json", json.loads(request_bytes))
        atomic_json(journal / "resource-manifest.json", resource_manifest)
        if connection_manifest:
            atomic_json(journal / "connection-manifest.json", connection_manifest)
        for path in journal.iterdir():
            if path.is_file():
                self._own(path, 0o400, identity)
        self.store.record_executor(
            invocation_id,
            {
                "unit_name": unit_name,
                "machine_id_sha256": spec["machine_id_sha256"],
                "boot_id": spec["boot_id"],
                "launch_nonce": launch_nonce,
                "journal_path": str(journal),
                "journal_digest": sha256(spec_payload),
            },
        )
        self._stop("after_journal_prepared", invocation_id)
        runner = Path(__file__).with_name("executor.py").resolve()
        self.launcher.launch_journal(
            journal,
            runner,
            unit=unit_name,
            timeout_seconds=descriptor.timeout_seconds,
            memory_mb=descriptor.memory_mb,
            read_only_paths=[script_root, resource_root, runner]
            + ([sdk_root] if sdk_root else [])
            + ([self.broker_socket] if broker_handles and self.broker_socket else []),
            writable_paths=[journal] + ([state_path] if state_path is not None else []),
            identity=identity,
        )
        launch_receipt = {
            "schema": "capy.executor-launch-receipt/v0",
            "invocation_id": invocation_id,
            "unit_name": unit_name,
            "launch_nonce": launch_nonce,
            "boot_id": spec["boot_id"],
            "launched_at": utc_now(),
        }
        atomic_json(journal / "launch-receipt.json", launch_receipt)
        self._own(journal / "launch-receipt.json", 0o400, identity)
        self.store.update_executor(invocation_id, "LAUNCHED", last_unit_state="launched")
        self._stop("after_systemd_launch_acknowledged", invocation_id)
        terminal_path = journal / "executor-terminal-receipt.json"
        deadline = time.monotonic() + descriptor.timeout_seconds + 8
        while time.monotonic() < deadline:
            if terminal_path.is_file():
                self._stop("after_runner_terminal_receipt", invocation_id)
                completed = self._adopt_terminal(invocation_id)
                self._stop("after_runtime_finalization", invocation_id)
                return completed.result, list(completed.artifacts)
            unit_state = self.launcher.unit_state(unit_name)
            if self._unit_active(unit_state):
                self.store.update_executor(invocation_id, "RUNNING", last_unit_state=unit_state)
            elif unit_state != "inactive" and "inactive" not in unit_state:
                break
            time.sleep(0.05)
        if terminal_path.is_file():
            completed = self._adopt_terminal(invocation_id)
            return completed.result, list(completed.artifacts)
        self.store.mark_execution_unknown(invocation_id, self.launcher.unit_state(unit_name))
        raise RuntimeFailure("INVOCATION_EXECUTION_UNKNOWN")

    @staticmethod
    def _unit_active(state: str) -> bool:
        return bool({"active", "activating", "deactivating"} & set(state.split(":")))

    def _adopt_terminal(self, invocation_id: str) -> InvocationResult:
        executor = self.store.executor(invocation_id)
        invocation = self.store.invocation(invocation_id)
        if invocation["status"] == "succeeded":
            return InvocationResult(
                invocation_id,
                invocation["result"],
                tuple(invocation["artifacts"] or []),
                invocation["receipt"],
            )
        journal = Path(executor["journal_path"])
        spec_payload = (journal / "executor-spec.json").read_bytes()
        if sha256(spec_payload) != executor["journal_digest"]:
            raise RuntimeFailure("EXECUTOR_SPEC_TAMPERED")
        spec = json.loads(spec_payload)
        terminal_payload = (journal / "executor-terminal-receipt.json").read_bytes()
        terminal = json.loads(terminal_payload)
        required = {
            "schema", "invocation_id", "launch_nonce", "scope_id", "capability_id",
            "version_digest", "request_digest", "resource_digests", "connection_names",
            "unit_name", "boot_id", "process_exit_class", "returncode",
            "stdout_digest", "stdout_size", "stderr_digest", "stderr_size", "artifacts",
            "executor_result_digest", "completed_at", "runner_version",
        }
        if (
            set(terminal) != required
            or terminal["schema"] != "capy.executor-terminal-receipt/v0"
            or terminal["invocation_id"] != invocation_id
            or terminal["launch_nonce"] != executor["launch_nonce"]
            or terminal["scope_id"] != invocation["scope_id"]
            or terminal["capability_id"] != invocation["capability_id"]
            or terminal["version_digest"] != invocation["version_digest"]
            or terminal["request_digest"] != invocation["request_digest"]
            or terminal["resource_digests"] != spec["resource_digests"]
            or terminal["connection_names"] != spec["connection_names"]
            or terminal["unit_name"] != executor["unit_name"]
            or terminal["boot_id"] != executor["boot_id"]
            or terminal["runner_version"] != RUNNER_VERSION
        ):
            raise RuntimeFailure("EXECUTOR_TERMINAL_RECEIPT_INVALID")
        stdout = (journal / "stdout.bin").read_bytes()
        stderr = (journal / "stderr.bin").read_bytes()
        result_payload = (journal / "executor-result.json").read_bytes()
        if (
            len(stdout) != terminal["stdout_size"]
            or sha256(stdout) != terminal["stdout_digest"]
            or len(stderr) != terminal["stderr_size"]
            or sha256(stderr) != terminal["stderr_digest"]
            or sha256(result_payload) != terminal["executor_result_digest"]
        ):
            raise RuntimeFailure("EXECUTOR_TERMINAL_RECEIPT_INVALID")
        terminal_digest = sha256(terminal_payload)
        self.store.update_executor(
            invocation_id,
            "TERMINAL_RECEIPT_AVAILABLE",
            last_unit_state="terminal_receipt",
            terminal_receipt_digest=terminal_digest,
        )
        self._stop("before_runtime_sqlite_finalization", invocation_id)
        if terminal["process_exit_class"] != "exited_0" or terminal["returncode"] != 0:
            failure_code = (
                "INVOCATION_TIMEOUT"
                if terminal["process_exit_class"] == "timeout"
                else "INVOCATION_PROCESS_FAILED"
            )
            descriptor = self.store.descriptor(invocation["capability_id"], invocation["version_digest"])
            if descriptor.schema == "capy.script/dev-v0" and terminal["returncode"] == 2:
                failure_code = self._application_failure_code(stderr) or failure_code
            cleanup = self._cleanup_devkit_journal(journal, spec)
            receipt = self._failure_receipt(
                invocation, spec, failure_code, terminal_digest, cleanup=cleanup
            )
            self.store.finish_invocation(invocation_id, "failed", receipt)
            raise RuntimeFailure(failure_code)
        if len(stdout) > MAX_RESULT_BYTES:
            raise RuntimeFailure("INVOCATION_RESULT_TOO_LARGE")
        try:
            result = json.loads(
                stdout,
                parse_constant=lambda value: (_ for _ in ()).throw(ValueError(value)),
            )
        except (UnicodeError, ValueError, json.JSONDecodeError) as exc:
            raise RuntimeFailure("INVOCATION_RESULT_INVALID") from exc
        if not isinstance(result, dict):
            raise RuntimeFailure("INVOCATION_RESULT_INVALID")
        declared = result.pop("artifacts", [])
        if (
            not isinstance(declared, list)
            or not all(isinstance(item, str) for item in declared)
            or len(declared) != len(set(declared))
        ):
            raise RuntimeFailure("INVOCATION_ARTIFACT_INVALID")
        descriptor = self.store.descriptor(invocation["capability_id"], invocation["version_digest"])
        validate_json(result, descriptor.result_schema, "INVOCATION_RESULT_SCHEMA_MISMATCH")
        output_root = journal / "output-staging"
        actual = sorted(item.name for item in output_root.iterdir())
        if actual != sorted(declared):
            raise RuntimeFailure("INVOCATION_UNDECLARED_OUTPUT")
        terminal_artifacts = {item["filename"]: item for item in terminal["artifacts"]}
        if set(terminal_artifacts) != set(declared):
            raise RuntimeFailure("INVOCATION_ARTIFACT_INVALID")
        artifacts = []
        for name in declared:
            candidate = output_root / name
            payload = candidate.read_bytes()
            fact = terminal_artifacts[name]
            if (
                candidate.is_symlink()
                or not candidate.is_file()
                or fact != {"filename": name, "digest": sha256(payload), "size_bytes": len(payload)}
            ):
                raise RuntimeFailure("INVOCATION_ARTIFACT_INVALID")
            registered = self.store.add_resource(invocation["scope_id"], name, payload)
            artifacts.append({"filename": name, "digest": registered, "size_bytes": len(payload)})
        cleanup = self._cleanup_devkit_journal(journal, spec)
        receipt = {
            "schema": "capy.invocation-receipt/v0",
            "invocation_id": invocation_id,
            "scope_id": invocation["scope_id"],
            "capability_id": invocation["capability_id"],
            "version_digest": invocation["version_digest"],
            "request_digest": invocation["request_digest"],
            "resource_digests": spec["resource_digests"],
            "connections": spec["connection_names"],
            "connection_receipts": [
                item["id"] for item in self.connection_control.receipts(invocation_id)
            ] if self.connection_control is not None else [],
            "result_digest": sha256(canonical_json(result)),
            "artifact_digests": sorted(item["digest"] for item in artifacts),
            "executor_terminal_receipt_digest": terminal_digest,
            "status": "succeeded",
            "duration_ms": 0,
            "completed_at": utc_now(),
            **({"initiator": spec["initiator"]} if "initiator" in spec else {}),
            **self._devkit_receipt_facts(spec),
            **({"cleanup": cleanup} if cleanup is not None else {}),
        }
        self.store.finish_invocation(
            invocation_id, "succeeded", receipt, result=result, artifacts=artifacts
        )
        return InvocationResult(invocation_id, result, tuple(artifacts), receipt)

    def _failure_receipt(
        self,
        invocation: dict[str, Any],
        spec: dict[str, Any],
        code: str,
        terminal_digest: str,
        *,
        cleanup: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        return {
            "schema": "capy.invocation-receipt/v0",
            "invocation_id": invocation["id"],
            "scope_id": invocation["scope_id"],
            "capability_id": invocation["capability_id"],
            "version_digest": invocation["version_digest"],
            "request_digest": invocation["request_digest"],
            "resource_digests": spec["resource_digests"],
            "connections": spec["connection_names"],
            "connection_receipts": [
                item["id"] for item in self.connection_control.receipts(invocation["id"])
            ] if self.connection_control is not None else [],
            "status": "failed",
            "failure_code": code,
            "executor_terminal_receipt_digest": terminal_digest,
            "duration_ms": 0,
            "completed_at": utc_now(),
            **({"initiator": spec["initiator"]} if "initiator" in spec else {}),
            **self._devkit_receipt_facts(spec),
            **({"cleanup": cleanup} if cleanup is not None else {}),
        }

    @staticmethod
    def _application_failure_code(stderr: bytes) -> str | None:
        lines = stderr.decode("utf-8", "replace").strip().splitlines()
        if not lines:
            return None
        match = re.fullmatch(r"([A-Z][A-Z0-9_]{0,127})(?:: [^\x00\r\n]{1,512})?", lines[-1])
        return match.group(1) if match else None

    @staticmethod
    def _devkit_receipt_facts(spec: dict[str, Any]) -> dict[str, Any]:
        if spec.get("application_archive_digest") is None:
            return {}
        return {
            "runtime_version": RUNTIME_VERSION,
            "application_archive_digest": spec["application_archive_digest"],
            "devkit_wheel_digest": spec["devkit_wheel_digest"],
            "devkit_environment_digest": spec["devkit_environment_digest"],
            "publication_identity_digest": spec["publication_identity_digest"],
            "import_identity_digest": spec.get("import_identity_digest"),
            "resource_slots": spec["resource_slots"],
        }

    def _devkit_failure_context(
        self, descriptor: Any, version_digest: str, invocation_id: str
    ) -> tuple[dict[str, Any], dict[str, Any] | None]:
        if descriptor.schema != "capy.script/dev-v0":
            return {}, None
        publication = self.store.execution_release(descriptor.id, version_digest)
        spec = {
            "application_archive_digest": publication["archive_digest"],
            "devkit_wheel_digest": publication["wheel_digest"],
            "devkit_environment_digest": publication["environment_digest"],
            "publication_identity_digest": publication.get("publication_identity_digest"),
            "import_identity_digest": publication.get("import_identity_digest"),
            "resource_slots": [item.name for item in descriptor.resource_requirements],
        }
        cleanup = self._cleanup_devkit_journal(self.store.journals / invocation_id, spec)
        return self._devkit_receipt_facts(spec), cleanup

    @staticmethod
    def _cleanup_devkit_journal(
        journal: Path, spec: dict[str, Any]
    ) -> dict[str, Any] | None:
        if spec.get("application_archive_digest") is None:
            return None
        for name in ("resources", "credentials", "output-staging"):
            shutil.rmtree(journal / name, ignore_errors=True)
        (journal / "connection-manifest.json").unlink(missing_ok=True)
        return {
            "credential_projections_remaining": 0,
            "transient_processes_remaining": 0,
            "invocation_sockets_remaining": 0,
            "temporary_package_roots_remaining": 0,
            "connection_manifest_remaining": 0,
        }

    def reconcile_incomplete(self) -> list[dict[str, str]]:
        results = []
        current_boot = self.launcher.boot_id()
        for executor in self.store.pending_executors():
            invocation_id = executor["invocation_id"]
            journal = Path(executor["journal_path"])
            if (journal / "executor-terminal-receipt.json").is_file():
                try:
                    self._adopt_terminal(invocation_id)
                except RuntimeFailure as exc:
                    results.append({"invocation_id": invocation_id, "result": exc.code})
                else:
                    results.append({"invocation_id": invocation_id, "result": "FINALIZED"})
                continue
            if executor["boot_id"] != current_boot:
                self.store.mark_execution_unknown(invocation_id, "boot_changed_without_receipt")
                results.append({"invocation_id": invocation_id, "result": "EXECUTION_UNKNOWN"})
                continue
            unit_state = self.launcher.unit_state(executor["unit_name"])
            if self._unit_active(unit_state):
                self.store.update_executor(invocation_id, "RUNNING", last_unit_state=unit_state)
                results.append({"invocation_id": invocation_id, "result": "RUNNING"})
                continue
            self.store.mark_execution_unknown(invocation_id, unit_state)
            results.append({"invocation_id": invocation_id, "result": "EXECUTION_UNKNOWN"})
        return results

    def _run_legacy(
        self,
        invocation_id: str,
        scope_id: str,
        descriptor: Any,
        version_digest: str,
        request_bytes: bytes,
        resources: list[tuple[str, bytes, str]],
        connections: list[tuple[str, Path]],
        identity: ExecutionIdentity | None,
    ) -> tuple[dict[str, Any], list[dict[str, Any]]]:
        invocation_root = Path(tempfile.mkdtemp(prefix=f"{invocation_id}-", dir=self.store.invocations))
        self._own(invocation_root, 0o700, identity)
        resource_root = invocation_root / "resources"
        credential_root = invocation_root / "credentials"
        output_root = invocation_root / "output"
        resource_root.mkdir(mode=0o700)
        credential_root.mkdir(mode=0o700)
        output_root.mkdir(mode=0o700)
        for path in (resource_root, credential_root, output_root):
            self._own(path, 0o700, identity)
        resource_manifest = []
        connection_manifest = {}
        try:
            for digest, payload, filename in resources:
                target = resource_root / digest
                target.write_bytes(payload)
                self._own(target, 0o400, identity)
                resource_manifest.append({"digest": digest, "filename": filename, "path": str(target)})
            for name, source in connections:
                target = credential_root / name
                shutil.copyfile(source, target)
                self._own(target, 0o400, identity)
                connection_manifest[name] = str(target)
            script_root = self.store.scripts / version_digest
            entrypoint = script_root / descriptor.entrypoint
            if not entrypoint.is_file():
                raise RuntimeFailure("CAPABILITY_VERSION_CORRUPT")
            environment = {
                "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
                "LANG": "C.UTF-8",
                "LC_ALL": "C.UTF-8",
                "PYTHONIOENCODING": "utf-8",
                "CAPY_INVOCATION_ID": invocation_id,
                "CAPY_RESOURCE_MANIFEST": json.dumps(resource_manifest, separators=(",", ":")),
                "CAPY_CONNECTION_MANIFEST": json.dumps(connection_manifest, separators=(",", ":")),
                "CAPY_OUTPUT_DIR": str(output_root),
            }
            if descriptor.state_required:
                state_path = self.store.state_path(scope_id, descriptor.id)
                self._own(state_path, 0o700, identity)
                environment["CAPY_STATE_DIR"] = str(state_path)
            argv = [sys.executable, "-I", str(entrypoint)] if entrypoint.suffix == ".py" else [str(entrypoint)]
            try:
                completed = self.launcher.run(
                    argv,
                    input_bytes=request_bytes,
                    cwd=script_root,
                    environment=environment,
                    timeout_seconds=descriptor.timeout_seconds,
                    memory_mb=descriptor.memory_mb,
                    read_only_paths=[script_root, resource_root, credential_root],
                    writable_paths=[output_root]
                    + ([self.store.state_path(scope_id, descriptor.id)] if descriptor.state_required else []),
                    identity=identity,
                )
            except subprocess.TimeoutExpired as exc:
                raise RuntimeFailure("INVOCATION_TIMEOUT") from exc
            if completed.returncode != 0:
                if completed.failure_code:
                    raise RuntimeFailure(completed.failure_code)
                raise RuntimeFailure("INVOCATION_PROCESS_FAILED", str(completed.returncode))
            if len(completed.stdout) > MAX_RESULT_BYTES:
                raise RuntimeFailure("INVOCATION_RESULT_TOO_LARGE")
            try:
                result = json.loads(
                    completed.stdout,
                    parse_constant=lambda value: (_ for _ in ()).throw(ValueError(value)),
                )
            except (UnicodeError, ValueError, json.JSONDecodeError) as exc:
                raise RuntimeFailure("INVOCATION_RESULT_INVALID") from exc
            if not isinstance(result, dict):
                raise RuntimeFailure("INVOCATION_RESULT_INVALID")
            declared = result.pop("artifacts", [])
            if (
                not isinstance(declared, list)
                or not all(isinstance(item, str) for item in declared)
                or len(declared) != len(set(declared))
            ):
                raise RuntimeFailure("INVOCATION_ARTIFACT_INVALID")
            try:
                actual_outputs = sorted(item.name for item in output_root.iterdir())
            except OSError as exc:
                raise RuntimeFailure("INVOCATION_ARTIFACT_INVALID") from exc
            if actual_outputs != sorted(declared):
                raise RuntimeFailure("INVOCATION_UNDECLARED_OUTPUT")
            validate_json(result, descriptor.result_schema, "INVOCATION_RESULT_SCHEMA_MISMATCH")
            artifacts = []
            for relative in declared:
                candidate = Path(relative)
                if (
                    candidate.is_absolute()
                    or ".." in candidate.parts
                    or candidate.name != relative
                    or len(relative.encode("utf-8")) > 255
                    or any(char in relative for char in "\x00\r\n")
                ):
                    raise RuntimeFailure("INVOCATION_ARTIFACT_INVALID")
                path = output_root / candidate
                if not path.is_file() or path.is_symlink() or path.stat().st_size > MAX_ARTIFACT_BYTES:
                    raise RuntimeFailure("INVOCATION_ARTIFACT_INVALID")
                digest = self.store.add_resource(scope_id, candidate.name, path.read_bytes())
                artifacts.append({"filename": candidate.name, "digest": digest, "size_bytes": path.stat().st_size})
            return result, artifacts
        finally:
            shutil.rmtree(invocation_root, ignore_errors=True)

    @staticmethod
    def _own(path: Path, mode: int, identity: ExecutionIdentity | None) -> None:
        path.chmod(mode)
        if identity is None:
            return
        try:
            os.chown(path, identity.uid, identity.gid, follow_symlinks=False)
        except PermissionError as exc:
            raise RuntimeFailure("SCOPE_EXECUTION_IDENTITY_REQUIRES_ROOT") from exc
        actual = path.stat(follow_symlinks=False)
        if actual.st_uid != identity.uid or actual.st_gid != identity.gid:
            raise RuntimeFailure("SCOPE_EXECUTION_IDENTITY_INVALID")
