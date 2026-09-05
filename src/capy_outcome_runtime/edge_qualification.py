"""Bounded qualification helpers for declared DevKit V0 edge mechanics.

These helpers are evidence producers, not application-facing APIs.  They use
the existing exact-archive publication and runtime invocation boundaries and
return an independent supported-or-blocked judgment without changing either
contract.
"""

from __future__ import annotations

import copy
import json
import threading
import time
from pathlib import Path
from typing import Any, Mapping

from .connections import ConnectionBroker, ConnectionControl, ConnectionInstance
from .launcher import Launcher, LocalProcessLauncher
from .model import RuntimeFailure
from .runtime import OutcomeRuntime
from .store import RuntimeStore, canonical_json, sha256, utc_now


def _snapshot(root: Path) -> dict[str, dict[str, Any]]:
    if not root.is_dir():
        return {}
    return {
        str(path.relative_to(root)): {
            "sha256": sha256(path.read_bytes()),
            "size_bytes": path.stat().st_size,
        }
        for path in sorted(root.rglob("*"))
        if path.is_file()
    }


def _expected_snapshot(values: Mapping[str, bytes | str]) -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    for name, value in values.items():
        if not isinstance(name, str) or not name or Path(name).is_absolute() or ".." in Path(name).parts:
            raise RuntimeFailure("EDGE_STATE_ORACLE_INVALID")
        payload = value.encode("utf-8") if isinstance(value, str) else value
        if not isinstance(payload, bytes):
            raise RuntimeFailure("EDGE_STATE_ORACLE_INVALID")
        result[name] = {"sha256": sha256(payload), "size_bytes": len(payload)}
    return result


def _resource_bindings(
    store: RuntimeStore,
    scope_id: str,
    resource_files: Mapping[str, list[Path]] | None,
) -> dict[str, list[str]]:
    result: dict[str, list[str]] = {}
    for slot, files in (resource_files or {}).items():
        if (
            not isinstance(slot, str)
            or not slot
            or not isinstance(files, list)
            or any(not isinstance(path, Path) for path in files)
        ):
            raise RuntimeFailure("EDGE_RESOURCE_INPUT_INVALID")
        result[slot] = [
            store.add_resource(scope_id, path.name, path.read_bytes()) for path in files
        ]
    return result


def _cleanup_ok(receipt: Mapping[str, Any]) -> bool:
    cleanup = receipt.get("cleanup")
    return isinstance(cleanup, dict) and bool(cleanup) and not any(cleanup.values())


def _invocation_for_key(store: RuntimeStore, scope_id: str, key: str) -> dict[str, Any] | None:
    with store.connect() as database:
        row = database.execute(
            "SELECT id FROM invocations WHERE scope_id=? AND idempotency_key=?",
            (scope_id, key),
        ).fetchone()
    return store.invocation(row["id"]) if row is not None else None


def qualify_scope_state_sequence(
    *,
    runtime_root: Path,
    application_archive: Path,
    acceptance_receipt: Path,
    devkit_wheel: Path,
    expected_identity: dict[str, str],
    first_request: dict[str, Any],
    first_expected_result: dict[str, Any],
    second_request: dict[str, Any],
    second_expected_result: dict[str, Any],
    foreign_request: dict[str, Any],
    foreign_expected_result: dict[str, Any],
    failing_request: dict[str, Any],
    expected_failure_code: str,
    expected_owner_state_after_first: Mapping[str, bytes | str],
    expected_owner_state_after_second: Mapping[str, bytes | str],
    expected_foreign_state: Mapping[str, bytes | str],
    expected_owner_state_after_failure: Mapping[str, bytes | str],
    resource_files: Mapping[str, list[Path]] | None = None,
    launcher: Launcher | None = None,
    owner_scope: str = "edge-state-owner",
    foreign_scope: str = "edge-state-foreign",
) -> dict[str, Any]:
    """Run the fixed state/replay/reopen/isolation/failure sequence.

    A failed invocation that mutates scope-owned state is recorded as a blocked
    judgment.  It is deliberately not hidden behind an exception.
    """

    if runtime_root.exists():
        raise RuntimeFailure("EDGE_RUNTIME_ROOT_EXISTS")
    launcher = launcher or LocalProcessLauncher()
    store = RuntimeStore(runtime_root)
    for scope in (owner_scope, foreign_scope):
        store.register_scope(scope)
    receipt_bytes = acceptance_receipt.read_bytes()
    descriptor, version, publication = store.publish_devkit_archive(
        application_archive,
        receipt_bytes,
        devkit_wheel,
        expected_identity=expected_identity,
    )
    if (
        descriptor.side_effect != "scope_state_mutation"
        or not descriptor.state_required
        or descriptor.connections
    ):
        raise RuntimeFailure("EDGE_STATE_DESCRIPTOR_OUT_OF_SCOPE")
    for scope in (owner_scope, foreign_scope):
        store.bind(scope, descriptor.id, version, {})
    owner_resources = _resource_bindings(store, owner_scope, resource_files)
    foreign_resources = _resource_bindings(store, foreign_scope, resource_files)
    runtime = OutcomeRuntime(store, launcher=launcher)
    replay_key = f"edge-state-first:{descriptor.id}"

    first = runtime.invoke(
        owner_scope,
        descriptor.id,
        first_request,
        resource_bindings=owner_resources,
        expected_version_digest=version,
        idempotency_key=replay_key,
    )
    after_first = _snapshot(store.state_path(owner_scope, descriptor.id))
    replay = runtime.invoke(
        owner_scope,
        descriptor.id,
        first_request,
        resource_bindings=owner_resources,
        expected_version_digest=version,
        idempotency_key=replay_key,
    )
    after_replay = _snapshot(store.state_path(owner_scope, descriptor.id))

    reopened_store = RuntimeStore(runtime_root)
    reopened = OutcomeRuntime(reopened_store, launcher=launcher).invoke(
        owner_scope,
        descriptor.id,
        first_request,
        resource_bindings=owner_resources,
        expected_version_digest=version,
        idempotency_key=replay_key,
    )
    after_reopen = _snapshot(reopened_store.state_path(owner_scope, descriptor.id))
    second = OutcomeRuntime(reopened_store, launcher=launcher).invoke(
        owner_scope,
        descriptor.id,
        second_request,
        resource_bindings=owner_resources,
        expected_version_digest=version,
        idempotency_key=f"edge-state-second:{descriptor.id}",
    )
    after_second = _snapshot(reopened_store.state_path(owner_scope, descriptor.id))
    foreign = OutcomeRuntime(reopened_store, launcher=launcher).invoke(
        foreign_scope,
        descriptor.id,
        foreign_request,
        resource_bindings=foreign_resources,
        expected_version_digest=version,
        idempotency_key=f"edge-state-foreign:{descriptor.id}",
    )
    foreign_state = _snapshot(reopened_store.state_path(foreign_scope, descriptor.id))

    failure_code: str | None = None
    failure_invocation_id: str | None = None
    before_failure = _snapshot(reopened_store.state_path(owner_scope, descriptor.id))
    failure_key = f"edge-state-failure:{descriptor.id}"
    try:
        OutcomeRuntime(reopened_store, launcher=launcher).invoke(
            owner_scope,
            descriptor.id,
            failing_request,
            resource_bindings=owner_resources,
            expected_version_digest=version,
            idempotency_key=failure_key,
        )
    except RuntimeFailure as error:
        failure_code = error.code
        failed = _invocation_for_key(reopened_store, owner_scope, failure_key)
        if failed is not None:
            failure_invocation_id = failed["id"]
    after_failure = _snapshot(reopened_store.state_path(owner_scope, descriptor.id))
    failed_receipt = (
        reopened_store.invocation(failure_invocation_id)["receipt"]
        if failure_invocation_id is not None
        else None
    )

    expected_first = _expected_snapshot(expected_owner_state_after_first)
    expected_second = _expected_snapshot(expected_owner_state_after_second)
    expected_foreign = _expected_snapshot(expected_foreign_state)
    expected_after_failure = _expected_snapshot(expected_owner_state_after_failure)
    checks = {
        "first_result": first.result == first_expected_result,
        "first_state": after_first == expected_first,
        "exact_replay": (
            replay.invocation_id == first.invocation_id
            and replay.receipt == first.receipt
            and after_replay == after_first
        ),
        "reopen_replay": (
            reopened.invocation_id == first.invocation_id
            and reopened.receipt == first.receipt
            and after_reopen == after_first
        ),
        "second_result": second.result == second_expected_result,
        "second_state": after_second == expected_second,
        "foreign_result": foreign.result == foreign_expected_result,
        "foreign_state": foreign_state == expected_foreign,
        "foreign_scope_independent": foreign_state != after_second,
        "failure_is_causal": (
            failure_code == expected_failure_code
            and isinstance(failed_receipt, dict)
            and failed_receipt.get("status") == "failed"
            and failed_receipt.get("failure_code") == expected_failure_code
        ),
        "failed_invocation_left_state_unchanged": after_failure == expected_after_failure,
        "successful_cleanup": all(
            _cleanup_ok(item.receipt) for item in (first, second, foreign)
        ),
        "failed_cleanup": isinstance(failed_receipt, dict) and _cleanup_ok(failed_receipt),
    }
    with reopened_store.connect() as database:
        invocation_count = database.execute("SELECT COUNT(*) FROM invocations").fetchone()[0]
    blocked_reasons = [name for name, passed in checks.items() if not passed]
    return {
        "schema": "capy.edge-state-sequence-proof/v0",
        "judgment": "supported" if not blocked_reasons else "blocked",
        "blocked_reasons": blocked_reasons,
        "capability_id": descriptor.id,
        "version_digest": version,
        "application_archive_sha256": sha256(application_archive.read_bytes()),
        "acceptance_receipt_sha256": sha256(receipt_bytes),
        "devkit_wheel_sha256": sha256(devkit_wheel.read_bytes()),
        "publication_identity_sha256": publication["publication_identity_digest"],
        "checks": checks,
        "invocation_ids": {
            "first": first.invocation_id,
            "replay": replay.invocation_id,
            "reopen": reopened.invocation_id,
            "second": second.invocation_id,
            "foreign": foreign.invocation_id,
            "failure": failure_invocation_id,
        },
        "invocation_count": invocation_count,
        "state": {
            "after_first": after_first,
            "after_replay": after_replay,
            "after_reopen": after_reopen,
            "after_second": after_second,
            "foreign": foreign_state,
            "before_failure": before_failure,
            "after_failure": after_failure,
        },
        "failure_code": failure_code,
        "completed_at": utc_now(),
    }


class _EmptyResolver:
    def healthy(self, _reference: str) -> bool:
        return True

    def resolve(self, _reference: str) -> dict[str, Any]:
        return {}


class _DeterministicAdapter:
    def __init__(self, response: object):
        self.response = response
        self.calls: list[dict[str, Any]] = []

    def call(self, **values: Any) -> Any:
        self.calls.append(copy.deepcopy(values))
        return copy.deepcopy(self.response)


def _wait_for_socket(path: Path) -> None:
    deadline = time.monotonic() + 3
    while not path.exists() and time.monotonic() < deadline:
        time.sleep(0.01)
    if not path.exists():
        raise RuntimeFailure("CONNECTION_BROKER_UNAVAILABLE")


def qualify_secretless_semantic_connection(
    *,
    runtime_root: Path,
    application_archive: Path,
    acceptance_receipt: Path,
    devkit_wheel: Path,
    expected_identity: dict[str, str],
    request: dict[str, Any],
    expected_result: dict[str, Any],
    simulator_response: dict[str, Any],
    expected_connection_payload: dict[str, Any],
    resource_files: Mapping[str, list[Path]] | None = None,
    launcher: Launcher | None = None,
    scope_id: str = "edge-connection-owner",
    foreign_scope: str = "edge-connection-foreign",
    secret_scan_values: tuple[str, ...] = (),
) -> dict[str, Any]:
    """Qualify one existing ``fedex.rates/v1`` quote with secretless fixtures."""

    if runtime_root.exists():
        raise RuntimeFailure("EDGE_RUNTIME_ROOT_EXISTS")
    launcher = launcher or LocalProcessLauncher()
    store = RuntimeStore(runtime_root)
    for scope in (scope_id, foreign_scope):
        store.register_scope(scope)
    receipt_bytes = acceptance_receipt.read_bytes()
    descriptor, version, publication = store.publish_devkit_archive(
        application_archive,
        receipt_bytes,
        devkit_wheel,
        expected_identity=expected_identity,
    )
    requirements = descriptor.connection_requirements
    if (
        descriptor.side_effect != "read_only"
        or descriptor.state_required
        or len(requirements) != 1
        or requirements[0].contract != "fedex.rates/v1"
        or requirements[0].operations != ("quote",)
    ):
        raise RuntimeFailure("EDGE_CONNECTION_DESCRIPTOR_OUT_OF_SCOPE")
    connection_name = requirements[0].name
    control = ConnectionControl(store)
    instance = ConnectionInstance(
        "edge-secretless-fedex",
        "fedex.rates/v1",
        "edge-deterministic-adapter/v0",
        "publisher",
        "edge-qualifier",
        "active",
        {"label": "Secretless deterministic FedEx simulator"},
        "secret:edge-empty",
        "profile:edge-deterministic",
    )
    control.put_instance(instance)
    grant_id = "edge-owner-fedex-quote"
    control.grant(
        grant_id,
        instance.id,
        scope_id,
        "fedex.rates/v1",
        ["quote"],
        capability_id=descriptor.id,
        version_digest=version,
    )
    store.bind(scope_id, descriptor.id, version, {connection_name: grant_id})
    owner_resources = _resource_bindings(store, scope_id, resource_files)
    adapter = _DeterministicAdapter(simulator_response)
    resolver = _EmptyResolver()
    # AF_UNIX path limits are small on several supported hosts; the runtime
    # root already identifies this bounded qualifier, so keep leaf names short.
    socket_path = runtime_root / "b.sock"
    stop = threading.Event()
    broker = ConnectionBroker(
        control,
        resolver,
        {"profile:edge-deterministic": {}},
        {"edge-deterministic-adapter/v0": adapter},
    )
    thread = threading.Thread(target=broker.serve, args=(socket_path, stop), daemon=True)
    thread.start()
    _wait_for_socket(socket_path)
    unavailable_key = f"edge-connection-unavailable:{descriptor.id}"
    try:
        completed = OutcomeRuntime(
            store,
            launcher=launcher,
            connection_control=control,
            broker_socket=socket_path,
        ).invoke(
            scope_id,
            descriptor.id,
            request,
            resource_bindings=owner_resources,
            expected_version_digest=version,
            idempotency_key=f"edge-connection-success:{descriptor.id}",
        )
    finally:
        stop.set()
        thread.join(timeout=3)

    success_receipts = control.receipts(completed.invocation_id)
    unavailable_socket = runtime_root / "u.sock"
    unavailable_stop = threading.Event()
    unavailable_broker = ConnectionBroker(
        control,
        resolver,
        {"profile:edge-deterministic": {}},
        {},
    )
    unavailable_thread = threading.Thread(
        target=unavailable_broker.serve,
        args=(unavailable_socket, unavailable_stop),
        daemon=True,
    )
    unavailable_thread.start()
    _wait_for_socket(unavailable_socket)
    unavailable_code: str | None = None
    try:
        OutcomeRuntime(
            store,
            launcher=launcher,
            connection_control=control,
            broker_socket=unavailable_socket,
        ).invoke(
            scope_id,
            descriptor.id,
            request,
            resource_bindings=owner_resources,
            expected_version_digest=version,
            idempotency_key=unavailable_key,
        )
    except RuntimeFailure as error:
        unavailable_code = error.code
    finally:
        unavailable_stop.set()
        unavailable_thread.join(timeout=3)
    unavailable_invocation = _invocation_for_key(store, scope_id, unavailable_key)

    missing_binding_code: str | None = None
    malformed_key = f"edge-connection-malformed:{descriptor.id}"
    try:
        store.bind(foreign_scope, descriptor.id, version, {})
    except RuntimeFailure as error:
        missing_binding_code = error.code
    store.bind(foreign_scope, descriptor.id, version, {connection_name: grant_id})
    unauthorized_code: str | None = None
    try:
        OutcomeRuntime(
            store,
            launcher=launcher,
            connection_control=control,
            broker_socket=socket_path,
        ).invoke(
            foreign_scope,
            descriptor.id,
            request,
            resource_bindings={},
            expected_version_digest=version,
        )
    except RuntimeFailure as error:
        unauthorized_code = error.code

    malformed_adapter = _DeterministicAdapter(["not", "an", "object"])
    malformed_socket = runtime_root / "m.sock"
    malformed_stop = threading.Event()
    malformed_broker = ConnectionBroker(
        control,
        resolver,
        {"profile:edge-deterministic": {}},
        {"edge-deterministic-adapter/v0": malformed_adapter},  # type: ignore[dict-item]
    )
    malformed_thread = threading.Thread(
        target=malformed_broker.serve,
        args=(malformed_socket, malformed_stop),
        daemon=True,
    )
    malformed_thread.start()
    _wait_for_socket(malformed_socket)
    malformed_code: str | None = None
    try:
        OutcomeRuntime(
            store,
            launcher=launcher,
            connection_control=control,
            broker_socket=malformed_socket,
        ).invoke(
            scope_id,
            descriptor.id,
            request,
            resource_bindings=owner_resources,
            expected_version_digest=version,
            idempotency_key=malformed_key,
        )
    except RuntimeFailure as error:
        malformed_code = error.code
    finally:
        malformed_stop.set()
        malformed_thread.join(timeout=3)
    malformed_invocation = _invocation_for_key(store, scope_id, malformed_key)

    persisted = b"".join(
        path.read_bytes() for path in runtime_root.rglob("*") if path.is_file()
    )
    secret_matches = [value for value in secret_scan_values if value.encode("utf-8") in persisted]
    success_call = adapter.calls[0] if len(adapter.calls) == 1 else None
    checks = {
        "result": completed.result == expected_result,
        "exact_one_success_call": len(adapter.calls) == 1,
        "contract": success_call is not None and success_call.get("contract") == "fedex.rates/v1",
        "operation": success_call is not None and success_call.get("operation") == "quote",
        "exact_payload": success_call is not None and success_call.get("payload") == expected_connection_payload,
        "secretless_resolver": success_call is not None and success_call.get("secret") == {},
        "exact_one_success_receipt": len(success_receipts) == 1,
        "success_cleanup": _cleanup_ok(completed.receipt),
        "unavailable_control": (
            unavailable_code == "CONNECTION_UNAVAILABLE"
            and unavailable_invocation is not None
            and unavailable_invocation["status"] == "failed"
            and unavailable_invocation["receipt"]["failure_code"] == unavailable_code
            and len(unavailable_invocation["receipt"]["connection_receipts"]) == 1
            and _cleanup_ok(unavailable_invocation["receipt"])
        ),
        "missing_binding_control": missing_binding_code == "CAPABILITY_CONNECTION_BINDING_INVALID",
        "unauthorized_grant_control": unauthorized_code == "CONNECTION_OPERATION_DENIED",
        "malformed_response_control": (
            malformed_code == "CONNECTION_RESPONSE_INVALID"
            and malformed_invocation is not None
            and malformed_invocation["status"] == "failed"
            and malformed_invocation["receipt"]["failure_code"] == malformed_code
            and len(malformed_invocation["receipt"]["connection_receipts"]) == 1
            and _cleanup_ok(malformed_invocation["receipt"])
        ),
        "malformed_exact_one_call": len(malformed_adapter.calls) == 1,
        "secret_scan": not secret_matches,
        "socket_cleanup": (
            not socket_path.exists()
            and not unavailable_socket.exists()
            and not malformed_socket.exists()
        ),
    }
    blocked_reasons = [name for name, passed in checks.items() if not passed]
    return {
        "schema": "capy.edge-secretless-connection-proof/v0",
        "judgment": "supported" if not blocked_reasons else "blocked",
        "blocked_reasons": blocked_reasons,
        "capability_id": descriptor.id,
        "version_digest": version,
        "application_archive_sha256": sha256(application_archive.read_bytes()),
        "acceptance_receipt_sha256": sha256(receipt_bytes),
        "devkit_wheel_sha256": sha256(devkit_wheel.read_bytes()),
        "publication_identity_sha256": publication["publication_identity_digest"],
        "invocation_id": completed.invocation_id,
        "invocation_receipt_sha256": sha256(canonical_json(completed.receipt)),
        "connection_receipt_sha256": (
            sha256(canonical_json(success_receipts[0])) if len(success_receipts) == 1 else None
        ),
        "request_payload_sha256": (
            sha256(canonical_json(success_call["payload"])) if success_call is not None else None
        ),
        "checks": checks,
        "controls": {
            "unavailable": unavailable_code,
            "missing_binding": missing_binding_code,
            "unauthorized_grant": unauthorized_code,
            "malformed_response": malformed_code,
        },
        "control_invocation_ids": {
            "unavailable": unavailable_invocation["id"] if unavailable_invocation else None,
            "malformed_response": malformed_invocation["id"] if malformed_invocation else None,
        },
        "secret_scan_matches": secret_matches,
        "completed_at": utc_now(),
    }
