"""Shared-host execution entrypoint for one exact published DevKit application."""

from __future__ import annotations

import argparse
import base64
import json
from pathlib import Path
from typing import Any

from .model import RuntimeFailure
from .productization import systemd_launcher
from .runtime import OutcomeRuntime
from .store import RuntimeStore, canonical_json, sha256, utc_now


def execute_shared_host_invocation(
    *,
    runtime_root: Path,
    application_archive: Path,
    acceptance_receipt: Path,
    devkit_wheel: Path,
    expected_identity: dict[str, str],
    scope_id: str,
    capability_id: str,
    version_digest: str,
    resources: list[dict[str, str]],
    request: dict[str, Any],
    idempotency_key: str | None,
    initiator: dict[str, str] | None,
    systemd_user: str,
) -> dict[str, Any]:
    if runtime_root.exists() or not scope_id or not capability_id or not systemd_user:
        raise RuntimeFailure("SHARED_HOST_INPUT_INVALID")
    store = RuntimeStore(runtime_root)
    store.register_scope(scope_id)
    receipt_bytes = acceptance_receipt.read_bytes()
    descriptor, published_version, publication = store.publish_devkit_archive(
        application_archive,
        receipt_bytes,
        devkit_wheel,
        expected_identity=expected_identity,
    )
    if (
        descriptor.id != capability_id
        or published_version != version_digest
        or descriptor.side_effect not in {"read_only", "artifact_generation"}
        or descriptor.state_required
        or descriptor.connections
    ):
        raise RuntimeFailure("SHARED_HOST_PUBLICATION_MISMATCH")
    store.bind(scope_id, capability_id, published_version, {})
    bindings: dict[str, list[str]] = {}
    observed_resources: list[dict[str, str]] = []
    for item in resources:
        if not isinstance(item, dict) or set(item) != {"slot", "digest", "filename", "path"}:
            raise RuntimeFailure("SHARED_HOST_RESOURCE_INVALID")
        payload = Path(item["path"]).read_bytes()
        if sha256(payload) != item["digest"]:
            raise RuntimeFailure("SHARED_HOST_RESOURCE_INVALID")
        registered = store.add_resource(scope_id, item["filename"], payload)
        if registered != item["digest"]:
            raise RuntimeFailure("SHARED_HOST_RESOURCE_INVALID")
        bindings.setdefault(item["slot"], []).append(registered)
        observed_resources.append({
            "slot": item["slot"], "digest": registered, "filename": item["filename"]
        })
    runtime = OutcomeRuntime(store, launcher=systemd_launcher(systemd_user))
    completed = runtime.invoke(
        scope_id,
        capability_id,
        request,
        resource_bindings=bindings,
        expected_version_digest=published_version,
        idempotency_key=idempotency_key,
        initiator=initiator,
    )
    replay = runtime.invoke(
        scope_id,
        capability_id,
        request,
        resource_bindings=bindings,
        expected_version_digest=published_version,
        idempotency_key=idempotency_key,
        initiator=initiator,
    )
    if replay.invocation_id != completed.invocation_id or replay.receipt != completed.receipt:
        raise RuntimeFailure("SHARED_HOST_REPLAY_MISMATCH")
    artifacts = []
    for item in completed.artifacts:
        path, _media_type = store.resource(scope_id, item["digest"])
        payload = path.read_bytes()
        artifacts.append({
            "filename": item["filename"],
            "digest": item["digest"],
            "size_bytes": len(payload),
            "payload_base64": base64.b64encode(payload).decode("ascii"),
        })
    cleanup = completed.receipt.get("cleanup")
    if not isinstance(cleanup, dict) or not cleanup or any(cleanup.values()):
        raise RuntimeFailure("SHARED_HOST_CLEANUP_INCOMPLETE")
    return {
        "schema": "capy.shared-host-invocation/v0",
        "status": "passed",
        "scope_id": scope_id,
        "capability_id": capability_id,
        "version_digest": published_version,
        "candidate_commit": publication["candidate_commit"],
        "candidate_tree": publication["candidate_tree"],
        "application_archive_sha256": publication["archive_digest"],
        "acceptance_receipt_sha256": publication["acceptance_digest"],
        "publication_identity_sha256": publication["publication_identity_digest"],
        "resource_bindings": observed_resources,
        "invocation_id": completed.invocation_id,
        "invocation_receipt": completed.receipt,
        "invocation_receipt_sha256": sha256(canonical_json(completed.receipt)),
        "result": completed.result,
        "result_sha256": sha256(canonical_json(completed.result)),
        "artifacts": artifacts,
        "cleanup": cleanup,
        "restart_reread_without_reexecution": True,
        "launcher": "SystemdTransientLauncher",
        "completed_at": utc_now(),
    }


def main(arguments: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="capy-shared-host-invoke")
    parser.add_argument("--runtime-root", required=True, type=Path)
    parser.add_argument("--application-archive", required=True, type=Path)
    parser.add_argument("--acceptance-receipt", required=True, type=Path)
    parser.add_argument("--devkit-wheel", required=True, type=Path)
    parser.add_argument("--expected-identity", required=True, type=Path)
    parser.add_argument("--scope-id", required=True)
    parser.add_argument("--capability-id", required=True)
    parser.add_argument("--version-digest", required=True)
    parser.add_argument("--resources", required=True, type=Path)
    parser.add_argument("--request", required=True, type=Path)
    parser.add_argument("--initiator", type=Path)
    parser.add_argument("--idempotency-key")
    parser.add_argument("--systemd-user", required=True)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args(arguments)
    try:
        result = execute_shared_host_invocation(
            runtime_root=args.runtime_root,
            application_archive=args.application_archive,
            acceptance_receipt=args.acceptance_receipt,
            devkit_wheel=args.devkit_wheel,
            expected_identity=json.loads(args.expected_identity.read_text(encoding="utf-8")),
            scope_id=args.scope_id,
            capability_id=args.capability_id,
            version_digest=args.version_digest,
            resources=json.loads(args.resources.read_text(encoding="utf-8")),
            request=json.loads(args.request.read_text(encoding="utf-8")),
            idempotency_key=args.idempotency_key,
            initiator=(json.loads(args.initiator.read_text(encoding="utf-8")) if args.initiator else None),
            systemd_user=args.systemd_user,
        )
        args.output.write_bytes(canonical_json(result) + b"\n")
    except (OSError, UnicodeError, ValueError, json.JSONDecodeError, RuntimeFailure) as error:
        print(error, file=__import__("sys").stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
