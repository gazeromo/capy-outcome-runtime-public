"""Exact-byte productization qualification for one accepted DevKit application."""

from __future__ import annotations

import json
import pwd
import grp
from pathlib import Path
from typing import Any

from .launcher import ExecutionIdentity, Launcher, LocalProcessLauncher, SystemdTransientLauncher
from .model import RuntimeFailure
from .runtime import OutcomeRuntime
from .store import RuntimeStore, canonical_json, sha256, utc_now


def systemd_launcher(user: str) -> SystemdTransientLauncher:
    account = pwd.getpwnam(user)
    group = grp.getgrgid(account.pw_gid)
    identity = ExecutionIdentity(user, group.gr_name, account.pw_uid, account.pw_gid)
    return SystemdTransientLauncher(lambda _scope_id: identity)


def qualify_productized_application(
    *,
    runtime_root: Path,
    application_archive: Path,
    acceptance_receipt: Path,
    devkit_wheel: Path,
    expected_identity: dict[str, str],
    resource_slot: str | None = None,
    resource_file: Path | None = None,
    resource_files: dict[str, list[Path]] | None = None,
    request: dict[str, Any],
    expected_result: dict[str, Any],
    expected_artifacts: dict[str, str],
    launcher: Launcher | None = None,
    scope_id: str = "productization-owner",
) -> dict[str, Any]:
    """Publish, bind, invoke, verify, and reread one exact accepted application."""

    if runtime_root.exists():
        raise RuntimeFailure("PRODUCTIZATION_RUNTIME_ROOT_EXISTS")
    legacy_resource = resource_slot is not None or resource_file is not None
    if resource_files is not None and legacy_resource:
        raise RuntimeFailure("PRODUCTIZATION_RESOURCE_INPUT_INVALID")
    if resource_files is None:
        if not isinstance(resource_slot, str) or not resource_slot or not isinstance(resource_file, Path):
            raise RuntimeFailure("PRODUCTIZATION_RESOURCE_INPUT_INVALID")
        resource_files = {resource_slot: [resource_file]}
    if (
        not isinstance(resource_files, dict)
        or any(
            not isinstance(slot, str)
            or not slot
            or not isinstance(files, list)
            or any(not isinstance(path, Path) for path in files)
            for slot, files in resource_files.items()
        )
        or not isinstance(request, dict)
        or not isinstance(expected_result, dict)
        or not isinstance(expected_artifacts, dict)
        or any(
            not isinstance(name, str)
            or Path(name).name != name
            or not isinstance(digest, str)
            or len(digest) != 64
            for name, digest in expected_artifacts.items()
        )
    ):
        raise RuntimeFailure("PRODUCTIZATION_ORACLE_INVALID")
    launcher = launcher or LocalProcessLauncher()
    store = RuntimeStore(runtime_root)
    store.register_scope(scope_id)
    store.register_scope("productization-foreign")
    receipt_bytes = acceptance_receipt.read_bytes()
    descriptor, version, publication = store.publish_devkit_archive(
        application_archive,
        receipt_bytes,
        devkit_wheel,
        expected_identity=expected_identity,
    )
    if (
        descriptor.side_effect not in {"read_only", "artifact_generation"}
        or descriptor.connections
        or descriptor.state_required
    ):
        raise RuntimeFailure("PRODUCTIZATION_DESCRIPTOR_OUT_OF_SCOPE")
    store.bind(scope_id, descriptor.id, version, {})
    resource_payloads: dict[str, list[tuple[Path, bytes, str]]] = {}
    resource_bindings: dict[str, list[str]] = {}
    for slot, files in resource_files.items():
        resource_payloads[slot] = []
        resource_bindings[slot] = []
        for resource_path in files:
            payload = resource_path.read_bytes()
            resource_digest = store.add_resource(scope_id, resource_path.name, payload)
            resource_payloads[slot].append((resource_path, payload, resource_digest))
            resource_bindings[slot].append(resource_digest)
    runtime = OutcomeRuntime(store, launcher=launcher)
    idempotency_key = f"minimal-devkit-productization-v0:{descriptor.id}"
    completed = runtime.invoke(
        scope_id,
        descriptor.id,
        request,
        resource_bindings=resource_bindings,
        expected_version_digest=version,
        idempotency_key=idempotency_key,
    )
    if completed.result != expected_result:
        raise RuntimeFailure("PRODUCTIZATION_RESULT_MISMATCH")
    observed_artifacts: dict[str, str] = {}
    for item in completed.artifacts:
        path, _media_type = store.resource(scope_id, item["digest"])
        observed_artifacts[item["filename"]] = sha256(path.read_bytes())
    if observed_artifacts != expected_artifacts:
        raise RuntimeFailure("PRODUCTIZATION_ARTIFACT_MISMATCH")
    cleanup = completed.receipt.get("cleanup")
    if not isinstance(cleanup, dict) or not cleanup or any(cleanup.values()):
        raise RuntimeFailure("PRODUCTIZATION_CLEANUP_INCOMPLETE")

    first_resource = next(
        (
            (slot, index, resource_path, payload)
            for slot, values in resource_payloads.items()
            for index, (resource_path, payload, _digest) in enumerate(values)
        ),
        None,
    )
    if first_resource is None:
        cross_scope_denial: bool | str = "not_applicable_zero_resources"
    else:
        foreign_slot, foreign_index, foreign_path, foreign_payload = first_resource
        foreign_digest = store.add_resource(
            "productization-foreign", foreign_path.name, foreign_payload + b"\n"
        )
        foreign_bindings = {slot: list(values) for slot, values in resource_bindings.items()}
        foreign_bindings[foreign_slot][foreign_index] = foreign_digest
        try:
            runtime.invoke(
                scope_id,
                descriptor.id,
                request,
                resource_bindings=foreign_bindings,
            )
        except RuntimeFailure as error:
            if error.code != "RESOURCE_NOT_IN_SCOPE":
                raise
        else:
            raise RuntimeFailure("PRODUCTIZATION_CROSS_SCOPE_ACCEPTED")
        cross_scope_denial = True

    reread_store = RuntimeStore(runtime_root)
    reread = OutcomeRuntime(reread_store, launcher=launcher).invoke(
        scope_id,
        descriptor.id,
        request,
        resource_bindings=resource_bindings,
        expected_version_digest=version,
        idempotency_key=idempotency_key,
    )
    if reread.invocation_id != completed.invocation_id or reread.receipt != completed.receipt:
        raise RuntimeFailure("PRODUCTIZATION_REREAD_MISMATCH")
    with reread_store.connect() as database:
        invocation_count = database.execute("SELECT COUNT(*) FROM invocations").fetchone()[0]
    if invocation_count != 1:
        raise RuntimeFailure("PRODUCTIZATION_REREAD_REEXECUTED")

    result = {
        "schema": "capy.minimal-devkit-product-proof/v0",
        "status": "passed",
        "scope_id": scope_id,
        "capability_id": descriptor.id,
        "version_digest": version,
        "application_archive_sha256": sha256(application_archive.read_bytes()),
        "devkit_wheel_sha256": sha256(devkit_wheel.read_bytes()),
        "acceptance_receipt_sha256": sha256(receipt_bytes),
        "candidate_commit": publication["candidate_commit"],
        "candidate_tree": publication["candidate_tree"],
        "publication_identity_sha256": publication["publication_identity_digest"],
        "invocation_id": completed.invocation_id,
        "invocation_receipt_sha256": sha256(canonical_json(completed.receipt)),
        "result_sha256": sha256(canonical_json(completed.result)),
        "artifact_sha256": observed_artifacts,
        "resource_bindings": {
            slot: [
                {"filename": path.name, "sha256": digest}
                for path, _payload, digest in values
            ]
            for slot, values in resource_payloads.items()
        },
        "resource_count": sum(len(values) for values in resource_payloads.values()),
        "resource_cardinality_validated": True,
        "cross_scope_denial": cross_scope_denial,
        "foreign_scope_denial": cross_scope_denial,
        "cleanup": cleanup,
        "restart_reread_without_reexecution": True,
        "idempotent_replay": {
            "invocation_id": reread.invocation_id,
            "without_reexecution": True,
        },
        "launcher": type(launcher).__name__,
        "completed_at": utc_now(),
    }
    return result


def main(arguments: list[str] | None = None) -> int:
    import argparse

    parser = argparse.ArgumentParser(prog="capy-productization-qualify")
    parser.add_argument("--runtime-root", required=True, type=Path)
    parser.add_argument("--application-archive", required=True, type=Path)
    parser.add_argument("--acceptance-receipt", required=True, type=Path)
    parser.add_argument("--devkit-wheel", required=True, type=Path)
    parser.add_argument("--expected-identity", required=True, type=Path)
    parser.add_argument("--resource-slot")
    parser.add_argument("--resource-file", type=Path)
    parser.add_argument(
        "--resource",
        action="append",
        default=[],
        metavar="SLOT=PATH",
        help="ordered resource binding; repeat for multiple resources",
    )
    parser.add_argument("--request", required=True, type=Path)
    parser.add_argument("--oracle", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--systemd-user")
    args = parser.parse_args(arguments)
    try:
        identity = json.loads(args.expected_identity.read_text(encoding="utf-8"))
        request = json.loads(args.request.read_text(encoding="utf-8"))
        oracle = json.loads(args.oracle.read_text(encoding="utf-8"))
        if set(oracle) != {"result", "artifact_sha256"}:
            raise RuntimeFailure("PRODUCTIZATION_ORACLE_INVALID")
        launcher = systemd_launcher(args.systemd_user) if args.systemd_user else None
        if args.resource and (args.resource_slot is not None or args.resource_file is not None):
            raise RuntimeFailure("PRODUCTIZATION_RESOURCE_INPUT_INVALID")
        resources: dict[str, list[Path]] | None = None
        if args.resource:
            resources = {}
            for value in args.resource:
                slot, separator, raw_path = value.partition("=")
                if not separator or not slot or not raw_path:
                    raise RuntimeFailure("PRODUCTIZATION_RESOURCE_INPUT_INVALID")
                resources.setdefault(slot, []).append(Path(raw_path))
        elif args.resource_slot is None and args.resource_file is None:
            resources = {}
        result = qualify_productized_application(
            runtime_root=args.runtime_root,
            application_archive=args.application_archive,
            acceptance_receipt=args.acceptance_receipt,
            devkit_wheel=args.devkit_wheel,
            expected_identity=identity,
            resource_slot=args.resource_slot,
            resource_file=args.resource_file,
            resource_files=resources,
            request=request,
            expected_result=oracle["result"],
            expected_artifacts=oracle["artifact_sha256"],
            launcher=launcher,
        )
        args.output.write_bytes(canonical_json(result) + b"\n")
    except (OSError, UnicodeError, ValueError, json.JSONDecodeError, RuntimeFailure) as error:
        print(error, file=__import__("sys").stderr)
        return 2
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
