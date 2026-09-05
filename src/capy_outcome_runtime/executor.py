"""Trusted scope runner for one durable invocation journal.

This module intentionally uses only the Python standard library so a systemd
transient unit can execute it by absolute path with isolated Python settings.
It records execution facts only; it never opens the runtime SQLite database.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


RUNNER_VERSION = "capy.executor-runner/v0"
MAX_STREAM_BYTES = 1024 * 1024
MAX_ARTIFACT_BYTES = 64 * 1024 * 1024


def canonical_json(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode()


def digest(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _sync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def atomic_json(path: Path, value: Any) -> bytes:
    payload = canonical_json(value)
    temporary = path.parent / f".{path.name}.{uuid.uuid4().hex}"
    with temporary.open("xb") as handle:
        handle.write(payload)
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temporary, path)
    _sync_directory(path.parent)
    return payload


def _write_stream(path: Path, payload: bytes) -> tuple[str, int]:
    if len(payload) > MAX_STREAM_BYTES:
        payload = payload[:MAX_STREAM_BYTES]
    with path.open("wb") as handle:
        handle.write(payload)
        handle.flush()
        os.fsync(handle.fileno())
    return digest(payload), len(payload)


def _artifacts(output: Path) -> list[dict[str, Any]]:
    result = []
    for candidate in sorted(output.iterdir(), key=lambda item: item.name):
        name = candidate.name
        if (
            candidate.is_symlink()
            or not candidate.is_file()
            or Path(name).name != name
            or any(char in name for char in "\x00\r\n")
            or len(name.encode()) > 255
            or candidate.stat().st_size > MAX_ARTIFACT_BYTES
        ):
            raise ValueError("invalid candidate artifact")
        payload = candidate.read_bytes()
        result.append({"filename": name, "digest": digest(payload), "size_bytes": len(payload)})
    return result


def run_journal(journal: Path) -> dict[str, Any]:
    journal = journal.resolve()
    spec_payload = (journal / "executor-spec.json").read_bytes()
    spec = json.loads(spec_payload)
    request = (journal / "request.json").read_bytes()
    resources = json.loads((journal / "resource-manifest.json").read_text(encoding="utf-8"))
    connection_manifest_path = journal / "connection-manifest.json"
    connection_manifest = (
        json.loads(connection_manifest_path.read_text(encoding="utf-8"))
        if connection_manifest_path.exists()
        else {}
    )
    output = journal / "output-staging"
    environment = {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "PYTHONIOENCODING": "utf-8",
        "CAPY_INVOCATION_ID": spec["invocation_id"],
        "CAPY_RESOURCE_MANIFEST": json.dumps(resources, separators=(",", ":")),
        "CAPY_RESOURCE_SLOTS": json.dumps(spec.get("resource_slots", []), separators=(",", ":")),
        "CAPY_CONNECTION_MANIFEST": json.dumps(connection_manifest, separators=(",", ":")),
        "CAPY_OUTPUT_DIR": str(output),
    }
    if spec.get("state_path"):
        environment["CAPY_STATE_DIR"] = spec["state_path"]
    sdk_root = spec.get("script_sdk_root")
    if sdk_root:
        bootstrap = (
            "import os,runpy,sys;"
            "sys.path[:0]=[sys.argv[1],os.path.dirname(sys.argv[2])];"
            "runpy.run_path(sys.argv[2],run_name='__main__')"
        )
        argv = [spec["python"], "-I", "-c", bootstrap, sdk_root, spec["entrypoint"]]
    else:
        argv = [spec["python"], "-I", spec["entrypoint"]]
    returncode = 125
    stdout = b""
    stderr = b""
    exit_class = "runner_error"
    try:
        completed = subprocess.run(
            argv,
            input=request,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=spec["script_root"],
            env=environment,
            timeout=spec["timeout_seconds"],
            check=False,
        )
        returncode = completed.returncode
        stdout = completed.stdout
        stderr = completed.stderr
        exit_class = "exited_0" if returncode == 0 else "exited_nonzero"
    except subprocess.TimeoutExpired as exc:
        stdout = exc.stdout or b""
        stderr = exc.stderr or b""
        exit_class = "timeout"
        returncode = 124
    except BaseException as exc:
        stderr = f"runner error: {type(exc).__name__}".encode()
    finally:
        credential_root = journal / "credentials"
        if credential_root.exists():
            shutil.rmtree(credential_root, ignore_errors=True)
        connection_manifest_path.unlink(missing_ok=True)

    stdout_digest, stdout_size = _write_stream(journal / "stdout.bin", stdout)
    stderr_digest, stderr_size = _write_stream(journal / "stderr.bin", stderr)
    artifacts = _artifacts(output)
    result = {
        "schema": "capy.executor-result/v0",
        "returncode": returncode,
        "process_exit_class": exit_class,
        "stdout_digest": stdout_digest,
        "stdout_size": stdout_size,
        "stderr_digest": stderr_digest,
        "stderr_size": stderr_size,
        "artifacts": artifacts,
    }
    result_payload = atomic_json(journal / "executor-result.json", result)
    terminal = {
        "schema": "capy.executor-terminal-receipt/v0",
        "invocation_id": spec["invocation_id"],
        "launch_nonce": spec["launch_nonce"],
        "scope_id": spec["scope_id"],
        "capability_id": spec["capability_id"],
        "version_digest": spec["version_digest"],
        "request_digest": spec["request_digest"],
        "resource_digests": spec["resource_digests"],
        "connection_names": spec["connection_names"],
        "unit_name": spec["unit_name"],
        "boot_id": spec["boot_id"],
        "process_exit_class": exit_class,
        "returncode": returncode,
        "stdout_digest": stdout_digest,
        "stdout_size": stdout_size,
        "stderr_digest": stderr_digest,
        "stderr_size": stderr_size,
        "artifacts": artifacts,
        "executor_result_digest": digest(result_payload),
        "completed_at": utc_now(),
        "runner_version": RUNNER_VERSION,
    }
    atomic_json(journal / "executor-terminal-receipt.json", terminal)
    return terminal


def main() -> int:
    if len(sys.argv) != 2:
        return 64
    try:
        terminal = run_journal(Path(sys.argv[1]))
    except BaseException:
        return 70
    return 0 if terminal["process_exit_class"] == "exited_0" else 1


if __name__ == "__main__":
    raise SystemExit(main())
