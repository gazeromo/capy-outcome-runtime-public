"""Execution adapters for tests/workstations and the accepted Linux boundary."""

from __future__ import annotations

import hashlib
import subprocess
import sys
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol


@dataclass(frozen=True)
class ProcessResult:
    returncode: int
    stdout: bytes
    stderr: bytes
    failure_code: str | None = None


@dataclass(frozen=True)
class ExecutionIdentity:
    user: str
    group: str
    uid: int
    gid: int


class Launcher(Protocol):
    def execution_identity(self, scope_id: str) -> ExecutionIdentity | None: ...

    def run(
        self,
        argv: list[str],
        *,
        input_bytes: bytes,
        cwd: Path,
        environment: dict[str, str],
        timeout_seconds: int,
        memory_mb: int,
        read_only_paths: list[Path],
        writable_paths: list[Path],
        identity: ExecutionIdentity | None,
    ) -> ProcessResult: ...

    def machine_id_sha256(self) -> str: ...

    def boot_id(self) -> str: ...

    def launch_journal(
        self,
        journal: Path,
        runner: Path,
        *,
        unit: str,
        timeout_seconds: int,
        memory_mb: int,
        read_only_paths: list[Path],
        writable_paths: list[Path],
        identity: ExecutionIdentity | None,
    ) -> None: ...

    def unit_state(self, unit: str) -> str: ...


class LocalProcessLauncher:
    """Portable provider-free test launcher; not the production trust boundary."""

    def execution_identity(self, scope_id: str) -> None:
        del scope_id
        return None

    def machine_id_sha256(self) -> str:
        return hashlib.sha256(b"provider-free-local-launcher").hexdigest()

    def boot_id(self) -> str:
        return "provider-free-local-boot"

    def launch_journal(
        self,
        journal: Path,
        runner: Path,
        *,
        unit: str,
        timeout_seconds: int,
        memory_mb: int,
        read_only_paths: list[Path],
        writable_paths: list[Path],
        identity: ExecutionIdentity | None,
    ) -> None:
        del unit, timeout_seconds, memory_mb, read_only_paths, writable_paths, identity
        completed = subprocess.run(
            [sys.executable, "-I", str(runner), str(journal)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        )
        if completed.returncode not in {0, 1}:
            raise RuntimeError("journal runner failed before terminal receipt")

    def unit_state(self, unit: str) -> str:
        del unit
        return "inactive"

    def run(
        self,
        argv: list[str],
        *,
        input_bytes: bytes,
        cwd: Path,
        environment: dict[str, str],
        timeout_seconds: int,
        memory_mb: int,
        read_only_paths: list[Path],
        writable_paths: list[Path],
        identity: ExecutionIdentity | None,
    ) -> ProcessResult:
        del memory_mb, read_only_paths, writable_paths, identity
        completed = subprocess.run(
            argv,
            input=input_bytes,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=cwd,
            env=environment,
            timeout=timeout_seconds,
            check=False,
        )
        return ProcessResult(completed.returncode, completed.stdout, completed.stderr)


class SystemdTransientLauncher:
    """Short-lived scope-identity execution for the dedicated Linux host."""

    def __init__(
        self,
        identity_resolver,
        systemd_run: str = "/usr/bin/systemd-run",
        systemctl: str = "/usr/bin/systemctl",
    ):
        self.identity_resolver = identity_resolver
        self.systemd_run = systemd_run
        self.systemctl = systemctl

    def execution_identity(self, scope_id: str) -> ExecutionIdentity:
        identity = self.identity_resolver(scope_id)
        if (
            not isinstance(identity, ExecutionIdentity)
            or identity.uid <= 0
            or identity.gid <= 0
            or not identity.user
            or not identity.group
        ):
            raise ValueError("invalid execution identity")
        return identity

    @staticmethod
    def machine_id_sha256() -> str:
        return hashlib.sha256(Path("/etc/machine-id").read_bytes().strip()).hexdigest()

    @staticmethod
    def boot_id() -> str:
        return Path("/proc/sys/kernel/random/boot_id").read_text(encoding="ascii").strip()

    def launch_journal(
        self,
        journal: Path,
        runner: Path,
        *,
        unit: str,
        timeout_seconds: int,
        memory_mb: int,
        read_only_paths: list[Path],
        writable_paths: list[Path],
        identity: ExecutionIdentity | None,
    ) -> None:
        if identity is None:
            raise ValueError("systemd execution identity is required")
        command = [
            self.systemd_run,
            "--quiet",
            "--collect",
            f"--unit={unit}",
            "--service-type=exec",
            f"--uid={identity.user}",
            f"--gid={identity.group}",
            "--property=PrivateTmp=yes",
            "--property=ProtectProc=invisible",
            "--property=ProcSubset=pid",
            "--property=NoNewPrivileges=yes",
            "--property=ProtectSystem=strict",
            "--property=ProtectHome=yes",
            "--property=InaccessiblePaths=/etc/capy-outcome-runtime/secrets",
            "--property=RestrictSUIDSGID=yes",
            "--property=LockPersonality=yes",
            "--property=PrivateDevices=yes",
            "--property=KillMode=mixed",
            "--property=TimeoutStopSec=2s",
            f"--property=MemoryMax={memory_mb}M",
            f"--property=RuntimeMaxSec={timeout_seconds + 5}s",
            f"--property=WorkingDirectory={journal}",
            "--property=StandardOutput=null",
            "--property=StandardError=null",
        ]
        command.extend(f"--property=BindReadOnlyPaths={path}" for path in read_only_paths)
        command.extend(f"--property=BindPaths={path}" for path in writable_paths)
        completed = subprocess.run(
            [*command, "--", sys.executable, "-I", str(runner), str(journal)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=10,
            check=False,
        )
        if completed.returncode:
            raise RuntimeError("systemd transient journal launch failed")

    def unit_state(self, unit: str) -> str:
        completed = subprocess.run(
            [
                self.systemctl,
                "show",
                "--property=LoadState,ActiveState,SubState,Result",
                "--value",
                unit,
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            timeout=5,
            check=False,
            text=True,
        )
        if completed.returncode:
            return "missing"
        values = [item.strip() for item in completed.stdout.splitlines()]
        return ":".join(values) if values else "missing"

    def command(
        self,
        argv: list[str],
        *,
        cwd: Path,
        environment: dict[str, str],
        timeout_seconds: int,
        memory_mb: int,
        read_only_paths: list[Path],
        writable_paths: list[Path],
        identity: ExecutionIdentity,
        unit: str | None = None,
    ) -> list[str]:
        unit = unit or f"capy-invocation-{uuid.uuid4().hex}"
        command = [
            self.systemd_run,
            "--quiet",
            "--pipe",
            "--wait",
            f"--unit={unit}",
            "--service-type=exec",
            f"--uid={identity.user}",
            f"--gid={identity.group}",
            "--property=PrivateTmp=yes",
            "--property=ProtectProc=invisible",
            "--property=ProcSubset=pid",
            "--property=NoNewPrivileges=yes",
            "--property=ProtectSystem=strict",
            "--property=ProtectHome=yes",
            "--property=InaccessiblePaths=/etc/capy-outcome-runtime/secrets",
            "--property=RestrictSUIDSGID=yes",
            "--property=LockPersonality=yes",
            "--property=PrivateDevices=yes",
            "--property=KillMode=mixed",
            "--property=TimeoutStopSec=2s",
            f"--property=MemoryMax={memory_mb}M",
            f"--property=RuntimeMaxSec={timeout_seconds}s",
            f"--property=WorkingDirectory={cwd}",
        ]
        command.extend(f"--property=BindReadOnlyPaths={path}" for path in read_only_paths)
        command.extend(f"--property=BindPaths={path}" for path in writable_paths)
        command.extend(f"--setenv={name}={value}" for name, value in sorted(environment.items()))
        return [*command, "--", *argv]

    def run(
        self,
        argv: list[str],
        *,
        input_bytes: bytes,
        cwd: Path,
        environment: dict[str, str],
        timeout_seconds: int,
        memory_mb: int,
        read_only_paths: list[Path],
        writable_paths: list[Path],
        identity: ExecutionIdentity | None,
    ) -> ProcessResult:
        if identity is None:
            raise ValueError("systemd execution identity is required")
        unit = f"capy-invocation-{uuid.uuid4().hex}"
        command = self.command(
            argv,
            cwd=cwd,
            environment=environment,
            timeout_seconds=timeout_seconds,
            memory_mb=memory_mb,
            read_only_paths=read_only_paths,
            writable_paths=writable_paths,
            identity=identity,
            unit=unit,
        )
        try:
            completed = subprocess.run(
                command,
                input=input_bytes,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=timeout_seconds + 5,
                check=False,
            )
            result = ""
            if completed.returncode:
                shown = subprocess.run(
                    [self.systemctl, "show", "--property=Result", "--value", unit],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.DEVNULL,
                    timeout=5,
                    check=False,
                    text=True,
                )
                result = shown.stdout.strip()
            failure_code = {
                "timeout": "INVOCATION_TIMEOUT",
                "oom-kill": "INVOCATION_MEMORY_LIMIT",
            }.get(result)
            return ProcessResult(
                completed.returncode,
                completed.stdout,
                completed.stderr,
                failure_code,
            )
        except subprocess.TimeoutExpired:
            subprocess.run(
                [self.systemctl, "stop", unit],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=5,
                check=False,
            )
            raise
        finally:
            subprocess.run(
                [self.systemctl, "reset-failed", unit],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=5,
                check=False,
            )
