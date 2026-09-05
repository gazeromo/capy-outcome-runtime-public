"""Production adapters for the bounded generic chat-to-software lane.

The web process may construct these adapters, but application code never sees
them.  All commands are operator-configured immutable prefixes; proposal or
model text is never interpreted as a shell command.
"""

from __future__ import annotations

import hashlib
import base64
import json
import os
import re
import shlex
import shutil
import subprocess
import tempfile
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path, PurePosixPath
from typing import Any, Callable, Mapping, Sequence

from .build import BuilderService
from .chat import ChatStore
from .generic_build import (
    AcceptanceDecision,
    AcceptanceOracleFailure,
    BuilderFailure,
    BuilderTimeout,
    CandidateIdentity,
    GenericBuildOrchestrator,
    GenericBuildOutcome,
    GenericBuildRequest,
    MinimalGitGrant,
    Publication,
)
from .launcher import LocalProcessLauncher
from .model import RuntimeFailure
from .runtime import InvocationResult, OutcomeRuntime
from .store import canonical_json, sha256, tree_digest


def _run(
    argv: Sequence[str],
    *,
    cwd: Path | None = None,
    environment: Mapping[str, str] | None = None,
    input_bytes: bytes | None = None,
    timeout: int = 300,
    preexec_fn: Callable[[], None] | None = None,
) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        list(argv),
        cwd=cwd,
        env=None if environment is None else dict(environment),
        input=input_bytes,
        stdin=subprocess.DEVNULL if input_bytes is None else None,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        timeout=timeout,
        check=False,
        preexec_fn=preexec_fn,
    )


@dataclass(frozen=True)
class MinimalGitCommandConfig:
    admin_command: tuple[str, ...]
    host: str
    port: int
    known_hosts_file: Path
    scratch_root: Path
    git_user: str = "capygit"
    grant_seconds: int = 3600

    def __post_init__(self) -> None:
        if (
            not self.admin_command
            or not self.host
            or not 1 <= self.port <= 65535
            or not self.known_hosts_file.is_file()
            or not self.scratch_root.is_absolute()
            or not re.fullmatch(r"[a-z_][a-z0-9_-]{0,31}", self.git_user)
            or not 300 <= self.grant_seconds <= 7200
        ):
            raise ValueError("invalid Minimal Git command configuration")


class NativeMinimalGitAuthority:
    """Operate the accepted Minimal Git SSH admin and ordinary Git data planes."""

    def __init__(self, config: MinimalGitCommandConfig):
        self.config = config
        self.config.scratch_root.mkdir(parents=True, exist_ok=True)
        self.config.scratch_root.chmod(0o700)

    def create_repository_and_grant(self, request: GenericBuildRequest) -> MinimalGitGrant:
        specification = request.packet.get("specification")
        candidate_repository = (
            specification.get("candidate_repository")
            if isinstance(specification, dict) else None
        )
        prefix = "minimal-git://"
        if not isinstance(candidate_repository, str) or not candidate_repository.startswith(prefix):
            raise RuntimeFailure("MINIMAL_GIT_REPOSITORY_ID_INVALID")
        repository_id = candidate_repository.removeprefix(prefix)
        try:
            if str(uuid.UUID(repository_id)) != repository_id:
                raise ValueError
        except ValueError as exc:
            raise RuntimeFailure("MINIMAL_GIT_REPOSITORY_ID_INVALID") from exc
        grant_id = str(uuid.uuid4())
        directory = self.config.scratch_root / request.build_id
        directory.mkdir(mode=0o700, parents=True, exist_ok=False)
        private_key = directory / "builder-ed25519"
        generated = _run(
            ["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(private_key)],
            timeout=30,
        )
        if generated.returncode != 0:
            raise RuntimeFailure("MINIMAL_GIT_KEYGEN_FAILED")
        private_key.chmod(0o600)
        self._admin(("repo", "create", "--repo-id", repository_id, "--json"))
        expires = (
            datetime.now(timezone.utc) + timedelta(seconds=self.config.grant_seconds)
        ).isoformat(timespec="seconds").replace("+00:00", "Z")
        public_key = private_key.with_suffix(".pub").read_bytes()
        self._admin(
            (
                "grant", "issue", "--grant-id", grant_id, "--repo-id", repository_id,
                "--mode", "write", "--public-key-file", "-", "--expires-at", expires,
                "--json",
            ),
            input_bytes=public_key,
        )
        clone_url = (
            f"ssh://{self.config.git_user}@{self.config.host}:"
            f"{self.config.port}/{repository_id}.git"
        )
        return MinimalGitGrant(
            candidate_repository, clone_url, grant_id, private_key
        )

    def collect_candidate(self, grant: MinimalGitGrant) -> CandidateIdentity | None:
        environment = self._git_environment(grant)
        observed = _run(
            ["git", "ls-remote", grant.clone_url, "refs/heads/main"],
            environment=environment,
            timeout=60,
        )
        if observed.returncode != 0:
            raise RuntimeFailure("MINIMAL_GIT_CANDIDATE_READ_FAILED")
        text = observed.stdout.decode("utf-8", "strict").strip()
        if not text:
            return None
        commit, separator, reference = text.partition("\t")
        if separator != "\t" or reference != "refs/heads/main" or re.fullmatch(r"[0-9a-f]{40}", commit) is None:
            raise RuntimeFailure("MINIMAL_GIT_CANDIDATE_IDENTITY_INVALID")
        checkout_root = grant.private_key_path.parent / "trusted-collection"
        cloned = _run(
            ["git", "clone", "--quiet", "--branch", "main", "--single-branch", grant.clone_url, str(checkout_root)],
            environment=environment,
            timeout=120,
        )
        if cloned.returncode != 0:
            raise RuntimeFailure("MINIMAL_GIT_CANDIDATE_READ_FAILED")
        exact_commit = self._git_value(checkout_root, ("rev-parse", "HEAD"))
        tree = self._git_value(checkout_root, ("rev-parse", "HEAD^{tree}"))
        if exact_commit != commit or self._git_value(checkout_root, ("status", "--porcelain")):
            raise RuntimeFailure("MINIMAL_GIT_CANDIDATE_IDENTITY_INVALID")
        archive_path = grant.private_key_path.parent / "candidate.zip"
        archived = _run(
            ["git", "archive", "--format=zip", "--output", str(archive_path), commit],
            cwd=checkout_root,
            timeout=120,
        )
        if archived.returncode != 0:
            raise RuntimeFailure("MINIMAL_GIT_CANDIDATE_ARCHIVE_FAILED")
        archive = archive_path.read_bytes()
        return CandidateIdentity(
            grant.repository, commit, tree, archive, hashlib.sha256(archive).hexdigest()
        )

    def revoke_grant(self, grant: MinimalGitGrant) -> None:
        self._admin(("grant", "revoke", "--grant-id", grant.grant_id, "--json"))

    def confirm_push_denied(self, grant: MinimalGitGrant) -> bool:
        denied = _run(
            ["git", "ls-remote", grant.clone_url, "refs/heads/main"],
            environment=self._git_environment(grant),
            timeout=30,
        )
        return denied.returncode != 0

    @staticmethod
    def remove_private_key(grant: MinimalGitGrant) -> None:
        grant.private_key_path.unlink(missing_ok=True)
        grant.private_key_path.with_suffix(".pub").unlink(missing_ok=True)

    def _admin(self, arguments: Sequence[str], *, input_bytes: bytes | None = None) -> dict[str, Any]:
        completed = _run(
            [*self.config.admin_command, *arguments], input_bytes=input_bytes, timeout=60
        )
        if completed.returncode != 0:
            raise RuntimeFailure("MINIMAL_GIT_ADMIN_FAILED")
        try:
            value = json.loads(completed.stdout)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise RuntimeFailure("MINIMAL_GIT_ADMIN_RESPONSE_INVALID") from exc
        if not isinstance(value, dict):
            raise RuntimeFailure("MINIMAL_GIT_ADMIN_RESPONSE_INVALID")
        return value

    def _git_environment(self, grant: MinimalGitGrant) -> dict[str, str]:
        ssh = (
            f"ssh -F /dev/null -i {grant.private_key_path} -o IdentitiesOnly=yes "
            f"-o BatchMode=yes -o StrictHostKeyChecking=yes "
            f"-o UserKnownHostsFile={self.config.known_hosts_file}"
        )
        return {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "GIT_SSH_COMMAND": ssh}

    @staticmethod
    def _git_value(cwd: Path, arguments: Sequence[str]) -> str:
        completed = _run(["git", *arguments], cwd=cwd, timeout=30)
        if completed.returncode != 0:
            raise RuntimeFailure("MINIMAL_GIT_CANDIDATE_IDENTITY_INVALID")
        return completed.stdout.decode("utf-8", "strict").strip()


@dataclass(frozen=True)
class FreshCodexCommandConfig:
    command: tuple[str, ...]
    authoring_bundle: Path
    known_hosts_file: Path
    codex_home: Path
    scratch_root: Path
    builder_uid: int
    builder_gid: int
    timeout_seconds: int = 1800

    def __post_init__(self) -> None:
        if (
            not self.command
            or not self.authoring_bundle.exists()
            or not self.known_hosts_file.is_file()
            or not self.codex_home.is_dir()
            or not self.scratch_root.is_absolute()
            or self.builder_uid <= 0
            or self.builder_gid <= 0
            or not 60 <= self.timeout_seconds <= 3600
        ):
            raise ValueError("invalid fresh Codex command configuration")


class FreshCodexCommandBuilder:
    """Run one fresh configured Codex process with only packet, bundle, and Git grant."""

    def __init__(self, config: FreshCodexCommandConfig):
        self.config = config
        self.config.scratch_root.mkdir(parents=True, exist_ok=True)

    def build_and_push(self, request: GenericBuildRequest, grant: MinimalGitGrant) -> None:
        root = self.config.scratch_root / request.build_id
        root.mkdir(mode=0o700, parents=True, exist_ok=False)
        os.chown(root, self.config.builder_uid, self.config.builder_gid)
        os.chown(grant.private_key_path.parent, self.config.builder_uid, self.config.builder_gid)
        os.chown(grant.private_key_path, self.config.builder_uid, self.config.builder_gid)
        worktree = root / "application"
        environment = {
            "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
            "HOME": str(root / "home"),
            "CODEX_HOME": str(self.config.codex_home),
            "GIT_SSH_COMMAND": (
                f"ssh -F /dev/null -i {grant.private_key_path} -o IdentitiesOnly=yes "
                "-o BatchMode=yes -o StrictHostKeyChecking=yes "
                f"-o UserKnownHostsFile={self.config.known_hosts_file}"
            ),
        }
        Path(environment["HOME"]).mkdir(mode=0o700)
        os.chown(Path(environment["HOME"]), self.config.builder_uid, self.config.builder_gid)

        def drop_builder_privileges() -> None:
            os.setgroups([])
            os.setgid(self.config.builder_gid)
            os.setuid(self.config.builder_uid)

        cloned = _run(
            ["git", "clone", "--quiet", grant.clone_url, str(worktree)],
            environment=environment,
            timeout=120,
            preexec_fn=drop_builder_privileges,
        )
        if cloned.returncode != 0:
            raise BuilderFailure("Minimal Git clone failed")
        packet_path = root / "BUILD-PACKET.json"
        packet_path.write_bytes(canonical_json(dict(request.packet)) + b"\n")
        packet_path.chmod(0o400)
        prompt = (
            f"Build the exact bounded Python application in {packet_path}. "
            f"The curated read-only DevKit authoring bundle is {self.config.authoring_bundle}. "
            "Work only in the current application repository. Run the specified checks, "
            "commit all application source on branch main, and leave the tree clean."
        )
        try:
            completed = _run(
                [*self.config.command, prompt],
                cwd=worktree,
                environment=environment,
                timeout=self.config.timeout_seconds,
                preexec_fn=drop_builder_privileges,
            )
        except subprocess.TimeoutExpired as exc:
            raise BuilderTimeout("fresh Codex timed out") from exc
        if completed.returncode != 0:
            raise BuilderFailure("fresh Codex failed")
        head = _run(
            ["git", "rev-parse", "HEAD"], cwd=worktree, timeout=30,
            preexec_fn=drop_builder_privileges,
        )
        clean = _run(
            ["git", "status", "--porcelain"], cwd=worktree, timeout=30,
            preexec_fn=drop_builder_privileges,
        )
        if head.returncode != 0 or clean.returncode != 0 or clean.stdout.strip():
            raise BuilderFailure("fresh Codex did not leave a clean commit")
        pushed = _run(
            ["git", "push", "origin", "HEAD:refs/heads/main"],
            cwd=worktree,
            environment=environment,
            timeout=120,
            preexec_fn=drop_builder_privileges,
        )
        if pushed.returncode != 0:
            raise BuilderFailure("fresh Codex candidate push failed")


class BuilderServiceIndependentAcceptor:
    """Persist the candidate, then invoke a separately configured acceptance process."""

    def __init__(
        self,
        service: BuilderService,
        *,
        command: Sequence[str],
        devkit_wheel: Path,
        timeout_seconds: int = 900,
    ):
        if not command or not devkit_wheel.is_file():
            raise ValueError("invalid independent acceptor configuration")
        self.service = service
        self.command = tuple(command)
        self.devkit_wheel = devkit_wheel
        self.timeout_seconds = timeout_seconds

    def accept(
        self, request: GenericBuildRequest, candidate: CandidateIdentity
    ) -> AcceptanceDecision:
        with tempfile.TemporaryDirectory(prefix="capy-independent-accept-") as temporary:
            root = Path(temporary)
            archive = root / "candidate.zip"
            receipt = root / "acceptance.json"
            packet = root / "packet.json"
            archive.write_bytes(candidate.archive)
            packet.write_bytes(canonical_json(dict(request.packet)) + b"\n")
            self.service.submit_devkit_candidate(
                request.build_id,
                candidate_repository=candidate.repository,
                candidate_commit=candidate.commit,
                candidate_tree=candidate.tree,
                application_archive=archive,
            )
            try:
                completed = _run(
                    [
                        *self.command,
                        "--packet", str(packet),
                        "--application-archive", str(archive),
                        "--devkit-wheel", str(self.devkit_wheel),
                        "--output", str(receipt),
                    ],
                    timeout=self.timeout_seconds,
                )
            except subprocess.TimeoutExpired as exc:
                raise AcceptanceOracleFailure("acceptance timed out") from exc
            if completed.returncode != 0:
                if receipt.is_file():
                    try:
                        rejected = json.loads(receipt.read_bytes())
                    except (OSError, json.JSONDecodeError, UnicodeDecodeError):
                        rejected = None
                    if (
                        isinstance(rejected, dict)
                        and rejected.get("schema") == "capy.application-rejection/v0"
                        and isinstance(rejected.get("reason"), str)
                    ):
                        return AcceptanceDecision(False, reason=rejected["reason"])
                raise AcceptanceOracleFailure("independent acceptance failed")
            try:
                receipt_bytes = receipt.read_bytes()
            except OSError as exc:
                raise AcceptanceOracleFailure("acceptance receipt missing") from exc
            self.service.record_devkit_acceptance(request.build_id, receipt_bytes)
            return AcceptanceDecision(True, receipt_bytes)


@dataclass(frozen=True)
class SecretlessConnectionBinding:
    name: str
    contract: str
    operation: str
    grant_id: str
    secretless: bool
    read_only: bool
    deterministic_simulator: bool
    available: bool


class BuilderServiceImmutablePublisher:
    """Publish exact accepted bytes and bind only an attested secretless read-only grant."""

    def __init__(
        self,
        service: BuilderService,
        *,
        devkit_wheel: Path,
        connection_resolver: Callable[
            [str, str, str, str, str], SecretlessConnectionBinding
        ] | None = None,
    ):
        self.service = service
        self.devkit_wheel = devkit_wheel
        self.connection_resolver = connection_resolver

    def publish(
        self,
        request: GenericBuildRequest,
        candidate: CandidateIdentity,
        acceptance_receipt: bytes,
    ) -> Publication:
        specification = request.packet.get("specification")
        if not isinstance(specification, dict):
            raise RuntimeFailure("BUILD_PACKET_INVALID")
        try:
            receipt = json.loads(acceptance_receipt)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise RuntimeFailure("CAPABILITY_ACCEPTANCE_RECEIPT_INVALID") from exc
        expected_identity = {
            "application_archive_sha256": candidate.archive_digest,
            "devkit_wheel_sha256": sha256(self.devkit_wheel.read_bytes()),
            "acceptance_receipt_sha256": sha256(acceptance_receipt),
            "candidate_commit": candidate.commit,
            "candidate_tree": candidate.tree,
            "devkit_commit": receipt.get("devkit_commit"),
            "descriptor_sha256": receipt.get("descriptor_sha256"),
        }
        with tempfile.TemporaryDirectory(prefix="capy-immutable-publish-") as temporary:
            archive = Path(temporary) / "candidate.zip"
            archive.write_bytes(candidate.archive)
            connections: dict[str, str] = {}
            requirements = specification.get("connections")
            if not isinstance(requirements, list) or len(requirements) > 1:
                raise RuntimeFailure("BUILD_CONNECTION_BINDING_MISMATCH")
            if requirements:
                if self.connection_resolver is None:
                    raise RuntimeFailure("BUILD_SECRETLESS_CONNECTION_UNAVAILABLE")
                requirement = requirements[0]
                with tempfile.TemporaryDirectory(prefix="capy-version-preflight-") as extracted:
                    source = Path(extracted) / "application"
                    source.mkdir()
                    self.service.runtime._extract_zip(archive, source)
                    version = tree_digest(source)
                binding = self.connection_resolver(
                    self.service.chat.build(request.build_id)["scope_id"],
                    specification["capability_id"],
                    version,
                    requirement["contract"],
                    requirement["operations"][0],
                )
                if (
                    not isinstance(binding, SecretlessConnectionBinding)
                    or not binding.secretless
                    or not binding.read_only
                    or not binding.deterministic_simulator
                    or not binding.available
                    or binding.name != requirement["name"]
                    or binding.contract != requirement["contract"]
                    or binding.operation != requirement["operations"][0]
                    or not binding.grant_id
                ):
                    raise RuntimeFailure("BUILD_SECRETLESS_CONNECTION_UNAVAILABLE")
                connections[binding.name] = binding.grant_id
            published = self.service.publish_devkit(
                request.build_id,
                archive,
                self.devkit_wheel,
                expected_identity,
                connections,
            )
        return Publication(published)


class ProductControllerFreshSemanticRetry:
    """Retry through the controller and its configured shared-host OutcomeRuntime."""

    def __init__(self, controller: Any, runtime: OutcomeRuntime, *, require_host: bool = True):
        if controller.runtime is not runtime:
            raise ValueError("retry controller/runtime mismatch")
        if require_host and isinstance(runtime.launcher, LocalProcessLauncher):
            raise ValueError("shared-host launcher required")
        self.controller = controller
        self.runtime = runtime

    def retry(self, request: GenericBuildRequest, publication: Publication) -> Any:
        build = self.controller.chat_store.build(request.build_id)
        if build["status"] != "PUBLISHED":
            raise RuntimeFailure("BUILD_STATE_CONFLICT")
        turn_id = self.controller.retry_build(request.build_id)
        turn = self.controller.chat_store.turn(turn_id)
        invocation_id = turn.get("invocation_id")
        decision = turn.get("action")
        if (
            turn.get("status") != "done"
            or turn.get("conversation_id") != build["conversation_id"]
            or turn.get("adapter") != self.controller.semantic.name
            or turn.get("model") != self.controller.semantic.model
            or not isinstance(invocation_id, str)
            or not isinstance(decision, dict)
            or decision.get("action") != "invoke"
            or decision.get("capability_id") != build["candidate_capability_id"]
            or decision.get("resources") != list(build["resources"])
        ):
            raise RuntimeFailure("BUILD_RETRY_EVIDENCE_INVALID")
        evidence_reader = getattr(self.runtime, "invocation_evidence", None)
        invocation = (
            evidence_reader(invocation_id)
            if callable(evidence_reader)
            else self.runtime.store.invocation(invocation_id)
        )
        receipt = invocation.get("receipt")
        published = build.get("published_binding") or {}
        if (
            invocation.get("status") != "succeeded"
            or not isinstance(receipt, dict)
            or receipt.get("invocation_id") != invocation_id
            or receipt.get("scope_id") != build["scope_id"]
            or receipt.get("capability_id") != build["candidate_capability_id"]
            or receipt.get("version_digest") != published.get("version_digest")
            or receipt.get("resource_digests") != list(build["resources"])
        ):
            raise RuntimeFailure("BUILD_RETRY_EVIDENCE_INVALID")
        return {
            "schema": "capy.generic-build-retry-evidence/v0",
            "turn_id": turn_id,
            "conversation_id": build["conversation_id"],
            "scope_id": build["scope_id"],
            "semantic_provider": turn["adapter"],
            "semantic_model": turn["model"],
            "semantic_decision": decision,
            "semantic_usage": turn.get("usage") or {},
            "invocation_id": invocation_id,
            "invocation_receipt_sha256": sha256(canonical_json(receipt)),
            "invocation_receipt": receipt,
            **(
                {"shared_host_proof": invocation["shared_host_proof"]}
                if isinstance(invocation.get("shared_host_proof"), dict) else {}
            ),
        }


@dataclass(frozen=True)
class SharedHostCommandConfig:
    ssh_command: tuple[str, ...]
    scp_command: tuple[str, ...]
    destination: str
    remote_runtime_source: str
    remote_scratch_root: str
    systemd_user: str = "nobody"
    timeout_seconds: int = 300

    def __post_init__(self) -> None:
        source = PurePosixPath(self.remote_runtime_source)
        scratch = PurePosixPath(self.remote_scratch_root)
        if (
            not self.ssh_command
            or not self.scp_command
            or not re.fullmatch(r"[A-Za-z0-9_.@-]+", self.destination)
            or not source.is_absolute()
            or not scratch.is_absolute()
            or str(scratch) in {"/", "/tmp"}
            or not re.fullmatch(r"[a-z_][a-z0-9_-]{0,31}", self.systemd_user)
            or not 30 <= self.timeout_seconds <= 900
        ):
            raise ValueError("invalid shared-host command configuration")


class _SharedHostLauncherMarker:
    """Marks that invocation is delegated to the committed shared-host bridge."""


class SshSharedHostOutcomeRuntime(OutcomeRuntime):
    """Revalidate locally, execute on shared systemd compute, and import exact results."""

    def __init__(self, store: Any, config: SharedHostCommandConfig):
        super().__init__(store, launcher=_SharedHostLauncherMarker())
        self.config = config
        self._evidence: dict[str, dict[str, Any]] = {}

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
        if on_invocation_started is not None:
            raise RuntimeFailure("SHARED_HOST_CALLBACK_UNSUPPORTED")
        binding = self.store.binding(scope_id, capability_id)
        version = binding.version_digest
        if expected_version_digest is not None and version != expected_version_digest:
            raise RuntimeFailure("CAPABILITY_VERSION_MISMATCH")
        descriptor = self.store.descriptor(capability_id, version)
        if descriptor.state_required or descriptor.connections:
            raise RuntimeFailure("SHARED_HOST_DESCRIPTOR_OUT_OF_SCOPE")
        if resource_bindings is not None and resource_digests is not None:
            raise RuntimeFailure("INVOCATION_RESOURCE_BINDING_INVALID")
        if resource_bindings is None:
            slots = [item.name for item in descriptor.resource_requirements]
            if len(slots) > 1:
                raise RuntimeFailure("SHARED_HOST_DESCRIPTOR_OUT_OF_SCOPE")
            resource_bindings = ({slots[0]: list(resource_digests or [])} if slots else {})
        ordered_resources: list[tuple[str, str, str, Path]] = []
        for slot, digests in resource_bindings.items():
            for digest in digests:
                path, filename = self.store.resource(scope_id, digest)
                if sha256(path.read_bytes()) != digest:
                    raise RuntimeFailure("RESOURCE_CORRUPT")
                ordered_resources.append((slot, digest, filename, path))
        publication = self.store.devkit_publication(capability_id, version)
        receipt_path = self.store.acceptance / publication["acceptance_digest"]
        archive_path = self.store.archives / publication["archive_digest"]
        wheel_path = self.store.environments / publication["wheel_digest"] / "wheel.whl"
        receipt_value = json.loads(receipt_path.read_bytes())
        expected_identity = {
            "application_archive_sha256": publication["archive_digest"],
            "devkit_wheel_sha256": publication["wheel_digest"],
            "acceptance_receipt_sha256": publication["acceptance_digest"],
            "candidate_commit": publication["candidate_commit"],
            "candidate_tree": publication["candidate_tree"],
            "devkit_commit": receipt_value["devkit_commit"],
            "descriptor_sha256": receipt_value["descriptor_sha256"],
        }
        remote = f"{self.config.remote_scratch_root.rstrip('/')}/{uuid.uuid4().hex}"
        with tempfile.TemporaryDirectory(prefix="capy-shared-host-client-") as temporary:
            local = Path(temporary)
            files: dict[str, Path] = {}
            for name, source in (
                ("application.zip", archive_path),
                ("acceptance.json", receipt_path),
                ("devkit.whl", wheel_path),
            ):
                staged = local / name
                shutil.copyfile(source, staged)
                files[name] = staged
            staged_resources = []
            for index, (slot, digest, filename, path) in enumerate(ordered_resources):
                staged = local / f"resource-{index}"
                shutil.copyfile(path, staged)
                files[staged.name] = staged
                staged_resources.append({
                    "slot": slot, "digest": digest, "filename": filename,
                    "path": f"{remote}/{staged.name}",
                })
            values: dict[str, Any] = {
                "expected-identity.json": expected_identity,
                "resources.json": staged_resources,
                "request.json": request,
            }
            if initiator is not None:
                values["initiator.json"] = initiator
            for name, value in values.items():
                path = local / name
                path.write_bytes(canonical_json(value) + b"\n")
                files[name] = path
            created = _run(
                [*self.config.ssh_command, self.config.destination,
                 f"test ! -e {shlex.quote(remote)} && mkdir -p {shlex.quote(remote)}"],
                timeout=30,
            )
            if created.returncode:
                raise RuntimeFailure("SHARED_HOST_STAGING_FAILED")
            try:
                copied = _run(
                    [*self.config.scp_command, *[str(path) for path in files.values()],
                     f"{self.config.destination}:{remote}/"],
                    timeout=120,
                )
                if copied.returncode:
                    raise RuntimeFailure("SHARED_HOST_STAGING_FAILED")
                arguments = [
                    "sudo", "env", f"PYTHONPATH={self.config.remote_runtime_source}/src",
                    "python3", "-m", "capy_outcome_runtime.shared_host",
                    "--runtime-root", f"{remote}/runtime",
                    "--application-archive", f"{remote}/application.zip",
                    "--acceptance-receipt", f"{remote}/acceptance.json",
                    "--devkit-wheel", f"{remote}/devkit.whl",
                    "--expected-identity", f"{remote}/expected-identity.json",
                    "--scope-id", scope_id,
                    "--capability-id", capability_id,
                    "--version-digest", version,
                    "--resources", f"{remote}/resources.json",
                    "--request", f"{remote}/request.json",
                    "--systemd-user", self.config.systemd_user,
                    "--output", f"{remote}/proof.json",
                ]
                if idempotency_key is not None:
                    arguments.extend(["--idempotency-key", idempotency_key])
                if initiator is not None:
                    arguments.extend(["--initiator", f"{remote}/initiator.json"])
                executed = _run(
                    [*self.config.ssh_command, self.config.destination, shlex.join(arguments)],
                    timeout=self.config.timeout_seconds,
                )
                if executed.returncode:
                    raise RuntimeFailure("SHARED_HOST_EXECUTION_FAILED")
                proof_path = local / "proof.json"
                collected = _run(
                    [*self.config.scp_command,
                     f"{self.config.destination}:{remote}/proof.json", str(proof_path)],
                    timeout=60,
                )
                if collected.returncode:
                    raise RuntimeFailure("SHARED_HOST_RESULT_UNAVAILABLE")
                proof = json.loads(proof_path.read_bytes())
            finally:
                _run(
                    [*self.config.ssh_command, self.config.destination,
                     f"sudo find {shlex.quote(remote)} -depth -delete"],
                    timeout=60,
                )
        receipt = proof.get("invocation_receipt")
        expected_resources = [item[1] for item in ordered_resources]
        if (
            proof.get("schema") != "capy.shared-host-invocation/v0"
            or proof.get("status") != "passed"
            or proof.get("scope_id") != scope_id
            or proof.get("capability_id") != capability_id
            or proof.get("version_digest") != version
            or proof.get("candidate_commit") != publication["candidate_commit"]
            or proof.get("candidate_tree") != publication["candidate_tree"]
            or proof.get("application_archive_sha256") != publication["archive_digest"]
            or proof.get("acceptance_receipt_sha256") != publication["acceptance_digest"]
            or proof.get("publication_identity_sha256") != publication["publication_identity_digest"]
            or proof.get("launcher") != "SystemdTransientLauncher"
            or not proof.get("restart_reread_without_reexecution")
            or not isinstance(receipt, dict)
            or receipt.get("scope_id") != scope_id
            or receipt.get("capability_id") != capability_id
            or receipt.get("version_digest") != version
            or receipt.get("resource_digests") != expected_resources
            or proof.get("invocation_receipt_sha256") != sha256(canonical_json(receipt))
        ):
            raise RuntimeFailure("SHARED_HOST_RESULT_INVALID")
        result = proof.get("result")
        if not isinstance(result, dict) or proof.get("result_sha256") != sha256(canonical_json(result)):
            raise RuntimeFailure("SHARED_HOST_RESULT_INVALID")
        artifacts = []
        for item in proof.get("artifacts", []):
            try:
                payload = base64.b64decode(item["payload_base64"], validate=True)
            except (KeyError, ValueError) as exc:
                raise RuntimeFailure("SHARED_HOST_RESULT_INVALID") from exc
            if len(payload) != item.get("size_bytes") or sha256(payload) != item.get("digest"):
                raise RuntimeFailure("SHARED_HOST_RESULT_INVALID")
            registered = self.store.add_resource(scope_id, item["filename"], payload)
            if registered != item["digest"]:
                raise RuntimeFailure("SHARED_HOST_RESULT_INVALID")
            artifacts.append({
                "filename": item["filename"], "digest": registered, "size_bytes": len(payload)
            })
        invocation_id = proof.get("invocation_id")
        if not isinstance(invocation_id, str) or receipt.get("invocation_id") != invocation_id:
            raise RuntimeFailure("SHARED_HOST_RESULT_INVALID")
        preserved = dict(proof)
        preserved["artifacts"] = [
            {key: value for key, value in item.items() if key != "payload_base64"}
            for item in proof.get("artifacts", [])
        ]
        self._evidence[invocation_id] = {
            "id": invocation_id, "status": "succeeded", "receipt": receipt,
            "result": result, "artifacts": artifacts, "shared_host_proof": preserved,
        }
        return InvocationResult(invocation_id, result, tuple(artifacts), receipt)

    def invocation_evidence(self, invocation_id: str) -> dict[str, Any]:
        try:
            return self._evidence[invocation_id]
        except KeyError as exc:
            raise RuntimeFailure("INVOCATION_UNKNOWN") from exc


class GenericBuildProductionCoordinator:
    """Digest-bound production entry point for one already approved proposal."""

    TERMINAL_STATUSES = {"COMPLETED", "BLOCKED", "CANDIDATE_REJECTED", "CANCELLED"}

    def __init__(
        self,
        chat: ChatStore,
        service: BuilderService,
        orchestrator: GenericBuildOrchestrator,
        *,
        builder_identity: str = "fresh-codex-generic-v0",
    ):
        self.chat = chat
        self.service = service
        self.orchestrator = orchestrator
        self.builder_identity = builder_identity

    def run(self, request: GenericBuildRequest) -> GenericBuildOutcome:
        """Controller hook: execute one already digest-verified approved build."""

        build = self.chat.build(request.build_id)
        proposal = self.chat.build_proposal_for_gap(build["scope_id"], build["gap_id"])
        if (
            proposal is None
            or proposal["status"] != "APPROVED"
            or proposal["approved_build_id"] != request.build_id
        ):
            raise RuntimeFailure("BUILD_PROPOSAL_AUTHORITY_MISMATCH")
        if build["status"] != "APPROVED_WAITING_FOR_BUILDER":
            raise RuntimeFailure("BUILD_STATE_CONFLICT")
        packet = dict(request.packet)
        if (
            packet.get("schema") != "capy.supervised-build-packet/v0"
            or packet.get("build_id") != request.build_id
            or not isinstance(packet.get("specification"), dict)
            or sha256(canonical_json(packet) + b"\n") != build["packet_digest"]
            or packet != self.service._packet_value(request.build_id)
        ):
            raise RuntimeFailure("BUILD_PACKET_TAMPERED")
        self.service.claim(request.build_id, self.builder_identity)
        outcome = self.orchestrator.run(
            request,
            cancelled=lambda: self.chat.build(request.build_id)["status"] == "CANCELLED",
        )
        self._persist_outcome(build, outcome)
        return outcome

    def run_approved(self, build_id: str, proposal_digest: str) -> GenericBuildOutcome:
        """Operator hook retaining an explicit proposal-digest recheck."""

        build = self.chat.build(build_id)
        proposal = self.chat.build_proposal_for_gap(build["scope_id"], build["gap_id"])
        if proposal is None or proposal["proposal_digest"] != proposal_digest:
            raise RuntimeFailure("BUILD_PROPOSAL_AUTHORITY_MISMATCH")
        return self.run(GenericBuildRequest(build_id, self.service._packet_value(build_id)))

    def _persist_outcome(
        self, original_build: dict[str, Any], outcome: GenericBuildOutcome
    ) -> None:
        current = self.chat.build(original_build["id"])
        if outcome.classification == "COMPLETED":
            if current["status"] != "COMPLETED":
                raise RuntimeFailure("BUILD_COMPLETION_NOT_PERSISTED")
            return
        target = (
            "CANCELLED" if outcome.classification == "CANCELLED"
            else "CANDIDATE_REJECTED" if outcome.classification in {
                "CANDIDATE_REJECTED", "ORACLE_FAILED"
            }
            else "BLOCKED"
        )
        if current["status"] not in self.TERMINAL_STATUSES:
            current = self.chat.transition_build(
                original_build["id"],
                {current["status"]},
                target,
                terminal_error=outcome.classification,
            )
        elif current["status"] != target and current["status"] != "BLOCKED":
            raise RuntimeFailure("BUILD_TERMINAL_STATE_CONFLICT")
        self._append_terminal_message_once(original_build, outcome)

    def _append_terminal_message_once(
        self, build: dict[str, Any], outcome: GenericBuildOutcome
    ) -> None:
        timeline = self.chat.timeline(build["scope_id"], build["conversation_id"])
        if any(
            item["metadata"].get("build_id") == build["id"]
            and item["metadata"].get("build_classification") == outcome.classification
            for item in timeline["messages"]
        ):
            return
        self.chat.append_message(
            build["scope_id"],
            build["conversation_id"],
            "assistant",
            "Capy could not complete the approved software build. No verified result was produced.",
            kind="problem",
            state="PROBLEM",
            metadata={
                "build_id": build["id"],
                "build_classification": outcome.classification,
                "cleanup_complete": outcome.cleanup_complete,
            },
        )
