"""Fail-closed orchestration for the bounded generic software build lane.

This module is an internal trusted-boundary adapter.  It deliberately does not
extend the application descriptor or the public DevKit contract.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Mapping, Protocol


_COMMIT = re.compile(r"[0-9a-f]{40}")
_DIGEST = re.compile(r"[0-9a-f]{64}")


class BuilderFailure(Exception):
    """The fresh builder stopped without producing a usable push."""


class BuilderTimeout(BuilderFailure):
    """The bounded fresh-builder window expired."""


class AcceptanceOracleFailure(Exception):
    """Independent acceptance could not make a trustworthy judgment."""


@dataclass(frozen=True)
class GenericBuildRequest:
    build_id: str
    packet: Mapping[str, Any]

    def __post_init__(self) -> None:
        if not self.build_id or not isinstance(self.packet, Mapping):
            raise ValueError("invalid generic build request")


@dataclass(frozen=True)
class MinimalGitGrant:
    repository: str
    clone_url: str
    grant_id: str
    private_key_path: Path = field(repr=False)

    def __post_init__(self) -> None:
        if (
            not self.repository.startswith("minimal-git://")
            or not self.clone_url.startswith("ssh://")
            or not self.grant_id
            or not isinstance(self.private_key_path, Path)
        ):
            raise ValueError("invalid Minimal Git grant")


@dataclass(frozen=True)
class CandidateIdentity:
    repository: str
    commit: str
    tree: str
    archive: bytes = field(repr=False)
    archive_digest: str

    def __post_init__(self) -> None:
        if (
            not self.repository
            or _COMMIT.fullmatch(self.commit) is None
            or _COMMIT.fullmatch(self.tree) is None
            or not isinstance(self.archive, bytes)
            or not self.archive
            or _DIGEST.fullmatch(self.archive_digest) is None
            or hashlib.sha256(self.archive).hexdigest() != self.archive_digest
        ):
            raise ValueError("invalid candidate identity")


@dataclass(frozen=True)
class AcceptanceDecision:
    accepted: bool
    receipt: bytes | None = field(default=None, repr=False)
    reason: str | None = None


@dataclass(frozen=True)
class Publication:
    identity: Mapping[str, Any]


@dataclass(frozen=True)
class GenericBuildOutcome:
    classification: str
    candidate: CandidateIdentity | None = None
    publication: Publication | None = None
    retry_result: Any = None
    detail: str | None = None
    cleanup_complete: bool = False

    @property
    def succeeded(self) -> bool:
        return self.classification == "COMPLETED"


class MinimalGitAuthority(Protocol):
    """Trusted repository authority; implementations own all Git credentials."""

    def create_repository_and_grant(self, request: GenericBuildRequest) -> MinimalGitGrant: ...

    def collect_candidate(self, grant: MinimalGitGrant) -> CandidateIdentity | None: ...

    def revoke_grant(self, grant: MinimalGitGrant) -> None: ...

    def confirm_push_denied(self, grant: MinimalGitGrant) -> bool: ...

    def remove_private_key(self, grant: MinimalGitGrant) -> None: ...


class FreshCodexBuilder(Protocol):
    def build_and_push(self, request: GenericBuildRequest, grant: MinimalGitGrant) -> None: ...


class IndependentAcceptor(Protocol):
    def accept(
        self, request: GenericBuildRequest, candidate: CandidateIdentity
    ) -> AcceptanceDecision: ...


class ImmutablePublisher(Protocol):
    def publish(
        self,
        request: GenericBuildRequest,
        candidate: CandidateIdentity,
        acceptance_receipt: bytes,
    ) -> Publication: ...


class FreshSemanticRetry(Protocol):
    def retry(self, request: GenericBuildRequest, publication: Publication) -> Any: ...


class _Cancelled(Exception):
    pass


class _CleanupFailure(Exception):
    pass


class _Terminal(Exception):
    pass


class GenericBuildOrchestrator:
    """Run one bounded build with authority removed before independent review."""

    def __init__(
        self,
        *,
        authority: MinimalGitAuthority,
        builder: FreshCodexBuilder,
        acceptor: IndependentAcceptor,
        publisher: ImmutablePublisher,
        retry: FreshSemanticRetry,
    ) -> None:
        self.authority = authority
        self.builder = builder
        self.acceptor = acceptor
        self.publisher = publisher
        self.retry = retry

    def run(
        self,
        request: GenericBuildRequest,
        *,
        cancelled: Callable[[], bool] = lambda: False,
    ) -> GenericBuildOutcome:
        grant: MinimalGitGrant | None = None
        candidate: CandidateIdentity | None = None
        publication: Publication | None = None
        cleanup_complete = False
        cleanup_attempted = False
        classification = "ORCHESTRATION_FAILED"
        detail: str | None = None
        retry_result: Any = None

        try:
            self._check_cancelled(cancelled)
            grant = self.authority.create_repository_and_grant(request)
            self._check_cancelled(cancelled)
            try:
                self.builder.build_and_push(request, grant)
            except (BuilderTimeout, TimeoutError):
                classification = "BUILDER_TIMEOUT"
                raise _Terminal
            except Exception as error:
                # Timeout is deliberately distinct; every other builder exception
                # is a truthful builder failure, not a missing-software success.
                classification = "BUILDER_FAILED"
                detail = type(error).__name__
                raise _Terminal

            self._check_cancelled(cancelled)
            candidate = self.authority.collect_candidate(grant)
            if candidate is None:
                classification = "NO_PUSH"
                raise _Terminal
            if candidate.repository != grant.repository:
                classification = "CANDIDATE_IDENTITY_INVALID"
                detail = "repository mismatch"
                raise _Terminal

            # This is not deferred to the outer finally: acceptance must never
            # run while the fresh builder retains write authority or key bytes.
            cleanup_attempted = True
            self._cleanup(grant)
            cleanup_complete = True
            self._check_cancelled(cancelled)

            try:
                decision = self.acceptor.accept(request, candidate)
            except AcceptanceOracleFailure as error:
                classification = "ORACLE_FAILED"
                detail = str(error) or type(error).__name__
                raise _Terminal
            except Exception as error:
                classification = "ORACLE_FAILED"
                detail = type(error).__name__
                raise _Terminal
            if not isinstance(decision, AcceptanceDecision):
                classification = "ORACLE_FAILED"
                detail = "invalid acceptance decision"
                raise _Terminal
            if not decision.accepted:
                classification = "CANDIDATE_REJECTED"
                detail = decision.reason
                raise _Terminal
            if not decision.receipt:
                classification = "ORACLE_FAILED"
                detail = "accepted decision omitted receipt"
                raise _Terminal

            self._check_cancelled(cancelled)
            try:
                publication = self.publisher.publish(request, candidate, decision.receipt)
            except Exception as error:
                classification = "PUBLICATION_FAILED"
                detail = type(error).__name__
                raise _Terminal
            self._check_cancelled(cancelled)
            try:
                retry_result = self.retry.retry(request, publication)
            except Exception as error:
                classification = "RETRY_FAILED"
                detail = type(error).__name__
                raise _Terminal
            classification = "COMPLETED"
        except _Terminal:
            pass
        except _Cancelled:
            classification = "CANCELLED"
        except _CleanupFailure as error:
            classification = "CLEANUP_FAILED"
            detail = str(error)
        except Exception as error:
            classification = "ORCHESTRATION_FAILED"
            detail = type(error).__name__
        finally:
            if grant is not None and not cleanup_attempted:
                cleanup_attempted = True
                try:
                    self._cleanup(grant)
                    cleanup_complete = True
                except _CleanupFailure as error:
                    classification = "CLEANUP_FAILED"
                    detail = str(error)

        return self._outcome(
            classification,
            candidate,
            publication,
            detail,
            cleanup_complete,
            retry_result,
        )

    def _cleanup(self, grant: MinimalGitGrant) -> None:
        failures: list[str] = []
        try:
            self.authority.revoke_grant(grant)
        except Exception as error:
            failures.append(f"revoke:{type(error).__name__}")
        try:
            if not self.authority.confirm_push_denied(grant):
                failures.append("denial:not-confirmed")
        except Exception as error:
            failures.append(f"denial:{type(error).__name__}")
        try:
            self.authority.remove_private_key(grant)
        except Exception:
            # The orchestrator owns the final local deletion guarantee even if
            # an authority adapter fails while removing ancillary key state.
            pass
        if grant.private_key_path.exists():
            try:
                grant.private_key_path.unlink()
            except OSError as error:
                failures.append(f"private-key:{type(error).__name__}")
        if grant.private_key_path.exists():
            failures.append("private-key:still-present")
        if failures:
            raise _CleanupFailure(",".join(failures))

    @staticmethod
    def _check_cancelled(cancelled: Callable[[], bool]) -> None:
        if cancelled():
            raise _Cancelled

    @staticmethod
    def _outcome(
        classification: str,
        candidate: CandidateIdentity | None,
        publication: Publication | None,
        detail: str | None,
        cleanup_complete: bool,
        retry_result: Any = None,
    ) -> GenericBuildOutcome:
        return GenericBuildOutcome(
            classification=classification,
            candidate=candidate,
            publication=publication,
            retry_result=retry_result,
            detail=detail,
            cleanup_complete=cleanup_complete,
        )
