"""Frozen core interfaces. Bytes are validated before constructing these models."""
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class Candidate:
    bundle_sha256: str
    manifest: dict[str, Any]
    verification: dict[str, Any]
    descriptor: dict[str, Any]
    interaction: dict[str, Any]
    members: dict[str, bytes]
    application_members: dict[str, bytes]
    wheel_bytes: bytes


@dataclass(frozen=True)
class Profile:
    bundle_sha256: str
    document: dict[str, Any]
    members: dict[str, bytes]


@dataclass(frozen=True)
class Evaluation:
    status: str
    classification: str
    document: dict[str, Any]
    case_records: list[dict[str, Any]]
