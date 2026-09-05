"""Deterministic portable receipt/rejection projection."""
from __future__ import annotations

import hashlib

from . import codec
from .constants import ACCEPT_SCHEMA, NON_GOALS, REJECT_SCHEMA


def build_identity(candidate, profile, release: dict) -> dict:
    return {
        "candidate_bundle_sha256": candidate.bundle_sha256,
        "candidate_release_candidate_id": candidate.manifest["release_candidate_id"],
        "profile_bundle_sha256": profile.bundle_sha256,
        "profile_id": profile.document["profile_id"],
        "application_id": profile.document["application_id"],
        "acceptor": dict(release),
    }


def identity_sha(identity: dict) -> str:
    return hashlib.sha256(codec.canonical_bytes(identity)).hexdigest()


def acceptance_id_for(isha: str) -> str:
    return "acc_" + isha[:32]


def application_projection(candidate) -> dict:
    m = candidate.manifest
    return {
        "archive_sha256": m["application"]["archive"]["sha256"],
        "descriptor_sha256": m["application"]["descriptor_sha256"],
        "interaction_sha256": m["application"]["interaction"]["sha256"],
        "execution_contract": m["application"]["contract"],
        "interaction_contract": m["application"]["interaction"]["schema"],
    }


def result_sha(result) -> str | None:
    if result is None:
        return None
    return hashlib.sha256(codec.canonical_bytes(result)).hexdigest()


def build_case_projection(*, case_id: str, matched: bool, classification: str, expected: dict, observed: dict) -> dict:
    return {
        "case_id": case_id,
        "matched": bool(matched),
        "classification": classification,
        "expected": dict(expected),
        "observed": dict(observed),
    }


def build_expected_entry(expect: dict, profile_members: dict) -> dict:
    arts = []
    for a in expect.get("artifacts", []):
        data = profile_members.get(a["member"], b"")
        arts.append({"filename": a["filename"], "sha256": a["sha256"], "size_bytes": len(data)})
    arts.sort(key=lambda x: x["filename"])
    return {
        "status": expect["status"],
        "result_sha256": result_sha(expect.get("result")),
        "artifacts": arts,
        "failure_code": expect.get("failure_code"),
    }


def build_observed_entry(*, status: str, result, artifacts: list, failure_code) -> dict:
    # artifacts: list of {filename, sha256, size_bytes} already sorted.
    arts = sorted(list(artifacts), key=lambda x: x["filename"])
    return {
        "status": status,
        "result_sha256": result_sha(result),
        "artifacts": arts,
        "failure_code": failure_code,
    }


def build_document(
    *,
    status: str,
    classification: str,
    identity: dict,
    isha: str,
    aid: str,
    candidate,
    cases: list[dict],
    secret_status: str,
    secret_findings: list[str],
) -> dict:
    schema = ACCEPT_SCHEMA if status == "ACCEPTED" else REJECT_SCHEMA
    return {
        "schema": schema,
        "acceptance_id": aid,
        "identity_sha256": isha,
        "identity": dict(identity),
        "status": status,
        "classification": classification,
        "source": dict(candidate.manifest["source"]),
        "application": application_projection(candidate),
        "toolchain": dict(candidate.manifest["toolchain"]),
        "cases": list(cases),
        "secret_scan": {"status": secret_status, "findings": list(secret_findings)},
        "cleanup": {"status": "CONFIRMED"},
        "non_claims": list(NON_GOALS),
    }
