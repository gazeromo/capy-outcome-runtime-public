"""Independent V1 candidate validator; frozen entrypoint."""
from __future__ import annotations

import hashlib
import io
import json
import re
from urllib.parse import urlsplit
import zipfile

from . import codec
from . import validation as V
from .constants import (
    APP_EXPANDED_MAX_BYTES,
    APP_MAX_MEMBERS,
    APP_ZIP_MAX_BYTES,
    BUNDLE_MAX_BYTES,
    CANDIDATE_SCHEMA_V0,
    CANDIDATE_SCHEMA_V1,
    EXPECTED_HANDOFF,
    EXPECTED_STAGE_ORDER,
    EXECUTION_CONTRACT,
    INTERACTION_CONTRACT,
    MANIFEST_MAX_BYTES,
    INTERACTION_MAX_BYTES,
    RECEIPT_MAX_BYTES,
    NULL_EXIT_STAGES,
    OUTER_CANDIDATE_MEMBERS,
    OUTER_MAX_BYTES,
    TRUSTED_BUNDLE_SHA256,
    TRUSTED_IMPLEMENTATION_COMMIT,
    TRUSTED_RELEASE_BINDING_COMMIT,
    TRUSTED_WHEEL_FILENAME,
    TRUSTED_WHEEL_SHA256,
)
from .errors import AcceptorError
from .interaction import InteractionError, load_interaction_from_bytes, parse_descriptor
from .models import Candidate


def _integrity(msg: str = "") -> AcceptorError:
    return AcceptorError("RELEASE_CANDIDATE_INTEGRITY_FAILED", "candidate")


def _toolchain_integrity() -> AcceptorError:
    return AcceptorError("TOOLCHAIN_INTEGRITY_FAILED", "toolchain")


def _untrusted() -> AcceptorError:
    return AcceptorError("TOOLCHAIN_UNTRUSTED", "toolchain")


def _unsupported() -> AcceptorError:
    return AcceptorError("APPLICATION_UNSUPPORTED", "application")


def read_candidate(payload: bytes) -> Candidate:
    """Validate copied complete .capyrc bytes, or raise AcceptorError."""
    try:
        return _read(payload)
    except AcceptorError:
        raise
    except Exception:
        raise _integrity()


def _read(payload: bytes) -> Candidate:
    if not isinstance(payload, bytes):
        raise _integrity()
    if len(payload) > OUTER_MAX_BYTES:
        raise _integrity()
    if len(payload) == 0:
        raise _integrity()

    # Fast path for historical v0: peek loosely before canonical checks.
    # If manifest schema is v0, report version error (spec requires this
    # even for the four-member public vector). ZipInfo metadata is checked
    # before decompression so a DEFLATED bomb is not expanded here; the
    # canonical check below rejects it without a large allocation.
    try:
        with zipfile.ZipFile(io.BytesIO(payload)) as _z:
            if "RELEASE-CANDIDATE.json" in _z.namelist():
                try:
                    _peek_info = _z.getinfo("RELEASE-CANDIDATE.json")
                except KeyError:
                    _peek_info = None
                # Only peek STORED members; DEFLATED/unsupported members are
                # left for the canonical discipline to reject without reading.
                if _peek_info is not None and _peek_info.compress_type == zipfile.ZIP_STORED:
                    if _peek_info.file_size > MANIFEST_MAX_BYTES:
                        raise _integrity()
                    _raw = _z.read("RELEASE-CANDIDATE.json")
                    _val = json.loads(_raw.decode("utf-8"))
                    if isinstance(_val, dict) and _val.get("schema") == CANDIDATE_SCHEMA_V0:
                        raise AcceptorError("RELEASE_CANDIDATE_VERSION_UNSUPPORTED", "version")
    except AcceptorError:
        raise
    except Exception:
        pass

    # Metadata boundedness before outer decompression: reject oversized
    # STORED declarations without allocating them.
    try:
        from .constants import INTERACTION_MAX_BYTES as _IMAX
        from .constants import RECEIPT_MAX_BYTES as _RMAX

        with zipfile.ZipFile(io.BytesIO(payload)) as _pre:
            _bounds = {
                "RELEASE-CANDIDATE.json": MANIFEST_MAX_BYTES,
                "application/interaction.json": _IMAX,
                "evidence/verification.json": _RMAX,
                "application/application.zip": APP_ZIP_MAX_BYTES,
                "toolchain/authoring-bundle.zip": BUNDLE_MAX_BYTES,
            }
            for _name, _bound in _bounds.items():
                try:
                    _pi = _pre.getinfo(_name)
                except KeyError:
                    continue
                if _pi.compress_type != zipfile.ZIP_STORED:
                    continue
                if _pi.file_size > _bound:
                    raise _integrity()
    except AcceptorError:
        raise
    except (zipfile.BadZipFile, OSError, ValueError, KeyError):
        raise _integrity()

    # Canonical outer ZIP discipline (order, metadata, trailing data).
    try:
        members = codec.check_zip_canonical_members(payload, list(OUTER_CANDIDATE_MEMBERS))
    except ValueError:
        raise _integrity()

    # Per-member size bounds before allocation.
    try:
        manifest_raw = members["RELEASE-CANDIDATE.json"]
        outer_interaction_raw = members["application/interaction.json"]
        receipt_raw = members["evidence/verification.json"]
        app_zip_bytes = members["application/application.zip"]
        bundle_bytes = members["toolchain/authoring-bundle.zip"]
    except KeyError:
        raise _integrity()

    if len(manifest_raw) > MANIFEST_MAX_BYTES or len(receipt_raw) > RECEIPT_MAX_BYTES:
        raise _integrity()
    if len(outer_interaction_raw) > INTERACTION_MAX_BYTES:
        raise _integrity()
    if len(app_zip_bytes) > APP_ZIP_MAX_BYTES:
        raise _integrity()
    if len(bundle_bytes) > BUNDLE_MAX_BYTES:
        raise _integrity()

    # Canonical JSON discipline for outer JSON members.
    try:
        manifest = codec.check_canonical_json_bytes(manifest_raw, what="manifest")
        outer_interaction_doc = codec.check_canonical_json_bytes(outer_interaction_raw, what="interaction")
        receipt = codec.check_canonical_json_bytes(receipt_raw, what="receipt")
    except ValueError:
        raise _integrity()

    _validate_manifest_shape(manifest, members, payload)

    # Validate actual byte bindings for manifest-declared members.
    _check_member_binding(manifest, members)

    # Validate application inner ZIP safety and descriptor/interaction.
    app_members = _validate_application_zip(app_zip_bytes, manifest)

    descriptor_raw = app_members["capability.toml"]
    try:
        descriptor = parse_descriptor(descriptor_raw)
    except InteractionError as e:
        # Determine unsupported vs integrity: if descriptor is structurally
        # parseable as TOML with required fields but declares unsupported
        # values, map to UNSUPPORTED. Otherwise integrity.
        raise _map_descriptor_error(descriptor_raw, str(e))

    # Unsupported descriptor state/connections/side-effect/contracts.
    # Must be checked before semantic trial, including during read.
    if descriptor.get("state_required") is True:
        raise _unsupported()
    if descriptor.get("connections"):
        raise _unsupported()
    if descriptor.get("side_effect") not in ("read_only", "artifact_generation"):
        raise _unsupported()
    if manifest["application"]["contract"] != EXECUTION_CONTRACT:
        raise _unsupported()
    if manifest["application"]["interaction"]["schema"] != INTERACTION_CONTRACT:
        raise _unsupported()
    if manifest["toolchain"]["interaction_contract"] != INTERACTION_CONTRACT:
        raise _unsupported()

    # Descriptor raw hash authoritative.
    if hashlib.sha256(descriptor_raw).hexdigest() != manifest["application"]["descriptor_sha256"]:
        raise _integrity()
    # Descriptor id must match manifest application id.
    if descriptor["id"] != manifest["application"]["id"]:
        raise _integrity()
    # Entrypoint must exist as safe regular python file.
    entrypoint = descriptor["entrypoint"]
    if entrypoint not in app_members:
        raise _integrity()

    # Inner interaction raw: source hash binding + full contract validation.
    inner_raw = app_members["interaction.json"]
    if hashlib.sha256(inner_raw).hexdigest() != manifest["application"]["interaction"]["source_sha256"]:
        raise _integrity()
    # Outer canonical hash/size bindings.
    if hashlib.sha256(outer_interaction_raw).hexdigest() != manifest["application"]["interaction"]["sha256"]:
        raise _integrity()
    if len(outer_interaction_raw) != manifest["application"]["interaction"]["size_bytes"]:
        raise _integrity()
    # Canonical equality: outer canonical must equal canonical(inner parsed).
    try:
        inner_parsed = codec.parse_strict_json(inner_raw)
    except ValueError:
        raise _integrity()
    try:
        inner_canonical = codec.canonical_bytes(inner_parsed)
    except (TypeError, ValueError):
        raise _integrity()
    if inner_canonical != outer_interaction_raw:
        raise _integrity()
    # Full interaction contract validation (both docs must satisfy contract;
    # outer doc already canonical, inner doc canonical-equivalent).
    try:
        contract_outer = load_interaction_from_bytes(outer_interaction_raw, descriptor)
        # Validate inner as well (same canonical, but raw differs).
        load_interaction_from_bytes(inner_canonical, descriptor)
    except InteractionError:
        raise _integrity()
    # Operation id binding.
    if contract_outer["operation_id"] != manifest["application"]["interaction"]["operation_id"]:
        raise _integrity()
    if manifest["application"]["interaction"]["source_member"] != "interaction.json":
        raise _integrity()

    # Receipt validation (cross-member identities, stages, facts).
    _validate_receipt(receipt, manifest, app_zip_bytes, outer_interaction_raw, inner_raw)

    # verified_at equality already checked in receipt validator.

    # Toolchain bundle validation (hash before inspection, then trust).
    wheel_bytes = _validate_toolchain(bundle_bytes, manifest)

    # Candidate identity projection.
    _validate_identity(manifest)

    bundle_sha = hashlib.sha256(payload).hexdigest()
    # Build frozen model fields strictly from validated bytes.
    # members: outer name->bytes; application_members: inner name->bytes.
    return Candidate(
        bundle_sha256=bundle_sha,
        manifest=manifest,
        verification=receipt,
        descriptor=descriptor,
        interaction=contract_outer["document"],
        members=dict(members),
        application_members=dict(app_members),
        wheel_bytes=wheel_bytes,
    )


def _map_descriptor_error(raw: bytes, msg: str) -> AcceptorError:
    # Try to determine if TOML parses and has recognized fields but
    # unsupported values; otherwise integrity.
    try:
        import tomllib

        value = tomllib.loads(raw.decode("utf-8"))
    except Exception:
        return _integrity()
    try:
        # If required keys present, check unsupported signals.
        if isinstance(value, dict):
            if value.get("state_required") is True:
                return _unsupported()
            if isinstance(value.get("connections"), list) and len(value["connections"]) > 0:
                # Only if connections list itself is well-formed? Treat as unsupported
                # when it is a list (self-consistent declaration).
                return _unsupported()
            se = value.get("side_effect")
            if se in ("scope_state_mutation", "external_effect"):
                return _unsupported()
            if se not in ("read_only", "artifact_generation") and isinstance(se, str):
                # Unknown side effect string: integrity (malformed) unless
                # it looks like a versioned/known value. Keep integrity.
                pass
            # Unsupported contract versions.
            if isinstance(value.get("schema"), str) and value.get("schema") != EXECUTION_CONTRACT:
                # Recognized versioned contract string -> unsupported.
                if "/" in value["schema"]:
                    return _unsupported()
    except AcceptorError:
        raise
    except Exception:
        pass
    return _integrity()


def _validate_manifest_shape(manifest, members, payload):
    # Top-level exact keys.
    try:
        V.require_closed(
            manifest,
            {"schema", "project", "application", "source", "toolchain", "verification",
             "handoff", "identity_sha256", "release_candidate_id", "verified_at"},
            "manifest",
        )
    except ValueError:
        raise _integrity()
    if manifest["schema"] == CANDIDATE_SCHEMA_V0:
        raise AcceptorError("RELEASE_CANDIDATE_VERSION_UNSUPPORTED", "version")
    if manifest["schema"] != CANDIDATE_SCHEMA_V1:
        raise _integrity()
    # project
    try:
        V.require_closed(manifest["project"], {"project_id"}, "project")
        V.check_prj(manifest["project"]["project_id"])
    except ValueError:
        raise _integrity()
    # application
    try:
        V.require_closed(
            manifest["application"],
            {"archive", "contract", "descriptor_sha256", "id", "interaction"},
            "application",
        )
        V.check_application_id(manifest["application"]["id"])
        V.check_hex64(manifest["application"]["descriptor_sha256"], "descriptor_sha256")
        if not isinstance(manifest["application"]["contract"], str):
            raise ValueError("contract")
        V.require_closed(manifest["application"]["archive"], {"member", "sha256", "size_bytes"}, "archive")
        V.require_closed(
            manifest["application"]["interaction"],
            {"member", "operation_id", "schema", "sha256", "size_bytes", "source_member", "source_sha256"},
            "interaction",
        )
        V.check_dotted(manifest["application"]["interaction"]["operation_id"], "operation_id")
        V.check_hex64(manifest["application"]["interaction"]["sha256"], "interaction.sha256")
        V.check_hex64(manifest["application"]["interaction"]["source_sha256"], "interaction.source_sha256")
        if manifest["application"]["archive"]["member"] != "application/application.zip":
            raise ValueError("archive.member")
        if manifest["application"]["interaction"]["member"] != "application/interaction.json":
            raise ValueError("interaction.member")
        for key in ("size_bytes",):
            for holder in (manifest["application"]["archive"], manifest["application"]["interaction"]):
                v = holder[key]
                if type(v) is not int or v < 0:
                    raise ValueError("size")
        V.check_hex64(manifest["application"]["archive"]["sha256"], "archive.sha256")
    except ValueError:
        raise _integrity()
    # source
    try:
        V.require_closed(manifest["source"], {"base_commit", "commit", "repository", "tree"}, "source")
        V.check_hex40(manifest["source"]["base_commit"], "base_commit")
        V.check_hex40(manifest["source"]["commit"], "commit")
        V.check_hex40(manifest["source"]["tree"], "tree")
        repo = manifest["source"]["repository"]
        V.require_closed(repo, {"identity_sha256", "kind", "public_identity"}, "repository")
        V.check_hex64(repo["identity_sha256"], "repository.identity_sha256")
        if repo["kind"] not in ("local", "remote"):
            raise ValueError("kind")
        if repo["kind"] == "local":
            if repo["public_identity"] is not None:
                raise ValueError("public_identity")
        else:
            pid = repo["public_identity"]
            if not isinstance(pid, str) or not pid.startswith("git://") or any(ord(ch) <= 32 or ord(ch) == 127 for ch in pid):
                raise ValueError("public_identity")
            parsed = urlsplit(pid)
            if parsed.scheme != "git" or not parsed.hostname or parsed.username is not None or parsed.password is not None or parsed.query or parsed.fragment:
                raise ValueError("public_identity")
            if not re.fullmatch(r"[A-Za-z0-9.-]+(?::[0-9]{1,5})?", parsed.netloc) or not parsed.path.startswith("/"):
                raise ValueError("public_identity")
            if parsed.port is not None and not 1 <= parsed.port <= 65535:
                raise ValueError("public_identity")
            if any(not re.fullmatch(r"[A-Za-z0-9._~-]+", part) or part in {".", ".."} for part in parsed.path[1:].split("/")):
                raise ValueError("public_identity")
            if hashlib.sha256(pid.encode("utf-8")).hexdigest() != repo["identity_sha256"]:
                raise ValueError("identity_sha256")
    except ValueError:
        raise _integrity()
    # toolchain
    try:
        V.require_closed(
            manifest["toolchain"],
            {"authoring_bundle", "implementation_commit", "interaction_contract",
             "release_binding_commit", "wheel_filename", "wheel_sha256"},
            "toolchain",
        )
        V.check_hex40(manifest["toolchain"]["implementation_commit"], "implementation_commit")
        V.check_hex40(manifest["toolchain"]["release_binding_commit"], "release_binding_commit")
        V.check_hex64(manifest["toolchain"]["wheel_sha256"], "wheel_sha256")
        if not isinstance(manifest["toolchain"]["wheel_filename"], str) or not manifest["toolchain"]["wheel_filename"]:
            raise ValueError("wheel_filename")
        if not isinstance(manifest["toolchain"]["interaction_contract"], str):
            raise ValueError("interaction_contract")
        V.require_closed(
            manifest["toolchain"]["authoring_bundle"], {"member", "sha256", "size_bytes"}, "bundle"
        )
        if manifest["toolchain"]["authoring_bundle"]["member"] != "toolchain/authoring-bundle.zip":
            raise ValueError("bundle.member")
        V.check_hex64(manifest["toolchain"]["authoring_bundle"]["sha256"], "bundle.sha256")
        v = manifest["toolchain"]["authoring_bundle"]["size_bytes"]
        if type(v) is not int or v < 0:
            raise ValueError("bundle.size")
    except ValueError:
        raise _integrity()
    # verification
    try:
        V.require_closed(manifest["verification"], {"receipt", "verification_id"}, "verification")
        V.check_ver(manifest["verification"]["verification_id"])
        V.require_closed(manifest["verification"]["receipt"], {"member", "sha256", "size_bytes"}, "receipt")
        if manifest["verification"]["receipt"]["member"] != "evidence/verification.json":
            raise ValueError("receipt.member")
        V.check_hex64(manifest["verification"]["receipt"]["sha256"], "receipt.sha256")
        v = manifest["verification"]["receipt"]["size_bytes"]
        if type(v) is not int or v < 0:
            raise ValueError("receipt.size")
    except ValueError:
        raise _integrity()
    # handoff exact
    if not isinstance(manifest.get("handoff"), dict) or manifest["handoff"] != EXPECTED_HANDOFF:
        raise _integrity()
    # identity / rc id syntax
    try:
        V.check_hex64(manifest["identity_sha256"], "identity_sha256")
        V.check_rc(manifest["release_candidate_id"])
        V.check_verified_at(manifest["verified_at"])
    except ValueError:
        raise _integrity()


def _check_member_binding(manifest, members):
    app_bytes = members["application/application.zip"]
    if len(app_bytes) != manifest["application"]["archive"]["size_bytes"]:
        raise _integrity()
    if hashlib.sha256(app_bytes).hexdigest() != manifest["application"]["archive"]["sha256"]:
        raise _integrity()
    inter_bytes = members["application/interaction.json"]
    if len(inter_bytes) != manifest["application"]["interaction"]["size_bytes"]:
        raise _integrity()
    if hashlib.sha256(inter_bytes).hexdigest() != manifest["application"]["interaction"]["sha256"]:
        raise _integrity()
    receipt_bytes = members["evidence/verification.json"]
    if len(receipt_bytes) != manifest["verification"]["receipt"]["size_bytes"]:
        raise _integrity()
    if hashlib.sha256(receipt_bytes).hexdigest() != manifest["verification"]["receipt"]["sha256"]:
        raise _integrity()
    bundle_bytes = members["toolchain/authoring-bundle.zip"]
    if len(bundle_bytes) != manifest["toolchain"]["authoring_bundle"]["size_bytes"]:
        raise _integrity()
    # Bundle hash mismatch here is toolchain integrity (corrupt toolchain bytes),
    # but spec says validate actual bundle hash before inspecting. The outer
    # manifest binding failure for the bundle could be either generic integrity
    # or toolchain integrity. Prefer toolchain integrity for bundle member.
    if hashlib.sha256(bundle_bytes).hexdigest() != manifest["toolchain"]["authoring_bundle"]["sha256"]:
        raise _toolchain_integrity()


def _validate_application_zip(app_zip_bytes: bytes, manifest) -> dict[str, bytes]:
    try:
        with zipfile.ZipFile(io.BytesIO(app_zip_bytes)) as z:
            names = z.namelist()
            if not names:
                raise _integrity()
            if len(names) != len(set(names)):
                raise _integrity()
            if len(names) > APP_MAX_MEMBERS:
                raise _integrity()
            # No directories, no encryption; collect infos.
            total = 0
            for info in z.infolist():
                if info.is_dir() or info.filename.endswith("/"):
                    raise _integrity()
                if info.flag_bits & 0x1:
                    raise _integrity()
                # Absolute/parent/backslash checks.
                try:
                    codec.check_inner_name_safe(info.filename)
                except ValueError:
                    raise _integrity()
                # Symlink check via external attr? Unix symlink file type 0o120000.
                mode = (info.external_attr >> 16) & 0o170000
                if mode not in (0, 0o100000):
                    raise _integrity()
                total += info.file_size
                if total > APP_EXPANDED_MAX_BYTES:
                    raise _integrity()
            try:
                codec.check_casefold_collisions(names)
            except ValueError:
                raise _integrity()
            if "capability.toml" not in names or "interaction.json" not in names:
                raise _integrity()
            out: dict[str, bytes] = {}
            for n in names:
                # Never extract unvalidated paths: names already validated.
                out[n] = z.read(n)
            # Expanded total already checked.
            return out
    except AcceptorError:
        raise
    except Exception:
        raise _integrity()


def _validate_receipt(receipt, manifest, app_zip_bytes: bytes, outer_canonical: bytes, inner_raw: bytes):
    try:
        V.require_closed(
            receipt,
            {"application_archive", "application_id", "classification", "interaction_contract",
             "pipeline", "project_id", "schema", "session_id", "source", "stages",
             "status", "toolchain", "verification_id", "verified_at"},
            "receipt",
        )
    except ValueError:
        raise _integrity()
    try:
        if receipt["schema"] != "capy.development-verification-receipt/v1":
            raise ValueError("receipt.schema")
        if receipt["pipeline"] != "capy.development-verification-pipeline/v1":
            raise ValueError("receipt.pipeline")
        if receipt["status"] != "PASSED":
            raise ValueError("receipt.status")
        if receipt["classification"] != "VERIFIED":
            raise ValueError("receipt.classification")
        if receipt["application_id"] != manifest["application"]["id"]:
            raise ValueError("receipt.app")
        if receipt["project_id"] != manifest["project"]["project_id"]:
            raise ValueError("receipt.project")
        V.check_ses(receipt["session_id"])
        V.check_ver(receipt["verification_id"])
        if receipt["verification_id"] != manifest["verification"]["verification_id"]:
            raise ValueError("receipt.verification_id")
        # source identities match manifest.
        V.require_closed(receipt["source"], {"base_commit", "commit", "tree"}, "receipt.source")
        if (receipt["source"]["base_commit"] != manifest["source"]["base_commit"]
                or receipt["source"]["commit"] != manifest["source"]["commit"]
                or receipt["source"]["tree"] != manifest["source"]["tree"]):
            raise ValueError("receipt.source-match")
        V.check_hex40(receipt["source"]["base_commit"], "receipt.base")
        V.check_hex40(receipt["source"]["commit"], "receipt.commit")
        V.check_hex40(receipt["source"]["tree"], "receipt.tree")
        if receipt["verified_at"] != manifest["verified_at"]:
            raise ValueError("verified_at-match")
        V.check_verified_at(receipt["verified_at"])
        # application_archive matches. Precise integer types: booleans
        # are not integers; float/int equality must not pass.
        V.require_closed(receipt["application_archive"], {"sha256", "size_bytes"}, "receipt.archive")
        if type(receipt["application_archive"]["size_bytes"]) is not int:
            raise ValueError("receipt.archive-size-type")
        if (receipt["application_archive"]["sha256"] != manifest["application"]["archive"]["sha256"]
                or receipt["application_archive"]["size_bytes"] != manifest["application"]["archive"]["size_bytes"]):
            raise ValueError("receipt.archive-match")
        # interaction_contract matches manifest interaction.
        V.require_closed(
            receipt["interaction_contract"],
            {"canonical_sha256", "canonical_size_bytes", "operation_id", "schema",
             "source_member", "source_sha256"},
            "receipt.interaction",
        )
        mi = manifest["application"]["interaction"]
        ri = receipt["interaction_contract"]
        if type(ri["canonical_size_bytes"]) is not int:
            raise ValueError("receipt.canonical-size-type")
        if (ri["canonical_sha256"] != mi["sha256"] or ri["canonical_size_bytes"] != mi["size_bytes"]
                or ri["operation_id"] != mi["operation_id"] or ri["schema"] != mi["schema"]
                or ri["source_member"] != mi["source_member"] or ri["source_sha256"] != mi["source_sha256"]):
            raise ValueError("receipt.interaction-match")
        if ri["schema"] != INTERACTION_CONTRACT:
            raise ValueError("receipt.interaction-schema")
        # Actual canonical/source hashes must also match real bytes.
        if ri["canonical_sha256"] != hashlib.sha256(outer_canonical).hexdigest():
            raise ValueError("receipt.canonical-sha")
        if ri["canonical_size_bytes"] != len(outer_canonical):
            raise ValueError("receipt.canonical-size")
        if ri["source_sha256"] != hashlib.sha256(inner_raw).hexdigest():
            raise ValueError("receipt.source-sha")
        if ri["source_member"] != "interaction.json":
            raise ValueError("receipt.source-member")
        # toolchain matches manifest for key identities.
        V.require_closed(
            receipt["toolchain"],
            {"authoring_bundle_sha256", "contract", "implementation_commit", "interaction_contract",
             "lock_digest", "release_binding_commit", "wheel_filename", "wheel_sha256"},
            "receipt.toolchain",
        )
        mt = manifest["toolchain"]
        rt = receipt["toolchain"]
        if (rt["authoring_bundle_sha256"] != mt["authoring_bundle"]["sha256"]
                or rt["wheel_sha256"] != mt["wheel_sha256"]
                or rt["wheel_filename"] != mt["wheel_filename"]
                or rt["release_binding_commit"] != mt["release_binding_commit"]
                or rt["implementation_commit"] != mt["implementation_commit"]
                or rt["contract"] != manifest["application"]["contract"]
                or rt["interaction_contract"] != mt["interaction_contract"]):
            raise ValueError("receipt.toolchain-match")
        V.check_hex64(rt["authoring_bundle_sha256"], "rt.bundle")
        V.check_hex64(rt["wheel_sha256"], "rt.wheel")
        V.check_hex40(rt["implementation_commit"], "rt.impl")
        V.check_hex40(rt["release_binding_commit"], "rt.binding")
        # lock_digest must be sha syntax (may be empty hash for template? check example).
        V.check_hex64(rt["lock_digest"], "rt.lock")
        # stages
        stages = receipt["stages"]
        if not isinstance(stages, list) or [s.get("name") for s in stages] != list(EXPECTED_STAGE_ORDER):
            raise ValueError("stages-order")
        for s in stages:
            _validate_stage(s, app_zip_bytes, outer_canonical, inner_raw)
    except ValueError:
        raise _integrity()


def _validate_stage(stage, app_zip_bytes: bytes, outer_canonical: bytes, inner_raw: bytes):
    try:
        V.require_closed(
            stage,
            {"exit_code", "facts", "name", "status", "stderr_truncated_bytes", "stdout_truncated_bytes",
             "stored_stderr_bytes", "stored_stderr_sha256", "stored_stdout_bytes", "stored_stdout_sha256"},
            f"stage:{stage.get('name')}",
        )
    except ValueError:
        raise _integrity()
    name = stage["name"]
    if stage["status"] != "PASSED":
        raise _integrity()
    # exit codes.
    if name in NULL_EXIT_STAGES:
        if stage["exit_code"] is not None:
            raise _integrity()
    else:
        if type(stage["exit_code"]) is not int or stage["exit_code"] != 0:
            raise _integrity()
    # counters nonnegative ints, hashes sha.
    for key in ("stderr_truncated_bytes", "stdout_truncated_bytes", "stored_stderr_bytes", "stored_stdout_bytes"):
        v = stage[key]
        if type(v) is not int or v < 0:
            raise _integrity()
    for key in ("stored_stderr_sha256", "stored_stdout_sha256"):
        try:
            V.check_hex64(stage[key], key)
        except ValueError:
            raise _integrity()
    facts = stage["facts"]
    if not isinstance(facts, dict):
        raise _integrity()
    app_sha = hashlib.sha256(app_zip_bytes).hexdigest()
    app_size = len(app_zip_bytes)
    outer_sha = hashlib.sha256(outer_canonical).hexdigest()
    inner_sha = hashlib.sha256(inner_raw).hexdigest()
    if name == "toolchain_install":
        if set(facts) != {"timed_out"} or facts["timed_out"] is not False:
            raise _integrity()
    elif name in ("check", "interaction_check", "test", "conform", "pack_a", "pack_b"):
        if set(facts) != {"candidate_unchanged", "timed_out"}:
            raise _integrity()
        if facts["candidate_unchanged"] is not True or facts["timed_out"] is not False:
            raise _integrity()
    elif name == "source_mutation_check":
        if set(facts) != set():
            raise _integrity()
    elif name == "package_compare":
        if set(facts) != {"sha256_a", "sha256_b", "size_a", "size_b"}:
            raise _integrity()
        # Strict integer types before equality: booleans are not integers
        # and 1.0 must not equal 1.
        for k in ("size_a", "size_b"):
            if type(facts[k]) is not int or facts[k] < 0:
                raise _integrity()
        if (facts["sha256_a"] != app_sha or facts["sha256_b"] != app_sha
                or facts["size_a"] != app_size or facts["size_b"] != app_size):
            raise _integrity()
        for k in ("sha256_a", "sha256_b"):
            try:
                V.check_hex64(facts[k], k)
            except ValueError:
                raise _integrity()
    elif name == "archive_preserve":
        if set(facts) != {"sha256", "size_bytes"}:
            raise _integrity()
        if type(facts["size_bytes"]) is not int or facts["size_bytes"] < 0:
            raise _integrity()
        if facts["sha256"] != app_sha or facts["size_bytes"] != app_size:
            raise _integrity()
    elif name == "interaction_preserve":
        if set(facts) != {"candidate_unchanged", "canonical_sha256", "canonical_size_bytes",
                           "source_sha256", "timed_out"}:
            raise _integrity()
        if type(facts["canonical_size_bytes"]) is not int or facts["canonical_size_bytes"] < 0:
            raise _integrity()
        if (facts["candidate_unchanged"] is not True or facts["timed_out"] is not False
                or facts["canonical_sha256"] != outer_sha
                or facts["canonical_size_bytes"] != len(outer_canonical)
                or facts["source_sha256"] != inner_sha):
            raise _integrity()
    else:
        raise _integrity()


def _validate_toolchain(bundle_bytes: bytes, manifest) -> bytes:
    # Fixed trusted bundle validation before any inner decompression.
    # Retains causal classifications: corrupt bytes already raised integrity
    # in _check_member_binding; self-consistent but unapproved is untrusted.
    try:
        _mt = manifest["toolchain"]
        if (
            _mt["release_binding_commit"] != TRUSTED_RELEASE_BINDING_COMMIT
            or _mt["wheel_sha256"] != TRUSTED_WHEEL_SHA256
            or _mt["authoring_bundle"]["sha256"] != TRUSTED_BUNDLE_SHA256
            or _mt["implementation_commit"] != TRUSTED_IMPLEMENTATION_COMMIT
            or _mt["wheel_filename"] != TRUSTED_WHEEL_FILENAME
            or _mt["interaction_contract"] != INTERACTION_CONTRACT
        ):
            raise _untrusted()
        if hashlib.sha256(bundle_bytes).hexdigest() != TRUSTED_BUNDLE_SHA256:
            raise _toolchain_integrity()
    except AcceptorError:
        raise
    except Exception:
        raise _toolchain_integrity()
    # Now inspect bundle contents, enforcing expanded-size bounds from
    # ZipInfo metadata before any inner decompression/allocation.
    try:
        with zipfile.ZipFile(io.BytesIO(bundle_bytes)) as z:
            names = z.namelist()
            if "RELEASE-MANIFEST.json" not in names:
                raise _toolchain_integrity()
            # Find wheel member: wheel/<filename>
            wheel_name = None
            for n in names:
                if n.startswith("wheel/") and n.endswith(".whl"):
                    wheel_name = n
            if wheel_name is None:
                raise _toolchain_integrity()
            # Trusted filename check before reads (no decompression needed).
            if wheel_name != f"wheel/{TRUSTED_WHEEL_FILENAME}":
                if _mt["wheel_filename"] not in wheel_name:
                    raise _toolchain_integrity()
                raise _untrusted()
            try:
                _mi = z.getinfo("RELEASE-MANIFEST.json")
                _wi = z.getinfo(wheel_name)
            except KeyError:
                raise _toolchain_integrity()
            if _mi.file_size > MANIFEST_MAX_BYTES or _mi.file_size == 0:
                raise _toolchain_integrity()
            if _mi.compress_size > BUNDLE_MAX_BYTES:
                raise _toolchain_integrity()
            if _wi.file_size > BUNDLE_MAX_BYTES or _wi.file_size == 0:
                raise _toolchain_integrity()
            if _wi.compress_size > BUNDLE_MAX_BYTES:
                raise _toolchain_integrity()
            try:
                manifest_raw = z.read("RELEASE-MANIFEST.json")
                if len(manifest_raw) > MANIFEST_MAX_BYTES:
                    raise _toolchain_integrity()
                wheel_bytes = z.read(wheel_name)
                if len(wheel_bytes) > BUNDLE_MAX_BYTES:
                    raise _toolchain_integrity()
            except AcceptorError:
                raise
            except KeyError:
                raise _toolchain_integrity()
    except AcceptorError:
        raise
    except Exception:
        raise _toolchain_integrity()
    # Validate RELEASE-MANIFEST.json (JSON, not necessarily canonical? Check strict parse).
    try:
        rm = json.loads(manifest_raw.decode("utf-8"))
    except Exception:
        raise _toolchain_integrity()
    try:
        V.require_closed(
            rm,
            {"build_python", "build_tool", "contract_sha256", "execution_contract",
             "interaction_contract", "interaction_contract_sha256", "package_tree_sha256",
             "python_requirement", "qualification_receipt_sha256", "schema",
             "source_commit", "source_repository", "source_tree", "template_members",
             "wheel_filename", "wheel_sha256"},
            "release-manifest",
        )
        if rm["schema"] != "capy.devkit-authoring-bundle/v1":
            raise ValueError("rm.schema")
        if rm["execution_contract"] != EXECUTION_CONTRACT:
            raise ValueError("rm.exec")
        if rm["interaction_contract"] != INTERACTION_CONTRACT:
            raise ValueError("rm.inter")
        V.check_hex40(rm["source_commit"], "rm.source_commit")
        V.check_hex40(rm["source_tree"], "rm.source_tree")
        V.check_hex64(rm["wheel_sha256"], "rm.wheel")
        V.check_hex64(rm["contract_sha256"], "rm.contract")
        V.check_hex64(rm["interaction_contract_sha256"], "rm.inter-contract")
        V.check_hex64(rm["package_tree_sha256"], "rm.tree")
        V.check_hex64(rm["qualification_receipt_sha256"], "rm.qual")
        if not isinstance(rm["wheel_filename"], str) or not rm["wheel_filename"]:
            raise ValueError("rm.wheel_filename")
        if not isinstance(rm["template_members"], list):
            raise ValueError("rm.templates")
    except ValueError:
        raise _toolchain_integrity()
    # Wheel hash/filename/source_commit/contracts must match actual + manifest.
    actual_wheel_sha = hashlib.sha256(wheel_bytes).hexdigest()
    if actual_wheel_sha != manifest["toolchain"]["wheel_sha256"]:
        raise _toolchain_integrity()
    if actual_wheel_sha != rm["wheel_sha256"]:
        raise _toolchain_integrity()
    if manifest["toolchain"]["wheel_filename"] != rm["wheel_filename"]:
        raise _toolchain_integrity()
    if rm["source_commit"] != manifest["toolchain"]["implementation_commit"]:
        raise _toolchain_integrity()
    # Trust: declared identities must equal fixed trusted values.
    mt = manifest["toolchain"]
    if (mt["release_binding_commit"] != TRUSTED_RELEASE_BINDING_COMMIT
            or mt["wheel_sha256"] != TRUSTED_WHEEL_SHA256
            or mt["authoring_bundle"]["sha256"] != TRUSTED_BUNDLE_SHA256
            or mt["implementation_commit"] != TRUSTED_IMPLEMENTATION_COMMIT
            or mt["wheel_filename"] != TRUSTED_WHEEL_FILENAME
            or mt["interaction_contract"] != INTERACTION_CONTRACT):
        raise _untrusted()
    if (rm["wheel_sha256"] != TRUSTED_WHEEL_SHA256
            or rm["source_commit"] != TRUSTED_IMPLEMENTATION_COMMIT
            or rm["wheel_filename"] != TRUSTED_WHEEL_FILENAME):
        raise _untrusted()
    # Wheel filename must match bundle member basename.
    if wheel_name != f"wheel/{TRUSTED_WHEEL_FILENAME}":
        # If self-consistent but different filename, untrusted; if corrupt, integrity.
        # Check if manifest filename matches bundle member: if not, integrity.
        if mt["wheel_filename"] not in wheel_name:
            raise _toolchain_integrity()
        raise _untrusted()
    return wheel_bytes


def _validate_identity(manifest):
    proj = {
        "schema": manifest["schema"],
        "project_id": manifest["project"]["project_id"],
        "application_id": manifest["application"]["id"],
        "source": manifest["source"],
        "application_archive_sha256": manifest["application"]["archive"]["sha256"],
        "application_descriptor_sha256": manifest["application"]["descriptor_sha256"],
        "interaction": {
            "schema": manifest["application"]["interaction"]["schema"],
            "source_sha256": manifest["application"]["interaction"]["source_sha256"],
            "canonical_sha256": manifest["application"]["interaction"]["sha256"],
            "operation_id": manifest["application"]["interaction"]["operation_id"],
        },
        "verification_receipt_sha256": manifest["verification"]["receipt"]["sha256"],
        "toolchain": {
            "release_binding_commit": manifest["toolchain"]["release_binding_commit"],
            "authoring_bundle_sha256": manifest["toolchain"]["authoring_bundle"]["sha256"],
            "wheel_sha256": manifest["toolchain"]["wheel_sha256"],
            "interaction_contract": manifest["toolchain"]["interaction_contract"],
        },
    }
    try:
        h = hashlib.sha256(codec.canonical_bytes(proj)).hexdigest()
    except (TypeError, ValueError):
        raise _integrity()
    if h != manifest["identity_sha256"]:
        raise _integrity()
    if manifest["release_candidate_id"] != "rc_" + h[:32]:
        raise _integrity()
