"""Durable supervised builder, trusted acceptance, publication, and rollback."""

from __future__ import annotations

import hashlib
import io
import json
import os
import pwd
import re
import shutil
import subprocess
import tempfile
import threading
import uuid
import zipfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence

from .chat import ChatStore
from .connections import ConnectionBroker, ConnectionControl, ConnectionInstance
from .encar_watcher_build import (
    APPLICATION_ID as ENCAR_WATCHER_APPLICATION_ID,
    campaign_input_paths as encar_watcher_campaign_input_paths,
    validate_gap as validate_encar_watcher_gap,
    validate_specification as validate_encar_watcher_specification,
)
from .fedex_oracle import compare_quote_results, normalize_rate_response, parse_package_csv
from .model import CapabilityDescriptor, RuntimeFailure
from .runtime import OutcomeRuntime
from .store import Binding, RuntimeStore, canonical_json, sha256, tree_digest, utc_now
from .world import WorldBuilder


ZIP_CAPABILITY_ID = "files.zip_selected"
FEDEX_CAPABILITY_ID = "shipping.fedex_quote"
BUILD_STATUSES = {
    "APPROVED_WAITING_FOR_BUILDER",
    "BUILDING",
    "CANDIDATE_SUBMITTED",
    "ACCEPTING",
    "CANDIDATE_REJECTED",
    "PUBLISHED",
    "RETRYING",
    "COMPLETED",
    "BLOCKED",
    "CANCELLED",
}
SECRET_PATTERNS = (
    re.compile(rb"sk-or-v1-[A-Za-z0-9_-]{16,}"),
    re.compile(rb"gh[oprsu]_[A-Za-z0-9]{20,}"),
    re.compile(rb"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
)


def _run(
    argv: Sequence[str],
    cwd: Path,
    *,
    timeout: int = 180,
    environment: Mapping[str, str] | None = None,
    preexec_fn: Callable[[], None] | None = None,
) -> subprocess.CompletedProcess[bytes]:
    try:
        return subprocess.run(
            list(argv), cwd=cwd, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT, timeout=timeout, check=False,
            env=None if environment is None else dict(environment),
            preexec_fn=preexec_fn,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise RuntimeFailure("BUILDER_COMMAND_FAILED") from exc


def _git(argv: Sequence[str], cwd: Path, *, timeout: int = 60) -> str:
    completed = _run(["git", *argv], cwd, timeout=timeout)
    if completed.returncode != 0:
        raise RuntimeFailure("BUILDER_GIT_FAILED")
    return completed.stdout.decode("utf-8", "strict").strip()


def _binding_value(binding: Binding | None) -> dict[str, Any] | None:
    if binding is None:
        return None
    return {
        "scope_id": binding.scope_id,
        "capability_id": binding.capability_id,
        "version_digest": binding.version_digest,
        "connections": binding.connections,
    }


def verify_zip_bytes(
    payload: bytes,
    expected: list[tuple[str, bytes]],
    *,
    max_archive_bytes: int = 64 * 1024 * 1024,
) -> dict[str, Any]:
    if not payload or len(payload) > max_archive_bytes:
        raise RuntimeFailure("ZIP_ORACLE_SIZE_INVALID")
    try:
        with zipfile.ZipFile(io.BytesIO(payload), "r") as archive:
            infos = archive.infolist()
            names = [item.filename for item in infos]
            expected_names = [name for name, _ in expected]
            if names != sorted(expected_names) or len(names) != len(expected_names):
                raise RuntimeFailure("ZIP_ORACLE_MEMBERS_INVALID")
            if len(names) != len(set(names)):
                raise RuntimeFailure("ZIP_ORACLE_MEMBERS_INVALID")
            expected_map = dict(expected)
            for info in infos:
                path = Path(info.filename)
                unix_mode = (info.external_attr >> 16) & 0o170000
                if (
                    path.is_absolute()
                    or ".." in path.parts
                    or path.name != info.filename
                    or unix_mode == 0o120000
                    or archive.read(info) != expected_map[info.filename]
                ):
                    raise RuntimeFailure("ZIP_ORACLE_MEMBER_INVALID")
    except (zipfile.BadZipFile, KeyError, OSError) as exc:
        raise RuntimeFailure("ZIP_ORACLE_INVALID") from exc
    return {
        "file_count": len(expected),
        "filenames": sorted(name for name, _ in expected),
        "digests": [
            {"filename": name, "sha256": sha256(content)}
            for name, content in sorted(expected)
        ],
        "archive_sha256": sha256(payload),
        "archive_size": len(payload),
    }


class BuilderService:
    """Trusted operator boundary. A Codex process never receives this object."""

    def __init__(
        self,
        chat: ChatStore,
        runtime: RuntimeStore,
        scripts_repository: Path,
        scratch_root: Path,
        *,
        publisher_identity: str = "trusted-local-publisher",
        builder_uid: int | None = None,
        builder_gid: int | None = None,
        connection_status: Callable[[str, str], str] | None = None,
        connection_inventory: Callable[[str], list[dict[str, Any]]] | None = None,
    ):
        self.chat = chat
        self.runtime = runtime
        self.scripts_repository = scripts_repository.resolve()
        self.scratch_root = scratch_root.resolve()
        self.publisher_identity = publisher_identity
        self.builder_uid = builder_uid
        self.builder_gid = builder_gid
        self.connection_status = connection_status
        self.connection_inventory = connection_inventory
        self.scratch_root.mkdir(parents=True, exist_ok=True)
        self.scratch_root.chmod(0o700)
        self.reconcile_publications()

    def _directory(self, build_id: str) -> Path:
        if not re.fullmatch(r"[0-9a-f]{32}", build_id):
            raise RuntimeFailure("BUILD_ID_INVALID")
        return self.scratch_root / build_id

    def approve(self, scope_id: str, gap_id: str) -> dict[str, Any]:
        gap = self.chat.gap(scope_id, gap_id)
        existing = [
            item for item in self.chat.builds_for_conversation(scope_id, gap["conversation_id"])
            if item["gap_id"] == gap_id
        ]
        if existing:
            return existing[0]
        is_fedex = "fedex" in (gap["needed_ability"] + " " + gap["original_message"]).lower()
        if gap["status"] != "open":
            raise RuntimeFailure("BUILD_APPROVAL_NOT_READY")
        if is_fedex:
            return self._approve_fedex(scope_id, gap)
        if gap["missing_information"]:
            raise RuntimeFailure("BUILD_APPROVAL_NOT_READY")
        if len(gap["resources"]) != 2:
            raise RuntimeFailure("BUILD_APPROVAL_NOT_READY")
        build_id = uuid.uuid4().hex
        directory = self._directory(build_id)
        fixtures = directory / "input" / "resources"
        fixtures.mkdir(parents=True)
        fixtures.chmod(0o700)
        resources = []
        for digest in gap["resources"]:
            source, filename = self.runtime.resource(scope_id, digest)
            payload = source.read_bytes()
            if sha256(payload) != digest:
                raise RuntimeFailure("RESOURCE_BYTES_INVALID")
            target = fixtures / digest
            target.write_bytes(payload)
            target.chmod(0o400)
            metadata = self.runtime.resource_metadata(scope_id, digest)
            resources.append({
                "handle": digest,
                "filename": filename,
                "size_bytes": metadata["size_bytes"],
                "sha256": digest,
                "fixture_path": str(target),
            })
        resources.sort(key=lambda item: (item["filename"], item["handle"]))
        inventory = self.runtime.list_bound_capabilities(scope_id)
        packet = {
            "schema": "capy.build-packet/v0",
            "build_id": build_id,
            "original_outcome": gap["original_message"],
            "conversation_context": [{"role": "owner", "text": gap["original_message"]}],
            "resources": resources,
            "world_digest": gap["world_digest"],
            "installed_capabilities": inventory,
            "connections": [
                fact for item in inventory for fact in item.get("connections", [])
            ],
            "gap": {
                "needed_ability": gap["needed_ability"],
                "desired_result": gap["desired_result"],
                "missing_information": gap["missing_information"],
            },
            "required_capability": {
                "id": ZIP_CAPABILITY_ID,
                "descriptor": {
                    "schema": "capy.script/v0",
                    "entrypoint": "main.py",
                    "side_effect": "read_only",
                    "visibility": "private",
                    "connections": [],
                    "state_required": False,
                },
                "input_schema": {"type": "object", "additionalProperties": False},
                "result_schema": {
                    "type": "object",
                    "required": ["filename", "file_count", "filenames", "digests"],
                    "additionalProperties": False,
                    "properties": {
                        "filename": {"type": "string"},
                        "file_count": {"type": "integer"},
                        "filenames": {"type": "array", "items": {"type": "string"}},
                        "digests": {"type": "array", "items": {
                            "type": "object", "required": ["filename", "sha256"],
                            "additionalProperties": False,
                            "properties": {
                                "filename": {"type": "string"},
                                "sha256": {"type": "string"},
                            },
                        }},
                    },
                },
                "side_effect_ceiling": "artifact_generation",
                "connections": [],
                "limits": {
                    "minimum_resources": 1,
                    "maximum_resources": 4,
                    "maximum_total_input_bytes": 16 * 1024 * 1024,
                    "maximum_archive_bytes": 64 * 1024 * 1024,
                    "artifact_filename": "selected-files.zip",
                },
            },
            "scope_and_safety": {
                "scope": scope_id,
                "no_arbitrary_host_paths": True,
                "no_runtime_database": True,
                "no_credentials": True,
                "no_publication_authority": True,
                "no_other_scope_data": True,
                "network_required": False,
            },
            "independent_oracle": {
                "identity": "capy.runtime.zip-selected/v0",
                "checks": [
                    "valid_zip", "exact_files", "exact_filenames", "exact_bytes",
                    "exact_sha256", "no_extra_members", "no_absolute_paths",
                    "no_parent_traversal", "no_symlinks", "sorted_members",
                    "bounded_archive_size",
                ],
            },
            "negative_controls": [
                "zero_selected_files", "duplicate_filename_conflict", "unsafe_filename",
                "oversized_total_input", "corrupt_or_missing_resource",
                "undeclared_output", "path_traversal_member", "extra_member",
            ],
            "repository": {
                "path": str(self.scripts_repository),
                "required_candidate_files": [
                    "capabilities/files/zip_selected/capability.toml",
                    "capabilities/files/zip_selected/main.py",
                    "tests/test_zip_selected.py",
                    "README.md",
                ],
                "test_commands": [
                    "python3 -W error::ResourceWarning -m unittest discover -s tests -v"
                ],
            },
            "publication_requirements": [
                "committed_candidate", "clean_tree", "trusted_acceptance",
                "immutable_publication", "scope_binding_by_trusted_publisher",
            ],
            "non_goals": [
                "FedEx", "sharing", "updates", "outbound Telegram",
                "external side effects", "containers", "microVMs",
            ],
        }
        encoded = canonical_json(packet) + b"\n"
        packet_digest = sha256(encoded)
        (directory / "BUILD-PACKET.json").write_bytes(encoded)
        (directory / "BUILD-PACKET.json").chmod(0o400)
        markdown = self._packet_markdown(packet, packet_digest)
        (directory / "BUILD-PACKET.md").write_text(markdown, encoding="utf-8")
        (directory / "BUILD-PACKET.md").chmod(0o400)
        now = utc_now()
        return self.chat.create_build_request({
            "id": build_id,
            "gap_id": gap_id,
            "conversation_id": gap["conversation_id"],
            "scope_id": scope_id,
            "original_owner_message_id": gap["owner_message_id"],
            "original_turn_id": gap["turn_id"],
            "original_world_digest": gap["world_digest"],
            "resources_json": canonical_json(gap["resources"]).decode(),
            "needed_ability": gap["needed_ability"],
            "desired_result": gap["desired_result"],
            "missing_information_json": canonical_json(gap["missing_information"]).decode(),
            "side_effect_ceiling": "artifact_generation",
            "packet_digest": packet_digest,
            "status": "APPROVED_WAITING_FOR_BUILDER",
            "created_at": now,
            "updated_at": now,
        })

    def approve_with_spec(
        self, scope_id: str, gap_id: str, specification: dict[str, Any]
    ) -> dict[str, Any]:
        """Approve one explicit supervisor profile without domain text routing."""

        self._validate_supervised_specification(specification)
        gap = self.chat.gap(scope_id, gap_id)
        resource_slot = specification["resource_slot"]
        minimum_resources = 0 if resource_slot is None else resource_slot["min_items"]
        maximum_resources = 0 if resource_slot is None else resource_slot["max_items"]
        if (
            gap["status"] != "open"
            or gap["missing_information"]
            or not minimum_resources <= len(gap["resources"]) <= maximum_resources
        ):
            raise RuntimeFailure("BUILD_APPROVAL_NOT_READY")
        existing = [
            item for item in self.chat.builds_for_conversation(scope_id, gap["conversation_id"])
            if item["gap_id"] == gap_id
        ]
        if existing:
            return existing[0]
        build_id = uuid.uuid4().hex
        directory = self._directory(build_id)
        resources_root = directory / "input" / "resources"
        resources_root.mkdir(parents=True)
        resources = []
        for digest in gap["resources"]:
            source, filename = self.runtime.resource(scope_id, digest)
            payload = source.read_bytes()
            if sha256(payload) != digest:
                raise RuntimeFailure("RESOURCE_BYTES_INVALID")
            fixture = resources_root / digest
            fixture.write_bytes(payload)
            fixture.chmod(0o400)
            resources.append({
                "handle": digest, "filename": filename, "size_bytes": len(payload),
                "sha256": digest, "fixture_path": str(fixture),
            })
        packet = {
            "schema": "capy.supervised-build-packet/v0",
            "build_id": build_id,
            "original_outcome": gap["original_message"],
            "resources": resources,
            "specification": specification,
            "scope_and_safety": {
                "no_runtime_source": True, "no_credentials": True,
                "no_publication_authority": True, "no_other_scope_data": True,
            },
        }
        encoded = canonical_json(packet) + b"\n"
        packet_digest = sha256(encoded)
        (directory / "BUILD-PACKET.json").write_bytes(encoded)
        (directory / "BUILD-PACKET.json").chmod(0o400)
        now = utc_now()
        return self.chat.create_build_request({
            "id": build_id, "gap_id": gap_id, "conversation_id": gap["conversation_id"],
            "scope_id": scope_id, "original_owner_message_id": gap["owner_message_id"],
            "original_turn_id": gap["turn_id"], "original_world_digest": gap["world_digest"],
            "resources_json": canonical_json(gap["resources"]).decode(),
            "needed_ability": gap["needed_ability"], "desired_result": gap["desired_result"],
            "missing_information_json": canonical_json(gap["missing_information"]).decode(),
            "side_effect_ceiling": specification["side_effect_ceiling"],
            "packet_digest": packet_digest, "status": "APPROVED_WAITING_FOR_BUILDER",
            "created_at": now, "updated_at": now,
        })

    def approve_encar_watcher(
        self, scope_id: str, gap_id: str, specification: dict[str, Any]
    ) -> dict[str, Any]:
        """Freeze the exact approved watcher packet without starting a builder."""

        validate_encar_watcher_specification(specification)
        gap = self.chat.gap(scope_id, gap_id)
        validate_encar_watcher_gap(gap)
        existing = [
            item
            for item in self.chat.builds_for_conversation(scope_id, gap["conversation_id"])
            if item["gap_id"] == gap_id
        ]
        if existing:
            return existing[0]

        build_id = uuid.uuid4().hex
        directory = self._directory(build_id)
        inputs_root = directory / "input" / "campaign"
        inputs_root.mkdir(parents=True)
        inputs_root.chmod(0o700)
        repository_root = Path(__file__).resolve().parents[2]
        inputs: list[dict[str, Any]] = []
        for source in encar_watcher_campaign_input_paths(repository_root):
            payload = source.read_bytes()
            target = inputs_root / source.name
            target.write_bytes(payload)
            target.chmod(0o400)
            inputs.append({
                "name": source.name,
                "fixture_path": str(target),
                "sha256": sha256(payload),
                "size_bytes": len(payload),
            })

        packet = {
            "schema": "capy.team-application-build-packet/v0",
            "build_id": build_id,
            "application": ENCAR_WATCHER_APPLICATION_ID,
            "original_owner_request": gap["original_message"],
            "gap": {
                "needed_ability": gap["needed_ability"],
                "desired_result": gap["desired_result"],
                "missing_information": [],
                "resources": [],
                "world_digest": gap["world_digest"],
            },
            "approved_specification": specification,
            "read_only_inputs": inputs,
            "input_policy": {
                "only_listed_campaign_inputs": True,
                "runtime_source": "excluded",
                "infrastructure_source": "excluded",
                "credentials": "excluded",
                "host_authority": "excluded",
                "publication_authority": "excluded",
            },
            "builder_handoff": {
                "repository": "one_empty_minimal_git_repository_allocated_after_approval",
                "authority": "one_temporary_repository_scoped_write_grant",
                "acceptance": "independent_after_grant_revocation_and_key_denial",
            },
        }
        encoded = canonical_json(packet) + b"\n"
        packet_digest = sha256(encoded)
        (directory / "BUILD-PACKET.json").write_bytes(encoded)
        (directory / "BUILD-PACKET.json").chmod(0o400)
        (directory / "BUILD-PACKET.md").write_text(
            "# Encar watcher application build packet\n\n"
            f"Application: `{ENCAR_WATCHER_APPLICATION_ID}`\n\n"
            f"Canonical JSON SHA-256: `{packet_digest}`\n\n"
            "The builder may read only the four copied campaign inputs listed in "
            "the canonical packet. Runtime and infrastructure source, credentials, "
            "host authority, and publication authority are excluded.\n",
            encoding="utf-8",
        )
        (directory / "BUILD-PACKET.md").chmod(0o400)
        now = utc_now()
        return self.chat.create_build_request({
            "id": build_id,
            "gap_id": gap_id,
            "conversation_id": gap["conversation_id"],
            "scope_id": scope_id,
            "original_owner_message_id": gap["owner_message_id"],
            "original_turn_id": gap["turn_id"],
            "original_world_digest": gap["world_digest"],
            "resources_json": canonical_json([]).decode(),
            "needed_ability": gap["needed_ability"],
            "desired_result": gap["desired_result"],
            "missing_information_json": canonical_json([]).decode(),
            "side_effect_ceiling": "private_stateful_scheduled_service",
            "packet_digest": packet_digest,
            "status": "APPROVED_WAITING_FOR_BUILDER",
            "created_at": now,
            "updated_at": now,
        })

    @staticmethod
    def _validate_supervised_specification(specification: dict[str, Any]) -> None:
        required = {
            "schema", "capability_id", "side_effect_ceiling", "resource_slot",
            "input_schema", "result_schema", "acceptance_profile",
            "candidate_repository", "devkit_commit", "devkit_wheel_sha256",
            "connections", "test_commands", "oracle_commands",
        }
        if (
            not isinstance(specification, dict)
            or set(specification) != required
            or specification.get("schema") != "capy.supervised-build-spec/v0"
            or specification.get("side_effect_ceiling") not in {
                "read_only", "artifact_generation"
            }
            or not isinstance(specification.get("capability_id"), str)
            or not specification["capability_id"]
            or not BuilderService._valid_supervised_resource_slot(
                specification.get("resource_slot")
            )
            or not isinstance(specification.get("input_schema"), dict)
            or not isinstance(specification.get("result_schema"), dict)
            or not isinstance(specification.get("connections"), list)
            or any(
                not isinstance(item, dict)
                or set(item) != {"name", "contract", "operations", "required"}
                or not isinstance(item["name"], str)
                or not isinstance(item["contract"], str)
                or not isinstance(item["operations"], list)
                or not all(isinstance(operation, str) for operation in item["operations"])
                or type(item["required"]) is not bool
                for item in specification.get("connections", [])
            )
            or len(specification.get("connections", [])) > 1
            or any(
                item != {
                    "name": "fedex_rates", "contract": "fedex.rates/v1",
                    "operations": ["quote"], "required": True,
                }
                for item in specification.get("connections", [])
            )
            or not isinstance(specification.get("acceptance_profile"), str)
            or not specification["acceptance_profile"]
            or not isinstance(specification.get("candidate_repository"), str)
            or not specification["candidate_repository"]
            or re.fullmatch(r"[0-9a-f]{40}", str(specification.get("devkit_commit"))) is None
            or re.fullmatch(r"[0-9a-f]{64}", str(specification.get("devkit_wheel_sha256"))) is None
            or not all(
                isinstance(items, list) and items
                and all(isinstance(command, str) and command for command in items)
                for items in (
                specification.get("test_commands"), specification.get("oracle_commands")
                )
            )
        ):
            raise RuntimeFailure("BUILD_SPECIFICATION_INVALID")

    @staticmethod
    def _valid_supervised_resource_slot(value: Any) -> bool:
        """Return whether the internal V0 profile describes its only bounded slot."""

        if value is None:
            return True
        return (
            isinstance(value, dict)
            and set(value) == {"name", "min_items", "max_items"}
            and isinstance(value["name"], str)
            and bool(value["name"])
            and type(value["min_items"]) is int
            and type(value["max_items"]) is int
            and 1 <= value["min_items"] <= value["max_items"] <= 2
        )

    def _approve_fedex(self, scope_id: str, gap: dict[str, Any]) -> dict[str, Any]:
        if len(gap["resources"]) != 1:
            raise RuntimeFailure("BUILD_APPROVAL_NOT_READY")
        connection_terms = ("fedex", "account", "credential", "connection", "origin", "shipper")
        if any(
            not any(term in item.lower() for term in connection_terms)
            for item in gap["missing_information"]
        ):
            raise RuntimeFailure("BUILD_APPROVAL_NOT_READY")
        original = gap["original_message"]
        date_match = re.search(r"\b(20\d{2}-\d{2}-\d{2})\b", original)
        required_facts = ("Austin", "78747", "TX", "US")
        if date_match is None or not all(item.lower() in original.lower() for item in required_facts):
            raise RuntimeFailure("BUILD_APPROVAL_NOT_READY")
        build_id = uuid.uuid4().hex
        directory = self._directory(build_id)
        fixtures = directory / "input" / "resources"
        fixtures.mkdir(parents=True)
        fixtures.chmod(0o700)
        digest = gap["resources"][0]
        source, filename = self.runtime.resource(scope_id, digest)
        payload = source.read_bytes()
        if sha256(payload) != digest:
            raise RuntimeFailure("RESOURCE_BYTES_INVALID")
        parse_package_csv(payload)
        target = fixtures / digest
        target.write_bytes(payload)
        target.chmod(0o400)
        metadata = self.runtime.resource_metadata(scope_id, digest)
        resource = {
            "handle": digest,
            "filename": filename,
            "size_bytes": metadata["size_bytes"],
            "sha256": digest,
            "fixture_path": str(target),
        }
        semantic_fixture = {
            "destination": {
                "country_code": "US", "postal_code": "78747", "city": "Austin",
                "state_or_province": "TX", "residential": False,
            },
            "ship_date": date_match.group(1),
            "include_list_rates": True,
            "return_transit_times": True,
        }
        result_schema = {
            "type": "object",
            "required": [
                "provider", "environment", "quoted_at", "ship_date", "origin_summary",
                "destination_summary", "package_count", "total_weight", "rates", "estimate_only",
            ],
            "additionalProperties": False,
            "properties": {
                "provider": {"type": "string"}, "environment": {"type": "string"},
                "quoted_at": {"type": "string"}, "ship_date": {"type": "string"},
                "provider_transaction_id": {"type": "string"},
                "origin_summary": {"type": "object"},
                "destination_summary": {"type": "object"},
                "package_count": {"type": "integer"}, "total_weight": {"type": "object"},
                "rates": {"type": "array", "items": {"type": "object"}},
                "estimate_only": {"type": "boolean"},
            },
        }
        connection_facts = self.connection_inventory(scope_id) if self.connection_inventory else [
            {"name": "fedex", "status": "unavailable", "default_origin_profile_available": False}
        ]
        packet = {
            "schema": "capy.build-packet/v0",
            "build_id": build_id,
            "original_outcome": original,
            "conversation_context": [{"role": "owner", "text": original}],
            "resources": [resource],
            "world_digest": gap["world_digest"],
            "installed_capabilities": self.runtime.list_bound_capabilities(
                scope_id, self.connection_status
            ),
            "connections": connection_facts,
            "gap": {
                "needed_ability": gap["needed_ability"],
                "desired_result": gap["desired_result"],
                "missing_information": [],
                "deferred_connection_prerequisites": gap["missing_information"],
            },
            "semantic_fixture": semantic_fixture,
            "required_capability": {
                "id": FEDEX_CAPABILITY_ID,
                "descriptor": {
                    "schema": "capy.script/v1", "entrypoint": "main.py",
                    "side_effect": "read_only", "visibility": "private",
                    "connections": [{
                        "name": "fedex_rates", "contract": "fedex.rates/v1",
                        "operations": ["quote"], "required": True,
                    }], "state_required": False,
                },
                "input_schema": {
                    "type": "object",
                    "required": ["destination", "ship_date", "include_list_rates", "return_transit_times"],
                    "additionalProperties": False,
                    "properties": {
                        "destination": {"type": "object"}, "ship_date": {"type": "string"},
                        "include_list_rates": {"type": "boolean"},
                        "return_transit_times": {"type": "boolean"},
                    },
                },
                "result_schema": result_schema,
                "side_effect_ceiling": "read_only_provider_quote",
                "connections": [{
                    "name": "fedex_rates", "contract": "fedex.rates/v1",
                    "operations": ["quote"], "required": True,
                }],
                "limits": {"resources": 1, "expanded_packages": 40, "input_bytes": 1024 * 1024},
            },
            "official_sources": [
                "https://developer.fedex.com/api/en-us/catalog/authorization/v1/docs.html",
                "https://developer.fedex.com/api/en-us/catalog/rate/v1/docs.html",
            ],
            "provider_free_fixture": {
                "schema": "capy.connection-result/v0",
                "contract": "fedex.rates/v1", "operation": "quote",
                "response_contract": "tests/fixtures/fedex/rate-multiple-services.json",
            },
            "runtime_abi": {
                "connection_environment": "CAPY_CONNECTION_MANIFEST",
                "connection_manifest_shape": {
                    "fedex_rates": "opaque invocation grant and local broker socket",
                },
                "provider_free_connection_schema": {
                    "required": ["schema", "status", "result", "receipt_id"],
                    "environment_result": "test",
                },
            },
            "trusted_normalized_result": {
                "ignored_by_comparison": [
                    "quoted_at", "provider_transaction_id", "origin_summary",
                ],
                "money_shape": {"amount": "JSON number", "currency": "string"},
                "rate_fields": [
                    "service_type", "service_name", "account_total", "list_total",
                    "delivery_date", "transit_days", "surcharges", "warnings",
                ],
                "warnings": "strings",
                "surcharges": "deduplicated {type, amount, currency} objects",
            },
            "scope_and_safety": {
                "scope": scope_id, "no_arbitrary_host_paths": True,
                "no_runtime_database": True, "no_credentials": True,
                "no_publication_authority": True, "no_other_scope_data": True,
                "network_required": False, "broker_required": True,
            },
            "independent_oracle": {
                "identity": "capy.runtime.fedex-quote/v1-secretless",
                "checks": [
                    "package_csv", "request_shape", "service_types", "account_totals",
                    "list_totals", "surcharges", "transit", "warnings", "estimate_only",
                ],
            },
            "negative_controls": [
                "invalid_csv", "zero_weight", "decimal_dimension", "duplicate_package_id",
                "oversized_package_count", "oauth_failure", "rate_authorization_failure",
                "invalid_destination", "malformed_provider_json", "provider_timeout", "provider_5xx",
                "unexpected_currency", "no_rates", "freight_rejected", "dangerous_goods_rejected",
            ],
            "repository": {
                "path": str(self.scripts_repository),
                "required_candidate_files": [
                    "capabilities/shipping/fedex_quote/capability.toml",
                    "capabilities/shipping/fedex_quote/main.py",
                    "tests/test_fedex_quote.py", "README.md",
                ],
                "test_commands": ["python3 -W error::ResourceWarning -m unittest discover -s tests -v"],
            },
            "publication_requirements": [
                "committed_candidate", "clean_tree", "trusted_acceptance",
                "immutable_publication", "scope_connection_binding_by_trusted_publisher",
            ],
            "non_goals": [
                "shipment creation", "label purchase", "pickup", "tracking", "FedEx Freight",
                "dangerous goods", "customs duties", "sharing", "updates",
            ],
        }
        encoded = canonical_json(packet) + b"\n"
        packet_digest = sha256(encoded)
        (directory / "BUILD-PACKET.json").write_bytes(encoded)
        (directory / "BUILD-PACKET.json").chmod(0o400)
        (directory / "BUILD-PACKET.md").write_text(
            self._packet_markdown(packet, packet_digest), encoding="utf-8"
        )
        (directory / "BUILD-PACKET.md").chmod(0o400)
        now = utc_now()
        return self.chat.create_build_request({
            "id": build_id, "gap_id": gap["id"], "conversation_id": gap["conversation_id"],
            "scope_id": scope_id, "original_owner_message_id": gap["owner_message_id"],
            "original_turn_id": gap["turn_id"], "original_world_digest": gap["world_digest"],
            "resources_json": canonical_json(gap["resources"]).decode(),
            "needed_ability": gap["needed_ability"], "desired_result": gap["desired_result"],
            "missing_information_json": canonical_json([]).decode(),
            "side_effect_ceiling": "read_only_provider_quote", "packet_digest": packet_digest,
            "status": "APPROVED_WAITING_FOR_BUILDER", "created_at": now, "updated_at": now,
        })

    @staticmethod
    def _packet_markdown(packet: dict[str, Any], digest: str) -> str:
        if packet["required_capability"]["id"] == FEDEX_CAPABILITY_ID:
            return BuilderService._fedex_packet_markdown(packet, digest)
        resource_lines = "\n".join(
            f"- `{item['filename']}` — SHA-256 `{item['sha256']}` — fixture `{item['fixture_path']}`"
            for item in packet["resources"]
        )
        exact_contract = json.dumps(
            packet["required_capability"], ensure_ascii=False, sort_keys=True, indent=2
        )
        required_files = "\n".join(
            f"- `{path}`" for path in packet["repository"]["required_candidate_files"]
        )
        return f"""# Capy build packet

Build: `{packet['build_id']}`
Canonical JSON SHA-256: `{digest}`

## Outcome

{packet['original_outcome']}

## Required capability

Implement `{ZIP_CAPABILITY_ID}` as ordinary committed source and focused tests.
It must accept only projected selected resources, create one ZIP artifact, and
return exact filenames and SHA-256 digests. It requires no network or credential.
Its `capy.script/v0` descriptor must use `side_effect = "read_only"`, private
visibility, `main.py`, no connections, and no persistent state. Accept 1–4
resources, cap their combined bytes at 16 MiB, cap the archive at 64 MiB, and
name the sole declared artifact `selected-files.zip`.

The descriptor contains exactly the standard `capy.script/v0` fields shown by
the existing CSV capability; do not add an `artifacts` descriptor field. The
process returns the exact semantic result fields `filename`, `file_count`,
`filenames`, and `digests`, plus the runtime-mechanical top-level `artifacts`
list containing only `selected-files.zip`. The runtime removes `artifacts`
before validating the semantic result schema. Sort ZIP members, `filenames`,
and `digests` by filename.

The exact canonical capability contract is:

```json
{exact_contract}
```

Required committed files:

{required_files}

The focused tests must live at `tests/test_zip_selected.py` and must pass:

```sh
python3 -W error::ResourceWarning -m unittest discover -s tests -v
```

## Fixtures

{resource_lines}

## Authority boundary

You may modify only the supplied `capy-scripts` worktree and build scratch.
You may not access runtime databases, active runtime stores, credentials,
other-scope data, or publication controls. A trusted acceptance boundary decides
whether the committed candidate is publishable.

## Independent acceptance

The trusted harness checks exact ZIP members and bytes, unsafe paths, symlinks,
extra members, resource corruption, duplicate filenames, zero inputs, total-size
bounds, undeclared outputs, focused tests, candidate cleanliness, and secrets.

## Non-goals

FedEx, sharing, updates, outbound Telegram, external side effects, containers,
microVMs, and runtime framework changes are excluded.
"""

    @staticmethod
    def _fedex_packet_markdown(packet: dict[str, Any], digest: str) -> str:
        resource = packet["resources"][0]
        contract = json.dumps(packet["required_capability"], sort_keys=True, indent=2)
        semantic = json.dumps(packet["semantic_fixture"], sort_keys=True, indent=2)
        return f"""# Capy build packet

Build: `{packet['build_id']}`

Canonical JSON SHA-256: `{digest}`

## Outcome

{packet['original_outcome']}

## Required capability

Implement `{FEDEX_CAPABILITY_ID}` as an ordinary secretless `capy.script/v1` capability and
focused tests. Follow the repository `AGENTS.md`, connection contract, `capy_script` client,
mock server, and test/run commands. The capability accepts exactly one projected package CSV,
one semantic destination/ship-date input, and one invocation-scoped `fedex_rates` handle for
`fedex.rates/v1:quote`. It validates input, calls that opaque operation once, and returns only
normalized quote facts. It never implements OAuth, provider HTTP, account/origin injection,
or credential handling.

It is quote-only. It must not create a shipment, buy or generate a label, schedule a pickup,
track a shipment, call FedEx Freight/LTL, accept dangerous goods, or calculate customs duties.
Reject unsupported declarations locally before a provider call. Rates are estimates and the
result must set `estimate_only` to true. Never invent account/list rates, currencies,
surcharges, warnings, transit facts, or delivery dates.

Use only `from capy_script import connection` and
`connection.call("fedex_rates", operation="quote", payload=...)`. Treat the connection manifest
as an opaque SDK detail. Do not open it directly, interpret socket paths or grant tokens, contact
FedEx, accept a base URL, or read any credential/profile source. Provider-free tests use the
repository mock connection server and normalized contract fixtures, never credential-shaped
fixtures.

The trusted oracle requires material results with numeric `{{amount, currency}}` account/list
totals, string warnings, deduplicated `{{type, amount, currency}}` surcharges, and top-level
delivery/transit facts per rate. It ignores only `quoted_at`, `provider_transaction_id`, and
`origin_summary`. Build `returnTransitTimes` under `rateRequestControlParameters`, use
`USE_SCHEDULED_PICKUP` and `YOUR_PACKAGING`, and preserve each CSV row using its
`groupPackageCount` quantity.

Exact capability contract:

```json
{contract}
```

Frozen semantic acceptance input:

```json
{semantic}
```

Package fixture: `{resource['filename']}` — SHA-256 `{resource['sha256']}` —
`{resource['fixture_path']}`.

Required committed files are listed in `BUILD-PACKET.json`. Run the complete unittest suite,
commit the candidate, and leave the tree clean.

## Authority boundary

Work only in the supplied `capy-scripts` worktree and build scratch. You receive no FedEx
credential, runtime/chat database, other-scope data, publication authority, or prior builder
conversation. The trusted harness owns provider-free/live acceptance and publication.
"""

    def packet_paths(self, build_id: str) -> tuple[Path, Path]:
        directory = self._directory(build_id)
        return directory / "BUILD-PACKET.json", directory / "BUILD-PACKET.md"

    def claim(self, build_id: str, builder_id: str, lease_seconds: int = 1800) -> dict[str, Any]:
        if not re.fullmatch(r"[A-Za-z0-9._-]{1,128}", builder_id) or not 30 <= lease_seconds <= 7200:
            raise RuntimeFailure("BUILDER_CLAIM_INVALID")
        self.chat.recover_expired_build_leases()
        lease_id = uuid.uuid4().hex
        expires = (
            datetime.now(timezone.utc) + timedelta(seconds=lease_seconds)
        ).isoformat(timespec="milliseconds").replace("+00:00", "Z")
        return self.chat.transition_build(
            build_id,
            {"APPROVED_WAITING_FOR_BUILDER"},
            "BUILDING",
            builder_id=builder_id,
            lease_id=lease_id,
            lease_expires_at=expires,
            builder_session_id=uuid.uuid4().hex,
        )

    def cancel(self, scope_id: str, build_id: str) -> dict[str, Any]:
        self.chat.build(build_id, scope_id)
        return self.chat.transition_build(
            build_id,
            {"APPROVED_WAITING_FOR_BUILDER", "BUILDING", "CANDIDATE_SUBMITTED"},
            "CANCELLED",
        )

    def prepare_worktree(self, build_id: str) -> Path:
        self.chat.recover_expired_build_leases()
        build = self.chat.build(build_id)
        if build["status"] != "BUILDING" or not build["lease_id"]:
            raise RuntimeFailure("BUILDER_LEASE_REQUIRED")
        if _git(["status", "--porcelain"], self.scripts_repository):
            raise RuntimeFailure("BUILDER_BASE_DIRTY")
        directory = self._directory(build_id)
        worktree = directory / "worktree"
        if worktree.exists():
            return worktree
        branch = f"codex/build-{build_id}"
        completed = _run(
            ["git", "clone", "--no-hardlinks", str(self.scripts_repository), str(worktree)],
            self.scripts_repository,
        )
        if completed.returncode != 0:
            raise RuntimeFailure("BUILDER_WORKTREE_FAILED")
        completed = _run(["git", "checkout", "-b", branch], worktree)
        if completed.returncode != 0:
            raise RuntimeFailure("BUILDER_WORKTREE_FAILED")
        return worktree

    def run_codex(self, build_id: str, command: Sequence[str]) -> subprocess.CompletedProcess[bytes]:
        if (
            not command
            or Path(command[0]).name != "codex"
            or "exec" not in command[1:]
            or "--ephemeral" not in command[1:]
        ):
            raise RuntimeFailure("BUILDER_COMMAND_INVALID")
        if (
            self.builder_uid is None
            or self.builder_gid is None
            or self.builder_uid == os.geteuid()
            or os.geteuid() != 0
        ):
            raise RuntimeFailure("BUILDER_ISOLATION_UNAVAILABLE")
        worktree = self.prepare_worktree(build_id)
        _, markdown = self.packet_paths(build_id)
        build_directory = self._directory(build_id)
        for root, directories, files in os.walk(build_directory, followlinks=False):
            root_path = Path(root)
            if root_path.is_symlink():
                raise RuntimeFailure("BUILDER_SCRATCH_INVALID")
            os.chown(root_path, self.builder_uid, self.builder_gid)
            for name in [*directories, *files]:
                child = root_path / name
                if child.is_symlink():
                    raise RuntimeFailure("BUILDER_SCRATCH_INVALID")
                os.chown(child, self.builder_uid, self.builder_gid)
        self.scratch_root.chmod(0o711)
        prompt = (
            f"Implement the complete build packet at {markdown}. Work only in this worktree, "
            "run focused tests, commit the candidate, and stop. Do not publish it."
        )
        safe_environment = {
            "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
            "LANG": "C.UTF-8",
            "LC_ALL": "C.UTF-8",
            "HOME": pwd.getpwuid(self.builder_uid).pw_dir,
            "TMPDIR": str(build_directory),
        }

        def drop_builder_privileges() -> None:
            os.setgroups([])
            os.setgid(self.builder_gid)
            os.setuid(self.builder_uid)

        completed = _run(
            [*command, prompt], worktree, timeout=3600,
            environment=safe_environment, preexec_fn=drop_builder_privileges,
        )
        if completed.returncode != 0:
            self.chat.transition_build(
                build_id, {"BUILDING"}, "BLOCKED", terminal_error="CODEX_PROCESS_FAILED"
            )
        return completed

    def submit(self, build_id: str, candidate_worktree: Path) -> dict[str, Any]:
        self.chat.recover_expired_build_leases()
        build = self.chat.build(build_id)
        if build["status"] != "BUILDING" or not build["lease_id"]:
            raise RuntimeFailure("BUILDER_LEASE_REQUIRED")
        try:
            worktree = candidate_worktree.resolve()
            if self._directory(build_id) not in worktree.parents:
                raise RuntimeFailure("BUILDER_WORKTREE_NOT_OWNED")
            if _git(["status", "--porcelain"], worktree):
                raise RuntimeFailure("CANDIDATE_WORKTREE_DIRTY")
            commit = _git(["rev-parse", "HEAD"], worktree)
            repository_tree = _git(["rev-parse", "HEAD^{tree}"], worktree)
            archive = _run(["git", "archive", "--format=tar", "HEAD"], worktree)
            if archive.returncode != 0:
                raise RuntimeFailure("CANDIDATE_ARCHIVE_FAILED")
            capability_id = self._packet_value(build_id)["required_capability"]["id"]
            candidate = self._candidate_path(worktree, capability_id)
            descriptor = CapabilityDescriptor.from_toml(candidate / "capability.toml")
            if descriptor.id != capability_id:
                raise RuntimeFailure("CANDIDATE_CAPABILITY_ID_INVALID")
        except Exception as exc:
            code = exc.code if isinstance(exc, RuntimeFailure) else "CANDIDATE_SUBMISSION_FAILED"
            self.chat.transition_build(
                build_id, {"BUILDING"}, "CANDIDATE_REJECTED", terminal_error=code
            )
            raise
        return self.chat.transition_build(
            build_id,
            {"BUILDING"},
            "CANDIDATE_SUBMITTED",
            candidate_repository=str(self.scripts_repository),
            candidate_commit=commit,
            candidate_tree=repository_tree,
            candidate_archive_digest=sha256(archive.stdout),
            candidate_capability_id=descriptor.id,
            candidate_version_digest=tree_digest(candidate),
        )

    def submit_devkit_candidate(
        self,
        build_id: str,
        *,
        candidate_repository: str,
        candidate_commit: str,
        candidate_tree: str,
        application_archive: Path,
    ) -> dict[str, Any]:
        """Record one exact generic DevKit candidate collected from Minimal Git."""

        self.chat.recover_expired_build_leases()
        build = self.chat.build(build_id)
        if build["status"] != "BUILDING" or not build["lease_id"]:
            raise RuntimeFailure("BUILDER_LEASE_REQUIRED")
        packet = self._packet_value(build_id)
        specification = packet.get("specification")
        if (
            packet.get("schema") != "capy.supervised-build-packet/v0"
            or not isinstance(specification, dict)
        ):
            raise RuntimeFailure("BUILD_PACKET_INVALID")
        self._validate_supervised_specification(specification)
        if candidate_repository != specification["candidate_repository"]:
            raise RuntimeFailure("BUILD_CANDIDATE_REPOSITORY_MISMATCH")
        if (
            re.fullmatch(r"[0-9a-f]{40}", candidate_commit) is None
            or re.fullmatch(r"[0-9a-f]{40}", candidate_tree) is None
        ):
            raise RuntimeFailure("CANDIDATE_SUBMISSION_FAILED")
        try:
            archive_bytes = application_archive.read_bytes()
            with tempfile.TemporaryDirectory(prefix="capy-generic-candidate-") as temporary:
                candidate = Path(temporary) / "application"
                candidate.mkdir()
                self.runtime._extract_zip(application_archive, candidate)
                descriptor = CapabilityDescriptor.from_toml(candidate / "capability.toml")
                version = tree_digest(candidate)
        except RuntimeFailure:
            raise
        except (OSError, ValueError) as exc:
            raise RuntimeFailure("CANDIDATE_SUBMISSION_FAILED") from exc
        if descriptor.id != specification["capability_id"]:
            raise RuntimeFailure("CANDIDATE_CAPABILITY_ID_INVALID")
        return self.chat.transition_build(
            build_id,
            {"BUILDING"},
            "CANDIDATE_SUBMITTED",
            candidate_repository=candidate_repository,
            candidate_commit=candidate_commit,
            candidate_tree=candidate_tree,
            candidate_archive_digest=sha256(archive_bytes),
            candidate_capability_id=descriptor.id,
            candidate_version_digest=version,
        )

    def record_devkit_acceptance(self, build_id: str, receipt: bytes) -> dict[str, Any]:
        """Persist independent acceptance bytes before immutable publication."""

        build = self.chat.build(build_id)
        if build["status"] != "CANDIDATE_SUBMITTED":
            raise RuntimeFailure("BUILD_STATE_CONFLICT")
        try:
            value = json.loads(receipt)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise RuntimeFailure("CAPABILITY_ACCEPTANCE_RECEIPT_INVALID") from exc
        if (
            value.get("schema") != "capy.application-acceptance/v1"
            or value.get("candidate_repository") != build["candidate_repository"]
            or value.get("candidate_commit") != build["candidate_commit"]
            or value.get("candidate_tree") != build["candidate_tree"]
            or value.get("application_id") != build["candidate_capability_id"]
            or value.get("application_archive_sha256") != build["candidate_archive_digest"]
        ):
            raise RuntimeFailure("CAPABILITY_ACCEPTANCE_RECEIPT_INVALID")
        target = self._directory(build_id) / "acceptance-receipt.json"
        target.write_bytes(receipt)
        target.chmod(0o400)
        return self.chat.transition_build(
            build_id,
            {"CANDIDATE_SUBMITTED"},
            "ACCEPTING",
            acceptance_digest=sha256(receipt),
        )

    def accept(self, build_id: str) -> dict[str, Any]:
        build = self.chat.transition_build(
            build_id, {"CANDIDATE_SUBMITTED"}, "ACCEPTING"
        )
        try:
            receipt = self._accept(build)
        except Exception as exc:
            code = exc.code if isinstance(exc, RuntimeFailure) else "CANDIDATE_ACCEPTANCE_FAILED"
            self.chat.transition_build(
                build_id, {"ACCEPTING"}, "CANDIDATE_REJECTED", terminal_error=code
            )
            raise
        encoded = canonical_json(receipt) + b"\n"
        digest = sha256(encoded)
        path = self._directory(build_id) / "acceptance-receipt.json"
        path.write_bytes(encoded)
        path.chmod(0o400)
        return self.chat.transition_build(
            build_id, {"ACCEPTING"}, "ACCEPTING", acceptance_digest=digest
        )

    def _accept(self, build: dict[str, Any]) -> dict[str, Any]:
        if self._packet_value(build["id"])["required_capability"]["id"] == FEDEX_CAPABILITY_ID:
            return self._accept_fedex(build)
        worktree = self._directory(build["id"]) / "worktree"
        if _git(["status", "--porcelain"], worktree):
            raise RuntimeFailure("CANDIDATE_WORKTREE_DIRTY")
        if _git(["rev-parse", "HEAD"], worktree) != build["candidate_commit"]:
            raise RuntimeFailure("CANDIDATE_COMMIT_CHANGED")
        if _git(["rev-parse", "HEAD^{tree}"], worktree) != build["candidate_tree"]:
            raise RuntimeFailure("CANDIDATE_TREE_CHANGED")
        candidate = worktree / "capabilities" / "files" / "zip_selected"
        if not (worktree / "tests" / "test_zip_selected.py").is_file():
            raise RuntimeFailure("CANDIDATE_TESTS_MISSING")
        if tree_digest(candidate) != build["candidate_version_digest"]:
            raise RuntimeFailure("CANDIDATE_TREE_CHANGED")
        descriptor = CapabilityDescriptor.from_toml(candidate / "capability.toml")
        if (
            descriptor.id != ZIP_CAPABILITY_ID
            or descriptor.side_effect != "read_only"
            or descriptor.connections
            or descriptor.state_required
        ):
            raise RuntimeFailure("CANDIDATE_DESCRIPTOR_MISMATCH")
        tests = _run(
            ["python3", "-W", "error::ResourceWarning", "-m", "unittest", "discover", "-s", "tests", "-v"],
            worktree,
        )
        if tests.returncode != 0:
            raise RuntimeFailure("CANDIDATE_TESTS_FAILED")
        scanned = 0
        for path in sorted(worktree.rglob("*")):
            if not path.is_file() or ".git" in path.parts:
                continue
            payload = path.read_bytes()
            scanned += len(payload)
            if any(pattern.search(payload) for pattern in SECRET_PATTERNS):
                raise RuntimeFailure("CANDIDATE_SECRET_SCAN_FAILED")
        fixtures = self._packet_resources(build["id"])
        with tempfile.TemporaryDirectory(prefix="capy-accept-") as temporary:
            isolated = RuntimeStore(Path(temporary) / "runtime")
            isolated.register_scope("acceptance")
            accepted_seed = canonical_json({"schema": "capy.acceptance-seed/v0", "build_id": build["id"]})
            accepted_descriptor, version = isolated.publish(candidate, accepted_seed)
            isolated.bind("acceptance", accepted_descriptor.id, version, {})
            selected = []
            expected = []
            for item in fixtures:
                payload = Path(item["fixture_path"]).read_bytes()
                selected.append(isolated.add_resource("acceptance", item["filename"], payload))
                expected.append((item["filename"], payload))
            completed = OutcomeRuntime(isolated).invoke(
                "acceptance", ZIP_CAPABILITY_ID, {}, resource_digests=selected,
                expected_version_digest=version,
            )
            if len(completed.artifacts) != 1:
                raise RuntimeFailure("ZIP_ORACLE_ARTIFACT_INVALID")
            artifact_path, _ = isolated.resource("acceptance", completed.artifacts[0]["digest"])
            oracle = verify_zip_bytes(artifact_path.read_bytes(), expected)
            expected_result = {
                "filename": "selected-files.zip",
                "file_count": oracle["file_count"],
                "filenames": oracle["filenames"],
                "digests": oracle["digests"],
            }
            if completed.result != expected_result:
                raise RuntimeFailure("CANDIDATE_RESULT_MISMATCH")
            negative = self._negative_controls(isolated, version, candidate, expected)
        return {
            "schema": "capy.candidate-acceptance/v0",
            "build_id": build["id"],
            "gap_id": build["gap_id"],
            "candidate_source_repository": build["candidate_repository"],
            "candidate_commit": build["candidate_commit"],
            "candidate_tree": build["candidate_tree"],
            "candidate_archive_digest": build["candidate_archive_digest"],
            "capability_id": descriptor.id,
            "candidate_version_digest": build["candidate_version_digest"],
            "descriptor_digest": sha256((candidate / "capability.toml").read_bytes()),
            "test_commands": [{
                "command": "python3 -W error::ResourceWarning -m unittest discover -s tests -v",
                "exit_code": tests.returncode,
            }],
            "independent_oracle": {"identity": "capy.runtime.zip-selected/v0", "result": oracle},
            "negative_controls": negative,
            "secret_scan": {"status": "passed", "bytes_scanned": scanned},
            "side_effect_class": descriptor.side_effect,
            "accepted_fixtures": [
                {key: item[key] for key in ("filename", "size_bytes", "sha256")}
                for item in fixtures
            ],
            "created_at": utc_now(),
        }

    def _packet_resources(self, build_id: str) -> list[dict[str, Any]]:
        return self._packet_value(build_id)["resources"]

    def _packet_value(self, build_id: str) -> dict[str, Any]:
        packet, _ = self.packet_paths(build_id)
        payload = packet.read_bytes()
        build = self.chat.build(build_id)
        if sha256(payload) != build["packet_digest"]:
            raise RuntimeFailure("BUILD_PACKET_TAMPERED")
        return json.loads(payload)

    @staticmethod
    def _candidate_path(worktree: Path, capability_id: str) -> Path:
        if capability_id == ZIP_CAPABILITY_ID:
            return worktree / "capabilities" / "files" / "zip_selected"
        if capability_id == FEDEX_CAPABILITY_ID:
            return worktree / "capabilities" / "shipping" / "fedex_quote"
        raise RuntimeFailure("CANDIDATE_CAPABILITY_ID_INVALID")

    def _accept_fedex(self, build: dict[str, Any]) -> dict[str, Any]:
        worktree = self._directory(build["id"]) / "worktree"
        if _git(["status", "--porcelain"], worktree):
            raise RuntimeFailure("CANDIDATE_WORKTREE_DIRTY")
        if _git(["rev-parse", "HEAD"], worktree) != build["candidate_commit"]:
            raise RuntimeFailure("CANDIDATE_COMMIT_CHANGED")
        if _git(["rev-parse", "HEAD^{tree}"], worktree) != build["candidate_tree"]:
            raise RuntimeFailure("CANDIDATE_TREE_CHANGED")
        candidate = self._candidate_path(worktree, FEDEX_CAPABILITY_ID)
        if not (worktree / "tests" / "test_fedex_quote.py").is_file():
            raise RuntimeFailure("CANDIDATE_TESTS_MISSING")
        if tree_digest(candidate) != build["candidate_version_digest"]:
            raise RuntimeFailure("CANDIDATE_TREE_CHANGED")
        descriptor = CapabilityDescriptor.from_toml(candidate / "capability.toml")
        if (
            descriptor.id != FEDEX_CAPABILITY_ID
            or descriptor.schema != "capy.script/v1"
            or descriptor.side_effect != "read_only"
            or descriptor.connections != ("fedex_rates",)
            or len(descriptor.connection_requirements) != 1
            or descriptor.connection_requirements[0].contract != "fedex.rates/v1"
            or descriptor.connection_requirements[0].operations != ("quote",)
            or not descriptor.connection_requirements[0].required
            or descriptor.state_required
        ):
            raise RuntimeFailure("CANDIDATE_DESCRIPTOR_MISMATCH")
        tests = _run(
            ["python3", "-W", "error::ResourceWarning", "-m", "unittest", "discover", "-s", "tests", "-v"],
            worktree,
        )
        if tests.returncode != 0:
            raise RuntimeFailure("CANDIDATE_TESTS_FAILED")
        scanned = 0
        for path in sorted(worktree.rglob("*")):
            if not path.is_file() or ".git" in path.parts:
                continue
            payload = path.read_bytes()
            scanned += len(payload)
            if any(pattern.search(payload) for pattern in SECRET_PATTERNS):
                raise RuntimeFailure("CANDIDATE_SECRET_SCAN_FAILED")
        packet = self._packet_value(build["id"])
        resource = packet["resources"][0]
        package_payload = Path(resource["fixture_path"]).read_bytes()
        packages = parse_package_csv(package_payload)
        fixture_path = Path(__file__).resolve().parents[2] / "tests/fixtures/fedex/rate-multiple-services.json"
        provider_fixture = json.loads(fixture_path.read_text(encoding="utf-8"))
        semantic = packet["semantic_fixture"]
        oracle = normalize_rate_response(
            provider_fixture, environment="test", semantic_input=semantic, packages=packages
        )
        broker_result = {
            "environment": "test",
            "quoted_at": "2026-08-28T00:00:00Z",
            "origin_summary": {"country_code": "KR", "postal_code": "00000"},
            "destination_summary": oracle["destination_summary"],
            "provider_transaction_id": oracle.get("provider_transaction_id", "fixture-transaction"),
            "rates": oracle["rates"],
        }

        class FixtureResolver:
            def resolve(self, _reference: str) -> dict[str, str]:
                return {"client_secret": "acceptance-canary-never-output"}

        class FixtureAdapter:
            def __init__(self) -> None:
                self.calls: list[dict[str, Any]] = []

            def call(self, **values: Any) -> dict[str, Any]:
                self.calls.append(values)
                return broker_result

        with tempfile.TemporaryDirectory(prefix="capy-fedex-accept-") as temporary:
            temporary_path = Path(temporary)
            isolated = RuntimeStore(temporary_path / "runtime")
            isolated.register_scope("acceptance")
            seed = canonical_json({"schema": "capy.acceptance-seed/v0", "build_id": build["id"]})
            accepted_descriptor, version = isolated.publish(candidate, seed)
            control = ConnectionControl(isolated)
            control.put_instance(ConnectionInstance(
                "acceptance-fedex-rates", "fedex.rates/v1", "acceptance-fedex-adapter/v1",
                "publisher", "trusted-acceptance", "active", {"label": "Provider-free FedEx rates"},
                "secret:acceptance-fedex", "profile:acceptance-origin",
            ))
            control.grant(
                "acceptance-fedex-quote", "acceptance-fedex-rates", "acceptance",
                "fedex.rates/v1", ["quote"], capability_id=accepted_descriptor.id,
                version_digest=version,
            )
            isolated.bind(
                "acceptance", accepted_descriptor.id, version,
                {"fedex_rates": "acceptance-fedex-quote"},
            )
            adapter = FixtureAdapter()
            broker = ConnectionBroker(
                control, FixtureResolver(), {"profile:acceptance-origin": {}},
                {"acceptance-fedex-adapter/v1": adapter},
            )
            socket_path = temporary_path / "connection-broker.sock"
            stop = threading.Event()
            broker_thread = threading.Thread(
                target=broker.serve, args=(socket_path, stop), daemon=True
            )
            broker_thread.start()
            for _ in range(100):
                if socket_path.exists():
                    break
                threading.Event().wait(0.01)
            runtime = OutcomeRuntime(
                isolated, connection_control=control, broker_socket=socket_path,
                script_sdk_root=worktree,
            )
            digest = isolated.add_resource("acceptance", resource["filename"], package_payload)
            try:
                completed = runtime.invoke(
                    "acceptance", FEDEX_CAPABILITY_ID, semantic,
                    resource_digests=[digest], expected_version_digest=version,
                )
                comparison = compare_quote_results(completed.result, oracle)
                if len(adapter.calls) != 1 or len(completed.receipt["connection_receipts"]) != 1:
                    raise RuntimeFailure("FEDEX_BROKER_CALL_BUDGET_INVALID")
                invalid_payloads = {
                    "zero_weight": package_payload.replace(b"box-a,10,", b"box-a,0,"),
                    "decimal_dimension": package_payload.replace(b",40,30,25,", b",40.5,30,25,"),
                    "duplicate_package_id": package_payload.replace(b"box-b,5.5", b"box-a,5.5"),
                    "oversized_package_count": package_payload.replace(
                        b"box-a,10,40,30,25,2", b"box-a,10,40,30,25,41"
                    ),
                }
                negative = {}
                before_calls = len(adapter.calls)
                for name, payload in invalid_payloads.items():
                    bad_digest = isolated.add_resource("acceptance", f"{name}.csv", payload)
                    try:
                        runtime.invoke(
                            "acceptance", FEDEX_CAPABILITY_ID, semantic,
                            resource_digests=[bad_digest], expected_version_digest=version,
                        )
                    except RuntimeFailure:
                        negative[name] = True
                    else:
                        raise RuntimeFailure("FEDEX_NEGATIVE_CONTROL_FAILED", name)
                if len(adapter.calls) != before_calls:
                    raise RuntimeFailure("FEDEX_INVALID_INPUT_CALLED_BROKER")
                for name, unsupported in (
                    ("freight_rejected", {**semantic, "freight": True}),
                    ("dangerous_goods_rejected", {**semantic, "dangerous_goods": True}),
                ):
                    try:
                        runtime.invoke(
                            "acceptance", FEDEX_CAPABILITY_ID, unsupported,
                            resource_digests=[digest], expected_version_digest=version,
                        )
                    except RuntimeFailure:
                        negative[name] = True
                    else:
                        raise RuntimeFailure("FEDEX_NEGATIVE_CONTROL_FAILED", name)
            finally:
                stop.set()
                broker_thread.join(2)
        return {
            "schema": "capy.candidate-acceptance/v0",
            "build_id": build["id"], "gap_id": build["gap_id"],
            "candidate_source_repository": build["candidate_repository"],
            "candidate_commit": build["candidate_commit"], "candidate_tree": build["candidate_tree"],
            "candidate_archive_digest": build["candidate_archive_digest"],
            "capability_id": descriptor.id, "candidate_version_digest": build["candidate_version_digest"],
            "descriptor_digest": sha256((candidate / "capability.toml").read_bytes()),
            "test_commands": [{
                "command": "python3 -W error::ResourceWarning -m unittest discover -s tests -v",
                "exit_code": tests.returncode,
            }],
            "independent_oracle": {
                "identity": "capy.runtime.fedex-quote/v1-secretless", "comparison": comparison,
                "broker_calls": 1, "connection_receipts": 1,
            },
            "negative_controls": negative,
            "secret_scan": {"status": "passed", "bytes_scanned": scanned},
            "side_effect_class": descriptor.side_effect,
            "accepted_fixtures": [{
                key: resource[key] for key in ("filename", "size_bytes", "sha256")
            }],
            "created_at": utc_now(),
        }

    def _negative_controls(
        self,
        isolated: RuntimeStore,
        version: str,
        candidate: Path,
        expected: list[tuple[str, bytes]],
    ) -> dict[str, bool]:
        checks: dict[str, bool] = {}
        try:
            OutcomeRuntime(isolated).invoke(
                "acceptance", ZIP_CAPABILITY_ID, {}, resource_digests=[],
                expected_version_digest=version,
            )
        except RuntimeFailure:
            checks["zero_selected_files"] = True
        else:
            raise RuntimeFailure("NEGATIVE_ZERO_FILES_FAILED")
        first_name = expected[0][0]
        duplicate_a = isolated.add_resource("acceptance", first_name, b"duplicate-a")
        duplicate_b = isolated.add_resource("acceptance", first_name, b"duplicate-b")
        try:
            OutcomeRuntime(isolated).invoke(
                "acceptance", ZIP_CAPABILITY_ID, {},
                resource_digests=[duplicate_a, duplicate_b], expected_version_digest=version,
            )
        except RuntimeFailure:
            checks["duplicate_filename_conflict"] = True
        else:
            raise RuntimeFailure("NEGATIVE_DUPLICATE_FILENAME_FAILED")
        try:
            isolated.add_resource("acceptance", "../unsafe", b"unsafe")
        except RuntimeFailure:
            checks["unsafe_filename"] = True
        else:
            raise RuntimeFailure("NEGATIVE_UNSAFE_FILENAME_FAILED")
        oversized_a = isolated.add_resource("acceptance", "large-a.bin", b"a" * (8 * 1024 * 1024 + 1))
        oversized_b = isolated.add_resource("acceptance", "large-b.bin", b"b" * (8 * 1024 * 1024 + 1))
        try:
            OutcomeRuntime(isolated).invoke(
                "acceptance", ZIP_CAPABILITY_ID, {},
                resource_digests=[oversized_a, oversized_b], expected_version_digest=version,
            )
        except RuntimeFailure:
            checks["oversized_total_input"] = True
        else:
            raise RuntimeFailure("NEGATIVE_OVERSIZED_INPUT_FAILED")
        corrupt = isolated.add_resource("acceptance", "corrupt.bin", b"original")
        corrupt_path, _ = isolated.resource("acceptance", corrupt)
        corrupt_path.chmod(0o600)
        corrupt_path.write_bytes(b"changed")
        try:
            OutcomeRuntime(isolated).invoke(
                "acceptance", ZIP_CAPABILITY_ID, {}, resource_digests=[corrupt],
                expected_version_digest=version,
            )
        except RuntimeFailure as exc:
            checks["corrupt_or_missing_resource"] = exc.code == "RESOURCE_BYTES_INVALID"
        else:
            raise RuntimeFailure("NEGATIVE_CORRUPT_RESOURCE_FAILED")
        good = io.BytesIO()
        with zipfile.ZipFile(good, "w") as archive:
            archive.writestr("../escape", b"x")
        try:
            verify_zip_bytes(good.getvalue(), expected)
        except RuntimeFailure:
            checks["path_traversal_member"] = True
        else:
            raise RuntimeFailure("NEGATIVE_TRAVERSAL_MEMBER_FAILED")
        extra = io.BytesIO()
        with zipfile.ZipFile(extra, "w") as archive:
            for name, payload in expected:
                archive.writestr(name, payload)
            archive.writestr("extra", b"extra")
        try:
            verify_zip_bytes(extra.getvalue(), expected)
        except RuntimeFailure:
            checks["extra_member"] = True
        else:
            raise RuntimeFailure("NEGATIVE_EXTRA_MEMBER_FAILED")
        with tempfile.TemporaryDirectory(prefix="capy-undeclared-") as temporary:
            malicious = Path(temporary) / "candidate"
            shutil.copytree(candidate, malicious)
            entrypoint = malicious / "main.py"
            entrypoint.chmod(0o600)
            entrypoint.write_text(
                entrypoint.read_text(encoding="utf-8")
                + '\nPath(os.environ["CAPY_OUTPUT_DIR"], "undeclared.txt").write_text("x")\n',
                encoding="utf-8",
            )
            _, malicious_version = isolated.publish(malicious, b"undeclared-output-negative")
            isolated.bind("acceptance", ZIP_CAPABILITY_ID, malicious_version, {})
            selected = [
                isolated.add_resource("acceptance", name, payload)
                for name, payload in expected
            ]
            try:
                OutcomeRuntime(isolated).invoke(
                    "acceptance", ZIP_CAPABILITY_ID, {}, resource_digests=selected,
                    expected_version_digest=malicious_version,
                )
            except RuntimeFailure as exc:
                checks["undeclared_output"] = exc.code == "INVOCATION_UNDECLARED_OUTPUT"
            else:
                raise RuntimeFailure("NEGATIVE_UNDECLARED_OUTPUT_FAILED")
            finally:
                isolated.bind("acceptance", ZIP_CAPABILITY_ID, version, {})
        return checks

    def publish(self, build_id: str) -> dict[str, Any]:
        build = self.chat.build(build_id)
        if build["status"] != "ACCEPTING" or not build["acceptance_digest"]:
            raise RuntimeFailure("CANDIDATE_NOT_ACCEPTED")
        receipt_path = self._directory(build_id) / "acceptance-receipt.json"
        receipt_bytes = receipt_path.read_bytes()
        if sha256(receipt_bytes) != build["acceptance_digest"]:
            raise RuntimeFailure("ACCEPTANCE_RECEIPT_TAMPERED")
        capability_id = self._packet_value(build_id)["required_capability"]["id"]
        candidate = self._candidate_path(self._directory(build_id) / "worktree", capability_id)
        if tree_digest(candidate) != build["candidate_version_digest"]:
            raise RuntimeFailure("CANDIDATE_TREE_CHANGED")
        previous = self.runtime.binding_or_none(build["scope_id"], capability_id)
        before = self._world().build(
            build["scope_id"], self.chat.visible_resources(build["scope_id"], build["conversation_id"])
        )
        descriptor, version = self.runtime.publish(candidate, receipt_bytes)
        if version != build["candidate_version_digest"]:
            raise RuntimeFailure("PUBLISHED_VERSION_MISMATCH")
        connections = (
            {"fedex_rates": f"{build['scope_id']}-cosmain-fedex-quote"}
            if capability_id == FEDEX_CAPABILITY_ID else {}
        )
        new_binding = {
            "scope_id": build["scope_id"],
            "capability_id": descriptor.id,
            "version_digest": version,
            "connections": connections,
        }
        after = self._world().build_with_binding(
            build["scope_id"],
            self.chat.visible_resources(build["scope_id"], build["conversation_id"]),
            descriptor.id,
            version,
            connections,
        )
        publication = {
            "schema": "capy.publication-receipt/v0",
            "build_id": build_id,
            "capability_id": descriptor.id,
            "new_version": version,
            "acceptance_digest": build["acceptance_digest"],
            "scope_id": build["scope_id"],
            "previous_binding": _binding_value(previous),
            "new_binding": new_binding,
            "world_digest_before": before.digest,
            "world_digest_after": after.digest,
            "publisher_identity": self.publisher_identity,
            "created_at": utc_now(),
        }
        self.runtime.bind_with_publication_receipt(
            build_id, build["scope_id"], descriptor.id, version, connections, publication, previous
        )
        return self.reconcile_publication(build_id)

    def publish_devkit(
        self,
        build_id: str,
        application_archive: Path,
        devkit_wheel: Path,
        expected_identity: dict[str, str],
        connection_bindings: dict[str, str] | None = None,
    ) -> dict[str, Any]:
        """Publish a supervisor-accepted DevKit archive without mutable source input."""

        build = self.chat.build(build_id)
        if build["status"] != "ACCEPTING" or not build["acceptance_digest"]:
            raise RuntimeFailure("CANDIDATE_NOT_ACCEPTED")
        receipt_path = self._directory(build_id) / "acceptance-receipt.json"
        receipt_bytes = receipt_path.read_bytes()
        if sha256(receipt_bytes) != build["acceptance_digest"]:
            raise RuntimeFailure("ACCEPTANCE_RECEIPT_TAMPERED")
        approved, preflight_descriptor, preflight_version = self._verify_devkit_candidate_binding(
            build, application_archive, devkit_wheel, receipt_bytes, expected_identity
        )
        descriptor, version, _identity = self.runtime.publish_devkit_archive(
            application_archive, receipt_bytes, devkit_wheel,
            expected_identity=expected_identity,
        )
        if descriptor.id != approved["capability_id"]:
            raise RuntimeFailure("CANDIDATE_CAPABILITY_ID_INVALID")
        if (
            version != preflight_version
            or descriptor.canonical_json() != preflight_descriptor.canonical_json()
        ):
            raise RuntimeFailure("PUBLISHED_CANDIDATE_IDENTITY_MISMATCH")
        previous = self.runtime.binding_or_none(build["scope_id"], descriptor.id)
        visible = self.chat.visible_resources(build["scope_id"], build["conversation_id"])
        before = self._world().build(build["scope_id"], visible)
        connections = dict(connection_bindings or {})
        approved_connection_names = {
            item["name"] for item in approved["connections"]
        }
        if (
            set(connections) != approved_connection_names
            or any(not isinstance(grant_id, str) or not grant_id for grant_id in connections.values())
        ):
            raise RuntimeFailure("BUILD_CONNECTION_BINDING_MISMATCH")
        after = self._world().build_with_binding(
            build["scope_id"], visible, descriptor.id, version, connections
        )
        publication = {
            "schema": "capy.publication-receipt/v0",
            "build_id": build_id,
            "capability_id": descriptor.id,
            "new_version": version,
            "acceptance_digest": build["acceptance_digest"],
            "scope_id": build["scope_id"],
            "previous_binding": _binding_value(previous),
            "new_binding": {
                "scope_id": build["scope_id"], "capability_id": descriptor.id,
                "version_digest": version, "connections": connections,
            },
            "world_digest_before": before.digest,
            "world_digest_after": after.digest,
            "publisher_identity": self.publisher_identity,
            "created_at": utc_now(),
        }
        self.runtime.bind_with_publication_receipt(
            build_id, build["scope_id"], descriptor.id, version,
            connections, publication, previous,
        )
        return self.reconcile_publication(build_id)

    def _verify_devkit_candidate_binding(
        self,
        build: dict[str, Any],
        application_archive: Path,
        devkit_wheel: Path,
        receipt_bytes: bytes,
        expected_identity: dict[str, str],
    ) -> tuple[dict[str, Any], CapabilityDescriptor, str]:
        """Bind the approved packet and durable candidate to exact accepted bytes."""

        packet = self._packet_value(build["id"])
        if (
            not isinstance(packet, dict)
            or packet.get("schema") != "capy.supervised-build-packet/v0"
            or packet.get("build_id") != build["id"]
            or not isinstance(packet.get("specification"), dict)
        ):
            raise RuntimeFailure("BUILD_PACKET_INVALID")
        approved = packet["specification"]
        self._validate_supervised_specification(approved)
        try:
            receipt = json.loads(receipt_bytes)
            archive_digest = sha256(application_archive.read_bytes())
            wheel_digest = sha256(devkit_wheel.read_bytes())
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            raise RuntimeFailure("CAPABILITY_ACCEPTANCE_RECEIPT_INVALID") from exc
        if receipt.get("schema") != "capy.application-acceptance/v1":
            raise RuntimeFailure("CAPABILITY_ACCEPTANCE_RECEIPT_INVALID")
        comparisons = (
            (
                "BUILD_CANDIDATE_REPOSITORY_MISMATCH",
                build["candidate_repository"], receipt.get("candidate_repository"),
                approved["candidate_repository"],
            ),
            (
                "BUILD_CANDIDATE_COMMIT_MISMATCH",
                build["candidate_commit"], receipt.get("candidate_commit"),
                expected_identity.get("candidate_commit"),
            ),
            (
                "BUILD_CANDIDATE_TREE_MISMATCH",
                build["candidate_tree"], receipt.get("candidate_tree"),
                expected_identity.get("candidate_tree"),
            ),
            (
                "BUILD_CANDIDATE_ARCHIVE_MISMATCH",
                build["candidate_archive_digest"], archive_digest,
                receipt.get("application_archive_sha256"),
                expected_identity.get("application_archive_sha256"),
            ),
            (
                "BUILD_CANDIDATE_CAPABILITY_MISMATCH",
                build["candidate_capability_id"], receipt.get("application_id"),
                approved["capability_id"],
            ),
            (
                "BUILD_ACCEPTANCE_IDENTITY_MISMATCH",
                build["acceptance_digest"], sha256(receipt_bytes),
                expected_identity.get("acceptance_receipt_sha256"),
            ),
            (
                "BUILD_DEVKIT_COMMIT_MISMATCH",
                approved["devkit_commit"], receipt.get("devkit_commit"),
                expected_identity.get("devkit_commit"),
            ),
            (
                "BUILD_DEVKIT_WHEEL_MISMATCH",
                approved["devkit_wheel_sha256"], wheel_digest,
                receipt.get("devkit_wheel_sha256"),
                expected_identity.get("devkit_wheel_sha256"),
            ),
            (
                "BUILD_ACCEPTANCE_PROFILE_MISMATCH",
                approved["acceptance_profile"], receipt.get("acceptance_profile"),
            ),
        )
        for code, *values in comparisons:
            if any(not isinstance(value, str) or value != values[0] for value in values):
                raise RuntimeFailure(code)
        if build["side_effect_ceiling"] != approved["side_effect_ceiling"]:
            raise RuntimeFailure("BUILD_SIDE_EFFECT_CEILING_MISMATCH")

        with tempfile.TemporaryDirectory(prefix="capy-build-preflight-") as temporary:
            candidate = Path(temporary) / "application"
            candidate.mkdir()
            self.runtime._extract_zip(application_archive, candidate)
            descriptor = CapabilityDescriptor.from_toml(candidate / "capability.toml")
            version = tree_digest(candidate)
        if build["candidate_version_digest"] != version:
            raise RuntimeFailure("BUILD_CANDIDATE_VERSION_MISMATCH")
        if descriptor.id != approved["capability_id"]:
            raise RuntimeFailure("BUILD_CANDIDATE_CAPABILITY_MISMATCH")
        allowed_side_effects = {
            "artifact_generation": {"read_only", "artifact_generation"},
        }.get(approved["side_effect_ceiling"], {approved["side_effect_ceiling"]})
        if descriptor.side_effect not in allowed_side_effects:
            raise RuntimeFailure("BUILD_SIDE_EFFECT_CEILING_EXCEEDED")
        resources = [
            {
                "name": item.name, "required": item.required,
                "min_items": item.min_items, "max_items": item.max_items,
            }
            for item in descriptor.resource_requirements
        ]
        slot = approved["resource_slot"]
        approved_resources = [] if slot is None else [{
            "name": slot["name"], "required": slot["min_items"] > 0,
            "min_items": slot["min_items"], "max_items": slot["max_items"],
        }]
        if resources != approved_resources:
            raise RuntimeFailure("BUILD_RESOURCE_CONTRACT_MISMATCH")
        if descriptor.input_schema != approved["input_schema"]:
            raise RuntimeFailure("BUILD_INPUT_SCHEMA_MISMATCH")
        if descriptor.result_schema != approved["result_schema"]:
            raise RuntimeFailure("BUILD_RESULT_SCHEMA_MISMATCH")
        connections = [
            {
                "name": item.name, "contract": item.contract,
                "operations": list(item.operations), "required": item.required,
            }
            for item in descriptor.connection_requirements
        ]
        if connections != approved["connections"]:
            raise RuntimeFailure("BUILD_CONNECTION_CONTRACT_MISMATCH")
        return approved, descriptor, version

    def reconcile_publications(self) -> int:
        reconciled = 0
        for item in self.runtime.publication_receipts():
            try:
                build = self.chat.build(item["build_id"])
            except RuntimeFailure as exc:
                if exc.code == "BUILD_REQUEST_UNKNOWN":
                    continue
                raise
            if build["status"] == "ACCEPTING":
                self.reconcile_publication(item["build_id"])
                reconciled += 1
        return reconciled

    def reconcile_publication(self, build_id: str) -> dict[str, Any]:
        build = self.chat.build(build_id)
        stored = self.runtime.publication_receipt(build_id)
        if stored is None:
            raise RuntimeFailure("PUBLICATION_RECEIPT_MISSING")
        publication = stored["receipt"]
        current = self.runtime.binding_or_none(publication["scope_id"], publication["capability_id"])
        if _binding_value(current) != publication["new_binding"]:
            raise RuntimeFailure("PUBLICATION_BINDING_CHANGED")
        after = self._world().build(
            build["scope_id"], self.chat.visible_resources(build["scope_id"], build["conversation_id"])
        )
        if after.digest != publication["world_digest_after"]:
            raise RuntimeFailure("PUBLICATION_WORLD_CHANGED")
        publication_digest = stored["digest"]
        self.chat.record_publication(build_id, publication, publication_digest)
        self.chat.record_binding_history(
            build_id, build["scope_id"], publication["capability_id"], "publish",
            publication["previous_binding"], publication["new_binding"], publication,
        )
        if build["status"] == "PUBLISHED":
            return build
        return self.chat.transition_build(
            build_id,
            {"ACCEPTING"},
            "PUBLISHED",
            lease_id=None,
            lease_expires_at=None,
            previous_binding_json=(
                canonical_json(publication["previous_binding"]).decode()
                if publication["previous_binding"] is not None else None
            ),
            published_binding_json=canonical_json(publication["new_binding"]).decode(),
        )

    def _world(self) -> WorldBuilder:
        return WorldBuilder(
            self.runtime,
            connection_status=self.connection_status,
            connection_inventory=self.connection_inventory,
        )

    def rollback(self, build_id: str) -> dict[str, Any]:
        build = self.chat.build(build_id)
        publication = self.chat.publication(build_id)
        if publication is None:
            raise RuntimeFailure("PUBLICATION_RECEIPT_MISSING")
        receipt = publication["receipt"]
        current = self.runtime.binding_or_none(build["scope_id"], receipt["capability_id"])
        if _binding_value(current) != receipt["new_binding"]:
            raise RuntimeFailure("ROLLBACK_BINDING_CHANGED")
        previous = receipt["previous_binding"]
        if previous is None:
            self.runtime.unbind(build["scope_id"], receipt["capability_id"])
        else:
            self.runtime.bind(
                build["scope_id"], previous["capability_id"],
                previous["version_digest"], previous["connections"],
            )
        rollback = {
            "schema": "capy.binding-operation/v0",
            "operation": "rollback",
            "build_id": build_id,
            "publication_digest": publication["digest"],
            "previous_binding": receipt["new_binding"],
            "new_binding": previous,
            "created_at": utc_now(),
        }
        self.chat.record_binding_history(
            build_id, build["scope_id"], receipt["capability_id"], "rollback",
            receipt["new_binding"], previous, rollback,
        )
        return rollback

    def reactivate(self, build_id: str) -> dict[str, Any]:
        build = self.chat.build(build_id)
        publication = self.chat.publication(build_id)
        if publication is None:
            raise RuntimeFailure("PUBLICATION_RECEIPT_MISSING")
        receipt = publication["receipt"]
        current = self.runtime.binding_or_none(build["scope_id"], receipt["capability_id"])
        if _binding_value(current) != receipt["previous_binding"]:
            raise RuntimeFailure("REACTIVATE_BINDING_CHANGED")
        target = receipt["new_binding"]
        self.runtime.bind(
            build["scope_id"], target["capability_id"], target["version_digest"], target["connections"]
        )
        operation = {
            "schema": "capy.binding-operation/v0",
            "operation": "reactivate",
            "build_id": build_id,
            "publication_digest": publication["digest"],
            "previous_binding": receipt["previous_binding"],
            "new_binding": target,
            "created_at": utc_now(),
        }
        self.chat.record_binding_history(
            build_id, build["scope_id"], receipt["capability_id"], "reactivate",
            receipt["previous_binding"], target, operation,
        )
        return operation
