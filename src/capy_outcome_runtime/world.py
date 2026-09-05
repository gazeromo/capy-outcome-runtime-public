"""Canonical current-world projection shared by the owner and semantic model."""

from __future__ import annotations

import copy
import hashlib
import json
from dataclasses import dataclass
from typing import Any, Callable

from .access import ActorContext
from .application_profiles import application_profile_for
from .store import RuntimeStore


NOT_ACCESSIBLE = [
    "arbitrary host filesystem",
    "other scopes' files and state",
    "raw provider credentials",
    "Git source and service logs",
    "email, Drive, WhatsApp, or web browsing unless configured",
    "FedEx quotes unless matching software and a connection are configured",
    "outbound Telegram",
]


def canonical_json(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


@dataclass(frozen=True)
class WorldSnapshot:
    value: dict[str, Any]
    digest: str


class WorldBuilder:
    def __init__(
        self,
        store: RuntimeStore,
        connection_status: Callable[[str, str], str] | None = None,
        connection_inventory: Callable[[str], list[dict[str, Any]]] | None = None,
        team_software: Callable[[ActorContext], list[Any]] | None = None,
        team_applications: Callable[[ActorContext], list[dict[str, Any]]] | None = None,
        interaction_contracts: Callable[[list[dict[str, Any]]], list[dict[str, Any]]] | None = None,
    ):
        self.store = store
        self.connection_status = connection_status
        self.connection_inventory = connection_inventory
        self.team_software = team_software
        self.team_applications = team_applications
        self.interaction_contracts = interaction_contracts

    def build(
        self,
        authority: str | ActorContext,
        visible_resources: list[dict[str, Any]],
    ) -> WorldSnapshot:
        scope_id = authority.execution_scope_id if isinstance(authority, ActorContext) else authority
        resources = []
        for item in visible_resources:
            metadata = self.store.resource_metadata(scope_id, item["digest"])
            resources.append(
                {
                    "handle": metadata["digest"],
                    "filename": metadata["filename"],
                    "size_bytes": metadata["size_bytes"],
                    "media_type": item.get("media_type") or "application/octet-stream",
                    "source_message": item.get("source_message"),
                    "created_at": metadata["created_at"],
                }
            )
        resources.sort(key=lambda item: (item["created_at"], item["handle"]))
        capabilities = self.store.list_bound_capabilities(scope_id, self.connection_status)
        inventory = self.connection_inventory
        if isinstance(authority, ActorContext) and self.team_software is not None:
            shared = {item.capability_id: item for item in self.team_software(authority)}
            capabilities = [item for item in capabilities if item["id"] in shared]
            for item in capabilities:
                projection = shared[item["id"]]
                if item["version_digest"] != projection.version_digest:
                    raise ValueError("team software projection version mismatch")
                item["source"] = projection.source
                item["shared_by"] = projection.shared_by
                item["maintained_by"] = projection.maintained_by
                item["available_to_members"] = projection.available_to_members
            inventory = None
        if isinstance(authority, ActorContext) and self.team_applications is not None:
            existing = {item["id"] for item in capabilities}
            additions = self.team_applications(authority)
            if any(item.get("id") in existing for item in additions):
                raise ValueError("team application projection conflicts with capability")
            capabilities.extend(additions)
            capabilities.sort(key=lambda item: item["id"])
        return self._snapshot(
            scope_id, resources, capabilities, inventory, authority
        )

    def build_with_binding(
        self,
        scope_id: str,
        visible_resources: list[dict[str, Any]],
        capability_id: str,
        version_digest: str,
        bindings: dict[str, str],
    ) -> WorldSnapshot:
        current = self.build(scope_id, visible_resources)
        capabilities = [
            item for item in current.value["capabilities"] if item["id"] != capability_id
        ]
        capabilities.append(
            self.store.capability_projection(
                scope_id, capability_id, version_digest, bindings, self.connection_status
            )
        )
        capabilities.sort(key=lambda item: item["id"])
        return self._snapshot(
            scope_id, current.value["resources"], capabilities, self.connection_inventory
        )

    def _snapshot(
        self,
        scope_id: str,
        resources: list[dict[str, Any]],
        capabilities: list[dict[str, Any]],
        connection_inventory: Callable[[str], list[dict[str, Any]]] | None = None,
        authority: str | ActorContext | None = None,
    ) -> WorldSnapshot:
        capabilities = copy.deepcopy(capabilities)
        connections_by_name = {}
        for capability in capabilities:
            profile = application_profile_for(capability)
            if profile is not None:
                capability["application_profile"] = profile
            for connection in capability["connections"]:
                fact = {"name": connection["name"], "status": connection["status"]}
                connections_by_name[fact["name"]] = fact
        if connection_inventory is not None:
            for fact in connection_inventory(scope_id):
                if (
                    not isinstance(fact, dict)
                    or not isinstance(fact.get("name"), str)
                    or fact.get("status") not in {"configured", "unavailable", "unhealthy"}
                ):
                    raise ValueError("invalid connection inventory fact")
                connections_by_name[fact["name"]] = fact
        value = {
            "schema": "capy.world/v0",
            "scope": scope_id,
            "capabilities": capabilities,
            "resources": resources,
            "connections": sorted(connections_by_name.values(), key=lambda item: item["name"]),
            "state": [
                {"capability_id": item["id"], "available": item["state_available"]}
                for item in capabilities
                if item["state_required"]
            ],
            "not_accessible_by_default": list(NOT_ACCESSIBLE),
        }
        if isinstance(authority, ActorContext):
            value["actor"] = {
                "principal_id": authority.principal_id,
                "display_name": authority.principal_display_name,
            }
            value["team"] = {
                "team_id": authority.team_id,
                "name": authority.team_name,
                "membership_id": authority.membership_id,
                "membership_kind": authority.membership_kind,
            }
            value["workspace"] = {
                "kind": authority.workspace_kind,
                "label": "Personal" if authority.workspace_kind == "personal" else authority.team_name,
                "workspace_id": (
                    authority.principal_id
                    if authority.workspace_kind == "personal"
                    else authority.team_id
                ),
            }
        if self.interaction_contracts is not None:
            value["applications"] = self.interaction_contracts(capabilities)
        if isinstance(authority, ActorContext):
            for capability in capabilities:
                if capability.get("id") != "vehicles.encar_watcher.watch.create":
                    continue
                schema = capability.get("input_schema") or {}
                properties = schema.get("properties") or {}
                properties.pop("visibility", None)
                schema["required"] = [
                    item for item in schema.get("required", []) if item != "visibility"
                ]
        return WorldSnapshot(value, hashlib.sha256(canonical_json(value)).hexdigest())
