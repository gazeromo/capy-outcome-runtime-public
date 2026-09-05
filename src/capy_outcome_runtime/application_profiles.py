"""Small version-bound semantic profiles for accepted application integrations."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any

from .model import RuntimeFailure


PROFORMA_CAPABILITY_ID = "documents.proforma_invoice"
PROFORMA_VERSION_DIGEST = (
    "a1f79c4012fa0eecb376196f2659a478e1016bf50ce02288b41b489b7aac2bb0"
)


@dataclass(frozen=True)
class OwnerField:
    name: str
    label: str


@dataclass(frozen=True)
class ApplicationProfile:
    application_id: str
    version_digest: str
    purpose: str
    required_owner_fields: tuple[OwnerField, ...]
    optional_owner_fields: tuple[OwnerField, ...]
    resource_slot: str
    resource_count: tuple[int, int]
    resource_format: str
    accepted_columns_in_order: tuple[str, ...]
    artifact_filenames: tuple[str, ...]
    result_facts: tuple[str, ...]
    side_effect_class: str
    information_operations: tuple[str, ...]
    application_owned_work: tuple[str, ...]

    def world_value(self) -> dict[str, Any]:
        """Return a fresh JSON value so callers cannot mutate the frozen profile."""

        return {
            "schema": "capy.application-profile/v0",
            "application_id": self.application_id,
            "version_digest": self.version_digest,
            "purpose": self.purpose,
            "owner_fields": {
                "required": [asdict(item) for item in self.required_owner_fields],
                "optional": [asdict(item) for item in self.optional_owner_fields],
            },
            "resource_contract": {
                "slot": self.resource_slot,
                "minimum_count": self.resource_count[0],
                "maximum_count": self.resource_count[1],
                "format": self.resource_format,
                "accepted_columns_in_order": list(self.accepted_columns_in_order),
            },
            "result_contract": {
                "verified_artifacts": list(self.artifact_filenames),
                "facts": list(self.result_facts),
            },
            "side_effect_class": self.side_effect_class,
            "information_operations": list(self.information_operations),
            "application_owned_work": list(self.application_owned_work),
        }


PROFORMA_PROFILE = ApplicationProfile(
    application_id=PROFORMA_CAPABILITY_ID,
    version_digest=PROFORMA_VERSION_DIGEST,
    purpose="Prepare one verified proforma invoice from one line-item CSV resource.",
    required_owner_fields=(
        OwnerField("invoice_number", "invoice number"),
        OwnerField("issue_date", "issue date"),
        OwnerField("currency", "currency"),
        OwnerField("seller", "seller"),
        OwnerField("buyer", "buyer"),
        OwnerField("payment_terms", "payment terms"),
    ),
    optional_owner_fields=(OwnerField("notes", "notes"),),
    resource_slot="line_items",
    resource_count=(1, 1),
    resource_format="CSV",
    accepted_columns_in_order=("sku", "description", "quantity", "unit_price"),
    artifact_filenames=("proforma-invoice.html", "proforma-invoice.json"),
    result_facts=(
        "invoice_number", "currency", "item_count", "total_quantity", "subtotal",
    ),
    side_effect_class="internal_artifact_generation_only",
    information_operations=(),
    application_owned_work=(
        "CSV decoding and validation",
        "line-item quantity and unit-price validation",
        "Decimal arithmetic and subtotal calculation",
        "HTML and JSON artifact construction",
    ),
)

_PROFILES = {PROFORMA_CAPABILITY_ID: PROFORMA_PROFILE}


def application_profile_for(capability: dict[str, Any]) -> dict[str, Any] | None:
    """Bind one optional profile to exact live application/version truth."""

    profile = _PROFILES.get(capability["id"])
    if profile is None:
        return None
    if capability["version_digest"] != profile.version_digest:
        raise RuntimeFailure("APPLICATION_PROFILE_VERSION_UNSUPPORTED")
    _validate_against_capability(profile, capability)
    return profile.world_value()


def _validate_against_capability(
    profile: ApplicationProfile, capability: dict[str, Any]
) -> None:
    input_schema = capability["input_schema"]
    required = tuple(input_schema.get("required", ()))
    properties = tuple(input_schema.get("properties", ()))
    profile_required = tuple(item.name for item in profile.required_owner_fields)
    profile_optional = tuple(item.name for item in profile.optional_owner_fields)
    resource_requirements = capability.get("resource_requirements", [])
    result_artifacts = (
        capability["result_schema"]
        .get("properties", {})
        .get("artifact_filenames", {})
        .get("items", {})
        .get("enum")
    )
    expected_resource = [{
        "name": profile.resource_slot,
        "required": True,
        "min_items": profile.resource_count[0],
        "max_items": profile.resource_count[1],
    }]
    if (
        required != profile_required
        or tuple(name for name in properties if name not in required) != profile_optional
        or resource_requirements != expected_resource
        or tuple(result_artifacts or ()) != profile.artifact_filenames
        or capability["side_effect"] != "artifact_generation"
    ):
        raise RuntimeFailure("APPLICATION_PROFILE_CONTRACT_MISMATCH")
