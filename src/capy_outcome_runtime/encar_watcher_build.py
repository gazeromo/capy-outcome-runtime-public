"""Exact proposal contract for the private Encar watcher application build.

This module is deliberately application-specific.  It is not a DevKit schema or
the beginning of a generic stateful-service build API.
"""

from __future__ import annotations

import copy
from pathlib import Path
from typing import Any

from .model import RuntimeFailure


LITERAL_OWNER_REQUEST = (
    "Create a watch for Volkswagen Jetta, years 2020–2024. Check Encar and "
    "notify me when something is worth my attention."
)
APPLICATION_ID = "vehicles.encar_watcher"
BUILD_SPEC_SCHEMA = "capy.team-application-build-spec/v0"
CAMPAIGN_INPUT_NAMES = (
    "SOURCE-FIT.json",
    "SOURCE-FIT.md",
    "APPLICATION-CONTRACT.md",
    "ACCEPTANCE-FIXTURE.json",
)


_SPECIFICATION: dict[str, Any] = {
    "schema": BUILD_SPEC_SCHEMA,
    "kind": "team_application",
    "shape": "stateful_scheduled_watcher",
    "application": APPLICATION_ID,
    "owner_request": LITERAL_OWNER_REQUEST,
    "initial_watch": {
        "source": "encar",
        "make": "Volkswagen",
        "model": "Jetta",
        "min_year": 2020,
        "max_year": 2024,
        "visibility": "personal",
        "attention_intent": "notify me when something is worth my attention",
        "invented_exclusions": [],
    },
    "state": {
        "owner": "application_transactional_sqlite",
        "first_snapshot": "silent_baseline",
        "source_failure": "preserve_prior_state",
    },
    "source": {
        "order": [
            "existing_team_compatible_eimcar_feed_if_sufficient",
            "normalized_eimcar_search_filtered_to_encar",
        ],
        "direct_encar_scraping": False,
        "browser_automation": False,
    },
    "shared_operation": "one_shared_scheduler_or_service",
    "ai_evaluation": "bounded_new_or_materially_changed_candidates_only",
    "notification": "authenticated_internal_capy_only",
    "team_reuse": "one_release_for_authorized_team_members",
    "builder_inputs": list(CAMPAIGN_INPUT_NAMES),
    "excluded_authority": [
        "capy_runtime_source",
        "capy_infrastructure_source",
        "credentials",
        "host_administration",
        "publication_authority",
    ],
    "non_goals": [
        "capy_script",
        "new_devkit_api",
        "generic_service_sdk",
        "generic_state_framework",
        "direct_encar_access",
        "seller_contact",
        "reservation",
        "vehicle_purchase",
        "external_notification",
        "public_endpoint",
        "marketplace",
        "per_user_or_watch_worker",
    ],
}

NONTECHNICAL_SUMMARY = {
    "reads": (
        "Encar listings for Volkswagen Jetta vehicles from 2020–2024 through "
        "EimCar's approved read-only source path."
    ),
    "produces": (
        "A personal watch that remembers what it has seen and uses bounded AI "
        "judgment only for new or materially changed listings."
    ),
    "external_connection": (
        "One shared periodic service reads EimCar's normalized Encar results; "
        "it does not scrape Encar or contact sellers."
    ),
    "persistent_state": (
        "Team watch history is stored transactionally on Capy's private server "
        "and reused by the same shared service after restart."
    ),
    "changes": (
        "Notifies you inside Capy when something appears worth attention and "
        "lets authorized teammates create their own watches with the same "
        "software. It never reserves or purchases a car."
    ),
}


def specification() -> dict[str, Any]:
    """Return an isolated copy of the one frozen watcher build specification."""

    return copy.deepcopy(_SPECIFICATION)


def validate_specification(value: dict[str, Any]) -> None:
    if value != _SPECIFICATION:
        raise RuntimeFailure("ENCAR_WATCHER_BUILD_SPEC_INVALID")


def is_exact_gap(gap: dict[str, Any]) -> bool:
    """Recognize only the literal no-attachment, no-clarification owner gap."""

    return (
        gap.get("original_message") == LITERAL_OWNER_REQUEST
        and gap.get("resources") == []
        and gap.get("missing_information") == []
    )


def validate_gap(gap: dict[str, Any]) -> None:
    if not is_exact_gap(gap) or gap.get("status") != "open":
        raise RuntimeFailure("ENCAR_WATCHER_BUILD_GAP_INVALID")
    if not all(
        isinstance(gap.get(field), str) and gap[field].strip()
        for field in ("needed_ability", "desired_result", "world_digest")
    ):
        raise RuntimeFailure("ENCAR_WATCHER_BUILD_GAP_INVALID")


def campaign_input_paths(repository_root: Path) -> list[Path]:
    root = repository_root / "campaigns" / "team_encar_watcher_v0"
    paths = [root / name for name in CAMPAIGN_INPUT_NAMES]
    if any(path.is_symlink() or not path.is_file() for path in paths):
        raise RuntimeFailure("ENCAR_WATCHER_CAMPAIGN_INPUT_INVALID")
    return paths
