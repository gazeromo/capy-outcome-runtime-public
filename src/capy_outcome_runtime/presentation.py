"""Trusted, local-only human presentation for exact application results."""

from __future__ import annotations

import re
import unicodedata
from typing import Any, Iterable

from .ui.models import UIAction, UIActivity, UIFact, UIStatus


WATCHER_ID = "vehicles.encar_watcher"
PROFORMA_ID = "documents.proforma_invoice"
PRESENTATION_KINDS = {
    (WATCHER_ID, "watch.create"): "watch_create",
    (WATCHER_ID, "watch.status"): "watch_status",
    (WATCHER_ID, "watch.list"): "watch_list",
    (WATCHER_ID, "watch.pause"): "watch_transition",
    (WATCHER_ID, "watch.resume"): "watch_transition",
    (WATCHER_ID, "watch.update"): "watch_update",
    (WATCHER_ID, "watch.delete"): "watch_delete",
    (WATCHER_ID, "watch.check_now"): "watch_check_now",
    (PROFORMA_ID, "invoice.generate"): "artifact_result",
}


def compact_conversation_title(value: object, maximum: int = 52) -> str:
    """Derive a bounded display-only title without changing stored history."""

    text = unicodedata.normalize("NFKC", str(value or ""))
    text = " ".join(text.split())
    if not text:
        return "New conversation"
    lowered = text.casefold()
    invoice = re.search(r"\b(?:invoice|proforma)\s+(?:number\s+)?([a-z0-9][a-z0-9._/-]{1,31})", text, re.I)
    if invoice:
        title = f"Proforma {invoice.group(1).upper()}"
    elif "watch" in lowered:
        target = re.sub(
            r"^(?:please\s+)?(?:create|start|set up|make|pause|resume|update|check)\s+(?:a|an|the|my|our)?\s*",
            "",
            text,
            flags=re.I,
        )
        target = re.sub(r"\b(?:car|vehicle|encar)\s+watch\s+(?:for\s+)?", "", target, flags=re.I)
        target = re.sub(r"\bwatch\s+(?:for\s+)?", "", target, flags=re.I)
        target = re.sub(r"\b(?:and\s+notify.*|that\s+.*|with\s+.*)$", "", target, flags=re.I)
        target = " ".join(target.split()).strip(" .,-")
        target = re.sub(r"\bmercedes[ -]?benz\b", "Mercedes-Benz", target, flags=re.I)
        target = re.sub(r"\bg[ -]?class\b", "G-Class", target, flags=re.I)
        title = (
            target if target.casefold().endswith(" watch")
            else (f"{target} watch" if target else "Vehicle watch")
        )
    else:
        title = text
    title = title[0].upper() + title[1:] if title else "New conversation"
    if len(title) <= maximum:
        return title
    return title[: maximum - 1].rstrip() + "…"


def _text(value: object) -> str | None:
    if isinstance(value, (str, int, float)) and not isinstance(value, bool):
        text = str(value).strip()
        return text or None
    return None


def _application_id(metadata: dict[str, Any]) -> str | None:
    direct = metadata.get("application_id")
    if direct in {WATCHER_ID, PROFORMA_ID}:
        return direct
    candidates: Iterable[object] = (
        metadata.get("capability_id"),
        (metadata.get("software") or {}).get("id")
        if isinstance(metadata.get("software"), dict) else None,
    )
    for candidate in candidates:
        if isinstance(candidate, str):
            if candidate.startswith(WATCHER_ID):
                return WATCHER_ID
            if candidate == PROFORMA_ID:
                return PROFORMA_ID
    return None


def presentation_binding_is_current(
    metadata: dict[str, Any], contract: dict[str, Any]
) -> bool:
    """Require an exact current contract tuple before specialized rendering."""

    application_id = _application_id(metadata)
    operation_id = metadata.get("operation_id")
    presentation_kind = metadata.get("presentation_kind")
    if (
        application_id != contract.get("application_id")
        or metadata.get("application_version") != contract.get("application_version")
        or metadata.get("interaction_contract_digest") != contract.get("digest")
        or PRESENTATION_KINDS.get((application_id, operation_id)) != presentation_kind
    ):
        return False
    operation = next(
        (item for item in contract.get("operations", []) if item.get("operation_id") == operation_id),
        None,
    )
    return bool(
        operation
        and isinstance(operation.get("result"), dict)
        and operation["result"].get("presentation") == presentation_kind
    )


def _watch_facts(value: dict[str, Any]) -> tuple[str, str, str, str, str, bool | None] | None:
    filters = value.get("filters") or value.get("hard_filters") or {}
    if not isinstance(filters, dict):
        filters = {}
    make = _text(filters.get("make"))
    model = _text(filters.get("model"))
    if not make or not model:
        return None
    minimum = _text(filters.get("min_year"))
    maximum = _text(filters.get("max_year"))
    years = minimum if minimum == maximum else "–".join(item for item in (minimum, maximum) if item)
    status_value = _text(value.get("status"))
    schedule = value.get("schedule_seconds")
    if not status_value or type(schedule) is not int or schedule <= 0:
        return None
    status = status_value.replace("_", " ").title()
    schedule_text = (
        f"{schedule // 60} minutes"
        if type(schedule) is int and schedule > 0 and schedule % 60 == 0
        else f"{schedule} seconds"
    )
    baseline_waiting = None
    if value.get("baseline_pending") is True or value.get("baseline_established") is False:
        baseline_waiting = True
    elif "baseline_at" in value:
        baseline_waiting = not bool(value.get("baseline_at"))
    return make, model, years, status, schedule_text, baseline_waiting


def present_application_result(
    metadata: dict[str, Any],
    *,
    application_href: str | None,
    workspace_name: str,
    resolved_watch: dict[str, Any] | None = None,
) -> UIActivity:
    """Create a strict view model from trusted metadata and optional local state."""

    app_id = _application_id(metadata)
    result = metadata.get("result")
    result = result if isinstance(result, dict) else {}
    receipt = metadata.get("operation_receipt") or metadata.get("invocation_receipt")
    receipt_value = _text(receipt) if not isinstance(receipt, dict) else _text(receipt.get("receipt"))
    technical: list[UIFact] = []
    if type(metadata.get("source_checked")) is bool:
        technical.append(UIFact("Source checked", "Yes" if metadata["source_checked"] else "No", "technical"))
    version = _text(metadata.get("application_version") or metadata.get("version_digest"))
    if version:
        technical.append(UIFact("Installed version", version, "technical"))
    if receipt_value:
        technical.append(UIFact("Receipt", receipt_value, "technical"))

    operation = _text(metadata.get("operation_id"))
    presentation_kind = _text(metadata.get("presentation_kind"))
    if PRESENTATION_KINDS.get((app_id, operation)) != presentation_kind:
        app_id = None

    if app_id == WATCHER_ID:
        watch = resolved_watch
        if watch is None and isinstance(result.get("watch"), dict):
            watch = result["watch"]
        if watch is None and isinstance(result.get("matches"), list) and len(result["matches"]) == 1:
            candidate = result["matches"][0]
            watch = candidate if isinstance(candidate, dict) else None
        facts = _watch_facts(watch or result)
        if facts:
            make, model, years, status, schedule, baseline_waiting = facts
            identity = " ".join(item for item in (make, model) if item).strip()
        else:
            identity, years, status, schedule, baseline_waiting = "", "", "", "", None
        if presentation_kind == "watch_check_now":
            if not all(type(result.get(key)) is int for key in ("total_hits", "candidates_created")):
                app_id = None
            else:
                headline = "Vehicle check completed"
                card_facts = [
                    ("Matching listings", str(result["total_hits"])),
                    ("New candidates", str(result["candidates_created"])),
                    ("Source", "Checked now"),
                ]
                summary = identity or "The selected watch was checked."
        elif presentation_kind == "watch_list":
            watches = result.get("watches")
            if not isinstance(watches, list):
                app_id = None
            else:
                headline = "Your vehicle watches"
                summary = f"{len(watches)} visible in {workspace_name}"
                card_facts = [("Visible watches", str(len(watches))), ("Source", "Stored state only")]
        elif presentation_kind == "watch_delete":
            headline = f"{identity} watch deleted" if identity else "Vehicle watch deleted"
            summary = workspace_name
            card_facts = [("Status", "Deleted"), ("Source", "Not checked")]
        elif presentation_kind in {"watch_transition", "watch_update"}:
            if not facts:
                app_id = None
            else:
                action = {"watch.pause": "paused", "watch.resume": "resumed", "watch.update": "updated"}[operation]
                headline = f"{identity} watch {action}"
                summary = " · ".join(item for item in (years, workspace_name) if item)
                card_facts = [("Status", status), ("Checks every", schedule)]
        elif presentation_kind == "watch_status":
            if not facts:
                app_id = None
            else:
                headline = identity
                summary = " · ".join(item for item in (years, workspace_name) if item)
                card_facts = [("Status", status), ("Checks every", schedule)]
                if baseline_waiting is not None:
                    card_facts.append(("Baseline", "Waiting for first check" if baseline_waiting else "Established"))
        else:
            if not facts:
                app_id = None
            else:
                headline = f"{identity} watch created"
                summary = " · ".join(item for item in (years, workspace_name) if item)
                card_facts = [("Status", status), ("Checks every", schedule)]
                if baseline_waiting is not None:
                    card_facts.append(("First baseline", "Waiting for first check" if baseline_waiting else "Established"))

        if app_id is None:
            return UIActivity(
                None, "Capy", operation, "succeeded", "Result ready",
                "The completed result is available without exposing internal data.",
                status=UIStatus("Completed", "neutral"),
                important_facts=(UIFact("Status", "Completed", "primary"),),
                technical_details=tuple(technical),
            )
        return UIActivity(
            WATCHER_ID, "Vehicle Watcher", operation, "succeeded", headline, summary,
            target_entity=identity or None,
            status=UIStatus("Completed", "success"),
            important_facts=tuple(
                UIFact(label, value, "primary" if index == 0 else "secondary")
                for index, (label, value) in enumerate(card_facts)
            ),
            primary_action=(
                UIAction("open-application", "Open Vehicle Watcher", href=application_href, hierarchy="primary")
                if application_href else None
            ),
            technical_details=tuple(technical),
        )

    if app_id == PROFORMA_ID:
        number = _text(result.get("invoice_number"))
        headline = f"Invoice {number} created" if number else "Proforma invoice created"
        item_count = result.get("item_count")
        subtotal = _text(result.get("subtotal"))
        currency = _text(result.get("currency"))
        facts = []
        if type(item_count) is int:
            facts.append(("Line items", str(item_count)))
        if subtotal:
            facts.append(("Subtotal", " ".join(item for item in (currency, subtotal) if item)))
        facts.append(("Workspace", workspace_name))
        return UIActivity(
            PROFORMA_ID, "Proforma Invoice", operation, "succeeded", headline,
            "Your verified invoice files are ready.",
            status=UIStatus("Completed", "success"),
            important_facts=tuple(
                UIFact(label, value, "primary" if index == 0 else "secondary")
                for index, (label, value) in enumerate(facts)
            ),
            primary_action=(
                UIAction("open-application", "Open Proforma Invoice", href=application_href, hierarchy="primary")
                if application_href else None
            ),
            technical_details=tuple(technical),
        )

    return UIActivity(
        None, "Capy", operation, "succeeded", "Result ready",
        "The completed result is available without exposing internal data.",
        status=UIStatus("Completed", "neutral"),
        important_facts=(UIFact("Status", "Completed", "primary"),),
        technical_details=tuple(technical),
    )
