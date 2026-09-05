"""Application-independent compositions of the workbench primitives."""

from __future__ import annotations

from collections.abc import Iterable
import html

from .models import UIActivity, UIEntity, UIForm, UINotice
from .render import (
    SafeHtml,
    _safe,
    render_activity,
    render_entity,
    render_form,
    render_inspector,
    render_message,
    render_notice,
    render_page_header,
)


def render_foundation_catalog() -> SafeHtml:
    colors = (
        "canvas", "surface", "surface-subtle", "surface-hover", "surface-selected",
        "border", "border-strong", "text", "text-secondary", "text-muted",
        "action", "action-hover", "accent", "accent-soft", "success", "warning",
        "danger", "danger-soft", "focus",
    )
    swatches = "".join(
        f'<div class="ui-lab-swatch"><span style="background:var(--ui-{name})"></span><code>--ui-{name}</code></div>'
        for name in colors
    )
    return _safe(
        '<section class="ui-pattern ui-lab-foundation"><header class="ui-pattern-header"><div>'
        '<p class="ui-kicker">Foundation</p><h2>Tokens and behavior</h2>'
        '<p>System typography, compact spacing, restrained radii, visible focus, and reduced motion.</p>'
        f'</div></header><div class="ui-lab-swatches">{swatches}</div>'
        '<div class="ui-lab-type"><p class="ui-kicker">Metadata · 12 / 16</p>'
        '<p>Dense controls and rows · 13 / 18</p><p>Standard interface · 14 / 20</p>'
        '<p class="ui-lab-body">Conversation and primary body · 15 / 22</p>'
        '<h2>Section title · 18 / 26</h2><h1>Task title · 24 / 32</h1></div></section>'
    )


def render_conversation_workspace(
    title: str,
    messages: Iterable[tuple[str, str]],
    activities: Iterable[UIActivity] = (),
    notice: UINotice | None = None,
) -> SafeHtml:
    content = "".join(str(render_message(role, body)) for role, body in messages)
    content += "".join(str(render_activity(activity)) for activity in activities)
    if notice is not None:
        content += str(render_notice(notice))
    return _safe(
        str(render_page_header("Conversation Workspace", title))
        + f'<section class="ui-pattern" aria-label="Conversation">{content}</section>'
    )


def render_entity_detail(entity: UIEntity) -> SafeHtml:
    inspector = render_inspector(entity.inspector)
    return _safe(
        '<div data-pattern="entity-detail">'
        + str(render_page_header("Entity Detail", entity.title))
        + '<section class="ui-pattern ui-workbench">'
        + str(render_entity(entity)) + str(inspector) + '</section></div>'
    )


def render_form_workflow(form: UIForm, result: UIActivity | None = None) -> SafeHtml:
    result_html = render_activity(result) if result is not None else _safe("")
    return _safe(
        '<div data-pattern="form-workflow">'
        + str(render_page_header("Form Workflow", form.task_title))
        + str(render_form(form)) + str(result_html) + '</div>'
    )


def render_activity_result(activity: UIActivity) -> SafeHtml:
    return _safe(
        '<div data-pattern="activity-result">'
        + str(render_page_header("Activity Result", activity.headline))
        + str(render_activity(activity)) + '</div>'
    )


def render_lab_section(title: str, fragments: Iterable[SafeHtml]) -> SafeHtml:
    """Compose qualification-only catalog sections through the trusted renderer."""
    values = tuple(fragments)
    if any(not isinstance(value, SafeHtml) for value in values):
        raise TypeError("lab fragments must come from trusted renderers")
    return _safe(
        f'<section class="ui-lab-section"><h2>{html.escape(title)}</h2>'
        f'{"".join(str(value) for value in values)}</section>'
    )
