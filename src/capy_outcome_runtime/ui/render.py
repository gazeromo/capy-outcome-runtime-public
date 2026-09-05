"""Escaping renderer for standard workbench primitives and patterns."""

from __future__ import annotations

import html
import hashlib
from typing import Iterable

from .models import (
    UIAction,
    UIActivity,
    UIArtifact,
    UICollection,
    UIConfirmation,
    UIEntity,
    UIFact,
    UIField,
    UIForm,
    UIInspector,
    UINotice,
    UIStatus,
)


_RENDER_CAPABILITY = object()
_STYLESHEET_CAPABILITY = object()
_APPROVED_STYLESHEET_DIGESTS = frozenset({
    "61160a35a7bb91b95cea4b51e345c04e97a46eea43b03e343695f5644a2cc18a",
})


class SafeHtml(str):
    """Opaque markup capability that only this renderer package can construct."""

    def __new__(cls, value: str, capability: object | None = None):
        if capability is not _RENDER_CAPABILITY:
            raise TypeError("rendered markup can only be created by the trusted UI renderer")
        return super().__new__(cls, value)


class StylesheetExtension(str):
    """Opaque, digest-allowlisted stylesheet capability for trusted adapters."""

    def __new__(cls, value: str, capability: object | None = None):
        if capability is not _STYLESHEET_CAPABILITY:
            raise TypeError("stylesheet extensions require a trusted renderer capability")
        return super().__new__(cls, value)


def render_stylesheet_extension(value: str) -> StylesheetExtension:
    if not isinstance(value, str):
        raise TypeError("stylesheet extension must be text")
    digest = hashlib.sha256(value.encode("utf-8")).hexdigest()
    if digest not in _APPROVED_STYLESHEET_DIGESTS:
        raise ValueError("stylesheet extension is not an approved compatibility asset")
    return StylesheetExtension(value, _STYLESHEET_CAPABILITY)


def _safe(value: str) -> SafeHtml:
    return SafeHtml(value, _RENDER_CAPABILITY)


def _join(values: Iterable[SafeHtml]) -> SafeHtml:
    values = tuple(values)
    if any(not isinstance(value, SafeHtml) for value in values):
        raise TypeError("only trusted renderer fragments may be joined")
    return _safe("".join(str(value) for value in values))


def render_stack(*values: SafeHtml) -> SafeHtml:
    """Compose trusted renderer fragments without accepting plain markup."""
    return _join(values)


def render_empty_conversation() -> SafeHtml:
    return _safe(
        '<section class="ui-empty"><p class="ui-kicker">Conversation</p>'
        '<h1>What can Capy take care of?</h1>'
        '<p>Start a conversation and describe the outcome you need.</p></section>'
    )


def render_chat_workspace(
    *,
    header: SafeHtml,
    messages: Iterable[SafeHtml],
    active: bool,
    csrf_token: str,
    conversation_id: str,
    submission_id: str,
) -> SafeHtml:
    """Render the production transcript and no-JavaScript composer."""
    if not isinstance(header, SafeHtml):
        raise TypeError("chat header must be trusted renderer output")
    rendered_messages = _join(messages)
    active_value = "true" if active else "false"
    return _safe(
        f'{header}<div id=timeline data-active={active_value}>{rendered_messages}</div>'
        '<div class="ui-composer-wrap composer-wrap"><form id=message-composer class=composer '
        'method=post action=/messages enctype=multipart/form-data>'
        f'<input type="hidden" name="csrf" value="{_e(csrf_token)}">'
        f'<input type="hidden" name="conversation" value="{_e(conversation_id)}">'
        f'<input type=hidden name=submission value="{_e(submission_id)}">'
        '<label class="ui-sr-only skip-link" for=message-text>Message Capy</label>'
        '<textarea id=message-text name=text required placeholder="Ask Capy or describe what you need…"></textarea>'
        '<div class="ui-composer-actions actions"><div class="ui-composer-attachments attachment-row">'
        '<label class="ui-file-button file-button" for="message-files">Attach</label>'
        '<input class="ui-file-input attachment-input" id="message-files" type="file" name="files" multiple>'
        '<span id="file-chips"></span></div><button class="ui-action ui-action--primary ui-composer-submit" '
        'id="message-send">Send</button></div><div class="ui-composer-meta">'
        f'<a class="conversation-info" href="/world?conversation={_e(conversation_id)}">'
        'Conversation information · What Capy can access</a>'
        '<p id=chat-live-status class="ui-live-status live-status" role=status aria-live=polite></p>'
        '</div></form></div>'
    )


def render_legacy_compatibility(markup: str) -> SafeHtml:
    """Migration-only boundary for the two accepted server-rendered application bodies."""
    if not isinstance(markup, str) or isinstance(markup, SafeHtml):
        raise TypeError("legacy compatibility markup must be a plain server-rendered string")
    return _safe(f'<div class="compat-application compat-body">{markup}</div>')


def _e(value: object, *, quote: bool = True) -> str:
    return html.escape(str(value), quote=quote)


def render_status(status: UIStatus) -> SafeHtml:
    detail = f'<span class="ui-status-detail">{_e(status.detail)}</span>' if status.detail else ""
    return _safe(
        f'<span class="ui-status ui-status--{_e(status.tone)}">'
        f'<span class="ui-status-mark" aria-hidden="true"></span>'
        f'<span>{_e(status.label)}</span>{detail}</span>'
    )


def render_action(action: UIAction) -> SafeHtml:
    classes = f"ui-action ui-action--{action.hierarchy}"
    reason_id = f"{action.action_id}-disabled-reason"
    loading = f' data-loading-label="{_e(action.loading_label)}"' if action.loading_label else ""
    if not action.enabled:
        return _safe(
            f'<span class="ui-disabled-action"><button class="{classes}" type="button" disabled '
            f'aria-describedby="{_e(reason_id)}">{_e(action.label)}</button>'
            f'<span class="ui-action-reason" id="{_e(reason_id)}">{_e(action.disabled_reason)}</span></span>'
        )
    if action.method == "GET":
        external = ' target="_blank" rel="noopener noreferrer"' if action.external else ""
        return _safe(
            f'<a class="{classes}" data-action-id="{_e(action.action_id)}" '
            f'href="{_e(action.href)}"{external}{loading}>{_e(action.label)}</a>'
        )
    fields = "".join(
        f'<input type="hidden" name="{_e(name)}" value="{_e(value)}">'
        for name, value in action.form_fields
    )
    confirm = ' data-requires-confirmation="true"' if action.requires_confirmation else ""
    enctype = ' enctype="multipart/form-data"' if action.encoding == "multipart" else ""
    return _safe(
        f'<form class="ui-action-form" method="post"{enctype} '
        f'action="{_e(action.form_action)}"{confirm}>{fields}'
        f'<button class="{classes}" data-action-id="{_e(action.action_id)}"{loading}>{_e(action.label)}</button></form>'
    )


def render_actions(actions: Iterable[UIAction], *, label: str = "Available actions") -> SafeHtml:
    values = tuple(actions)
    if sum(action.hierarchy == "primary" for action in values) > 1:
        raise ValueError("a context may contain at most one primary action")
    routine = [action for action in values if action.hierarchy != "danger"]
    danger = [action for action in values if action.hierarchy == "danger"]
    routine_html = _join(render_action(action) for action in routine)
    danger_html = (
        f'<div class="ui-actions-danger" aria-label="Danger zone">{_join(render_action(action) for action in danger)}</div>'
        if danger else ""
    )
    return _safe(
        f'<div class="ui-actions" aria-label="{_e(label)}"><div class="ui-actions-main">{routine_html}</div>{danger_html}</div>'
    )


def render_facts(facts: Iterable[UIFact], *, class_name: str = "ui-facts") -> SafeHtml:
    values = tuple(facts)
    if not values:
        return _safe("")
    rows = "".join(
        f'<div class="ui-fact ui-fact--{_e(fact.importance)}"><dt>{_e(fact.label)}</dt>'
        f'<dd>{_e(fact.value)}</dd></div>'
        for fact in values
    )
    return _safe(f'<dl class="{_e(class_name)}">{rows}</dl>')


def render_technical_details(facts: Iterable[UIFact]) -> SafeHtml:
    values = tuple(facts)
    if not values:
        return _safe("")
    return _safe(
        '<details class="ui-technical"><summary>Technical details</summary>'
        f'{render_facts(values, class_name="ui-technical-facts")}</details>'
    )


def _render_artifact(artifact: UIArtifact) -> SafeHtml:
    if artifact.state == "ready":
        return _safe(
            f'<a class="ui-artifact" href="{_e(artifact.href)}"><span aria-hidden="true">↓</span>{_e(artifact.label)}</a>'
        )
    return _safe(
        f'<span class="ui-artifact ui-artifact--unavailable" aria-disabled="true">'
        f'{_e(artifact.label)} · {_e(artifact.state.title())}</span>'
    )


def render_artifacts(artifacts: Iterable[UIArtifact]) -> SafeHtml:
    """Render downloadable resources without exposing raw-markup composition."""
    values = tuple(artifacts)
    if not values:
        return _safe("")
    return _safe(
        '<div class="ui-artifacts" aria-label="Files">'
        f'{_join(_render_artifact(item) for item in values)}</div>'
    )


def render_activity(activity: UIActivity) -> SafeHtml:
    status = activity.status or UIStatus(
        {
            "queued": "Queued", "working": "Working", "succeeded": "Completed",
            "failed": "Failed", "denied": "Permission required", "stale": "Out of date",
            "cancelled": "Cancelled",
        }[activity.state],
        {"succeeded": "success", "failed": "danger", "denied": "warning", "stale": "warning"}.get(activity.state, "neutral"),
    )
    state_label = "polite" if activity.state in {"queued", "working"} else "off"
    target = f'<p class="ui-activity-target">{_e(activity.target_entity)}</p>' if activity.target_entity else ""
    summary = f'<p class="ui-activity-summary">{_e(activity.summary)}</p>' if activity.summary else ""
    source = f'<p class="ui-source-effect">{_e(activity.source_effect_summary)}</p>' if activity.source_effect_summary else ""
    artifacts = render_artifacts(activity.artifacts)
    actions = []
    if activity.primary_action:
        actions.append(activity.primary_action)
    actions.extend(activity.secondary_actions)
    action_html = render_actions(actions, label="Activity actions") if actions else _safe("")
    technical = activity.technical_details + activity.timestamps
    return _safe(
        f'<article class="ui-activity result-card ui-activity--{_e(activity.state)}" data-activity-state="{_e(activity.state)}" '
        f'aria-label="Verified result" data-application-label="{_e(activity.application_title)}" aria-live="{state_label}">'
        '<header class="ui-activity-header">'
        f'<div><p class="ui-kicker result-app">{_e(activity.application_title)}</p>'
        f'<h2>{_e(activity.headline)}</h2></div>{render_status(status)}</header>'
        f'{target}{summary}<div class="result-facts">{render_facts(activity.important_facts)}</div>{source}{artifacts}'
        f'<div class="result-actions">{action_html}</div>{render_technical_details(technical)}</article>'
    )


def render_notice(notice: UINotice) -> SafeHtml:
    did_not = (
        f'<p class="ui-notice-boundary"><strong>What did not happen</strong><br>{_e(notice.what_did_not_happen)}</p>'
        if notice.what_did_not_happen else ""
    )
    action = render_action(notice.next_action) if notice.next_action else _safe("")
    return _safe(
        f'<aside class="ui-notice ui-notice--{_e(notice.kind)}" role="{("alert" if notice.kind == "error" else "status")}">'
        f'<div class="ui-notice-mark" aria-hidden="true"></div><div class="ui-notice-content">'
        f'<h2>{_e(notice.title)}</h2><p>{_e(notice.explanation)}</p>{did_not}{action}'
        f'{render_technical_details(notice.technical_details)}</div></aside>'
    )


def render_page_header(
    eyebrow: str,
    title: str,
    introduction: str = "",
    *,
    status: UIStatus | None = None,
    return_action: UIAction | None = None,
) -> SafeHtml:
    back = f'<div class="ui-page-return">{render_action(return_action)}</div>' if return_action else ""
    intro = f'<p class="ui-page-intro">{_e(introduction)}</p>' if introduction else ""
    state = f'<div class="ui-page-status">{render_status(status)}</div>' if status else ""
    return _safe(
        f'<header class="ui-page-header">{back}<div class="ui-page-heading"><p class="ui-kicker">{_e(eyebrow)}</p>'
        f'<h1>{_e(title)}</h1>{intro}</div>{state}</header>'
    )


def render_message(
    role: str,
    body: str,
    *,
    working: bool = False,
    content: SafeHtml | None = None,
    supplements: Iterable[SafeHtml] = (),
) -> SafeHtml:
    if role not in {"user", "assistant"}:
        raise ValueError("message role is invalid")
    speaker = "You" if role == "user" else "Capy"
    supplement_values = tuple(supplements)
    if any(not isinstance(item, SafeHtml) for item in supplement_values):
        raise TypeError("message supplements must be trusted renderer output")
    if working:
        visible = (
            '<div class="ui-working" role="status" aria-live="polite">'
            '<span class="ui-working-mark" aria-hidden="true"></span>'
            f'<p><strong>Working</strong>{_e(body)}</p></div>'
        )
    elif content is not None:
        if not isinstance(content, SafeHtml):
            raise TypeError("message content must be trusted renderer output")
        visible = str(content)
    else:
        visible = f'<div class="ui-message-body message-body">{_e(body)}</div>' if body else ""
    visible += str(_join(supplement_values))
    return _safe(
        f'<section class="ui-message message {"owner" if role == "user" else "assistant"} ui-message--{_e(role)}">'
        f'<p class="ui-speaker speaker">{speaker}</p>{visible}</section>'
    )


def render_entity(entity: UIEntity) -> SafeHtml:
    state = " selected" if entity.selected else ""
    disabled = " disabled" if entity.disabled_reason else ""
    status = render_status(entity.status) if entity.status else _safe("")
    subtitle = f'<p class="ui-entity-subtitle">{_e(entity.subtitle)}</p>' if entity.subtitle else ""
    actions = []
    if entity.primary_action:
        actions.append(entity.primary_action)
    actions.extend(entity.secondary_actions)
    reason = f'<p class="ui-entity-disabled">{_e(entity.disabled_reason)}</p>' if entity.disabled_reason else ""
    return _safe(
        f'<article class="ui-entity{state}{disabled}" data-entity-ref="{_e(entity.reference)}">'
        f'<div class="ui-entity-copy"><div class="ui-entity-title-row"><h3>{_e(entity.title)}</h3>{status}</div>'
        f'{subtitle}{render_facts(entity.primary_facts, class_name="ui-entity-facts")}'
        f'<div class="ui-entity-secondary">{render_facts(entity.secondary_facts, class_name="ui-entity-facts")}</div>{reason}</div>'
        f'{render_actions(actions, label="Record actions") if actions else ""}</article>'
    )


def render_collection(collection: UICollection) -> SafeHtml:
    header_actions = render_action(collection.primary_action) if collection.primary_action else _safe("")
    controls = _join(render_field(item) for item in collection.controls)
    body = _join(render_entity(item) for item in collection.entities) if collection.entities else render_notice(collection.empty_state)
    inspector = render_inspector(collection.selected_entity.inspector) if collection.selected_entity and collection.selected_entity.inspector else _safe("")
    return _safe(
        '<section class="ui-pattern ui-collection"><header class="ui-pattern-header">'
        f'<div><p class="ui-kicker">Collection</p><h2>{_e(collection.title)}</h2>'
        f'<p>{collection.count} {"record" if collection.count == 1 else "records"}</p></div>{header_actions}</header>'
        f'{f"<div class=\"ui-collection-controls\">{controls}</div>" if controls else ""}'
        f'<div class="ui-workbench"><div class="ui-entity-list">{body}</div>{inspector}</div></section>'
    )


def render_inspector(inspector: UIInspector | None) -> SafeHtml:
    if inspector is None:
        return _safe("")
    sections = "".join(
        f'<section class="ui-inspector-section"><h3>{_e(section.title)}</h3>'
        f'{f"<p>{_e(section.body)}</p>" if section.body else ""}{render_facts(section.facts)}</section>'
        for section in inspector.sections
    )
    authority = (
        f'<section class="ui-inspector-section"><h3>Access</h3><p>{_e(inspector.authority_explanation)}</p></section>'
        if inspector.authority_explanation else ""
    )
    danger = (
        f'<section class="ui-inspector-danger"><h3>{_e(inspector.danger_section.title)}</h3>'
        f'<p>{_e(inspector.danger_section.body or "")}</p></section>'
        if inspector.danger_section else ""
    )
    actions = list(inspector.secondary_actions)
    if inspector.return_action:
        actions.insert(0, inspector.return_action)
    return _safe(
        '<aside class="ui-inspector" data-inspector aria-label="Details"><header>'
        '<div><p class="ui-kicker">Details</p>'
        f'<h2>{_e(inspector.title)}</h2></div><button class="ui-inspector-close ui-action ui-action--quiet" '
        'type="button" data-close-inspector aria-label="Close details">Close</button></header>'
        f'{sections}{authority}'
        f'{render_actions(actions, label="Detail actions") if actions else ""}'
        f'{render_technical_details(inspector.technical_details)}{danger}</aside>'
    )


def render_field(field: UIField) -> SafeHtml:
    field_id = _e(field.field_id)
    required = " required" if field.required else ""
    disabled = " disabled" if not field.enabled else ""
    readonly = " readonly" if field.read_only else ""
    invalid = ' aria-invalid="true"' if field.validation_state == "invalid" else ""
    help_id = f"{field_id}-help"
    described = f' aria-describedby="{help_id}"' if field.help_text or field.validation_message else ""
    placeholder = f' placeholder="{_e(field.placeholder)}"' if field.placeholder is not None else ""
    if field.input_type == "long_text":
        control = f'<textarea id="{field_id}" name="{field_id}"{required}{disabled}{readonly}{invalid}{described}{placeholder}>{_e(field.current_value)}</textarea>'
    elif field.input_type == "choice" and field.options:
        options = "".join(
            f'<option value="{_e(value)}"{" selected" if value == field.current_value else ""}>{_e(label)}</option>'
            for value, label in field.options
        )
        control = f'<select id="{field_id}" name="{field_id}"{required}{disabled}{described}>{options}</select>'
    else:
        input_type = {"number":"number","date":"date","file":"file","hidden":"hidden"}.get(field.input_type, "text")
        value = "" if input_type == "file" else f' value="{_e(field.current_value)}"'
        accept = f' accept="{_e(field.accept)}"' if field.accept else ""
        control = f'<input id="{field_id}" name="{field_id}" type="{input_type}"{value}{required}{disabled}{readonly}{invalid}{described}{placeholder}{accept}>'
    semantic = field.semantic.replace("-", " ").capitalize()
    help_text = " · ".join(item for item in (field.help_text, semantic) if item)
    if field.validation_message:
        help_text = " · ".join(item for item in (field.validation_message, help_text) if item)
    help_html = f'<small id="{help_id}" class="ui-field-help">{_e(help_text)}</small>' if help_text else ""
    required_text = '<span class="ui-required">Required</span>' if field.required else '<span class="ui-optional">Optional</span>'
    return _safe(
        f'<div class="ui-field ui-field--{_e(field.validation_state)} ui-field--{_e(field.semantic)}">'
        f'<label for="{field_id}"><span>{_e(field.label)}</span>{required_text}</label>{control}{help_html}</div>'
    )


def render_form(form: UIForm) -> SafeHtml:
    fields = "".join(
        f'<fieldset class="ui-field-group"><legend>{_e(group.title)}</legend>'
        f'{f"<p>{_e(group.description)}</p>" if group.description else ""}'
        f'{_join(render_field(field) for field in group.fields)}</fieldset>'
        for group in form.field_groups
    )
    summary = (
        f'<div class="ui-validation-summary" role="alert"><strong>Review the highlighted fields</strong><p>{_e(form.validation_summary)}</p></div>'
        if form.validation_summary else ""
    )
    cancel = render_action(form.cancel_action) if form.cancel_action else _safe("")
    submit = form.submit_action
    hidden = "".join(
        f'<input type="hidden" name="{_e(name)}" value="{_e(value)}">'
        for name, value in submit.form_fields
    )
    return _safe(
        '<section class="ui-pattern ui-form-workflow"><header class="ui-pattern-header"><div>'
        f'<p class="ui-kicker">Form</p><h2>{_e(form.task_title)}</h2><p>{_e(form.purpose)}</p></div></header>'
        f'{render_facts(form.context_values, class_name="ui-context-facts")}{summary}'
        f'<form data-protect-draft method="post" enctype="multipart/form-data" action="{_e(submit.form_action)}">'
        f'{hidden}{fields}<div class="ui-form-actions">{cancel}'
        f'<button class="ui-action ui-action--primary" data-action-id="{_e(submit.action_id)}">{_e(submit.label)}</button>'
        '</div></form></section>'
    )


def render_confirmation(confirmation: UIConfirmation) -> SafeHtml:
    hidden = "".join(
        f'<input type="hidden" name="{_e(name)}" value="{_e(value)}">'
        for name, value in confirmation.form_fields
    )
    danger_class = " ui-confirmation--danger" if confirmation.danger_level == "destructive" else ""
    return _safe(
        f'<details class="ui-confirmation{danger_class}" data-confirmation><summary>{_e(confirmation.title)}</summary>'
        f'<div><p>{_e(confirmation.consequence)}</p>{render_facts(confirmation.preserved_facts)}'
        f'<form method="post" enctype="multipart/form-data" action="{_e(confirmation.form_action)}">{hidden}'
        '<div class="ui-confirm-check"><label><input type="checkbox" name="confirm" value="delete" required> '
        f'{_e(confirmation.confirm_label)}</label></div><div class="ui-actions-main">'
        f'<button class="ui-action ui-action--danger">{_e(confirmation.confirm_label)}</button>'
        f'<button class="ui-action ui-action--quiet" type="button" data-close-confirmation>{_e(confirmation.cancel_label)}</button>'
        '</div></form></div></details>'
    )
