"""Strict, immutable view models for the private workbench renderer."""

from __future__ import annotations

import re
import urllib.parse
from dataclasses import dataclass, field


_IDENTITY = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}")
_METHODS = frozenset({"GET", "POST"})
_HIERARCHIES = frozenset({"primary", "secondary", "quiet", "danger"})
_TONES = frozenset({"neutral", "info", "success", "warning", "danger"})
_IMPORTANCE = frozenset({"primary", "secondary", "technical"})
_ACTIVITY_STATES = frozenset({"queued", "working", "succeeded", "failed", "denied", "stale", "cancelled"})
_NOTICE_KINDS = frozenset({"info", "success", "warning", "error", "permission", "stale", "unsupported", "empty"})
_WORKSPACE_KINDS = frozenset({"personal", "team"})
_FIELD_SEMANTICS = frozenset({"enforced", "preference", "context-derived", "presentation-only"})
_VALIDATION_STATES = frozenset({"none", "valid", "invalid"})
_ARTIFACT_STATES = frozenset({"ready", "denied", "missing", "stale"})
_INPUT_TYPES = frozenset({"text", "long_text", "number", "date", "choice", "file", "hidden"})


def _text(value: object, name: str, maximum: int = 512, *, empty: bool = False) -> str:
    if not isinstance(value, str):
        raise TypeError(f"{name} must be text")
    clean = " ".join(value.split())
    if not clean and not empty:
        raise ValueError(f"{name} is required")
    if len(clean) > maximum:
        raise ValueError(f"{name} is too long")
    return clean


def _identity(value: str, name: str) -> str:
    clean = _text(value, name, 128)
    if not _IDENTITY.fullmatch(clean):
        raise ValueError(f"{name} is invalid")
    return clean


def _internal_path(value: str, name: str) -> str:
    clean = _text(value, name, 2048)
    parsed = urllib.parse.urlsplit(clean)
    if not clean.startswith("/") or clean.startswith("//") or parsed.scheme or parsed.netloc:
        raise ValueError(f"{name} must be an internal path")
    return clean


def _tuple_of(value: object, item_type: type, name: str) -> tuple:
    if not isinstance(value, tuple):
        raise TypeError(f"{name} must be a tuple")
    if any(not isinstance(item, item_type) for item in value):
        raise TypeError(f"{name} contains an invalid item")
    return value


def _optional(value: object, item_type: type, name: str) -> None:
    if value is not None and not isinstance(value, item_type):
        raise TypeError(f"{name} has an invalid type")


def _required(value: object, item_type: type, name: str) -> None:
    if not isinstance(value, item_type):
        raise TypeError(f"{name} has an invalid type")


def _boolean(value: object, name: str) -> None:
    if not isinstance(value, bool):
        raise TypeError(f"{name} must be boolean")


@dataclass(frozen=True)
class UINavItem:
    item_id: str
    label: str
    href: str
    current: bool = False
    disabled_reason: str | None = None
    compact: bool = False

    def __post_init__(self) -> None:
        object.__setattr__(self, "item_id", _identity(self.item_id, "item_id"))
        object.__setattr__(self, "label", _text(self.label, "label", 96))
        object.__setattr__(self, "href", _internal_path(self.href, "href"))
        _boolean(self.current, "current")
        _boolean(self.compact, "compact")
        if self.disabled_reason is not None:
            object.__setattr__(self, "disabled_reason", _text(self.disabled_reason, "disabled_reason", 240))


@dataclass(frozen=True)
class UIContext:
    principal_display_name: str
    workspace_display_name: str
    workspace_kind: str
    current_destination: str
    navigation_items: tuple[UINavItem, ...]
    recent_items: tuple[UINavItem, ...] = ()
    current_application: str | None = None
    current_conversation: str | None = None
    return_target: UINavItem | None = None
    application_items: tuple[UINavItem, ...] = ()
    account_item: UINavItem | None = None
    client_label: str = ""

    def __post_init__(self) -> None:
        object.__setattr__(self, "principal_display_name", _text(self.principal_display_name, "principal_display_name", 120))
        object.__setattr__(self, "workspace_display_name", _text(self.workspace_display_name, "workspace_display_name", 120))
        if self.workspace_kind not in _WORKSPACE_KINDS:
            raise ValueError("workspace_kind is invalid")
        object.__setattr__(self, "current_destination", _identity(self.current_destination, "current_destination"))
        _tuple_of(self.navigation_items, UINavItem, "navigation_items")
        _tuple_of(self.recent_items, UINavItem, "recent_items")
        _tuple_of(self.application_items, UINavItem, "application_items")
        _optional(self.return_target, UINavItem, "return_target")
        _optional(self.account_item, UINavItem, "account_item")
        if self.current_application is not None:
            object.__setattr__(self, "current_application", _text(self.current_application, "current_application", 160))
        if self.current_conversation is not None:
            object.__setattr__(self, "current_conversation", _text(self.current_conversation, "current_conversation", 160))
        object.__setattr__(self, "client_label", _text(self.client_label, "client_label", 120, empty=True))


@dataclass(frozen=True)
class UIAction:
    action_id: str
    label: str
    href: str | None = None
    form_action: str | None = None
    method: str = "GET"
    hierarchy: str = "secondary"
    enabled: bool = True
    disabled_reason: str | None = None
    requires_confirmation: bool = False
    loading_label: str | None = None
    icon_key: str | None = None
    form_fields: tuple[tuple[str, str], ...] = ()
    external: bool = False
    encoding: str = "urlencoded"

    def __post_init__(self) -> None:
        object.__setattr__(self, "action_id", _identity(self.action_id, "action_id"))
        object.__setattr__(self, "label", _text(self.label, "label", 96))
        if self.method not in _METHODS:
            raise ValueError("method is invalid")
        if self.hierarchy not in _HIERARCHIES:
            raise ValueError("hierarchy is invalid")
        if self.encoding not in {"urlencoded", "multipart"}:
            raise ValueError("encoding is invalid")
        _boolean(self.enabled, "enabled")
        _boolean(self.requires_confirmation, "requires_confirmation")
        _boolean(self.external, "external")
        if self.href is not None:
            if self.external:
                parsed = urllib.parse.urlsplit(self.href)
                if parsed.scheme != "https" or not parsed.netloc:
                    raise ValueError("external href must use HTTPS")
            else:
                object.__setattr__(self, "href", _internal_path(self.href, "href"))
        if self.form_action is not None:
            object.__setattr__(self, "form_action", _internal_path(self.form_action, "form_action"))
        if self.enabled:
            if self.method == "GET" and self.href is None:
                raise ValueError("enabled GET action requires href")
            if self.method == "POST" and self.form_action is None:
                raise ValueError("enabled POST action requires form_action")
        if self.method == "GET" and self.form_action is not None:
            raise ValueError("GET action cannot have form_action")
        if self.method == "POST" and self.href is not None:
            raise ValueError("POST action cannot have href")
        if self.method == "GET" and self.encoding != "urlencoded":
            raise ValueError("GET action cannot set an encoding")
        if not self.enabled and self.disabled_reason is None:
            raise ValueError("disabled action requires a reason")
        if self.disabled_reason is not None:
            object.__setattr__(self, "disabled_reason", _text(self.disabled_reason, "disabled_reason", 240))
        if self.loading_label is not None:
            object.__setattr__(self, "loading_label", _text(self.loading_label, "loading_label", 96))
        if self.icon_key is not None:
            object.__setattr__(self, "icon_key", _identity(self.icon_key, "icon_key"))
        if not isinstance(self.form_fields, tuple):
            raise TypeError("form_fields must be a tuple")
        normalized = []
        for item in self.form_fields:
            if not isinstance(item, tuple) or len(item) != 2:
                raise TypeError("form_fields contains an invalid item")
            name, value = item
            normalized.append((_identity(name, "form field name"), _text(value, "form field value", 4096, empty=True)))
        object.__setattr__(self, "form_fields", tuple(normalized))


@dataclass(frozen=True)
class UIStatus:
    label: str
    tone: str = "neutral"
    detail: str | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "label", _text(self.label, "status label", 96))
        if self.tone not in _TONES:
            raise ValueError("status tone is invalid")
        if self.detail is not None:
            object.__setattr__(self, "detail", _text(self.detail, "status detail", 240))


@dataclass(frozen=True)
class UIFact:
    label: str
    value: str
    importance: str = "secondary"
    sort_value: str | int | float | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "label", _text(self.label, "fact label", 96))
        object.__setattr__(self, "value", _text(self.value, "fact value", 512, empty=True) or "Not available")
        if self.importance not in _IMPORTANCE:
            raise ValueError("fact importance is invalid")
        if isinstance(self.sort_value, bool) or self.sort_value is not None and not isinstance(self.sort_value, (str, int, float)):
            raise TypeError("sort_value is invalid")


@dataclass(frozen=True)
class UIArtifact:
    label: str
    href: str | None
    state: str = "ready"

    def __post_init__(self) -> None:
        object.__setattr__(self, "label", _text(self.label, "artifact label", 180))
        if self.state not in _ARTIFACT_STATES:
            raise ValueError("artifact state is invalid")
        if self.href is not None:
            object.__setattr__(self, "href", _internal_path(self.href, "artifact href"))
        if self.state == "ready" and self.href is None:
            raise ValueError("ready artifact requires href")


@dataclass(frozen=True)
class UIActivity:
    application_identity: str | None
    application_title: str
    operation_identity: str | None
    state: str
    headline: str
    summary: str
    activity_identity: str | None = None
    target_entity: str | None = None
    status: UIStatus | None = None
    important_facts: tuple[UIFact, ...] = ()
    artifacts: tuple[UIArtifact, ...] = ()
    primary_action: UIAction | None = None
    secondary_actions: tuple[UIAction, ...] = ()
    technical_details: tuple[UIFact, ...] = ()
    timestamps: tuple[UIFact, ...] = ()
    source_effect_summary: str | None = None

    def __post_init__(self) -> None:
        if self.application_identity is not None:
            object.__setattr__(self, "application_identity", _text(self.application_identity, "application_identity", 180))
        object.__setattr__(self, "application_title", _text(self.application_title, "application_title", 180))
        if self.operation_identity is not None:
            object.__setattr__(self, "operation_identity", _text(self.operation_identity, "operation_identity", 180))
        if self.state not in _ACTIVITY_STATES:
            raise ValueError("activity state is invalid")
        object.__setattr__(self, "headline", _text(self.headline, "headline", 240))
        object.__setattr__(self, "summary", _text(self.summary, "summary", 720, empty=True))
        if self.activity_identity is not None:
            object.__setattr__(self, "activity_identity", _text(self.activity_identity, "activity_identity", 180))
        if self.target_entity is not None:
            object.__setattr__(self, "target_entity", _text(self.target_entity, "target_entity", 240))
        _optional(self.status, UIStatus, "status")
        _tuple_of(self.important_facts, UIFact, "important_facts")
        _tuple_of(self.artifacts, UIArtifact, "artifacts")
        _optional(self.primary_action, UIAction, "primary_action")
        _tuple_of(self.secondary_actions, UIAction, "secondary_actions")
        _tuple_of(self.technical_details, UIFact, "technical_details")
        _tuple_of(self.timestamps, UIFact, "timestamps")
        actions = ((self.primary_action,) if self.primary_action else ()) + self.secondary_actions
        if sum(action.hierarchy == "primary" for action in actions) > 1:
            raise ValueError("activity has more than one primary action")
        if self.primary_action is not None and self.primary_action.hierarchy != "primary":
            raise ValueError("primary_action must use primary hierarchy")
        if self.source_effect_summary is not None:
            object.__setattr__(self, "source_effect_summary", _text(self.source_effect_summary, "source_effect_summary", 480))

    @property
    def application_id(self) -> str | None:
        """Compatibility read for the former presentation DTO."""
        return self.application_identity

    @property
    def facts(self) -> tuple[tuple[str, str], ...]:
        return tuple((fact.label, fact.value) for fact in self.important_facts)

    @property
    def primary_label(self) -> str | None:
        return self.primary_action.label if self.primary_action else None

    @property
    def primary_href(self) -> str | None:
        return self.primary_action.href if self.primary_action else None


@dataclass(frozen=True)
class UISection:
    title: str
    facts: tuple[UIFact, ...] = ()
    body: str | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "title", _text(self.title, "section title", 160))
        _tuple_of(self.facts, UIFact, "section facts")
        if self.body is not None:
            object.__setattr__(self, "body", _text(self.body, "section body", 1200, empty=True))


@dataclass(frozen=True)
class UIInspector:
    title: str
    sections: tuple[UISection, ...]
    secondary_actions: tuple[UIAction, ...] = ()
    authority_explanation: str | None = None
    technical_details: tuple[UIFact, ...] = ()
    danger_section: UISection | None = None
    return_action: UIAction | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "title", _text(self.title, "inspector title", 180))
        _tuple_of(self.sections, UISection, "inspector sections")
        _tuple_of(self.secondary_actions, UIAction, "inspector secondary_actions")
        _tuple_of(self.technical_details, UIFact, "inspector technical_details")
        _optional(self.danger_section, UISection, "danger_section")
        _optional(self.return_action, UIAction, "return_action")
        if self.authority_explanation is not None:
            object.__setattr__(self, "authority_explanation", _text(self.authority_explanation, "authority_explanation", 720))


@dataclass(frozen=True)
class UIEntity:
    reference: str
    title: str
    subtitle: str = ""
    status: UIStatus | None = None
    primary_facts: tuple[UIFact, ...] = ()
    secondary_facts: tuple[UIFact, ...] = ()
    primary_action: UIAction | None = None
    secondary_actions: tuple[UIAction, ...] = ()
    inspector: UIInspector | None = None
    selected: bool = False
    disabled_reason: str | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "reference", _identity(self.reference, "entity reference"))
        object.__setattr__(self, "title", _text(self.title, "entity title", 240))
        object.__setattr__(self, "subtitle", _text(self.subtitle, "entity subtitle", 360, empty=True))
        _boolean(self.selected, "entity selected")
        _optional(self.status, UIStatus, "entity status")
        _tuple_of(self.primary_facts, UIFact, "entity primary_facts")
        _tuple_of(self.secondary_facts, UIFact, "entity secondary_facts")
        _optional(self.primary_action, UIAction, "entity primary_action")
        _tuple_of(self.secondary_actions, UIAction, "entity secondary_actions")
        _optional(self.inspector, UIInspector, "entity inspector")
        actions = ((self.primary_action,) if self.primary_action else ()) + self.secondary_actions
        if sum(action.hierarchy == "primary" for action in actions) > 1:
            raise ValueError("entity has more than one primary action")
        if self.disabled_reason is not None:
            object.__setattr__(self, "disabled_reason", _text(self.disabled_reason, "disabled_reason", 240))


@dataclass(frozen=True)
class UINotice:
    kind: str
    title: str
    explanation: str
    what_did_not_happen: str | None = None
    next_action: UIAction | None = None
    technical_details: tuple[UIFact, ...] = ()

    def __post_init__(self) -> None:
        if self.kind not in _NOTICE_KINDS:
            raise ValueError("notice kind is invalid")
        object.__setattr__(self, "title", _text(self.title, "notice title", 200))
        object.__setattr__(self, "explanation", _text(self.explanation, "notice explanation", 900, empty=True))
        if self.what_did_not_happen is not None:
            object.__setattr__(self, "what_did_not_happen", _text(self.what_did_not_happen, "what_did_not_happen", 480))
        _optional(self.next_action, UIAction, "notice next_action")
        _tuple_of(self.technical_details, UIFact, "notice technical_details")


@dataclass(frozen=True)
class UICollection:
    title: str
    count: int
    entities: tuple[UIEntity, ...]
    empty_state: UINotice
    selected_entity: UIEntity | None = None
    primary_action: UIAction | None = None
    controls: tuple[UIField, ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(self, "title", _text(self.title, "collection title", 180))
        if isinstance(self.count, bool) or not isinstance(self.count, int):
            raise TypeError("collection count must be an integer")
        _tuple_of(self.entities, UIEntity, "collection entities")
        _required(self.empty_state, UINotice, "collection empty_state")
        _optional(self.selected_entity, UIEntity, "collection selected_entity")
        _optional(self.primary_action, UIAction, "collection primary_action")
        _tuple_of(self.controls, UIField, "collection controls")
        if self.count < 0 or self.count != len(self.entities):
            raise ValueError("collection count does not match entities")


@dataclass(frozen=True)
class UIField:
    field_id: str
    label: str
    input_type: str
    required: bool = False
    current_value: str = ""
    placeholder: str | None = None
    help_text: str | None = None
    validation_state: str = "none"
    validation_message: str | None = None
    semantic: str = "enforced"
    enabled: bool = True
    read_only: bool = False
    options: tuple[tuple[str, str], ...] = ()
    accept: str | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "field_id", _identity(self.field_id, "field_id"))
        object.__setattr__(self, "label", _text(self.label, "field label", 160))
        if self.input_type not in _INPUT_TYPES:
            raise ValueError("input_type is invalid")
        _boolean(self.required, "field required")
        _boolean(self.enabled, "field enabled")
        _boolean(self.read_only, "field read_only")
        object.__setattr__(self, "current_value", _text(self.current_value, "current_value", 4096, empty=True))
        if self.placeholder is not None:
            object.__setattr__(self, "placeholder", _text(self.placeholder, "placeholder", 240, empty=True))
        if self.help_text is not None:
            object.__setattr__(self, "help_text", _text(self.help_text, "help_text", 600, empty=True))
        if self.validation_state not in _VALIDATION_STATES:
            raise ValueError("validation_state is invalid")
        if self.validation_state == "invalid" and not self.validation_message:
            raise ValueError("invalid field requires validation_message")
        if self.validation_message is not None:
            object.__setattr__(self, "validation_message", _text(self.validation_message, "validation_message", 360))
        if self.semantic not in _FIELD_SEMANTICS:
            raise ValueError("field semantic is invalid")
        if not isinstance(self.options, tuple):
            raise TypeError("options must be a tuple")
        normalized = []
        for item in self.options:
            if not isinstance(item, tuple) or len(item) != 2:
                raise TypeError("options contains an invalid item")
            value, label = item
            normalized.append((_text(value, "option value", 160, empty=True), _text(label, "option label", 160)))
        object.__setattr__(self, "options", tuple(normalized))
        if self.accept is not None:
            object.__setattr__(self, "accept", _text(self.accept, "accept", 240))


@dataclass(frozen=True)
class UIFieldGroup:
    title: str
    fields: tuple[UIField, ...]
    description: str = ""

    def __post_init__(self) -> None:
        object.__setattr__(self, "title", _text(self.title, "field group title", 160))
        _tuple_of(self.fields, UIField, "field group fields")
        object.__setattr__(self, "description", _text(self.description, "field group description", 480, empty=True))


@dataclass(frozen=True)
class UIForm:
    task_title: str
    purpose: str
    field_groups: tuple[UIFieldGroup, ...]
    submit_action: UIAction
    context_values: tuple[UIFact, ...] = ()
    validation_summary: str | None = None
    cancel_action: UIAction | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "task_title", _text(self.task_title, "task_title", 200))
        object.__setattr__(self, "purpose", _text(self.purpose, "purpose", 720, empty=True))
        _tuple_of(self.field_groups, UIFieldGroup, "form field_groups")
        _required(self.submit_action, UIAction, "form submit_action")
        _tuple_of(self.context_values, UIFact, "form context_values")
        _optional(self.cancel_action, UIAction, "form cancel_action")
        if self.submit_action.method != "POST" or self.submit_action.hierarchy != "primary":
            raise ValueError("submit_action must be a primary POST action")
        if self.validation_summary is not None:
            object.__setattr__(self, "validation_summary", _text(self.validation_summary, "validation_summary", 720))


@dataclass(frozen=True)
class UIConfirmation:
    title: str
    consequence: str
    preserved_facts: tuple[UIFact, ...]
    confirm_label: str
    cancel_label: str
    danger_level: str
    form_action: str
    form_fields: tuple[tuple[str, str], ...] = field(default_factory=tuple)

    def __post_init__(self) -> None:
        object.__setattr__(self, "title", _text(self.title, "confirmation title", 180))
        object.__setattr__(self, "consequence", _text(self.consequence, "confirmation consequence", 720))
        object.__setattr__(self, "confirm_label", _text(self.confirm_label, "confirm_label", 96))
        object.__setattr__(self, "cancel_label", _text(self.cancel_label, "cancel_label", 96))
        _tuple_of(self.preserved_facts, UIFact, "confirmation preserved_facts")
        if self.danger_level not in {"ordinary", "destructive"}:
            raise ValueError("danger_level is invalid")
        object.__setattr__(self, "form_action", _internal_path(self.form_action, "form_action"))
        if not isinstance(self.form_fields, tuple):
            raise TypeError("confirmation form_fields must be a tuple")
        normalized = []
        for item in self.form_fields:
            if not isinstance(item, tuple) or len(item) != 2:
                raise TypeError("confirmation form_fields contains an invalid item")
            name, value = item
            normalized.append((_identity(name, "form field name"), _text(value, "form field value", 4096, empty=True)))
        object.__setattr__(self, "form_fields", tuple(normalized))
