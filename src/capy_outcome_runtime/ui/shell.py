"""One canonical responsive product shell."""

from __future__ import annotations

import html
from typing import Literal

from .assets import STANDARD_SCRIPT, WORKBENCH_CSS
from .enhancements import ENHANCEMENTS
from .models import UIAction, UIContext
from .render import SafeHtml, StylesheetExtension, _safe


def _nav(items, *, label: str, nested: bool = False, recent: bool = False) -> str:
    classes = "ui-nav-item nav-link"
    if nested:
        classes += " ui-nav-item--nested"
    if recent:
        classes += " ui-nav-item--recent conversation"
    rows = []
    for item in items:
        current = ' aria-current="page"' if item.current else ""
        if item.disabled_reason:
            rows.append(
                f'<span class="{classes} ui-nav-item--disabled" aria-disabled="true" '
                f'title="{html.escape(item.disabled_reason)}">{html.escape(item.label)}</span>'
            )
            continue
        rows.append(
            f'<a class="{classes}" href="{html.escape(item.href)}"{current}>{html.escape(item.label)}</a>'
        )
    return f'<nav class="ui-nav-group" aria-label="{html.escape(label)}">{"".join(rows)}</nav>'


def render_workspace_switcher(
    workspaces: tuple[tuple[str, str], ...],
    *,
    current_membership_id: str,
    current_name: str,
    workspace_kind: str,
    csrf_token: str,
) -> SafeHtml:
    """Render the trusted desktop workspace control without putting credentials in UIContext."""
    options = "".join(
        f'<option value="{html.escape(membership_id)}"'
        f'{" selected" if membership_id == current_membership_id else ""}>{html.escape(label)}</option>'
        for membership_id, label in workspaces
    )
    return _safe(
        '<form class="ui-workspace ui-workspace-picker workspace-picker" data-workspace-switcher '
        'aria-label="Working in current workspace" method="post" action="/workspaces/activate">'
        f'<input type="hidden" name="csrf" value="{html.escape(csrf_token)}">'
        '<span class="ui-workspace-label workspace-label">Current workspace</span>'
        f'<strong class="ui-workspace-name workspace-name">{html.escape(current_name)} · {html.escape(workspace_kind.title())}</strong>'
        f'<label><span class="ui-sr-only skip-link">Choose workspace</span><select name="workspace">{options}</select></label>'
        '<button class="ui-action ui-action--secondary workspace-submit">Use workspace</button></form>'
    )


def render_mobile_workspace_switcher(
    workspaces: tuple[tuple[str, str], ...], *, csrf_token: str
) -> SafeHtml:
    buttons = "".join(
        '<form method="post" action="/workspaces/activate">'
        f'<input type="hidden" name="csrf" value="{html.escape(csrf_token)}">'
        f'<input type="hidden" name="workspace" value="{html.escape(membership_id)}">'
        f'<button class="ui-action ui-action--secondary">{html.escape(label)}</button></form>'
        for membership_id, label in workspaces
    )
    return _safe(
        '<div class="ui-mobile-workspaces mobile-workspaces"><p class="ui-nav-label nav-heading">Switch workspace</p>'
        f'{buttons}</div>'
    )


def render_shell_action(action: UIAction) -> SafeHtml:
    """Render a rail action using the standard action grammar."""
    from .render import render_action

    return render_action(action)


def render_shell(
    context: UIContext,
    *,
    title: str,
    body: SafeHtml,
    workspace_switcher: SafeHtml,
    mobile_workspace_switcher: SafeHtml,
    new_item_action: SafeHtml,
    account_item: SafeHtml,
    stylesheet_extension: StylesheetExtension | None = None,
    main_wide: bool = False,
    enhancement: Literal["none", "chat", "form-protection"] = "none",
) -> SafeHtml:
    if not all(isinstance(value, SafeHtml) for value in (body, workspace_switcher, mobile_workspace_switcher, new_item_action, account_item)):
        raise TypeError("shell fragments must come from trusted renderers")
    primary = _nav(context.navigation_items, label="Primary")
    applications = _nav(context.application_items, label="Installed applications", nested=True)
    recent = _nav(context.recent_items, label="Recent conversations", recent=True)
    desktop = (
        '<div class="ui-nav-content nav-content">'
        f'{workspace_switcher}{primary}{applications}{new_item_action}'
        '<p class="ui-nav-label nav-heading">Recent</p>'
        f'{recent}<div class="ui-nav-spacer"></div><div class="ui-rail-footer sidebar-footer">{account_item}'
        f'<div class="ui-identity identity"><strong>{html.escape(context.principal_display_name)}</strong>'
        f'{html.escape(context.client_label)}</div></div></div>'
    )
    mobile = (
        '<div class="ui-nav-content nav-content">'
        f'{mobile_workspace_switcher}{primary}{applications}{new_item_action}'
        '<p class="ui-nav-label nav-heading">Recent</p>'
        f'{recent}<div class="ui-rail-footer sidebar-footer">{account_item}</div></div>'
    )
    wide = " ui-content--wide" if main_wide else ""
    if enhancement not in ENHANCEMENTS:
        raise ValueError("unknown enhancement")
    if stylesheet_extension is not None and not isinstance(stylesheet_extension, StylesheetExtension):
        raise TypeError("stylesheet extension must be an approved renderer capability")
    compatibility_css = str(stylesheet_extension or "")
    script = STANDARD_SCRIPT + ENHANCEMENTS[enhancement]
    return _safe(
        '<!doctype html><html lang="en"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width,initial-scale=1">'
        f'<meta name="description" content="{html.escape(title)} in Capy"><title>{html.escape(title)} · Capy</title>'
        f'<style>{WORKBENCH_CSS}{compatibility_css}</style></head><body>'
        '<a class="ui-skip-link skip-link" href="#main-content">Skip to content</a><div class="ui-shell shell">'
        '<header class="ui-mobile-header mobile-header"><details class="ui-mobile-nav mobile-nav"><summary aria-label="Open navigation">☰</summary>'
        f'<div class="ui-mobile-panel mobile-panel">{mobile}</div></details><a class="ui-brand brand" href="/">Capy</a>'
        f'<div class="ui-mobile-workspace mobile-workspace"><strong>{html.escape(context.workspace_display_name)}</strong>'
        f'<span>{html.escape(context.workspace_kind.title())} workspace</span></div></header>'
        f'<aside class="ui-rail sidebar"><div class="ui-rail-head"><a class="ui-brand brand" href="/">Capy</a></div>{desktop}</aside>'
        f'<main class="ui-main main" id="main-content" tabindex="-1"><div class="ui-content content{wide}">{body}</div></main>'
        f'</div><script>{script}</script></body></html>'
    )
