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
    if len(workspaces) < 2:
        return _safe(f'<span class="workspace-name">{html.escape(current_name)}</span>')
    options = "".join(
        f'<option value="{html.escape(mid)}"{" selected" if mid == current_membership_id else ""}>{html.escape(label)}</option>'
        for mid, label in workspaces
    )
    return _safe('<form class="ui-workspace" data-auto-submit method="post" action="/workspaces/activate">'
        f'<input type="hidden" name="csrf" value="{html.escape(csrf_token)}">'
        f'<label><span class="ui-sr-only">Workspace</span><select name="workspace">{options}</select></label>'
        '<noscript><button>Switch workspace</button></noscript></form>')


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
    enhancement: Literal["none", "chat", "form-protection", "developer-status", "human-launch"] = "none",
) -> SafeHtml:
    if not all(isinstance(value, SafeHtml) for value in (body, workspace_switcher, mobile_workspace_switcher, new_item_action, account_item)):
        raise TypeError("shell fragments must come from trusted renderers")
    primary = _nav(tuple(x for x in context.navigation_items if x.item_id in {"chat", "applications", "needs-you"}), label="Primary")
    apps = _nav(tuple(x for x in context.navigation_items if x.item_id == "applications"), label="Apps")
    history = (f'<details class="chat-history"><summary>Conversation history</summary>{new_item_action}'
               + _nav(context.recent_items, label="Recent conversations", recent=True) + '</details>') if context.current_destination == "chat" else ""
    if enhancement not in ENHANCEMENTS:
        raise ValueError("unknown enhancement")
    if stylesheet_extension is not None and not isinstance(stylesheet_extension, StylesheetExtension):
        raise TypeError("stylesheet extension must be an approved renderer capability")
    script = STANDARD_SCRIPT + ENHANCEMENTS[enhancement]
    return _safe(
        '<!doctype html><html lang="en"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width,initial-scale=1">'
        f'<title>{html.escape(title)} · Capy</title><style>{WORKBENCH_CSS}{stylesheet_extension or ""}{COMPACT_CSS}</style></head>'
        '<body><a class="ui-skip-link" href="#main-content">Skip to content</a>'
        '<header class="capy-header"><a class="ui-brand" href="/">Capy</a>'
        f'{primary}<a href="/recent-work">Recent work</a><div class="capy-context">{workspace_switcher}'
        '<details class="capy-menu"><summary>Menu</summary><div>'
        f'{account_item}<p>{html.escape(context.principal_display_name)}</p></div></details></div></header>'
        f'<main id="main-content" class="capy-content" tabindex="-1">{history}{body}</main>'
        f'<script>{script}</script></body></html>'
    )


COMPACT_CSS = """
.capy-header{display:flex;align-items:center;gap:32px;padding:14px 28px;border-bottom:1px solid #deded8;background:#fff;min-height:66px}
.capy-header .ui-nav-group{display:flex;margin:0;gap:8px}.capy-header .ui-nav-item{margin:0;padding:8px 12px}
.capy-context{margin-left:auto;display:flex;align-items:center;gap:18px}.capy-context form{margin:0}.capy-context label{margin:0}
.capy-context select{margin:0;width:auto;max-width:180px}.capy-menu{position:relative}.capy-menu>div{position:absolute;right:0;top:32px;z-index:10;background:white;border:1px solid #ddd;padding:20px;min-width:210px;box-shadow:0 8px 25px #0001}.capy-menu .ui-nav-group{display:block}
.capy-content{max-width:1120px;margin:auto;padding:32px 24px;min-width:0}.chat-history{margin-bottom:20px}.chat-history .ui-nav-group{max-height:240px;overflow:auto}
.human-question{max-width:640px;margin:32px auto 48px}.human-question h2{font-size:28px;line-height:1.25;margin:12px 0 26px}.human-question h2 a{text-decoration:none;color:inherit}
.app-choice{padding:24px 0;border-bottom:1px solid #deded8;max-width:680px}.app-choice h2{margin:0 0 10px}.app-choice p{margin-bottom:20px}
.human-work{margin-bottom:28px;padding-bottom:24px;border-bottom:1px solid #deded8}.human-work h2{margin-bottom:12px}.human-work h3{font-size:15px;margin:20px 0 12px}.human-work dl{display:grid;grid-template-columns:minmax(100px,1fr) 2fr;gap:8px 20px;margin:0}.human-work dt{color:#62675f}.human-work dd{margin:0;overflow-wrap:anywhere}.human-question .human-question-title{font-size:23px;margin-bottom:18px}
.human-question label{display:block;margin-bottom:8px;font-weight:500}.human-question input{display:block;width:100%;max-width:440px;padding:12px;border:1px solid #aab1aa;border-radius:5px;background:#fff;font-size:16px}.human-question button{padding:11px 18px;border:1px solid #254b3c;border-radius:5px;background:#254b3c;color:#fff;font-weight:600;cursor:pointer}.human-question button.secondary{background:transparent;color:#254b3c}.human-question form{margin:16px 0}.human-question details button{font-weight:400}.capy-context .ui-workspace{padding:0;border:0}.capy-content .ui-composer-wrap{left:0}.human-actions{display:flex;gap:16px;align-items:center;flex-wrap:wrap}.human-actions form{margin:0}.human-question details{margin-top:24px}.human-question .field-error{color:#983f30}.human-question .human-context{color:#62675f}.human-history{border-top:1px solid #ddd;padding-top:20px}.human-history p{display:flex;gap:20px;flex-wrap:wrap}.human-status{margin:20px 0}.human-question [hidden]{display:none!important}
@media(max-width:600px){.capy-header{padding:12px 16px;gap:12px;flex-wrap:wrap}.capy-header .ui-nav-item{padding:7px}.capy-context{gap:10px}.capy-content{padding:24px 18px}.human-question{margin:16px auto 32px}.human-question h2{font-size:25px}}
"""


def render_application_document(title, body, enhancement="human-launch"):
    """Separate viewport document, with no ordinary shell navigation."""
    script = ENHANCEMENTS[enhancement]
    return _safe('<!doctype html><html lang="en"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width,initial-scale=1">'
        f'<title>{html.escape(title)} · Capy</title><style>{WORKBENCH_CSS}{COMPACT_CSS}'
        'body{margin:0;height:100dvh;display:flex;flex-direction:column;overflow:hidden}'
        '.app-bar{display:flex;align-items:center;justify-content:space-between;gap:16px;padding:12px 20px;border-bottom:1px solid #ddd;background:white;flex:none}'
        '.app-bar a{white-space:nowrap}.app-bar span{min-width:0;overflow-wrap:anywhere}'
        '.app-stage{flex:1;min-height:0;display:flex;flex-direction:column}.app-stage iframe{width:100%;flex:1;min-height:0;border:0}'
        '.app-result{overflow:auto;padding:28px;flex:1}.app-result h1{font-size:28px;letter-spacing:-.035em}.app-result h2{font-size:22px}.app-result button{padding:10px 16px;border:1px solid #b9beb9;border-radius:6px;background:#fff;cursor:pointer}.app-result form{margin:12px 0}.app-result input,.app-result select,.app-result textarea{max-width:100%;padding:10px;border:1px solid #b9beb9;border-radius:5px}.app-result details{margin:20px 0}.app-result dl{display:grid;grid-template-columns:minmax(120px,200px) 1fr;gap:12px}.app-result dd{margin:0;overflow-wrap:anywhere}.app-notice{padding:10px 20px;background:#fff5db;margin:0}'
        '[hidden]{display:none!important}@media(max-width:500px){.app-bar{padding:10px 14px;gap:10px;font-size:13px;flex-wrap:wrap}}'
        f'</style></head><body>{body}<script>{STANDARD_SCRIPT}{script}</script></body></html>')
