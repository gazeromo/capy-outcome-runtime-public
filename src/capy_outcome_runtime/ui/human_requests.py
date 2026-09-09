"""Small trusted questions and outcomes; application editors own their viewport."""
import html
import urllib.parse
from .render import _safe
from ..work_context import completed_request_label

LABELS = {'waiting': 'Needs your answer', 'saved': 'Response saved. Preparing your result…',
          'processing': 'Response saved. Preparing your result…', 'completed': 'Result ready',
          'failed': 'The application could not complete this request.',
          'uncertain': 'The result is not yet confirmed. Your response is saved.',
          'cancelled': 'Request cancelled', 'expired': 'Request expired', 'superseded': 'This request has changed.'}


def _hidden(auth, request):
    return (f'<input type="hidden" name="csrf" value="{html.escape(auth.csrf_token)}">'
            f'<input type="hidden" name="generation" value="{request["generation"]}">')


def _card(auth, request, *, detail=False, app_available=True, error='', answer=''):
    e = html.escape
    url = '/needs-you/' + request['id']
    workspace = 'Personal' if auth.actor.workspace_kind == 'personal' else auth.actor.team_name
    body = f'<section class="human-question" data-request="{url}" data-status="{request["status"]}"><p class="human-context">{e(request["title"])} · {e(workspace)}</p>'
    business_label = completed_request_label(request) if request['status'] == 'completed' else None
    context = request.get('work_context')
    if context and (request['status'] != 'completed' or business_label != 'Ready'):
        body += f'<div class="human-work"><h2>{e(context["title"])}</h2><p>{e(context["purpose"])}</p>'
        if context['facts']:
            body += '<h3>Details already supplied</h3><dl>' + ''.join(
                f'<dt>{e(label)}</dt><dd>{e(value)}</dd>' for label, value in context['facts']) + '</dl>'
        body += '</div>'
    if request['status'] == 'waiting':
        field = request.get('human_field', {})
        label = field.get('label', request['field'].replace('_', ' ')).capitalize()
        body += f'<h2 class="human-question-title">{e(request["question"])}</h2><form data-quick-answer method="post" action="{url}/answer">{_hidden(auth, request)}'
        body += f'<label for="answer-{request["id"]}">{e(label)}</label><input id="answer-{request["id"]}" name="answer" value="{e(answer)}" maxlength="500" required autocomplete="off" aria-describedby="error-{request["id"]}">'
        body += f'<p class="field-error" id="error-{request["id"]}" role="alert">{e(error)}</p><button>Continue</button></form>'
        if app_available:
            body += (f'<form method="post" action="{url}/open">{_hidden(auth, request)}'
                     '<button class="secondary">Review or edit in app</button></form>')
        body += (f'<details><summary>Details</summary><form method="post" action="{url}/cancel">{_hidden(auth, request)}'
                 '<button class="secondary">Cancel request</button></form></details>')
    elif request['status'] != 'completed' or not request['outcome']:
        body += f'<div class="human-status" role="status" tabindex="-1"><h2>{e(business_label if request["status"] == "completed" else LABELS[request["status"]])}</h2></div>'
    if request['outcome'] and request['status'] == 'completed':
        projection = request.get('result_view')
        confirmed = business_label == 'Ready'
        headline = (projection.headline if projection else 'Result ready') if confirmed else business_label
        body += f'<div role="status" tabindex="-1"><h2>{e(headline)}</h2></div>'
        if not confirmed:
            body += '<p>This attempt is saved. Opening it does not run it again.</p>'
        secondary = ''
        for artifact in request['outcome']['artifacts']:
            href = f'/application-artifact/{request["invocation_id"]}/{artifact["digest"]}'
            if confirmed and artifact['filename'].endswith('.html'):
                body += f'<p><a class="ui-action ui-action--primary" href="{href}">View document</a></p>'
            else:
                secondary += f'<p><a href="{href}">{e(artifact["filename"])}</a></p>'
        body += '<details><summary>Details</summary><dl>' + ''.join(f'<dt>{e(k)}</dt><dd>{e(v)}</dd>' for k,v in (projection.facts if projection and confirmed else ())) + '</dl>' + secondary + '</details>'
    if request['status'] in {'saved', 'processing', 'uncertain'}:
        body += (f'<p data-poll-note hidden></p><form method="post" action="{url}/retry">{_hidden(auth, request)}'
                 '<button class="secondary">Check current result</button></form>')
    return body + '</section>'


def render_index(auth, values, app_available):
    active = [x for x in values if x['status'] == 'waiting']
    progress = [x for x in values if x['status'] in {'saved', 'processing'}]
    history = [x for x in values if x not in active and x not in progress]
    body = '<h1>Needs you</h1>'
    body += ''.join(_card(auth, x, app_available=app_available) for x in active) if active else '<p>Nothing needs your answer.</p>'
    body += ''.join(_card(auth, x, app_available=app_available) for x in progress)
    if history:
        body += '<details class="human-history"><summary>Recently handled</summary>'
        for x in history:
            label = completed_request_label(x) if x['status'] == 'completed' else LABELS[x['status']]
            body += f'<p><a href="/needs-you/{x["id"]}">{html.escape(x["title"])}</a> {html.escape(label)}</p>'
        body += '</details>'
    return _safe(body)


def render_detail(auth, request, app_available, **kwargs):
    return _safe(_card(auth, request, detail=True, app_available=app_available, **kwargs))


def render_launch(auth, request, url):
    e = html.escape
    fragment = urllib.parse.parse_qs(urllib.parse.urlsplit(url).fragment)
    binding = fragment['presentation'][0]
    body = (f'<header class="app-bar"><a data-human-return href="/needs-you/{request["id"]}">← Back to Capy</a>'
            f'<span>{e(request["title"])} · {e("Personal" if auth.actor.workspace_kind == "personal" else auth.actor.team_name)}</span>'
            f'<a href="{e(url)}" target="_blank" rel="noopener noreferrer">Open in browser</a></header>'
            '<p class="app-notice" data-app-notice role="status" hidden></p>'
            f'<main class="app-stage" data-request="/needs-you/{request["id"]}" data-generation="{request["generation"]}" data-binding="{e(binding)}">'
            f'<iframe data-human-application title="{e(request["title"])}" src="{e(url)}" sandbox="allow-scripts allow-same-origin" referrerpolicy="no-referrer"></iframe>'
            '<div class="app-result" hidden tabindex="-1"></div></main>')
    return _safe(body)
