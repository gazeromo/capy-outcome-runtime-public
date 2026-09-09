"""Escaping, fixed-shape Developer Link views in the trusted UI boundary."""
import html
import secrets
from .. import _developer_link_protocol as wire
from .render import _safe

def esc(value):
    return html.escape(str(value), quote=True)


def form(auth, action, label, *, developer_open=False, **fields):
    values = {'csrf': auth.csrf_token, **fields}
    marker = ' data-developer-open' if developer_open else ''
    return '<form method="post" action="' + esc(action) + '"' + marker + '>' + ''.join('<input type="hidden" name="' + esc(k) + '" value="' + esc(v) + '">' for k,v in values.items()) + '<button>' + esc(label) + '</button></form>'


LABELS = {
 'READY_TO_OPEN': 'Ready to open on this computer', 'PREPARING': 'Preparing your project',
 'WAITING_FOR_HARNESS': 'Waiting for Codex connection', 'HARNESS_ATTACHED': 'Connected to Codex; describe or continue your app there',
 'CHANGES_IN_PROGRESS': 'Changes in progress', 'VERIFYING': 'Checking the app',
 'CHECKS_FAILED': 'Checks need attention in Codex', 'CHECKS_PASSED': 'Checks passed; preparing candidate',
 'CANDIDATE_PREPARED': 'Candidate prepared on your computer', 'SESSION_FINISHED': 'Session finished',
 'LAUNCH_OUTCOME_UNKNOWN': 'Desktop launch outcome unknown; open again when ready',
}


def card(status):
    req, snap = status['request'], status['snapshot'] or {}
    label = 'Request cancelled' if status['state'] == 'CANCELLED' else LABELS.get(snap.get('milestone', 'READY_TO_OPEN'), 'Local development')
    return '<article><h3><a href="/developer/requests/' + esc(req['handoff_id']) + '">' + esc(label) + '</a></h3><p>' + esc(status['connection']) + ' · Local development</p></article>'


def render_development_section(statuses):
    return _safe('<section aria-label="Local development"><h2>Request an app or a change</h2><p>This starts a separate development request. Using an installed app does not start development.</p><a class="button" href="/developer/overview">Request an app or a change</a>' + ''.join(card(s) for s in statuses) + '</section>')


def render_setup(auth, devices, statuses, site_origin, site_id, now, *, transfer_enabled=False, clients=(), conversations=()):
    content = introduction()
    content += '<h2>Connect a coding client</h2><p><a href="/developer/connect">Open the managed connection guide</a> to use this site’s exact Developer package and your existing installation. Follow the guide for supported clients and prerequisites.</p>'
    content += '<p>Compare the named computer and confirmation code before approving. Revocation stops new access; local code and running editors remain on your computer.</p>'
    for dev in devices:
        content += '<article><h3>' + esc(dev['label']) + '</h3><p>' + ('Revoked' if dev['revoked'] else 'Expires at epoch ' + str(dev['expires'])) + '</p>'
        device_clients = [client for client in clients if client['device_id'] == dev['id']]
        if device_clients:
            content += '<h4>Coding clients</h4><ul>'
            for client in device_clients:
                checked = client['last_checked']
                elapsed = max(0, int(now - checked)) if checked is not None else None
                age = ('not checked yet' if elapsed is None else 'just now' if elapsed < 60
                       else str(elapsed // 60) + ' minutes ago' if elapsed < 3600
                       else str(elapsed // 3600) + ' hours ago' if elapsed < 86400
                       else str(elapsed // 86400) + ' days ago')
                content += '<li>' + esc(client['label']) + ' — ' + esc(client['state']) + '. Last Capy check: ' + age + '.</li>'
            content += '</ul><p>Client names are integration labels. Revoking this computer stops access for all its clients. Local files and running editors remain.</p>'
        if not dev['revoked'] and dev['expires'] > now:
            content += '<p><a href="/developer/connections/' + esc(dev['id']) + '/work">Review linked-work permission</a></p>'
            create = form(auth, '/developer/requests', 'Request an app or a change', device_id=dev['id'], idempotency_key=secrets.token_hex(16))
            options='<option value="">No linked conversation</option>'+''.join('<option value="'+esc(c['id'])+'">'+esc(c.get('title') or 'Saved conversation')+'</option>' for c in conversations)
            content += create.replace('<button>', '<label>Original work (optional)<select name="conversation_id">'+options+'</select></label><button>', 1)
            content += form(auth, '/developer/connections/' + dev['id'] + '/revoke', 'Revoke connection')
        content += '</article>'
    content += '<h2>Linked development</h2>' + ''.join(card(s) for s in statuses)
    return _safe(content)

def render_pair(auth, site_origin, site_id, pair, path):
    content = introduction()
    content += '<h2>Connect ' + esc(pair['label']) + '</h2><p>Site: ' + esc(site_origin) + ' · ' + esc(site_id) + '</p><p>Only approve if you started setup on this computer. Enter the confirmation code displayed there.</p><form method="post" action="' + esc(path + '/approve') + '"><input type="hidden" name="csrf" value="' + esc(auth.csrf_token) + '"><label>Confirmation code <input name="confirmation_code" required maxlength="8" autocomplete="off"></label><button>Approve this computer</button></form>'
    return _safe(content)

def render_request(auth, site_id, status, path, handoff):
    content = introduction()
    req, snap = status['request'], status['snapshot'] or {}
    content += '<div id=developer-status aria-live=polite>' + card(status) + '<p>Last report received: ' + esc(status['received_at'] or 'No local report yet') + '</p>'
    if snap.get('candidate_id'):
        content += '<details><summary>Technical details</summary><dl><dt>Candidate</dt><dd>' + esc(snap['candidate_id']) + '</dd><dt>Exact commit</dt><dd>' + esc(snap['candidate_commit']) + '</dd><dt>SHA-256</dt><dd>' + esc(snap['candidate_sha256']) + '</dd></dl></details>'
    if snap and not snap.get('source_fresh'):
        content += '<p>New changes are not yet verified. Historical candidate identity remains unchanged.</p>'
    content += '</div><a href="' + esc(path) + '">Refresh status</a>'
    if status['connection'] not in ('REVOKED','DISCONNECTED'):
        content += form(auth, path + '/open', 'Open Codex', developer_open=True)
        content += '<p id="developer-launch-notice" role="status">Open Codex prepares a fresh launch in the same project workspace. It may open a new Codex conversation.</p>'
        content += '<p><a id="developer-launch-fallback" href="' + esc(wire.make_uri(site_id, handoff, req['launch_generation'])) + '">Launch prepared task</a></p><p>Approve your browser’s confirmation to open Capy Developer. If nothing opens, use this page in a standalone desktop browser; embedded browsers may not deliver the app link. You can also use Launch prepared task. Without JavaScript, first press Open Codex, then use that link on the refreshed page. Describe or continue your app in Codex after it opens. Opening a window does not confirm a harness connection.</p>'
        if status['state'] == 'READY':
            content += form(auth, path + '/cancel', 'Cancel request')
        else:
            content += form(auth, path + '/continue', 'Continue development', idempotency_key=secrets.token_hex(16))
            content += form(auth, path + '/disconnect', 'Disconnect from Capy')
            content += '<p>Disconnect stops reports to Capy. Coding may continue locally; stop it in Codex. Your source and candidates are retained.</p>'
    content += '<p><a href="/developer/overview">Manage connected computers</a></p>'
    return _safe(content)

def introduction():
    return '<h1>Develop on this computer</h1><p>Local development reports are supplied by your connected computer. These reports describe preparation; application checks and workspace installation are recorded separately.</p>'
