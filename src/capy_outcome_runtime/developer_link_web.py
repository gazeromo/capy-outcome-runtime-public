"""Browser forms and separate device-only JSON routing for Developer Link V0."""
import html
import base64
import hashlib
import json
import re
import secrets
import urllib.parse

from . import _developer_link_protocol as wire
from .developer_link import LinkError
from .harness_link import HarnessLink
from .model import RuntimeFailure
from .ui.assets import STANDARD_SCRIPT
from .ui.enhancements import ENHANCEMENTS
from .ui.developer_link import render_development_section, esc, render_setup, render_pair, render_request



def json_reply(handler, value, status=200):
    data = wire.canonical(value)
    handler.send_response(status)
    for key,val in [('Content-Type','application/json'),('Content-Length',str(len(data))),('Cache-Control','no-store'),('X-Content-Type-Options','nosniff')]:
        handler.send_header(key,val)
    handler.end_headers()
    handler.wfile.write(data)


def route(handler, method, parsed):
    if not (parsed.path == '/developer' or parsed.path.startswith('/developer/') or parsed.path.startswith('/api/developer-link/')):
        return False
    link = getattr(handler.product, 'developer_link', None)
    if link is None:
        handler.send_error(404)
        return True
    try:
        if parsed.query or parsed.fragment:
            raise LinkError('INVALID_ROUTE', 400)
        bootstrap = getattr(handler.product, 'developer_bootstrap', None)
        if bootstrap is not None and bootstrap.route(handler, method, parsed):
            return True
        if parsed.path == '/developer/connection-info.json' and method == 'GET':
            json_reply(handler, dict(schema='capy.harness-connection/v0', site_id=link.site_id,
                                     origin=link.origin, capability='harness-first/v0'))
            return True
        if parsed.path.startswith('/api/'):
            if method != 'POST' or handler.headers.get_content_type() != 'application/json':
                raise LinkError('INVALID_METHOD_OR_CONTENT_TYPE', 400)
            # Reject before reading an oversized body. These APIs never accept browser cookies as authority.
            try:
                length = int(handler.headers.get('Content-Length', '-1'))
            except ValueError:
                raise LinkError('INVALID_LENGTH', 400) from None
            if not 0 <= length <= 256*1024:
                raise LinkError('BODY_LIMIT', 413)
            raw = handler.rfile.read(length)
            if len(raw) != length:
                raise LinkError('INVALID_LENGTH', 400)
            value = wire.decode_json(raw, max_bytes=256*1024)
            peer = handler.client_address[0]
            authorization = handler.headers.get('Authorization','')
            secret = authorization.removeprefix('Bearer ') if authorization.startswith('Bearer ') else ''
            if parsed.path == '/api/developer-link/pair/start':
                result = link.start_pair(value, peer)
            elif parsed.path == '/api/developer-link/pair/poll':
                result = link.poll(value, secret, peer)
            elif (match := re.fullmatch(r'/api/developer-link/harness-v0/(status|register|check|begin|reopen)', parsed.path)):
                result = getattr(HarnessLink(link), match[1])(value, secret, peer)
            else:
                match = re.fullmatch(r'/api/developer-link/requests/(hof_[0-9a-f]{32})/(claim|events)', parsed.path)
                if not match:
                    raise LinkError('NOT_FOUND', 404)
                result = getattr(link, match[2])(match[1], value, secret, peer)
            json_reply(handler, result)
            return True
        auth = handler.require_actor()
        if auth is None:
            return True
        link.actor(auth.actor)
        enhancement = "none"
        fields = {}
        if method == 'POST':
            fields = handler.urlencoded()
            if handler.headers.get('Origin') != link.origin or not secrets.compare_digest(fields.get('csrf',''), auth.csrf_token):
                raise LinkError('HTTP_CSRF_OR_ORIGIN_DENIED')
        if parsed.path == '/developer' and method == 'GET':
            devices, statuses = link.listing(auth.actor)
            rows = HarnessLink(link).listing(auth.actor)
            content = render_setup(auth, devices, statuses, link.origin, link.site_id, link.clock(),
                                   transfer_enabled=getattr(handler.product,"release_workflow",None) is not None,
                                   clients=rows)
            if bootstrap is not None:
                content = '<p><a href="/developer/connect">Connect a coding client</a></p>' + content
        elif (match := re.fullmatch(r'/developer/connections/(dev_[0-9a-f]{32})/work(?:/(approve))?', parsed.path)):
            harness = HarnessLink(link)
            with link.db() as db:
                device = link.device(db, match[1])
                if device['principal'] != auth.actor.principal_id:
                    raise LinkError()
            if method == 'POST' and match[2] == 'approve':
                if fields.get('allow_linked_work') != 'yes':
                    raise LinkError('EXPLICIT_LINKED_WORK_CONSENT_REQUIRED', 400)
                harness.approve(auth.actor, match[1])
                handler.redirect('/developer')
                return True
            if method != 'GET' or match[2]:
                raise LinkError('NOT_FOUND', 404)
            from .ui_compatibility import compatibility_body
            content = compatibility_body('<h1>Allow linked development work</h1><p>Allow ' + esc(device['label']) +
                ' to prepare linked development work in your current ' + esc(auth.actor.workspace_kind) +
                ' workspace. Trusted tools running as this computer’s local user can use this permission. It does not approve source transfer, checks or installation.</p>' +
                '<form method="post" action="' + esc(parsed.path + '/approve') + '">' +
                '<input type="hidden" name="csrf" value="' + esc(auth.csrf_token) + '">' +
                '<button name="allow_linked_work" value="yes">Allow linked development work</button></form>')
        elif (match := re.fullmatch(r'/developer/connections/(pair_[0-9a-f]{32})', parsed.path)) and method == 'GET':
            with link.db() as db:
                pair = db.execute('SELECT label,expires FROM pairs WHERE id=?', (match[1],)).fetchone()
            if pair is None or pair['expires'] <= link.clock():
                raise LinkError('PAIR_EXPIRED', 404)
            content = render_pair(auth, link.origin, link.site_id, pair, parsed.path)
        elif (match := re.fullmatch(r'/developer/connections/(pair_[0-9a-f]{32})/approve', parsed.path)) and method == 'POST':
            link.approve(auth.actor, match[1], fields.get('confirmation_code',''))
            handler.redirect('/developer')
            return True
        elif (match := re.fullmatch(r'/developer/connections/(dev_[0-9a-f]{32})/revoke', parsed.path)) and method == 'POST':
            link.revoke(auth.actor, match[1])
            handler.redirect('/developer')
            return True
        elif parsed.path == '/developer/requests' and method == 'POST':
            req = link.create(auth.actor, fields.get('device_id',''), fields.get('idempotency_key',''))
            handler.redirect('/developer/requests/' + req['handoff_id'])
            return True
        elif (match := re.fullmatch(r'/developer/requests/(hof_[0-9a-f]{32})(?:/(open|continue|cancel|disconnect))?', parsed.path)):
            handoff, action = match.groups()
            if method == 'POST' and action:
                if action == 'continue':
                    old = link.status(auth.actor, handoff)['request']
                    req = link.create(auth.actor, old['device_id'], fields.get('idempotency_key',''), parent=handoff)
                    handoff = req['handoff_id']
                else:
                    link.action(auth.actor, handoff, action)
                handler.redirect('/developer/requests/' + handoff)
                return True
            if method != 'GET' or action:
                raise LinkError('NOT_FOUND', 404)
            status = link.status(auth.actor, handoff)
            content = render_request(auth, link.site_id, status, parsed.path, handoff)
            if getattr(handler.product, "release_workflow", None) is not None and (status.get("snapshot") or {}).get("candidate_id"):
                from .ui_compatibility import compatibility_body
                content = compatibility_body(str(content)+'<a class="button" href="/releases/review/'+handoff+'">Review for testing</a>')
            enhancement = "developer-status"
        else:
            raise LinkError('NOT_FOUND', 404)
        script_hash = base64.b64encode(hashlib.sha256((STANDARD_SCRIPT + ENHANCEMENTS[enhancement]).encode()).digest()).decode()
        handler.send_html(handler.product_shell(auth, title='Local development', active='applications', body=content, application=True, enhancement=enhancement), script_sha256=script_hash, referrer_policy="same-origin")
    except (LinkError, wire.ProtocolError, RuntimeFailure) as exc:
        status = getattr(exc, 'status', 403)
        if parsed.path.startswith('/api/'):
            value = {'error': str(exc) if isinstance(exc, LinkError) else 'INVALID_DEVELOPER_LINK_REQUEST'}
            if getattr(exc, 'expected', None) is not None:
                value['expected_sequence'] = exc.expected
            json_reply(handler, value, status)
        else:
            handler.send_html('<h1>Developer link unavailable</h1><p>' + esc(str(exc) if isinstance(exc, LinkError) else 'Current authorization or request is invalid.') + '</p><a href="/developer">Return to development</a>', status, referrer_policy="same-origin")
    return True


def applications_section(handler, auth):
    from .ui import render_stack
    link = getattr(handler.product, 'developer_link', None)
    if not link or (auth.actor.workspace_kind == 'team' and auth.actor.membership_kind != 'owner'):
        return render_stack()
    _, statuses = link.listing(auth.actor)
    return render_development_section(statuses)
