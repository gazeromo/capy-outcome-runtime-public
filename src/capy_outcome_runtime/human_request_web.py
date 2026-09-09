"""Optional Needs you shell and narrow, credential-free cross-origin app API."""
from __future__ import annotations

import base64
import html
import json
import threading
import urllib.parse

from .model import RuntimeFailure
from .ui.human_requests import render_index, render_detail, render_launch



def _json(handler, value, status=200, origin=None):
    payload = json.dumps(value).encode()
    handler.send_response(status)
    handler.send_header('Content-Type', 'application/json')
    handler.send_header('Content-Length', str(len(payload)))
    handler.send_header('Cache-Control', 'no-store')
    handler.send_header('X-Content-Type-Options', 'nosniff')
    if origin:
        handler.send_header('Access-Control-Allow-Origin', origin)
        handler.send_header('Vary', 'Origin')
    handler.end_headers()
    handler.wfile.write(payload)


def _body(handler):
    if handler.headers.get('Content-Type', '').split(';')[0] != 'application/json':
        raise RuntimeFailure('HUMAN_HTTP_INPUT_INVALID')
    try:
        length = int(handler.headers.get('Content-Length', '0'))
        if not 1 <= length <= 3 * 1024 * 1024:
            raise ValueError()
        value = json.loads(handler.rfile.read(length))
    except (ValueError, UnicodeError) as exc:
        raise RuntimeFailure('HUMAN_HTTP_INPUT_INVALID') from exc
    if not isinstance(value, dict):
        raise RuntimeFailure('HUMAN_HTTP_INPUT_INVALID')
    return value


def _dispatch(service, request_id):
    service.start_background(service.dispatch, request_id)


def _page(handler, auth, title, body, status=200):
    from .ui.enhancements import HUMAN_STATUS_ENHANCEMENT
    from .web import workbench_script_sha256
    handler.send_html(handler.product_shell(auth, title=title, active='needs-you', body=body, enhancement='human-status'),
                      status, script_sha256=workbench_script_sha256(HUMAN_STATUS_ENHANCEMENT))


def _view(service, actor, request):
    # Presentation is enabled only by the exact reviewed contract already bound to this request.
    value = dict(request)
    try:
        contract, op, _ = service._contract(actor, request['app'], request['operation'])
        if (contract['application_version'], contract['digest']) == (request['version'], request['contract']):
            value['human_field'] = next(x for x in op['human_fields'] if x['field_id'] == request['field'])
            value['presentation'] = {'application_id': request['app'], 'operation_id': request['operation'],
                'presentation_kind': op['result']['presentation'],
                'result': request['outcome']['result'] if request['outcome'] else {}}
            facts = []
            for field in op['human_fields']:
                key = field['field_id']
                saved = request['inputs'].get(key)
                if isinstance(saved, (str, int, float)) and str(saved).strip():
                    text = str(saved)
                    facts.append((field['label'], text[:300] + ('…' if len(text) > 300 else '')))
                for digest in request['resources'].get(key, []):
                    metadata = service.store.resource_metadata(actor.execution_scope_id, digest)
                    facts.append((field['label'], metadata['filename']))
            value['work_context'] = {'title': op['title'],
                'purpose': contract.get('purpose') or op['user_outcome'], 'facts': facts}
    except (RuntimeFailure, KeyError, StopIteration):
        pass
    from .presentation import present_application_result
    value['result_view'] = present_application_result(value.get('presentation', {}), application_href=None,
        workspace_name='Personal' if actor.workspace_kind == 'personal' else actor.team_name)
    return value



def route(handler, method, parsed):
    if not (parsed.path.startswith('/needs-you') or parsed.path.startswith('/human-app/') or parsed.path == '/human-producer/requests'):
        return False
    service = getattr(handler.product, 'human_requests', None)
    attachment = getattr(handler.product, 'human_ui', None)
    if service is None and parsed.path == '/needs-you' and method == 'GET':
        auth=handler.require_actor()
        if auth is not None:
            from .work_context import attention_html
            from .ui_compatibility import compatibility_body
            body=attention_html(handler.product,auth.actor)
            handler.send_html(handler.product_shell(auth,title='Needs you',active='needs-you',body=compatibility_body('<h1>Needs you</h1>'+ (body or '<p>Nothing needs your response.</p>'))))
        return True
    if service is None:
        handler.send_error(404)
        return True
    cors = None
    try:
        if handler.headers.get('Host') != urllib.parse.urlsplit(handler.product.origin).netloc:
            raise RuntimeFailure('HUMAN_HTTP_HOST_DENIED')
        if parsed.path.startswith('/human-app/'):
            if attachment is None or handler.headers.get('Origin') != attachment.app_origin or handler.headers.get('Cookie'):
                raise RuntimeFailure('HUMAN_APP_ORIGIN_DENIED')
            cors = attachment.app_origin
            if method == 'OPTIONS':
                if (handler.headers.get('Access-Control-Request-Method') not in {'GET', 'POST'}
                    or set(x.strip().lower() for x in handler.headers.get('Access-Control-Request-Headers', '').split(',') if x.strip()) - {'authorization', 'content-type'}):
                    raise RuntimeFailure('HUMAN_APP_ORIGIN_DENIED')
                handler.send_response(204)
                handler.send_header('Access-Control-Allow-Origin', cors)
                handler.send_header('Access-Control-Allow-Methods', 'GET, POST')
                handler.send_header('Access-Control-Allow-Headers', 'Authorization, Content-Type')
                handler.send_header('Vary', 'Origin')
                handler.end_headers()
                return True
            authorization = handler.headers.get('Authorization', '')
            if not authorization.startswith('Bearer '):
                raise RuntimeFailure('HUMAN_CREDENTIAL_DENIED')
            actor, request = attachment.resolve(service, authorization[7:])
            if method == 'GET' and parsed.path == '/human-app/context':
                _json(handler, attachment.context(service, actor, request), origin=cors)
            elif method == 'GET' and parsed.path == '/human-app/resource':
                slot = urllib.parse.parse_qs(parsed.query).get('slot', [''])[0]
                selected = request['resources'].get(slot, [])
                if len(selected) != 1:
                    raise RuntimeFailure('HUMAN_RESOURCES_INVALID')
                payload, filename = service.read_resource(actor, selected[0])
                _json(handler, {'filename': filename, 'base64': base64.b64encode(payload).decode()}, origin=cors)
            elif method == 'POST' and parsed.path == '/human-app/respond':
                data = _body(handler)
                if set(data) - {'generation', 'inputs', 'file'}:
                    raise RuntimeFailure('HUMAN_HTTP_INPUT_INVALID')
                resources = request['resources']
                if data.get('file') is not None:
                    file = data['file']
                    if not isinstance(file, dict) or set(file) != {'slot', 'filename', 'base64'} or file['slot'] not in resources:
                        raise RuntimeFailure('HUMAN_RESOURCES_INVALID')
                    filename = file['filename']
                    if not isinstance(filename, str) or not filename.lower().endswith('.csv') or any(c in filename for c in '/\\\x00\r\n') or len(filename) > 255:
                        raise RuntimeFailure('HUMAN_RESOURCES_INVALID')
                    try:
                        payload = base64.b64decode(file['base64'], validate=True)
                    except (ValueError, TypeError) as exc:
                        raise RuntimeFailure('HUMAN_RESOURCES_INVALID') from exc
                    if not 1 <= len(payload) <= 2 * 1024 * 1024:
                        raise RuntimeFailure('HUMAN_RESOURCES_INVALID')
                    digest = service.store.add_resource(actor.execution_scope_id, filename, payload)
                    resources = {**resources, file['slot']: [digest]}
                result = service.respond(actor, request['id'], data.get('generation'), inputs=data.get('inputs'), resources=resources)
                _json(handler, {'status': result['status'], 'return_url': attachment.host_origin + '/needs-you/' + request['id']}, origin=cors)
                _dispatch(service, request['id'])
            else:
                handler.send_error(404)
            return True
        if parsed.path == '/human-producer/requests':
            if method != 'POST' or handler.headers.get('Origin') or handler.headers.get('Cookie'):
                raise RuntimeFailure('HUMAN_PRODUCER_DENIED')
            authorization = handler.headers.get('Authorization', '')
            if not authorization.startswith('Bearer '):
                raise RuntimeFailure('HUMAN_CREDENTIAL_DENIED')
            data = _body(handler)
            if set(data) != {'key', 'inputs', 'resources'}:
                raise RuntimeFailure('HUMAN_HTTP_INPUT_INVALID')
            value = service.create_from_producer(authorization[7:], data['key'], data['inputs'], data['resources'])
            _json(handler, {'id': value['id'], 'status': value['status']}, 201)
            return True
        auth = handler.require_actor()
        if auth is None:
            return True
        parts = parsed.path.strip('/').split('/')
        if method == 'GET' and parsed.path == '/needs-you':
            values = [_view(service, auth.actor, x) for x in service.list(auth.actor)]
            from .work_context import attention_html
            from .ui_compatibility import compatibility_body
            body=str(render_index(auth, values, attachment is not None))+attention_html(handler.product,auth.actor)
            _page(handler, auth, 'Needs you', compatibility_body(body))
        elif len(parts) in {2, 3}:
            request = _view(service, auth.actor, service.get(auth.actor, parts[1]))
            if method == 'GET' and len(parts) == 2:
                _page(handler, auth, request['title'], render_detail(auth, request, attachment is not None))
            elif method == 'GET' and len(parts) == 3 and parts[2] == 'status':
                _json(handler, {'status': request['status'], 'generation': request['generation'],
                    'html': str(render_detail(auth, request, attachment is not None))})
            elif method == 'POST' and len(parts) == 3:
                form = handler.urlencoded()
                handler.require_post(auth, form.get('csrf', ''))
                try:
                    generation = int(form.get('generation', ''))
                except ValueError as exc:
                    raise RuntimeFailure('HUMAN_HTTP_INPUT_INVALID') from exc
                if parts[2] == 'answer':
                    try:
                        service.respond(auth.actor, request['id'], generation, answer=form.get('answer'))
                    except RuntimeFailure as exc:
                        if exc.code == 'HUMAN_INPUT_INVALID':
                            message = 'Check this value and try again.'
                            body = render_detail(auth, request, attachment is not None, error=message, answer=form.get('answer', ''))
                            if handler.headers.get('Accept') == 'application/json':
                                _json(handler, {'error': message}, 422)
                            else:
                                _page(handler, auth, request['title'], body, 422)
                            return True
                        raise
                    if handler.headers.get('Accept') == 'application/json':
                        _json(handler, {'status': 'saved', 'waiting_count': sum(x['status'] == 'waiting' for x in service.list(auth.actor))})
                    else:
                        handler.redirect('/needs-you/' + request['id'])
                    _dispatch(service, request['id'])
                elif parts[2] == 'cancel':
                    service.cancel(auth.actor, request['id'], generation)
                    handler.redirect('/needs-you/' + request['id'])
                elif parts[2] == 'retry':
                    handler.redirect('/needs-you/' + request['id'])
                    _dispatch(service, request['id'])
                elif parts[2] == 'open' and attachment:
                    url = attachment.issue(service, auth.actor, request['id'])
                    from .ui.shell import render_application_document
                    page = render_application_document(request['title'], render_launch(auth, request, url))
                    from .ui.assets import STANDARD_SCRIPT
                    from .ui.enhancements import HUMAN_LAUNCH_ENHANCEMENT
                    import hashlib
                    script_digest = base64.b64encode(hashlib.sha256((STANDARD_SCRIPT + HUMAN_LAUNCH_ENHANCEMENT).encode()).digest()).decode()
                    handler.send_html(page, frame_origin=attachment.app_origin, script_sha256=script_digest)
                else:
                    handler.send_error(404)
            else:
                handler.send_error(404)
        else:
            handler.send_error(404)
    except (RuntimeFailure, KeyError, StopIteration) as exc:
        code = exc.code if isinstance(exc, RuntimeFailure) else 'HUMAN_REQUEST_DENIED'
        if parsed.path.startswith('/human-') or method == 'OPTIONS':
            _json(handler, {'error': code}, 409 if 'STALE' in code or 'CONFLICT' in code else 403, cors)
        else:
            handler.send_html('<h1>This action could not be completed</h1><p>' + html.escape(code.replace('_', ' ').title()) + '</p><p>Your saved response, if any, is retained.</p><a href="/needs-you">Return to Needs you</a>', 409)
    return True
