"""Reviewed static attachment and request-scoped application launch sessions."""
from __future__ import annotations

import hashlib
import json
import mimetypes
import secrets
import time
import urllib.parse
from dataclasses import asdict
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from .access import ActorContext
from .model import RuntimeFailure
from .store import canonical_json


def listener_address(args):
    """Public browser identity is distinct from the private HTTP listener."""
    manifest = getattr(args, 'human_ui_manifest', None)
    origin = getattr(args, 'human_ui_origin', None)
    port = getattr(args, 'human_ui_port', None)
    if manifest is None and origin is None and port is None:
        return None
    if not getattr(args, 'human_requests', False) or not manifest or not origin:
        raise RuntimeFailure('HUMAN_UI_CONFIGURATION_INVALID')
    try:
        parsed = urllib.parse.urlsplit(origin)
        if port is None and parsed.scheme == 'http' and parsed.hostname in {'localhost', '127.0.0.1'}:
            port = parsed.port
    except ValueError as exc:
        raise RuntimeFailure('HUMAN_UI_CONFIGURATION_INVALID') from exc
    if type(port) is not int or not 1 <= port <= 65535:
        raise RuntimeFailure('HUMAN_UI_LISTENER_PORT_REQUIRED')
    return ('127.0.0.1', port)


class UIAttachment:
    def __init__(self, manifest_path, host_origin, app_origin):
        self.root = Path(manifest_path).resolve().parent
        self.manifest = json.loads(Path(manifest_path).read_text())
        self.host_origin, self.app_origin = host_origin, app_origin
        host, app = urllib.parse.urlsplit(host_origin), urllib.parse.urlsplit(app_origin)
        if (host.scheme not in {'http', 'https'} or app.scheme not in {'http', 'https'}
            or not host.netloc or not app.netloc or host.hostname == app.hostname
            or any(x.path or x.query or x.fragment or x.username or x.password for x in (host, app))):
            raise RuntimeFailure('HUMAN_UI_ORIGIN_INVALID')
        if self.manifest.get('schema') != 'capy.reviewed-ui-attachment/v0':
            raise RuntimeFailure('HUMAN_UI_ATTACHMENT_INVALID')
        self.assets = {}
        for name, digest in self.manifest['assets'].items():
            path = self.root / name
            if (name.startswith('/') or '..' in Path(name).parts or path.is_symlink()
                or not path.resolve().is_relative_to(self.root) or not isinstance(digest, str)):
                raise RuntimeFailure('HUMAN_UI_ATTACHMENT_INVALID')
            payload = path.read_bytes()
            if hashlib.sha256(payload).hexdigest() != digest:
                raise RuntimeFailure('HUMAN_UI_DIGEST_MISMATCH')
            # Serve these verified bytes, never mutable files after verification.
            self.assets['/' + name] = payload
        if '/' + self.manifest['entrypoint'] not in self.assets:
            raise RuntimeFailure('HUMAN_UI_ATTACHMENT_INVALID')
        self.digest = hashlib.sha256(canonical_json(self.manifest)).hexdigest()

    def issue(self, service, actor, request_id):
        request = service.get(actor, request_id)
        if (request['app'], request['version']) != (self.manifest['application_id'], self.manifest['backend_version']):
            raise RuntimeFailure('HUMAN_UI_VERSION_MISMATCH')
        token = secrets.token_urlsafe(32)
        session = {'actor': asdict(actor), 'request': request_id, 'generation': request['generation'],
                   'attachment': self.digest, 'expires': time.time() + 900}
        with service.store.connect() as db:
            db.execute('INSERT INTO human_launches_v0 VALUES (?, ?)',
                       (service.digest(token), canonical_json(session).decode()))
        fragment = urllib.parse.urlencode({'session': token, 'host': self.host_origin, 'presentation': secrets.token_urlsafe(24)})
        return self.app_origin + '/' + self.manifest['entrypoint'] + '#' + fragment

    def resolve(self, service, token):
        session = service._credential('human_launches_v0', token)
        if session['attachment'] != self.digest:
            raise RuntimeFailure('HUMAN_UI_SESSION_STALE')
        actor = ActorContext(**session['actor'])
        request = service.get(actor, session['request'])
        if request['generation'] != session['generation']:
            raise RuntimeFailure('HUMAN_UI_SESSION_STALE')
        if (request['app'], request['version']) != (self.manifest['application_id'], self.manifest['backend_version']):
            raise RuntimeFailure('HUMAN_UI_SESSION_STALE')
        return actor, request

    def context(self, service, actor, request):
        contract = service.contract_resolver(actor, request['app'])
        operation = next(x for x in contract['operations'] if x['operation_id'] == request['operation'])
        return {'id': request['id'], 'generation': request['generation'], 'status': request['status'],
                'title': request['title'], 'workspace': 'Personal' if actor.workspace_kind == 'personal' else actor.team_name,
                'inputs': request['inputs'], 'fields': operation['human_fields'],
                'resources': {name: [{'digest': d, 'filename': service.store.resource(actor.execution_scope_id, d)[1]}
                                      for d in values] for name, values in request['resources'].items()},
                'return_url': self.host_origin + '/needs-you/' + request['id'],
                'outcome': request['outcome'], 'error': request['error']}

    def server(self, address):
        attachment = self
        class StaticHandler(BaseHTTPRequestHandler):
            def log_message(self, *_): pass
            def do_GET(self):
                expected_host = urllib.parse.urlsplit(attachment.app_origin).netloc
                if self.headers.get('Host') != expected_host:
                    self.send_error(403)
                    return
                path = urllib.parse.urlsplit(self.path).path
                payload = attachment.assets.get(path)
                if payload is None:
                    self.send_error(404)
                    return
                self.send_response(200)
                self.send_header('Content-Type', mimetypes.guess_type(path)[0] or 'application/octet-stream')
                self.send_header('Content-Length', str(len(payload)))
                self.send_header('X-Content-Type-Options', 'nosniff')
                self.send_header('Referrer-Policy', 'no-referrer')
                self.send_header('Cache-Control', 'no-store')
                self.send_header('Content-Security-Policy',
                    "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'none'; "
                    f"connect-src {attachment.host_origin}; frame-ancestors {attachment.host_origin}; "
                    "base-uri 'none'; form-action 'none'; object-src 'none'")
                self.send_header('Permissions-Policy', 'camera=(), microphone=(), geolocation=(), payment=(), usb=()')
                self.end_headers()
                self.wfile.write(payload)
        return ThreadingHTTPServer(address, StaticHandler)
