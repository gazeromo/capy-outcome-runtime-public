"""Loopback-only Core JSON transport. No browser credentials or UI routes."""
import argparse
import base64
import json
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

from .core import Core
from .model import RuntimeFailure

MAX_BODY = 3 * 1024 * 1024


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass  # Never log credentials, task inputs or resource bytes.

    def do_POST(self):
        status = 200
        try:
            if self.headers.get('Origin') or self.headers.get('Transfer-Encoding'):
                raise RuntimeFailure('CORE_TRANSPORT_DENIED')
            length = int(self.headers.get('Content-Length','0'))
            if not 0 < length <= MAX_BODY:
                raise RuntimeFailure('CORE_BODY_INVALID')
            self.connection.settimeout(10)
            raw = self.rfile.read(length)
            if self.path == '/v0/context':
                from .context_search import _closed_object
                data = json.loads(raw, object_pairs_hook=_closed_object)
            else:
                data = json.loads(raw)
            shapes = {'/v0/context':set(),'/v0/discover':set(),'/v0/work':set(),'/v0/upload':{'filename','base64'},
                '/v0/invoke':{'operation','inputs','resources','key'},'/v0/question':{'id'},
                '/v0/answer':{'id','generation','answer'},'/v0/result':{'id'},'/v0/artifact':{'id','digest'}}
            if (self.path not in shapes or not isinstance(data,dict)
                    or (set(data) not in (set(), {'query'}, {'cursor'}) if self.path == '/v0/context'
                        else set(data)!=shapes[self.path])):
                raise RuntimeFailure('CORE_REQUEST_INVALID')
            credential = self.headers.get('Authorization','')
            if not credential.startswith('Bearer '):
                raise RuntimeFailure('CORE_CLIENT_DENIED')
            token = credential[7:]
            core = self.server.core
            if self.path == '/v0/discover':
                value = core.discover(token)
            elif self.path == '/v0/context':
                if any(not isinstance(value, str) for value in data.values()):
                    raise RuntimeFailure('CORE_CONTEXT_REQUEST_INVALID')
                value = core.context(token, **data)
            elif self.path == '/v0/work':
                value = core.work(token)
            elif self.path == '/v0/upload':
                value = core.upload(token,data['filename'],base64.b64decode(data['base64'],validate=True))
            elif self.path == '/v0/invoke':
                value = core.invoke(token,data['operation'],data['inputs'],data['resources'],data['key'])
            elif self.path == '/v0/question':
                value = core.question(token,data['id'])
            elif self.path == '/v0/answer':
                value = core.question(token,data['id'],generation=data['generation'],answer=data['answer'])
            elif self.path == '/v0/result':
                value = core.result(token,data['id'])
            elif self.path == '/v0/artifact':
                payload, filename = core.artifact(token,data['id'],data['digest'])
                value = dict(filename=filename,base64=base64.b64encode(payload).decode())
            else:
                raise RuntimeFailure('CORE_ROUTE_DENIED')
        except RuntimeFailure as exc:
            status, value = 403, {'error':exc.code}
        except (ValueError, TypeError, KeyError):
            status, value = 400, {'error':'CORE_REQUEST_INVALID'}
        except Exception:
            status, value = 500, {'error':'CORE_UNAVAILABLE'}
        payload = json.dumps(value).encode()
        self.send_response(status)
        self.send_header('Content-Type','application/json')
        self.send_header('Content-Length',str(len(payload)))
        self.send_header('Cache-Control','no-store')
        self.end_headers()
        self.wfile.write(payload)


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--runtime-root',type=Path,required=True)
    parser.add_argument('--port',type=int,default=8766)
    parser.add_argument('--broker-socket',type=Path)
    args=parser.parse_args()
    core=Core(args.runtime_root,broker_socket=args.broker_socket)
    try:
        server=HTTPServer(('127.0.0.1',args.port),Handler)
        server.core=core
        print(json.dumps({'contract':'capy.core/v0','origin':f'http://127.0.0.1:{server.server_port}'}),flush=True)
        server.serve_forever()
    finally:
        core.close()

if __name__=='__main__':
    main()
