"""Bounded peer-authenticated local messages for the account service.

This is an internal host protocol, never an application/MCP surface. Handlers
must return allowlisted safe data; exceptions are deliberately not serialized.
"""
import json
import os
import socket
import socketserver
import struct
import threading
from pathlib import Path

from .model import RuntimeFailure
from .store import canonical_json

LIMIT=256*1024


def peer_uid(sock):
    if hasattr(socket,'SO_PEERCRED'):
        return struct.unpack('3i',sock.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12))[1]
    if hasattr(sock,'getpeereid'):return sock.getpeereid()[0]
    return None


def read(sock):
    data=bytearray()
    while b'\n' not in data:
        part=sock.recv(min(16384,LIMIT+1-len(data)))
        if not part:break
        data.extend(part)
        if len(data)>LIMIT:raise RuntimeFailure('ACCOUNT_PROTOCOL_INVALID')
    if not data.endswith(b'\n') or data.count(b'\n')!=1:raise RuntimeFailure('ACCOUNT_PROTOCOL_INVALID')
    value=json.loads(data[:-1])
    if not isinstance(value,dict):raise RuntimeFailure('ACCOUNT_PROTOCOL_INVALID')
    return value


class Client:
    def __init__(self,path,uid,*,timeout=90,test_no_peer=False):
        self.path,self.uid,self.timeout,self.test_no_peer=str(path),uid,timeout,test_no_peer

    def call(self,operation,**values):
        payload=canonical_json({'operation':operation,'values':values})+b'\n'
        if len(payload)>LIMIT:raise RuntimeFailure('ACCOUNT_PROTOCOL_INVALID')
        try:
            with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as sock:
                sock.settimeout(self.timeout);sock.connect(self.path)
                if not self.test_no_peer and peer_uid(sock)!=self.uid:raise RuntimeFailure('ACCOUNT_AUTHORITY_DENIED')
                sock.sendall(payload);result=read(sock)
            if result.get('ok') is not True:
                code=result.get('code')
                safe={'ACCOUNT_AUTHORITY_DENIED','ACCOUNT_REQUEST_CHANGED','ACCOUNT_SETUP_REQUIRED',
                      'FEDEX_AUTHENTICATION_FAILED','FEDEX_PROVIDER_UNAVAILABLE','FEDEX_RATE_REJECTED',
                      'FEDEX_NO_RATES_RETURNED','ACCOUNT_VERIFICATION_PENDING'}
                raise RuntimeFailure(code if code in safe else 'ACCOUNT_SERVICE_UNAVAILABLE')
            if set(result)!={'ok','result'} or not isinstance(result['result'],dict):raise RuntimeFailure('ACCOUNT_PROTOCOL_INVALID')
            return result['result']
        except (OSError,ValueError,TypeError):raise RuntimeFailure('ACCOUNT_SERVICE_UNAVAILABLE') from None


class Server(socketserver.ThreadingMixIn,socketserver.UnixStreamServer):
    daemon_threads=True
    def __init__(self,path,uid,dispatch,*,test_no_peer=False):
        self.uid,self.dispatch,self.test_no_peer=uid,dispatch,test_no_peer
        path=Path(path);path.parent.mkdir(mode=0o755,parents=True,exist_ok=True)
        if path.exists():
            # Never replace a live listener on duplicate service startup.
            with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as probe:
                try:probe.connect(str(path))
                except ConnectionRefusedError:path.unlink()
                else:raise RuntimeFailure('ACCOUNT_SERVICE_ALREADY_RUNNING')
        super().__init__(str(path),Handler)
        path.chmod(0o660)
    def handle_error(self,*_):pass


class Handler(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(90)
        try:
            if not self.server.test_no_peer and peer_uid(self.request)!=self.server.uid:
                raise RuntimeFailure('ACCOUNT_AUTHORITY_DENIED')
            value=read(self.request)
            if set(value)!={'operation','values'} or not isinstance(value['operation'],str) or not isinstance(value['values'],dict):
                raise RuntimeFailure('ACCOUNT_PROTOCOL_INVALID')
            result=self.server.dispatch(value['operation'],value['values'])
            response={'ok':True,'result':result}
        except Exception as exc:
            code=getattr(exc,'code',None)
            allowed={'ACCOUNT_AUTHORITY_DENIED','ACCOUNT_REQUEST_CHANGED','ACCOUNT_SETUP_REQUIRED',
                     'FEDEX_AUTHENTICATION_FAILED','FEDEX_PROVIDER_UNAVAILABLE','FEDEX_RATE_REJECTED',
                     'FEDEX_NO_RATES_RETURNED','ACCOUNT_VERIFICATION_PENDING'}
            response={'ok':False,'code':code if code in allowed else 'ACCOUNT_SERVICE_UNAVAILABLE'}
        try:
            data=canonical_json(response)+b'\n'
            if len(data)>LIMIT:data=b'{"ok":false,"code":"ACCOUNT_SERVICE_UNAVAILABLE"}\n'
            self.request.sendall(data)
        except (OSError,ValueError,TypeError):pass
