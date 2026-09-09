"""Standalone stdlib-only authenticated Unix client; safe to vendor verbatim."""
import hashlib
import io
import json
from pathlib import Path
import socket
import stat
import struct
import zipfile

class BridgeError(Exception):
    def __init__(self,code): self.code=code; super().__init__(code)

def _canonical(value):
    return json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=False,allow_nan=False).encode()

def _exact(sock,length):
    out=[]
    while length:
        chunk=sock.recv(min(length,65536))
        if not chunk: raise BridgeError('TRUNCATED_REPLY')
        out.append(chunk); length-=len(chunk)
    return b''.join(out)

class Client:
    def __init__(self,socket_path,expected_peer_uid,timeout=35):
        self.socket_path=str(socket_path); self.expected_peer_uid=expected_peer_uid; self.timeout=timeout
    def _request(self,operation,payload,stream,body_size):
        if type(body_size) is not int or not 0<=body_size<=33554432: raise BridgeError('BODY_LIMIT')
        path=Path(self.socket_path)
        if path.is_symlink(): raise BridgeError('PEER_AUTH_FAILED')
        info=path.stat()
        if not stat.S_ISSOCK(info.st_mode) or info.st_uid!=self.expected_peer_uid or info.st_mode & 0o007: raise BridgeError('PEER_AUTH_FAILED')
        raw=_canonical(dict(schema='capy.release-bridge-call/v0',operation=operation,payload=payload,body_size=body_size))
        if len(raw)>262144: raise BridgeError('HEADER_LIMIT')
        with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as sock:
            sock.settimeout(self.timeout); sock.connect(self.socket_path)
            if not hasattr(socket,'SO_PEERCRED'): raise BridgeError('PEER_AUTH_UNAVAILABLE')
            uid=struct.unpack('3i',sock.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12))[1]
            if uid!=self.expected_peer_uid: raise BridgeError('PEER_AUTH_FAILED')
            sock.sendall(struct.pack('!I',len(raw))+raw)
            remaining=body_size
            while remaining:
                data=stream.read(min(65536,remaining))
                if not data or len(data)>remaining: raise BridgeError('TRUNCATED_BODY')
                sock.sendall(data); remaining-=len(data)
            size=struct.unpack('!I',_exact(sock,4))[0]
            if not 0<size<=262144: raise BridgeError('HEADER_LIMIT')
            raw=_exact(sock,size)
            try:
                reply=json.loads(raw)
                if _canonical(reply)!=raw or set(reply)!={'schema','ok','result','error','body_size'} or reply['schema']!='capy.release-bridge-reply/v0' or type(reply['ok']) is not bool: raise ValueError()
                if type(reply['body_size']) is not int or not 0<=reply['body_size']<=35000000: raise ValueError()
            except (ValueError,TypeError): raise BridgeError('INVALID_REPLY')
            if not reply['ok']:
                if reply['body_size'] or reply['result'] is not None or type(reply['error']) is not str or len(reply['error'])>96: raise BridgeError('INVALID_REPLY')
                raise BridgeError(reply['error'])
            if reply['error'] is not None: raise BridgeError('INVALID_REPLY')
            body=_exact(sock,reply['body_size'])
            return reply['result'],body
    def call_stream(self,operation,payload,stream,body_size):
        result,body=self._request(operation,payload,stream,body_size)
        if body: raise BridgeError('UNEXPECTED_REPLY_BODY')
        return result
    def call(self,operation,payload,body=b''):
        return self.call_stream(operation,payload,io.BytesIO(body),len(body))
    def export(self,*,owner,submission_id,attempt_id):
        result,body=self._request('accepted-release.export',dict(owner=owner,submission_id=submission_id,attempt_id=attempt_id),io.BytesIO(),0)
        if type(result) is not dict or set(result)!={'record'}: raise BridgeError('INVALID_REPLY')
        record=result['record']
        try:
            with zipfile.ZipFile(io.BytesIO(body)) as archive:
                if archive.namelist()!=['candidate.capyrc','acceptance.json']: raise ValueError()
                for info,maximum in zip(archive.infolist(),(32000000,2000000)):
                    if info.compress_type!=zipfile.ZIP_STORED or info.file_size>maximum or info.file_size!=info.compress_size or info.flag_bits & 1 or info.is_dir(): raise ValueError()
                c=archive.read('candidate.capyrc'); r=archive.read('acceptance.json')
            rebuilt=io.BytesIO()
            with zipfile.ZipFile(rebuilt,'w',compression=zipfile.ZIP_STORED) as archive:
                for name,raw in [('candidate.capyrc',c),('acceptance.json',r)]:
                    info=zipfile.ZipInfo(name,(1980,1,1,0,0,0)); info.create_system=3; info.external_attr=0o100644<<16; archive.writestr(info,raw)
            if rebuilt.getvalue()!=body: raise ValueError()
            if len(c)!=record['candidate_size_bytes'] or len(r)!=record['receipt_size_bytes'] or hashlib.sha256(c).hexdigest()!=record['candidate_sha256'] or hashlib.sha256(r).hexdigest()!=record['receipt_sha256']: raise ValueError()
        except (ValueError,KeyError,zipfile.BadZipFile): raise BridgeError('EXPORT_INTEGRITY')
        return record,c,r
