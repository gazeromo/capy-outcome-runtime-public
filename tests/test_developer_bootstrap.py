import hashlib
import io
from pathlib import Path
from types import SimpleNamespace
from urllib.parse import urlsplit
import pytest
from capy_outcome_runtime.developer_bootstrap import BootstrapHost, configured_bootstrap
from capy_outcome_runtime._bootstrap_manifest import ManifestError, canonical


def write_artifact(path, raw):
    # Windows maps write bits to the read-only attribute. Publish immutable
    # fixtures explicitly; intentional test mutations restore owner write first.
    if path.exists():
        path.chmod(0o600)
    path.write_bytes(raw)
    path.chmod(0o444)


def fixture(root):
    def item(name,raw):
        write_artifact(root/name,raw)
        return dict(filename=name,sha256=hashlib.sha256(raw).hexdigest(),size_bytes=len(raw))
    m=dict(schema='capy.harness-bootstrap/v0',release_id='0.7.0-probe',origin='https://127.0.0.1:18891',site_id='site_'+'1'*32,scope='local-coding-client',protocols={'developer':'harness-first/v0','runtime':'harness-first/v0'},developer=dict(version='0.7.0',artifact=item('capy_developer-0.7.0-py3-none-any.whl',b'test inert wheel')),installer=item('capy-bootstrap.py',b'# test inert installer'),platforms=['macos-arm64'],clients={x:dict(version=v,transport='MCP_STDIO') for x,v in [('muse','1.0.3'),('codex','0.153.4')]},prerequisites=dict(python_minimum='3.11',python_exact='3.13.7',uv={}))
    write_artifact(root/'manifest.json',canonical(m))
    return m


def host(root,m):return BootstrapHost(root,origin=m['origin'],site_id=m['site_id'])

class Handler:
    def __init__(self):self.wfile=io.BytesIO();self.headers={};self.status=None
    def send_error(self,status):self.status=status
    def send_response(self,status):self.status=status
    def send_header(self,key,value):self.headers[key]=value
    def end_headers(self):pass
    def send_html(self,body,**kwargs):self.wfile.write(body.encode());self.status=200


def test_immutable_files_and_same_manifest_guide(tmp_path):
    m=fixture(tmp_path);h=host(tmp_path,m)
    for path in ['/developer/connect','/developer/connect.md',h.prefix+'manifest.json',h.prefix+'capy-bootstrap.py']:
        handler=Handler();assert h.route(handler,'GET',urlsplit(path));assert handler.status==200
        if path.endswith('.py'):assert handler.headers['Content-Type']=='application/octet-stream' and 'attachment' in handler.headers['Content-Disposition']
    assert h.digest in h.markdown() and m['installer']['sha256'] in h.markdown()
    assert m['origin']+'/developer/connect.md' in h.prompt()
    write_artifact(tmp_path/'capy-bootstrap.py',b'changed after load')
    handler=Handler();h.route(handler,'GET',urlsplit(h.prefix+'capy-bootstrap.py'))
    assert handler.wfile.getvalue()==b'# test inert installer'

@pytest.mark.parametrize('path',['/developer/bootstrap/0.7.0-probe/../../secret','/developer/bootstrap/unknown/capy-bootstrap.py','/developer/connect.md?token=secret','/developer/bootstrap/0.7.0-probe/manifest.json?x=y'])
def test_exact_routes_only(tmp_path,path):
    m=fixture(tmp_path);handler=Handler();host(tmp_path,m).route(handler,'GET',urlsplit(path));assert handler.status==404


def test_missing_modified_symlink_and_wrong_site_fail_before_advertising(tmp_path):
    m=fixture(tmp_path)
    with pytest.raises(ManifestError):BootstrapHost(tmp_path,origin='https://wrong.example',site_id=m['site_id'])
    p=tmp_path/'capy-bootstrap.py';write_artifact(p,b'wrong')
    with pytest.raises(ManifestError):host(tmp_path,m)
    p.chmod(0o600);p.unlink();outside=tmp_path/'outside';write_artifact(outside,b'# test inert installer');p.symlink_to(outside)
    with pytest.raises(ManifestError):host(tmp_path,m)
    p.unlink()
    with pytest.raises(OSError):host(tmp_path,m)


def test_default_off_and_link_required(tmp_path):
    assert configured_bootstrap(SimpleNamespace(),None) is None
    with pytest.raises(ManifestError):configured_bootstrap(SimpleNamespace(developer_bootstrap_root=tmp_path),None)


def test_prerequisite_script_served_with_exact_guide_digest(tmp_path):
    from capy_outcome_runtime._bootstrap_manifest import artifact_url
    m=fixture(tmp_path)
    def item(name, raw):
        write_artifact(tmp_path/name,raw)
        return dict(filename=name,sha256=hashlib.sha256(raw).hexdigest(),size_bytes=len(raw))
    python=item('python.tar.gz',b'inert python archive')
    key='cpython-3.13.7-darwin-aarch64-none'
    record=dict(name='cpython',arch=dict(family='aarch64',variant=None),os='darwin',libc='none',major=3,minor=13,patch=7,prerelease='',url=artifact_url(m,python),sha256=python['sha256'],variant=None,build='20250918')
    pin=dict(version='0.9.0',artifact=item('uv.tar.gz',b'inert uv archive'),python_artifact=python,python_key=key,downloads=item('downloads.json',canonical({key:record})))
    m['prerequisites']['uv']['macos-arm64']=pin
    write_artifact(tmp_path/'manifest.json',canonical(m))
    h=host(tmp_path,m);path,digest,size=h.prerequisite_scripts['macos-arm64']
    handler=Handler();h.route(handler,'GET',urlsplit(path))
    script=handler.wfile.getvalue()
    assert handler.status==200 and len(script)==size
    assert hashlib.sha256(script).hexdigest()==digest and digest in h.markdown()
    assert m['origin']+path in h.markdown()
    assert 'attachment' in handler.headers['Content-Disposition']
    # Even a correctly hashed metadata artifact cannot redirect Python elsewhere.
    record['url']='https://other.example/python.tar.gz'
    pin['downloads']=item('downloads.json',canonical({key:record}))
    write_artifact(tmp_path/'manifest.json',canonical(m))
    with pytest.raises(ManifestError):host(tmp_path,m)


def test_actual_http_public_and_host_header_cannot_change_guide(tmp_path):
    import http.client
    import threading
    from capy_outcome_runtime.web import ProductServer
    m=fixture(tmp_path);link=SimpleNamespace(origin=m['origin'],site_id=m['site_id'])
    product=SimpleNamespace(developer_link=link,developer_bootstrap=host(tmp_path,m))
    server=ProductServer(('127.0.0.1',0),product)
    thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
    try:
        c=http.client.HTTPConnection(*server.server_address,timeout=5)
        c.request('GET','/developer/connect.md',headers={'Host':'attacker.example','X-Forwarded-Host':'attacker.example'})
        r=c.getresponse();body=r.read().decode();assert r.status==200
        assert m['origin'] in body and 'attacker.example' not in body
        assert 'Set-Cookie' not in dict(r.getheaders());c.close()
    finally:
        server.shutdown();server.server_close();thread.join(5)
