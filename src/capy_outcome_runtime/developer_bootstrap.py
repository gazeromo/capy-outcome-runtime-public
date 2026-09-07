"""Explicitly configured immutable bootstrap downloads; no Developer imports."""
import hashlib
import html
import os
from pathlib import Path
import stat

from ._bootstrap_manifest import decode, artifacts, artifact_url, ManifestError, MAX_ARTIFACT, MAX_MANIFEST, validate_downloads


def read_regular(path, maximum):
    if any(p.is_symlink() for p in (path, *path.parents)):
        raise ManifestError('bootstrap artifacts cannot pass through symlinks')
    with path.open('rb') as source:
        info = os.fstat(source.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_size > maximum or info.st_mode & 0o022:
            raise ManifestError('unsafe bootstrap artifact')
        raw = source.read(maximum + 1)
    if len(raw) > maximum:
        raise ManifestError('bootstrap artifact exceeds bound')
    return raw


class BootstrapHost:
    def __init__(self, root, *, origin, site_id):
        root = Path(root)
        raw = read_regular(root/'manifest.json', MAX_MANIFEST)
        self.manifest = m = decode(raw)
        if m['origin'] != origin or m['site_id'] != site_id:
            raise ManifestError('bootstrap and configured site differ')
        self.digest = hashlib.sha256(raw).hexdigest()
        self.prefix = '/developer/bootstrap/' + m['release_id'] + '/'
        self.files = {self.prefix+'manifest.json':(raw, 'application/json')}
        if sum(a['size_bytes'] for a in artifacts(m)) > 256*1024*1024:
            raise ManifestError('bootstrap release exceeds total bound')
        for item in artifacts(m):
            content = read_regular(root/item['filename'], min(MAX_ARTIFACT,item['size_bytes']))
            if len(content) != item['size_bytes'] or hashlib.sha256(content).hexdigest() != item['sha256']:
                raise ManifestError('bootstrap artifact identity mismatch')
            self.files[self.prefix+item['filename']] = (content,'application/octet-stream')
        for pin in m['prerequisites']['uv'].values():
            validate_downloads(m,pin,self.files[self.prefix+pin['downloads']['filename']][0])
        from ._bootstrap_prerequisites import posix_script, MEMBERS
        self.prerequisite_scripts = {}
        for platform in m['prerequisites']['uv']:
            if platform not in MEMBERS:continue
            path=self.prefix+'bootstrap-'+platform+'.sh'
            if path in self.files:raise ManifestError('generated script filename conflicts with an artifact')
            script=posix_script(m,self.digest,platform)
            self.files[path]=(script,'application/octet-stream')
            self.prerequisite_scripts[platform]=(path,hashlib.sha256(script).hexdigest(),len(script))

    def prompt(self):
        return ('Connect this coding client to my Capy using the instructions at\n' +
                self.manifest['origin'] + '/developer/connect.md.\n\n' +
                'Use verified HTTPS throughout. If certificate verification fails, report the trust problem; never disable TLS checks to fetch the guide or artifacts. '
                'Reuse my existing Capy installation and projects. Configure the supported Capy tools for this client without changing my model or unrelated settings. '
                'Open the Capy approval page when account permission is needed, then verify that this session can call Capy. '
                'After connecting, help me create or continue a Capy app without asking me to choose a repository or worktree. '
                'Retain any app objective supplied with this prompt across setup and reopening.')

    def markdown(self):
        m=self.manifest; installer=m['installer']; wheel=m['developer']['artifact']
        prerequisites='\n## If compatible Python is missing\n\n' if self.prerequisite_scripts else ''
        for platform,(path,digest,size) in self.prerequisite_scripts.items():
            prerequisites += f'{platform}: {m["origin"]}{path}\n\nSHA-256: `{digest}`; bytes: {size}. Download through verified HTTPS, check this exact size and digest, then run the saved script using `/bin/sh <saved-file> muse` (or `codex`). It preserves native approvals and uses only private pinned prerequisites.\n\n'
        return ('# Connect a coding client to Capy\n\n'
                'This setup supports local coding clients with normal native approvals. Account approval, source transfer, independent checks and workspace installation remain separate owner actions.\n\n'
                f"Site: {m['origin']}\n\nRelease: {m['release_id']}\n\n"
                f"Manifest: {m['origin']}{self.prefix}manifest.json\n\nManifest SHA-256: `{self.digest}`\n\n"
                f"Installer: {artifact_url(m,installer)}\n\nInstaller SHA-256: `{installer['sha256']}`; bytes: {installer['size_bytes']}.\n\n"
                f"Developer {m['developer']['version']}: {artifact_url(m,wheel)}\n\nWheel SHA-256: `{wheel['sha256']}`; bytes: {wheel['size_bytes']}.\n\n"
                'Supported platform matrix: '+', '.join(m['platforms'])+'.\n\n'
                'Tested client versions: '+', '.join(k+' '+v['version']+' ('+v['transport']+')' for k,v in m['clients'].items())+'.\n\n'
                'Download the manifest and installer through verified HTTPS without redirects. Verify the exact size and SHA-256 above before executing the installer. '
                'Use a compatible existing Python first; never install into an application environment or replace system Python. '
                'Run the verified installer with argument array:\n\n```json\n'+__import__('json').dumps(['python3','capy-bootstrap.py','--manifest',m['origin']+self.prefix+'manifest.json','--manifest-sha256',self.digest,'--client','muse'])+'\n```\n\n'
                'Use `codex` for a Codex session. The installer must reuse recognized Capy roots and fail on ambiguous or modified ownership. '
                'Missing Python uses only a prerequisite explicitly pinned in this manifest; missing native Git requires the normal OS developer-tools action. '
                'Do not substitute latest downloads, disable protections, change provider settings, or treat configured tools as a successful channel check.\n\n'
                + prerequisites + 'Preserve the user app objective locally. After connect, load the installed capy-development instructions in a fresh client session if required and perform the actual Capy tool check.\n')

    def route(self, handler, method, parsed):
        if parsed.path not in ('/developer/connect','/developer/connect.md') and not parsed.path.startswith('/developer/bootstrap/'):
            return False
        if method!='GET' or parsed.query or parsed.fragment:
            handler.send_error(404); return True
        if parsed.path=='/developer/connect':
            body='<h1>Connect a coding client</h1><p>Copy this prompt into your local coding client. You can append your app request.</p><pre>'+html.escape(self.prompt())+'</pre><p><a href="/developer/connect.md">Setup instructions and exact versions</a></p>'
            handler.send_html(body,script_sha256=None); return True
        if parsed.path=='/developer/connect.md':
            data,kind=self.markdown().encode(),'text/markdown; charset=utf-8'
        else:
            found=self.files.get(parsed.path)
            if found is None:
                handler.send_error(404);return True
            data,kind=found
        handler.send_response(200)
        for key,value in [('Content-Type',kind),('Content-Length',str(len(data))),('Cache-Control','no-store'),('X-Content-Type-Options','nosniff'),('Content-Security-Policy',"default-src 'none'; sandbox")]:handler.send_header(key,value)
        if parsed.path in self.files and kind=='application/octet-stream':
            handler.send_header('Content-Disposition','attachment; filename="'+parsed.path.rsplit('/',1)[1]+'"')
        handler.end_headers();handler.wfile.write(data)
        return True


def configured_bootstrap(args, link):
    root=getattr(args,'developer_bootstrap_root',None)
    if root is None:return None
    if link is None:raise ManifestError('bootstrap hosting requires configured Developer Link')
    return BootstrapHost(root,origin=link.origin,site_id=link.site_id)
