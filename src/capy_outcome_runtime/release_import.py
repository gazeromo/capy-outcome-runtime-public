"""Operator-only immutable accepted-release imports into marked preview stores."""
from __future__ import annotations
import io
import json
import os
import shutil
import stat
import re
import sqlite3
from functools import wraps
import uuid
import zipfile
from contextlib import contextmanager
from pathlib import Path

from .model import CapabilityDescriptor, RuntimeFailure
from .store import RuntimeStore, tree_digest, canonical_json, utc_now
from .release_validation import validate_release, digest, fail
from ._release_format import codec

MARKER = 'PREVIEW-IMPORT.json'
APPROVALS = 'IMPORT-APPROVALS.json'


def _checkpoint(stage):
    """Fault injection seam; production implementation performs no action."""


def _bounded_errors(function):
    @wraps(function)
    def call(*args, **kwargs):
        try:
            return function(*args, **kwargs)
        except RuntimeFailure:
            raise
        except (OSError, ValueError, TypeError, KeyError, sqlite3.Error,
                zipfile.BadZipFile, RuntimeError) as exc:
            raise RuntimeFailure('RELEASE_IMPORT_INTEGRITY_FAILED') from exc
    return call


def _safe_path(path):
    """Check every existing component before any resolve/open/mkdir/chmod."""
    path = Path(path)
    if '..' in path.parts:
        fail('RELEASE_PREVIEW_PATH_INVALID')
    path = Path(os.path.abspath(path))
    for part in (*reversed(path.parents), path):
        if part.is_symlink():
            fail('RELEASE_PREVIEW_PATH_INVALID')
    return path


def _store_paths(root):
    # RuntimeStore.__init__ creates/chmods these. Check BEFORE constructing it.
    names = ('control.sqlite3', 'control.sqlite3-wal', 'control.sqlite3-shm',
             'control.sqlite3-journal', 'scripts/sha256', 'acceptance/sha256',
             'resources/sha256', 'state', 'invocations', 'invocation-journal',
             'application-archives/sha256', 'devkit-environments/sha256',
             'import-environments', 'accepted-releases', 'import-staging',
             'release-import.lock')
    _safe_path(root)
    for name in names:
        _safe_path(root / name)


@_bounded_errors
def prepare_preview(root, approvals):
    root = _safe_path(root)
    if root.exists():
        fail('RELEASE_PREVIEW_EXISTS')
    if not isinstance(approvals, dict) or set(approvals) != {'schema', 'preview_id', 'entries'} or approvals['schema'] != 'capy.runtime-import-approval/v0' or not approvals['preview_id']:
        fail('RELEASE_OPERATOR_APPROVAL_REQUIRED')
    raw = canonical_json(approvals)
    root.mkdir(parents=True, mode=0o755)
    (root / APPROVALS).write_bytes(raw)
    (root / APPROVALS).chmod(0o444)
    marker = {'schema': 'capy.runtime-import-preview/v0',
              'preview_id': approvals['preview_id'],
              'approvals_sha256': digest(raw), 'production': False,
              'preview_root': str(root)}
    (root / MARKER).write_bytes(canonical_json(marker))
    (root / MARKER).chmod(0o444)
    store = RuntimeStore(root / 'runtime')
    _schema(store)
    # Bootstrap owns this envelope. Deployment gives only runtime/ to the web
    # identity; it must not chown the envelope or its operator records.
    root.chmod(0o755)
    return marker


def _context(root):
    root = _safe_path(root)
    if root.stat().st_mode & 0o022:
        fail('RELEASE_PREVIEW_REQUIRED')
    for name in (MARKER, APPROVALS):
        _safe_path(root / name)
        if (root / name).stat().st_mode & 0o222:
            fail('RELEASE_PREVIEW_REQUIRED')
    marker = codec.parse_strict_json(_read(root / MARKER, 16_384))
    raw = _read(root / APPROVALS, 2_000_000)
    approvals = codec.parse_strict_json(raw)
    if marker != {'schema': 'capy.runtime-import-preview/v0',
                  'preview_id': approvals['preview_id'],
                  'approvals_sha256': digest(raw), 'production': False,
                  'preview_root': str(root)}:
        fail('RELEASE_PREVIEW_REQUIRED')
    runtime = root / 'runtime'
    if not runtime.is_dir() or not (runtime / 'control.sqlite3').is_file():
        fail('RELEASE_PREVIEW_REQUIRED')
    _store_paths(runtime)
    return RuntimeStore(runtime), approvals


def _envelope(store):
    if store.root.name != 'runtime':
        fail('RELEASE_PREVIEW_REQUIRED')
    return store.root.parent


def _schema(store):
    with store.connect() as db:
        db.execute('CREATE TABLE IF NOT EXISTS accepted_imports (import_id TEXT PRIMARY KEY, capability_id TEXT NOT NULL, version_digest TEXT NOT NULL, record_json TEXT NOT NULL, UNIQUE(capability_id,version_digest))')
        db.execute('CREATE TABLE IF NOT EXISTS release_import_attempts (attempt_id TEXT PRIMARY KEY, import_id TEXT NOT NULL, status TEXT NOT NULL, created_at TEXT NOT NULL)')


@contextmanager
def _lock(store):
    # OS locks release on process death; no stale PID ownership inference.
    path=store.root/'release-import.lock'
    if path.is_symlink(): fail()
    with path.open('a+b') as handle:
        if os.name=='nt':
            import msvcrt
            handle.write(b'0');handle.flush();handle.seek(0);msvcrt.locking(handle.fileno(),msvcrt.LK_LOCK,1)
        else:
            import fcntl
            fcntl.flock(handle.fileno(),fcntl.LOCK_EX)
        try: yield
        finally:
            if os.name=='nt':
                handle.seek(0);msvcrt.locking(handle.fileno(),msvcrt.LK_UNLCK,1)
            else: fcntl.flock(handle.fileno(),fcntl.LOCK_UN)


def _read(path,limit):
    p=_safe_path(path)
    if p.is_symlink() or not p.is_file() or p.stat().st_size>limit: fail()
    with p.open('rb') as f: data=f.read(limit+1)
    if len(data)>limit: fail()
    return data


def _write_members(root,members,modes=None):
    root.mkdir(parents=True)
    for name,data in members.items():
        codec.check_inner_name_safe(name)
        target=root/name;target.parent.mkdir(parents=True,exist_ok=True)
        with target.open('xb') as out:
            out.write(data);out.flush();os.fsync(out.fileno())
        target.chmod(0o555 if modes and modes.get(name) else 0o444)
    for p in sorted(root.rglob('*'),reverse=True):
        if p.is_dir(): p.chmod(0o555)
    root.chmod(0o555)


def _wheel_members(payload):
    with zipfile.ZipFile(io.BytesIO(payload)) as z:
        infos=z.infolist(); names=[i.filename for i in infos]
        if len(infos)>2048 or sum(i.file_size for i in infos)>32_000_000: fail()
        codec.check_casefold_collisions(names)
        result={}
        for i in infos:
            codec.check_inner_name_safe(i.filename)
            mode=(i.external_attr>>16)&0o170000
            if mode not in (0,stat.S_IFREG) or i.is_dir() or i.flag_bits&1 or i.compress_type not in (0,8): fail()
            if i.filename.endswith('.pth') or '.data/' in i.filename: fail('RELEASE_ENVIRONMENT_UNSUPPORTED')
            result[i.filename]=z.read(i)
        return result


def _publish_dir(source,target):
    _safe_path(source); _safe_path(target)
    target.parent.mkdir(parents=True,exist_ok=True)
    if target.exists() or target.is_symlink():
        if tree_digest(source)!=tree_digest(target): fail('RELEASE_IMPORT_CONFLICT')
    else:
        source.chmod(0o755)
        try: os.rename(source,target)
        finally:
            (target if target.exists() else source).chmod(0o555)


def _cleanup(path):
    _safe_path(path)
    if not path.exists(): return
    for p in path.rglob('*'):
        if p.is_dir() and not p.is_symlink(): p.chmod(0o700)
    path.chmod(0o700);shutil.rmtree(path)


@_bounded_errors
def import_release(root,candidate_path,acceptance_path):
    store,approvals=_context(root);_schema(store)
    candidate_bytes=_read(candidate_path,32_000_000); acceptance_bytes=_read(acceptance_path,2_000_000)
    candidate,receipt=validate_release(candidate_bytes,acceptance_bytes,approvals)
    identity={'candidate_sha256':digest(candidate_bytes),'acceptance_sha256':digest(acceptance_bytes),'preview_id':approvals['preview_id']}
    identity_digest=digest(canonical_json(identity)); import_id='imp_'+identity_digest[:32]
    with _lock(store):
        with store.connect() as db:
            existing=db.execute('SELECT record_json FROM accepted_imports WHERE import_id=?',(import_id,)).fetchone()
            interrupted=db.execute("SELECT attempt_id FROM release_import_attempts WHERE status='STAGING'").fetchall()
            for row in interrupted:
                if not isinstance(row['attempt_id'],str) or re.fullmatch(r'[0-9a-f]{32}',row['attempt_id']) is None: fail()
                _cleanup(_safe_path(store.root/'import-staging'/row['attempt_id']))
            db.execute("UPDATE release_import_attempts SET status='INTERRUPTED' WHERE status='STAGING'")
        if existing: return inspect_import(root,import_id)
        attempt=uuid.uuid4().hex; staging=store.root/'import-staging'/attempt
        with store.connect() as db: db.execute('INSERT INTO release_import_attempts VALUES (?,?,?,?)',(attempt,import_id,'STAGING',utc_now()))
        _checkpoint('attempt_started')
        try:
            modes={}
            with zipfile.ZipFile(io.BytesIO(candidate.members['application/application.zip'])) as z:
                modes={i.filename:bool((i.external_attr>>16)&0o111) for i in z.infolist()}
            _write_members(staging/'application',candidate.application_members,modes)
            _write_members(staging/'environment',_wheel_members(candidate.wheel_bytes))
            for branch, expected in ((staging/'application', candidate.application_members),
                                     (staging/'environment', _wheel_members(candidate.wheel_bytes))):
                actual = {p.relative_to(branch).as_posix(): p.read_bytes()
                          for p in branch.rglob('*') if p.is_file() and not p.is_symlink()}
                if actual != expected or any(p.is_symlink() for p in branch.rglob('*')):
                    fail('RELEASE_IMPORT_INTEGRITY_FAILED')
            version=tree_digest(staging/'application'); env_digest=tree_digest(staging/'environment')
            descriptor=CapabilityDescriptor.from_toml(staging/'application'/'capability.toml')
            from .portable_interfaces import project_portable
            project_portable({**candidate.descriptor, 'version_digest': version}, candidate.interaction, import_id)
            m=candidate.manifest
            record={'schema':'capy.runtime-accepted-release-import/v0','status':'IMPORTED','import_id':import_id,'application_id':descriptor.id,'version_digest':version,**identity,'interaction_sha256':m['application']['interaction']['sha256'],'interaction':candidate.interaction,'archive_digest':m['application']['archive']['sha256'],'wheel_digest':digest(candidate.wheel_bytes),'environment_digest':env_digest,'import_identity_digest':identity_digest,'binding_state':'UNBOUND','candidate_id':m['release_candidate_id'],'acceptance_id':receipt['acceptance_id'],'source':m['source'],'toolchain':m['toolchain']}
            preserved={'candidate.capyrc':candidate_bytes,'acceptance.json':acceptance_bytes,'application.zip':candidate.members['application/application.zip'],'devkit.whl':candidate.wheel_bytes,'record.json':canonical_json(record)}
            _write_members(staging/'evidence',preserved)
            _checkpoint('files_staged')
            with store.connect() as db:
                conflict=db.execute('SELECT 1 FROM capability_versions WHERE capability_id=? AND version_digest=?',(descriptor.id,version)).fetchone()
                if conflict: fail('RELEASE_IMPORT_CONFLICT')
            _publish_dir(staging/'application',store.scripts/version)
            _publish_dir(staging/'environment',store.root/'import-environments'/env_digest)
            _publish_dir(staging/'evidence',store.root/'accepted-releases'/import_id)
            _checkpoint('files_published')
            with store.connect() as db:
                db.execute('INSERT INTO capability_versions VALUES (?,?,?,?,?)',(descriptor.id,version,descriptor.canonical_json(),digest(acceptance_bytes),utc_now()))
                db.execute('INSERT INTO accepted_imports VALUES (?,?,?,?)',(import_id,descriptor.id,version,canonical_json(record).decode()))
                db.execute("UPDATE release_import_attempts SET status='COMMITTED' WHERE attempt_id=?",(attempt,))
            _checkpoint('committed')
            return inspect_import(root,import_id)
        except Exception:
            with store.connect() as db: db.execute("UPDATE release_import_attempts SET status='FAILED' WHERE attempt_id=? AND status='STAGING'",(attempt,))
            raise
        finally: _cleanup(staging)


@_bounded_errors
def inspect_import(root,import_id):
    store,approvals=_context(root)
    if not isinstance(import_id,str) or len(import_id)!=36 or not import_id.startswith('imp_') or any(c not in '0123456789abcdef' for c in import_id[4:]): fail()
    with store.connect() as db:
        row=db.execute('SELECT * FROM accepted_imports WHERE import_id=?',(import_id,)).fetchone()
    if row is None: fail('RELEASE_IMPORT_NOT_FOUND')
    record=codec.parse_strict_json(row['record_json'].encode())
    expected_keys={'schema','status','import_id','application_id','version_digest','candidate_sha256','acceptance_sha256','preview_id','interaction_sha256','interaction','archive_digest','wheel_digest','environment_digest','import_identity_digest','binding_state','candidate_id','acceptance_id','source','toolchain'}
    if not isinstance(record,dict) or set(record)!=expected_keys or record['schema']!='capy.runtime-accepted-release-import/v0' or record['import_id']!=import_id or record['status']!='IMPORTED': fail()
    for key in ('version_digest','environment_digest','candidate_sha256','acceptance_sha256','interaction_sha256','archive_digest','wheel_digest','import_identity_digest'):
        if not isinstance(record.get(key),str) or re.fullmatch(r'[0-9a-f]{64}',record[key]) is None: fail()
    if row['capability_id']!=record.get('application_id') or row['version_digest']!=record['version_digest']: fail()
    folder=_safe_path(store.root/'accepted-releases'/import_id)
    if folder.is_symlink(): fail()
    raw=_read(folder/'record.json',2_000_000)
    if raw!=canonical_json(record): fail()
    candidate_bytes=_read(folder/'candidate.capyrc',32_000_000); receipt_bytes=_read(folder/'acceptance.json',2_000_000)
    candidate,receipt=validate_release(candidate_bytes,receipt_bytes,approvals)
    expected_identity={'candidate_sha256':digest(candidate_bytes),'acceptance_sha256':digest(receipt_bytes),'preview_id':approvals['preview_id']}
    if any(record.get(k)!=v for k,v in expected_identity.items()) or record['import_identity_digest']!=digest(canonical_json(expected_identity)) or import_id!='imp_'+record['import_identity_digest'][:32]: fail()
    if record['candidate_id']!=candidate.manifest['release_candidate_id'] or record['acceptance_id']!=receipt['acceptance_id'] or record['source']!=candidate.manifest['source'] or record['toolchain']!=candidate.manifest['toolchain'] or record['binding_state']!='UNBOUND': fail()
    if record['application_id']!=candidate.descriptor['id'] or record['interaction']!=candidate.interaction or record['interaction_sha256']!=digest(candidate.members['application/interaction.json']): fail()
    if _read(folder/'application.zip',16_000_000)!=candidate.members['application/application.zip'] or _read(folder/'devkit.whl',16_000_000)!=candidate.wheel_bytes: fail()
    if record['archive_digest']!=digest(candidate.members['application/application.zip']) or record['wheel_digest']!=digest(candidate.wheel_bytes): fail()
    app=_safe_path(store.scripts/record['version_digest']); env=_safe_path(store.root/'import-environments'/record['environment_digest'])
    for parent in (store.scripts.parent,store.scripts,store.root/'accepted-releases',store.root/'import-environments'):
        if parent.is_symlink(): fail()
    with zipfile.ZipFile(io.BytesIO(candidate.members['application/application.zip'])) as archive:
        modes={i.filename:bool((i.external_attr>>16)&0o111) for i in archive.infolist()}
    for name in candidate.application_members:
        if bool((app/name).stat().st_mode&0o111)!=modes[name]: fail()
    for path in env.rglob('*'):
        if path.is_file() and path.stat().st_mode&0o111: fail()
    if tree_digest(app)!=record['version_digest'] or tree_digest(env)!=record['environment_digest']: fail()
    # Exact expected file sets and content prevent a forged metadata digest from
    # blessing an altered tree, including executable-bit identity changes.
    if {p.relative_to(app).as_posix():p.read_bytes() for p in app.rglob('*') if p.is_file()}!=candidate.application_members: fail()
    if {p.relative_to(env).as_posix():p.read_bytes() for p in env.rglob('*') if p.is_file()}!=_wheel_members(candidate.wheel_bytes): fail()
    with store.connect() as db:
        version=db.execute('SELECT descriptor_json,acceptance_digest FROM capability_versions WHERE capability_id=? AND version_digest=?',(record['application_id'],record['version_digest'])).fetchone()
    if version is None or version['acceptance_digest']!=digest(receipt_bytes) or version['descriptor_json']!=CapabilityDescriptor.from_toml(app/'capability.toml').canonical_json(): fail()
    return record


@_bounded_errors
def lookup_import(store,capability_id,version_digest):
    with store.connect() as db:
        if not db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='accepted_imports'").fetchone(): return None
        row=db.execute('SELECT import_id FROM accepted_imports WHERE capability_id=? AND version_digest=?',(capability_id,version_digest)).fetchone()
    return inspect_import(_envelope(store),row['import_id']) if row else None


@_bounded_errors
def imported_environment(store,record):
    verified=inspect_import(_envelope(store),record['import_id'])
    if verified!=record: fail()
    return store.root/'import-environments'/record['environment_digest']
