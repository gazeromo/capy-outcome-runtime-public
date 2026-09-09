"""Trusted bridge custody admission into ordinary runtime stores, without execution.

Only the configured authenticated bridge client supplies custody. This module
never accepts browser-supplied receipts or changes legacy preview import guards.
"""
from __future__ import annotations

import io
import re
import uuid
import zipfile
from typing import Protocol

from ._release_format import codec
from .model import CapabilityDescriptor
from .store import canonical_json, tree_digest, utc_now
from .release_validation import validate_release, digest, fail
from .release_import import (_bounded_errors, _safe_path, _store_paths, _lock,
                             _read, _write_members, _wheel_members,
                             _publish_dir, _cleanup)

ACCEPTOR_WHEEL = 'bc1efe5cf11bc69a573300cf00a659dd71213055f9647eebc7e6ab4860b1b28d'
OWNER_KEYS = {'principal_id', 'authority_id', 'membership_id', 'workspace_id', 'workspace_kind'}
SELECTION_KEYS = {'handoff_id', 'project_id', 'application_id', 'session_id',
                  'verification_id', 'source_commit', 'candidate_id',
                  'candidate_sha256', 'candidate_size_bytes'}
TRUST_KEYS = {'schema', 'submission_id', 'owner', 'selection', 'profile_id',
              'profile_sha256', 'summary_sha256', 'authorization_id',
              'enrollment_id', 'attempt_id', 'acceptor', 'acceptor_wheel_sha256',
              'candidate_sha256', 'candidate_size_bytes', 'receipt_sha256',
              'receipt_size_bytes', 'source', 'application', 'toolchain',
              'expected_cases', 'expected_cases_sha256'}


class TrustedBridgeClient(Protocol):
    def export(self, *, owner: dict, submission_id: str, attempt_id: str) -> tuple[dict, bytes, bytes]: ...


def _checkpoint(stage):
    """Fault injection seam; performs no application work."""


def _shape(value, keys):
    if not isinstance(value, dict) or set(value) != keys:
        fail('RELEASE_CUSTODY_INVALID')


def _text(value):
    if not isinstance(value, str) or not value or len(value) > 256:
        fail('RELEASE_CUSTODY_INVALID')


def _hash(value):
    if not isinstance(value, str) or re.fullmatch('[0-9a-f]{64}', value) is None:
        fail('RELEASE_CUSTODY_INVALID')


def _trusted(record, candidate_bytes, receipt_bytes, owner, submission_id, attempt_id):
    _shape(record, TRUST_KEYS)
    if record['schema'] != 'capy.trusted-accepted-release/v0': fail('RELEASE_CUSTODY_INVALID')
    _shape(owner, OWNER_KEYS); _shape(record['owner'], OWNER_KEYS)
    for value in owner.values(): _text(value)
    if record['owner'] != owner or record['submission_id'] != submission_id or record['attempt_id'] != attempt_id:
        fail('RELEASE_CUSTODY_OWNER_MISMATCH')
    for key in ('submission_id', 'attempt_id', 'authorization_id', 'enrollment_id', 'profile_id'):
        _text(record[key])
    for key, prefix in (('submission_id','sub'), ('attempt_id','att'), ('authorization_id','aut'), ('enrollment_id','enr')):
        if re.fullmatch(prefix+'_[0-9a-f]{32}',record[key]) is None: fail('RELEASE_CUSTODY_INVALID')
    from .release_validation import ACCEPTOR_WHEELS
    if not isinstance(record['acceptor_wheel_sha256'], str) or ACCEPTOR_WHEELS.get(record['acceptor_wheel_sha256']) != record['acceptor']: fail('RELEASE_ACCEPTOR_UNTRUSTED')
    for key in ('profile_sha256', 'summary_sha256', 'candidate_sha256', 'receipt_sha256', 'expected_cases_sha256'):
        _hash(record[key])
    for raw, prefix, limit in ((candidate_bytes, 'candidate', 32_000_000), (receipt_bytes, 'receipt', 2_000_000)):
        if not isinstance(raw, bytes) or type(record[prefix+'_size_bytes']) is not int or not 0 < len(raw) <= limit:
            fail('RELEASE_CUSTODY_INVALID')
        if len(raw) != record[prefix+'_size_bytes'] or digest(raw) != record[prefix+'_sha256']:
            fail('RELEASE_CUSTODY_INVALID')
    selection = record['selection']; _shape(selection, SELECTION_KEYS)
    for key in SELECTION_KEYS - {'candidate_size_bytes'}: _text(selection[key])
    if type(selection['candidate_size_bytes']) is not int or selection['candidate_size_bytes'] != len(candidate_bytes) or selection['candidate_sha256'] != digest(candidate_bytes):
        fail('RELEASE_CUSTODY_INVALID')
    cases = record['expected_cases']
    if not isinstance(cases, list) or not cases or len(cases) > 1000 or digest(canonical_json(cases)) != record['expected_cases_sha256']:
        fail('RELEASE_CUSTODY_INVALID')
    seen = set()
    for case in cases:
        _shape(case, {'case_id', 'expected'}); _text(case['case_id'])
        if case['case_id'] in seen: fail('RELEASE_CUSTODY_INVALID')
        seen.add(case['case_id'])
    identity = {'candidate_bundle_sha256':record['candidate_sha256'],
                'candidate_release_candidate_id':selection['candidate_id'],
                'profile_bundle_sha256':record['profile_sha256'],
                'profile_id':record['profile_id'], 'application_id':selection['application_id'],
                'acceptor':record['acceptor']}
    entry = {'candidate_sha256':record['candidate_sha256'], 'acceptance_sha256':record['receipt_sha256'],
             'identity':identity, **{k:record[k] for k in ('source', 'application', 'toolchain')},
             'expected_cases':{c['case_id']:c['expected'] for c in cases}}
    # Reuse non-executing format checks, anchored exclusively to authenticated
    # custody. This value is never a preview envelope or caller approval file.
    candidate, receipt = validate_release(candidate_bytes, receipt_bytes,
        {'schema':'capy.runtime-import-approval/v0', 'preview_id':'trusted-bridge-custody', 'entries':[entry]})
    if [c['case_id'] for c in receipt['cases']] != [c['case_id'] for c in cases]:
        fail('RELEASE_CUSTODY_CASE_ORDER_MISMATCH')
    m = candidate.manifest
    if (selection['project_id'] != m['project']['project_id'] or
        selection['source_commit'] != m['source']['commit'] or
        selection['verification_id'] != m['verification']['verification_id']):
        fail('RELEASE_CUSTODY_SELECTION_MISMATCH')
    return candidate, receipt


def _schema(store):
    with store.connect() as db:
        db.execute('CREATE TABLE IF NOT EXISTS release_namespace_claims (capability_id TEXT PRIMARY KEY, namespace_json TEXT NOT NULL)')
        db.execute('CREATE TABLE IF NOT EXISTS accepted_admissions (admission_id TEXT PRIMARY KEY, capability_id TEXT NOT NULL, version_digest TEXT NOT NULL, record_json TEXT NOT NULL, UNIQUE(capability_id,version_digest))')
        db.execute('CREATE TABLE IF NOT EXISTS release_admission_attempts (stage_id TEXT PRIMARY KEY, admission_id TEXT NOT NULL, status TEXT NOT NULL, created_at TEXT NOT NULL)')


def _namespace(trust):
    return {**{k:trust['owner'][k] for k in ('authority_id','principal_id')}, 'project_id':trust['selection']['project_id']}


def _record(trust, candidate, receipt, version, environment):
    identity = digest(canonical_json(trust)); admission_id = 'adm_'+identity[:32]
    return {'schema':'capy.runtime-accepted-release-admission/v0', 'status':'ADMITTED',
            'admission_id':admission_id, 'import_id':admission_id, 'admission_identity_digest':identity,
            'namespace':_namespace(trust), 'trusted_record':trust, 'binding_state':'UNBOUND',
            'application_id':candidate.descriptor['id'], 'version_digest':version,
            'candidate_sha256':trust['candidate_sha256'], 'acceptance_sha256':trust['receipt_sha256'],
            'candidate_id':candidate.manifest['release_candidate_id'], 'acceptance_id':receipt['acceptance_id'],
            'interaction_sha256':digest(candidate.members['application/interaction.json']),
            'interaction':candidate.interaction, 'archive_digest':digest(candidate.members['application/application.zip']),
            'wheel_digest':digest(candidate.wheel_bytes), 'environment_digest':environment,
            'source':candidate.manifest['source'], 'toolchain':candidate.manifest['toolchain']}


def _paths(store):
    _store_paths(store.root)
    for name in ('admission-staging', 'admitted-releases'):
        _safe_path(store.root/name)


@_bounded_errors
def admit_release(store, bridge_client: TrustedBridgeClient, owner, submission_id, attempt_id):
    """Admit one currently authorized export from the configured trusted peer."""
    trust, candidate_bytes, receipt_bytes = bridge_client.export(owner=owner, submission_id=submission_id, attempt_id=attempt_id)
    # Deep-copy the peer result so later caller mutation cannot change custody.
    trust = codec.parse_strict_json(canonical_json(trust))
    candidate, receipt = _trusted(trust, candidate_bytes, receipt_bytes, owner, submission_id, attempt_id)
    _paths(store); _schema(store)
    admission_id = 'adm_'+digest(canonical_json(trust))[:32]
    namespace = canonical_json(_namespace(trust)).decode()
    with _lock(store):
        with store.connect() as db:
            stale = db.execute("SELECT stage_id FROM release_admission_attempts WHERE status='STAGING'").fetchall()
            for row in stale:
                if re.fullmatch('[0-9a-f]{32}',row['stage_id']) is None: fail()
                _cleanup(store.root/'admission-staging'/row['stage_id'])
            db.execute("UPDATE release_admission_attempts SET status='INTERRUPTED' WHERE status='STAGING'")
            existing = db.execute('SELECT admission_id FROM accepted_admissions WHERE admission_id=?',(admission_id,)).fetchone()
        if existing: return inspect_admission(store, admission_id)
        stage_id = uuid.uuid4().hex; staging = store.root/'admission-staging'/stage_id
        with store.connect() as db:
            db.execute('INSERT INTO release_admission_attempts VALUES (?,?,?,?)',(stage_id,admission_id,'STAGING',utc_now()))
        try:
            _checkpoint('attempt_started')
            with zipfile.ZipFile(io.BytesIO(candidate.members['application/application.zip'])) as archive:
                modes = {i.filename:bool((i.external_attr>>16)&0o111) for i in archive.infolist()}
            _write_members(staging/'application', candidate.application_members, modes)
            _write_members(staging/'environment', _wheel_members(candidate.wheel_bytes))
            version = tree_digest(staging/'application'); environment = tree_digest(staging/'environment')
            descriptor = CapabilityDescriptor.from_toml(staging/'application'/'capability.toml')
            from .portable_interfaces import project_portable
            project_portable({**candidate.descriptor,'version_digest':version}, candidate.interaction, admission_id)
            record = _record(trust,candidate,receipt,version,environment)
            _write_members(staging/'evidence', {'candidate.capyrc':candidate_bytes,'acceptance.json':receipt_bytes,'record.json':canonical_json(record)})
            _checkpoint('files_staged')
            with store.connect() as db:
                claim = db.execute('SELECT namespace_json FROM release_namespace_claims WHERE capability_id=?',(descriptor.id,)).fetchone()
                prior = db.execute('SELECT 1 FROM capability_versions WHERE capability_id=?',(descriptor.id,)).fetchone()
                if (claim and claim['namespace_json'] != namespace) or (prior and not claim):
                    fail('RELEASE_NAMESPACE_CONFLICT')
                conflict = db.execute('SELECT record_json FROM accepted_admissions WHERE capability_id=? AND version_digest=?',(descriptor.id,version)).fetchone()
                if conflict:
                    old = codec.parse_strict_json(conflict['record_json'].encode())
                    # A different custody/profile receipt cannot silently replace
                    # the release identity even if application bytes match.
                    if old != record: fail('RELEASE_ADMISSION_CONFLICT')
                legacy = db.execute('SELECT 1 FROM capability_versions WHERE capability_id=? AND version_digest=?',(descriptor.id,version)).fetchone()
                if legacy and not conflict: fail('RELEASE_ADMISSION_CONFLICT')
            _publish_dir(staging/'application',store.scripts/version)
            _publish_dir(staging/'environment',store.root/'import-environments'/environment)
            _safe_path(store.root/'import-environments').chmod(0o711)
            _publish_dir(staging/'evidence',store.root/'admitted-releases'/admission_id)
            _checkpoint('files_published')
            with store.connect() as db:
                db.execute('INSERT OR IGNORE INTO release_namespace_claims VALUES (?,?)',(descriptor.id,namespace))
                db.execute('INSERT INTO capability_versions VALUES (?,?,?,?,?)',(descriptor.id,version,descriptor.canonical_json(),digest(receipt_bytes),utc_now()))
                db.execute('INSERT INTO accepted_admissions VALUES (?,?,?,?)',(admission_id,descriptor.id,version,canonical_json(record).decode()))
                db.execute("UPDATE release_admission_attempts SET status='COMMITTED' WHERE stage_id=?",(stage_id,))
            _checkpoint('committed')
            return inspect_admission(store, admission_id)
        except Exception:
            with store.connect() as db:
                db.execute("UPDATE release_admission_attempts SET status='FAILED' WHERE stage_id=? AND status='STAGING'",(stage_id,))
            raise
        finally:
            _cleanup(staging)


@_bounded_errors
def inspect_admission(store, admission_id):
    if not isinstance(admission_id,str) or re.fullmatch('adm_[0-9a-f]{32}',admission_id) is None: fail()
    _paths(store)
    with store.connect() as db:
        if not db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='accepted_admissions'").fetchone():
            fail('RELEASE_ADMISSION_NOT_FOUND')
        row = db.execute('SELECT * FROM accepted_admissions WHERE admission_id=?',(admission_id,)).fetchone()
    if row is None: fail('RELEASE_ADMISSION_NOT_FOUND')
    record = codec.parse_strict_json(row['record_json'].encode())
    folder = _safe_path(store.root/'admitted-releases'/admission_id)
    if _read(folder/'record.json',2_000_000) != canonical_json(record): fail()
    trust = record['trusted_record']
    candidate, receipt = _trusted(trust, _read(folder/'candidate.capyrc',32_000_000),
        _read(folder/'acceptance.json',2_000_000),trust['owner'],trust['submission_id'],trust['attempt_id'])
    for key in ('version_digest','environment_digest'): _hash(record[key])
    app = _safe_path(store.scripts/record['version_digest'])
    env = _safe_path(store.root/'import-environments'/record['environment_digest'])
    for path, expected in ((app,candidate.application_members),(env,_wheel_members(candidate.wheel_bytes))):
        if not path.is_dir() or any(p.is_symlink() for p in path.rglob('*')): fail()
        actual = {p.relative_to(path).as_posix():p.read_bytes() for p in path.rglob('*') if p.is_file()}
        if actual != expected: fail()
    with zipfile.ZipFile(io.BytesIO(candidate.members['application/application.zip'])) as archive:
        modes = {i.filename:bool((i.external_attr>>16)&0o111) for i in archive.infolist()}
    if any(bool((app/name).stat().st_mode&0o111) != mode for name,mode in modes.items()): fail()
    if any(p.stat().st_mode&0o111 for p in env.rglob('*') if p.is_file()): fail()
    expected = _record(trust,candidate,receipt,tree_digest(app),tree_digest(env))
    if record != expected or record['admission_id'] != admission_id: fail()
    if row['capability_id'] != record['application_id'] or row['version_digest'] != record['version_digest']: fail()
    with store.connect() as db:
        claim = db.execute('SELECT namespace_json FROM release_namespace_claims WHERE capability_id=?',(record['application_id'],)).fetchone()
        version = db.execute('SELECT descriptor_json,acceptance_digest FROM capability_versions WHERE capability_id=? AND version_digest=?',(record['application_id'],record['version_digest'])).fetchone()
    if claim is None or claim['namespace_json'] != canonical_json(record['namespace']).decode(): fail()
    if version is None or version['descriptor_json'] != CapabilityDescriptor.from_toml(app/'capability.toml').canonical_json() or version['acceptance_digest'] != record['acceptance_sha256']: fail()
    return record


@_bounded_errors
def lookup_admission(store, capability_id, version_digest):
    with store.connect() as db:
        if not db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='accepted_admissions'").fetchone(): return None
        row = db.execute('SELECT admission_id FROM accepted_admissions WHERE capability_id=? AND version_digest=?',(capability_id,version_digest)).fetchone()
    return inspect_admission(store,row['admission_id']) if row else None


@_bounded_errors
def admitted_environment(store, record):
    if inspect_admission(store,record['admission_id']) != record: fail()
    # The service umask must not prevent the isolated app identity from
    # traversing to its verified, read-only library tree.
    parent = _safe_path(store.root/'import-environments')
    parent.chmod(0o711)
    return parent/record['environment_digest']
