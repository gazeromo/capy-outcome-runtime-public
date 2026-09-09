"""Private preview contexts using the same portable Workbench and runtime."""
from __future__ import annotations

import json
import hashlib
import re
import secrets
import os
import shutil
import threading
from contextlib import contextmanager
from dataclasses import replace
from pathlib import Path

from .application_interfaces import ContractDerivedInterfaceService
from .portable_interfaces import project_portable
from .release_admission import admit_release, inspect_admission
from .release_import import _safe_path
from .launcher import LocalProcessLauncher
from .release_workflow import fail
from .runtime import OutcomeRuntime
from .store import RuntimeStore, canonical_json


def _cleanup(path):
    """Delete a fenced, reaped preview without changing executor-owned modes.

    The controller can remove foreign-owned journals through its existing
    filesystem authority. That does not imply permission to chmod them.
    Any deletion denial propagates, retaining DELETING and its occupied slot.
    """
    _safe_path(path)
    if not path.exists():
        return
    path.chmod(0o700)
    for item in path.rglob('*'):
        if (not item.is_symlink() and item.is_dir()
                and item.stat().st_uid == os.geteuid()):
            item.chmod(0o700)
    shutil.rmtree(path)


class ReleasePreviews:
    def __init__(self, workflow, root, launcher_factory, *, slots=2, ttl=86400, quota=16_000_000,
                 connection_control=None, broker_socket=None):
        self.connection_control, self.broker_socket = connection_control, broker_socket
        self.workflow, self.root = workflow, Path(root)
        self.launcher_factory, self.slots, self.ttl, self.quota = launcher_factory, slots, ttl, quota
        if self.root.is_symlink() or not 1 <= slots <= 16 or not 1 <= ttl <= 86400:
            fail('RELEASE_PREVIEW_CONFIG_INVALID')
        self.root.mkdir(mode=0o711, parents=True, exist_ok=True)
        self.root.chmod(0o711)
        self._lock = threading.RLock()
        # Migrate the task's initial unique-per-release schema without losing
        # rows. New generations retain old immutable identity/audit records.
        with workflow.store.transaction() as db:
            columns = {r[1] for r in db.execute("PRAGMA table_info(release_previews)")}
            if columns and 'generation' not in columns:
                db.execute('ALTER TABLE release_previews RENAME TO release_previews_v0')
            db.execute("""CREATE TABLE IF NOT EXISTS release_previews (
              id TEXT PRIMARY KEY, submission_id TEXT NOT NULL, attempt_id TEXT NOT NULL,
              record_json TEXT NOT NULL, status TEXT NOT NULL, expires_at INTEGER NOT NULL,
              successful_activity TEXT, slot INTEGER NOT NULL, generation INTEGER NOT NULL,
              audit_json TEXT, UNIQUE(submission_id,attempt_id,generation))""")
            if columns and 'generation' not in columns:
                db.execute("""INSERT INTO release_previews SELECT id,submission_id,attempt_id,
                  record_json,status,expires_at,successful_activity,slot,1,NULL FROM release_previews_v0""")
                db.execute('DROP TABLE release_previews_v0')
            db.execute("""CREATE UNIQUE INDEX IF NOT EXISTS preview_occupied_slot ON
              release_previews(slot) WHERE status IN ('PREPARING','ACTIVE','CLEANUP_PENDING','DELETING')""")

    def _row(self, actor, preview_id, *, allow_ended=False):
        if not isinstance(preview_id, str) or not re.fullmatch(r'prv_[0-9a-f]{32}', preview_id):
            fail('RELEASE_PREVIEW_UNKNOWN')
        with self.workflow.store.connect() as db:
            row = db.execute('SELECT * FROM release_previews WHERE id=?', (preview_id,)).fetchone()
        if row is None:
            fail('RELEASE_PREVIEW_UNKNOWN')
        row = dict(row)
        self.workflow._row(row['submission_id'], actor)
        if not allow_ended and (row['status'] != 'ACTIVE' or row['expires_at'] <= self.workflow.clock()):
            fail('RELEASE_PREVIEW_EXPIRED')
        row['record'] = json.loads(row['record_json'])
        return row

    def create(self, actor, submission):
        with self.workflow.access.guarded_actor(actor), self._lock:
            source = self.workflow._row(submission, actor)
            status = self.workflow.status(actor, submission)
            attempt = status['attempt']
            if not attempt or attempt['status'] != 'ACCEPTED':
                fail('RELEASE_CHECKS_REQUIRED')
            self.expire()
            with self.workflow.store.connect() as db:
                previous = db.execute('SELECT * FROM release_previews WHERE submission_id=? AND attempt_id=? ORDER BY generation DESC LIMIT 1', (submission, attempt['attempt_id'])).fetchone()
                old = previous if previous and previous['status'] in ('PREPARING','ACTIVE') else None
                if old and old['status'] == 'ACTIVE':
                    return self._row(actor, old['id'])
                occupied = {r[0] for r in db.execute("SELECT slot FROM release_previews WHERE status IN ('PREPARING','ACTIVE','CLEANUP_PENDING','DELETING')")}
            slot = old['slot'] if old else next((s for s in range(self.slots) if s not in occupied), None)
            if slot is None:
                fail('RELEASE_PREVIEW_CAPACITY')
            pid = old['id'] if old else 'prv_'+secrets.token_hex(16)
            generation = old['generation'] if old else (previous['generation']+1 if previous else 1)
            with self.workflow.store.connect() as db:
                db.execute('INSERT OR IGNORE INTO release_previews VALUES (?,?,?,?,?,?,NULL,?,?,NULL)',
                    (pid, submission, attempt['attempt_id'], '{}', 'PREPARING', int(self.workflow.clock())+self.ttl, slot,generation))
            folder = _safe_path(self.root / pid)
            folder.mkdir(mode=0o711,exist_ok=True)
            folder.chmod(0o711)
            store = RuntimeStore(folder/'application-store')
            record = admit_release(store, self.workflow.bridge, source['owner'], submission, attempt['attempt_id'])
            scope = 'preview_'+pid[4:]
            store.register_scope(scope)
            descriptor = store.descriptor(record['application_id'], record['version_digest'])
            connections = self.bindings(descriptor, record['version_digest'], source['owner']['workspace_id'],
                                        scope, source['owner']['membership_id'], preview_id=pid)
            store.bind(scope, record['application_id'], record['version_digest'], connections)
            with self.workflow.store.connect() as db:
                db.execute("UPDATE release_previews SET record_json=?,status='ACTIVE' WHERE id=?",
                    (canonical_json(record).decode(), pid))
            return self._row(actor, pid)

    def bindings(self, descriptor, version, workspace_id, scope_id, membership_id, *, preview_id=None):
        if not descriptor.connections:
            return {}
        if self.connection_control is None or self.broker_socket is None:
            fail('APPLICATION_CONNECTION_SETUP_REQUIRED')
        return self.connection_control.application_bindings(
            descriptor, version, workspace_id=workspace_id, scope_id=scope_id,
            membership_id=membership_id, preview_id=preview_id)

    @contextmanager
    def context(self, actor, preview_id):
        # Shared current-authority guard serializes with revocation. URL fields
        # never manufacture an actor; only this private exact stored mapping can.
        with self.workflow.access.guarded_actor(actor), self._lock:
            row = self._row(actor, preview_id)
            # Restore traversal for active previews created under a restrictive
            # service umask. Retired previews never reach this guarded context.
            folder = _safe_path(self.root/preview_id)
            folder.chmod(0o711)
            store = RuntimeStore(folder/'application-store')
            record = inspect_admission(store, row['record']['admission_id'])
            if record != row['record']:
                fail('RELEASE_PREVIEW_IDENTITY_CHANGED')
            source = self.workflow._row(row['submission_id'], actor)
            owner = source['owner']
            mapped = replace(actor, execution_scope_id='preview_'+preview_id[4:],
                             membership_id=owner['membership_id'], team_id=owner['workspace_id'],
                             workspace_kind=owner['workspace_kind'])
            binding = store.binding(mapped.execution_scope_id, record['application_id'])
            descriptor = store.descriptor(record['application_id'], record['version_digest'])
            if descriptor.connections:
                connections = self.bindings(descriptor, record['version_digest'], owner['workspace_id'],
                                            mapped.execution_scope_id, owner['membership_id'], preview_id=preview_id)
                if connections != binding.connections:
                    self.connection_control.revoke_bindings(binding.connections)
                    store.bind(mapped.execution_scope_id, record['application_id'], record['version_digest'], connections)
            runtime = OutcomeRuntime(store, launcher=self.launcher_factory(row['slot']),
                                     connection_control=self.connection_control, broker_socket=self.broker_socket)
            def contract(_actor, app):
                if _actor != mapped or app != record['application_id']:
                    fail('RELEASE_PREVIEW_IDENTITY_CHANGED')
                execution = json.loads(store.descriptor(app, record['version_digest']).canonical_json())
                return project_portable(dict(execution, version_digest=record['version_digest']), record['interaction'], record['import_id'])
            # Methods are called only inside this authority-held context.
            service = ContractDerivedInterfaceService(store, None, runtime, None, contract)
            yield row, mapped, service

    def submit(self, actor, preview_id, operation, fields, files):
        with self.context(actor, preview_id) as (row, mapped, service):
            incoming = {hashlib.sha256(item[2]).hexdigest():len(item[2]) for value in files.values()
                        for item in (value if isinstance(value, list) else [value])}
            with service.runtime_store.connect() as db:
                existing = {r['digest']:r['size_bytes'] for r in db.execute('SELECT digest,size_bytes FROM resources')}
            if sum(existing.values())+sum(size for digest,size in incoming.items() if digest not in existing) > self.quota:
                fail('RELEASE_PREVIEW_RESOURCE_QUOTA')
            if fields.get('workspace_membership_id') != mapped.membership_id:
                fail('RELEASE_PREVIEW_IDENTITY_CHANGED')
            result = service.submit(mapped, row['record']['application_id'], operation, fields, files)
            if result.get('result',{}).get('status')!='needs_input':
                with self.workflow.store.connect() as db:
                    db.execute('UPDATE release_previews SET successful_activity=? WHERE id=?', (result['activity_id'], preview_id))
            return result

    def _retire(self, row):
        """Revoke access first, prove cleanup, preserve audit, then delete payload."""
        pid=row['id']
        if not re.fullmatch(r'prv_[0-9a-f]{32}',pid): fail('RELEASE_PREVIEW_UNKNOWN')
        if row['status']=='ENDED' and row['audit_json']:
            return True
        folder=_safe_path(self.root/pid)
        with self.workflow.store.connect() as db:
            db.execute("UPDATE release_previews SET status='CLEANUP_PENDING' WHERE id=? AND status!='DELETING'",(pid,))
        if self.connection_control is not None:
            with self.connection_control.store.connect() as db:
                grants = {r['id']: r['id'] for r in db.execute(
                    "SELECT id FROM connection_grants WHERE scope_id=?", ('preview_'+pid[4:],))}
            self.connection_control.revoke_bindings(grants)
        if folder.exists(): folder.chmod(0o700)
        # A persisted proof precedes any destructive cleanup, so restart after
        # partial deletion never opens a damaged store or guesses process state.
        audit=json.loads(row['audit_json']) if row.get('audit_json') else None
        if not audit or audit.get('cleanup_confirmed') is not True:
            audit={'schema':'capy.preview-retirement/v0','preview_id':pid,
                   'generation':row['generation'],'admission_record_sha256':hashlib.sha256(row['record_json'].encode()).hexdigest(),
                   'invocations':[],'cleanup_confirmed':False}
            database=folder/'application-store'/'control.sqlite3'
            if not database.exists():
                if row['status']!='PREPARING': return False
            else:
                store=RuntimeStore(folder/'application-store')
                launcher=self.launcher_factory(row['slot'])
                with store.connect() as db:
                    executors=[dict(r) for r in db.execute('SELECT * FROM invocation_executors')]
                    invocations=[dict(r) for r in db.execute('SELECT id,scope_id,status,request_digest,receipt_json FROM invocations')]
                by_id={r['id']:r for r in invocations}
                for executor in executors:
                    invocation=by_id.get(executor['invocation_id'])
                    journal=_safe_path(store.journals/executor['invocation_id'])
                    if (not invocation or invocation['scope_id']!='preview_'+pid[4:] or
                        executor['unit_name']!='capy-outcome-invocation-'+executor['invocation_id'] or
                        executor['journal_path']!=str(journal) or
                        hashlib.sha256((journal/'executor-spec.json').read_bytes()).hexdigest()!=executor['journal_digest']):
                        return False
                    if isinstance(launcher,LocalProcessLauncher):
                        # Synchronous LocalProcessLauncher is unit behavior only.
                        # A nonterminal unit has no trustworthy restart PID proof.
                        if invocation['status'] not in ('succeeded','failed'): return False
                    else:
                        if executor['machine_id_sha256']!=launcher.machine_id_sha256(): return False
                        if executor['boot_id']==launcher.boot_id():
                            stop=getattr(launcher,'stop_owned_unit',None)
                            if stop is None or not stop(executor['unit_name'],journal,launcher.execution_identity(invocation['scope_id'])):
                                return False
                        # Same machine / changed boot proves prior processes gone.
                if any(r['status']=='running' and r['id'] not in {e['invocation_id'] for e in executors} for r in invocations): return False
                for invocation in invocations:
                    audit['invocations'].append({'invocation_id':invocation['id'],'status':invocation['status'],
                        'request_digest':invocation['request_digest'],
                        'receipt_sha256':hashlib.sha256((invocation['receipt_json'] or '').encode()).hexdigest()})
            audit['cleanup_confirmed']=True
            audit['payload_deleted']=False
            with self.workflow.store.connect() as db:
                db.execute("UPDATE release_previews SET audit_json=?,status='DELETING' WHERE id=?",(canonical_json(audit).decode(),pid))
        _cleanup(folder)
        audit['payload_deleted']=True
        with self.workflow.store.connect() as db:
            db.execute("UPDATE release_previews SET audit_json=?,status='ENDED' WHERE id=?",(canonical_json(audit).decode(),pid))
        return True

    def expire(self):
        """Authority-independent expiry cleanup; inaccessible failures keep slots."""
        results=[]
        with self._lock:
            with self.workflow.store.connect() as db:
                rows=[dict(r) for r in db.execute("""SELECT * FROM release_previews
                    WHERE (status IN ('ACTIVE','PREPARING') AND expires_at<=?)
                    OR status IN ('CLEANUP_PENDING','DELETING')
                    OR (status='ENDED' AND audit_json IS NULL)""",(int(self.workflow.clock()),))]
            for row in rows:
                try:clean=self._retire(row)
                except Exception:clean=False
                results.append({'preview_id':row['id'],'cleanup_confirmed':clean})
        return results

    def end(self, actor, preview_id):
        with self.workflow.access.guarded_actor(actor), self._lock:
            self._row(actor,preview_id,allow_ended=True)
            with self.workflow.store.connect() as db:
                row=dict(db.execute('SELECT * FROM release_previews WHERE id=?',(preview_id,)).fetchone())
            if not self._retire(row): fail('RELEASE_PREVIEW_CLEANUP_REQUIRED')
