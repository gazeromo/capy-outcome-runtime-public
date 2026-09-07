"""Owner authority and durable coordination; never executes application checks."""
from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import tempfile
import threading
import time
from pathlib import Path

from .model import RuntimeFailure
from .store import canonical_json

MAX_CANDIDATE = 32_000_000


def fail(code='RELEASE_AUTHORITY_DENIED'):
    raise RuntimeFailure(code)


def owner_context(actor):
    return dict(principal_id=actor.principal_id, authority_id=actor.authority_id,
                membership_id=actor.membership_id, workspace_id=actor.team_id,
                workspace_kind=actor.workspace_kind)


class ReleaseWorkflow:
    def __init__(self, store, access, link, bridge, root, *, clock=time.time):
        if link is None:
            fail('RELEASE_DEVELOPER_LINK_REQUIRED')
        self.store, self.access, self.link, self.bridge = store, access, link, bridge
        self.root, self.clock = Path(root), clock
        if self.root.is_symlink():
            fail('RELEASE_PATH_INVALID')
        self.root.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.root.chmod(0o700)
        self._pump_lock = threading.Lock()
        self._stop = threading.Event()
        self._thread = None
        with store.connect() as db:
            db.executescript('''
              CREATE TABLE IF NOT EXISTS release_submissions (
                id TEXT PRIMARY KEY, handoff_id TEXT NOT NULL, owner_json TEXT NOT NULL,
                intent_json TEXT NOT NULL, profile_sha256 TEXT, attempt_id TEXT,
                error_code TEXT, created_at INTEGER NOT NULL,
                idempotency_key TEXT NOT NULL, UNIQUE(owner_json,idempotency_key));
              CREATE TABLE IF NOT EXISTS release_check_actions (
                submission_id TEXT NOT NULL, idempotency_key TEXT NOT NULL,
                request_json TEXT NOT NULL, attempt_id TEXT,
                PRIMARY KEY(submission_id,idempotency_key));
              CREATE TABLE IF NOT EXISTS release_installation_acks (
                activation_id TEXT PRIMARY KEY);

            ''')

    def _authority(self, owner):
        self.link.authority(owner['principal_id'], owner['authority_id'],
                            owner['membership_id'], owner['workspace_id'], owner['workspace_kind'])

    def _row(self, submission, actor=None):
        if not isinstance(submission, str) or not re.fullmatch(r'sub_[0-9a-f]{32}', submission):
            fail('RELEASE_SUBMISSION_UNKNOWN')
        with self.store.connect() as db:
            row = db.execute('SELECT * FROM release_submissions WHERE id=?', (submission,)).fetchone()
        if row is None:
            fail('RELEASE_SUBMISSION_UNKNOWN')
        row = dict(row)
        row['owner'] = json.loads(row['owner_json'])
        row['intent'] = json.loads(row['intent_json'])
        self._authority(row['owner'])
        if actor is not None:
            self.access._require_current_actor(actor)
            if actor.principal_id != row['owner']['principal_id'] or actor.authority_id != row['owner']['authority_id']:
                fail()
        return row

    def review(self, actor, handoff):
        with self.access.guarded_actor(actor):
            status = self.link.status(actor, handoff)
            snap = status['snapshot']
            if not snap or not snap['candidate_id'] or not snap['candidate_sha256']:
                fail('RELEASE_CANDIDATE_REQUIRED')
            selection = dict(handoff_id=handoff, project_id=snap['project_id'],
                application_id=snap['application_id'], session_id=snap['session_id'],
                verification_id=snap['candidate_verification_id'], source_commit=snap['candidate_commit'],
                candidate_id=snap['candidate_id'], candidate_sha256=snap['candidate_sha256'],
                candidate_size_bytes=snap['candidate_size'])
            if not all(v is not None for v in selection.values()):
                fail('RELEASE_CANDIDATE_REQUIRED')
            return status['request'], selection

    def begin(self, actor, handoff, idempotency_key):
        if not isinstance(idempotency_key, str) or not re.fullmatch(r'[A-Za-z0-9_-]{16,128}', idempotency_key):
            fail('RELEASE_IDEMPOTENCY_INVALID')
        with self.access.guarded_actor(actor):
            request, selection = self.review(actor, handoff)
            owner = owner_context(actor)
            with self.store.transaction() as db:
                old = db.execute('SELECT * FROM release_submissions WHERE owner_json=? AND idempotency_key=?',
                                 (canonical_json(owner).decode(), idempotency_key)).fetchone()
                if old:
                    intent = json.loads(old['intent_json'])
                    if intent['selection'] != selection:
                        fail('RELEASE_IDEMPOTENCY_CONFLICT')
                else:
                    # Bridge enforces pending-count and payload quotas per principal;
                    # retained terminal history must not exhaust pending capacity.
                    now = int(self.clock())
                    intent = dict(submission_id='sub_'+secrets.token_hex(16), site_id=self.link.site_id,
                        device_id=request['device_id'], owner=owner, selection=selection,
                        consent_revision='source-package-v0', created_at=now,
                        expires_at=now+900, generation=1)
                    db.execute('INSERT INTO release_submissions VALUES (?,?,?,?,NULL,NULL,NULL,?,?)',
                               (intent['submission_id'], handoff, canonical_json(owner).decode(),
                                canonical_json(intent).decode(), now, idempotency_key))
            # Intent precedes external mutation. Replaying after lost bridge ack is safe.
            self.bridge.call('submission.begin', intent)
            return intent['submission_id']

    def device_capabilities(self, value, secret, peer):
        if set(value) != {'schema','site_id','device_id'} or value['schema'] != 'capy.candidate-capabilities/v0' or value['site_id'] != self.link.site_id:
            fail('RELEASE_PROTOCOL_INVALID')
        proof = self.link.proof(secret, peer)
        with self.link.db() as db:
            self.link.device(db, value['device_id'], proof)
        return dict(schema='capy.candidate-capabilities/v0', site_id=self.link.site_id,
                    device_id=value['device_id'], supported=True, max_candidate_bytes=MAX_CANDIDATE)

    def pending_for_device(self, value, secret, peer):
        if (not isinstance(value, dict) or set(value) != {'schema', 'site_id', 'device_id', 'handoff_id'}
                or value['schema'] != 'capy.candidate-pending-request/v0' or value['site_id'] != self.link.site_id
                or not isinstance(value['handoff_id'], str) or not re.fullmatch(r'hof_[0-9a-f]{32}', value['handoff_id'])):
            fail('RELEASE_PROTOCOL_INVALID')
        proof = self.link.proof(secret, peer)
        with self.access.authority_transition_guard():
            with self.link.db() as db:
                device = self.link.device(db, value['device_id'], proof)
                _, request = self.link.request(db, value['handoff_id'], proof=proof)
                if request['device_id'] != device['id']:
                    fail()
            with self.store.connect() as db:
                rows = db.execute('''SELECT id,intent_json FROM release_submissions
                    WHERE handoff_id=? AND created_at>? ORDER BY created_at,id LIMIT 21''',
                    (value['handoff_id'], int(self.clock()) - 900)).fetchall()
            if len(rows) > 20:
                fail('RELEASE_PENDING_LIMIT')
            pending = []
            for saved in rows:
                row = self._row(saved['id'])
                intent = row['intent']
                if intent['device_id'] != device['id'] or intent['expires_at'] <= self.clock():
                    continue
                if row['owner']['principal_id'] != device['principal'] or row['owner']['authority_id'] != device['authority']:
                    fail()
                remote = self.bridge.call('submission.inspect', dict(submission_id=row['id'], owner=row['owner']))
                if remote['status'] not in ('AUTHORIZED', 'PENDING', 'WAITING', 'RECEIVING'):
                    continue
                # Reuse every current grant check; this read never creates consent.
                grant = self.grant(row['id'], dict(schema='capy.candidate-grant-request/v0',
                    site_id=value['site_id'], device_id=device['id'], generation=intent['generation']), secret, peer)
                pending.append(dict(submission_id=row['id'], generation=intent['generation'],
                    candidate_id=grant['selection']['candidate_id'], source_commit=grant['selection']['source_commit']))
            return dict(schema='capy.candidate-pending/v0', site_id=value['site_id'],
                        device_id=device['id'], handoff_id=value['handoff_id'], submissions=pending)

    def grant(self, submission, value, secret, peer):
        if set(value) != {'schema','site_id','device_id','generation'} or value['schema'] != 'capy.candidate-grant-request/v0':
            fail('RELEASE_PROTOCOL_INVALID')
        with self.access.authority_transition_guard():
            row = self._row(submission)
            intent = row['intent']
            if (type(value['generation']) is not int or any(value[k] != intent[k] for k in ('site_id','device_id','generation'))
                or intent['expires_at'] <= self.clock()):
                fail('RELEASE_GRANT_EXPIRED')
            proof = self.link.proof(secret, peer)
            with self.link.db() as db:
                device = self.link.device(db, intent['device_id'], proof)
                _stored, request = self.link.request(db, row['handoff_id'], permit_disconnected=True)
                pair = db.execute('SELECT * FROM device_installations WHERE device=?', (intent['device_id'],)).fetchone()
                if pair is None or any(pair[k] != device[k] for k in ('digest','principal','authority')) or request['device_id'] != intent['device_id'] or device['principal'] != row['owner']['principal_id'] or _stored['state'] in ('CANCELLED','DISCONNECTED'):
                    fail()
            remote = self.bridge.call('submission.inspect', dict(submission_id=submission, owner=row['owner']))
            if remote['status'] not in ('AUTHORIZED','PENDING','RECEIVED','WAITING','RECEIVING'):
                fail('RELEASE_SUBMISSION_CANCELLED')
            return dict(schema='capy.candidate-transfer-grant/v0', submission_id=submission,
                site_id=intent['site_id'], device_id=intent['device_id'], generation=intent['generation'],
                expires_at=intent['expires_at'], consent_revision=intent['consent_revision'],
                installation_id=pair['installation'], principal_id=row['owner']['principal_id'],
                authority_id=row['owner']['authority_id'], selection=intent['selection'])

    def receive(self, submission, value, secret, peer, stream, length):
        grant = self.grant(submission, value, secret, peer)
        if type(length) is not int or not 0 < length <= MAX_CANDIDATE or length != grant['selection']['candidate_size_bytes']:
            fail('RELEASE_BODY_LIMIT')
        fd, path = tempfile.mkstemp(prefix='opaque-upload-', dir=self.root)
        try:
            digest = hashlib.sha256()
            with os.fdopen(fd, 'w+b') as staged:
                remaining = length
                while remaining:
                    block = stream.read(min(65536, remaining))
                    if not block:
                        fail('RELEASE_UPLOAD_INTERRUPTED')
                    staged.write(block); digest.update(block); remaining -= len(block)
                if digest.hexdigest() != grant['selection']['candidate_sha256']:
                    fail('RELEASE_CANDIDATE_DIGEST_MISMATCH')
                staged.flush(); os.fsync(staged.fileno()); staged.seek(0)
                # Revocation during receive is observed here, before custody publication.
                with self.access.authority_transition_guard():
                    self.grant(submission, value, secret, peer)
                    row = self._row(submission)
                    current = self.bridge.call('submission.inspect', dict(submission_id=submission, owner=row['owner']))
                    self.bridge.call_stream('submission.receive', dict(submission_id=submission,
                        owner=row['owner'], expected_revision=current['revision']), staged, length)
                return dict(schema='capy.candidate-custody/v0', submission_id=submission,
                    candidate_id=grant['selection']['candidate_id'], candidate_sha256=digest.hexdigest(),
                    candidate_size_bytes=length, status='RECEIVED')
        finally:
            Path(path).unlink(missing_ok=True)

    def attach_profile(self, submission, profile_sha256):
        """Private operator CLI only; binding makes checks reviewable, never approved."""
        row = self._row(submission)
        profile = self.bridge.call('profile.inspect', {'profile_sha256':profile_sha256})
        if not profile:
            fail('PROFILE_REQUIRED')
        with self.store.transaction() as db:
            pending=db.execute('SELECT 1 FROM release_check_actions WHERE submission_id=? AND attempt_id IS NULL',(submission,)).fetchone()
            if pending and profile_sha256 != row['profile_sha256']:
                fail('RELEASE_CHECK_ACTION_PENDING')
            db.execute('UPDATE release_submissions SET profile_sha256=? WHERE id=?', (profile_sha256, submission))
        return profile

    def status(self, actor, submission):
        row = self._row(submission, actor)
        result = self.bridge.call('submission.inspect', dict(submission_id=submission, owner=row['owner']))
        result['profile'] = self.bridge.call('profile.inspect', {'profile_sha256':row['profile_sha256']}) if row['profile_sha256'] else None
        with self.store.connect() as db:
            actions=db.execute('SELECT attempt_id FROM release_check_actions WHERE submission_id=? AND attempt_id IS NOT NULL ORDER BY rowid',(submission,)).fetchall()
            result['check_action_pending']=db.execute('SELECT 1 FROM release_check_actions WHERE submission_id=? AND attempt_id IS NULL',(submission,)).fetchone() is not None
        result['history']=[self.bridge.call('acceptance.inspect',dict(submission_id=submission,owner=row['owner'],attempt_id=a['attempt_id'])) for a in actions]
        result['attempt'] = self.bridge.call('acceptance.inspect', dict(submission_id=submission,
            owner=row['owner'], attempt_id=row['attempt_id'])) if row['attempt_id'] else None
        return result

    def _finish_check_action(self, row, payload):
        # A stale completed action returns its historical attempt without selecting it.
        with self.store.connect() as db:
            saved=db.execute('SELECT attempt_id FROM release_check_actions WHERE submission_id=? AND idempotency_key=?',(row['id'],payload['idempotency_key'])).fetchone()
        if saved and saved['attempt_id']:
            return self.bridge.call('acceptance.inspect',dict(submission_id=row['id'],owner=row['owner'],attempt_id=saved['attempt_id']))
        # Exact persisted request survives either lost authorization or enqueue ack.
        if payload['profile_sha256'] != row['profile_sha256']:
            fail('RELEASE_PROFILE_CHANGED')
        authorization = self.bridge.call('test.authorize', payload)
        attempt = self.bridge.call('acceptance.enqueue', dict(submission_id=row['id'],
            owner=row['owner'], authorization_id=authorization['authorization_id'],
            idempotency_key=payload['idempotency_key']))
        with self.store.transaction() as db:
            changed=db.execute('UPDATE release_check_actions SET attempt_id=? WHERE submission_id=? AND idempotency_key=? AND attempt_id IS NULL',
                       (attempt['attempt_id'],row['id'],payload['idempotency_key'])).rowcount
            if changed:
                db.execute('UPDATE release_submissions SET attempt_id=? WHERE id=?', (attempt['attempt_id'],row['id']))
        return attempt

    def approve_checks(self, actor, submission, profile_sha256, summary_sha256, idempotency_key):
        if not isinstance(idempotency_key,str) or not re.fullmatch(r'[A-Za-z0-9_-]{16,128}',idempotency_key):
            fail('RELEASE_IDEMPOTENCY_INVALID')
        with self.access.guarded_actor(actor):
            row = self._row(submission, actor)
            if profile_sha256 != row['profile_sha256']:
                fail('RELEASE_PROFILE_CHANGED')
            payload = dict(submission_id=submission, owner=row['owner'],profile_sha256=profile_sha256,
                summary_sha256=summary_sha256,consent_revision='checks-v0',idempotency_key=idempotency_key)
            with self.store.transaction() as db:
                old=db.execute('SELECT request_json FROM release_check_actions WHERE submission_id=? AND idempotency_key=?',
                               (submission,idempotency_key)).fetchone()
                if old and old['request_json']!=canonical_json(payload).decode():
                    fail('RELEASE_IDEMPOTENCY_CONFLICT')
                pending=db.execute('SELECT request_json FROM release_check_actions WHERE submission_id=? AND attempt_id IS NULL', (submission,)).fetchone()
                if pending and json.loads(pending['request_json']) != payload:
                    fail('RELEASE_CHECK_ACTION_PENDING')
                db.execute('INSERT OR IGNORE INTO release_check_actions VALUES (?,?,?,NULL)',
                           (submission,idempotency_key,canonical_json(payload).decode()))
            return self._finish_check_action(row,payload)

    def submissions(self, actor, handoff):
        self.review(actor,handoff)
        with self.store.connect() as db:
            ids=[r[0] for r in db.execute('SELECT id FROM release_submissions WHERE handoff_id=? ORDER BY created_at,id',(handoff,))]
        return [self._row(sid,actor) for sid in ids]

    def acknowledge_installation(self, receipt):
        with self.store.connect() as db:
            if db.execute('SELECT 1 FROM release_installation_acks WHERE activation_id=?',(receipt['activation_id'],)).fetchone():
                return
        row=self._row(receipt['submission_id'])
        self.bridge.call('submission.installed',dict(submission_id=row['id'],owner=row['owner'],attempt_id=receipt['attempt_id']))
        with self.store.connect() as db:
            db.execute('INSERT OR IGNORE INTO release_installation_acks VALUES (?)',(receipt['activation_id'],))

    def cancel(self, actor, submission):
        with self.access.guarded_actor(actor):
            row = self._row(submission, actor)
            return self.bridge.call('submission.cancel', dict(submission_id=submission, owner=row['owner']))

    def reconcile(self):
        """Background owner-authorized queue reconciliation. Never called by a GET."""
        if not self._pump_lock.acquire(blocking=False):
            return
        try:
            with self.store.connect() as db:
                rows = db.execute('SELECT id FROM release_submissions WHERE attempt_id IS NOT NULL').fetchall()
            with self.store.connect() as db:
                pending=[dict(r) for r in db.execute('SELECT * FROM release_check_actions WHERE attempt_id IS NULL')]
            for action in pending:
                try:
                    with self.access.authority_transition_guard():
                        row=self._row(action['submission_id'])
                        self._finish_check_action(row,json.loads(action['request_json']))
                except Exception:
                    pass  # Keep exact pending request for a later explicit/current-authority retry.
            for saved in rows:
                try:
                    with self.access.authority_transition_guard():
                        row = self._row(saved['id'])
                        payload = dict(submission_id=row['id'], owner=row['owner'], attempt_id=row['attempt_id'])
                        attempt = self.bridge.call('acceptance.inspect', payload)
                        operation = {'QUEUED':'acceptance.dispatch','COMPLETED_UNPROMOTED':'acceptance.promote'}.get(attempt['status'])
                        if operation:
                            self._authority(row['owner'])
                            self.bridge.call(operation, dict(**payload, expected_revision=attempt['revision'],
                                permit_id='permit_'+secrets.token_hex(16), expires_at=int(self.clock())+30))
                except Exception as exc:
                    # No raw remote text/credentials or success inference on failures.
                    with self.store.connect() as db:
                        db.execute('UPDATE release_submissions SET error_code=? WHERE id=?',
                                   ('RELEASE_RECONCILIATION_BLOCKED', saved['id']))
            expiry=getattr(self,'expire_previews',None)
            if expiry is not None:
                expiry()
            with self.store.connect() as db:
                has_activations=db.execute("SELECT 1 FROM sqlite_master WHERE name='release_activations'").fetchone()
                installed=[json.loads(r[0]) for r in db.execute("SELECT record_json FROM release_activations WHERE status='ACTIVE'")] if has_activations else []
            for receipt in installed:
                try:
                    self.acknowledge_installation(receipt)
                except Exception:
                    pass
        finally:
            self._pump_lock.release()

    def start(self):
        if self._thread is not None:
            return
        def run():
            while not self._stop.wait(1):
                try:
                    self.reconcile()
                except Exception:
                    self.last_error='RELEASE_RECONCILIATION_BLOCKED'
        self._thread = threading.Thread(target=run, name='release-authority-reconciler', daemon=True)
        self._thread.start()

    def stop(self):
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=40)
