"""Isolated, default-off local developer reports. No execution authority."""
from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import sqlite3
import time
import unicodedata
from contextlib import contextmanager
from pathlib import Path

from . import _developer_link_protocol as wire


class LinkError(ValueError):
    def __init__(self, code='DEVELOPER_LINK_DENIED', status=403, expected=None):
        super().__init__(code)
        self.status, self.expected = status, expected


def closed(value, fields):
    if not isinstance(value, dict) or set(value) != set(fields.split()):
        raise LinkError('INVALID_FIELDS', 400)


def token(value, pattern):
    if not isinstance(value, str) or not re.fullmatch(pattern, value):
        raise LinkError('INVALID_VALUE', 400)
    return value


class DeveloperLink:
    def __init__(self, path: Path, access, site_id: str, site_origin: str, *, clock=time.time):
        self.site_id = token(site_id, r'site_[0-9a-f]{32}')
        self.origin = wire.origin(site_origin)
        self.access, self.clock, self.path = access, clock, Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if self.path.is_symlink():
            raise LinkError('UNSAFE_STORE')
        fd = os.open(self.path, os.O_CREAT | os.O_RDWR, 0o600)
        os.close(fd)
        os.chmod(self.path, 0o600)
        with self.db() as db:
            db.executescript('''
            CREATE TABLE IF NOT EXISTS metadata(site_id TEXT PRIMARY KEY, origin TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS pairs(id TEXT PRIMARY KEY, installation TEXT, digest TEXT UNIQUE, label TEXT,
              code TEXT, expires INTEGER, device TEXT, principal TEXT, authority TEXT);
            CREATE TABLE IF NOT EXISTS devices(id TEXT PRIMARY KEY, digest TEXT UNIQUE, label TEXT,
              principal TEXT, authority TEXT, expires INTEGER, revoked INTEGER DEFAULT 0);
            CREATE TABLE IF NOT EXISTS device_installations(device TEXT PRIMARY KEY, installation TEXT NOT NULL, digest TEXT NOT NULL, principal TEXT NOT NULL, authority TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS requests(id TEXT PRIMARY KEY, principal TEXT, membership TEXT,
              idem TEXT, request TEXT, state TEXT, ack INTEGER DEFAULT 0, snapshot TEXT, received INTEGER,
              UNIQUE(principal,membership,idem));
            CREATE TABLE IF NOT EXISTS events(request TEXT, sequence INTEGER, digest TEXT,
              PRIMARY KEY(request,sequence));
            CREATE TABLE IF NOT EXISTS associations(kind TEXT,id TEXT, project TEXT, session TEXT, facts TEXT,
              PRIMARY KEY(kind,id));
            CREATE TABLE IF NOT EXISTS rates(key TEXT PRIMARY KEY, window INTEGER, count INTEGER);
            CREATE TABLE IF NOT EXISTS verification_states(id TEXT PRIMARY KEY, status TEXT NOT NULL);
            ''')
            # Pairing challenges expire; the authenticated device association
            # must survive their garbage collection for later source transfers.
            db.execute('''INSERT OR IGNORE INTO device_installations
              SELECT p.device,p.installation,p.digest,p.principal,p.authority FROM pairs p JOIN devices d ON d.id=p.device
              WHERE p.digest=d.digest AND p.principal=d.principal AND p.authority=d.authority''')
            rows = db.execute('SELECT * FROM metadata').fetchall()
            if rows and (rows[0]['site_id'], rows[0]['origin']) != (self.site_id, self.origin):
                raise LinkError('STORE_SITE_CONFLICT')
            db.execute('INSERT OR IGNORE INTO metadata VALUES (?,?)', (self.site_id, self.origin))
            # Additive upgrade: preserve every known receipt, but never invent the
            # terminal outcome of a historical digest-only event. Such an old ID
            # stays unavailable for promotion until a new verification is made.
            db.execute("INSERT OR IGNORE INTO verification_states SELECT id,'UNKNOWN' FROM associations WHERE kind='verification'")
            for old in db.execute('SELECT snapshot FROM requests WHERE snapshot IS NOT NULL').fetchall():
                snap = json.loads(old['snapshot'])
                if snap.get('verification_id'):
                    db.execute("UPDATE verification_states SET status=? WHERE id=? AND status='UNKNOWN'", (snap['verification_status'], snap['verification_id']))
            for old in db.execute("SELECT facts FROM associations WHERE kind='candidate'").fetchall():
                facts = json.loads(old['facts'])
                if len(facts) == 4:
                    db.execute("UPDATE verification_states SET status='PASSED' WHERE id=? AND status='UNKNOWN'", (facts[0],))


    @contextmanager
    def db(self):
        db = sqlite3.connect(self.path, timeout=10)
        db.row_factory = sqlite3.Row
        try:
            db.execute('BEGIN IMMEDIATE')
            yield db
            db.commit()
        except BaseException:
            db.rollback()
            raise
        finally:
            db.close()

    def rate(self, key, limit=30):
        now = int(self.clock()) // 600
        with self.db() as db:
            db.execute('DELETE FROM rates WHERE window < ?', (now,))
            db.execute('INSERT INTO rates VALUES (?,?,1) ON CONFLICT(key) DO UPDATE SET count=count+1', (key, now))
            count = db.execute('SELECT count FROM rates WHERE key=?', (key,)).fetchone()[0]
        if count > limit:
            raise LinkError('RATE_LIMITED', 429)

    def authority(self, principal, authority, membership=None, workspace=None, kind=None):
        with self.access.runtime.connect() as db:
            p = db.execute("SELECT id FROM access_principals WHERE id=? AND authority_id=? AND status='active'", (principal, authority)).fetchone()
            if p is None:
                raise LinkError()
            if membership:
                m = db.execute("""SELECT m.kind,m.team_id,w.principal_id AS personal FROM access_memberships m
                JOIN access_teams t ON t.id=m.team_id AND t.status='active' AND t.authority_id=?
                LEFT JOIN access_personal_workspaces w ON w.membership_id=m.id AND w.principal_id=m.principal_id
                WHERE m.id=? AND m.principal_id=? AND m.status='active'""", (authority, membership, principal)).fetchone()
                if m is None or m['team_id'] != workspace or ('personal' if m['personal'] else 'team') != kind or (kind == 'team' and m['kind'] != 'owner'):
                    raise LinkError()

    def actor(self, actor):
        current = self.access.resolve_actor(actor.client_id, actor.membership_id)
        if current != actor:
            raise LinkError()
        self.authority(actor.principal_id, actor.authority_id, actor.membership_id, actor.team_id, actor.workspace_kind)

    def start_pair(self, value, peer):
        closed(value, 'site_id installation_id secret_sha256 label')
        self.rate('start:' + peer, 10)
        if value['site_id'] != self.site_id:
            raise LinkError()
        token(value['installation_id'], r'[0-9a-f]{32}')
        token(value['secret_sha256'], r'[0-9a-f]{64}')
        label = value['label']
        if not isinstance(label, str) or not 1 <= len(label) <= 80 or any(unicodedata.category(c) in ('Cc', 'Cf', 'Cs') for c in label):
            raise LinkError('INVALID_LABEL', 400)
        pair, code, expiry = 'pair_' + secrets.token_hex(16), secrets.token_hex(4).upper(), int(self.clock()) + 600
        with self.db() as db:
            db.execute('DELETE FROM pairs WHERE expires < ?', (int(self.clock()),))
            existing = db.execute('SELECT * FROM pairs WHERE digest=?', (value['secret_sha256'],)).fetchone()
            if existing:
                if existing['installation'] != value['installation_id'] or existing['label'] != label:
                    raise LinkError('PAIR_CONFLICT', 409)
                return dict(site_id=self.site_id, pair_id=existing['id'], confirmation_code=existing['code'], expires_at=existing['expires'], verification_path='/developer/connections/' + existing['id'])
            if db.execute('SELECT id FROM devices WHERE digest=?', (value['secret_sha256'],)).fetchone():
                raise LinkError('EXISTING_DEVICE_USE_SAVED_CONNECTION', 409)
            if db.execute('SELECT count(*) FROM pairs').fetchone()[0] >= 1000:
                raise LinkError('PAIR_CAPACITY', 429)
            try:
                db.execute('INSERT INTO pairs VALUES (?,?,?,?,?,?,NULL,NULL,NULL)', (pair, value['installation_id'], value['secret_sha256'], label, code, expiry))
            except sqlite3.IntegrityError:
                raise LinkError('PAIR_CONFLICT', 409) from None
        return dict(site_id=self.site_id, pair_id=pair, confirmation_code=code, expires_at=expiry, verification_path='/developer/connections/' + pair)

    def approve(self, actor, pair, code):
        self.rate('approve:' + actor.principal_id, 20)
        with self.access.authority_transition_guard(), self.db() as db:
            self.actor(actor)
            row = db.execute('SELECT * FROM pairs WHERE id=?', (pair,)).fetchone()
            if row is None or row['expires'] <= self.clock() or not secrets.compare_digest(row['code'], code):
                raise LinkError()
            if row['device']:
                if row['principal'] != actor.principal_id:
                    raise LinkError()
                return row['device']
            device = 'dev_' + secrets.token_hex(16)
            db.execute('INSERT INTO devices VALUES (?,?,?,?,?,?,0)', (device, row['digest'], row['label'], actor.principal_id, actor.authority_id, int(self.clock()) + 90 * 86400))
            db.execute('INSERT INTO device_installations VALUES (?,?,?,?,?)', (device,row['installation'],row['digest'],actor.principal_id,actor.authority_id))
            db.execute('UPDATE pairs SET device=?,principal=?,authority=? WHERE id=?', (device, actor.principal_id, actor.authority_id, pair))
            return device

    def proof(self, secret, peer):
        self.rate('proof:' + peer, 300)
        token(secret, r'[0-9a-f]{64}')
        return hashlib.sha256(secret.encode()).hexdigest()

    def poll(self, value, secret, peer):
        closed(value, 'site_id pair_id')
        token(value['pair_id'], r'pair_[0-9a-f]{32}')
        proof = self.proof(secret, peer)
        with self.access.authority_transition_guard(), self.db() as db:
            row = db.execute('SELECT * FROM pairs WHERE id=? AND digest=?', (value['pair_id'], proof)).fetchone()
            if value['site_id'] != self.site_id or row is None or row['expires'] <= self.clock():
                raise LinkError()
            expiry = row['expires']
            if row['device']:
                device = self.device(db, row['device'], proof)
                expiry = device['expires']
            return dict(status='APPROVED' if row['device'] else 'PENDING', site_id=self.site_id, device_id=row['device'], principal_id=row['principal'], expires_at=expiry)

    def device(self, db, device_id, proof=None):
        row = db.execute('SELECT * FROM devices WHERE id=?', (device_id,)).fetchone()
        if row is None or row['revoked'] or row['expires'] <= self.clock() or (proof is not None and not secrets.compare_digest(row['digest'], proof)):
            raise LinkError()
        self.authority(row['principal'], row['authority'])
        return row

    def revoke(self, actor, device_id):
        with self.access.authority_transition_guard(), self.db() as db:
            self.actor(actor)
            row = db.execute('SELECT * FROM devices WHERE id=? AND principal=?', (device_id, actor.principal_id)).fetchone()
            if row is None:
                raise LinkError()
            db.execute('UPDATE devices SET revoked=1 WHERE id=?', (device_id,))

    def request(self, db, handoff, actor=None, proof=None, permit_disconnected=False):
        row = db.execute('SELECT * FROM requests WHERE id=?', (handoff,)).fetchone()
        if row is None:
            raise LinkError()
        req = json.loads(row['request'])
        if actor:
            self.actor(actor)
            if actor.principal_id != req['principal_id'] or actor.membership_id != req['membership_id']:
                raise LinkError()
        self.authority(req['principal_id'], req['authority_id'], req['membership_id'], req['workspace_id'], req['workspace_kind'])
        if not permit_disconnected:
            dev = self.device(db, req['device_id'], proof)
            if dev['principal'] != req['principal_id'] or row['state'] in ('CANCELLED','DISCONNECTED') or req['expires_at'] <= self.clock():
                raise LinkError()
        return row, req

    def create(self, actor, device_id, idem, parent=None):
        token(idem, r'[0-9a-f]{32}')
        token(device_id, r'dev_[0-9a-f]{32}')
        with self.access.authority_transition_guard(), self.db() as db:
            self.actor(actor)
            return self._create_authorized(db, actor, device_id, idem, parent)

    def _create_authorized(self, db, actor, device_id, idem, parent=None, *, project_id=None):
        """Caller holds authority guard/transaction and validates workspace facts.

        No browser session is fabricated for device-originated work. Only the
        narrow principal/workspace facts needed by the existing allocator pass in.
        """
        device = self.device(db, device_id)
        if project_id is not None:
            token(project_id, r'prj_[0-9a-f]{32}')
            if parent is not None:
                raise LinkError('INVALID_PROJECT_INTENT', 400)
        if device['principal'] != actor.principal_id:
            raise LinkError()
        candidate = None
        if parent:
            old, prior = self.request(db, parent)
            snapshot = json.loads(old['snapshot']) if old['snapshot'] else {}
            if old['state'] != 'CLAIMED':
                raise LinkError('PARENT_NOT_CLAIMED', 409)
            if prior['device_id'] != device_id or prior['principal_id'] != actor.principal_id or prior['membership_id'] != actor.membership_id:
                raise LinkError()
            if snapshot.get('terminal') == 'CANCELLED':
                raise LinkError('PARENT_CANCELLED', 409)
            if snapshot.get('terminal') == 'COMPLETED':
                candidate = snapshot.get('candidate_id')
                if not candidate:
                    raise LinkError('NO_CONTINUATION_SOURCE', 409)
                if not snapshot.get('source_fresh') or snapshot.get('dirty'):
                    raise LinkError('SOURCE_CHANGED', 409)
        old = db.execute('SELECT request FROM requests WHERE principal=? AND membership=? AND idem=?', (actor.principal_id, actor.membership_id, idem)).fetchone()
        if old:
            req = json.loads(old[0])
            if req['device_id'] != device_id or req['parent_handoff_id'] != parent or req.get('project_id') != project_id:
                raise LinkError('IDEMPOTENCY_CONFLICT', 409)
            return req
        if db.execute('SELECT count(*) FROM requests WHERE principal=?', (actor.principal_id,)).fetchone()[0] >= 1000:
            raise LinkError('REQUEST_CAPACITY', 429)
        now = int(self.clock())
        req = dict(schema='capy.developer-link-request/v0', site_id=self.site_id, handoff_id='hof_' + secrets.token_hex(16), device_id=device_id, principal_id=actor.principal_id, authority_id=actor.authority_id, workspace_kind=actor.workspace_kind, workspace_id=actor.team_id, membership_id=actor.membership_id, intent='CONTINUE' if parent else 'NEW', parent_handoff_id=parent, release_candidate_id=candidate, created_at=now, expires_at=now+30*86400, launch_generation=1)
        if project_id is not None:
            req.update(schema='capy.developer-link-request/v1',intent='EXISTING',project_id=project_id)
        req['request_digest'] = wire.digest({k:v for k,v in req.items() if k != 'launch_generation'})
        wire.validate_request(req)
        db.execute('INSERT INTO requests(id,principal,membership,idem,request,state) VALUES (?,?,?,?,?,?)', (req['handoff_id'], actor.principal_id, actor.membership_id, idem, json.dumps(req), 'READY'))
        return req

    def action(self, actor, handoff, action):
        with self.access.authority_transition_guard(), self.db() as db:
            row, req = self.request(db, handoff, actor)
            if action == 'open':
                if req['launch_generation'] >= 2147483647:
                    raise LinkError('LAUNCH_LIMIT', 409)
                req['launch_generation'] += 1
                db.execute('UPDATE requests SET request=? WHERE id=?', (json.dumps(req), handoff))
            elif action == 'cancel':
                if row['state'] != 'READY':
                    raise LinkError('ALREADY_CLAIMED_DISCONNECT_INSTEAD', 409)
                db.execute("UPDATE requests SET state='CANCELLED' WHERE id=?", (handoff,))
            elif action == 'disconnect':
                db.execute("UPDATE requests SET state='DISCONNECTED' WHERE id=?", (handoff,))
            else:
                raise LinkError('INVALID_ACTION', 400)
            return req

    def claim(self, handoff, value, secret, peer):
        closed(value, 'site_id device_id launch_generation')
        proof = self.proof(secret, peer)
        with self.access.authority_transition_guard(), self.db() as db:
            row, req = self.request(db, handoff, proof=proof)
            if any(value[k] != req[k] for k in value) or type(value['launch_generation']) is not int:
                raise LinkError()
            db.execute("UPDATE requests SET state='CLAIMED' WHERE id=?", (handoff,))
            return req

    def events(self, handoff, value, secret, peer):
        closed(value, 'events')
        if not isinstance(value['events'], list) or len(value['events']) > 64 or len(wire.canonical(value)) > 256*1024:
            raise LinkError('EVENT_LIMIT', 400)
        proof = self.proof(secret, peer)
        with self.access.authority_transition_guard(), self.db() as db:
            row, req = self.request(db, handoff, proof=proof)
            if row['state'] != 'CLAIMED':
                raise LinkError('CLAIM_REQUIRED', 409)
            ack, previous = row['ack'], json.loads(row['snapshot']) if row['snapshot'] else None
            for event in value['events']:
                wire.validate_event(event)
                if len(wire.canonical(event)) > 16384 or any(event[k] != req[k] for k in ('site_id','handoff_id','device_id')) or event['digest'] != wire.digest({k:v for k,v in event.items() if k != 'digest'}):
                    raise LinkError('INVALID_EVENT', 400)
                sequence = event['sequence']
                existing = db.execute('SELECT digest FROM events WHERE request=? AND sequence=?', (handoff, sequence)).fetchone()
                if existing:
                    if existing[0] != event['digest']:
                        raise LinkError('REPLAY_CONFLICT', 409, ack+1)
                    continue
                if sequence != ack+1:
                    raise LinkError('SEQUENCE_GAP', 409, ack+1)
                if sequence > 4096:
                    raise LinkError('HISTORY_LIMIT', 409, ack+1)
                snap = event['snapshot']
                if req.get('project_id') is not None and snap['project_id'] not in (None,req['project_id']):
                    raise LinkError('PROJECT_ASSOCIATION_MISMATCH', 409)
                if previous:
                    if previous['terminal'] and snap['terminal'] != previous['terminal']:
                        raise LinkError('TERMINAL_CONFLICT', 409)
                    if previous['candidate_id'] and not snap['candidate_id']:
                        raise LinkError('CANDIDATE_HISTORY_REQUIRED', 409)
                    for key in ('project_id','session_id'):
                        if previous[key] and snap[key] != previous[key]:
                            raise LinkError('ASSOCIATION_CONFLICT', 409)
                if snap['verification_id']:
                    self.verification(db, snap['verification_id'], snap['project_id'], snap['session_id'], snap['verification_commit'], snap['verification_status'])
                if snap['candidate_id']:
                    self.verification(db, snap['candidate_verification_id'], snap['project_id'], snap['session_id'], snap['candidate_commit'], 'PASSED')
                    fields = ('candidate_verification_id','candidate_sha256','candidate_size','candidate_commit')
                    facts = json.dumps([snap[k] for k in fields])
                    prior = db.execute("SELECT project,session,facts FROM associations WHERE kind='candidate' AND id=?", (snap['candidate_id'],)).fetchone()
                    expected = (snap['project_id'], snap['session_id'], facts)
                    if prior and tuple(prior) != expected:
                        raise LinkError('ASSOCIATION_CONFLICT', 409)
                    db.execute("INSERT OR IGNORE INTO associations VALUES ('candidate',?,?,?,?)", (snap['candidate_id'], *expected))
                db.execute('INSERT INTO events VALUES (?,?,?)', (handoff, sequence, event['digest']))
                ack, previous = sequence, snap
            db.execute('UPDATE requests SET ack=?,snapshot=?,received=? WHERE id=?', (ack, json.dumps(previous) if previous else None, int(self.clock()), handoff))
            return {'ack_sequence': ack}

    @staticmethod
    def verification(db, identity, project, session, commit, status):
        if not project or not session or not commit:
            raise LinkError('ASSOCIATION_REQUIRED', 400)
        prior = db.execute("SELECT project,session,facts FROM associations WHERE kind='verification' AND id=?", (identity,)).fetchone()
        expected = (project, session, json.dumps([commit]))
        if prior and tuple(prior) != expected:
            raise LinkError('ASSOCIATION_CONFLICT', 409)
        recorded = db.execute('SELECT status FROM verification_states WHERE id=?', (identity,)).fetchone()
        if recorded and recorded['status'] != status and recorded['status'] != 'RUNNING':
            raise LinkError('VERIFICATION_STATUS_CONFLICT', 409)
        db.execute("INSERT OR IGNORE INTO associations VALUES ('verification',?,?,?,?)", (identity, *expected))
        db.execute('INSERT INTO verification_states VALUES (?,?) ON CONFLICT(id) DO UPDATE SET status=excluded.status', (identity, status))

    def status(self, actor, handoff):
        with self.access.authority_transition_guard(), self.db() as db:
            row, req = self.request(db, handoff, actor, permit_disconnected=True)
            dev = db.execute('SELECT * FROM devices WHERE id=?', (req['device_id'],)).fetchone()
            freshness = 'REVOKED' if dev is None or dev['revoked'] or dev['expires'] <= self.clock() else 'DISCONNECTED' if row['state'] in ('CANCELLED','DISCONNECTED') or req['expires_at'] <= self.clock() else 'CONNECTED' if row['received'] and self.clock()-row['received'] <= 90 else 'STALE'
            return dict(request=req, state=row['state'], snapshot=json.loads(row['snapshot']) if row['snapshot'] else None, received_at=row['received'], connection=freshness)

    def listing(self, actor):
        with self.access.authority_transition_guard(), self.db() as db:
            self.actor(actor)
            devices = [dict(r) for r in db.execute('SELECT id,label,expires,revoked FROM devices WHERE principal=? ORDER BY rowid DESC LIMIT 50', (actor.principal_id,))]
            ids = [r[0] for r in db.execute('SELECT id FROM requests WHERE principal=? AND membership=? ORDER BY rowid DESC LIMIT 50', (actor.principal_id, actor.membership_id))]
        return devices, [self.status(actor, item) for item in ids]


def configured_link(args, access):
    """Disabled configuration must not touch or create a developer store."""
    if not getattr(args, 'developer_link', False):
        return None
    path = getattr(args, 'developer_link_database', None)
    if not path:
        raise ValueError('--developer-link-database is required when enabled')
    return DeveloperLink(path, access, getattr(args, 'developer_link_site_id', None), getattr(args, 'developer_link_origin', None))
