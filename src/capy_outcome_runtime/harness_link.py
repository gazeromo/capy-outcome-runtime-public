"""Explicit computer-scoped linked work and bounded coding-client observations."""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import secrets

from .developer_link import LinkError, closed, token


@dataclass(frozen=True)
class WorkspaceFacts:
    principal_id: str
    authority_id: str
    membership_id: str
    team_id: str
    workspace_kind: str


class HarnessLink:
    def __init__(self, link):
        self.link = link
        with link.db() as db:
            db.executescript('''
                CREATE TABLE IF NOT EXISTS harness_scopes(
                    device TEXT PRIMARY KEY, principal TEXT NOT NULL, authority TEXT NOT NULL,
                    membership TEXT NOT NULL, workspace TEXT NOT NULL, kind TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS harness_clients(
                    device TEXT NOT NULL, client TEXT NOT NULL, label TEXT NOT NULL,
                    version TEXT NOT NULL, transport TEXT NOT NULL, nonce TEXT NOT NULL,
                    nonce_expires INTEGER NOT NULL, checked INTEGER,
                    PRIMARY KEY(device,client));
                CREATE TABLE IF NOT EXISTS harness_intents(
                    device TEXT NOT NULL, intent TEXT NOT NULL, client TEXT NOT NULL,
                    membership TEXT NOT NULL, parent TEXT, request TEXT NOT NULL,
                    PRIMARY KEY(device,intent));
            ''')

    def approve(self, actor, device_id):
        link = self.link
        token(device_id, r'dev_[0-9a-f]{32}')
        with link.access.authority_transition_guard(), link.db() as db:
            link.actor(actor)
            device = link.device(db, device_id)
            if device['principal'] != actor.principal_id or device['authority'] != actor.authority_id:
                raise LinkError()
            facts = (device_id, actor.principal_id, actor.authority_id,
                     actor.membership_id, actor.team_id, actor.workspace_kind)
            prior = db.execute('SELECT * FROM harness_scopes WHERE device=?', (device_id,)).fetchone()
            if prior is not None and tuple(prior) != facts:
                raise LinkError('WORKSPACE_SCOPE_CONFLICT', 409)
            db.execute('INSERT OR IGNORE INTO harness_scopes VALUES (?,?,?,?,?,?)', facts)

    def _device(self, db, value, proof):
        if value['site_id'] != self.link.site_id:
            raise LinkError()
        token(value['device_id'], r'dev_[0-9a-f]{32}')
        return self.link.device(db, value['device_id'], proof)

    def _scope(self, db, device):
        row = db.execute('SELECT * FROM harness_scopes WHERE device=?', (device['id'],)).fetchone()
        if row is None:
            raise LinkError('LINKED_WORK_APPROVAL_REQUIRED', 403)
        if row['principal'] != device['principal'] or row['authority'] != device['authority']:
            raise LinkError()
        self.link.authority(row['principal'], row['authority'], row['membership'], row['workspace'], row['kind'])
        return WorkspaceFacts(row['principal'], row['authority'], row['membership'], row['workspace'], row['kind'])

    def register(self, value, secret, peer):
        closed(value, 'site_id device_id client_id label version transport')
        token(value['client_id'], r'cli_[0-9a-f]{32}')
        token(value['label'], r'(Muse Code|Codex)')
        token(value['version'], r'[A-Za-z0-9 ._()+-]{1,80}')
        token(value['transport'], r'(JSON_CLI|MCP_STDIO)')
        proof = self.link.proof(secret, peer)
        with self.link.access.authority_transition_guard(), self.link.db() as db:
            device = self._device(db, value, proof)
            self._scope(db, device)
            prior = db.execute('SELECT * FROM harness_clients WHERE device=? AND client=?',
                               (device['id'], value['client_id'])).fetchone()
            if prior is not None:
                if any(prior[k] != value[k] for k in ('label', 'version', 'transport')):
                    raise LinkError('CLIENT_REGISTRATION_CONFLICT', 409)
                if prior['nonce_expires'] > self.link.clock():
                    return dict(client_id=prior['client'], nonce=prior['nonce'], expires_at=prior['nonce_expires'])
            elif db.execute('SELECT count(*) FROM harness_clients WHERE device=?', (device['id'],)).fetchone()[0] >= 20:
                raise LinkError('CLIENT_CAPACITY', 429)
            nonce, expires = secrets.token_hex(32), int(self.link.clock()) + 600
            db.execute('''INSERT INTO harness_clients VALUES (?,?,?,?,?,?,?,NULL)
                ON CONFLICT(device,client) DO UPDATE SET nonce=excluded.nonce,nonce_expires=excluded.nonce_expires''',
                       (device['id'], value['client_id'], value['label'], value['version'], value['transport'], nonce, expires))
            return dict(client_id=value['client_id'], nonce=nonce, expires_at=expires)

    def check(self, value, secret, peer):
        closed(value, 'site_id device_id client_id nonce')
        token(value['client_id'], r'cli_[0-9a-f]{32}')
        token(value['nonce'], r'[0-9a-f]{64}')
        proof = self.link.proof(secret, peer)
        with self.link.access.authority_transition_guard(), self.link.db() as db:
            device = self._device(db, value, proof)
            self._scope(db, device)
            row = db.execute('SELECT * FROM harness_clients WHERE device=? AND client=?', (device['id'], value['client_id'])).fetchone()
            if row is None or not secrets.compare_digest(row['nonce'], value['nonce']):
                raise LinkError('CLIENT_CHECK_CHALLENGE_INVALID', 403)
            now = int(self.link.clock())
            # Replay returns the original receive time, never manufactures freshness.
            if row['checked'] is not None and row['nonce_expires'] == row['checked']:
                return self._public(row)
            if row['nonce_expires'] <= self.link.clock():
                raise LinkError('CLIENT_CHECK_CHALLENGE_INVALID', 403)
            db.execute('UPDATE harness_clients SET checked=?,nonce_expires=? WHERE device=? AND client=?',
                       (now, now, device['id'], value['client_id']))
            return self._public(db.execute('SELECT * FROM harness_clients WHERE device=? AND client=?', (device['id'], value['client_id'])).fetchone())

    def _public(self, row, revoked=False):
        checked = row['checked']
        state = 'Revoked' if revoked else ('Configured; waiting for a tool check' if checked is None else
                ('Idle' if self.link.clock() - checked > 90 else 'Ready through ' + ('MCP' if row['transport'] == 'MCP_STDIO' else 'CLI')))
        return dict(client_id=row['client'], label=row['label'], version=row['version'],
                    transport=row['transport'], state=state, last_checked=checked)

    def status(self, value, secret, peer):
        closed(value, 'site_id device_id')
        proof = self.link.proof(secret, peer)
        with self.link.access.authority_transition_guard(), self.link.db() as db:
            device = self._device(db, value, proof)
            try:
                facts = self._scope(db, device)
            except LinkError as exc:
                if str(exc) != 'LINKED_WORK_APPROVAL_REQUIRED':
                    raise
                return dict(approved=False, approval_path='/developer/connections/' + device['id'] + '/work', clients=[])
            clients = [self._public(r) for r in db.execute('SELECT * FROM harness_clients WHERE device=? ORDER BY client', (device['id'],))]
            return dict(approved=True, workspace_kind=facts.workspace_kind, workspace_id=facts.team_id, clients=clients)

    def begin(self, value, secret, peer):
        fields='site_id device_id client_id intent_id parent_handoff_id'
        closed(value,fields+(' project_id' if isinstance(value,dict) and 'project_id' in value else ''))
        token(value['client_id'], r'cli_[0-9a-f]{32}')
        token(value['intent_id'], r'[0-9a-f]{32}')
        parent = value['parent_handoff_id']
        project_id=value.get('project_id')
        if 'project_id' in value:
            token(project_id,r'prj_[0-9a-f]{32}')
            if parent is not None:raise LinkError('INVALID_PROJECT_INTENT',400)
        if parent is not None:
            token(parent, r'hof_[0-9a-f]{32}')
        proof = self.link.proof(secret, peer)
        with self.link.access.authority_transition_guard(), self.link.db() as db:
            device = self._device(db, value, proof)
            facts = self._scope(db, device)
            client = db.execute('SELECT * FROM harness_clients WHERE device=? AND client=?', (device['id'], value['client_id'])).fetchone()
            if client is None or client['checked'] is None:
                raise LinkError('CLIENT_CHECK_REQUIRED', 409)
            prior = db.execute('SELECT * FROM harness_intents WHERE device=? AND intent=?', (device['id'], value['intent_id'])).fetchone()
            if prior:
                if prior['client'] != value['client_id'] or prior['membership'] != facts.membership_id or prior['parent'] != parent:
                    raise LinkError('IDEMPOTENCY_CONFLICT', 409)
                request = json.loads(prior['request'])
                if request.get('project_id') != project_id:
                    raise LinkError('IDEMPOTENCY_CONFLICT',409)
                self.link.request(db, request['handoff_id'], proof=proof)
                return request
            if parent:
                old, _ = self.link.request(db, parent, proof=proof)
                snapshot = json.loads(old['snapshot']) if old['snapshot'] else {}
                # Opening an active writer is a separate explicit handover operation.
                if snapshot.get('terminal') != 'COMPLETED':
                    raise LinkError('ACTIVE_WRITER_HANDOVER_REQUIRED', 409)
            # Domain-separated key prevents collision with browser-created requests.
            idem = hashlib.sha256(('harness-v0:' + device['id'] + ':' + value['intent_id']).encode()).hexdigest()[:32]
            request = self.link._create_authorized(db, facts, device['id'], idem, parent, project_id=project_id)
            db.execute('INSERT INTO harness_intents VALUES (?,?,?,?,?,?)',
                       (device['id'], value['intent_id'], value['client_id'], facts.membership_id, parent, json.dumps(request)))
            return request

    def reopen(self, value, secret, peer):
        closed(value, 'site_id device_id client_id handoff_id previous_editor_stopped')
        token(value['client_id'], r'cli_[0-9a-f]{32}')
        token(value['handoff_id'], r'hof_[0-9a-f]{32}')
        if value['previous_editor_stopped'] is not True:
            raise LinkError('ACTIVE_WRITER_HANDOVER_REQUIRED', 409)
        proof = self.link.proof(secret, peer)
        with self.link.access.authority_transition_guard(), self.link.db() as db:
            device = self._device(db, value, proof)
            facts = self._scope(db, device)
            client = db.execute('SELECT * FROM harness_clients WHERE device=? AND client=?',
                (device['id'], value['client_id'])).fetchone()
            if client is None or client['checked'] is None:
                raise LinkError('CLIENT_CHECK_REQUIRED', 409)
            associations = db.execute('SELECT request FROM harness_intents WHERE device=? AND client=? AND membership=?',
                (device['id'], value['client_id'], facts.membership_id)).fetchall()
            if not any(json.loads(r['request'])['handoff_id'] == value['handoff_id'] for r in associations):
                raise LinkError('WORK_CLIENT_ASSOCIATION_MISMATCH', 409)
            row, request = self.link.request(db, value['handoff_id'], proof=proof)
            if request['membership_id'] != facts.membership_id or request['workspace_id'] != facts.team_id:
                raise LinkError()
            snapshot = json.loads(row['snapshot']) if row['snapshot'] else {}
            if snapshot.get('terminal') in ('COMPLETED', 'CANCELLED'):
                raise LinkError('WORK_SESSION_TERMINAL', 409)
            # Same client and exact handoff only. Never allocates or relabels a
            # session, renews authority, or infers editor exit from presence.
            return request

    def listing(self, actor):
        with self.link.access.authority_transition_guard(), self.link.db() as db:
            self.link.actor(actor)
            rows = db.execute('''SELECT c.*,d.revoked,d.expires FROM harness_clients c JOIN devices d ON d.id=c.device
                                 WHERE d.principal=? ORDER BY c.device,c.client''', (actor.principal_id,)).fetchall()
            return [{"device_id": r['device'], **self._public(r, bool(r['revoked']) or r['expires'] <= self.link.clock())} for r in rows]
