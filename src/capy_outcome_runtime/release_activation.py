"""Current-authority first installation/removal using canonical workspace bindings."""
from __future__ import annotations

import json
import re
import secrets

from .release_admission import admit_release
from .release_workflow import fail
from .store import canonical_json, utc_now


def _checkpoint(stage):
    """Fault-injection seam; no application effects."""


class ReleaseActivation:
    def __init__(self, workflow, previews, team):
        self.workflow, self.previews, self.team = workflow, previews, team
        with workflow.store.connect() as db:
            db.executescript('''
              CREATE TABLE IF NOT EXISTS release_activations (
                workspace_id TEXT NOT NULL, application_id TEXT NOT NULL,
                record_json TEXT NOT NULL, status TEXT NOT NULL,
                PRIMARY KEY(workspace_id,application_id));
              CREATE TABLE IF NOT EXISTS release_activation_actions (
                principal_id TEXT NOT NULL, idempotency_key TEXT NOT NULL,
                intent_json TEXT NOT NULL, receipt_json TEXT NOT NULL,
                PRIMARY KEY(principal_id,idempotency_key));
            ''')

    def add(self, actor, preview_id, membership_id, idempotency_key):
        if not isinstance(idempotency_key, str) or not re.fullmatch(r'[A-Za-z0-9_-]{16,128}', idempotency_key):
            fail('RELEASE_IDEMPOTENCY_INVALID')
        access, store = self.workflow.access, self.workflow.store
        with access.guarded_actor(actor), self.previews._lock:
            preview = self.previews._row(actor, preview_id)
            if not preview['successful_activity']:
                fail('RELEASE_SUCCESSFUL_PREVIEW_REQUIRED')
            target = next((v for v in access.workspaces(actor) if v.membership_id == membership_id), None)
            if target is None or (target.workspace_kind == 'team' and target.membership_kind != 'owner'):
                fail('RELEASE_TARGET_AUTHORITY_DENIED')
            # Verify success is a real persisted invocation for this exact context.
            with self.previews.context(actor, preview_id) as (_row, mapped, interface):
                interface.activity(mapped, preview['record']['application_id'], preview['successful_activity'])
            source = self.workflow._row(preview['submission_id'], actor)
            record = admit_release(store, self.workflow.bridge, source['owner'], source['id'], preview['attempt_id'])
            if record['version_digest'] != preview['record']['version_digest'] or record['admission_identity_digest'] != preview['record']['admission_identity_digest']:
                fail('RELEASE_PREVIEW_IDENTITY_CHANGED')
            _checkpoint('admitted_unbound')
            intent = dict(preview_id=preview_id, admission_id=record['admission_id'],
                          membership_id=target.membership_id, workspace_id=target.team_id,
                          application_id=record['application_id'], version_digest=record['version_digest'])
            raw = canonical_json(intent).decode()
            with store.transaction() as db:
                # Current authority and version conflicts are checked under the
                # same serialized transaction as shares, bindings and receipt.
                current = access.resolve_actor(target.client_id, target.membership_id)
                if current != target:
                    fail('RELEASE_TARGET_AUTHORITY_DENIED')
                prior = db.execute('SELECT * FROM release_activation_actions WHERE principal_id=? AND idempotency_key=?',
                                   (actor.principal_id, idempotency_key)).fetchone()
                if prior:
                    if prior['intent_json'] != raw:
                        fail('RELEASE_IDEMPOTENCY_CONFLICT')
                    saved = json.loads(prior['receipt_json'])
                    now = db.execute('SELECT status FROM release_activations WHERE workspace_id=? AND application_id=?',
                                     (target.team_id,record['application_id'])).fetchone()
                    binding=store.binding_or_none(target.execution_scope_id,record['application_id'])
                    state=now['status'] if binding is not None and binding.version_digest==record['version_digest'] else 'REMOVED'
                    return dict(saved,status=state)
                existing = store.binding_or_none(target.execution_scope_id, record['application_id'])
                if existing and existing.version_digest != record['version_digest']:
                    fail('UPDATE_REQUIRES_SEPARATE_FLOW')
                previous = db.execute('SELECT * FROM release_activations WHERE workspace_id=? AND application_id=?',
                                      (target.team_id, record['application_id'])).fetchone()
                if previous and json.loads(previous['record_json'])['version_digest'] != record['version_digest']:
                    fail('UPDATE_REQUIRES_SEPARATE_FLOW')
                if existing and previous is None:
                    fail('RELEASE_EXISTING_BINDING_CONFLICT')
                if target.workspace_kind == 'team':
                    self.team.share_software(target, record['application_id'], record['version_digest'])
                elif existing is None:
                    store.bind(target.execution_scope_id, record['application_id'], record['version_digest'], {})
                _checkpoint('bindings_written')
                receipt = dict(intent, submission_id=source['id'],attempt_id=preview['attempt_id'], activation_id=('act_'+secrets.token_hex(16)), status='ACTIVE',
                               principal_id=actor.principal_id, workspace_kind=target.workspace_kind,
                               created_at=utc_now(), preview_data_copied=False)
                if previous and previous['status'] == 'ACTIVE':
                    receipt = json.loads(previous['record_json'])
                encoded = canonical_json(receipt).decode()
                db.execute('INSERT INTO release_activations VALUES (?,?,?,?) ON CONFLICT(workspace_id,application_id) DO UPDATE SET record_json=excluded.record_json,status=excluded.status',
                           (target.team_id, record['application_id'], encoded, 'ACTIVE'))
                db.execute('INSERT INTO release_activation_actions VALUES (?,?,?,?)',
                           (actor.principal_id,idempotency_key,raw,encoded))
                _checkpoint('receipt_written')
            try:
                self.workflow.acknowledge_installation(receipt)
            except Exception:
                pass  # Activation is committed; background retention ack retries.
            return receipt

    def current(self, actor, application_id):
        with self.workflow.access.guarded_actor(actor), self.workflow.store.connect() as db:
            row=db.execute('SELECT record_json,status FROM release_activations WHERE workspace_id=? AND application_id=?',
                           (actor.team_id,application_id)).fetchone()
            if row is None:
                return None
            record=json.loads(row['record_json'])
            binding=self.workflow.store.binding_or_none(actor.execution_scope_id,application_id)
            status=row['status'] if binding is not None and binding.version_digest==record['version_digest'] else 'REMOVED'
            return dict(record,status=status)

    def remove(self, actor, application_id):
        with self.workflow.access.guarded_actor(actor), self.workflow.store.transaction() as db:
            row = db.execute('SELECT * FROM release_activations WHERE workspace_id=? AND application_id=?',
                             (actor.team_id,application_id)).fetchone()
            if row is None:
                fail('RELEASE_ACTIVATION_UNKNOWN')
            record = json.loads(row['record_json'])
            if actor.membership_kind != 'owner' or actor.principal_id != record['principal_id']:
                fail('RELEASE_TARGET_AUTHORITY_DENIED')
            if row['status'] == 'REMOVED':
                return dict(record,status='REMOVED')
            if actor.workspace_kind == 'team':
                self.team.revoke_software(actor, application_id)
            else:
                self.workflow.store.unbind(actor.execution_scope_id, application_id)
            _checkpoint('removed_bindings')
            db.execute("UPDATE release_activations SET status='REMOVED' WHERE workspace_id=? AND application_id=?", (actor.team_id, application_id))
            return dict(record,status='REMOVED')
