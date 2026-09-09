"""Runtime-owned nonsecret account requests and exact preview continuation.

Host policy binds an account to its managing workspace explicitly. An app grant
alone never grants account administration. Stored requests contain ordinary app
input only; the protected form is served and submitted by a separate process.
"""
from __future__ import annotations

import hashlib
import json
import re
import secrets
import threading
import time
from dataclasses import asdict

from .access import ActorContext
from .model import RuntimeFailure
from .store import canonical_json


def denied():raise RuntimeFailure('ACCOUNT_AUTHORITY_DENIED')


class AccountSetup:
    def __init__(self, releases, previews, policies, *, clock=time.time):
        self.releases,self.previews,self.policies,self.clock=releases,previews,policies,clock
        self.access=releases.workflow.access;self.store=releases.control.store
        self.lock=threading.RLock();self.custody=None
        with self.store.connect() as db:
            db.executescript('''CREATE TABLE IF NOT EXISTS account_setup_requests (
                id TEXT PRIMARY KEY, preview_id TEXT NOT NULL, submission_id TEXT NOT NULL,
                connection_id TEXT NOT NULL, workspace_id TEXT NOT NULL, version_digest TEXT NOT NULL,
                choice_id TEXT NOT NULL, actor_json TEXT NOT NULL, operation TEXT, fields_json TEXT,
                status TEXT NOT NULL, created_at REAL NOT NULL, expires_at REAL NOT NULL,
                activity_id TEXT, error_code TEXT);
                CREATE TABLE IF NOT EXISTS account_owner_requests (
                workspace_id TEXT NOT NULL, connection_id TEXT NOT NULL, principal_id TEXT NOT NULL,
                created_at REAL NOT NULL, PRIMARY KEY(workspace_id,connection_id,principal_id));''')
            columns={r[1] for r in db.execute('PRAGMA table_info(account_setup_requests)')}
            if 'attempt' not in columns:db.execute('ALTER TABLE account_setup_requests ADD COLUMN attempt INTEGER NOT NULL DEFAULT 0')

    def _policy(self,actor,connection):
        policy=self.policies.get(connection)
        if not policy or policy['workspace_id']!=actor.team_id or actor.membership_kind!='owner':denied()
        if policy.get('environment') not in {'production','sandbox'} or policy.get('account_mode') not in {'standard','child'}:denied()
        return policy

    def _selection(self,actor,preview_id):
        preview=self.previews._row(actor,preview_id)
        _,version,options,_=self.releases._snapshot(actor,preview['submission_id'])
        selected=[o for o in options if o['target'].team_id==actor.team_id and o['target'].membership_id==actor.membership_id]
        selected=[o for o in selected if o['connection_id'] in self.policies and self.policies[o['connection_id']]['workspace_id']==actor.team_id]
        if len(selected)!=1:denied()
        policy=self._policy(actor,selected[0]['connection_id'])
        return preview,version,selected[0],policy

    def create(self,actor,preview_id,operation=None,fields=None,files=None):
        with self.access.guarded_actor(actor) as current,self.lock:
            preview,version,selection,policy=self._selection(current,preview_id)
            clean=None
            if operation is None and hasattr(self.previews,'context'):
                recovered=self.recover_preview_input(current,preview_id)
                if recovered is not None:operation,fields=recovered
            if operation is not None:
                # The existing app contract parses the original request before
                # deferral; setup does not create a second input language.
                from .application_interfaces import META_FIELDS
                from .portable_interfaces import parse_portable_request
                if files:raise RuntimeFailure('ACCOUNT_CONTINUATION_UNSUPPORTED')
                with self.previews.context(current,preview_id) as (row,mapped,service):
                    contract=service.contract_resolver(mapped,row['record']['application_id'])
                    service._validate_binding(mapped,contract,fields)
                    op=next((o for o in contract['operations'] if o['operation_id']==operation),None)
                    if not op or op.get('resources') or not contract.get('portable_import'):denied()
                    parse_portable_request(op,{k.removeprefix('input.'):v for k,v in fields.items() if k not in META_FIELDS})
                    clean={k:v for k,v in fields.items() if k!='csrf'}
                    if len(canonical_json(clean))>32768:denied()
            with self.store.connect() as db:
                rows=db.execute("SELECT * FROM account_setup_requests WHERE preview_id=? AND status NOT IN ('CANCELLED','DONE') AND expires_at>? ORDER BY created_at DESC",
                                (preview_id,self.clock())).fetchall()
                for row in rows:
                    old=json.loads(row['actor_json'])
                    if old['principal_id']==current.principal_id and old['client_id']==current.client_id:
                        if clean is not None and row['status']=='NEEDS_INPUT':
                            db.execute("UPDATE account_setup_requests SET fields_json=?,operation=?,status='WAITING',activity_id=NULL,attempt=attempt+1 WHERE id=?",
                                (canonical_json(clean).decode(),operation,row['id']))
                            return {'request_id':row['id'],'url':'/connect-account/'+row['id']}
                        if clean is not None and row['fields_json'] is not None and json.loads(row['fields_json'])!=clean:
                            raise RuntimeFailure('ACCOUNT_SETUP_IN_PROGRESS')
                        if clean is not None and row['fields_json'] is None:
                            db.execute('UPDATE account_setup_requests SET fields_json=?,operation=? WHERE id=?',
                                       (canonical_json(clean).decode(),operation,row['id']))
                        return {'request_id':row['id'],'url':'/connect-account/'+row['id']}
                rid='acr_'+secrets.token_hex(16)
                db.execute('INSERT INTO account_setup_requests (id,preview_id,submission_id,connection_id,workspace_id,version_digest,choice_id,actor_json,operation,fields_json,status,created_at,expires_at,activity_id,error_code) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,NULL,NULL)',
                    (rid,preview_id,preview['submission_id'],selection['connection_id'],current.team_id,version,
                     selection['choice_id'],canonical_json(asdict(current)).decode(),operation,
                     canonical_json(clean).decode() if clean is not None else None,'WAITING',self.clock(),self.clock()+3600))
            return {'request_id':rid,'url':'/connect-account/'+rid}

    def recover_preview_input(self,actor,preview_id):
        """Recover only the last exact failed quote from its verified journal.

        This never searches other scopes or environments. No file upload or
        arbitrary input is reconstructed, and a missing journal is not guessed.
        """
        with self.previews.context(actor,preview_id) as (row,mapped,service):
            app=row['record']['application_id'];version=row['record']['version_digest']
            with service.runtime_store.connect() as db:
                activity=db.execute("SELECT * FROM interface_activities WHERE scope_id=? AND principal_id=? AND application_id=? AND application_version=? ORDER BY rowid DESC LIMIT 1",
                    (mapped.execution_scope_id,mapped.principal_id,app,version)).fetchone()
                invocation=db.execute('SELECT * FROM invocations WHERE id=?',(activity['invocation_id'],)).fetchone() if activity and activity['invocation_id'] else None
            if not activity or activity['status']!='failed' or not invocation:return None
            if invocation['scope_id']!=mapped.execution_scope_id or invocation['version_digest']!=version or invocation['capability_id']!=app:denied()
            path=service.runtime_store.journals/invocation['id']/'request.json'
            if not path.is_file():return None
            if any(p.is_symlink() for p in (path,path.parent)) or path.stat().st_size>32768:denied()
            request=json.loads(path.read_bytes())
            descriptor=service.runtime_store.descriptor(app,version)
            # Runtime digests bind input, resources and selected connection
            # names together. This recovery supports no resources and the
            # exact declared connection set; a different envelope fails closed.
            envelope=dict(input=request,resource_digests=[],connections=sorted(descriptor.connections))
            if hashlib.sha256(canonical_json(envelope)).hexdigest()!=invocation['request_digest']:denied()
            contract=service.contract_resolver(mapped,app)
            operation=next((o for o in contract['operations'] if o['operation_id']==activity['operation_id']),None)
            if not operation or operation.get('resources') or not contract.get('portable_import'):return None
            fields={'application_version':version,'contract_digest':contract['digest'],
                'workspace_membership_id':mapped.membership_id,'submission':'recovered-'+activity['id']}
            for field in operation['human_fields']:
                value=request
                for segment in field['field_id'].split('.'):
                    if not isinstance(value,dict) or segment not in value:value=None;break
                    value=value[segment]
                if value is not None:
                    fields['input.'+field['field_id']]=str(value).lower() if type(value) is bool else str(value)
            return activity['operation_id'],fields

    def _current(self,rid):
        if not isinstance(rid,str) or re.fullmatch('acr_[0-9a-f]{32}',rid) is None:denied()
        with self.store.connect() as db:row=db.execute('SELECT * FROM account_setup_requests WHERE id=?',(rid,)).fetchone()
        if row is None or row['expires_at']<=self.clock() or row['status']=='CANCELLED':denied()
        row=dict(row);actor=ActorContext(**json.loads(row['actor_json']))
        current=self.access._require_current_actor(actor)
        # Current kind is checked, rather than trusting the saved actor snapshot.
        preview,version,selected,policy=self._selection(current,row['preview_id'])
        if version!=row['version_digest'] or selected['choice_id']!=row['choice_id'] or selected['connection_id']!=row['connection_id']:
            raise RuntimeFailure('ACCOUNT_REQUEST_CHANGED')
        return row,current,policy

    def validate(self,rid):
        with self.lock:
            row,actor,policy=self._current(rid)
            return dict(request_id=rid,connection_id=row['connection_id'],workspace_id=actor.team_id,
                workspace_name=actor.team_name,environment=policy['environment'],account_mode=policy['account_mode'],
                version_digest=row['version_digest'],status=row['status'],
                return_url='/releases/previews/'+row['preview_id'],has_shipment=row['fields_json'] is not None)

    def authorize_http(self,rid,credential,csrf=None):
        with self.access.authority_transition_guard(),self.lock:
            auth=self.access.authenticate_client(credential)
            row,actor,_=self._current(rid)
            if auth.actor.client_id!=actor.client_id or auth.actor.membership_id!=actor.membership_id or auth.actor.principal_id!=actor.principal_id:denied()
            if csrf is not None and not secrets.compare_digest(csrf,auth.csrf_token):denied()
            return dict(self.validate(rid),csrf=auth.csrf_token)

    def resume(self,rid):
        # Do not hold the coordinator lock across app execution: the broker must
        # be able to revalidate this exact continuation from its own thread.
        with self.access.authority_transition_guard(),self.lock:
            row,actor,_=self._current(rid)
            if row['status'] in {'DONE','NEEDS_INPUT'}:
                return {'status':'needs_input' if row['status']=='NEEDS_INPUT' else 'done','url':'/releases/previews/'+row['preview_id']+'/activity/'+row['activity_id']}
            if row['status'] in {'RESUMING','RETRY'}:
                if hasattr(self.previews,'context'):
                    with self.previews.context(actor,row['preview_id']) as (_,mapped,interface):
                        interface.runtime.reconcile_incomplete()
                        with interface.runtime_store.connect() as db:
                            prior=db.execute('SELECT status FROM invocations WHERE scope_id=? AND idempotency_key=?',
                                (mapped.execution_scope_id,'account-'+rid+'-'+str(row['attempt']))).fetchone()
                        if prior and prior['status'] in {'running','accepted'}:
                            return {'status':'continuing','url':'/connect-account/'+rid}
                        if prior and prior['status']!='succeeded':row['attempt']+=1
                elif row['status']=='RETRY':row['attempt']+=1
                if row['attempt']>=5:return {'status':'pending','url':'/connect-account/'+rid}
                with self.store.connect() as db:db.execute('UPDATE account_setup_requests SET attempt=? WHERE id=?',(row['attempt'],rid))
            if row['fields_json'] is None:
                with self.store.connect() as db:db.execute("UPDATE account_setup_requests SET status='READY' WHERE id=?",(rid,))
                return {'status':'shipment_required','url':'/releases/previews/'+row['preview_id']}
            fields=json.loads(row['fields_json'])
            # One deterministic idempotency identity per preserved request.
            fields['submission']='account-'+rid+'-'+str(row['attempt'])
            with self.store.connect() as db:db.execute("UPDATE account_setup_requests SET status='RESUMING',error_code=NULL WHERE id=?",(rid,))
        try:
            result=self.previews.submit(actor,row['preview_id'],row['operation'],fields,{})
        except Exception:
            with self.lock,self.store.connect() as db:db.execute("UPDATE account_setup_requests SET status='RETRY',error_code='ACCOUNT_CONTINUATION_PENDING' WHERE id=?",(rid,))
            return {'status':'pending','url':'/connect-account/'+rid}
        with self.lock,self.store.connect() as db:
            needs_input=result.get('result',{}).get('status')=='needs_input'
            db.execute("UPDATE account_setup_requests SET status=?,activity_id=? WHERE id=?",('NEEDS_INPUT' if needs_input else 'DONE',result['activity_id'],rid))
        return {'status':'needs_input' if needs_input else 'done','url':'/releases/previews/'+row['preview_id']+'/activity/'+result['activity_id']}

    def authorize_quote(self, values):
        required={'grant_id','scope_id','capability_id','version_digest','invocation_id','connection_id'}
        if set(values)!=required:denied()
        with self.lock:
            control=self.releases.control
            grant=control.resolve_grant(values['grant_id'],scope_id=values['scope_id'],
                capability_id=values['capability_id'],version_digest=values['version_digest'],operation='quote')
            if grant['contract'] not in {'fedex.rates/v1','fedex.rates/v2'}:denied()
            if grant['connection_id']!=values['connection_id'] or grant['connection_id'] not in self.policies:denied()
            with self.store.connect() as db:
                invocation=db.execute('SELECT 1 FROM invocation_connection_grants WHERE invocation_id=? AND grant_id=? AND used_at IS NOT NULL',
                    (values['invocation_id'],values['grant_id'])).fetchone()
                rows=db.execute("SELECT id FROM account_setup_requests WHERE preview_id=? AND connection_id=? AND status IN ('RESUMING','READY') AND expires_at>? ORDER BY created_at DESC",
                    ('prv_'+values['scope_id'].removeprefix('preview_'),values['connection_id'],self.clock())).fetchall() if values['scope_id'].startswith('preview_') else []
            if invocation is None:denied()
            sid=None
            for r in rows:
                try:self.validate(r['id']);sid=r['id'];break
                except RuntimeFailure:continue
            return {'connection_id':values['connection_id'],'setup_request_id':sid,'contract':grant['contract']}

    def dispatch(self,op,values):
        if op=='authorize_http' and set(values)<={'request_id','credential','csrf'} and {'request_id','credential'}<=set(values):
            return self.authorize_http(values['request_id'],values['credential'],values.get('csrf'))
        if op=='validate' and set(values)=={'request_id'}:return self.validate(values['request_id'])
        if op=='resume' and set(values)=={'request_id'}:return self.resume(values['request_id'])
        if op=='retry' and set(values)=={'request_id'}:
            with self.access.authority_transition_guard(),self.lock:
                row,_,_=self._current(values['request_id'])
                if row['status']!='RETRY':denied()
                with self.store.connect() as db:db.execute("UPDATE account_setup_requests SET status='WAITING',attempt=attempt+1,error_code=NULL WHERE id=?",(row['id'],))
            return {'status':'waiting'}
        if op=='prepare' and set(values)=={'request_id'}:
            self.validate(values['request_id'])
            with self.store.connect() as db:
                db.execute("UPDATE account_setup_requests SET status='WAITING',activity_id=NULL,attempt=attempt+1 WHERE id=? AND status='DONE'",(values['request_id'],))
            return {'status':'waiting'}
        if op=='quote_authority':return self.authorize_quote(values)
        if op=='connected' and set(values)=={'request_id'}:
            context=self.validate(values['request_id'])
            with self.store.connect() as db:db.execute('DELETE FROM account_owner_requests WHERE workspace_id=? AND connection_id=?',(context['workspace_id'],context['connection_id']))
            return {'status':'connected'}
        if op=='cancel' and set(values)=={'request_id'}:
            self.validate(values['request_id'])
            with self.store.connect() as db:db.execute("UPDATE account_setup_requests SET status='CANCELLED' WHERE id=?",(values['request_id'],))
            return {'status':'cancelled'}
        denied()

    def supports(self,actor,preview_id):
        try:
            with self.access.guarded_actor(actor) as current:self._selection(current,preview_id)
            return True
        except RuntimeFailure:return False

    def readiness(self, actor, preview_id):
        """Nonsecret availability only; never verifies by invoking a provider."""
        with self.access.guarded_actor(actor) as current:
            _, _, selection, _ = self._selection(current, preview_id)
            try:
                available = self.custody.call('available', connection_id=selection['connection_id'])
            except (RuntimeFailure, OSError):
                return {'status': 'unconfirmed'}
            return {'status': 'available' if available.get('available') is True else 'account_required'}

    def saved_inputs(self, actor, preview_id):
        """Recover acknowledged ordinary facts within the existing request lifetime."""
        with self.access.guarded_actor(actor) as current, self.lock:
            self._selection(current, preview_id)
            with self.store.connect() as db:
                rows = db.execute("SELECT id,fields_json FROM account_setup_requests WHERE preview_id=? AND expires_at>? AND status!='CANCELLED' ORDER BY created_at DESC", (preview_id,self.clock())).fetchall()
            for row in rows:
                try:
                    _, owner, _ = self._current(row['id'])
                except RuntimeFailure:
                    continue
                if owner.principal_id != current.principal_id or owner.membership_id != current.membership_id:
                    continue
                if row['fields_json']:
                    return {k:v for k,v in json.loads(row['fields_json']).items() if k.startswith('input.')}
            return {}

    def maybe_defer(self,actor,preview_id,operation,fields,files):
        if not self.supports(actor,preview_id):return None
        with self.access.guarded_actor(actor) as current:
            self.preview_correction(current,preview_id)
            _,_,selection,_=self._selection(current,preview_id)
            if self.custody.call('available',connection_id=selection['connection_id'])['available']:
                return None
            return self.create(current,preview_id,operation,fields,files)

    def preview_correction(self,actor,preview_id):
        """Recover ordinary form values after an app asks for clarification.

        A successful process is not necessarily a completed quote. Reuse the
        same pending custody request, including pre-fix DONE rows, without ever
        exposing or copying account values.
        """
        with self.access.guarded_actor(actor),self.lock:
            with self.store.connect() as db:
                rows=db.execute("SELECT id,activity_id,fields_json FROM account_setup_requests WHERE preview_id=? AND status IN ('DONE','NEEDS_INPUT') AND expires_at>? ORDER BY created_at DESC",
                    (preview_id,self.clock())).fetchall()
            for row in rows:
                try:self._current(row['id'])
                except RuntimeFailure:continue
                if not row['activity_id']:continue
                with self.previews.context(actor,preview_id) as (preview,mapped,interface):
                    result=interface.activity(mapped,preview['record']['application_id'],row['activity_id'])
                if result.get('result',{}).get('status')!='needs_input':continue
                with self.store.connect() as db:db.execute("UPDATE account_setup_requests SET status='NEEDS_INPUT' WHERE id=?",(row['id'],))
                return json.loads(row['fields_json']) if row['fields_json'] else {}
        return None

    def request_owner(self,actor,connection):
        with self.access.guarded_actor(actor) as current:
            policy=self.policies.get(connection)
            if not policy or policy['workspace_id']!=current.team_id:denied()
            with self.store.connect() as db:
                eligible=db.execute("SELECT 1 FROM access_memberships WHERE team_id=? AND kind='owner' AND status='active'",(current.team_id,)).fetchone()
                if eligible is None:denied()
                db.execute('INSERT OR IGNORE INTO account_owner_requests VALUES (?,?,?,?)',
                    (current.team_id,connection,current.principal_id,self.clock()))
            return {'status':'requested'}

    def account_requests(self,actor):
        with self.access.guarded_actor(actor) as current:
            choices=[connection for connection,policy in self.policies.items() if policy['workspace_id']==current.team_id]
            with self.store.connect() as db:
                count=db.execute('SELECT COUNT(*) FROM account_owner_requests WHERE workspace_id=?',(current.team_id,)).fetchone()[0] if current.membership_kind=='owner' else 0
            return {'connections':choices,'owner':current.membership_kind=='owner','pending_requests':count}
