"""Presentation-independent installed-software consumer service.

Enrollment is a quiescent administrator operation, never a consumer API.
Delegations are exact-version, workspace and originating-client bound. This
module has no browser, conversation, renderer, model or Developer dependency.
"""
from __future__ import annotations

import hashlib
import json
import re
import secrets
import time
from contextlib import contextmanager
from dataclasses import asdict
from pathlib import Path

from .access import AccessStore, ActorContext
from .connections import ConnectionControl
from .human_requests import HumanRequests
from .interaction_contracts import InteractionContractRegistry
from .model import RuntimeFailure
from .runtime import OutcomeRuntime
from .serving import acquire_serving_lease
from .store import RuntimeStore, canonical_json
from .team import TeamSoftwareStore
from .world import WorldBuilder

CONTRACT = 'capy.core/v0'
MAX_UPLOAD = 2 * 1024 * 1024


class Core:
    def __init__(self, root, *, launcher=None, broker_socket=None):
        self.lease = acquire_serving_lease(root)
        self.broker_socket = broker_socket
        try:
            package=Path(__file__).parent
            self.build=hashlib.sha256(b''.join(p.relative_to(package).as_posix().encode()+b'\0'+p.read_bytes()
                for p in sorted(package.rglob('*.py')))).hexdigest()
            self.store = RuntimeStore(root)
            self.access = AccessStore(self.store)
            self.connections = ConnectionControl(self.store)
            self.teams = TeamSoftwareStore(self.store, self.access, connection_control=self.connections)
            self.access.set_membership_reconciler(self.teams.reconcile_team)
            self.world = WorldBuilder(self.store, team_software=self.teams.software_for_actor,
                                      interaction_contracts=InteractionContractRegistry().for_world)
            self.runtime = OutcomeRuntime(self.store, launcher=launcher,
                                          connection_control=self.connections, broker_socket=broker_socket)
            self.questions = HumanRequests(self.store, self.access, self.runtime, self.resolve)
            with self.store.connect() as db:
                db.executescript('''
                    CREATE TABLE IF NOT EXISTS core_clients_v0 (
                        digest TEXT PRIMARY KEY, value TEXT NOT NULL, revoked INTEGER NOT NULL DEFAULT 0);
                    CREATE TABLE IF NOT EXISTS core_resources_v0 (
                        client TEXT NOT NULL, digest TEXT NOT NULL, PRIMARY KEY(client,digest));
                    CREATE TABLE IF NOT EXISTS core_keys_v0 (
                        client TEXT NOT NULL, key TEXT NOT NULL, meaning TEXT NOT NULL, PRIMARY KEY(client,key));
                    CREATE TABLE IF NOT EXISTS core_questions_v0 (
                        id TEXT PRIMARY KEY, client TEXT NOT NULL);
                ''')
            self.questions.delegation_authorizer = self._question_authority
            self.runtime.reconcile_incomplete()
            self.recover_questions()
        except BaseException:
            self.lease.close()
            raise

    def close(self):
        self.questions.drain_background()
        self.lease.close()

    def resolve(self, actor, app):
        world = self.world.build(actor, []).value
        contract = next((x for x in world['applications'] if x['application_id'] == app),None)
        if contract is not None:
            return contract
        # Historical packages without presentation metadata retain exact execution.
        capability = next(x for x in world['capabilities'] if x['id'] == app)
        contract = dict(application_id=app,application_version=capability['version_digest'],
            title=capability['name'], operations=[dict(operation_id='invoke',capability_id=app,
            title=capability['name'],description=capability['description'],human_fields=[])])
        contract['digest']=hashlib.sha256(canonical_json(contract)).hexdigest()
        return contract

    def enroll(self, actor, operations, *, ttl=3600):
        """Trusted local administrator only; caller discloses external data use.

        operations contains exact app/operation/version triples. The credential
        must be delivered in a mode-0600 file, never in a model-visible response.
        """
        if not operations or not 1 <= ttl <= 86400:
            raise RuntimeFailure('CORE_ENROLLMENT_INVALID')
        with self.access.guarded_actor(actor):
            for item in operations:
                self.operation(actor, item)
            token = secrets.token_urlsafe(32)
            value = dict(actor=asdict(actor), operations=operations, expires=time.time()+ttl)
            with self.store.connect() as db:
                db.execute('INSERT INTO core_clients_v0(digest,value) VALUES (?,?)',
                           (self.digest(token), canonical_json(value).decode()))
            return token

    @staticmethod
    def digest(token):
        return hashlib.sha256(token.encode()).hexdigest()

    def revoke(self, digest):
        with self.access.authority_transition_guard(), self.store.connect() as db:
            db.execute('UPDATE core_clients_v0 SET revoked=1 WHERE digest=?', (digest,))

    @contextmanager
    def authorized(self, token):
        if not isinstance(token, str) or not 32 <= len(token) <= 128:
            raise RuntimeFailure('CORE_CLIENT_DENIED')
        with self._authorized_digest(self.digest(token)) as context:
            yield context

    @contextmanager
    def _authorized_digest(self, client):
        with self.access.authority_transition_guard():
            with self.store.connect() as db:
                row = db.execute('SELECT value,revoked FROM core_clients_v0 WHERE digest=?', (client,)).fetchone()
            if row is None or row[1]:
                raise RuntimeFailure('CORE_CLIENT_DENIED')
            grant = json.loads(row[0])
            if grant['expires'] <= time.time():
                raise RuntimeFailure('CORE_CLIENT_EXPIRED')
            with self.access.guarded_actor(ActorContext(**grant['actor'])) as actor:
                yield client, grant, actor

    def _question_authority(self, client, actor, value):
        with self._authorized_digest(client) as (_, grant, current):
            if current != actor or dict(app=value['app'],operation=value['operation'],version=value['version']) not in grant['operations']:
                raise RuntimeFailure('CORE_QUESTION_DENIED')

    def recover_questions(self):
        """Recover accepted ordinary answers only under their current delegation."""
        with self.store.connect() as db:
            pending = list(db.execute("SELECT q.id,q.client FROM core_questions_v0 q "
                "JOIN human_requests_v0 h ON q.id=h.id WHERE h.status IN ('saved','processing','uncertain')"))
        for reference, client in pending:
            try:
                with self._authorized_digest(client) as (_, grant, actor):
                    value = self.questions.get(actor, reference)
                    item = dict(app=value['app'],operation=value['operation'],version=value['version'])
                    if item not in grant['operations']:
                        continue
                    self.operation(actor,item)
                    self.questions.dispatch(reference)
            except RuntimeFailure:
                continue # Preserve denied/expired work; never execute under a stale grant.

    def operation(self, actor, item):
        try:
            if set(item) != {'app', 'operation', 'version'}:
                raise ValueError()
            contract = self.resolve(actor, item['app'])
            if contract['application_version'] != item['version']:
                raise ValueError()
            op = next(x for x in contract['operations'] if x['operation_id'] == item['operation'])
            descriptor = self.store.descriptor(op['capability_id'], item['version'])
            if descriptor.side_effect not in {'read_only', 'artifact_generation'} or descriptor.state_required:
                raise ValueError()
            return contract, op, descriptor
        except (StopIteration, KeyError, ValueError, TypeError) as exc:
            raise RuntimeFailure('CORE_OPERATION_DENIED') from exc

    def _authorized_operations(self, client, grant, actor):
        """Project only currently valid exact grants; never cache authority."""
        operations = []
        for item in grant['operations']:
            try:
                contract, op, descriptor = self.operation(actor, item)
            except RuntimeFailure:
                continue
            operations.append({**item, 'title': op['title'], 'description': op.get('description', ''),
                'input_schema': descriptor.input_schema,
                'resources': [asdict(x) for x in descriptor.resource_requirements],
                'effect': descriptor.side_effect, 'human_fields': op['human_fields'],
                'connection_required': bool(descriptor.connections),
                'readiness': self.readiness(actor, descriptor, item['version'])})
        return operations

    def discover(self, token):
        with self.authorized(token) as (client, grant, actor):
            operations = self._authorized_operations(client, grant, actor)
            return dict(contract=CONTRACT, build=self.build, server=actor.authority_id, client=client, workspace=actor.team_id, operations=operations,
                        capabilities=['discover','upload','invoke','question','answer','result','artifact','work'])

    def context(self, token, *, query=None, cursor=None):
        from .context_search import context_page
        with self.authorized(token) as (client, grant, actor):
            return context_page(self._authorized_operations(client, grant, actor),
                dict(contract=CONTRACT, build=self.build, server=actor.authority_id,
                     client=client, workspace=actor.team_id), query=query, cursor=cursor)

    def readiness(self, actor, descriptor, version):
        if not descriptor.connections:
            return {'status':'ready'}
        status = self.connections.application_status(actor.team_id,descriptor,version)
        configured = status.get('status') == 'configured'
        available = self.broker_socket is not None and self.broker_socket.exists()
        return {'status': 'ready' if configured and available else ('broker_unavailable' if configured else 'setup_required'),
                'next_action': None if configured and available else 'trusted_human_connection_setup_required'}

    def upload(self, token, filename, payload):
        if (not isinstance(filename, str) or not filename or len(filename)>128
                or any(x in filename for x in ('/', '\\', '\x00')) or len(payload)>MAX_UPLOAD):
            raise RuntimeFailure('CORE_RESOURCE_INVALID')
        with self.authorized(token) as (client, grant, actor):
            digest = self.store.add_resource(actor.execution_scope_id, filename, payload)
            with self.store.connect() as db:
                db.execute('INSERT OR IGNORE INTO core_resources_v0 VALUES (?,?)', (client, digest))
            return dict(handle=digest, filename=filename, size_bytes=len(payload), provenance='client_upload')

    def _resources(self, client, resources):
        if not isinstance(resources, dict) or any(not isinstance(x,list) for x in resources.values()):
            raise RuntimeFailure('CORE_RESOURCE_DENIED')
        with self.store.connect() as db:
            for values in resources.values():
                for digest in values:
                    if not isinstance(digest,str) or not db.execute(
                        'SELECT 1 FROM core_resources_v0 WHERE client=? AND digest=?',(client,digest)).fetchone():
                        raise RuntimeFailure('CORE_RESOURCE_DENIED')

    def invoke(self, token, operation, inputs, resources, key):
        if not isinstance(inputs,dict) or not isinstance(key,str) or not re.fullmatch(r'[A-Za-z0-9:._-]{1,128}',key):
            raise RuntimeFailure('CORE_KEY_INVALID')
        with self.authorized(token) as (client, grant, actor):
            if operation not in grant['operations']:
                raise RuntimeFailure('CORE_OPERATION_DENIED')
            contract, op, descriptor = self.operation(actor, operation)
            self._resources(client, resources)
            meaning = hashlib.sha256(canonical_json(dict(operation=operation,inputs=inputs,resources=resources))).hexdigest()
            with self.store.transaction() as db:
                old = db.execute('SELECT meaning FROM core_keys_v0 WHERE client=? AND key=?',(client,key)).fetchone()
                if old and old[0] != meaning:
                    raise RuntimeFailure('CORE_IDEMPOTENCY_CONFLICT')
                db.execute('INSERT OR IGNORE INTO core_keys_v0 VALUES (?,?,?)',(client,key,meaning))
            missing = [x for x in descriptor.input_schema.get('required',[]) if x not in inputs]
            if missing:
                contract, op, descriptor = self.questions._contract(actor, operation['app'], operation['operation'])
                value = self.questions._create(actor, contract, op, descriptor, 'core:'+client,
                                               key, inputs, resources, 86400)
                with self.store.connect() as db:
                    db.execute('INSERT OR IGNORE INTO core_questions_v0 VALUES (?,?)',(value['id'],client))
                return self._question(value)
            with self.store.connect() as db:
                prior = db.execute('SELECT id FROM invocations WHERE scope_id=? AND idempotency_key=?',
                    (actor.execution_scope_id,'core:'+client+':'+key)).fetchone()
            if prior:
                return self.result(token,prior[0])
            self.questions._validate(actor, descriptor, inputs, resources)
            try:
                result = self.runtime.invoke(actor.execution_scope_id, op['capability_id'], inputs,
                    resource_bindings=resources, resource_digests=[d for values in resources.values() for d in values],
                    expected_version_digest=operation['version'], idempotency_key='core:'+client+':'+key,
                    initiator=actor.initiator())
            except RuntimeFailure:
                with self.store.connect() as db:
                    allocated=db.execute('SELECT id FROM invocations WHERE scope_id=? AND idempotency_key=?',
                        (actor.execution_scope_id,'core:'+client+':'+key)).fetchone()
                if allocated:
                    return self.result(token,allocated[0])
                raise
            return self.result(token, result.invocation_id)

    @staticmethod
    def _question(value):
        return {k: value[k] for k in ('id','app','title','operation','version','generation','status',
                                    'question','field','inputs','expires','invocation_id','error')}

    def question(self, token, reference, *, generation=None, answer=None):
        with self.authorized(token) as (client, grant, actor):
            with self.store.connect() as db:
                if not db.execute('SELECT 1 FROM core_questions_v0 WHERE id=? AND client=?',(reference,client)).fetchone():
                    raise RuntimeFailure('CORE_QUESTION_DENIED')
            value = self.questions.get(actor, reference)
            item = dict(app=value['app'],operation=value['operation'],version=value['version'])
            if item not in grant['operations']:
                raise RuntimeFailure('CORE_OPERATION_DENIED')
            self.operation(actor,item)
            if generation is not None:
                self.questions.respond(actor, reference, generation, answer=answer)
                # Guard stays held across dispatch, so revocation cannot race admission.
                value = self.questions.dispatch(reference)
            return self._question(value)

    def result(self, token, reference):
        with self.authorized(token) as (client, grant, actor):
            value = self.store.invocation(reference)
            owned = (value.get('idempotency_key') or '').startswith('core:'+client+':')
            if not owned:
                with self.store.connect() as db:
                    owned = bool(db.execute('SELECT 1 FROM core_questions_v0 q JOIN human_requests_v0 h ON q.id=h.id '
                        "WHERE q.client=? AND json_extract(h.value,'$.invocation_id')=?",(client,reference)).fetchone())
            if not owned or value['scope_id'] != actor.execution_scope_id:
                raise RuntimeFailure('CORE_RESULT_DENIED')
            allowed = False
            for item in grant['operations']:
                try:
                    _, op, _ = self.operation(actor,item)
                    allowed |= op['capability_id']==value['capability_id'] and item['version']==value['version_digest']
                except RuntimeFailure:
                    pass
            if not allowed:
                raise RuntimeFailure('CORE_RESULT_DENIED')
            return dict(id=reference, execution_state=value['status'], business_outcome='not_inferred',
                        result=value['result'], artifacts=value['artifacts'] or [])

    def work(self, token):
        """Bounded owned references, including failed and uncertain invocations."""
        with self.authorized(token) as (client, grant, actor):
            with self.store.connect() as db:
                invocations = [r[0] for r in db.execute(
                    'SELECT id FROM invocations WHERE scope_id=? AND idempotency_key LIKE ? ORDER BY created_at DESC LIMIT 50',
                    (actor.execution_scope_id,'core:'+client+':%'))]
                questions = [r[0] for r in db.execute('SELECT id FROM core_questions_v0 WHERE client=? ORDER BY rowid DESC LIMIT 50',(client,))]
            results=[]
            pending=[]
            for reference in invocations:
                try:results.append(self.result(token,reference))
                except RuntimeFailure:pass
            for reference in questions:
                try:pending.append(self.question(token,reference))
                except RuntimeFailure:pass
            return dict(results=results,questions=pending)

    def artifact(self, token, reference, digest):
        with self.authorized(token) as (_, _, actor):
            value = self.result(token,reference)
            if not any(x['digest']==digest for x in value['artifacts']):
                raise RuntimeFailure('CORE_ARTIFACT_DENIED')
            return self.questions.read_resource(actor,digest)
