"""Durable, bounded human answers over existing exact application invocations.

No application workflow or executable presentation lives in this module.
"""
from __future__ import annotations

import fcntl
import hashlib
import json
import secrets
import time
import threading
import uuid
from dataclasses import asdict
from typing import Any

from .access import ActorContext
from .model import RuntimeFailure, validate_json
from .store import canonical_json


TERMINAL = {"completed", "failed", "uncertain", "cancelled", "expired", "superseded"}


class HumanRequests:
    def __init__(self, store, access, runtime, contract_resolver):
        self.store, self.access, self.runtime = store, access, runtime
        self.contract_resolver = contract_resolver
        self.delegation_authorizer = None
        self._background = []
        self._background_lock = threading.Lock()
        self._closing = False
        with store.connect() as db:
            db.executescript("""
                CREATE TABLE IF NOT EXISTS human_requests_v0 (
                    id TEXT PRIMARY KEY, principal TEXT NOT NULL, membership TEXT NOT NULL,
                    scope TEXT NOT NULL, generation INTEGER NOT NULL, status TEXT NOT NULL,
                    producer TEXT NOT NULL, creation_key TEXT NOT NULL, creation_digest TEXT NOT NULL,
                    value TEXT NOT NULL, UNIQUE(producer, creation_key)
                );
                CREATE TABLE IF NOT EXISTS human_producers_v0 (
                    digest TEXT PRIMARY KEY, value TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS human_launches_v0 (
                    digest TEXT PRIMARY KEY, value TEXT NOT NULL
                );
                CREATE TRIGGER IF NOT EXISTS human_binding_changed_v0 AFTER UPDATE ON bindings
                WHEN OLD.version_digest != NEW.version_digest OR OLD.connections_json != NEW.connections_json
                BEGIN
                    UPDATE human_requests_v0 SET status='superseded',
                        value=json_set(value, '$.status', 'superseded', '$.error', 'HUMAN_BINDING_CHANGED')
                    WHERE scope=OLD.scope_id AND json_extract(value, '$.capability')=OLD.capability_id
                      AND status IN ('waiting', 'saved', 'processing');
                END;
                CREATE TRIGGER IF NOT EXISTS human_binding_removed_v0 AFTER DELETE ON bindings
                BEGIN
                    UPDATE human_requests_v0 SET status='superseded',
                        value=json_set(value, '$.status', 'superseded', '$.error', 'HUMAN_BINDING_REMOVED')
                    WHERE scope=OLD.scope_id AND json_extract(value, '$.capability')=OLD.capability_id
                      AND status IN ('waiting', 'saved', 'processing');
                END;
                CREATE TRIGGER IF NOT EXISTS human_membership_revoked_v0 AFTER UPDATE OF status ON access_memberships
                WHEN NEW.status != 'active'
                BEGIN
                    UPDATE human_requests_v0 SET status='superseded',
                        value=json_set(value, '$.status', 'superseded', '$.error', 'HUMAN_MEMBERSHIP_REVOKED')
                    WHERE membership=OLD.id AND status IN ('waiting', 'saved', 'processing');
                END;
                CREATE TRIGGER IF NOT EXISTS human_resource_revoked_v0 AFTER DELETE ON resources
                BEGIN
                    UPDATE human_requests_v0 SET status='superseded',
                        value=json_set(value, '$.status', 'superseded', '$.error', 'HUMAN_RESOURCE_REVOKED')
                    WHERE scope=OLD.scope_id AND status IN ('waiting', 'saved', 'processing')
                      AND EXISTS (SELECT 1 FROM json_each(json_extract(human_requests_v0.value, '$.resources')) slots,
                          json_each(slots.value) item WHERE item.value=OLD.digest);
                END;
            """)

    def start_background(self, target, *args):
        with self._background_lock:
            if self._closing:
                return  # The durable saved request is recovered on next startup.
            thread = threading.Thread(target=target, args=args, daemon=True)
            self._background.append(thread)
            thread.start()

    def drain_background(self):
        with self._background_lock:
            self._closing = True
            threads = list(self._background)
        for thread in threads:
            thread.join()

    @staticmethod
    def digest(value):
        return hashlib.sha256(value.encode()).hexdigest()

    def _contract(self, actor, app, operation):
        try:
            contract = self.contract_resolver(actor, app)
        except (KeyError, StopIteration) as exc:
            raise RuntimeFailure("HUMAN_APPLICATION_UNAVAILABLE") from exc
        op = next((x for x in contract["operations"] if x["operation_id"] == operation), None)
        if op is None:
            raise RuntimeFailure("HUMAN_OPERATION_DENIED")
        descriptor = self.store.descriptor(op["capability_id"], contract["application_version"])
        # V0 never converts ordinary response controls into consequential consent.
        if descriptor.side_effect != "artifact_generation" or descriptor.state_required or descriptor.connections:
            raise RuntimeFailure("HUMAN_OPERATION_UNSUPPORTED")
        return contract, op, descriptor

    def issue_producer(self, actor, app, operation, *, ttl=3600):
        """Trusted backend provisioning only; never exposed as a browser endpoint."""
        with self.access.guarded_actor(actor) as current:
            contract, _, _ = self._contract(current, app, operation)
            token = secrets.token_urlsafe(32)
            value = {"actor": asdict(current), "app": app, "operation": operation,
                     "version": contract["application_version"], "contract": contract["digest"],
                     "expires": time.time() + min(max(ttl, 1), 86400)}
            with self.store.connect() as db:
                db.execute("INSERT INTO human_producers_v0 VALUES (?, ?)",
                           (self.digest(token), canonical_json(value).decode()))
            return token

    def _credential(self, table, token):
        if not isinstance(token, str) or not 32 <= len(token) <= 128:
            raise RuntimeFailure("HUMAN_CREDENTIAL_DENIED")
        with self.store.connect() as db:
            row = db.execute(f"SELECT value FROM {table} WHERE digest=?", (self.digest(token),)).fetchone()
        if row is None:
            raise RuntimeFailure("HUMAN_CREDENTIAL_DENIED")
        value = json.loads(row[0])
        if value["expires"] <= time.time():
            raise RuntimeFailure("HUMAN_CREDENTIAL_DENIED")
        return value

    def create_from_producer(self, token, key, inputs, resources, *, ttl=86400):
        producer = self._credential("human_producers_v0", token)
        actor = ActorContext(**producer["actor"])
        with self.access.guarded_actor(actor) as current:
            contract, op, descriptor = self._contract(current, producer["app"], producer["operation"])
            if (contract["application_version"], contract["digest"]) != (producer["version"], producer["contract"]):
                raise RuntimeFailure("HUMAN_PRODUCER_STALE")
            return self._create(current, contract, op, descriptor, self.digest(token), key, inputs, resources, ttl)

    def create(self, actor, app, operation, key, inputs, resources, *, ttl=86400):
        with self.access.guarded_actor(actor) as current:
            contract, op, descriptor = self._contract(current, app, operation)
            return self._create(current, contract, op, descriptor,
                                "actor:" + current.membership_id, key, inputs, resources, ttl)

    def read_resource(self, actor, digest):
        path, filename = self.store.resource(actor.execution_scope_id, digest)
        try:
            if path.is_symlink() or not path.is_file() or path.stat().st_size > 2 * 1024 * 1024:
                raise RuntimeFailure("HUMAN_RESOURCE_INVALID")
            payload = path.read_bytes()
        except OSError as exc:
            raise RuntimeFailure("HUMAN_RESOURCE_INVALID") from exc
        if hashlib.sha256(payload).hexdigest() != digest:
            raise RuntimeFailure("HUMAN_RESOURCE_INVALID")
        return payload, filename

    def _validate(self, actor, descriptor, inputs, resources, *, missing=None):
        if not isinstance(inputs, dict) or not isinstance(resources, dict):
            raise RuntimeFailure("HUMAN_INPUT_INVALID")
        schema = dict(descriptor.input_schema)
        if missing is not None:
            schema["required"] = [x for x in schema.get("required", []) if x != missing]
        validate_json(inputs, schema, "HUMAN_INPUT_INVALID")
        slots = {x.name: x for x in descriptor.resource_requirements}
        if set(resources) != set(slots):
            raise RuntimeFailure("HUMAN_RESOURCES_INVALID")
        for name, digests in resources.items():
            slot = slots[name]
            if not isinstance(digests, list) or not slot.min_items <= len(digests) <= slot.max_items:
                raise RuntimeFailure("HUMAN_RESOURCES_INVALID")
            for digest in digests:
                if not isinstance(digest, str):
                    raise RuntimeFailure("HUMAN_RESOURCES_INVALID")
                self.read_resource(actor, digest)

    def _create(self, actor, contract, op, descriptor, producer, key, inputs, resources, ttl):
        if not isinstance(key, str) or not 1 <= len(key) <= 128 or not isinstance(inputs, dict):
            raise RuntimeFailure("HUMAN_INPUT_INVALID")
        missing = [x for x in op["human_fields"] if x["required"] and x["input_kind"] != "file" and x["field_id"] not in inputs]
        if len(missing) != 1 or missing[0]["input_kind"] not in {"text", "choice"}:
            raise RuntimeFailure("HUMAN_SMALL_QUESTION_REQUIRED")
        field = missing[0]
        self._validate(actor, descriptor, inputs, resources, missing=field["field_id"])
        creation_digest = hashlib.sha256(canonical_json({"inputs": inputs, "resources": resources,
                                                        "contract": contract["digest"]})).hexdigest()
        with self.store.transaction() as db:
            old = db.execute("SELECT value, creation_digest FROM human_requests_v0 WHERE producer=? AND creation_key=?",
                             (producer, key)).fetchone()
            if old:
                if old[1] != creation_digest:
                    raise RuntimeFailure("HUMAN_CREATION_CONFLICT")
                return json.loads(old[0])
            value = {"id": uuid.uuid4().hex, "actor": asdict(actor), "app": contract["application_id"],
                     "title": contract["title"], "operation": op["operation_id"], "capability": op["capability_id"],
                     "version": contract["application_version"], "contract": contract["digest"],
                     "generation": 1, "status": "waiting", "question": field["clarification_question"],
                     "field": field["field_id"], "inputs": inputs, "resources": resources,
                     "expires": time.time() + min(max(ttl, 1), 86400), "response": None,
                     "application_disposition": None, "invocation_id": None, "outcome": None,
                     "created": time.time(), "error": None}
            db.execute("INSERT INTO human_requests_v0 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                       (value["id"], actor.principal_id, actor.membership_id, actor.execution_scope_id,
                        1, "waiting", producer, key, creation_digest, canonical_json(value).decode()))
        return value

    def _load(self, db, request_id):
        row = db.execute("SELECT value FROM human_requests_v0 WHERE id=?", (request_id,)).fetchone()
        if row is None:
            raise RuntimeFailure("HUMAN_REQUEST_DENIED")
        return json.loads(row[0])

    def _save(self, db, value):
        db.execute("UPDATE human_requests_v0 SET generation=?, status=?, value=? WHERE id=?",
                   (value["generation"], value["status"], canonical_json(value).decode(), value["id"]))

    def _owner(self, actor, value):
        with self.store.connect() as db:
            row = db.execute('SELECT producer FROM human_requests_v0 WHERE id=?',(value['id'],)).fetchone()
        if row and row[0].startswith('core:'):
            if self.delegation_authorizer is None:
                raise RuntimeFailure('HUMAN_DELEGATED_CLIENT_REQUIRED')
            self.delegation_authorizer(row[0][5:], actor, value)
        saved = value["actor"]
        if any(getattr(actor, k) != saved[k] for k in
               ("authority_id", "principal_id", "membership_id", "team_id", "execution_scope_id")):
            raise RuntimeFailure("HUMAN_REQUEST_DENIED")

    def _receipt(self, db, value):
        row = db.execute("SELECT * FROM invocations WHERE scope_id=? AND idempotency_key=?",
                         (value["actor"]["execution_scope_id"], "human:" + value["id"])).fetchone()
        if row is None:
            return None
        invocation = self.store._decode_invocation(row)
        value["invocation_id"] = invocation["id"]
        if invocation["status"] == "succeeded":
            value.update(status="completed", application_disposition="accepted", error=None,
                         outcome={"result": invocation["result"], "artifacts": invocation["artifacts"],
                                  "receipt": invocation["receipt"]})
        elif invocation["status"] == "failed":
            value.update(status="failed", application_disposition="not_confirmed", error="APPLICATION_EXECUTION_FAILED")
        self._save(db, value)
        return invocation

    def _refresh(self, db, actor, value):
        self._owner(actor, value)
        self._receipt(db, value)
        if value["status"] in TERMINAL:
            return
        if value["expires"] <= time.time() and value["response"] is None:
            value["status"] = "expired"
        else:
            try:
                contract, _, descriptor = self._contract(actor, value["app"], value["operation"])
                if (contract["application_version"], contract["digest"]) != (value["version"], value["contract"]):
                    raise RuntimeFailure("HUMAN_REQUEST_STALE")
                self._validate(actor, descriptor, value["inputs"], value["resources"],
                               missing=value["field"] if value["response"] is None else None)
            except RuntimeFailure as exc:
                value["status"], value["error"] = "superseded", exc.code
        self._save(db, value)

    def get(self, actor, request_id):
        with self.access.guarded_actor(actor) as current, self.store.transaction() as db:
            value = self._load(db, request_id)
            self._refresh(db, current, value)
            return value

    def list(self, actor):
        with self.access.guarded_actor(actor) as current, self.store.transaction() as db:
            ids = [x[0] for x in db.execute(
                "SELECT id FROM human_requests_v0 WHERE principal=? AND membership=? AND scope=? AND producer NOT LIKE 'core:%' ORDER BY rowid DESC",
                (current.principal_id, current.membership_id, current.execution_scope_id))]
            values = []
            for request_id in ids:
                value = self._load(db, request_id)
                self._refresh(db, current, value)
                values.append(value)
            return values

    def respond(self, actor, request_id, generation, *, answer=None, inputs=None, resources=None):
        """Commit the answer and delivery obligation before any execution starts."""
        if type(generation) is not int:
            raise RuntimeFailure("HUMAN_RESPONSE_STALE")
        with self.access.guarded_actor(actor) as current:
            # Persist discovered staleness even when the attempted reply is denied.
            self.get(current, request_id)
            with self.store.transaction() as db:
                value = self._load(db, request_id)
                self._owner(current, value)
                if value["status"] != "waiting" or value["generation"] != generation:
                    raise RuntimeFailure("HUMAN_RESPONSE_STALE")
                _, _, descriptor = self._contract(current, value["app"], value["operation"])
                detailed = inputs is not None
                new_inputs = inputs if detailed else {**value["inputs"], value["field"]: answer}
                new_resources = resources if resources is not None else value["resources"]
                self._validate(current, descriptor, new_inputs, new_resources)
                value.update(inputs=new_inputs, resources=new_resources, status="saved",
                             generation=generation + (1 if detailed else 0),
                             response={"id": uuid.uuid4().hex, "actor": asdict(current),
                                       "saved": time.time(), "route": "application" if detailed else "quick"})
                producer = db.execute('SELECT producer FROM human_requests_v0 WHERE id=?',(request_id,)).fetchone()[0]
                if producer.startswith('core:'):
                    value['response']['provenance'] = 'delegated_client'
                    value['response']['delegation'] = producer[5:]
                self._save(db, value)
                return value

    def cancel(self, actor, request_id, generation):
        with self.access.guarded_actor(actor) as current, self.store.transaction() as db:
            value = self._load(db, request_id)
            self._owner(current, value)
            if value["status"] != "waiting" or value["generation"] != generation:
                raise RuntimeFailure("HUMAN_RESPONSE_STALE")
            value["status"] = "cancelled"
            self._save(db, value)
            return value

    def dispatch(self, request_id):
        if not isinstance(request_id, str) or len(request_id) != 32 or any(c not in "0123456789abcdef" for c in request_id):
            raise RuntimeFailure("HUMAN_REQUEST_DENIED")
        locks = self.store.root / "human-dispatch-locks"
        locks.mkdir(mode=0o700, exist_ok=True)
        with (locks / request_id).open("a") as lock:
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                with self.store.connect() as db:
                    return self._load(db, request_id)
            return self._dispatch(request_id)

    def _dispatch(self, request_id):
        """One bounded attempt. Saved obligations survive outages and restarts.

        Existing runtime idempotency refuses replay of any allocated unfinished
        invocation. A saved-but-not-allocated operation remains retryable.
        """
        with self.store.transaction() as db:
            value = self._load(db, request_id)
            self._receipt(db, value)
        if value["status"] not in {"saved", "processing", "uncertain"}:
            return value
        actor = ActorContext(**value["response"]["actor"])
        try:
            with self.access.guarded_actor(actor) as current:
                with self.store.transaction() as db:
                    value = self._load(db, request_id)
                    self._refresh(db, current, value)
                    if value["status"] not in {"saved", "processing", "uncertain"}:
                        return value
                    value["status"] = "processing"
                    self._save(db, value)
                def allocated(invocation_id):
                    with self.store.transaction() as db:
                        latest = self._load(db, request_id)
                        latest["invocation_id"] = invocation_id
                        latest["application_disposition"] = "processing"
                        self._save(db, latest)
                result = self.runtime.invoke(
                    current.execution_scope_id, value["capability"], value["inputs"],
                    resource_bindings=value["resources"],
                    resource_digests=[d for values in value["resources"].values() for d in values],
                    expected_version_digest=value["version"], idempotency_key="human:" + value["id"],
                    initiator=current.initiator(), on_invocation_started=allocated)
                with self.store.transaction() as db:
                    value = self._load(db, request_id)
                    value.update(status="completed", application_disposition="accepted", error=None,
                                 invocation_id=result.invocation_id,
                                 outcome={"result": result.result, "artifacts": list(result.artifacts), "receipt": result.receipt})
                    self._save(db, value)
        except (RuntimeFailure, OSError) as exc:
            with self.store.transaction() as db:
                value = self._load(db, request_id)
                if value["status"] in TERMINAL:
                    return value
                value["error"] = exc.code if isinstance(exc, RuntimeFailure) else "APPLICATION_UNAVAILABLE"
                row = db.execute("SELECT id, status FROM invocations WHERE scope_id=? AND idempotency_key=?",
                                 (value["actor"]["execution_scope_id"], "human:" + request_id)).fetchone()
                if row:
                    value["invocation_id"] = row[0]
                    # Another dispatcher may still be executing. Never overwrite
                    # its terminal result or turn an active invocation into failure.
                    value["status"] = "uncertain"
                    if row[1] == "failed":
                        value["status"] = "failed"
                    value["application_disposition"] = "not_confirmed"
                elif isinstance(exc, RuntimeFailure) and exc.code.startswith(("ACCESS_", "HUMAN_", "INVOCATION_INPUT", "BINDING_", "RESOURCE_")):
                    value["status"], value["application_disposition"] = "failed", "rejected"
                else:
                    value["status"] = "saved"
                self._save(db, value)
        return value

    def recover(self):
        with self.store.connect() as db:
            ids = [x[0] for x in db.execute("SELECT id FROM human_requests_v0 WHERE status IN ('saved', 'processing', 'uncertain')")]
        return [self.dispatch(request_id) for request_id in ids]
