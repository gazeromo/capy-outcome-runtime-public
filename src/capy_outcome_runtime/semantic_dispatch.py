"""One private durable, globally paced semantic-provider dispatch lane."""

from __future__ import annotations

import hashlib
import json
import sqlite3
import threading
import time
import uuid
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

from .model import RuntimeFailure
from .store import canonical_json


TRANSIENT_PROVIDER_CODES = {
    "SEMANTIC_PROVIDER_RATE_LIMIT",
    "SEMANTIC_PROVIDER_TEMPORARY",
    "SEMANTIC_PROVIDER_ERROR",
}


@dataclass(frozen=True)
class DispatchPolicy:
    max_attempts: int = 3
    max_elapsed_seconds: float = 180.0
    minimum_spacing_seconds: float = 3.0
    base_backoff_seconds: float = 15.0
    maximum_backoff_seconds: float = 60.0
    lease_seconds: float = 90.0


class SemanticDispatchStore:
    """SQLite state for one shared lane; this is not a generic job framework."""

    def __init__(
        self,
        database: Path,
        *,
        policy: DispatchPolicy | None = None,
        clock: Callable[[], float] = time.time,
    ):
        self.database = database
        self.policy = policy or DispatchPolicy()
        self.clock = clock
        self._initialize()

    @contextmanager
    def connect(self):
        db = sqlite3.connect(self.database, timeout=30)
        db.row_factory = sqlite3.Row
        try:
            yield db
            db.commit()
        except BaseException:
            db.rollback()
            raise
        finally:
            db.close()

    def _initialize(self) -> None:
        with self.connect() as db:
            db.executescript(
                """
                CREATE TABLE IF NOT EXISTS semantic_dispatch_jobs (
                    id TEXT PRIMARY KEY,
                    consumer_key TEXT NOT NULL UNIQUE,
                    work_kind TEXT NOT NULL CHECK(work_kind IN ('chat_turn','watcher_judgment')),
                    payload_json TEXT NOT NULL,
                    request_sha256 TEXT NOT NULL,
                    state TEXT NOT NULL CHECK(state IN ('queued','retry_wait','provider_running','result_ready','completed','failed')),
                    attempt_count INTEGER NOT NULL,
                    max_attempts INTEGER NOT NULL,
                    created_at REAL NOT NULL,
                    deadline_at REAL NOT NULL,
                    next_attempt_at REAL NOT NULL,
                    result_json TEXT,
                    error_code TEXT,
                    attempts_json TEXT NOT NULL,
                    completed_at REAL
                );
                CREATE INDEX IF NOT EXISTS semantic_dispatch_due
                ON semantic_dispatch_jobs(state,next_attempt_at,created_at,id);
                CREATE TABLE IF NOT EXISTS semantic_provider_lane (
                    singleton INTEGER PRIMARY KEY CHECK(singleton=1),
                    active_job_id TEXT,
                    lease_until REAL,
                    cooldown_until REAL NOT NULL,
                    last_attempt_at REAL,
                    health TEXT NOT NULL,
                    updated_at REAL NOT NULL
                );
                """
            )
            now = self.clock()
            db.execute(
                """INSERT OR IGNORE INTO semantic_provider_lane
                   VALUES(1,NULL,NULL,0,NULL,'unknown',?)""",
                (now,),
            )

    def enqueue(
        self,
        work_kind: str,
        consumer_key: str,
        payload: dict[str, Any],
        *,
        max_attempts: int | None = None,
        max_elapsed_seconds: float | None = None,
    ) -> str:
        if work_kind not in {"chat_turn", "watcher_judgment"}:
            raise RuntimeFailure("SEMANTIC_DISPATCH_KIND_INVALID")
        raw = canonical_json(payload)
        digest = hashlib.sha256(raw).hexdigest()
        now = self.clock()
        attempts = max_attempts or self.policy.max_attempts
        elapsed = max_elapsed_seconds or self.policy.max_elapsed_seconds
        if not 1 <= attempts <= 8 or not 1 <= elapsed <= 3600:
            raise RuntimeFailure("SEMANTIC_DISPATCH_POLICY_INVALID")
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            existing = db.execute(
                "SELECT id,request_sha256,work_kind FROM semantic_dispatch_jobs WHERE consumer_key=?",
                (consumer_key,),
            ).fetchone()
            if existing is not None:
                if existing["request_sha256"] != digest or existing["work_kind"] != work_kind:
                    raise RuntimeFailure("SEMANTIC_DISPATCH_IDEMPOTENCY_CONFLICT")
                return str(existing["id"])
            job_id = uuid.uuid4().hex
            db.execute(
                """INSERT INTO semantic_dispatch_jobs
                   VALUES(?,?,?,?,?,'queued',0,?,?,?,?,NULL,NULL,'[]',NULL)""",
                (job_id, consumer_key, work_kind, raw.decode(), digest, attempts,
                 now, now + elapsed, now),
            )
            return job_id

    def job(self, job_id: str) -> dict[str, Any]:
        with self.connect() as db:
            row = db.execute("SELECT * FROM semantic_dispatch_jobs WHERE id=?", (job_id,)).fetchone()
        if row is None:
            raise RuntimeFailure("SEMANTIC_DISPATCH_JOB_UNKNOWN")
        value = dict(row)
        value["payload"] = json.loads(value.pop("payload_json"))
        value["result"] = json.loads(value.pop("result_json")) if value.get("result_json") else None
        value["attempts"] = json.loads(value.pop("attempts_json"))
        return value

    def job_for_consumer(self, consumer_key: str) -> dict[str, Any]:
        with self.connect() as db:
            row = db.execute(
                "SELECT id FROM semantic_dispatch_jobs WHERE consumer_key=?", (consumer_key,)
            ).fetchone()
        if row is None:
            raise RuntimeFailure("SEMANTIC_DISPATCH_JOB_UNKNOWN")
        return self.job(str(row["id"]))

    def _release_expired(self, db: sqlite3.Connection, now: float) -> None:
        lane = db.execute("SELECT * FROM semantic_provider_lane WHERE singleton=1").fetchone()
        if lane["active_job_id"] is not None and (lane["lease_until"] or 0) <= now:
            job = db.execute(
                "SELECT * FROM semantic_dispatch_jobs WHERE id=?", (lane["active_job_id"],)
            ).fetchone()
            if job is not None and job["state"] == "provider_running":
                attempts = json.loads(job["attempts_json"])
                attempts.append({
                    "attempt": job["attempt_count"], "outcome": "interrupted",
                    "model_calls": 1,
                    "error_code": "SEMANTIC_PROVIDER_ATTEMPT_INTERRUPTED",
                })
                if job["deadline_at"] <= now:
                    db.execute(
                        """UPDATE semantic_dispatch_jobs SET state='failed',next_attempt_at=?,
                                  error_code='SEMANTIC_PROVIDER_RECOVERY_EXPIRED',attempts_json=?,completed_at=?
                           WHERE id=? AND state='provider_running'""",
                        (now, canonical_json(attempts).decode(), now, job["id"]),
                    )
                else:
                    db.execute(
                        """UPDATE semantic_dispatch_jobs SET state='retry_wait',next_attempt_at=?,attempts_json=?
                           WHERE id=? AND state='provider_running'""",
                        (now + self.policy.base_backoff_seconds,
                         canonical_json(attempts).decode(), job["id"]),
                    )
            db.execute(
                """UPDATE semantic_provider_lane SET active_job_id=NULL,lease_until=NULL,
                          health='recovering',updated_at=? WHERE singleton=1""",
                (now,),
            )

    @staticmethod
    def _expire_waiting(db: sqlite3.Connection, now: float) -> None:
        rows = db.execute(
            """SELECT id,attempt_count,attempts_json FROM semantic_dispatch_jobs
               WHERE state IN ('queued','retry_wait') AND deadline_at<=?""",
            (now,),
        ).fetchall()
        for row in rows:
            attempts = json.loads(row["attempts_json"])
            attempts.append({
                "attempt": row["attempt_count"],
                "outcome": "recovery_expired",
                "model_calls": 0,
                "error_code": "SEMANTIC_PROVIDER_RECOVERY_EXPIRED",
            })
            db.execute(
                """UPDATE semantic_dispatch_jobs SET state='failed',next_attempt_at=?,
                          error_code='SEMANTIC_PROVIDER_RECOVERY_EXPIRED',attempts_json=?,completed_at=?
                   WHERE id=? AND state IN ('queued','retry_wait')""",
                (now, canonical_json(attempts).decode(), now, row["id"]),
            )

    def claim(self) -> dict[str, Any] | None:
        now = self.clock()
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            self._release_expired(db, now)
            self._expire_waiting(db, now)
            lane = db.execute("SELECT * FROM semantic_provider_lane WHERE singleton=1").fetchone()
            if lane["active_job_id"] is not None or lane["cooldown_until"] > now:
                return None
            if lane["last_attempt_at"] is not None:
                earliest = lane["last_attempt_at"] + self.policy.minimum_spacing_seconds
                if earliest > now:
                    return None
            row = db.execute(
                """SELECT * FROM semantic_dispatch_jobs
                   WHERE state IN ('queued','retry_wait') AND next_attempt_at<=?
                   ORDER BY next_attempt_at,created_at,rowid LIMIT 1""",
                (now,),
            ).fetchone()
            if row is None:
                return None
            attempt = row["attempt_count"] + 1
            changed = db.execute(
                """UPDATE semantic_dispatch_jobs SET state='provider_running',attempt_count=?
                   WHERE id=? AND state IN ('queued','retry_wait')""",
                (attempt, row["id"]),
            ).rowcount
            if changed != 1:
                return None
            db.execute(
                """UPDATE semantic_provider_lane SET active_job_id=?,lease_until=?,last_attempt_at=?,
                          health='calling',updated_at=? WHERE singleton=1""",
                (row["id"], now + self.policy.lease_seconds, now, now),
            )
        return self.job(str(row["id"]))

    @staticmethod
    def _safe_attempt(exc: RuntimeFailure, attempt: int) -> dict[str, Any]:
        facts = exc.safe_facts
        return {
            "attempt": attempt,
            "model_calls": int(facts.get("semantic_attempt_count") or 1),
            "semantic_attempts": facts.get("semantic_attempts"),
            "outcome": "provider_error",
            "error_code": exc.code,
            "provider_http_status": facts.get("provider_http_status"),
            "provider_error_code": (facts.get("provider_envelope") or {}).get("error_code"),
            "provider_response_sha256": facts.get("provider_response_sha256"),
            "provider_response_bytes": facts.get("provider_response_bytes"),
            "provider_request_id": facts.get("provider_request_id"),
            "retry_after_seconds": facts.get("provider_retry_after_seconds"),
            "semantic_failure_shape": facts.get("semantic_failure_shape"),
        }

    def provider_succeeded(self, job_id: str, result: dict[str, Any]) -> bool:
        now = self.clock()
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            job = db.execute("SELECT * FROM semantic_dispatch_jobs WHERE id=?", (job_id,)).fetchone()
            if job is None or job["state"] != "provider_running":
                raise RuntimeFailure("SEMANTIC_DISPATCH_STATE_CONFLICT")
            attempts = json.loads(job["attempts_json"])
            usage = (
                result.get("dispatch_usage") or result.get("usage")
                if isinstance(result, dict) else None
            )
            usage = usage if isinstance(usage, dict) else {}
            receipt = {
                "attempt": job["attempt_count"], "outcome": "success",
                "model_calls": int(usage.get("semantic_attempt_count") or 1),
                "semantic_attempts": usage.get("semantic_attempts"),
                "request_sha256": usage.get("semantic_request_sha256") or result.get("request_digest"),
                "response_sha256": usage.get("response_sha256") or result.get("response_digest"),
                "provider_http_status": usage.get("provider_http_status"),
                "provider_request_id": usage.get("provider_request_id"),
                "prompt_tokens": usage.get("prompt_tokens"),
                "completion_tokens": usage.get("completion_tokens"),
                "total_tokens": usage.get("total_tokens"),
                "cost": usage.get("cost"),
            }
            if job["deadline_at"] <= now:
                receipt["outcome"] = "provider_success_after_deadline"
                receipt["error_code"] = "SEMANTIC_PROVIDER_RECOVERY_EXPIRED"
                attempts.append(receipt)
                db.execute(
                    """UPDATE semantic_dispatch_jobs SET state='failed',result_json=NULL,
                              error_code='SEMANTIC_PROVIDER_RECOVERY_EXPIRED',attempts_json=?,completed_at=?
                       WHERE id=?""",
                    (canonical_json(attempts).decode(), now, job_id),
                )
                ready = False
            else:
                attempts.append(receipt)
                db.execute(
                    """UPDATE semantic_dispatch_jobs SET state='result_ready',result_json=?,error_code=NULL,attempts_json=?
                       WHERE id=?""",
                    (canonical_json(result).decode(), canonical_json(attempts).decode(), job_id),
                )
                ready = True
            db.execute(
                """UPDATE semantic_provider_lane SET active_job_id=NULL,lease_until=NULL,
                          cooldown_until=0,health='available',updated_at=? WHERE singleton=1""",
                (now,),
            )
        return ready

    def provider_failed(self, job_id: str, exc: RuntimeFailure) -> None:
        now = self.clock()
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            job = db.execute("SELECT * FROM semantic_dispatch_jobs WHERE id=?", (job_id,)).fetchone()
            if job is None or job["state"] != "provider_running":
                raise RuntimeFailure("SEMANTIC_DISPATCH_STATE_CONFLICT")
            attempts = json.loads(job["attempts_json"])
            attempt = self._safe_attempt(exc, job["attempt_count"])
            attempt["request_sha256"] = job["request_sha256"]
            attempts.append(attempt)
            transient = exc.code in TRANSIENT_PROVIDER_CODES
            exhausted = job["attempt_count"] >= job["max_attempts"] or now >= job["deadline_at"]
            if transient and not exhausted:
                exponent = self.policy.base_backoff_seconds * (2 ** (job["attempt_count"] - 1))
                jitter_seed = int(hashlib.sha256(f"{job_id}:{job['attempt_count']}".encode()).hexdigest()[:8], 16)
                jitter = (jitter_seed % 1000) / 1000 * min(1.0, exponent * 0.25)
                delay = min(self.policy.maximum_backoff_seconds, exponent + jitter)
                retry_after = exc.safe_facts.get("provider_retry_after_seconds")
                if type(retry_after) in {int, float}:
                    delay = max(delay, min(float(retry_after), self.policy.maximum_backoff_seconds))
                next_attempt = now + delay
                state, completed_at = "retry_wait", None
            else:
                next_attempt = now
                state, completed_at = "failed", now
            cooldown = next_attempt if exc.code == "SEMANTIC_PROVIDER_RATE_LIMIT" else 0
            db.execute(
                """UPDATE semantic_dispatch_jobs SET state=?,next_attempt_at=?,error_code=?,
                          attempts_json=?,completed_at=? WHERE id=?""",
                (state, next_attempt, exc.code, canonical_json(attempts).decode(), completed_at, job_id),
            )
            db.execute(
                """UPDATE semantic_provider_lane SET active_job_id=NULL,lease_until=NULL,
                          cooldown_until=MAX(cooldown_until,?),health=?,updated_at=? WHERE singleton=1""",
                (cooldown, "rate_limited" if exc.code == "SEMANTIC_PROVIDER_RATE_LIMIT" else "degraded", now),
            )

    def mark_consumed(self, job_id: str) -> None:
        now = self.clock()
        with self.connect() as db:
            changed = db.execute(
                """UPDATE semantic_dispatch_jobs SET state='completed',completed_at=?
                   WHERE id=? AND state='result_ready'""",
                (now, job_id),
            ).rowcount
        if changed != 1:
            raise RuntimeFailure("SEMANTIC_DISPATCH_STATE_CONFLICT")

    def mark_failure_consumed(self, job_id: str) -> None:
        now = self.clock()
        with self.connect() as db:
            changed = db.execute(
                """UPDATE semantic_dispatch_jobs SET state='completed',completed_at=?
                   WHERE id=? AND state='failed'""",
                (now, job_id),
            ).rowcount
        if changed != 1:
            raise RuntimeFailure("SEMANTIC_DISPATCH_STATE_CONFLICT")

    def ready(self) -> list[dict[str, Any]]:
        with self.connect() as db:
            rows = db.execute(
                "SELECT id FROM semantic_dispatch_jobs WHERE state='result_ready' ORDER BY created_at,id"
            ).fetchall()
        return [self.job(str(row["id"])) for row in rows]

    def terminal_failures(self) -> list[dict[str, Any]]:
        with self.connect() as db:
            rows = db.execute(
                "SELECT id FROM semantic_dispatch_jobs WHERE state='failed' ORDER BY created_at,id"
            ).fetchall()
        return [self.job(str(row["id"])) for row in rows]

    def health(self) -> dict[str, Any]:
        now = self.clock()
        with self.connect() as db:
            lane = dict(db.execute("SELECT * FROM semantic_provider_lane WHERE singleton=1").fetchone())
            counts = {
                row["state"]: row["count"]
                for row in db.execute("SELECT state,COUNT(*) count FROM semantic_dispatch_jobs GROUP BY state")
            }
        return {
            "health": lane["health"],
            "cooldown_remaining_seconds": round(max(0.0, lane["cooldown_until"] - now), 3),
            "provider_attempt_active": lane["active_job_id"] is not None,
            "jobs": counts,
        }

    def metrics(self) -> dict[str, Any]:
        with self.connect() as db:
            rows = db.execute(
                "SELECT created_at,completed_at,attempt_count,attempts_json FROM semantic_dispatch_jobs"
            ).fetchall()
        tokens = 0
        cost = 0.0
        latencies = []
        for row in rows:
            for attempt in json.loads(row["attempts_json"]):
                if attempt.get("outcome") in {"success", "provider_success_after_deadline"}:
                    tokens += int(attempt.get("total_tokens") or 0)
                    cost += float(attempt.get("cost") or 0)
            if row["completed_at"] is not None:
                latencies.append(float(row["completed_at"] - row["created_at"]))
        return {
            "logical_work_items": len(rows),
            "provider_attempts": sum(
                sum(
                    int(item["model_calls"])
                    if type(item.get("model_calls")) is int
                    else (0 if item.get("outcome") == "recovery_expired" else 1)
                    for item in json.loads(row["attempts_json"])
                )
                for row in rows
            ),
            "successful_model_tokens": tokens,
            "provider_cost": round(cost, 12),
            "maximum_completion_seconds": round(max(latencies), 3) if latencies else None,
        }


class SemanticDispatcher:
    def __init__(
        self,
        store: SemanticDispatchStore,
        providers: dict[str, Callable[[dict[str, Any]], dict[str, Any]]],
        consumers: dict[str, Callable[[dict[str, Any], dict[str, Any]], None]],
        failure_consumers: dict[str, Callable[[dict[str, Any]], None]] | None = None,
    ):
        self.store = store
        self.providers = providers
        self.consumers = consumers
        self.failure_consumers = failure_consumers or {}

    def run_once(self) -> bool:
        for job in self.store.ready():
            self.consumers[job["work_kind"]](job, job["result"])
            self.store.mark_consumed(job["id"])
            return True
        for job in self.store.terminal_failures():
            consumer = self.failure_consumers.get(job["work_kind"])
            if consumer is not None:
                consumer(job)
            self.store.mark_failure_consumed(job["id"])
            return True
        job = self.store.claim()
        if job is None:
            return False
        try:
            result = self.providers[job["work_kind"]](job["payload"])
        except RuntimeFailure as exc:
            self.store.provider_failed(job["id"], exc)
            return True
        if not self.store.provider_succeeded(job["id"], result):
            return True
        refreshed = self.store.job(job["id"])
        self.consumers[job["work_kind"]](refreshed, refreshed["result"])
        self.store.mark_consumed(job["id"])
        return True

    def serve(self, stop: threading.Event, idle_seconds: float = 0.1) -> None:
        while not stop.is_set():
            try:
                worked = self.run_once()
            except Exception:
                worked = False
            if not worked:
                stop.wait(idle_seconds)
