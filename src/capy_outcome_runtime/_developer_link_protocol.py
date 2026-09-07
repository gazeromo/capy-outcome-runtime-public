"""Intentionally public, dependency-free Developer Link V0 wire grammar.

Mirrored byte-for-byte in the runtime; neither implementation imports the other.
"""
from __future__ import annotations
import hashlib
import json
import re
from urllib.parse import urlsplit

class ProtocolError(ValueError):
    pass

def canonical(value):
    try:
        return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8")
    except (TypeError, ValueError, UnicodeError) as exc:
        raise ProtocolError("INVALID_JSON") from exc

def digest(value):
    return hashlib.sha256(canonical(value)).hexdigest()

def decode_json(raw, max_bytes=262144):
    if len(raw) > max_bytes:
        raise ProtocolError("PAYLOAD_TOO_LARGE")
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ProtocolError("DUPLICATE_KEY")
            result[key] = value
        return result
    def invalid(value):
        raise ProtocolError("NONFINITE_JSON")
    try:
        value = json.loads(raw, object_pairs_hook=pairs, parse_constant=invalid)
        canonical(value)
        return value
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise ProtocolError("INVALID_JSON") from exc

def _match(value, pattern):
    return isinstance(value, str) and re.fullmatch(pattern, value) is not None

def _id(value, prefix):
    return _match(value, re.escape(prefix) + r"_[0-9a-f]{32}")

def _int(value, low=1, high=2147483647):
    return type(value) is int and low <= value <= high

def _text(value):
    return _match(value, r"[A-Za-z0-9_.:-]{1,160}")

def origin(value):
    if not isinstance(value, str) or len(value) > 256 or any(c.isspace() for c in value):
        raise ProtocolError("SITE_ORIGIN_INVALID")
    try:
        p = urlsplit(value)
        if (p.scheme != "https" or not p.hostname or p.username or p.password or
                p.path or p.query or p.fragment or p.port == 0 or
                p.netloc != p.netloc.lower() or '%' in value or '\\' in value):
            raise ProtocolError("SITE_ORIGIN_INVALID")
    except ValueError as exc:
        raise ProtocolError("SITE_ORIGIN_INVALID") from exc
    return value

def parse_uri(value):
    if not isinstance(value, str):
        raise ProtocolError("HANDOFF_URI_INVALID")
    m = re.fullmatch(r"capy-dev://handoff/(hof_[0-9a-f]{32})\?site=(site_[0-9a-f]{32})&launch=([1-9][0-9]{0,9})", value)
    if not m or not _int(int(m[3])):
        raise ProtocolError("HANDOFF_URI_INVALID")
    return {"handoff_id": m[1], "site_id": m[2], "launch_generation": int(m[3])}

def make_uri(site_id, handoff_id, launch_generation):
    value = f"capy-dev://handoff/{handoff_id}?site={site_id}&launch={launch_generation}"
    parse_uri(value)
    return value

REQUEST_FIELDS = set("schema site_id handoff_id device_id principal_id authority_id workspace_kind workspace_id membership_id intent parent_handoff_id release_candidate_id created_at expires_at request_digest launch_generation".split())
def validate_request(value):
    if not isinstance(value, dict):
        raise ProtocolError("REQUEST_SHAPE_INVALID")
    existing = value.get('schema') == 'capy.developer-link-request/v1'
    if set(value) != (REQUEST_FIELDS | {'project_id'} if existing else REQUEST_FIELDS):
        raise ProtocolError("REQUEST_SHAPE_INVALID")
    if value['schema'] not in ('capy.developer-link-request/v0','capy.developer-link-request/v1'):
        raise ProtocolError("REQUEST_SCHEMA_INVALID")
    if existing and (value['intent'] != 'EXISTING' or not _id(value['project_id'],'prj')):
        raise ProtocolError("REQUEST_INTENT_INVALID")
    for key, prefix in [('site_id','site'),('handoff_id','hof'),('device_id','dev')]:
        if not _id(value[key],prefix): raise ProtocolError("REQUEST_ID_INVALID")
    for key in ('principal_id','authority_id','workspace_id','membership_id'):
        if not _text(value[key]): raise ProtocolError("REQUEST_AUTHORITY_INVALID")
    if value['workspace_kind'] not in ('personal','team') or value['intent'] not in (('EXISTING',) if existing else ('NEW','CONTINUE')):
        raise ProtocolError("REQUEST_INTENT_INVALID")
    if not _int(value['launch_generation']) or not _int(value['created_at'],0,2**53) or not _int(value['expires_at'],value['created_at']+1,2**53):
        raise ProtocolError("REQUEST_TIME_INVALID")
    if value['intent'] in ('NEW','EXISTING'):
        if value['parent_handoff_id'] is not None or value['release_candidate_id'] is not None: raise ProtocolError("REQUEST_PARENT_INVALID")
    elif not _id(value['parent_handoff_id'],'hof') or (value['release_candidate_id'] is not None and not _id(value['release_candidate_id'],'rc')):
        raise ProtocolError("REQUEST_PARENT_INVALID")
    expected=digest({k:v for k,v in value.items() if k not in ('request_digest','launch_generation')})
    if value['request_digest'] != expected: raise ProtocolError("REQUEST_DIGEST_INVALID")
    return value

SNAPSHOT_FIELDS = set("milestone project_id session_id application_id source_commit dirty verification_id verification_commit verification_status candidate_id candidate_verification_id candidate_sha256 candidate_size candidate_commit source_fresh terminal".split())
MILESTONES = {'PREPARING','WAITING_FOR_HARNESS','HARNESS_ATTACHED','CHANGES_IN_PROGRESS','VERIFYING','CHECKS_FAILED','CHECKS_PASSED','CANDIDATE_PREPARED','SESSION_FINISHED','LAUNCH_OUTCOME_UNKNOWN'}
def validate_snapshot(value):
    if not isinstance(value,dict) or set(value)!=SNAPSHOT_FIELDS or not isinstance(value['milestone'], str) or value['milestone'] not in MILESTONES:
        raise ProtocolError("SNAPSHOT_SHAPE_INVALID")
    for key,prefix in [('project_id','prj'),('session_id','ses'),('candidate_id','rc')]:
        if value[key] is not None and not _id(value[key],prefix): raise ProtocolError("SNAPSHOT_ID_INVALID")
    if any(value[k] is not None and not _match(value[k],r'ver_[A-Za-z0-9_]{1,100}') for k in ('verification_id','candidate_verification_id')):
        raise ProtocolError("SNAPSHOT_ID_INVALID")
    if value['application_id'] is not None and not _text(value['application_id']): raise ProtocolError("SNAPSHOT_APPLICATION_INVALID")
    for key in ('source_commit','candidate_commit','verification_commit'):
        if value[key] is not None and not _match(value[key],r'[0-9a-f]{40}'): raise ProtocolError("SNAPSHOT_COMMIT_INVALID")
    if type(value['dirty']) is not bool or type(value['source_fresh']) is not bool: raise ProtocolError("SNAPSHOT_BOOLEAN_INVALID")
    if value['verification_status'] not in (None,'RUNNING','PASSED','FAILED','INTERRUPTED') or value['terminal'] not in (None,'COMPLETED','CANCELLED'):
        raise ProtocolError("SNAPSHOT_STATUS_INVALID")
    if (value['project_id'] is None)!=(value['session_id'] is None): raise ProtocolError("SNAPSHOT_SESSION_INVALID")
    if (value['verification_id'] is None)!=(value['verification_status'] is None) or (value['verification_id'] is None)!=(value['verification_commit'] is None): raise ProtocolError("SNAPSHOT_VERIFICATION_INVALID")
    if value['source_fresh'] and (value['dirty'] or value['session_id'] is None or value['source_commit'] is None or (value['verification_id'] is None and value['candidate_id'] is None)):
        raise ProtocolError('SNAPSHOT_FRESHNESS_INVALID')
    candidate_fields=[value[k] for k in ('candidate_id','candidate_verification_id','candidate_sha256','candidate_size','candidate_commit')]
    if any(v is not None for v in candidate_fields):
        if (any(v is None for v in candidate_fields) or not _match(value['candidate_sha256'],r'[0-9a-f]{64}') or
                not _int(value['candidate_size'],1,2**53) or value['session_id'] is None):
            raise ProtocolError("SNAPSHOT_CANDIDATE_INVALID")
        if value['source_fresh'] and (value['dirty'] or value['source_commit']!=value['candidate_commit']):
            raise ProtocolError("SNAPSHOT_FRESHNESS_INVALID")
    if value['source_fresh'] and value['candidate_id'] is None and value['source_commit']!=value['verification_commit']:
        raise ProtocolError('SNAPSHOT_FRESHNESS_INVALID')
    required_status={'VERIFYING':'RUNNING','CHECKS_FAILED':'FAILED','CHECKS_PASSED':'PASSED','CANDIDATE_PREPARED':'PASSED'}
    if value['milestone'] in required_status and value['verification_status']!=required_status[value['milestone']]:
        raise ProtocolError("SNAPSHOT_MILESTONE_INVALID")
    if value['milestone']=='CANDIDATE_PREPARED' and (value['candidate_id'] is None or value['verification_id']!=value['candidate_verification_id'] or value['verification_commit']!=value['candidate_commit']): raise ProtocolError("SNAPSHOT_CANDIDATE_INVALID")
    if value['milestone']=='SESSION_FINISHED' and value['terminal'] is None: raise ProtocolError("SNAPSHOT_TERMINAL_INVALID")
    if value['milestone'] not in {'PREPARING','LAUNCH_OUTCOME_UNKNOWN'} and value['session_id'] is None: raise ProtocolError("SNAPSHOT_SESSION_INVALID")
    return value

def validate_event(value):
    if not isinstance(value,dict) or set(value)!=set('schema site_id handoff_id device_id sequence snapshot digest'.split()):
        raise ProtocolError("EVENT_SHAPE_INVALID")
    if len(canonical(value))>16384: raise ProtocolError("EVENT_TOO_LARGE")
    if value['schema']!='capy.developer-link-event/v0' or not _int(value['sequence'],1,2**53): raise ProtocolError("EVENT_SCHEMA_INVALID")
    for key,prefix in [('site_id','site'),('handoff_id','hof'),('device_id','dev')]:
        if not _id(value[key],prefix): raise ProtocolError("EVENT_ID_INVALID")
    validate_snapshot(value['snapshot'])
    if value['digest']!=digest({k:v for k,v in value.items() if k!='digest'}): raise ProtocolError("EVENT_DIGEST_INVALID")
    return value
