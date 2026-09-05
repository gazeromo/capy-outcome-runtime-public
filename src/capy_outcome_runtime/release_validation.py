"""Non-executing validation of independently approved portable releases."""
from __future__ import annotations

import hashlib
from ._release_format import codec
from ._release_format.candidate import read_candidate
from ._release_format.errors import AcceptorError
from ._release_format.projection import application_projection
from ._release_format.constants import NON_GOALS, OUTER_MAX_BYTES
from .model import RuntimeFailure


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def fail(code='RELEASE_IMPORT_INTEGRITY_FAILED'):
    raise RuntimeFailure(code)


def validate_release(candidate_bytes: bytes, acceptance_bytes: bytes, approvals: dict):
    """Verify complete formats before applying the independent operator anchor.

    An entry contains candidate_sha256, acceptance_sha256, identity, source,
    application, toolchain and expected_cases (case_id -> expected projection).
    Exact transport approval supplements, never replaces, structural checks.
    """
    try:
        if len(candidate_bytes) > OUTER_MAX_BYTES or len(acceptance_bytes) > 2_000_000:
            fail()
        candidate = read_candidate(candidate_bytes)
        doc = codec.check_canonical_json_bytes(acceptance_bytes, what='acceptance')
        required = {'schema','acceptance_id','identity_sha256','identity','status','classification',
                    'source','application','toolchain','cases','secret_scan','cleanup','non_claims'}
        if not isinstance(doc, dict) or set(doc) != required:
            fail()
        if doc['schema'] != 'capy.independent-application-acceptance/v0' or doc['status'] != 'ACCEPTED' or doc['classification'] != 'ACCEPTED':
            fail('RELEASE_ACCEPTANCE_REQUIRED')
        identity = doc['identity']
        if set(identity) != {'candidate_bundle_sha256','candidate_release_candidate_id','profile_bundle_sha256','profile_id','application_id','acceptor'}:
            fail()
        for key in ('candidate_bundle_sha256','profile_bundle_sha256'):
            if not isinstance(identity[key],str) or len(identity[key]) != 64 or any(c not in '0123456789abcdef' for c in identity[key]): fail()
        if identity['acceptor'] != {'contract':'capy.independent-application-acceptance/v0','implementation_commit':'05420906f3966a4c73a2261b1ce48d0a48a4d60c','implementation_tree':'dc383e96373ed109b5a8560ee8df6d76be8604b5','version':'0.1.0'}: fail('RELEASE_ACCEPTOR_UNTRUSTED')
        ih = digest(codec.canonical_bytes(identity))
        if doc['identity_sha256'] != ih or doc['acceptance_id'] != 'acc_'+ih[:32]: fail()
        m = candidate.manifest
        if identity['candidate_bundle_sha256'] != candidate.bundle_sha256 or identity['candidate_release_candidate_id'] != m['release_candidate_id'] or identity['application_id'] != m['application']['id']: fail()
        if doc['source'] != m['source'] or doc['application'] != application_projection(candidate) or doc['toolchain'] != m['toolchain']: fail()
        if doc['cleanup'] != {'status':'CONFIRMED'} or doc['secret_scan'] != {'status':'PASSED','findings':[]} or doc['non_claims'] != list(NON_GOALS): fail()
        cases=doc['cases']
        if not isinstance(cases,list) or not cases: fail()
        case_ids=set()
        for c in cases:
            if set(c) != {'case_id','matched','classification','expected','observed'} or not isinstance(c['case_id'],str) or c['case_id'] in case_ids: fail()
            case_ids.add(c['case_id'])
            if c['matched'] is not True or c['classification'] != 'CASE_MATCHED' or codec.canonical_bytes(c['expected']) != codec.canonical_bytes(c['observed']): fail()
            e=c['expected']
            if set(e) != {'status','result_sha256','artifacts','failure_code'} or e['status'] not in ('ok','failed') or not isinstance(e['artifacts'],list): fail()
            if e['status']=='ok' and (e['failure_code'] is not None or not isinstance(e['result_sha256'],str) or len(e['result_sha256'])!=64): fail()
            if e['status']=='failed' and (e['result_sha256'] is not None or not isinstance(e['failure_code'],str) or e['artifacts']): fail()
            names=set()
            for a in e['artifacts']:
                if set(a) != {'filename','sha256','size_bytes'} or a['filename'] in names or type(a['size_bytes']) is not int or a['size_bytes']<0: fail()
                codec.check_inner_name_safe(a['filename']); names.add(a['filename'])
                if not isinstance(a['sha256'],str) or len(a['sha256'])!=64: fail()
        if not isinstance(approvals,dict) or set(approvals) != {'schema','preview_id','entries'} or approvals['schema'] != 'capy.runtime-import-approval/v0' or not isinstance(approvals['preview_id'],str) or not approvals['preview_id']: fail('RELEASE_OPERATOR_APPROVAL_REQUIRED')
        matched=[e for e in approvals['entries'] if e.get('candidate_sha256')==digest(candidate_bytes) and e.get('acceptance_sha256')==digest(acceptance_bytes)]
        if len(matched)!=1: fail('RELEASE_OPERATOR_APPROVAL_REQUIRED')
        entry=matched[0]
        if set(entry) != {'candidate_sha256','acceptance_sha256','identity','source','application','toolchain','expected_cases'}: fail('RELEASE_OPERATOR_APPROVAL_REQUIRED')
        for key in ('identity','source','application','toolchain'):
            if codec.canonical_bytes(entry[key]) != codec.canonical_bytes(doc[key]): fail('RELEASE_OPERATOR_APPROVAL_MISMATCH')
        if codec.canonical_bytes(entry['expected_cases']) != codec.canonical_bytes({c['case_id']:c['expected'] for c in cases}): fail('RELEASE_OPERATOR_APPROVAL_MISMATCH')
        return candidate, doc
    except RuntimeFailure:
        raise
    except AcceptorError as exc:
        raise RuntimeFailure(exc.code) from exc
    except (ValueError,TypeError,KeyError,AttributeError,UnicodeError) as exc:
        raise RuntimeFailure('RELEASE_IMPORT_INTEGRITY_FAILED') from exc
