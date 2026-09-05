"""Independent V1 controls frozen before reading importer implementation.

Only B and C are positive handoffs. Synthetic approvals below authorize negative
parser probes only. Local-process controls do not qualify Linux execution.
"""
from __future__ import annotations

import copy
from concurrent.futures import ThreadPoolExecutor
import hashlib
import io
import json
from pathlib import Path
import shutil
import sqlite3
import subprocess
import tempfile
import unittest
from unittest.mock import patch
import zipfile

from capy_outcome_runtime import release_import as api

CAMPAIGN = Path(__file__).resolve().parents[1] / 'campaigns/accepted_release_import_preview_v0'
INPUTS = CAMPAIGN / 'inputs'
PINNED = {
    'B_verified_mean': ('06aa352d7acc659a701525335109ae9cd1e6caab1480bc6c4658307521e90406', 'c0a1faf7b8f4c7fb036b6c4d28fe709ce8e38348d99302da99375018722c61f5'),
    'C_verified_artifact': ('72f11e6ea927648e1c5dcb26a9b7062d3593850ca11dc362ece21f273f17bff9', '0cfa35a07f5333a34ab0baf132d2e72af23dde03a68e1e3189e9782c5a38930a'),
}

def digest(data):
    return hashlib.sha256(data).hexdigest()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False, allow_nan=False).encode()


def frozen_document(name):
    candidate = (INPUTS / name / 'candidate.capyrc').read_bytes()
    document = (INPUTS / name / 'document.json').read_bytes()
    assert (digest(candidate), digest(document)) == PINNED[name], 'frozen positive input drift'
    return json.loads(document)


def counts(root):
    """Observe effective stored state without constructing/mutating a store."""
    totals = dict(capability_versions=0, bindings=0, invocations=0, accepted_imports=0)
    for database in root.rglob('control.sqlite3'):
        with sqlite3.connect(f'file:{database}?mode=ro', uri=True) as db:
            existing = {row[0] for row in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
            for table in totals:
                if table in existing:
                    totals[table] += db.execute(f'SELECT COUNT(*) FROM {table}').fetchone()[0]
    return totals


def rewrite_zip(data, name, replacement=None, extra=None):
    output = io.BytesIO()
    with zipfile.ZipFile(io.BytesIO(data)) as source, zipfile.ZipFile(output, 'w') as target:
        for info in source.infolist():
            target.writestr(info, replacement if info.filename == name else source.read(info))
        if extra is not None:
            target.writestr(*extra)
    return output.getvalue()


class IndependentImportControls(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name).resolve()
        self.root = self.base / 'preview'

    def prepared(self, approvals=None):
        api.prepare_preview(self.root, approvals or approvals_for_preview())

    def import_named(self, name='B_verified_mean'):
        return api.import_release(self.root, INPUTS / name / 'candidate.capyrc', INPUTS / name / 'document.json')

    def rejected(self, candidate, document):
        before = counts(self.root)
        with self.assertRaises(Exception) as caught:
            api.import_release(self.root, candidate, document)
        self.assertNotIsInstance(caught.exception, (AssertionError, TypeError, AttributeError, NameError), 'programming errors are not causal rejection')
        self.assertEqual(before, counts(self.root))
        return caught.exception

    def test_exact_positives_import_without_activation_or_commands(self):
        self.prepared()
        with patch.object(subprocess, 'Popen', side_effect=AssertionError('import executed a command')):
            for name in PINNED:
                record = self.import_named(name)
                self.assertEqual('UNBOUND', record['binding_state'])
                self.assertEqual(PINNED[name][0], record['candidate_sha256'])
                self.assertEqual(PINNED[name][1], record['acceptance_sha256'])
                inspected = api.inspect_import(self.root, record['import_id'])
                self.assertEqual(record['import_id'], inspected['import_id'])
        state = counts(self.root)
        self.assertEqual(2, state['capability_versions'])
        self.assertEqual(2, state['accepted_imports'])
        self.assertEqual(0, state['bindings'])
        self.assertEqual(0, state['invocations'])

    def test_cross_pair_and_rejected_total_do_not_install(self):
        self.prepared()
        self.rejected(INPUTS/'B_verified_mean/candidate.capyrc', INPUTS/'C_verified_artifact/document.json')
        self.rejected(INPUTS/'A_verified_total/candidate.capyrc', INPUTS/'A_verified_total/document.json')

    def test_unmarked_and_existing_roots_are_refused_without_database(self):
        self.root.mkdir()
        sentinel = self.root/'owner-data'
        sentinel.write_bytes(b'preserve')
        with self.assertRaises(Exception):
            self.import_named()
        with self.assertRaises(Exception):
            api.prepare_preview(self.root, approvals_for_preview())
        self.assertEqual(b'preserve', sentinel.read_bytes())
        self.assertEqual([], list(self.root.rglob('*.sqlite3')))

    def test_symlink_ancestor_remains_rejected(self):
        from capy_outcome_runtime.model import RuntimeFailure
        actual = self.base/'actual'
        actual.mkdir()
        alias = self.base/'alias'
        alias.symlink_to(actual, target_is_directory=True)
        with self.assertRaises(RuntimeFailure):
            api.prepare_preview(alias/'preview', approvals_for_preview())
        self.assertFalse((actual/'preview').exists())

    def test_repeat_and_simultaneous_imports_have_one_identity(self):
        self.prepared()
        with ThreadPoolExecutor(max_workers=4) as pool:
            records = list(pool.map(lambda _: self.import_named(), range(4)))
        self.assertEqual(1, len({r['import_id'] for r in records}))
        self.assertEqual(1, len({r['version_digest'] for r in records}))
        self.assertEqual(records[0]['import_id'], self.import_named()['import_id'])
        self.assertEqual({'capability_versions':1,'accepted_imports':1,'bindings':0,'invocations':0}, counts(self.root))

    def test_caller_bytes_can_disappear_after_import(self):
        self.prepared()
        copied = self.base/'transport'
        shutil.copytree(INPUTS/'B_verified_mean', copied)
        record = api.import_release(self.root, copied/'candidate.capyrc', copied/'document.json')
        shutil.rmtree(copied)
        self.assertEqual(record['import_id'], api.inspect_import(self.root, record['import_id'])['import_id'])

    def test_corrupt_committed_candidate_is_not_hidden_by_database(self):
        self.prepared()
        record = self.import_named()
        expected = PINNED['B_verified_mean'][0]
        copies = [p for p in (self.root/'runtime').rglob('*') if p.is_file() and digest(p.read_bytes()) == expected]
        self.assertTrue(copies, 'exact candidate bytes must be preserved')
        for p in copies:
            p.chmod(0o600)
            p.write_bytes(b'corrupt committed candidate')
        with self.assertRaises(Exception):
            api.inspect_import(self.root, record['import_id'])
        self.rejected(INPUTS/'B_verified_mean/candidate.capyrc', INPUTS/'B_verified_mean/document.json')

    def test_valid_receipt_cannot_choose_another_approval(self):
        approvals = approvals_for_preview()
        approvals['entries'] = []
        from capy_outcome_runtime.model import RuntimeFailure
        try:
            self.prepared(approvals)
        except RuntimeFailure:
            self.assertEqual(0, counts(self.root)['capability_versions'])
            return
        self.rejected(INPUTS/'B_verified_mean/candidate.capyrc', INPUTS/'B_verified_mean/document.json')


def approvals_for_preview():
    entries = []
    for name, (candidate_hash, document_hash) in PINNED.items():
        document = frozen_document(name)
        entries.append(dict(candidate_sha256=candidate_hash, acceptance_sha256=document_hash,
            identity=copy.deepcopy(document['identity']), source=copy.deepcopy(document['source']),
            application=copy.deepcopy(document['application']), toolchain=copy.deepcopy(document['toolchain']),
            expected_cases={case['case_id']:copy.deepcopy(case['expected']) for case in document['cases']}))
    return dict(schema='capy.runtime-import-approval/v0', preview_id='independent-controls-v1', entries=entries)


class IndependentDeepValidationControls(unittest.TestCase):
    def setUp(self):
        from capy_outcome_runtime.release_validation import validate_release
        self.validate = validate_release
        self.candidate = (INPUTS/'B_verified_mean/candidate.capyrc').read_bytes()
        self.document = frozen_document('B_verified_mean')
        self.approvals = approvals_for_preview()

    def reject(self, candidate=None, document=None, approvals=None):
        from capy_outcome_runtime.model import RuntimeFailure
        with self.assertRaises(RuntimeFailure) as caught:
            self.validate(candidate if candidate is not None else self.candidate,
                document if document is not None else canonical(self.document),
                approvals if approvals is not None else self.approvals)
        self.assertTrue(caught.exception.code)
        return caught.exception.code

    def negative_document(self, value):
        """Change ONLY synthetic negative approval hash to reach receipt checks."""
        document = canonical(value)
        approval = copy.deepcopy(self.approvals)
        approval['entries'][0]['acceptance_sha256'] = digest(document)
        return self.reject(document=document, approvals=approval)

    def test_receipt_status_schema_cases_scan_cleanup_and_nonclaims(self):
        mutations = [
            ('status', lambda d:d.update(status='REJECTED')),
            ('classification', lambda d:d.update(classification='REJECTED')),
            ('schema', lambda d:d.update(schema='capy.independent-application-acceptance/v99')),
            ('empty_cases', lambda d:d.update(cases=[])),
            ('missing_cases', lambda d:d.pop('cases')),
            ('unmatched', lambda d:d['cases'][0].update(matched=False)),
            ('case_classification', lambda d:d['cases'][0].update(classification='CASE_MISMATCH')),
            ('expected_observed', lambda d:d['cases'][0]['observed'].update(result_sha256='0'*64)),
            ('duplicate_cases', lambda d:d['cases'].append(copy.deepcopy(d['cases'][0]))),
            ('missing_case', lambda d:d['cases'].pop()),
            ('failed_scan', lambda d:d['secret_scan'].update(status='FAILED')),
            ('scan_finding', lambda d:d['secret_scan'].update(findings=['synthetic finding'])),
            ('cleanup', lambda d:d['cleanup'].update(status='UNCONFIRMED')),
            ('nonclaims', lambda d:d.update(non_claims=[])),
            ('unknown_key', lambda d:d.update(unapproved_authority=True)),
        ]
        for name, change in mutations:
            with self.subTest(name=name):
                value = copy.deepcopy(self.document)
                change(value)
                self.negative_document(value)

    def test_deep_identity_mismatches(self):
        paths = [('identity','acceptor','version'),('identity','acceptor','implementation_commit'),
            ('identity','acceptor','implementation_tree'),('identity','profile_bundle_sha256'),
            ('identity','application_id'),('source','commit'),('source','tree'),
            ('application','descriptor_sha256'),('application','interaction_sha256'),
            ('toolchain','wheel_sha256')]
        for path in paths:
            with self.subTest(path=path):
                value=copy.deepcopy(self.document)
                target=value
                for key in path[:-1]:
                    target=target[key]
                target[path[-1]]='0'*64
                self.negative_document(value)

    def test_strict_json_vectors_reach_parser(self):
        raw=canonical(self.document)
        vectors=[raw[:-1]+b',"status":"ACCEPTED"}',raw[:-1]+b',"unexpected":NaN}',
                 raw[:-1]+b',"unexpected":Infinity}',b'\xff'+raw, raw+b' {}',b'[]']
        for vector in vectors:
            with self.subTest(digest=digest(vector)):
                approvals=copy.deepcopy(self.approvals)
                approvals['entries'][0]['acceptance_sha256']=digest(vector)
                self.reject(document=vector, approvals=approvals)

    def test_outer_zip_member_and_path_controls(self):
        names=['../escape','/absolute','C:/drive','a\\b','a:b','//server/share','application/../escape',
               'APPLICATION/interaction.json','application/interaction.json','unexpected']
        for name in names:
            with self.subTest(name=name):
                data=rewrite_zip(self.candidate, None, extra=(name,b'negative'))
                approvals=copy.deepcopy(self.approvals)
                approvals['entries'][0]['candidate_sha256']=digest(data)
                self.reject(candidate=data,approvals=approvals)
        self.reject(candidate=self.candidate[:-30])

    def test_carried_members_cannot_be_tampered(self):
        with zipfile.ZipFile(io.BytesIO(self.candidate)) as archive:
            names=archive.namelist()
        for name in names:
            with self.subTest(member=name):
                data=rewrite_zip(self.candidate,name,b'negative tamper')
                approvals=copy.deepcopy(self.approvals)
                approvals['entries'][0]['candidate_sha256']=digest(data)
                self.reject(candidate=data,approvals=approvals)

    def test_resealed_pair_cannot_copy_acceptor_authority(self):
        # Synthetic forgery only, never an accepted positive application. Reproduce
        # the accepted Developer V1 identity projection, not the entire manifest.
        # Oracle source: capy-developer@9f0d0334 release_candidate.py:247-270.
        def candidate_identity(manifest):
            app = manifest['application']
            interaction = app['interaction']
            toolchain = manifest['toolchain']
            return dict(schema=manifest['schema'],project_id=manifest['project']['project_id'],
                application_id=app['id'],source=manifest['source'],
                application_archive_sha256=app['archive']['sha256'],
                application_descriptor_sha256=app['descriptor_sha256'],
                interaction=dict(schema=interaction['schema'],source_sha256=interaction['source_sha256'],
                    canonical_sha256=interaction['sha256'],operation_id=interaction['operation_id']),
                verification_receipt_sha256=manifest['verification']['receipt']['sha256'],
                toolchain=dict(release_binding_commit=toolchain['release_binding_commit'],
                    authoring_bundle_sha256=toolchain['authoring_bundle']['sha256'],
                    wheel_sha256=toolchain['wheel_sha256'],interaction_contract=toolchain['interaction_contract']))

        with zipfile.ZipFile(io.BytesIO(self.candidate)) as archive:
            manifest=json.loads(archive.read('RELEASE-CANDIDATE.json'))
            verification=json.loads(archive.read('evidence/verification.json'))
        self.assertEqual(manifest['identity_sha256'],digest(canonical(candidate_identity(manifest))))
        approvals_before=canonical(self.approvals)
        manifest['verified_at']=verification['verified_at']='2026-09-05T00:00:00.000000Z'
        verification_bytes=canonical(verification)
        manifest['verification']['receipt'].update(sha256=digest(verification_bytes),size_bytes=len(verification_bytes))
        manifest_hash=digest(canonical(candidate_identity(manifest)))
        manifest.update(identity_sha256=manifest_hash,release_candidate_id='rc_'+manifest_hash[:32])
        candidate=rewrite_zip(self.candidate,'evidence/verification.json',verification_bytes)
        candidate=rewrite_zip(candidate,'RELEASE-CANDIDATE.json',canonical(manifest))
        receipt=copy.deepcopy(self.document)
        receipt['identity'].update(candidate_bundle_sha256=digest(candidate),candidate_release_candidate_id=manifest['release_candidate_id'])
        identity_hash=digest(canonical(receipt['identity']))
        receipt.update(identity_sha256=identity_hash,acceptance_id='acc_'+identity_hash[:32])
        self.assertEqual(self.document['identity']['acceptor'],receipt['identity']['acceptor'])
        self.assertNotEqual(PINNED['B_verified_mean'][0],digest(candidate))
        self.assertNotEqual(PINNED['B_verified_mean'][1],digest(canonical(receipt)))
        # Exact causal code proves the complete pair passed structural checks and
        # reached the independent operator-approval boundary with original anchors.
        self.assertEqual('RELEASE_OPERATOR_APPROVAL_REQUIRED',
            self.reject(candidate=candidate,document=canonical(receipt)))
        self.assertEqual(approvals_before,canonical(self.approvals))


class IndependentInterruptionControls(unittest.TestCase):
    def test_before_and_after_visibility_interruption_retries_same_intent(self):
        for stage in ('attempt_started','files_staged','files_published','committed'):
            with self.subTest(stage=stage), tempfile.TemporaryDirectory() as directory:
                root=Path(directory).resolve()/'preview'
                api.prepare_preview(root,approvals_for_preview())
                def crash(current):
                    if current==stage:
                        raise KeyboardInterrupt('synthetic abrupt interruption')
                with patch.object(api,'_checkpoint',side_effect=crash):
                    with self.assertRaises(KeyboardInterrupt):
                        api.import_release(root,INPUTS/'B_verified_mean/candidate.capyrc',INPUTS/'B_verified_mean/document.json')
                interrupted=counts(root)
                self.assertEqual(1 if stage=='committed' else 0,interrupted['capability_versions'])
                self.assertEqual(0,interrupted['bindings'])
                self.assertEqual(0,interrupted['invocations'])
                record=api.import_release(root,INPUTS/'B_verified_mean/candidate.capyrc',INPUTS/'B_verified_mean/document.json')
                self.assertEqual(record['import_id'],api.inspect_import(root,record['import_id'])['import_id'])
                self.assertEqual(1,counts(root)['accepted_imports'])
                self.assertEqual(1,counts(root)['capability_versions'])


if __name__=='__main__':
    unittest.main()
