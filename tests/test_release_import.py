import copy
import hashlib
import json
from pathlib import Path
import pytest
from capy_outcome_runtime.release_import import prepare_preview,import_release,inspect_import,lookup_import,imported_environment
from capy_outcome_runtime.release_validation import validate_release
from capy_outcome_runtime.model import RuntimeFailure
from capy_outcome_runtime.store import RuntimeStore,canonical_json

INPUTS=Path(__file__).resolve().parents[1]/'campaigns/accepted_release_import_preview_v0/inputs'
PINS={
'B_verified_mean':('06aa352d7acc659a701525335109ae9cd1e6caab1480bc6c4658307521e90406','c0a1faf7b8f4c7fb036b6c4d28fe709ce8e38348d99302da99375018722c61f5'),
'C_verified_artifact':('72f11e6ea927648e1c5dcb26a9b7062d3593850ca11dc362ece21f273f17bff9','0cfa35a07f5333a34ab0baf132d2e72af23dde03a68e1e3189e9782c5a38930a')}

def approval():
    entries=[]
    for name,pins in PINS.items():
        c=(INPUTS/name/'candidate.capyrc').read_bytes();r=(INPUTS/name/'document.json').read_bytes()
        assert (hashlib.sha256(c).hexdigest(),hashlib.sha256(r).hexdigest())==pins
        d=json.loads(r)
        entries.append({'candidate_sha256':pins[0],'acceptance_sha256':pins[1],**{k:d[k] for k in ('identity','source','application','toolchain')},'expected_cases':{x['case_id']:x['expected'] for x in d['cases']}})
    return {'schema':'capy.runtime-import-approval/v0','preview_id':'synthetic-import-test','entries':entries}

@pytest.mark.parametrize('name',PINS)
def test_import_unbound_replay_integrity(tmp_path,name):
    root=tmp_path/'preview';prepare_preview(root,approval());src=INPUTS/name
    record=import_release(root,src/'candidate.capyrc',src/'document.json')
    assert record['binding_state']=='UNBOUND'
    assert import_release(root,src/'candidate.capyrc',src/'document.json')==record
    store=RuntimeStore(root/'runtime')
    assert lookup_import(store,record['application_id'],record['version_digest'])==record
    assert imported_environment(store,record).is_dir()
    with store.connect() as db: assert db.execute('SELECT COUNT(*) FROM bindings').fetchone()[0]==0
    app=store.scripts/record['version_digest']/'capability.toml';app.chmod(0o600);app.write_bytes(b'changed')
    with pytest.raises(RuntimeFailure): inspect_import(root,record['import_id'])

@pytest.mark.parametrize('field,value',[('status','REJECTED'),('cleanup',{'status':'FAILED'}),('secret_scan',{'status':'PASSED','findings':['secret']})])
def test_deep_receipt_validation_before_approval(field,value):
    src=INPUTS/'B_verified_mean';d=json.loads((src/'document.json').read_bytes());d[field]=value
    with pytest.raises(RuntimeFailure) as error: validate_release((src/'candidate.capyrc').read_bytes(),canonical_json(d),approval())
    assert error.value.code!='RELEASE_OPERATOR_APPROVAL_REQUIRED'


def test_unapproved_and_duplicate_json():
    src=INPUTS/'B_verified_mean';a=approval();a['entries']=[]
    with pytest.raises(RuntimeFailure,match='RELEASE_OPERATOR_APPROVAL_REQUIRED'): validate_release((src/'candidate.capyrc').read_bytes(),(src/'document.json').read_bytes(),a)
    with pytest.raises(RuntimeFailure): validate_release((src/'candidate.capyrc').read_bytes(),b'{"schema":1,"schema":2}',approval())


def test_recovery_published_before_commit(tmp_path,monkeypatch):
    from capy_outcome_runtime import release_import as mod
    root=tmp_path/'preview';prepare_preview(root,approval());src=INPUTS/'B_verified_mean'
    def crash(stage):
        if stage=='files_published': raise KeyboardInterrupt()
    monkeypatch.setattr(mod,'_checkpoint',crash)
    with pytest.raises(KeyboardInterrupt): import_release(root,src/'candidate.capyrc',src/'document.json')
    with RuntimeStore(root/'runtime').connect() as db: assert db.execute('SELECT COUNT(*) FROM capability_versions').fetchone()[0]==0
    monkeypatch.setattr(mod,'_checkpoint',lambda stage:None)
    record=import_release(root,src/'candidate.capyrc',src/'document.json')
    assert inspect_import(root,record['import_id'])==record


def test_preview_envelope_identity_and_permissions(tmp_path):
    import shutil
    root=tmp_path/'preview'; marker=prepare_preview(root,approval())
    assert marker['preview_root']==str(root)
    assert root.stat().st_mode & 0o022 == 0
    assert (root/'IMPORT-APPROVALS.json').stat().st_mode & 0o222 == 0
    assert (root/'runtime'/'control.sqlite3').is_file()
    copied=tmp_path/'copied';shutil.copytree(root,copied)
    src=INPUTS/'B_verified_mean'
    with pytest.raises(RuntimeFailure,match='RELEASE_PREVIEW_REQUIRED'):
        import_release(copied,src/'candidate.capyrc',src/'document.json')


def test_symlink_ancestor_rejected_before_preview_write(tmp_path):
    real=tmp_path/'real';real.mkdir();alias=tmp_path/'alias';alias.symlink_to(real,target_is_directory=True)
    with pytest.raises(RuntimeFailure): prepare_preview(alias/'preview',approval())
    assert not (real/'preview').exists()


@pytest.mark.parametrize('internal',['scripts/sha256','import-environments','control.sqlite3'])
def test_symlink_store_destination_rejected_before_constructor(tmp_path,internal):
    import shutil
    root=tmp_path/'preview';prepare_preview(root,approval())
    path=root/'runtime'/internal
    outside=tmp_path/'outside'
    if internal=='control.sqlite3':
        outside.write_bytes(b'not-a-runtime-database');path.unlink()
    else:
        outside.mkdir()
        if path.exists(): shutil.rmtree(path)
    outside.chmod(0o700)
    path.symlink_to(outside,target_is_directory=outside.is_dir())
    before=outside.stat().st_mode
    src=INPUTS/'B_verified_mean'
    with pytest.raises(RuntimeFailure): import_release(root,src/'candidate.capyrc',src/'document.json')
    assert outside.stat().st_mode==before
    if outside.is_dir(): assert not list(outside.iterdir())
    else: assert outside.read_bytes()==b'not-a-runtime-database'


def test_projection_compatibility_fails_before_visibility(tmp_path,monkeypatch):
    from capy_outcome_runtime import portable_interfaces
    root=tmp_path/'preview';prepare_preview(root,approval());src=INPUTS/'B_verified_mean'
    def unsupported(*args): raise RuntimeFailure('PORTABLE_INTERACTION_INVALID')
    monkeypatch.setattr(portable_interfaces,'project_portable',unsupported)
    with pytest.raises(RuntimeFailure,match='PORTABLE_INTERACTION_INVALID'):
        import_release(root,src/'candidate.capyrc',src/'document.json')
    with RuntimeStore(root/'runtime').connect() as db:
        assert db.execute('SELECT COUNT(*) FROM capability_versions').fetchone()[0]==0
        assert db.execute('SELECT COUNT(*) FROM accepted_imports').fetchone()[0]==0


def test_missing_member_and_malicious_record_digest_fail_closed(tmp_path):
    root=tmp_path/'preview';prepare_preview(root,approval());src=INPUTS/'B_verified_mean'
    record=import_release(root,src/'candidate.capyrc',src/'document.json')
    folder=root/'runtime'/'accepted-releases'/record['import_id']
    receipt=folder/'acceptance.json';folder.chmod(0o755);saved=receipt.read_bytes();receipt.unlink()
    with pytest.raises(RuntimeFailure): inspect_import(root,record['import_id'])
    receipt.write_bytes(saved)
    record['version_digest']='../../outside'
    record_path=folder/'record.json';record_path.chmod(0o644);record_path.write_bytes(canonical_json(record))
    with RuntimeStore(root/'runtime').connect() as db:
        db.execute('UPDATE accepted_imports SET record_json=? WHERE import_id=?',(canonical_json(record).decode(),record['import_id']))
    with pytest.raises(RuntimeFailure): inspect_import(root,record['import_id'])
