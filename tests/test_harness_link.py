import secrets
import json

import pytest

from capy_outcome_runtime.developer_link import LinkError
from capy_outcome_runtime.harness_link import HarnessLink
from test_developer_link import env, paired, SITE


def client(env):
    secret, _, device = paired(env)
    harness = HarnessLink(env.link)
    harness.approve(env.actor, device)
    value = dict(site_id=SITE, device_id=device, client_id='cli_' + secrets.token_hex(16),
                 label='Muse Code', version='1.0.3', transport='JSON_CLI')
    challenge = harness.register(value, secret, 'test')
    return harness, secret, value, challenge


def check(harness, secret, value, challenge):
    return harness.check({k:value[k] for k in ('site_id','device_id','client_id')} | {'nonce':challenge['nonce']}, secret, 'test')


def begin(harness, secret, value, intent=None, parent=None):
    return harness.begin({k:value[k] for k in ('site_id','device_id','client_id')} |
                         {'intent_id':intent or secrets.token_hex(16), 'parent_handoff_id':parent}, secret, 'test')


def test_old_pair_has_no_new_scope_and_old_handoff_still_works(env):
    secret, _, device = paired(env)
    harness = HarnessLink(env.link)
    assert not harness.status(dict(site_id=SITE, device_id=device), secret, 'test')['approved']
    with pytest.raises(LinkError, match='LINKED_WORK_APPROVAL_REQUIRED'):
        harness.register(dict(site_id=SITE, device_id=device, client_id='cli_'+'a'*32,
                              label='Codex', version='0.153.4', transport='MCP_STDIO'), secret, 'test')
    assert env.link.create(env.actor, device, secrets.token_hex(16))['intent'] == 'NEW'


def test_configured_check_nonce_replay_and_idle_are_truthful(env):
    harness, secret, value, challenge = client(env)
    status = harness.status({k:value[k] for k in ('site_id','device_id')}, secret, 'test')
    assert status['clients'][0]['last_checked'] is None
    with pytest.raises(LinkError, match='CLIENT_CHECK_REQUIRED'):
        begin(harness, secret, value)
    checked = check(harness, secret, value, challenge)
    assert checked['state'] == 'Ready through CLI'
    env.now[0] += 100
    replay = check(harness, secret, value, challenge)
    assert replay['last_checked'] == checked['last_checked']
    assert replay['state'] == 'Idle'


def test_request_replay_is_one_handoff_and_mismatched_client_is_denied(env):
    harness, secret, value, challenge = client(env)
    check(harness, secret, value, challenge)
    intent = secrets.token_hex(16)
    first = begin(harness, secret, value, intent)
    assert begin(harness, secret, value, intent) == first
    second = {**value, 'client_id':'cli_'+secrets.token_hex(16), 'label':'Codex'}
    check(harness, secret, second, harness.register(second, secret, 'test'))
    with pytest.raises(LinkError, match='IDEMPOTENCY_CONFLICT'):
        begin(harness, secret, second, intent)
    with env.link.db() as db:
        assert db.execute('SELECT count(*) FROM requests').fetchone()[0] == 1


def test_revocation_and_current_membership_block_all_new_operations(env):
    harness, secret, value, challenge = client(env)
    check(harness, secret, value, challenge)
    env.link.revoke(env.actor, value['device_id'])
    with pytest.raises(LinkError):
        begin(harness, secret, value)
    assert harness.listing(env.actor)[0]['state'] == 'Revoked'


def test_wrong_secret_site_nonce_and_extra_fields_fail_closed(env):
    harness, secret, value, challenge = client(env)
    with pytest.raises(LinkError):
        check(harness, 'f'*64, value, challenge)
    with pytest.raises(LinkError):
        check(harness, secret, {**value,'site_id':'site_'+'b'*32}, challenge)
    with pytest.raises(LinkError):
        check(harness, secret, value, {**challenge,'nonce':'a'*64})
    with pytest.raises(LinkError, match='INVALID_FIELDS'):
        harness.register({**value, 'model_identity_verified':True}, secret, 'test')


def test_active_writer_is_not_taken_over(env):
    harness, secret, value, challenge = client(env)
    check(harness, secret, value, challenge)
    first = begin(harness, secret, value)
    with pytest.raises(LinkError, match='ACTIVE_WRITER_HANDOVER_REQUIRED'):
        begin(harness, secret, value, parent=first['handoff_id'])


def test_existing_project_selection_is_explicit_and_bound_to_retry(env):
    harness,secret,value,challenge=client(env)
    check(harness,secret,value,challenge)
    payload={k:value[k] for k in ('site_id','device_id','client_id')} | {
        'intent_id':secrets.token_hex(16),'parent_handoff_id':None,'project_id':'prj_'+'a'*32}
    request=harness.begin(payload,secret,'test')
    assert request['schema']=='capy.developer-link-request/v1'
    assert request['intent']=='EXISTING' and request['project_id']==payload['project_id']
    assert harness.begin(payload,secret,'test')==request
    with pytest.raises(LinkError,match='IDEMPOTENCY_CONFLICT'):
        harness.begin({**payload,'project_id':'prj_'+'b'*32},secret,'test')
    with pytest.raises(LinkError):
        harness.begin({**payload,'parent_handoff_id':request['handoff_id']},secret,'test')
    with env.link.db() as db:
        assert db.execute('SELECT count(*) FROM requests').fetchone()[0]==1
    from test_developer_link import claim,event
    claim(env,secret,request)
    with pytest.raises(LinkError,match='PROJECT_ASSOCIATION_MISMATCH'):
        env.link.events(request['handoff_id'],{'events':[event(request)]},secret,'test')
    env.link.events(request['handoff_id'],{'events':[event(request,project_id=payload['project_id'])]},secret,'test')


def test_explicit_same_client_reopen_preserves_handoff_and_current_authority(env):
    harness, secret, value, challenge = client(env)
    check(harness,secret,value,challenge)
    first=begin(harness,secret,value)
    payload={k:value[k] for k in ('site_id','device_id','client_id')} | {
        'handoff_id':first['handoff_id'],'previous_editor_stopped':True}
    assert harness.reopen(payload,secret,'test')==first
    assert harness.reopen(payload,secret,'test')==first
    for confirmation in (False,1,'true',None):
        with pytest.raises(LinkError,match='ACTIVE_WRITER_HANDOVER_REQUIRED'):
            harness.reopen({**payload,'previous_editor_stopped':confirmation},secret,'test')
    other={**value,'client_id':'cli_'+secrets.token_hex(16),'label':'Codex'}
    check(harness,secret,other,harness.register(other,secret,'test'))
    with pytest.raises(LinkError,match='WORK_CLIENT_ASSOCIATION_MISMATCH'):
        harness.reopen({**payload,'client_id':other['client_id']},secret,'test')
    with env.link.db() as db:
        assert db.execute('SELECT count(*) FROM requests').fetchone()[0]==1
        assert db.execute('SELECT count(*) FROM harness_intents').fetchone()[0]==1
        db.execute('UPDATE requests SET snapshot=? WHERE id=?',
            (json.dumps({'terminal':'COMPLETED'}),first['handoff_id']))
    with pytest.raises(LinkError,match='WORK_SESSION_TERMINAL'):
        harness.reopen(payload,secret,'test')
    env.link.revoke(env.actor,value['device_id'])
    with pytest.raises(LinkError):harness.reopen(payload,secret,'test')


def test_workspace_authority_is_rechecked(env):
    harness, secret, value, challenge = client(env)
    check(harness, secret, value, challenge)
    with env.runtime.connect() as db:
        db.execute("UPDATE access_memberships SET status='revoked' WHERE id=?", (env.actor.membership_id,))
    with pytest.raises(LinkError):
        begin(harness, secret, value)


def test_forged_display_identity_never_grants_scope_or_checked_authority(env):
    secret, _, device = paired(env)
    harness = HarnessLink(env.link)
    forged = dict(site_id=SITE, device_id=device, client_id='cli_'+secrets.token_hex(16),
                  label='Codex', version='999.0.0', transport='MCP_STDIO')
    with pytest.raises(LinkError, match='INVALID_VALUE'):
        harness.register({**forged, 'label':'Codex administrator verified model'}, secret, 'test')
    with pytest.raises(LinkError, match='LINKED_WORK_APPROVAL_REQUIRED'):
        harness.register(forged, secret, 'test')
    harness.approve(env.actor, device)
    challenge = harness.register(forged, secret, 'test')
    with pytest.raises(LinkError, match='CLIENT_CHECK_REQUIRED'):
        begin(harness, secret, forged)
    check(harness, secret, forged, challenge)
    env.link.revoke(env.actor, device)
    with pytest.raises(LinkError):
        begin(harness, secret, forged)
    with env.link.db() as db:
        assert db.execute('SELECT count(*) FROM requests').fetchone()[0] == 0
