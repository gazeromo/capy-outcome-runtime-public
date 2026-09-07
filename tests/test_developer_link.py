"""Synthetic Access + isolated Developer Link authority and HTTP controls."""
import hashlib
import http.client
import json
import secrets
import threading
from concurrent.futures import ThreadPoolExecutor
from types import SimpleNamespace

import pytest
from capy_outcome_runtime import AccessStore, RuntimeStore, ChatStore
from capy_outcome_runtime import _developer_link_protocol as wire
from capy_outcome_runtime.developer_link import DeveloperLink, LinkError
from capy_outcome_runtime.web import Handler, ProductServer

SITE = 'site_' + 'a'*32
ORIGIN = 'https://capy.test'

@pytest.fixture
def env(tmp_path):
    runtime = RuntimeStore(tmp_path/'runtime')
    access = AccessStore(runtime)
    owner = access.redeem_claim(access.create_bootstrap_claim()['token'], display_name='Synthetic Owner')
    now = [1800000000]
    link = DeveloperLink(tmp_path/'developer.sqlite', access, SITE, ORIGIN, clock=lambda:now[0])
    return SimpleNamespace(runtime=runtime, access=access, actor=owner.actor, credential=owner.credential, link=link, now=now)


def paired(env):
    secret = secrets.token_hex(32)
    pair = env.link.start_pair(dict(site_id=SITE, installation_id=secrets.token_hex(16), secret_sha256=hashlib.sha256(secret.encode()).hexdigest(), label='Laptop <script>'), 'test')
    dev = env.link.approve(env.actor, pair['pair_id'], pair['confirmation_code'])
    return secret, pair, dev


def request(env):
    secret, pair, dev = paired(env)
    req = env.link.create(env.actor, dev, secrets.token_hex(16))
    return secret, dev, req


def claim(env, secret, req):
    return env.link.claim(req['handoff_id'], {k:req[k] for k in ('site_id','device_id','launch_generation')}, secret, 'test')


def event(req, sequence=1, **changes):
    snap = {k:None for k in wire.SNAPSHOT_FIELDS}
    snap.update(milestone='HARNESS_ATTACHED', project_id='prj_'+'1'*32, session_id='ses_'+'2'*32, source_commit='3'*40, dirty=False, source_fresh=False)
    snap.update(changes)
    value = dict(schema='capy.developer-link-event/v0', site_id=SITE, handoff_id=req['handoff_id'], device_id=req['device_id'], sequence=sequence, snapshot=snap)
    value['digest'] = wire.digest(value)
    return value


def test_pair_requires_code_proof_expiry_and_stores_no_secret(env):
    secret, pair, dev = paired(env)
    assert env.link.poll(dict(site_id=SITE,pair_id=pair['pair_id']),secret,'test')['device_id'] == dev
    assert secret.encode() not in env.link.path.read_bytes()
    with pytest.raises(LinkError): env.link.approve(env.actor,pair['pair_id'],'bad')
    with pytest.raises(LinkError): env.link.poll(dict(site_id=SITE,pair_id=pair['pair_id']),'f'*64,'test')
    env.now[0] += 601
    with pytest.raises(LinkError): env.link.poll(dict(site_id=SITE,pair_id=pair['pair_id']),secret,'test')


def test_idempotent_create_launch_digest_and_cancel_claim_race(env):
    secret, _, dev = paired(env)
    key = secrets.token_hex(16)
    first = env.link.create(env.actor,dev,key)
    assert env.link.create(env.actor,dev,key) == first
    newer = env.link.action(env.actor,first['handoff_id'],'open')
    assert newer['request_digest'] == first['request_digest'] and newer['launch_generation'] == 2
    with pytest.raises(LinkError): claim(env,secret,first)
    barrier=threading.Barrier(2)
    def attempt(action):
        barrier.wait()
        try:
            if action=='claim': claim(env,secret,newer)
            else: env.link.action(env.actor,newer['handoff_id'],'cancel')
            return action
        except LinkError: return 'denied'
    with ThreadPoolExecutor(2) as pool: results=list(pool.map(attempt,['claim','cancel']))
    assert results.count('denied') == 1


def test_event_replay_gap_atomicity_associations_heartbeat_and_revocation(env):
    secret,dev,req=request(env);claim(env,secret,req)
    ev=event(req)
    assert env.link.events(req['handoff_id'],{'events':[ev]},secret,'test') == {'ack_sequence':1}
    assert env.link.events(req['handoff_id'],{'events':[ev]},secret,'test') == {'ack_sequence':1}
    with pytest.raises(LinkError,match='REPLAY_CONFLICT'): env.link.events(req['handoff_id'],{'events':[event(req,dirty=True)]},secret,'test')
    with pytest.raises(LinkError,match='SEQUENCE_GAP') as caught: env.link.events(req['handoff_id'],{'events':[event(req,3)]},secret,'test')
    assert caught.value.expected == 2
    with pytest.raises(LinkError,match='ASSOCIATION_CONFLICT'): env.link.events(req['handoff_id'],{'events':[event(req,2,session_id='ses_'+'4'*32)]},secret,'test')
    env.now[0]+=100
    assert env.link.status(env.actor,req['handoff_id'])['connection']=='STALE'
    env.link.events(req['handoff_id'],{'events':[]},secret,'test')
    assert env.link.status(env.actor,req['handoff_id'])['connection']=='CONNECTED'
    with env.link.db() as db: assert db.execute('SELECT count(*) FROM events').fetchone()[0]==1
    env.link.revoke(env.actor,dev)
    assert env.link.status(env.actor,req['handoff_id'])['connection']=='REVOKED'
    with pytest.raises(LinkError): env.link.events(req['handoff_id'],{'events':[]},secret,'test')


def test_candidate_associations_continuation_and_source_freshness(env):
    secret,dev,req=request(env);claim(env,secret,req)
    fields=dict(milestone='CANDIDATE_PREPARED',terminal='COMPLETED',verification_id='ver_test',verification_commit='3'*40,verification_status='PASSED',candidate_id='rc_'+'5'*32,candidate_verification_id='ver_test',candidate_sha256='6'*64,candidate_size=123,candidate_commit='3'*40)
    env.link.events(req['handoff_id'],{'events':[event(req,**fields,source_fresh=True)]},secret,'test')
    child=env.link.create(env.actor,dev,secrets.token_hex(16),parent=req['handoff_id'])
    assert child['release_candidate_id']==fields['candidate_id'] and child['parent_handoff_id']==req['handoff_id']
    env.link.events(req['handoff_id'],{'events':[event(req,2,**fields,dirty=True,source_fresh=False)]},secret,'test')
    with pytest.raises(LinkError,match='SOURCE_CHANGED'): env.link.create(env.actor,dev,secrets.token_hex(16),parent=req['handoff_id'])


def test_membership_and_principal_current_on_browser_and_device(env):
    secret,dev,req=request(env);claim(env,secret,req)
    with env.runtime.connect() as db: db.execute("UPDATE access_memberships SET status='revoked' WHERE id=?",(env.actor.membership_id,))
    with pytest.raises(Exception): env.link.status(env.actor,req['handoff_id'])
    with pytest.raises(LinkError): env.link.events(req['handoff_id'],{'events':[]},secret,'test')


def test_default_off_routes_and_authenticated_http(env):
    # Real HTTP parser, Access session/CSRF and Workbench shell; no production execution setup.
    product=SimpleNamespace(access_store=env.access, developer_link=None, origin=ORIGIN,
        controller=SimpleNamespace(application_contracts=lambda actor: []),
        chat_store=ChatStore(env.link.path.parent/'chat.sqlite'))
    server=ProductServer(('127.0.0.1',0),product)
    thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
    def call(method,path,body=None,headers=None):
        c=http.client.HTTPConnection('127.0.0.1',server.server_port)
        c.request(method,path,body,headers or {})
        r=c.getresponse(); data=r.read(); result=(r.status,dict(r.getheaders()),data);c.close();return result
    try:
        assert call('GET','/health')[1]['Referrer-Policy']=='no-referrer'
        assert call('GET','/developer')[0]==404
        assert call('POST','/api/developer-link/pair/start','{}',{'Content-Type':'application/json'})[0]==404
        product.developer_link=env.link
        assert call('GET','/developer')[0]==303
        secret,pair,dev=paired(env)
        browser={'Cookie':'capy_client='+env.credential,'Origin':ORIGIN,'Content-Type':'application/x-www-form-urlencoded'}
        page=call('GET','/developer',headers=browser)
        assert page[0]==200 and b'&lt;script&gt;' in page[2] and b'--site-id' in page[2]
        assert page[1]['Referrer-Policy']=='same-origin'
        denied=call('POST','/developer/requests','csrf=bad',browser)
        assert denied[0]==403 and denied[1]['Referrer-Policy']=='same-origin'
        csrf=env.access.authenticate_client(env.credential).csrf_token
        pending_secret=secrets.token_hex(32)
        pending=env.link.start_pair(dict(site_id=SITE,installation_id=secrets.token_hex(16),secret_sha256=hashlib.sha256(pending_secret.encode()).hexdigest(),label='Pending computer'),'http-pair')
        pair_page=call('GET',pending['verification_path'],headers=browser)
        assert pair_page[0]==200 and pair_page[1]['Referrer-Policy']=='same-origin'
        approval='csrf='+csrf+'&confirmation_code='+pending['confirmation_code']
        for untrusted in ('null','https://other.test',''):
            headers={**browser,'Origin':untrusted,'Sec-Fetch-Site':'same-origin','Sec-Fetch-Mode':'navigate'}
            assert call('POST',pending['verification_path']+'/approve',approval,headers)[0]==403
        assert env.link.poll(dict(site_id=SITE,pair_id=pending['pair_id']),pending_secret,'http-pair')['status']=='PENDING'
        assert call('POST',pending['verification_path']+'/approve',approval,browser)[0]==303
        assert env.link.poll(dict(site_id=SITE,pair_id=pending['pair_id']),pending_secret,'http-pair')['status']=='APPROVED'
        body='csrf='+csrf+'&device_id='+dev+'&idempotency_key='+secrets.token_hex(16)
        created=call('POST','/developer/requests',body,browser)
        assert created[0]==303
        page=call('GET',created[1]['Location'],headers=browser)
        assert b'Open Codex' in page[2] and b'application checks and workspace installation are recorded separately' in page[2]
        assert b'getElementById("developer-status")' in page[2]
        assert b'data-developer-open' in page[2] and b'Launch prepared task' in page[2]
        assert b'Without JavaScript' in page[2] and b'new Codex conversation' in page[2]
        handoff=created[1]['Location'].split('/')[-1]
        initial=env.link.status(env.actor,handoff)['request']
        for generation in (2,3):
            opened=call('POST',created[1]['Location']+'/open','csrf='+csrf,browser)
            assert opened[0]==303 and opened[1]['Location']==created[1]['Location']
            fresh=env.link.status(env.actor,handoff)['request']
            assert fresh['launch_generation']==generation and fresh['request_digest']==initial['request_digest']
            fallback_page=call('GET',opened[1]['Location'],headers=browser)
            assert ('&amp;launch='+str(generation)).encode() in fallback_page[2]
        assert call('POST',created[1]['Location']+'/open','csrf=wrong',browser)[0]==403
        assert call('POST',created[1]['Location']+'/open','csrf='+csrf,{**browser,'Origin':'https://other.test'})[0]==403
        assert call('POST',created[1]['Location']+'/open','csrf='+csrf,{'Content-Type':'application/x-www-form-urlencoded','Origin':ORIGIN})[0]==303
        assert env.link.status(env.actor,handoff)['request']['launch_generation']==3

        apps=call('GET','/applications',headers=browser)
        assert apps[1]['Referrer-Policy']=='no-referrer'
        assert apps[0]==200 and b'Build an app' in apps[2] and b'No applications installed' in apps[2]
        assert b'Local development' in apps[2]
        # Device credential is not browser authority; cookie is not device proof.
        assert call('GET','/developer',headers={'Authorization':'Bearer '+secret})[0]==303
        bad=call('POST','/api/developer-link/pair/poll',json.dumps(dict(site_id=SITE,pair_id=pair['pair_id'])),{**browser,'Content-Type':'application/json'})
        assert bad[0]==400
        assert call('POST','/api/developer-link/pair/start','{"site_id":1,"site_id":2}',{'Content-Type':'application/json'})[0]==403
    finally:
        server.shutdown();server.server_close();thread.join()


def test_default_off_configuration_creates_no_store(env,tmp_path):
    from capy_outcome_runtime.developer_link import configured_link
    path=tmp_path/'never-created'/'developer.sqlite'
    assert configured_link(SimpleNamespace(developer_link_database=path),env.access) is None
    assert not path.parent.exists()
    with pytest.raises(wire.ProtocolError): DeveloperLink(path,env.access,SITE,'http://untrusted.test')
    assert not path.parent.exists()


def test_pair_retry_rate_limit_and_closed_shapes(env):
    secret=secrets.token_hex(32)
    value=dict(site_id=SITE,installation_id=secrets.token_hex(16),secret_sha256=hashlib.sha256(secret.encode()).hexdigest(),label='Same computer')
    first=env.link.start_pair(value,'retry')
    assert env.link.start_pair(value,'retry')==first
    with pytest.raises(LinkError): env.link.start_pair({**value,'shell':'bad'},'retry')
    with pytest.raises(LinkError): env.link.poll(dict(site_id=SITE,pair_id={}),secret,'retry')
    for _ in range(8): env.link.start_pair(value,'retry')
    with pytest.raises(LinkError,match='RATE_LIMITED'): env.link.start_pair(value,'retry')


def test_team_member_and_cross_principal_device_isolation(env):
    team=next(a for a in env.access.workspaces(env.actor) if a.workspace_kind=='team')
    owner_team=env.access.activate_membership(env.actor,team.membership_id)
    invite=env.access.create_join_team_claim(owner_team)
    second=env.access.redeem_claim(invite['token'],display_name='Other Owner')
    member=next(a for a in env.access.workspaces(second.actor) if a.workspace_kind=='team')
    secret,dev,req=request(env)
    with pytest.raises(LinkError): env.link.create(second.actor,dev,secrets.token_hex(16))
    with pytest.raises(LinkError): env.link.status(second.actor,req['handoff_id'])
    with pytest.raises(LinkError): env.link.create(member,dev,secrets.token_hex(16))
    team_req=env.link.create(owner_team,dev,secrets.token_hex(16))
    claim(env,secret,team_req)
    with env.runtime.connect() as db: db.execute("UPDATE access_memberships SET kind='member' WHERE id=?",(owner_team.membership_id,))
    with pytest.raises(LinkError): env.link.events(team_req['handoff_id'],{'events':[]},secret,'test')


def test_active_continuation_reopens_and_candidate_history_can_have_failed_latest_check(env):
    secret,dev,req=request(env);claim(env,secret,req)
    candidate=dict(candidate_id='rc_'+'5'*32,candidate_verification_id='ver_passed',candidate_commit='3'*40,candidate_sha256='4'*64,candidate_size=55)
    passed=event(req,milestone='CANDIDATE_PREPARED',verification_id='ver_passed',verification_commit='3'*40,verification_status='PASSED',source_fresh=True,**candidate)
    env.link.events(req['handoff_id'],{'events':[passed]},secret,'test')
    child=env.link.create(env.actor,dev,secrets.token_hex(16),parent=req['handoff_id'])
    assert child['release_candidate_id'] is None
    changed=event(req,2,milestone='CHANGES_IN_PROGRESS',source_commit='7'*40,verification_id='ver_passed',verification_commit='3'*40,verification_status='PASSED',**candidate)
    failed=event(req,3,milestone='CHECKS_FAILED',source_commit='7'*40,verification_id='ver_failed',verification_commit='7'*40,verification_status='FAILED',**candidate)
    env.link.events(req['handoff_id'],{'events':[changed,failed]},secret,'test')
    snapshot=env.link.status(env.actor,req['handoff_id'])['snapshot']
    assert snapshot['candidate_id']==candidate['candidate_id'] and snapshot['verification_status']=='FAILED'
    wrong=event(req,4,milestone='CHECKS_FAILED',source_commit='8'*40,verification_id='ver_failed',verification_commit='8'*40,verification_status='FAILED',**candidate)
    with pytest.raises(LinkError,match='ASSOCIATION_CONFLICT'): env.link.events(req['handoff_id'],{'events':[wrong]},secret,'test')


def test_event_batch_rollback_expiry_and_device_wrong_secret(env):
    secret,dev,req=request(env);claim(env,secret,req)
    with pytest.raises(LinkError): env.link.events(req['handoff_id'],{'events':[]},'9'*64,'test')
    with pytest.raises(LinkError,match='SEQUENCE_GAP'): env.link.events(req['handoff_id'],{'events':[event(req),event(req,3)]},secret,'test')
    with env.link.db() as db:
        assert db.execute('SELECT count(*) FROM events').fetchone()[0]==0
        assert db.execute('SELECT ack FROM requests').fetchone()[0]==0
    env.now[0]+=30*86400+1
    with pytest.raises(LinkError): claim(env,secret,req)
    assert env.link.status(env.actor,req['handoff_id'])['connection']=='DISCONNECTED'


@pytest.mark.parametrize('terminal',['PASSED','FAILED','INTERRUPTED'])
def test_verification_terminal_status_is_immutable_across_intervening_receipts(env,terminal):
    secret,dev,req=request(env);claim(env,secret,req)
    milestone={'PASSED':'CHECKS_PASSED','FAILED':'CHECKS_FAILED','INTERRUPTED':'CHANGES_IN_PROGRESS'}[terminal]
    initial=event(req,milestone='VERIFYING',verification_id='ver_original',verification_commit='3'*40,verification_status='RUNNING')
    final=event(req,2,milestone=milestone,verification_id='ver_original',verification_commit='3'*40,verification_status=terminal)
    other=event(req,3,milestone='VERIFYING',verification_id='ver_other',verification_commit='3'*40,verification_status='RUNNING')
    env.link.events(req['handoff_id'],{'events':[initial,final,other]},secret,'test')
    for outcome,phase in [('RUNNING','VERIFYING'),('PASSED','CHECKS_PASSED'),('FAILED','CHECKS_FAILED')]:
        if outcome==terminal: continue
        bad=event(req,4,milestone=phase,verification_id='ver_original',verification_commit='3'*40,verification_status=outcome)
        with pytest.raises(LinkError,match='VERIFICATION_STATUS_CONFLICT'):
            env.link.events(req['handoff_id'],{'events':[bad]},secret,'test')
    assert env.link.events(req['handoff_id'],{'events':[]},secret,'test')['ack_sequence']==3


def test_candidate_cannot_promote_previously_failed_verification(env):
    secret,dev,req=request(env);claim(env,secret,req)
    failed=event(req,milestone='CHECKS_FAILED',verification_id='ver_failed',verification_commit='3'*40,verification_status='FAILED')
    env.link.events(req['handoff_id'],{'events':[failed]},secret,'test')
    candidate=dict(candidate_id='rc_'+'5'*32,candidate_verification_id='ver_failed',candidate_commit='3'*40,candidate_sha256='4'*64,candidate_size=55)
    # Even a historical candidate with a different latest receipt cannot relabel the failure.
    bad=event(req,2,milestone='CHECKS_PASSED',verification_id='ver_different',verification_commit='3'*40,verification_status='PASSED',**candidate)
    with pytest.raises(LinkError,match='VERIFICATION_STATUS_CONFLICT'):
        env.link.events(req['handoff_id'],{'events':[bad]},secret,'test')
    assert env.link.status(env.actor,req['handoff_id'])['snapshot']['verification_status']=='FAILED'
    with env.link.db() as db: assert db.execute("SELECT count(*) FROM verification_states WHERE id='ver_different'").fetchone()[0]==0


def test_candidate_first_report_registers_passed_verification_and_details_collapsed(env):
    from capy_outcome_runtime.ui.developer_link import render_request
    secret,dev,req=request(env);claim(env,secret,req)
    candidate=dict(candidate_id='rc_'+'5'*32,candidate_verification_id='ver_historical',candidate_commit='3'*40,candidate_sha256='4'*64,candidate_size=55)
    report=event(req,milestone='CHECKS_FAILED',verification_id='ver_latest',verification_commit='7'*40,verification_status='FAILED',source_commit='7'*40,**candidate)
    env.link.events(req['handoff_id'],{'events':[report]},secret,'test')
    with env.link.db() as db: assert db.execute("SELECT status FROM verification_states WHERE id='ver_historical'").fetchone()[0]=='PASSED'
    auth=env.access.authenticate_client(env.credential)
    page=str(render_request(auth,SITE,env.link.status(env.actor,req['handoff_id']),'/developer/requests/'+req['handoff_id'],req['handoff_id']))
    details=page[page.index('<details>'):page.index('</details>')]
    assert '<summary>Technical details</summary>' in details and candidate['candidate_commit'] in details
    assert candidate['candidate_sha256'] in details and ' open' not in details
    visible=page.replace(details,'')
    assert candidate['candidate_commit'] not in visible and candidate['candidate_id'] not in visible


def test_terminal_verification_guard_survives_restart_and_other_handoff(env):
    secret,dev,req=request(env);claim(env,secret,req)
    env.link.events(req['handoff_id'],{'events':[event(req,milestone='CHECKS_FAILED',verification_id='ver_failed',verification_commit='3'*40,verification_status='FAILED')]},secret,'test')
    env.link=DeveloperLink(env.link.path,env.access,SITE,ORIGIN,clock=lambda:env.now[0])
    child=env.link.create(env.actor,dev,secrets.token_hex(16),parent=req['handoff_id']);claim(env,secret,child)
    with pytest.raises(LinkError,match='VERIFICATION_STATUS_CONFLICT'):
        env.link.events(child['handoff_id'],{'events':[event(child,milestone='CHECKS_PASSED',verification_id='ver_failed',verification_commit='3'*40,verification_status='PASSED')]},secret,'test')


def test_additive_receipt_upgrade_preserves_known_and_refuses_unknown_history(env):
    secret,dev,req=request(env);claim(env,secret,req)
    env.link.events(req['handoff_id'],{'events':[event(req,milestone='CHECKS_FAILED',verification_id='ver_known',verification_commit='3'*40,verification_status='FAILED')]},secret,'test')
    with env.link.db() as db:
        db.execute('DROP TABLE verification_states')
        db.execute("INSERT INTO associations VALUES ('verification','ver_unknown',?,?,?)",('prj_'+'1'*32,'ses_'+'2'*32,json.dumps(['3'*40])))
    env.link=DeveloperLink(env.link.path,env.access,SITE,ORIGIN,clock=lambda:env.now[0])
    with env.link.db() as db:
        states=dict(db.execute('SELECT id,status FROM verification_states').fetchall())
    assert states=={'ver_known':'FAILED','ver_unknown':'UNKNOWN'}
    with pytest.raises(LinkError,match='VERIFICATION_STATUS_CONFLICT'):
        env.link.events(req['handoff_id'],{'events':[event(req,2,milestone='CHECKS_PASSED',verification_id='ver_unknown',verification_commit='3'*40,verification_status='PASSED')]},secret,'test')


def test_setup_exposes_install_route_and_honest_platform_prerequisites(env):
    from capy_outcome_runtime.ui.developer_link import render_setup
    auth=env.access.authenticate_client(env.credential)
    page=str(render_setup(auth,[],[],ORIGIN,SITE,env.now[0]))
    for text in ('Python 3.11','native Git','Codex desktop','Apple Command Line Tools','swiftc','python3 -m pip install ./capy_developer-0.5.0-py3-none-any.whl','capy-dev setup --site','Windows and Linux desktop handlers are not qualified'):
        assert text in page
    assert '/blob/9f0d0334e1eedc230f109d13bc9893aac0d56750/README.md' in page
    assert '/blob/main/' not in page and '/releases/latest' not in page


def test_repeat_open_keeps_request_and_attached_session(env):
    secret,dev,req=request(env);claim(env,secret,req)
    env.link.events(req['handoff_id'],{'events':[event(req)]},secret,'test')
    before=env.link.status(env.actor,req['handoff_id'])
    for generation in (2,3):
        opened=env.link.action(env.actor,req['handoff_id'],'open')
        assert opened['launch_generation']==generation
        assert opened['request_digest']==req['request_digest']
        assert opened['handoff_id']==req['handoff_id']
        claim(env,secret,opened)
        after=env.link.status(env.actor,req['handoff_id'])
        assert after['snapshot']==before['snapshot']
    with env.link.db() as db: assert db.execute('SELECT count(*) FROM requests').fetchone()[0]==1


def test_native_launch_enhancement_repeats_and_rejects_untrusted_response():
    """Execute actual enhancement against a fake DOM: native navigation is only recorded."""
    import shutil
    import subprocess
    from capy_outcome_runtime.ui.enhancements import DEVELOPER_STATUS_ENHANCEMENT
    node=shutil.which('node')
    if not node: pytest.skip('Node unavailable for the isolated JavaScript contract test')
    harness=r'''
const assert = require('node:assert/strict');
const source = JSON.parse(require('node:fs').readFileSync(0, 'utf8'));
(async () => {
  const handoff = 'hof_' + 'a'.repeat(32), site = 'site_' + 'b'.repeat(32);
  const path = '/developer/requests/' + handoff;
  const uri = generation => 'capy-dev://handoff/' + handoff + '?site=' + site + '&launch=' + generation;
  let submit, release, fetchCount = 0, expectedHref, assigned = [];
  const button = {disabled:false};
  const fallback = {href:uri(1),hidden:false,getAttribute:() => fallback.href,setAttribute:(_,value) => fallback.href=value};
  const notice = {textContent:''};
  const form = {action:'https://capy.test'+path+'/open',addEventListener:(_,callback) => submit=callback,querySelector:() => button};
  global.document = {getElementById:id => ({'developer-status':{},'developer-launch-fallback':fallback,'developer-launch-notice':notice})[id],querySelector:() => form};
  global.window = {location:{href:'https://capy.test'+path,origin:'https://capy.test',pathname:path,assign:value => assigned.push(value)},setTimeout:() => {}};
  global.FormData = class { *[Symbol.iterator]() { yield ['csrf','test-csrf']; } };
  global.DOMParser = class { parseFromString() { return {getElementById:() => ({getAttribute:() => expectedHref})}; } };
  global.fetch = async (url,options) => {
    fetchCount++;
    assert.equal(url,form.action);assert.equal(options.method,'POST');
    assert.equal(options.credentials,'same-origin');assert.equal(options.body.get('csrf'),'test-csrf');
    return await new Promise(resolve => {release=resolve;});
  };
  eval(source);
  const ok=() => release({ok:true,url:window.location.href,text:async () => '<page>'});
  const event={preventDefault(){}};
  const first=submit(event);
  await submit(event);
  assert.equal(fetchCount,1);assert.equal(button.disabled,true);assert.equal(fallback.hidden,true);
  expectedHref=uri(2);ok();await first;
  assert.deepEqual(assigned,[uri(2)]);assert.equal(fallback.href,uri(2));assert.equal(button.disabled,false);
  const again=submit(event);expectedHref=uri(3);ok();await again;
  assert.deepEqual(assigned,[uri(2),uri(3)]);assert.match(notice.textContent,/new conversation in the same workspace/);
  for (const invalid of [uri(3),uri(4).replace(handoff,'hof_'+'c'.repeat(32)),uri(4).replace(site,'site_'+'d'.repeat(32)),'https://other.test',uri('04'),uri(2147483648)]) {
    const denied=submit(event);expectedHref=invalid;ok();await denied;
    assert.equal(assigned.length,2);assert.match(notice.textContent,/Could not confirm/);
  }
  const forbidden=submit(event);release({ok:false,url:window.location.href});await forbidden;
  assert.equal(assigned.length,2);
  const redirected=submit(event);release({ok:true,url:'https://other.test'+path});await redirected;
  assert.equal(assigned.length,2);
})().catch(error => {console.error(error);process.exitCode=1;});
'''
    result=subprocess.run([node,'-e',harness],input=json.dumps(DEVELOPER_STATUS_ENHANCEMENT),text=True,capture_output=True,timeout=10)
    assert result.returncode==0,result.stderr
