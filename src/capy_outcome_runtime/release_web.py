"""Explicit release actions and isolated generic Workbench routes."""
from __future__ import annotations

import hashlib
import html
import json
import re
import secrets
import urllib.parse
from dataclasses import replace

from .model import RuntimeFailure
from .release_workflow import fail, MAX_CANDIDATE
from .ui import UIArtifact
from .ui_compatibility import compatibility_body


def esc(value):
    return html.escape(str(value), quote=True)


def form(auth, action, label, values=None):
    fields = dict(csrf=auth.csrf_token, **(values or {}))
    return ('<form method=post action="'+esc(action)+'">'+''.join(
        '<input type=hidden name="'+esc(k)+'" value="'+esc(v)+'">' for k,v in fields.items())
        +'<button>'+esc(label)+'</button></form>')


class PreviewWorkbench:
    """Adapt only trusted paths/context; reuse the generic Workbench renderer."""
    def __init__(self, handler, prefix, contract, result):
        self.handler, self.prefix, self.contract, self.result = handler, prefix, contract, result

    def __getattr__(self, name):
        return getattr(self.handler, name)

    def operation_path(self, contract, operation):
        return self.prefix+'/operations/'+urllib.parse.quote(operation,safe='')

    def current_application_contract(self, auth, app):
        return self.contract if app == self.contract['application_id'] else None

    def result_card(self, auth, metadata):
        artifacts = tuple(UIArtifact(label=item['filename'], href=self.prefix+'/artifacts/'
            +metadata['invocation_id']+'/'+item['digest']+'/'+urllib.parse.quote(item['filename'],safe=''))
            for item in metadata.get('artifacts', []))
        return type(self.handler).result_card(self,auth,metadata,artifacts=artifacts)

    def render(self, auth, page):
        return type(self.handler).application_interface(self, auth, page, self.result)


def route(handler, method, parsed):
    path = parsed.path
    if not (path.startswith('/releases/') or path.startswith('/api/candidate-submissions/')):
        return False
    workflow = getattr(handler.product, 'release_workflow', None)
    if workflow is None:
        handler.send_error(404)
        return True
    try:
        if parsed.query or parsed.fragment:
            fail('RELEASE_ROUTE_INVALID')
        if path.startswith('/api/'):
            _device_route(handler, method, path, workflow)
            return True
        auth = handler.require_actor()
        if auth is None:
            return True
        fields = {}
        operation = re.fullmatch(r'/releases/previews/(prv_[0-9a-f]{32})/operations/([a-z0-9._]+)',path)
        if method == 'POST':
            if operation:
                fields, files = handler.multipart_named()
            else:
                fields = handler.urlencoded()
            if handler.headers.get('Origin') != workflow.link.origin or not secrets.compare_digest(fields.get('csrf',''),auth.csrf_token):
                fail('HTTP_CSRF_OR_ORIGIN_DENIED')
        previews, activation = handler.product.release_previews, handler.product.release_activation
        match = re.fullmatch(r'/releases/review/(hof_[0-9a-f]{32})',path)
        if match:
            if method == 'POST':
                sid = workflow.begin(auth.actor,match[1],fields.get('idempotency_key',''))
                handler.redirect('/releases/submissions/'+sid)
                return True
            request, selection = workflow.review(auth.actor,match[1])
            body = ('<h1>Review for testing</h1><p>This version is still on your computer. '
                    'Sending it shares packaged application source, contracts, packaged tests and fixtures, '
                    'and verification evidence with your Capy release service. It does not share Git history, '
                    'your Codex conversation, other projects, or files outside the package. It will not install the app.</p>'
                    '<p>Package size: '+esc(selection['candidate_size_bytes'])+' bytes. Site: '+esc(workflow.link.origin)+'</p>'
                    +form(auth,path,'Send this version',{'idempotency_key':secrets.token_hex(16)})
                    +'<details><summary>Version details</summary><pre>'+esc(json.dumps(selection,indent=2))+'</pre></details>')
            history=workflow.submissions(auth.actor,match[1])
            if history:
                body += '<h2>Sent versions and check history</h2><ul>'+''.join('<li><a href="/releases/submissions/'+esc(v['id'])+'">Review saved submission</a></li>' for v in history)+'</ul>'
        elif (match := re.fullmatch(r'/releases/submissions/(sub_[0-9a-f]{32})(?:/(checks|try|cancel))?',path)):
            sid, action = match.groups()
            if method == 'POST':
                if action == 'checks':
                    workflow.approve_checks(auth.actor,sid,fields.get('profile_sha256',''),fields.get('summary_sha256',''),fields.get('idempotency_key',''))
                elif action == 'try':
                    preview = previews.create(auth.actor,sid)
                    handler.redirect('/releases/previews/'+preview['id']);return True
                elif action == 'cancel':
                    workflow.cancel(auth.actor,sid)
                else:
                    fail('RELEASE_ROUTE_INVALID')
                handler.redirect('/releases/submissions/'+sid);return True
            if action:
                fail('RELEASE_ROUTE_INVALID')
            status = workflow.status(auth.actor,sid)
            row = workflow._row(sid,auth.actor)
            body = '<h1>Application checks</h1>'
            if status['status'] == 'RECEIVED':
                body += '<p>This exact package was received.</p>'
            elif status['status'] == 'CANCELLED':
                body += '<p>Submission cancelled. Its retained history is unchanged.</p>'
            else:
                uri = 'capy-dev://submission/'+sid+'?site='+workflow.link.site_id+'&send='+str(row['intent']['generation'])
                body += '<p>Waiting for your computer. Confirm the package in Capy Developer to send it. This action requires Capy Developer 0.6 or later; an older companion must be upgraded first.</p><a class=button href="'+esc(uri)+'">Open Capy Developer to send</a>'
            profile, attempt = status['profile'], status['attempt']
            if profile:
                summary = profile['summary']
                body += '<h2>'+esc(summary.get('title','Independent checks'))+'</h2><p>Prepared independently with maintainer assistance.</p>'
                body += '<h3>Does</h3><ul>'+''.join('<li>'+esc(v)+'</li>' for v in summary.get('does',[]))+'</ul>'
                body += '<h3>Does not</h3><ul>'+''.join('<li>'+esc(v)+'</li>' for v in summary.get('does_not',[]))+'</ul>'
                body += '<h3>Examples we will check</h3><ul>'+''.join('<li>'+esc(v['explanation'])+'</li>' for v in summary.get('examples',[]))+'</ul>'
                body += '<details><summary>Exact check version</summary><p>'+esc(profile['profile_sha256'])+'</p></details>'
                if status.get('check_action_pending'):
                    body += '<p>Your approved check request is being recovered. No new approval is needed.</p>'
                elif not attempt or attempt['status'] in ('INTERRUPTED','BLOCKED','FAILED'):
                    body += form(auth,path+'/checks','Approve checks and test this version',
                        dict(profile_sha256=profile['profile_sha256'],summary_sha256=profile['summary_sha256'],idempotency_key=secrets.token_hex(16)))
            else:
                body += '<p>Waiting for independently prepared checks.</p>'
            if attempt:
                labels = {'ACCEPTED':'Checks passed — ready to try','REJECTED':'Checks failed',
                    'QUEUED':'Checks queued','RUNNING':'Checking this version','COMPLETED_UNPROMOTED':'Confirming check results',
                    'INTERRUPTED':'Checks interrupted','BLOCKED':'Checks blocked','FAILED':'Checks could not complete','CANCELLED':'Checks cancelled'}
                body += '<p>'+esc(labels.get(attempt['status'],'Checks unavailable'))+'</p>'
                if attempt['status'] == 'ACCEPTED':
                    body += form(auth,path+'/try','Try in Capy')
                elif attempt['status'] in ('REJECTED','BLOCKED','INTERRUPTED','FAILED'):
                    body += '<p>'+esc(attempt.get('error_code') or 'Review this result before continuing.')+'</p>'
                    body += '<ul>'+''.join('<li>'+esc(v['case_id'])+': '+esc(v['classification'])+'</li>' for v in attempt.get('case_failures',[]))+'</ul>'
                    body += form(auth,'/developer/requests/'+row['handoff_id']+'/continue','Continue in Codex',{'idempotency_key':secrets.token_hex(16)})
            history=status.get('history',[])
            if history:
                body += '<details><summary>Check history</summary><ul>'+''.join('<li>'+esc(v['status'])+(' — '+esc(v['error_code']) if v.get('error_code') else '')+'</li>' for v in history)+'</ul></details>'
            if status['status']!='CANCELLED' and not (attempt and attempt['status']=='ACCEPTED'):
                body += form(auth,path+'/cancel','Withdraw pending submission')
        elif operation:
            if method == 'GET':
                handler.redirect('/releases/previews/'+operation[1]);return True
            if method != 'POST':
                fail('RELEASE_ROUTE_INVALID')
            result = previews.submit(auth.actor,operation[1],operation[2],fields,files)
            handler.redirect('/releases/previews/'+operation[1]+'/activity/'+result['activity_id']);return True
        elif (match := re.fullmatch(r'/releases/previews/(prv_[0-9a-f]{32})(?:/(end|add)|/activity/([a-zA-Z0-9_-]+))?',path)):
            pid, action, activity = match.groups()
            prefix = '/releases/previews/'+pid
            if method == 'POST':
                if action == 'end':
                    previews.end(auth.actor,pid)
                    body = '<h1>Preview ended</h1><p>Preview execution and access are closed. Retained history is preserved.</p>'
                elif action == 'add':
                    receipt = activation.add(auth.actor,pid,fields.get('membership_id',''),fields.get('idempotency_key',''))
                    name = 'Personal' if receipt['workspace_kind']=='personal' else next(v.team_name for v in workflow.access.workspaces(auth.actor) if v.membership_id==receipt['membership_id'])
                    body = '<h1>'+esc(('Added to ' if receipt['status']=='ACTIVE' else 'Removed from ')+name)+'</h1>'
                    body += '<a href="/applications/'+urllib.parse.quote(receipt['application_id'],safe='')+'?workspace='+esc(receipt['membership_id'])+'">Open app</a>'
                else:
                    fail('RELEASE_ROUTE_INVALID')
            else:
                if action:
                    fail('RELEASE_ROUTE_INVALID')
                with previews.context(auth.actor,pid) as (row,mapped,interface):
                    mapped_auth = replace(auth,actor=mapped)
                    page = interface.page(mapped,row['record']['application_id'])
                    result = interface.activity(mapped,row['record']['application_id'],activity) if activity else None
                    installed=activation.current(auth.actor,row['record']['application_id'])
                    banner='Preview — app added to this workspace' if installed and installed['status']=='ACTIVE' else 'Preview — not added to this workspace'
                    body = '<h1>'+esc(page['contract']['title'])+'</h1><p role=status><strong>'+esc(banner)+'</strong></p><p>Only files uploaded here are available in this preview. Preview files and results are not copied when software is added.</p>'
                    body += PreviewWorkbench(handler,prefix,page['contract'],result).render(mapped_auth,page)
                    if row['successful_activity']:
                        body += '<h2>Add this app</h2><p>Choose who can use this software. Preview files and results stay private to this preview.</p>'
                        for target in workflow.access.workspaces(auth.actor):
                            if target.workspace_kind=='personal' or target.membership_kind=='owner':
                                label = 'Personal' if target.workspace_kind=='personal' else target.team_name
                                if target.workspace_kind=='team':
                                    body += '<p>Adding to '+esc(label)+' makes this packaged software available to current and future authorized team members. You share and maintain this version; your preview files stay here.</p>'
                                body += form(auth,prefix+'/add','Add to '+label,dict(membership_id=target.membership_id,idempotency_key=secrets.token_hex(16)))
                    body += form(auth,prefix+'/end','End preview')
        elif (match := re.fullmatch(r'/releases/previews/(prv_[0-9a-f]{32})/artifacts/([0-9a-f]{32})/([0-9a-f]{64})/([^/]+)',path)):
            if method != 'GET':
                fail('RELEASE_ROUTE_INVALID')
            with previews.context(auth.actor,match[1]) as (_row,mapped,interface):
                file, filename = interface.artifact(mapped,match[2],match[3],urllib.parse.unquote(match[4]))
                if file.is_symlink() or not file.is_file():
                    fail('RESOURCE_BYTES_INVALID')
                payload=file.read_bytes()
                if hashlib.sha256(payload).hexdigest()!=match[3]:
                    fail('RESOURCE_BYTES_INVALID')
                handler.send_response(200)
                for k,v in [('Content-Type','application/octet-stream'),('Content-Length',str(len(payload))),('Cache-Control','no-store'),('X-Content-Type-Options','nosniff'),('Content-Disposition',"attachment; filename*=UTF-8''"+urllib.parse.quote(filename,safe=''))]:
                    handler.send_header(k,v)
                handler.end_headers();handler.wfile.write(payload);return True
        elif (match := re.fullmatch(r'/releases/remove/([a-z0-9._]+)',path)) and method=='POST':
            activation.remove(auth.actor,match[1]);handler.redirect('/applications');return True
        else:
            fail('RELEASE_ROUTE_INVALID')
        handler.send_html(handler.product_shell(auth,title='Application checks',active='applications',body=compatibility_body(body),application=True),referrer_policy='same-origin')
    except Exception as exc:
        if path.startswith('/api/'):
            from .developer_link_web import json_reply
            handler.close_connection = True
            json_reply(handler, {'error':'RELEASE_REQUEST_DENIED'}, 409)
            return True
        # A failed operation never becomes optimistic acceptance or installation.
        # Diagnostic class is bounded; raw exception/remote bodies are private.
        messages = {
            'RELEASE_PREVIEW_EXPIRED':'This preview has ended. Return to the saved submission and choose Try in Capy for a new preview.',
            'RELEASE_PREVIEW_UNAVAILABLE':'This preview is unavailable. Return to the saved submission to check its state.',
            'RELEASE_CHECK_ACTION_PENDING':'Your earlier check approval is still being recovered. Return to its saved submission to check progress.',
            'RELEASE_PROFILE_CHANGED':'The check version changed. Review the current checks before approving again.',
            'UPDATE_REQUIRES_SEPARATE_FLOW':'A different version is already registered for this app. This first-install flow cannot replace it.',
            'RELEASE_TARGET_AUTHORITY_DENIED':'You no longer have permission to add or remove software in this workspace.',
            'RELEASE_GRANT_EXPIRED':'The send window expired. Return to Review for testing to start a new send request.',
        }
        message=messages.get(getattr(exc,'code',None),'Your saved version and previous results are preserved. Refresh the page to check its current state.')
        if (path.startswith('/releases/previews/') and
                getattr(exc,'safe_facts',{}).get('application_invoked') is True):
            code=getattr(exc,'code','')
            if not re.fullmatch(r'[A-Z][A-Z0-9_]{0,127}',code): code='APPLICATION_FAILED'
            message='The application ran and reported '+code+'. Review the input and application guidance before trying again. No successful result was produced.'
        handler.send_html('<h1>Action could not complete</h1><p>'+esc(message)+'</p><a href="/applications">Applications</a>',409,referrer_policy='same-origin')
    return True


def _device_route(handler,method,path,workflow):
    from ._developer_link_protocol import decode_json
    from .developer_link_web import json_reply
    if method!='POST' or handler.headers.get('Transfer-Encoding'):
        fail('RELEASE_PROTOCOL_INVALID')
    lengths=handler.headers.get_all('Content-Length',[])
    if len(lengths)!=1 or not re.fullmatch(r'0|[1-9][0-9]*',lengths[0]):
        fail('RELEASE_BODY_LIMIT')
    length=int(lengths[0]); peer=handler.client_address[0]
    authorization=handler.headers.get('Authorization','')
    secret=authorization[7:] if authorization.startswith('Bearer ') else ''
    match=re.fullmatch(r'/api/candidate-submissions/(sub_[0-9a-f]{32})/(grant|bytes)',path)
    old_timeout=handler.connection.gettimeout();handler.connection.settimeout(30)
    try:
        if match and match[2]=='bytes':
            if handler.headers.get_content_type()!='application/octet-stream' or not 0<length<=MAX_CANDIDATE:
                fail('RELEASE_BODY_LIMIT')
            generation=handler.headers.get('X-Capy-Generation','')
            if not re.fullmatch(r'[1-9][0-9]{0,8}',generation):
                fail('RELEASE_PROTOCOL_INVALID')
            value=dict(schema='capy.candidate-grant-request/v0',site_id=workflow.link.site_id,
                       device_id=handler.headers.get('X-Capy-Device',''),generation=int(generation))
            result=workflow.receive(match[1],value,secret,peer,handler.rfile,length)
        else:
            if handler.headers.get_content_type()!='application/json' or length>262144:
                fail('RELEASE_BODY_LIMIT')
            raw=handler.rfile.read(length)
            if len(raw)!=length:
                fail('RELEASE_UPLOAD_INTERRUPTED')
            value=decode_json(raw,max_bytes=262144)
            if path=='/api/candidate-submissions/capabilities':
                result=workflow.device_capabilities(value,secret,peer)
            elif path=='/api/candidate-submissions/pending-v0':
                result=workflow.pending_for_device(value,secret,peer)
            elif match and match[2]=='grant':
                result=workflow.grant(match[1],value,secret,peer)
            else:
                fail('RELEASE_ROUTE_INVALID')
        json_reply(handler,result)
    finally:
        handler.connection.settimeout(old_timeout)
