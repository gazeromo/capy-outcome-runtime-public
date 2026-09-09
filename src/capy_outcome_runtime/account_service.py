"""Dedicated, unprivileged human secret ingress and encrypted provider custody.

Reverse proxy only /connect-account/ to this listener. No normal runtime HTML,
app JavaScript, analytics, body logging or generic secret API is hosted here.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import html
import json
import os
import re
import secrets
import signal
import socket
import threading
import time
import urllib.parse
from concurrent.futures import ThreadPoolExecutor
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
from pathlib import Path

from .account_custody import AccountVault
from .account_ipc import Client,Server
from .model import RuntimeFailure

SCRIPT='''document.querySelectorAll('form').forEach(form=>form.addEventListener('submit',async event=>{
 event.preventDefault();let body=new URLSearchParams(new FormData(form));
 form.querySelectorAll('input[type=password]').forEach(input=>{input.value='';});
 const button=form.querySelector('button');button.disabled=true;
 try {const response=await fetch(form.action,{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded','Accept':'application/json'},body,credentials:'same-origin',cache:'no-store'});
 body=null;const result=await response.json();if(result.next&&['/connect-account/','/releases/previews/'].some(prefix=>result.next.startsWith(prefix)))location.replace(result.next);
 else {document.getElementById('notice').textContent='Capy could not complete that step. Please try again.';button.disabled=false;}}
 catch(_){body=null;document.getElementById('notice').textContent='Capy could not complete that step. Please try again.';button.disabled=false;}
}));
window.addEventListener('pageshow',()=>document.querySelectorAll('input[type=password]').forEach(input=>{input.value='';}));
const country=document.getElementById('country_code');
if(country){const update=()=>{const required=['US','CA','PR'].includes(country.value);const region=document.getElementById('region');region.hidden=!required;region.querySelector('input').required=required;
if(!required)region.querySelector('input').value='';document.getElementById('postal_code').required=['KR','US','CA','PR'].includes(country.value);};country.addEventListener('change',update);update();}
const progress=document.querySelector('[data-progress]');
if(progress){setTimeout(async()=>{try{const r=await fetch(location.pathname+'/status',{credentials:'same-origin',cache:'no-store'});const s=await r.json();
if(s.next&&['/connect-account/','/releases/previews/'].some(prefix=>s.next.startsWith(prefix)))location.replace(s.next);else location.reload();}catch(_){location.reload();}},2500);}
'''
SCRIPT_HASH=base64.b64encode(hashlib.sha256(SCRIPT.encode()).digest()).decode()
STYLE='''*{box-sizing:border-box}body{margin:0;background:#f7f6f2;color:#222824;font:17px/1.55 system-ui,sans-serif}main{max-width:480px;margin:3vh auto;padding:24px}header{font-size:14px;color:#617068;margin-bottom:24px}h1{font-size:28px;line-height:1.18;letter-spacing:-.8px;margin:0 0 18px}p{color:#556158;margin:12px 0 24px}label{display:block;font-weight:550;font-size:15px;margin:14px 0 7px}input,select{width:100%;font:inherit;padding:12px;border:1px solid #b7c0b9;border-radius:8px;background:white}input:focus{outline:3px solid #c4d9cb;border-color:#315942}button{border:0;border-radius:8px;background:#28523a;color:white;font:inherit;font-weight:600;padding:12px 22px;cursor:pointer}button:disabled{opacity:.5}a{color:#28523a;text-underline-offset:3px}.actions{display:flex;gap:22px;align-items:center;margin:28px 0}details{font-size:14px;color:#556158;margin-top:24px}summary{cursor:pointer}small{display:inline-block;margin-left:6px;color:#65736b;font-weight:400;margin-top:3px}.secondary button{background:transparent;color:#28523a;padding:0;font-size:15px}#notice{color:#814128}dl{font-size:15px}dt{color:#65736b}dd{margin:0 0 12px}@media(max-width:520px){main{margin:0;padding:32px 24px;min-height:100dvh}header{margin-bottom:28px}h1{font-size:28px}}'''
COUNTRIES = [('KR','South Korea'),('US','United States'),('CA','Canada'),('PR','Puerto Rico'),
    ('JP','Japan'),('CN','China'),('HK','Hong Kong'),('SG','Singapore'),('TW','Taiwan'),
    ('AU','Australia'),('NZ','New Zealand'),('GB','United Kingdom'),('DE','Germany'),('FR','France'),
    ('NL','Netherlands'),('BE','Belgium'),('ES','Spain'),('IT','Italy'),('CH','Switzerland'),
    ('AT','Austria'),('SE','Sweden'),('NO','Norway'),('DK','Denmark'),('FI','Finland'),
    ('PL','Poland'),('CZ','Czechia'),('IE','Ireland'),('PT','Portugal'),('GR','Greece'),
    ('TR','Türkiye'),('AE','United Arab Emirates'),('SA','Saudi Arabia'),('IL','Israel'),
    ('IN','India'),('TH','Thailand'),('VN','Vietnam'),('MY','Malaysia'),('ID','Indonesia'),
    ('PH','Philippines'),('MX','Mexico'),('BR','Brazil'),('CL','Chile'),('ZA','South Africa')]

MESSAGES={
 'verification_pending':('Checking your account','Verification is pending. You can leave this page; Capy will keep your progress securely and retry.'),
 'account_rejected':('Check your account details','FedEx did not accept these account details. Enter the complete set again to correct them.'),
 'account_rates_unverified':('Account rates are not verified','FedEx has not returned account-specific rates for this shipment. Your existing connected account has not been replaced.'),
 'expired':('Connect your account','The protected pending details have expired and were removed. Enter them again to continue.'),
 'reconnect_required':('Reconnect your account','FedEx no longer accepts the connected account. Reconnect securely to continue.'),
 'service_unavailable':('Capy is having a connection problem','Your account details are not needed right now. Capy will retry when its connection service is ready.'),
}


def esc(value):return html.escape(str(value),quote=True)
def hidden(name,value):return '<input type="hidden" name="'+name+'" value="'+esc(value)+'">'


class AccountApplication:
    def __init__(self,vault,authority,origin,*,service_ready=lambda:True):
        self.vault,self.authority,self.origin=vault,authority,origin
        self.service_ready=service_ready
        self.pool=ThreadPoolExecutor(max_workers=4,thread_name_prefix='account-setup')
        self.lock=threading.RLock();self.running=set();self.retry_at={};self.results={};self.stop=threading.Event()

    def job(self,rid):
        with self.lock:
            if rid in self.running or time.monotonic()<self.retry_at.get(rid,0):return
            self.running.add(rid)
        self.pool.submit(self._drive,rid)

    def _drive(self,rid):
        try:
            context=self.authority.call('validate',request_id=rid)
            if not self.service_ready():return
            status=self.vault.inspect(context)['status']
            if status=='verification_pending':status=self.vault.authenticate(context)['status']
            if status in {'ready_to_continue','connected'}:
                outcome=self.authority.call('resume',request_id=rid)
                with self.lock:self.results[rid]=outcome
                if self.vault.inspect(context)['status']=='connected':self.authority.call('connected',request_id=rid)
        except Exception:pass
        finally:
            with self.lock:
                self.running.discard(rid);self.retry_at[rid]=time.monotonic()+60

    def maintenance(self):
        while not self.stop.wait(15):
            try:
                self.vault.expire_all()
                with self.vault.lock:
                    requests=[]
                    for path in self.vault.root.glob('*.sealed'):
                        data=self.vault._load(path.name.removesuffix('.sealed'))
                        requests.extend(rid for rid,row in data['requests'].items() if row['created_at']+3600>self.vault.clock() and row['status'] in {'verification_pending','ready_to_continue','connected'})
                with self.lock:
                    self.retry_at={k:v for k,v in self.retry_at.items() if k in requests or k in self.running}
                    self.results={k:v for k,v in self.results.items() if k in requests or k in self.running}
                for rid in requests:self.job(rid)
            except Exception:pass

    def dispatch(self,operation,values):
        if operation=='retry' and set(values)=={'request_id'}:
            context=self.authority.call('validate',**values)
            self.authority.call('retry',**values)
            with self.vault.lock:
                data=self.vault._load(context['connection_id']);self.vault._expire(data)
                pending=data['pending']
                if not pending or pending['request_id']!=context['request_id'] or not pending['authenticated'] or not pending.get('origin'):
                    raise RuntimeFailure('ACCOUNT_SETUP_REQUIRED')
                data['requests'][context['request_id']].update(status='ready_to_continue')
                data['requests'][context['request_id']].pop('provider_problem',None)
                self.vault._save(context['connection_id'],data)
            with self.lock:self.retry_at.pop(context['request_id'],None);self.results.pop(context['request_id'],None)
            self.job(context['request_id'])
            return {'status':'continuing'}
        if operation=='status' and set(values)=={'request_id'}:
            context=self.authority.call('validate',**values)
            return self.vault.inspect(context)
        if operation=='available' and set(values)=={'connection_id'}:
            # This socket admits only the configured runtime/broker peer UID.
            # It exposes a boolean, never account or profile values.
            with self.vault.lock:
                data=self.vault._load(values['connection_id']);active=data['active']
                return {'available':bool(active and active['authenticated'] and active.get('origin'))}
        if operation=='quote' and set(values)=={'authority','payload'}:
            authority=self.authority.call('quote_authority',**values['authority'])
            return self.vault.quote(authority,values['payload'])
        raise RuntimeFailure('ACCOUNT_AUTHORITY_DENIED')

    def close(self):self.stop.set();self.pool.shutdown(wait=True)


class AccountHTTP(ThreadingHTTPServer):
    daemon_threads=True
    def __init__(self,address,application):self.application=application;super().__init__(address,Handler)
    def handle_error(self,*_):pass


class Handler(BaseHTTPRequestHandler):
    def log_message(self,*_):pass
    def do_GET(self):self.route('GET')
    def do_POST(self):self.route('POST')
    def do_PUT(self):self.respond('Not available',404)
    def do_OPTIONS(self):self.respond('Not available',404)

    @property
    def app(self):return self.server.application

    def respond(self,body,status=200,*,json_response=False):
        payload=(json.dumps(body) if json_response else body).encode()
        self.send_response(status)
        self.send_header('Content-Type','application/json' if json_response else 'text/html; charset=utf-8')
        self.send_header('Content-Length',str(len(payload)))
        for key,value in {
            'Cache-Control':'no-store, max-age=0','Pragma':'no-cache','Referrer-Policy':'no-referrer',
            'X-Content-Type-Options':'nosniff','X-Frame-Options':'DENY','Cross-Origin-Opener-Policy':'same-origin',
            'Cross-Origin-Resource-Policy':'same-origin',
            'Content-Security-Policy':"default-src 'none'; style-src 'unsafe-inline'; script-src 'sha256-"+SCRIPT_HASH+"'; connect-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'",
            'Permissions-Policy':'camera=(), microphone=(), geolocation=()'}.items():self.send_header(key,value)
        self.end_headers();self.wfile.write(payload)

    def route(self,method):
        try:
            parsed=urllib.parse.urlsplit(self.path)
            match=re.fullmatch(r'/connect-account/(acr_[0-9a-f]{32})(?:/(status|credentials|origin|cancel|replace))?',parsed.path)
            if not match or parsed.query or parsed.fragment:self.respond('Not available',404);return
            rid,action=match.groups();base='/connect-account/'+rid
            expected=urllib.parse.urlsplit(self.app.origin).netloc
            if self.headers.get('Host')!=expected:raise RuntimeFailure('ACCOUNT_AUTHORITY_DENIED')
            if self.headers.get('Sec-Fetch-Dest') in {'iframe','frame','object','embed'}:raise RuntimeFailure('ACCOUNT_AUTHORITY_DENIED')
            cookie=SimpleCookie(self.headers.get('Cookie',''));client=cookie.get('capy_client')
            if client is None:raise RuntimeFailure('ACCOUNT_AUTHORITY_DENIED')
            context=self.app.authority.call('authorize_http',request_id=rid,credential=client.value)
            if method=='POST':
                # Reject cross-origin/unauthenticated input before reading its body.
                if self.headers.get('Origin')!=self.app.origin or self.headers.get('Transfer-Encoding'):
                    raise RuntimeFailure('ACCOUNT_AUTHORITY_DENIED')
                if self.headers.get_content_type()!='application/x-www-form-urlencoded':raise RuntimeFailure('ACCOUNT_INPUT_INVALID')
                length=int(self.headers.get('Content-Length','-1'))
                if not 0<=length<=8192:raise RuntimeFailure('ACCOUNT_INPUT_INVALID')
                raw=self.rfile.read(length)
                if len(raw)!=length:raise RuntimeFailure('ACCOUNT_INPUT_INVALID')
                parsed_fields=urllib.parse.parse_qs(raw.decode(),keep_blank_values=True,strict_parsing=True,max_num_fields=12)
                raw=None
                if any(len(v)!=1 for v in parsed_fields.values()):raise RuntimeFailure('ACCOUNT_INPUT_INVALID')
                fields={k:v[0] for k,v in parsed_fields.items()};parsed_fields=None
                self.app.authority.call('authorize_http',request_id=rid,credential=client.value,csrf=fields.pop('csrf',''))
                if action=='credentials':
                    nonce=fields.pop('nonce','');generation=int(fields.pop('generation','-1'))
                    staged=self.app.vault.stage(context,fields,nonce,generation)
                    fields.clear();fields=None
                    if staged['status']=='verification_pending':self.app.authority.call('prepare',request_id=rid)
                    with self.app.lock:self.app.retry_at.pop(rid,None);self.app.results.pop(rid,None)
                    self.app.job(rid)
                elif action=='origin':
                    self.app.vault.origin(context,fields);fields.clear()
                    with self.app.lock:self.app.retry_at.pop(rid,None)
                    self.app.job(rid)
                elif action=='cancel' and not fields:
                    self.app.vault.cancel(context);self.app.authority.call('cancel',request_id=rid)
                    if self.headers.get('Accept')=='application/json':
                        self.respond({'next':context['return_url']},json_response=True);return
                    self.respond(self.page('<h1>Connection cancelled</h1><p>Your pending account details were removed.</p><a href="'+esc(context['return_url'])+'">Return to your work</a>'));return
                else:raise RuntimeFailure('ACCOUNT_INPUT_INVALID')
                self.respond({'next':base},json_response=True) if self.headers.get('Accept')=='application/json' else self.redirect(base)
                return
            if not self.app.service_ready():raise RuntimeFailure('ACCOUNT_SERVICE_UNAVAILABLE')
            if action not in {None,'status','replace'}:self.respond('Not available',404);return
            status=self.app.vault.inspect(context)
            if context.get('status')=='WAITING':
                with self.app.lock:
                    self.app.results.pop(rid,None);self.app.retry_at.pop(rid,None)
                self.app.job(rid)
            if action=='status':
                with self.app.lock:outcome=self.app.results.get(rid)
                next_url=outcome['url'] if outcome and outcome.get('status') in {'done','needs_input','shipment_required'} and context.get('status') not in {'WAITING','RESUMING'} else base
                self.respond({'status':status['status'],'next':next_url},json_response=True);return
            self.respond(self.render(context,status,replace=action=='replace'))
        except Exception as exc:
            code=getattr(exc,'code',None)
            if code in {'ACCOUNT_AUTHORITY_DENIED','ACCOUNT_REQUEST_CHANGED'}:
                self.respond(self.page('<h1>This connection request is unavailable</h1><p>Your access or the saved work has changed. Return to Capy to continue.</p><a href="/">Return to Capy</a>'),403)
            elif code in {'ACCOUNT_INPUT_INVALID','ACCOUNT_ORIGIN_INVALID','ACCOUNT_SETUP_IN_PROGRESS'}:
                if self.headers.get('Accept')=='application/json':self.respond({'next':'/connect-account/'+rid},409,json_response=True)
                else:self.respond(self.page('<h1>Check the information</h1><p>Capy could not accept that complete set of details. No existing account was replaced.</p><a href="/connect-account/'+esc(rid)+'">Try again</a>'),409)
            else:self.respond(self.page('<h1>Capy is having a connection problem</h1><p data-progress>Your account details are not needed right now. Please try again shortly.</p>'),503)

    def redirect(self,path):
        self.send_response(303);self.send_header('Location',path);self.send_header('Cache-Control','no-store');self.send_header('Content-Length','0');self.end_headers()

    def page(self,body):
        return '<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Connect an account · Capy</title><style>'+STYLE+'</style><body data-capy-sensitive="true"><main><header>Capy · Secure account connection</header>'+body+'<p id="notice" role="status" aria-live="polite"></p></main><script>'+SCRIPT+'</script></body></html>'

    def render(self,context,state,*,replace=False):
        base='/connect-account/'+context['request_id'];csrf=hidden('csrf',context['csrf']);status=state['status']
        cancel='<form class="secondary" method="post" action="'+base+'/cancel">'+csrf+'<button>Cancel</button></form>'
        if replace or status in {'account_required','account_rejected','expired','reconnect_required','cancelled'}:
            title="Connect "+context['workspace_name']+"’s FedEx account"
            body='<h1>'+esc(title)+'</h1><p>Use this account for shipping quotes in '+esc(context['workspace_name'])+'. This connection does not buy shipping.</p>'
            if status in MESSAGES:body+='<p role="status">'+esc(MESSAGES[status][1])+'</p>'
            if context['environment']=='sandbox':body+='<p><strong>Test environment</strong></p>'
            body+='<form method="post" action="'+base+'/credentials" autocomplete="off">'+csrf+hidden('nonce',secrets.token_hex(16))+hidden('generation',state['generation'])
            fields=[('client_id','FedEx API key','Client ID'),('client_secret','FedEx secret key','Client Secret'),('account_number','FedEx account number','')]
            if context['account_mode']=='child':fields += [('child_key','FedEx customer key',''),('child_secret','FedEx customer secret','')]
            for name,label,helper in fields:
                body+='<label for="'+name+'">'+label+('<small>'+helper+'</small>' if helper else '')+'</label><input type="password" id="'+name+'" name="'+name+'" required maxlength="256" autocomplete="off" spellcheck="false" autocapitalize="none">'
            body+='<div class="actions"><button>Connect</button></div></form>'+cancel
            body+='<details><summary>Where do I find these?</summary><p>Sign in to the <a href="https://developer.fedex.com/api/en-us/catalog/authorization/docs.html" target="_blank" rel="noopener noreferrer">FedEx Developer Portal</a> and open your project. The API key is shown on Project Overview. Use the secret key issued when the project was created. Avoid regenerating a key used by another integration.</p><p>Enter the keys only here, never in chat. Your FedEx website password is not needed.</p></details>'
        elif status=='provider_rejected':
            reason=(state.get('provider_problem') or {}).get('reason')
            if (state.get('provider_problem') or {}).get('provider_code') in {'RATE.CUSTOMCLEARANCEDETAIL.INVALID','CUSTOMSCLEARANCEDETAIL.COMMODITIES.REQUIRED'}:
                reason='customs_required'
            message={'account_not_linked':'FedEx accepted the API keys, but did not authorize this account for the rate request. Check that this account is linked to the same production project in FedEx.',
                'access_denied':'FedEx accepted the API keys, but denied access to rates. Check the Rates API access for this production project in FedEx.',
                'customs_required':'FedEx needs details about the goods for this international quote. This version of the application does not collect those details yet. Your shipment is saved; changing your API keys will not resolve this request.',
                'ship_date':'FedEx did not accept the shipment date. Return to your quote and correct the date.'}.get(reason,'FedEx did not accept this shipment request. Your account details are still saved; the account has not been marked connected.')
            body='<h1>FedEx could not return rates</h1><p>'+esc(message)+'</p><p><a href="'+esc(context['return_url'])+'">Return to your quote</a></p>'+cancel
        elif status=='origin_required':
            origin=state.get('origin') or {}
            body='<h1>Where does '+esc(context['workspace_name'])+' ship from?</h1><p>Use the shipping origin for these quotes. It may differ from your company’s registered address.</p><form method="post" action="'+base+'/origin">'+csrf
            body+='<label for="country_code">Country</label><select id="country_code" name="country_code" required><option value="">Choose the shipping country</option>'+''.join('<option value="'+code+'"'+(' selected' if origin.get('country_code')==code else '')+'>'+name+'</option>' for code,name in COUNTRIES)+'</select>'
            body+='<label for="postal_code">Postal code</label><input id="postal_code" name="postal_code" value="'+esc(origin.get('postal_code',''))+'" maxlength="32" autocomplete="postal-code">'
            body+='<div id="region"><label for="state_or_province_code">State or province code</label><input id="state_or_province_code" name="state_or_province_code" value="'+esc(origin.get('state_or_province_code',''))+'" maxlength="2"></div>'
            body+='<div class="actions"><button>Continue</button></div></form>'+cancel
        elif status in {'connected','ready_to_continue'}:
            self.app.job(context['request_id'])
            body='<h1>'+('Connected. Continuing your setup…' if status=='connected' else 'Continuing your quote…')+'</h1><p data-progress>Capy is returning to your saved work.</p>'
            if state.get('origin'):
                body+='<details><summary>Shipping origin</summary><dl>'+''.join('<dt>'+esc(k.replace('_',' ').title())+'</dt><dd>'+esc(v)+'</dd>' for k,v in state['origin'].items())+'</dl></details>'
            body+='<p><a href="'+base+'/replace">Replace account details</a></p>'
        else:
            title,message=MESSAGES.get(status,MESSAGES['service_unavailable'])
            body='<h1>'+esc(title)+'</h1><p'+(' data-progress' if status=='verification_pending' else '')+'>'+esc(message)+'</p>'+cancel
        return self.page(body)


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--vault-root',type=Path,required=True)
    parser.add_argument('--authority-socket',required=True);parser.add_argument('--authority-uid',type=int,required=True)
    parser.add_argument('--service-socket',required=True);parser.add_argument('--runtime-uid',type=int,required=True)
    parser.add_argument('--broker-socket',required=True);parser.add_argument('--origin',required=True);parser.add_argument('--port',type=int,default=20920)
    args=parser.parse_args()
    if os.geteuid()==0:raise SystemExit('account service requires an unprivileged identity')
    key=(Path(os.environ['CREDENTIALS_DIRECTORY'])/'account-key').read_bytes().strip()
    from capy_connections.fedex_rates_v3 import FedExRatesAdapter,UrlLibTransport
    authority=Client(args.authority_socket,args.authority_uid)
    vault=AccountVault(args.vault_root,key,FedExRatesAdapter(UrlLibTransport()),lambda rid:authority.call('validate',request_id=rid))
    def broker_ready():
        try:
            with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as sock:
                sock.settimeout(2);sock.connect(args.broker_socket)
                sock.sendall(b'{"schema":"capy.connection-health/v0"}\n')
                from .account_ipc import read
                return read(sock)=={'schema':'capy.connection-health/v0','status':'ready'}
        except Exception:return False
    app=AccountApplication(vault,authority,args.origin,service_ready=broker_ready)
    ipc=Server(args.service_socket,args.runtime_uid,app.dispatch)
    threading.Thread(target=ipc.serve_forever,daemon=True).start()
    threading.Thread(target=app.maintenance,daemon=True).start()
    http=AccountHTTP(('127.0.0.1',args.port),app)
    def stop(*_):threading.Thread(target=http.shutdown,daemon=True).start()
    signal.signal(signal.SIGTERM,stop);signal.signal(signal.SIGINT,stop)
    try:http.serve_forever()
    finally:ipc.shutdown();ipc.server_close();http.server_close();app.close()
    return 0

if __name__=='__main__':raise SystemExit(main())
