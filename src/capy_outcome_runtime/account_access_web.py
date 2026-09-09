"""Small in-product owner request; it does not grant account administration."""
import html
import secrets

from .model import RuntimeFailure


def route(handler,method,parsed):
    if parsed.path not in {'/account-access','/account-access/request'}:return False
    service=getattr(handler.product,'account_setup',None)
    if service is None:handler.send_error(404);return True
    try:
        if parsed.query or parsed.fragment:raise RuntimeFailure('ACCOUNT_AUTHORITY_DENIED')
        auth=handler.require_actor()
        if auth is None:return True
        if method=='POST':
            fields=handler.urlencoded()
            if parsed.path!='/account-access/request' or handler.headers.get('Origin')!=handler.product.origin or not secrets.compare_digest(fields.get('csrf',''),auth.csrf_token):raise RuntimeFailure('ACCOUNT_AUTHORITY_DENIED')
            if set(fields)!={'csrf','connection'}:raise RuntimeFailure('ACCOUNT_AUTHORITY_DENIED')
            service.request_owner(auth.actor,fields['connection'])
            body='<h1>Request sent to your team owners</h1><p>They can see that this account connection is needed in Capy. You do not need to handle credentials.</p>'
        elif method=='GET' and parsed.path=='/account-access':
            view=service.account_requests(auth.actor)
            body='<h1>FedEx account connection</h1>'
            if not view['connections']:body+='<p>No account connection is available in this workspace.</p>'
            elif view['owner']:
                body+='<p>'+str(view['pending_requests'])+' team member requests are waiting. Connect FedEx from your saved application preview.</p><p><a href="/applications">Open apps</a></p>'
            else:
                body+='<p>A team owner can connect this account for your workspace.</p>'
                for cid in view['connections']:
                    body+='<form method="post" action="/account-access/request"><input type="hidden" name="csrf" value="'+html.escape(auth.csrf_token,quote=True)+'"><input type="hidden" name="connection" value="'+html.escape(cid,quote=True)+'"><button>Ask a team owner to connect FedEx</button></form>'
        else:handler.send_error(404);return True
        handler.send_html('<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Account connection · Capy</title><body><main>'+body+'<p><a href="/">Return to Capy</a></p></main></body></html>',script_sha256=None)
    except RuntimeFailure:handler.send_html('<h1>This account request is unavailable</h1>',403,script_sha256=None)
    return True
