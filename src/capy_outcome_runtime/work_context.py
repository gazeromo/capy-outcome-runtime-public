"""Read-only work retrieval over existing authority-owned records.

An index entry grants nothing. Every resolver revalidates current access; this
module never invokes an app, reads account custody, or copies domain data.
"""
from datetime import datetime
from urllib.parse import quote

from .model import RuntimeFailure


def outcome_label(result, *, artifacts=(), process_status='succeeded'):
    if process_status == 'failed':
        return 'Could not finish'
    if process_status != 'succeeded':
        return 'Status unconfirmed'
    status = result.get('status') if isinstance(result, dict) else None
    if status in {'needs_input', 'input_required'}:
        return 'Needs you'
    if status in {'failed', 'error', 'rejected'}:
        return 'Could not finish'
    if status in {'unknown', 'uncertain', 'unconfirmed'}:
        return 'Status unconfirmed'
    if status in {'active', 'paused', 'cancelled', 'expired', 'waiting'}:
        return status.title()
    if isinstance(result, dict) and result.get('provider_status') == 'not_queried':
        return 'Could not finish'
    if status in {'ok', 'success', 'succeeded', 'ready', 'completed', 'quoted'} or artifacts:
        return 'Ready'
    # Unrecognized domain outcomes are not proof of finite business completion.
    return 'Result recorded'


def completed_request_label(request):
    """A saved invocation is not necessarily a completed business outcome."""
    outcome = request.get('outcome')
    if not outcome:
        return 'Status unconfirmed'
    label = outcome_label(outcome.get('result'), artifacts=outcome.get('artifacts', ()))
    return 'Needs more information' if label == 'Needs you' else label


def _time(value):
    try:
        return float(value)
    except (TypeError, ValueError):
        try:
            return datetime.fromisoformat(str(value).replace('Z', '+00:00')).timestamp()
        except ValueError:
            return 0


def recent_work(product, actor, limit=30):
    with product.access_store.guarded_actor(actor) as current:
        rows = []
        def add(title, href, state, when, kind):
            rows.append(dict(title=title, href=href, state=state, updated_at=when,
                             kind=kind, workspace='Personal' if current.workspace_kind == 'personal' else current.team_name))
        for item in product.chat_store.list_conversations(current):
            add(item.get('title') or 'Conversation', '/?conversation='+quote(item['id'],safe=''),
                'Conversation', item.get('updated_at'), 'chat')
        service = getattr(product, 'application_interfaces', None)
        if service:
            with service.runtime_store.connect() as db:
                activities = db.execute('''SELECT id,application_id FROM interface_activities
                    WHERE principal_id=? AND membership_id=? AND team_id=? AND scope_id=?
                    ORDER BY created_at DESC LIMIT ?''', (current.principal_id,current.membership_id,
                    current.team_id,current.execution_scope_id,limit)).fetchall()
            for item in activities:
                try:
                    result = service.activity(current,item['application_id'],item['id'])
                    contract = service.contract_resolver(current,item['application_id'])
                except RuntimeFailure:
                    continue
                add(contract['title'], '/applications/'+quote(item['application_id'],safe='')+'/activity/'+item['id']+'?workspace='+quote(current.membership_id,safe=''),
                    outcome_label(result.get('result'),artifacts=result.get('artifacts'),process_status=result.get('status','succeeded')),
                    result.get('completed_at') or result.get('created_at'),'app')
        requests = getattr(product,'human_requests',None)
        if requests:
            for item in requests.list(current):
                add(item.get('title') or 'Saved request','/needs-you/'+quote(item['id'],safe=''),
                    completed_request_label(item) if item['status']=='completed' else {'waiting':'Needs you','saved':'Working'}.get(item['status'],item['status'].title()),
                    item.get('updated_at') or item.get('created_at'),'request')
        developer = getattr(product,'developer_link',None)
        if developer and (current.workspace_kind=='personal' or current.membership_kind=='owner'):
            _, changes=developer.listing(current)
            for change in changes:
                request=change['request']
                add('App change','/developer/requests/'+request['handoff_id'],
                    'Development: '+change['state'].replace('_',' ').lower(),change.get('received_at'),'development')
        workflow = getattr(product,'release_workflow',None)
        if workflow:
            with workflow.store.connect() as db:
                submissions = db.execute('SELECT id,created_at FROM release_submissions ORDER BY created_at DESC').fetchall()
            for item in submissions:
                try:
                    submission = workflow._row(item['id'],current)
                except RuntimeFailure:
                    continue
                owner = submission['owner']
                if owner['membership_id'] != current.membership_id or owner['workspace_id'] != current.team_id:
                    continue
                add('App preparation','/releases/submissions/'+item['id'],'Review current status',item['created_at'],'development')
                previews = getattr(product,'release_previews',None)
                if previews:
                    with workflow.store.connect() as db:
                        trials=db.execute('SELECT id FROM release_previews WHERE submission_id=? ORDER BY generation DESC',(item['id'],)).fetchall()
                    for trial in trials:
                        try:
                            preview=previews._row(current,trial['id'])
                        except RuntimeFailure:
                            continue
                        href='/releases/previews/'+trial['id']
                        add(preview['record'].get('title') or 'App trial',href+'?from=recent-work','Trial',item['created_at'],'trial')
        return sorted(rows,key=lambda x:_time(x['updated_at']),reverse=True)[:limit]


def linked_conversation(product, actor, handoff, conversation=None):
    """A scoped reference, not a copy of either work's state or authority."""
    with product.access_store.guarded_actor(actor) as current:
        product.developer_link.status(current,handoff)
        with product.runtime_store.connect() as db:
            if conversation is None and not db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='work_development_links'").fetchone():
                return None
            if conversation is not None:
                db.execute('''CREATE TABLE IF NOT EXISTS work_development_links (
                handoff_id TEXT PRIMARY KEY, conversation_id TEXT NOT NULL,
                principal_id TEXT NOT NULL, membership_id TEXT NOT NULL,
                    scope_id TEXT NOT NULL)''')
            if conversation is not None:
                with product.chat_store.connect() as chat_db:
                    product.chat_store._conversation(chat_db,current,conversation)
                db.execute('INSERT OR IGNORE INTO work_development_links VALUES (?,?,?,?,?)',
                    (handoff,conversation,current.principal_id,current.membership_id,current.execution_scope_id))
            row=db.execute('SELECT conversation_id FROM work_development_links WHERE handoff_id=? AND principal_id=? AND membership_id=? AND scope_id=?',
                (handoff,current.principal_id,current.membership_id,current.execution_scope_id)).fetchone()
        if row:
            with product.chat_store.connect() as chat_db:
                saved=product.chat_store._conversation(chat_db,current,row['conversation_id'])
            return {'id':row['conversation_id'],'title':saved['title'] or 'Original work','href':'/?conversation='+quote(row['conversation_id'],safe='')}
        return None


def attention_work(product, actor):
    """Only actions this actor can perform now; machine/maintainer waits stay out."""
    actions=[]
    with product.access_store.guarded_actor(actor) as current:
        workflow=getattr(product,'release_workflow',None)
        if workflow:
            with workflow.store.connect() as db:
                rows=db.execute('SELECT id FROM release_submissions ORDER BY created_at DESC').fetchall()
            for row in rows:
                try:
                    saved=workflow._row(row['id'],current)
                    if saved['owner']['membership_id']!=current.membership_id:continue
                    status=workflow.status(current,row['id'])
                except RuntimeFailure:
                    continue
                attempt=status.get('attempt') or {}
                if status['status']=='CANCELLED':continue
                if status['status']!='RECEIVED':
                    title='Confirm source delivery on your computer'
                elif status.get('profile') and not attempt and not status.get('check_action_pending'):
                    title='Review the prepared checks'
                elif attempt.get('status')=='ACCEPTED' and getattr(product,'release_connections',None):
                    setup=product.release_connections.view(current,row['id'])
                    if not setup or not setup['requirements'] or setup['preview_status']=='configured':continue
                    title='Review account-use permission'
                else:continue
                actions.append({'title':title,'href':'/releases/submissions/'+row['id']+('/connections' if title=='Review account-use permission' else '')})
        accounts=getattr(product,'account_setup',None)
        if accounts:
            requests=accounts.account_requests(current)
            if requests['owner'] and requests['pending_requests']:
                actions.append({'title':'Your team needs an account connection','href':'/account-access'})
    return actions


def attention_html(product, actor):
    import html
    actions=attention_work(product,actor)
    if not actions:return ''
    return '<section><h2>Decisions ready for you</h2><ul>'+''.join('<li><a href="'+html.escape(a['href'],quote=True)+'">'+html.escape(a['title'])+'</a></li>' for a in actions)+'</ul></section>'
