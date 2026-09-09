"""Private encrypted account custody. Only the dedicated trusted service uses it.

No runtime DB, model channel, app environment or public endpoint receives values.
Fernet is the standard authenticated encryption primitive; its deployment key is
supplied by systemd's encrypted credential facility, never stored beside data.
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import tempfile
import threading
import time
from pathlib import Path

from cryptography.fernet import Fernet, InvalidToken

from .model import RuntimeFailure
from .store import canonical_json

TTL = 3600
ID = re.compile(r'[a-zA-Z0-9_.:-]{1,128}')
STATUSES = frozenset({'account_required','verification_pending','account_rejected',
    'origin_required','ready_to_continue','connected','account_rates_unverified',
    'expired','cancelled','service_unavailable','reconnect_required','provider_rejected'})


def fail():
    raise RuntimeFailure('ACCOUNT_SERVICE_UNAVAILABLE') from None


class AccountVault:
    def __init__(self, root, key, adapter, authorize, *, clock=time.time):
        self.root=Path(root)
        self.root.mkdir(mode=0o700,parents=True,exist_ok=True)
        st=self.root.lstat()
        if self.root.is_symlink() or st.st_uid!=os.geteuid() or st.st_mode & 0o077: fail()
        self.cipher=Fernet(key)
        self.adapter,self.authorize,self.clock=adapter,authorize,clock
        self.lock=threading.RLock()

    def _path(self, connection):
        if not isinstance(connection,str) or ID.fullmatch(connection) is None: fail()
        return self.root/(connection+'.sealed')

    def _load(self, connection):
        p=self._path(connection)
        try:
            st=p.lstat()
            if p.is_symlink() or not p.is_file() or st.st_uid!=os.geteuid() or st.st_mode&0o077: fail()
            if st.st_size>256*1024: fail()
            data=json.loads(self.cipher.decrypt(p.read_bytes()))
            if not isinstance(data,dict) or set(data)!={'generation','active','pending','requests'}: fail()
            return data
        except FileNotFoundError:
            return {'generation':0,'active':None,'pending':None,'requests':{}}
        except (ValueError,InvalidToken,OSError): fail()

    def _save(self, connection, data):
        destination=self._path(connection)
        fd,name=tempfile.mkstemp(prefix='.sealed-',dir=self.root)
        try:
            os.fchmod(fd,0o600)
            with os.fdopen(fd,'wb') as f:
                f.write(self.cipher.encrypt(canonical_json(data)));f.flush();os.fsync(f.fileno())
            os.replace(name,destination)
            fd=os.open(self.root,os.O_RDONLY)
            try:os.fsync(fd)
            finally:os.close(fd)
        finally:Path(name).unlink(missing_ok=True)

    def _expire(self, data):
        now=self.clock()
        pending=data['pending']
        if pending and pending['expires_at']<=now:
            row=data['requests'].get(pending['request_id'])
            if row:row['status']='expired'
            data['pending']=None
        # Only bounded non-secret progress receipts remain after secret expiry.
        if len(data['requests'])>32:
            keep=sorted(data['requests'],key=lambda k:data['requests'][k]['created_at'],reverse=True)[:32]
            data['requests']={k:data['requests'][k] for k in keep}

    def inspect(self, context):
        with self.lock:
            data=self._load(context['connection_id']);self._expire(data)
            self._save(context['connection_id'],data)
            active=data['active'];pending=data['pending']
            row=data['requests'].get(context['request_id'])
            status=row['status'] if row else ('connected' if active and active['authenticated'] else 'account_required')
            if active and not active['authenticated'] and not row:status='reconnect_required'
            origin=(pending.get('origin') if pending and pending['request_id']==context['request_id'] else None) or (active.get('origin') if active else None)
            return {'status':status,'generation':data['generation'], 'has_active_account':bool(active and active['authenticated']),
                'provider_problem':row.get('provider_problem') if row else None,
                'origin':origin, 'expires_at':pending['expires_at'] if pending and pending['request_id']==context['request_id'] else None}

    def stage(self, context, values, nonce, generation):
        from capy_connections.fedex_rates import validate_secret
        required={'client_id','client_secret','account_number'}
        if context['account_mode']=='child': required|={'child_key','child_secret'}
        if not isinstance(values,dict) or set(values)!=required or not isinstance(nonce,str) or not re.fullmatch('[0-9a-f]{32}',nonce):
            raise RuntimeFailure('ACCOUNT_INPUT_INVALID')
        secret={k:values[k] for k in ('client_id','client_secret','account_number')}
        secret['environment']=context['environment']
        if context['account_mode']=='child':secret['child_credentials']={k:values[k] for k in ('child_key','child_secret')}
        try:secret=validate_secret(secret)
        except Exception:raise RuntimeFailure('ACCOUNT_INPUT_INVALID') from None
        digest=hashlib.sha256(canonical_json(secret)).hexdigest()
        with self.lock:
            data=self._load(context['connection_id']);self._expire(data)
            row=data['requests'].get(context['request_id'])
            if row and row['nonce']==nonce:
                if row['digest']!=digest:raise RuntimeFailure('ACCOUNT_REQUEST_CHANGED')
                return self.inspect(context)
            if type(generation) is not int or generation!=data['generation']:
                raise RuntimeFailure('ACCOUNT_REQUEST_CHANGED')
            pending=data['pending']
            if pending and pending['request_id']!=context['request_id']:
                raise RuntimeFailure('ACCOUNT_SETUP_IN_PROGRESS')
            expires=self.clock()+TTL
            data['pending']={'request_id':context['request_id'],'nonce':nonce,'secret':secret,
                'origin':data['active']['origin'] if data['active'] else None,
                'authenticated':False,'expires_at':expires,'generation':generation}
            data['requests'][context['request_id']]={'nonce':nonce,'digest':digest,'status':'verification_pending','created_at':self.clock()}
            self._save(context['connection_id'],data)
            return self.inspect(context)

    def authenticate(self, context):
        with self.lock:
            data=self._load(context['connection_id']);self._expire(data);self._save(context['connection_id'],data)
            pending=data['pending']
            if not pending or pending['request_id']!=context['request_id']:return self.inspect(context)
            nonce=pending['nonce'];secret=pending['secret']
        self.authorize(context['request_id'])
        try:
            self.adapter.authenticate(secret)
            outcome='accepted'
        except Exception as exc:
            outcome='rejected' if getattr(exc,'code',None)=='FEDEX_AUTHENTICATION_FAILED' else 'pending'
        # Current authorization is checked again before any durable acceptance.
        self.authorize(context['request_id'])
        with self.lock:
            data=self._load(context['connection_id']);self._expire(data)
            current=data['pending']
            if not current or current['nonce']!=nonce or current['request_id']!=context['request_id']:
                return self.inspect(context)
            row=data['requests'][context['request_id']]
            if outcome=='rejected':
                data['pending']=None;row['status']='account_rejected'
            elif outcome=='accepted':
                current['authenticated']=True
                row['status']='ready_to_continue' if current['origin'] else 'origin_required'
            else:row['status']='verification_pending'
            self._save(context['connection_id'],data)
        return self.inspect(context)

    def origin(self, context, values):
        from capy_connections.fedex_rates_v2 import validate_profile
        try:origin=validate_profile(values)
        except Exception:raise RuntimeFailure('ACCOUNT_ORIGIN_INVALID') from None
        with self.lock:
            data=self._load(context['connection_id']);self._expire(data)
            pending=data['pending']
            if not pending or pending['request_id']!=context['request_id'] or not pending['authenticated']:
                raise RuntimeFailure('ACCOUNT_REQUEST_CHANGED')
            pending['origin']=origin
            data['requests'][context['request_id']]['status']='ready_to_continue'
            self._save(context['connection_id'],data)
        return self.inspect(context)

    def cancel(self, context):
        with self.lock:
            data=self._load(context['connection_id'])
            pending=data['pending']
            if pending and pending['request_id']==context['request_id']:
                data['pending']=None
                data['requests'][context['request_id']]['status']='cancelled'
            self._save(context['connection_id'],data)
        return self.inspect(context)

    def quote(self, authority, payload):
        """Called only after broker and current runtime authority have both checked.

        A pending replacement is visible solely to its exact continuing preview.
        Other authorized applications keep using the validated active generation.
        """
        connection=authority['connection_id'];sid=authority.get('setup_request_id')
        with self.lock:
            data=self._load(connection);self._expire(data);self._save(connection,data)
            pending=data['pending']
            use_pending=bool(sid and pending and pending['request_id']==sid)
            account=pending if use_pending else data['active']
            if not account or not account['authenticated'] or not account.get('origin'):
                raise RuntimeFailure('ACCOUNT_SETUP_REQUIRED')
            generation=data['generation'];nonce=account.get('nonce')
            secret,profile=account['secret'],account['origin']
        if use_pending:self.authorize(sid)
        try:
            result=self.adapter.call(contract=authority.get('contract','fedex.rates/v1'),operation='quote',secret=secret,profile=profile,payload=payload)
        except Exception as exc:
            code=getattr(exc,'code',None)
            # Diagnose using fixed classifications only, never exception text,
            # provider payloads, credentials or origin/account values.
            diagnostic_codes={'FEDEX_ADAPTER_INPUT_INVALID','FEDEX_PROFILE_INVALID',
                'FEDEX_PROFILE_INCOMPLETE','FEDEX_PROVIDER_RESPONSE_INVALID',
                'FEDEX_RESPONSE_TOO_LARGE','FEDEX_REQUEST_TOO_LARGE',
                'FEDEX_REDIRECT_DENIED','CONNECTION_OPERATION_DENIED',
                'FEDEX_AUTHENTICATION_FAILED','FEDEX_PROVIDER_UNAVAILABLE',
                'FEDEX_RATE_REJECTED','FEDEX_NO_RATES_RETURNED'}
            logging.getLogger(__name__).warning('Account quote classification: %s',
                code if isinstance(code,str) and code in diagnostic_codes else 'UNCLASSIFIED')
            problem=getattr(exc,'provider_problem',None)
            if use_pending and isinstance(problem,dict) and {'http_status','reason'}<=set(problem)<={'http_status','reason','provider_code','phase','response_kind'} and problem['http_status'] in {400,401,403,404,422} and problem['reason'] in {'request_rejected','account_not_linked','access_denied','ship_date','customs_required'} and ('provider_code' not in problem or isinstance(problem['provider_code'],str) and re.fullmatch(r'[A-Z0-9][A-Z0-9_.-]{1,95}',problem['provider_code'])) and problem.get('phase','rates') in {'rates','authorization'} and problem.get('response_kind','json_errors') in {'json_errors','json_other','non_json'}:
                with self.lock:
                    data=self._load(connection)
                    if data['pending'] and data['pending']['request_id']==sid:
                        data['requests'][sid].update(status='provider_rejected',provider_problem=problem)
                        self._save(connection,data)
            # A generic outage or rejected quote never invalidates stored keys.
            if code=='FEDEX_AUTHENTICATION_FAILED' and not use_pending:
                with self.lock:
                    data=self._load(connection)
                    if data['generation']==generation and data['active']:
                        data['active']['authenticated']=False;self._save(connection,data)
            allowed={'FEDEX_AUTHENTICATION_FAILED','FEDEX_PROVIDER_UNAVAILABLE','FEDEX_RATE_REJECTED','FEDEX_NO_RATES_RETURNED'}
            raise RuntimeFailure(code if code in allowed else 'ACCOUNT_VERIFICATION_PENDING') from None
        from .connections import ConnectionBroker
        ConnectionBroker._reject_secret_reflection(result,secret)
        account_rates=any(isinstance(r,dict) and 'account_total' in r for r in result.get('rates',[]))
        if use_pending:
            self.authorize(sid)
            with self.lock:
                data=self._load(connection);self._expire(data)
                pending=data['pending']
                if not pending or pending['request_id']!=sid or pending['nonce']!=nonce or data['generation']!=generation:
                    raise RuntimeFailure('ACCOUNT_REQUEST_CHANGED')
                if account_rates:
                    data['active']={'secret':secret,'origin':profile,'authenticated':True}
                    data['pending']=None;data['generation']+=1
                    data['requests'][sid]['status']='connected'
                else:data['requests'][sid]['status']='account_rates_unverified'
                self._save(connection,data)
        return result

    def expire_all(self):
        with self.lock:
            for path in self.root.glob('*.sealed'):
                connection=path.name.removesuffix('.sealed')
                data=self._load(connection);self._expire(data);self._save(connection,data)
