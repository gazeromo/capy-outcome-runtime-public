"""Integration regressions from independent product review; synthetic contracts."""
import tempfile
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
import pytest
from test_portable_interfaces import fixture
from actors import actor
from capy_outcome_runtime.portable_interfaces import project_portable
from capy_outcome_runtime.application_interfaces import ContractDerivedInterfaceService
from capy_outcome_runtime.store import RuntimeStore
from capy_outcome_runtime.chat import ChatStore
from capy_outcome_runtime.model import RuntimeFailure
from capy_outcome_runtime.web import Handler


def test_portable_reserved_names_and_watch_alias_submit_once(tmp_path):
    execution, interaction = fixture()
    execution['input_schema']={'type':'object','additionalProperties':False,'required':['csrf'],'properties':{'csrf':{'type':'string'}}}
    field={**interaction['operation']['request_fields'][2],'field_id':'csrf'}
    interaction['operation']['request_fields']=[field]
    interaction['operation']['operation_id']='watch.delete'
    interaction['boundaries'][0]['nearest_operation_ids']=['watch.delete']
    contract=project_portable(execution,interaction,'import-test')
    store=RuntimeStore(tmp_path/'runtime'); who=actor();store.register_scope(who.execution_scope_id)
    calls=[]
    def invoke(*args,**kwargs):
        calls.append((args,kwargs))
        return SimpleNamespace(invocation_id='a'*32,result={'stats':{'count':3,'ok':True}},artifacts=(),receipt={})
    service=ContractDerivedInterfaceService(store,ChatStore(tmp_path/'chat'),SimpleNamespace(invoke=invoke),None,lambda *_:contract)
    fields={'csrf':'runtime-token','application_version':contract['application_version'],'contract_digest':contract['digest'],'workspace_membership_id':who.membership_id,'submission':'s'*32,'__portable_form':'1','input.csrf':'app-value'}
    first=service.submit(who,execution['id'],'watch.delete',fields,{})
    second=service.submit(who,execution['id'],'watch.delete',fields,{})
    assert first==second and len(calls)==1
    assert calls[0][0][2]=={'csrf':'app-value'}


@pytest.mark.parametrize('body',[
    b'--b\r\nContent-Disposition: form-data; name="name"\r\n\r\nvalue',
    b'--b\r\nContent-Disposition: form-data; name="name"\r\n\r\n\xff\r\n--b--\r\n',
    b'--b\r\nContent-Disposition: form-data; name="name"\r\nContent-Type: multipart/mixed; boundary=x\r\n\r\n--x--\r\n--b--\r\n',
])
def test_malformed_multipart_is_causal(body):
    handler=Handler.__new__(Handler);handler.headers={'Content-Type':'multipart/form-data; boundary=b'};handler.body=lambda:body
    with pytest.raises(RuntimeFailure,match='HTTP_FORM_INVALID'):handler.multipart_named()


def test_download_uses_invocation_filename_and_disambiguates_equal_bytes():
    who=actor();record={'scope_id':who.execution_scope_id,'capability_id':'example.scalar','version_digest':'a'*64,'status':'succeeded','artifacts':[{'filename':'one.json','digest':'b'*64},{'filename':'two.json','digest':'b'*64}]}
    store=SimpleNamespace(invocation=lambda _:record,resource=lambda *_:(Path('/test/artifact'),'previous-upload.txt'))
    contract={'application_id':'example.scalar','application_version':'a'*64,'operations':[{'result':{'artifacts':['one.json','two.json']}}]}
    service=ContractDerivedInterfaceService(store,None,None,None,lambda *_:contract)
    assert service.artifact(who,'c'*32,'b'*64,'two.json')==(Path('/test/artifact'),'two.json')
    with pytest.raises(RuntimeFailure):service.artifact(who,'c'*32,'b'*64)
    with pytest.raises(RuntimeFailure):service.artifact(who,'c'*32,'b'*64,'outside.json')
