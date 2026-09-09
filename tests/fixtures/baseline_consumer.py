"""Thin stdio MCP consumer. Only HTTP and selected resource bytes cross the seam.

Protocol 2025-11-25; no database, runtime implementation, provider access,
installation, source transfer or authority administration imports.
"""
import argparse
import base64
import hashlib
import json
import os
import stat
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

VERSION='0.1.0-headless-v0'


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self,*args,**kwargs):
        return None


class Consumer:
    def __init__(self, origin, credential_file, output_directory=None):
        parsed=urllib.parse.urlsplit(origin)
        if (parsed.scheme!='http' or parsed.hostname!='127.0.0.1' or not parsed.port
                or parsed.username or parsed.password or parsed.path or parsed.query or parsed.fragment):
            raise ValueError('Exact loopback origin required')
        path=Path(credential_file)
        fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW)
        try:
            info=os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_uid!=os.getuid() or info.st_mode & 0o077:
                raise ValueError('Credential must be an owner-only regular file')
            self.token=os.read(fd,129).decode().strip()
            if not 32<=len(self.token)<=128:raise ValueError('Invalid credential')
        finally:
            os.close(fd)
        self.origin=origin
        self.http=urllib.request.build_opener(urllib.request.ProxyHandler({}),NoRedirect())
        self.output_directory=Path(output_directory) if output_directory else None
        self.operations={}

    def call(self,route,data):
        req=urllib.request.Request(self.origin+'/v0/'+route,data=json.dumps(data).encode(),
            headers={'Authorization':'Bearer '+self.token,'Content-Type':'application/json'})
        try:
            with self.http.open(req,timeout=90) as response:
                return json.loads(response.read(4*1024*1024))
        except urllib.error.HTTPError as exc:
            try:return {'error':json.loads(exc.read(4096)).get('error','CORE_REQUEST_FAILED')}
            except ValueError:return {'error':'CORE_REQUEST_FAILED'}
        except (OSError,ValueError):return {'error':'CORE_UNAVAILABLE'}

    def tools(self):
        surface=self.call('discover',{})
        self.operations={}
        if 'error' in surface:raise ValueError(surface['error'])
        def tool(name,description,properties,required):
            return dict(name=name,description=description,inputSchema=dict(type='object',properties=properties,
                required=required,additionalProperties=False))
        string={'type':'string'}
        tools=[tool('capy_context','Inspect current client, workspace and exact installed operation schemas.',{},[]),
            tool('capy_work','Retrieve recent authorized work and questions after reconnecting.',{},[]),
            tool('capy_upload_text','Upload explicitly selected UTF-8 text such as a CSV. Returns a scoped resource handle.',
                 dict(filename=string,text=string),['filename','text']),
            tool('capy_question','Retrieve a durable ordinary question without executing work.',dict(id=string),['id']),
            tool('capy_answer','Provide an ordinary nonsecret task fact. This cannot grant authority or approve effects.',
                 dict(id=string,generation={'type':'integer','minimum':1},answer=string),['id','generation','answer']),
            tool('capy_result','Retrieve an existing execution and its actual result without rerunning it.',dict(id=string),['id']),
            tool('capy_artifact','Retrieve authorized artifact bytes as base64, without executing software.',
                 dict(id=string,digest=string),['id','digest'])]
        for op in surface['operations']:
            identity={k:op[k] for k in ('app','operation','version')}
            name='capy_run_'+hashlib.sha256(json.dumps(identity,sort_keys=True).encode()).hexdigest()[:16]
            self.operations[name]=identity
            inputs=dict(op['input_schema'])
            inputs.pop('required',None) # Core validates; one supported missing fact becomes a question.
            resources=dict(type='object',properties={r['name']:dict(type='array',items=string,
                minItems=r['min_items'],maxItems=r['max_items']) for r in op['resources']},
                required=[r['name'] for r in op['resources']],additionalProperties=False)
            tools.append(tool(name,op['title']+'. '+op['description']+
                ' Runs installed software on Capy. One missing required ordinary field may return a durable question. '
                'Reuse the same key only for identical inputs; changed inputs require a new key.',
                dict(inputs=inputs,resources=resources,key=dict(type='string',minLength=1,maxLength=128,pattern='^[A-Za-z0-9:._-]+$')),
                ['inputs','resources','key']))
        return tools

    def invoke(self,name,args):
        if name in self.operations:
            return self.call('invoke',dict(operation=self.operations[name],**args))
        if name=='capy_work':return self.call('work',{})
        if name=='capy_context':return self.call('discover',{})
        if name=='capy_upload_text':
            return self.call('upload',dict(filename=args['filename'],base64=base64.b64encode(args['text'].encode()).decode()))
        routes={'capy_question':'question','capy_answer':'answer','capy_result':'result','capy_artifact':'artifact'}
        if name not in routes:raise ValueError('Unknown consumer tool')
        value=self.call(routes[name],args)
        if name=='capy_artifact' and self.output_directory is not None and not value.get('error'):
            payload=base64.b64decode(value['base64'],validate=True)
            digest=hashlib.sha256(payload).hexdigest()
            if digest != args['digest']:return {'error':'ARTIFACT_DIGEST_MISMATCH'}
            suffix=Path(value['filename']).suffix
            if suffix not in {'.json','.html','.csv','.pdf','.txt'}:suffix='.bin'
            self.output_directory.mkdir(mode=0o700,parents=True,exist_ok=True)
            output=self.output_directory/(digest+suffix)
            fd=os.open(output,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600) if not output.exists() else None
            if fd is not None:
                with os.fdopen(fd,'wb') as f:f.write(payload)
            elif output.is_symlink() or output.read_bytes()!=payload:
                return {'error':'ARTIFACT_LOCAL_CONFLICT'}
            return dict(filename=value['filename'],digest=digest,size_bytes=len(payload),local_path=str(output.resolve()))
        return value


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--origin',required=True)
    parser.add_argument('--credential-file',required=True)
    parser.add_argument('--output-directory')
    args=parser.parse_args()
    consumer=Consumer(args.origin,args.credential_file,args.output_directory)
    while True:
        line=sys.stdin.buffer.readline(3*1024*1024+1)
        if not line:break
        if len(line)>3*1024*1024:break
        request={}
        try:
            request=json.loads(line)
            if 'id' not in request:continue
            method=request['method']
            if method=='initialize':
                result=dict(protocolVersion='2025-11-25',capabilities={'tools':{}},
                            serverInfo=dict(name='capy-consumer',version=VERSION))
            elif method=='ping':result={}
            elif method=='tools/list':result={'tools':consumer.tools()}
            elif method=='tools/call':
                try:
                    value=consumer.invoke(request['params']['name'],request['params'].get('arguments',{}))
                except OSError:
                    value={'error':'ARTIFACT_LOCAL_UNAVAILABLE'}
                result={'content':[{'type':'text','text':json.dumps(value)}],'isError':bool(value.get('error'))}
            else:
                raise ValueError('Unsupported method')
            reply=dict(jsonrpc='2.0',id=request['id'],result=result)
        except (ValueError,TypeError,KeyError):
            reply=dict(jsonrpc='2.0',id=request.get('id'),error=dict(code=-32602,message='Invalid consumer request'))
        print(json.dumps(reply),flush=True)

if __name__=='__main__':main()
