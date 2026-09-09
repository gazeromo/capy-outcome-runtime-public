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

VERSION='0.1.1-bounded-context-v0'


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
        tools=[tool('capy_context','Search the software currently available to this Capy client before manually implementing domain work or concluding that no suitable capability exists. Returns a bounded authorized relevance slice. Use the cursor when more matches are available.',
            dict(query=dict(type='string',minLength=1,maxLength=2048),
                 cursor=dict(type='string',minLength=1,maxLength=16384)),[]),
            tool('capy_work','Retrieve recent authorized work and questions after reconnecting.',{},[]),
            tool('capy_upload_text','Upload explicitly selected UTF-8 text such as a CSV. Returns a scoped resource handle.',
                 dict(filename=string,text=string),['filename','text']),
            tool('capy_question','Retrieve a durable ordinary question without executing work.',dict(id=string),['id']),
            tool('capy_answer','Provide an ordinary nonsecret task fact. This cannot grant authority or approve effects.',
                 dict(id=string,generation={'type':'integer','minimum':1},answer=string),['id','generation','answer']),
            tool('capy_result','Retrieve an existing execution and its actual result without rerunning it. If artifact delivery is incomplete, call capy_result with the returned invocation ID to retry retrieval. Do not rerun the application merely to download its existing artifacts.',dict(id=string),['id']),
            tool('capy_artifact','Retrieve authorized artifact bytes as base64, without executing software. With an output directory, verify and materialize this artifact. Use capy_result to retry complete delivery without rerunning the application.',
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
            return self._complete_artifacts(self.call('invoke',dict(operation=self.operations[name],**args)))
        if name=='capy_work':return self.call('work',{})
        if name=='capy_context':return self.call('context',args)
        if name=='capy_upload_text':
            return self.call('upload',dict(filename=args['filename'],base64=base64.b64encode(args['text'].encode()).decode()))
        routes={'capy_question':'question','capy_answer':'answer','capy_result':'result','capy_artifact':'artifact'}
        if name not in routes:raise ValueError('Unknown consumer tool')
        value=self.call(routes[name],args)
        if name=='capy_result':return self._complete_artifacts(value)
        if name=='capy_artifact' and self.output_directory is not None and not value.get('error'):
            try:
                try:payload=base64.b64decode(value['base64'],validate=True)
                except (ValueError,TypeError,KeyError):raise ValueError('ARTIFACT_BASE64_INVALID') from None
                metadata=dict(filename=value['filename'],digest=args['digest'],size_bytes=len(payload))
                self._validate_artifact(metadata)
                payload=self._decode_artifact(value,metadata)
                return dict(metadata,local_path=self._materialize(metadata,payload))
            except (ValueError,KeyError,TypeError) as exc:
                return {'error':str(exc) if isinstance(exc,ValueError) else 'ARTIFACT_METADATA_INVALID'}
            except OSError:
                return {'error':'ARTIFACT_LOCAL_UNAVAILABLE'}
        return value

    @staticmethod
    def _validate_artifact(item):
        digest=item['digest']
        if (not isinstance(digest,str) or len(digest)!=64 or
                any(c not in '0123456789abcdef' for c in digest) or
                not isinstance(item['filename'],str) or
                type(item['size_bytes']) is not int or item['size_bytes']<0):
            raise ValueError('ARTIFACT_METADATA_INVALID')

    @staticmethod
    def _decode_artifact(value,item):
        try:
            payload=base64.b64decode(value['base64'],validate=True)
        except (ValueError,TypeError,KeyError):
            raise ValueError('ARTIFACT_BASE64_INVALID') from None
        if hashlib.sha256(payload).hexdigest()!=item['digest']:
            raise ValueError('ARTIFACT_DIGEST_MISMATCH')
        if len(payload)!=item['size_bytes']:
            raise ValueError('ARTIFACT_SIZE_MISMATCH')
        return payload

    def _output_fd(self):
        # Walk from the filesystem root using directory descriptors: neither an
        # existing component nor a replacement symlink can redirect a write.
        output=Path(os.path.abspath(self.output_directory))
        fd=os.open(output.anchor,os.O_RDONLY|os.O_DIRECTORY)
        try:
            for component in output.parts[1:]:
                try:os.mkdir(component,mode=0o700,dir_fd=fd)
                except FileExistsError:pass
                child=os.open(component,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=fd)
                os.close(fd)
                fd=child
            return fd,output
        except BaseException:
            os.close(fd)
            raise

    def _materialize(self,item,payload=None):
        suffix=Path(item['filename']).suffix
        if suffix not in {'.json','.html','.csv','.pdf','.txt'}:suffix='.bin'
        name=item['digest']+suffix
        directory,output=self._output_fd()
        try:
            try:
                fd=os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=directory)
            except FileNotFoundError:
                if payload is None:return None
                try:
                    fd=os.open(name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=directory)
                except FileExistsError:
                    raise ValueError('ARTIFACT_LOCAL_CONFLICT') from None
                try:
                    with os.fdopen(fd,'wb') as stream:
                        stream.write(payload)
                        stream.flush()
                        os.fsync(stream.fileno())
                except BaseException:
                    os.unlink(name,dir_fd=directory)
                    raise
                return str(output/name)
            except OSError:
                raise ValueError('ARTIFACT_LOCAL_CONFLICT') from None
            with os.fdopen(fd,'rb') as stream:
                info=os.fstat(stream.fileno())
                if not stat.S_ISREG(info.st_mode) or info.st_size!=item['size_bytes']:
                    raise ValueError('ARTIFACT_LOCAL_CONFLICT')
                # Stream verification avoids trusting or allocating a large local file.
                digest=hashlib.sha256()
                for block in iter(lambda:stream.read(65536),b''):digest.update(block)
                if digest.hexdigest()!=item['digest']:
                    raise ValueError('ARTIFACT_LOCAL_CONFLICT')
            return str(output/name)
        finally:
            os.close(directory)

    def _complete_artifacts(self,value):
        if value.get('error') or 'execution_state' not in value or 'artifacts' not in value:
            return value
        items=[]
        for declared in value['artifacts']:
            item={k:declared.get(k) for k in ('filename','digest','size_bytes')}
            try:
                self._validate_artifact(item)
                if self.output_directory is None:
                    item['status']='remote_only'
                else:
                    local=self._materialize(item)
                    if local is None:
                        response=self.call('artifact',dict(id=value['id'],digest=item['digest']))
                        if response.get('error'):raise ValueError(response['error'])
                        local=self._materialize(item,self._decode_artifact(response,item))
                    item.update(status='verified',local_path=local)
            except (ValueError,KeyError,TypeError) as exc:
                item.update(status='failed',error=str(exc) if isinstance(exc,ValueError) else 'ARTIFACT_METADATA_INVALID')
            except OSError:
                item.update(status='failed',error='ARTIFACT_LOCAL_UNAVAILABLE')
            items.append(item)
        projection=[{k:item[k] for k in ('filename','digest','size_bytes','status')} for item in items]
        manifest=hashlib.sha256(json.dumps(projection,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode()).hexdigest()
        failed=any(item['status']=='failed' for item in items)
        status='incomplete' if failed else ('remote_only' if items and self.output_directory is None else 'complete')
        delivery=dict(status=status,expected_count=len(items),delivered_count=sum(i['status']=='verified' for i in items),
                      manifest_sha256=manifest,items=items)
        completed=dict(value,artifact_delivery=delivery)
        if failed:completed['error']='ARTIFACT_DELIVERY_INCOMPLETE'
        return completed



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
