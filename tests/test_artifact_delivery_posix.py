"""Consumer completion: exact declarations, safe files, retries without execution."""
import base64
import copy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from capy_outcome_runtime.consumer_mcp import Consumer


class ArtifactDeliveryTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        self.root=Path(self.temp.name).resolve()
        self.consumer=Consumer.__new__(Consumer)
        self.consumer.output_directory=self.root/'output'
        self.consumer.operations={'capy_run_test':{'app':'generic'}}
        self.calls=[]
        self.responses={}
        self.result=dict(id='inv_test',execution_state='succeeded',business_outcome='not_inferred',
                         result={'truth':'preserved'},artifacts=[])
        self.denied=False
        def call(route,args):
            self.calls.append((route,args))
            if route in {'invoke','result'}:
                return {'error':'CORE_RESULT_DENIED'} if self.denied else copy.deepcopy(self.result)
            if route=='artifact':return copy.deepcopy(self.responses[args['digest']])
            if route=='answer':return {'id':'question','invocation_id':'inv_test','status':'answered'}
            return {'route':route,**args}
        self.consumer.call=call

    def tearDown(self):self.temp.cleanup()

    def add(self,name,payload):
        item=dict(filename=name,digest=hashlib.sha256(payload).hexdigest(),size_bytes=len(payload))
        self.result['artifacts'].append(item)
        self.responses[item['digest']]=dict(filename=name,base64=base64.b64encode(payload).decode())
        return item

    def run_result(self):return self.consumer.invoke('capy_result',{'id':'inv_test'})

    def test_zero_one_many_direct_and_manifest(self):
        self.assertEqual('complete',self.run_result()['artifact_delivery']['status'])
        for index in range(3):
            self.add('file'+str(index)+'.txt',str(index).encode())
            value=self.consumer.invoke('capy_run_test',{'key':str(index)})
            delivery=value['artifact_delivery']
            self.assertEqual(index+1,delivery['delivered_count'])
            self.assertEqual(self.result['result'],value['result'])
            for item in delivery['items']:
                self.assertEqual(item['digest'],hashlib.sha256(Path(item['local_path']).read_bytes()).hexdigest())
            projection=[{k:i[k] for k in ('filename','digest','size_bytes','status')} for i in delivery['items']]
            canonical=json.dumps(projection,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode()
            self.assertEqual(hashlib.sha256(canonical).hexdigest(),delivery['manifest_sha256'])

    def test_remote_only_and_answer_unchanged(self):
        self.consumer.output_directory=None
        self.assertEqual('complete',self.run_result()['artifact_delivery']['status'])
        self.add('one.csv',b'one')
        delivery=self.run_result()['artifact_delivery']
        self.assertEqual(('remote_only',0), (delivery['status'],delivery['delivered_count']))
        self.assertFalse(any(route=='artifact' for route,_ in self.calls))
        answer=self.consumer.invoke('capy_answer',{})
        self.assertEqual({'id':'question','invocation_id':'inv_test','status':'answered'},answer)

    def test_retry_missing_only_and_revocation(self):
        first=self.add('first.txt',b'first')
        second=self.add('second.json',b'second')
        good=self.responses[second['digest']]
        self.responses[second['digest']]={'error':'CORE_ARTIFACT_DENIED'}
        value=self.consumer.invoke('capy_run_test',{})
        self.assertEqual('ARTIFACT_DELIVERY_INCOMPLETE',value['error'])
        self.assertEqual('succeeded',value['execution_state'])
        self.responses[second['digest']]=good
        self.calls.clear()
        self.assertEqual('complete',self.run_result()['artifact_delivery']['status'])
        self.assertEqual(['result','artifact'],[r for r,_ in self.calls])
        self.assertEqual(second['digest'],self.calls[1][1]['digest'])
        self.denied=True
        self.calls.clear()
        self.assertEqual({'error':'CORE_RESULT_DENIED'},self.run_result())
        self.assertEqual(['result'],[r for r,_ in self.calls])

    def test_corrupt_base64_digest_size(self):
        item=self.add('one.txt',b'one')
        original=copy.deepcopy(self.responses[item['digest']])
        for response,error in [(dict(base64='!'),'ARTIFACT_BASE64_INVALID'),
                               (dict(base64=base64.b64encode(b'wrong').decode()),'ARTIFACT_DIGEST_MISMATCH')]:
            self.responses[item['digest']]=response
            self.assertEqual(error,self.run_result()['artifact_delivery']['items'][0]['error'])
        self.responses[item['digest']]=original
        item['size_bytes']+=1
        self.assertEqual('ARTIFACT_SIZE_MISMATCH',self.run_result()['artifact_delivery']['items'][0]['error'])

    def test_names_duplicates_and_canonical_paths_excluded(self):
        self.add('../../escape.txt',b'same')
        self.add('/other/name.txt',b'same')
        self.add('unexpected.exe',b'other')
        first=self.run_result()['artifact_delivery']
        self.assertEqual(3,first['delivered_count'])
        self.assertEqual(2,len(list(self.consumer.output_directory.iterdir())))
        self.assertTrue(first['items'][2]['local_path'].endswith('.bin'))
        self.consumer.output_directory=self.root/'elsewhere'
        second=self.run_result()['artifact_delivery']
        self.assertEqual(first['manifest_sha256'],second['manifest_sha256'])

    def test_local_conflict_and_symlinks(self):
        item=self.add('one.txt',b'one')
        self.consumer.output_directory.mkdir()
        output=self.consumer.output_directory/(item['digest']+'.txt')
        output.write_bytes(b'bad')
        self.assertEqual('ARTIFACT_LOCAL_CONFLICT',self.run_result()['artifact_delivery']['items'][0]['error'])
        output.unlink()
        target=self.root/'target';target.write_bytes(b'one')
        output.symlink_to(target)
        self.assertEqual('ARTIFACT_LOCAL_CONFLICT',self.run_result()['artifact_delivery']['items'][0]['error'])
        output.unlink();self.consumer.output_directory.rmdir()
        self.consumer.output_directory.symlink_to(self.root,target_is_directory=True)
        self.assertEqual('ARTIFACT_LOCAL_UNAVAILABLE',self.run_result()['artifact_delivery']['items'][0]['error'])
        self.assertEqual(b'one',target.read_bytes())

    def test_unavailable_mid_delivery_preserves_successes(self):
        self.add('first.txt',b'first');self.add('second.txt',b'second')
        original=self.consumer._output_fd
        count=0
        def directory():
            nonlocal count
            count+=1
            if count>2:raise OSError('unavailable')
            return original()
        with patch.object(self.consumer,'_output_fd',directory):value=self.run_result()
        self.assertEqual('succeeded',value['execution_state'])
        self.assertEqual(1,value['artifact_delivery']['delivered_count'])
        self.assertEqual('ARTIFACT_LOCAL_UNAVAILABLE',value['artifact_delivery']['items'][1]['error'])

    def test_retry_rechecks_local_bytes_and_missing_file(self):
        self.add('one.txt',b'one')
        first=self.run_result()
        path=Path(first['artifact_delivery']['items'][0]['local_path'])
        path.write_bytes(b'bad')
        self.assertEqual('ARTIFACT_LOCAL_CONFLICT',self.run_result()['artifact_delivery']['items'][0]['error'])
        path.unlink();self.calls.clear()
        self.assertEqual('complete',self.run_result()['artifact_delivery']['status'])
        self.assertEqual(['result','artifact'],[route for route,_ in self.calls])

    def test_explicit_artifact_reauthorizes_and_context_separate(self):
        item=self.add('one.txt',b'one')
        self.run_result();self.calls.clear()
        value=self.consumer.invoke('capy_artifact',{'id':'inv_test','digest':item['digest']})
        self.assertIn('local_path',value)
        self.assertEqual('artifact',self.calls[0][0])
        self.assertEqual({'route':'context','query':'hello'},self.consumer.invoke('capy_context',{'query':'hello'}))


