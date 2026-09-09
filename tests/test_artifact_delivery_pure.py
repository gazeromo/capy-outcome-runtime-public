import base64, hashlib, unittest
from capy_outcome_runtime.consumer_mcp import Consumer

class PortableArtifactChecks(unittest.TestCase):

    def test_metadata_validation(self):
        item = dict(filename='item.txt', digest=hashlib.sha256(b'one').hexdigest(), size_bytes=3)
        Consumer._validate_artifact(item)
        for key, value in [('digest', 'z' * 64), ('filename', None), ('size_bytes', True), ('size_bytes', -1)]:
            with self.assertRaisesRegex(ValueError, 'ARTIFACT_METADATA_INVALID'):
                Consumer._validate_artifact({**item, key: value})

    def test_decode_digest_size_and_base64(self):
        item = dict(filename='item.txt', digest=hashlib.sha256(b'one').hexdigest(), size_bytes=3)
        self.assertEqual(b'one', Consumer._decode_artifact(dict(base64=base64.b64encode(b'one').decode()), item))
        for value, error in [(dict(base64='!'), 'ARTIFACT_BASE64_INVALID'), (dict(base64=base64.b64encode(b'two').decode()), 'ARTIFACT_DIGEST_MISMATCH')]:
            with self.assertRaisesRegex(ValueError, error):
                Consumer._decode_artifact(value, item)
        with self.assertRaisesRegex(ValueError, 'ARTIFACT_SIZE_MISMATCH'):
            Consumer._decode_artifact(dict(base64=base64.b64encode(b'one').decode()), {**item, 'size_bytes': 4})

    def test_remote_projection_without_filesystem_or_execution(self):
        consumer = Consumer.__new__(Consumer)
        consumer.output_directory = None
        item = dict(filename='item.txt', digest=hashlib.sha256(b'one').hexdigest(), size_bytes=3)
        result = dict(id='existing', execution_state='succeeded', result={'truth': 'preserved'}, artifacts=[item, item])
        value = consumer._complete_artifacts(result)
        self.assertEqual('remote_only', value['artifact_delivery']['status'])
        self.assertEqual(2, value['artifact_delivery']['expected_count'])
        self.assertEqual(0, value['artifact_delivery']['delivered_count'])
        self.assertEqual(result['result'], value['result'])
