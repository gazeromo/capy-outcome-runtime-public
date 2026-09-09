"""Public pure discovery qualification, extracted from the accepted test bodies."""
import base64, copy, hashlib, json, os, random, subprocess, unittest
from pathlib import Path
from capy_outcome_runtime.context_search import context_page, normalize, rank
from capy_outcome_runtime.consumer_mcp import Consumer
from capy_outcome_runtime.model import RuntimeFailure
os.environ['CAPY_BASELINE_CONSUMER'] = str(Path(__file__).parent/'fixtures/baseline_consumer.py')
def catalog(count=192):
    return [dict(app=f'app.{i:03}', operation='report.generate', version='a' * 64, title=f'Report {i}', description='Generate financial report', input_schema={'type': 'object', 'properties': {'accountCode': {'type': 'string', 'description': 'customer identifier'}}, 'required': ['accountCode']}, resources=[{'name': 'source', 'min_items': 1, 'max_items': 1}], effect='artifact_generation', human_fields=[{'field': 'period', 'label': 'Reporting period'}], connection_required=False, readiness={'status': 'ready'}) for i in range(count)]
ENVELOPE = dict(contract='capy.core/v0', build='b' * 64, server='server', client='c' * 64, workspace='workspace')

class SearchTests(unittest.TestCase):

    def test_normalization_and_generic_fields(self):
        self.assertEqual(['csv', 'product', 'code', 'product', 'code', 'price', 'list', 'sku', '001', '한국', 'é', 'x', '2'], normalize('CSV product_code ProductCode price-list SKU 001 한국 É / x2'))
        for query in ('Report', 'generate', 'financial', 'customer', 'accountCode', 'source', 'period'):
            self.assertEqual(192, len(rank(catalog(), normalize(query))))
        self.assertEqual([], rank(catalog(), normalize('unrelated')))

    def test_shuffle_rank_digest_and_all_pages(self):
        ops = catalog()
        expected = rank(ops, normalize('financial report'))
        first = context_page(ops, ENVELOPE, query='financial report')
        for seed in range(5):
            shuffled = copy.deepcopy(ops)
            random.Random(seed).shuffle(shuffled)
            self.assertEqual(expected, rank(shuffled, normalize('financial report')))
            self.assertEqual(first, context_page(shuffled, ENVELOPE, query='financial report'))
        seen = []
        page = first
        while True:
            self.assertLessEqual(page['returned'], 8)
            self.assertLessEqual(len(json.dumps(page).encode()), 16384)
            seen.extend((x['app'] for x in page['results']))
            if page['next_cursor'] is None:
                break
            page = context_page(ops, ENVELOPE, cursor=page['next_cursor'])
        self.assertEqual([op['app'] for op, _ in expected], seen)

    def test_overview_empty_and_large_metadata_unicode(self):
        ops = catalog(9)
        ops[0]['title'] = '한' * 10000
        ops[0]['description'] = 'é' * 10000
        page = context_page(ops, ENVELOPE)
        self.assertTrue(page['results'][0]['fields_compacted'])
        self.assertLessEqual(len(json.dumps(page).encode()), 16384)
        self.assertEqual(0, context_page(ops, ENVELOPE, query='!!!')['total_matches'])
        self.assertEqual(0, context_page([], ENVELOPE)['returned'])
        for query in ('ﷺ' * 2048, '𐐀' * 2048):
            for op in ops:
                op['title'] = query
            page = context_page(ops, ENVELOPE, query=query)
            self.assertLessEqual(len(json.dumps(page).encode()), 16384)
            self.assertIsNotNone(page['next_cursor'])
            nextpage = context_page(ops, ENVELOPE, cursor=page['next_cursor'])
            self.assertEqual(9, nextpage['total_matches'])

    def test_strict_query_cursor_stale_and_changed_readiness(self):
        ops = catalog(9)
        cursor = context_page(ops, ENVELOPE)['next_cursor']
        for query in ('', ' ', 'x\n', 'x' * 2049, 1, '\ud800'):
            with self.assertRaises(RuntimeFailure):
                context_page(ops, ENVELOPE, query=query)
        for bad in ('', '!', cursor + '=', 'a' * 16385, True):
            with self.assertRaises(RuntimeFailure):
                context_page(ops, ENVELOPE, cursor=bad)
        with self.assertRaises(RuntimeFailure):
            context_page(ops, ENVELOPE, query='x', cursor=cursor)
        for changed in (ops[:-1], [{**op, 'readiness': {'status': 'setup_required'}} for op in ops]):
            with self.assertRaisesRegex(RuntimeFailure, 'CORE_CONTEXT_STALE'):
                context_page(changed, ENVELOPE, cursor=cursor)
        with self.assertRaisesRegex(RuntimeFailure, 'CORE_CONTEXT_STALE'):
            context_page(ops, {**ENVELOPE, 'client': 'd' * 64}, cursor=cursor)
        value = json.loads(base64.urlsafe_b64decode(cursor + '=' * (-len(cursor) % 4)))
        for key, bad in [('offset', True), ('offset', 192), ('page_size', 7), ('query', []), ('extra', 'x')]:
            altered = {**value, key: bad}
            encoded = base64.urlsafe_b64encode(json.dumps(altered).encode()).decode().rstrip('=')
            with self.assertRaises(RuntimeFailure):
                context_page(ops, ENVELOPE, cursor=encoded)

    def test_192_native_declaration_exact_baseline_parity(self):
        baseline = Path(os.environ['CAPY_BASELINE_CONSUMER']).read_text() if os.environ.get('CAPY_BASELINE_CONSUMER') else subprocess.check_output(['git', 'show', '359dda9222a3036c5ad330575ba25122c588f07d:src/capy_outcome_runtime/consumer_mcp.py'], text=True)
        self.assertEqual('b978a9e0dd8b55272edf2d94091be0387f3bcb2edebf1a02b3eb072d79ae340a', hashlib.sha256(baseline.encode()).hexdigest())
        namespace = {'__name__': 'baseline_consumer'}
        exec(compile(baseline, 'baseline_consumer', 'exec'), namespace)
        surface = dict(ENVELOPE, operations=catalog())
        before = object.__new__(namespace['Consumer'])
        before.call = lambda *args: surface
        after = object.__new__(Consumer)
        after.call = lambda *args: surface
        native = lambda value: [x for x in value if x['name'].startswith('capy_run_')]
        expected = native(before.tools())
        self.assertEqual(192, len(expected))
        self.assertEqual(expected, native(after.tools()))
        mapping = copy.deepcopy(after.operations)
        context_page(surface['operations'], ENVELOPE, query='report')
        self.assertEqual(mapping, after.operations)
