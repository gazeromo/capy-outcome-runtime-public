"""Hash-bound nine-test pure behavior proof; never an original-wheel execution claim."""
import argparse, ast, hashlib, importlib.metadata, json, os, platform, subprocess, sys, unittest, zipfile
from pathlib import Path

root = Path(__file__).resolve().parents[1]
parser = argparse.ArgumentParser()
parser.add_argument('mode', choices=['source', 'installed'])
parser.add_argument('--wheel', required=True, type=Path)
parser.add_argument('--require-windows', action='store_true')
args = parser.parse_args()
if args.require_windows:
    assert os.name == 'nt' and platform.system() == 'Windows'
manifest = json.loads((root/'BOUNDED-WINDOWS.json').read_text(encoding='utf-8'))
sha = lambda data: hashlib.sha256(data).hexdigest()
def ast_identity(node):
    # ast.dump formatting/empty fields differ across supported Python versions.
    def canonical(value):
        if isinstance(value, ast.AST):
            return {'node': type(value).__name__, **{name: canonical(item) for name, item in ast.iter_fields(value) if not (name == 'type_params' and item == [])}}
        if isinstance(value, list):
            return [canonical(item) for item in value]
        if isinstance(value, bytes):
            return {'bytes_hex': value.hex()}
        return value
    return sha(json.dumps(canonical(node), sort_keys=True, separators=(',', ':')).encode())
for name, expected in manifest['test_ast_sha256'].items():
    actual = {}
    for node in ast.parse((root/name).read_text(encoding='utf-8')).body:
        key = node.name if isinstance(node, (ast.ClassDef, ast.FunctionDef)) else node.targets[0].id if isinstance(node, ast.Assign) and isinstance(node.targets[0], ast.Name) else ''
        if key in expected:
            actual[key] = ast_identity(node)
    assert actual == expected, name
assert sha((root/'tests/fixtures/baseline_consumer.py').read_bytes()) == manifest['baseline_consumer_sha256']
wheel = args.wheel.resolve()
with zipfile.ZipFile(wheel) as archive:
    for name, expected in manifest['module_sha256'].items():
        assert sha(archive.read('capy_outcome_runtime/'+name)) == expected, name
if args.mode == 'source':
    sys.path.insert(0, str(root/'src'))
sys.path.insert(0, str(root/'tests'))
from test_bounded_context_pure import SearchTests
from test_artifact_delivery_pure import PortableArtifactChecks
from test_artifact_delivery_posix import ArtifactDeliveryTests
import capy_outcome_runtime
package = Path(capy_outcome_runtime.__file__).resolve().parent
if args.mode == 'source':
    assert package == (root/'src/capy_outcome_runtime').resolve()
else:
    assert 'site-packages' in package.parts and not package.is_relative_to(root/'src')

def imports():
    found = {}
    for name, module in sys.modules.items():
        if name == 'capy_outcome_runtime' or name.startswith('capy_outcome_runtime.'):
            path = Path(module.__file__).resolve()
            assert path.is_relative_to(package), name
            relative = path.relative_to(package).as_posix()
            assert relative in manifest['module_sha256'], name
            digest = sha(path.read_bytes())
            assert digest == manifest['module_sha256'][relative], name
            found[relative] = digest
    assert found == manifest['module_sha256']
    return found

before = imports()
suite = unittest.TestSuite([
    unittest.defaultTestLoader.loadTestsFromTestCase(SearchTests),
    ArtifactDeliveryTests('test_remote_only_and_answer_unchanged'),
    unittest.defaultTestLoader.loadTestsFromTestCase(PortableArtifactChecks),
])
result = unittest.TextTestRunner(verbosity=2).run(suite)
after = imports()
assert result.testsRun == manifest['expected_test_count'] and not result.skipped
receipt = {
    'schema': manifest['schema'], 'mode': args.mode,
    'platform': platform.platform(), 'os_name': os.name, 'python': sys.version,
    'public_commit': subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=root, text=True).strip(),
    'tested_wheel_sha256': sha(wheel.read_bytes()),
    'installed_distribution_version': importlib.metadata.version('capy-outcome-runtime') if args.mode == 'installed' else None,
    'original_commit': manifest['original_commit'], 'original_wheel_sha256': manifest['original_wheel_sha256'],
    'original_wheel_executed_on_windows': False,
    'manifest_sha256': sha((root/'BOUNDED-WINDOWS.json').read_bytes()),
    'test_ast_sha256': manifest['test_ast_sha256'], 'baseline_consumer_sha256': manifest['baseline_consumer_sha256'],
    'imports_before': before, 'imports_after': after,
    'tests_run': result.testsRun, 'success': result.wasSuccessful(),
    'failures': len(result.failures), 'errors': len(result.errors), 'skipped': result.skipped,
    'scope': manifest['scope'], 'native_windows_execution_claim': False,
}
output = root/'.qualification'
output.mkdir(exist_ok=True)
(output/(args.mode+'.json')).write_text(json.dumps(receipt, indent=2)+'\n', encoding='utf-8')
print(json.dumps(receipt, sort_keys=True))
sys.exit(not result.wasSuccessful())
