"""Run copied public tests with no checkout source on the import path."""
import os,shutil,subprocess,sys,tempfile
from pathlib import Path
root=Path(__file__).resolve().parents[1]
with tempfile.TemporaryDirectory() as directory:
    work=Path(directory)
    for name in ('tests','campaigns'):shutil.copytree(root/name,work/name)
    env={k:v for k,v in os.environ.items() if k not in ('PYTHONPATH','CAPY_BASELINE_CONSUMER')}
    subprocess.run([sys.executable,'-I','-c',"import capy_outcome_runtime; from pathlib import Path; assert 'site-packages' in Path(capy_outcome_runtime.__file__).parts; print('Installed import guard passed')"],cwd=work,env=env,check=True)
    targets=['tests'] if os.name!='nt' else ['tests/test_portable_interfaces.py','tests/test_accepted_release_controls.py::IndependentDeepValidationControls','tests/test_bounded_context_pure.py','tests/test_artifact_delivery_pure.py']
    subprocess.run([sys.executable,'-I','-m','pytest','-q',*targets],cwd=work,env=env,check=True)
