"""Reject common private artifacts and credential formats in the public tree.

This is a regression guard, not a substitute for an independent secret scan.
"""
import io, json, re, zipfile
from pathlib import Path
root=Path(__file__).resolve().parents[1]
manifest=json.loads((root/'SNAPSHOT.json').read_text(encoding='utf-8'))
patterns=[rb'/(?:Users|home)/[A-Za-z0-9._-]+',rb'(?i)cosmain|capybarnia\.com',rb'(?:ghp_|github_pat_|sk-proj-)[A-Za-z0-9_-]{20,}',rb'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----\s+[A-Za-z0-9+/=]{40}',rb'Bearer [A-Za-z0-9._~-]{25,}']
failures=[]
def check(name,data,depth=0):
    if depth>5:raise AssertionError('Archive depth exceeds audit bound')
    for pattern in patterns:
        if re.search(pattern,data):failures.append(name)
    if zipfile.is_zipfile(io.BytesIO(data)):
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            for entry in archive.infolist():
                if not entry.is_dir():check(name+'!'+entry.filename,archive.read(entry),depth+1)
for item in manifest['files']+manifest.get('generated_files',[]):
    name=item['path']
    if name=='tools/check_publication.py':continue
    assert not any(part in {'infra','.env','credentials','traces','logs'} for part in Path(name).parts),name
    check(name,(root/name).read_bytes())
assert not failures,sorted(set(failures))
print('Public file and nested archive guard passed; no values disclosed.')
