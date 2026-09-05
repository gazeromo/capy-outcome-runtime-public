"""Verify exported bytes; does not access any upstream repository or service."""
import hashlib
import json
from pathlib import Path

root = Path(__file__).resolve().parents[1]
manifest = json.loads((root / "SNAPSHOT.json").read_text())
for entry in manifest["files"] + manifest.get("generated_files", []):
    path = root / entry["path"]
    assert path.is_relative_to(root) and not path.is_symlink()
    assert hashlib.sha256(path.read_bytes()).hexdigest() == entry["sha256"], entry["path"]
expected = {e["path"] for e in manifest["files"] if e["path"].startswith("src/")}
actual = {p.relative_to(root).as_posix() for p in (root / "src").rglob("*") if p.is_file() and "__pycache__" not in p.parts}
assert expected == actual
print(f"Verified {len(expected)} runtime source files and all exported test/fixture bytes.")
