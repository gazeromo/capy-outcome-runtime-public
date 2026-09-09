"""Deterministic local bootstrap-link writer for Capy Access."""

from __future__ import annotations

import argparse
import os
import tempfile
import urllib.parse
from pathlib import Path

from .access import AccessStore
from .store import RuntimeStore


def _atomic_private_text(path: Path, value: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            stream.write(value)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    except BaseException:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
        raise


def main() -> int:
    parser = argparse.ArgumentParser(prog="python -m capy_outcome_runtime.access_cli")
    commands = parser.add_subparsers(dest="command", required=True)
    bootstrap = commands.add_parser("bootstrap")
    bootstrap.add_argument("--runtime-root", required=True, type=Path)
    bootstrap.add_argument("--origin", required=True)
    bootstrap.add_argument("--team-name", default="Example")
    bootstrap.add_argument("--legacy-scope", default="owner")
    bootstrap.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    origin = urllib.parse.urlsplit(args.origin)
    if origin.scheme not in {"http", "https"} or not origin.netloc or origin.path not in {"", "/"}:
        raise SystemExit("origin must be an HTTP(S) origin")
    access = AccessStore(RuntimeStore(args.runtime_root))
    claim = access.create_bootstrap_claim(args.team_name, args.legacy_scope)
    url = args.origin.rstrip("/") + "/claim/" + claim["token"]
    _atomic_private_text(args.output, url)
    print(f"bootstrap link written privately; expires_at={claim['expires_at']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
