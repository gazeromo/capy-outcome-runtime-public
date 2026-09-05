"""One bounded shared scheduler entrypoint for vehicles.encar_watcher."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from .access import AccessStore
from .chat import ChatStore
from .encar_watcher_runtime import EncarWatcherRuntime, QueuedWatcherEvaluator
from .semantic_dispatch import SemanticDispatchStore
from .store import RuntimeStore


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--runtime-root", required=True, type=Path)
    parser.add_argument("--chat-database", required=True, type=Path)
    parser.add_argument("--application-executable", required=True, type=Path)
    parser.add_argument("--application-state-root", required=True, type=Path)
    parser.add_argument("--provider-credential", required=True, type=Path)
    args = parser.parse_args()
    runtime = RuntimeStore(args.runtime_root)
    adapter = EncarWatcherRuntime(
        runtime, ChatStore(args.chat_database), AccessStore(runtime),
        args.application_executable, args.application_state_root,
        QueuedWatcherEvaluator(SemanticDispatchStore(args.chat_database)),
    )
    print(json.dumps(adapter.run_due(), sort_keys=True, separators=(",", ":")), flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
