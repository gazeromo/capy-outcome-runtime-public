"""Trusted local operator CLI for supervised build lifecycle operations."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from .build import BuilderService
from .chat import ChatStore
from .connections import ConnectionControl
from .store import RuntimeStore


def main() -> int:
    parser = argparse.ArgumentParser(prog="capy-builder")
    parser.add_argument("--runtime-root", required=True, type=Path)
    parser.add_argument("--chat-database", required=True, type=Path)
    parser.add_argument("--scripts-repository", required=True, type=Path)
    parser.add_argument("--scratch-root", required=True, type=Path)
    parser.add_argument("--builder-uid", type=int)
    parser.add_argument("--builder-gid", type=int)
    parser.add_argument("--connection-socket", type=Path)
    commands = parser.add_subparsers(dest="operation", required=True)

    claim = commands.add_parser("claim")
    claim.add_argument("build_id")
    claim.add_argument("--builder-id", required=True)
    claim.add_argument("--lease-seconds", type=int, default=1800)

    prepare = commands.add_parser("prepare")
    prepare.add_argument("build_id")

    run = commands.add_parser("run")
    run.add_argument("build_id")
    run.add_argument("codex_command", nargs=argparse.REMAINDER)

    submit = commands.add_parser("submit")
    submit.add_argument("build_id")
    submit.add_argument("candidate_worktree", type=Path)

    for name in ("accept", "publish", "rollback", "reactivate"):
        command = commands.add_parser(name)
        command.add_argument("build_id")

    args = parser.parse_args()
    runtime = RuntimeStore(args.runtime_root)
    connections = ConnectionControl(runtime)
    connection_status = (
        (lambda scope, grant: connections.status(scope, grant) if args.connection_socket.exists() else "unavailable")
        if args.connection_socket else None
    )
    service = BuilderService(
        ChatStore(args.chat_database), runtime,
        args.scripts_repository, args.scratch_root,
        builder_uid=args.builder_uid, builder_gid=args.builder_gid,
        connection_status=connection_status,
        connection_inventory=connections.inventory if args.connection_socket else None,
    )
    if args.operation == "claim":
        result = service.claim(args.build_id, args.builder_id, args.lease_seconds)
    elif args.operation == "prepare":
        result = {"worktree": str(service.prepare_worktree(args.build_id))}
    elif args.operation == "run":
        command = args.codex_command
        if command and command[0] == "--":
            command = command[1:]
        completed = service.run_codex(args.build_id, command)
        result = {"exit_code": completed.returncode}
    elif args.operation == "submit":
        result = service.submit(args.build_id, args.candidate_worktree)
    elif args.operation == "accept":
        result = service.accept(args.build_id)
    elif args.operation == "publish":
        result = service.publish(args.build_id)
    elif args.operation == "rollback":
        result = service.rollback(args.build_id)
    else:
        result = service.reactivate(args.build_id)
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
