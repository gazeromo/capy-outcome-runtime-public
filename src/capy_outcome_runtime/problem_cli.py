"""Private read-only problem-reference lookup."""

from __future__ import annotations

import argparse
import json
import os
import sqlite3
from contextlib import closing
from pathlib import Path


DEFAULT_CHAT_DATABASE = Path(
    "/var/lib/capy-outcome-runtime-real-team-preview-v0/chat.sqlite3"
)


def inspect(database: Path, problem_reference: str) -> dict[str, object]:
    uri = f"file:{database.resolve()}?mode=ro"
    with closing(sqlite3.connect(uri, uri=True)) as db:
        db.row_factory = sqlite3.Row
        row = db.execute(
            """SELECT pi.facts_json, pi.created_at AS recorded_at,
                      t.status AS turn_status, t.created_at AS turn_created_at,
                      t.completed_at AS turn_completed_at, m.text AS owner_text
               FROM problem_incidents pi
               JOIN turns t ON t.id=pi.turn_id
               JOIN messages m ON m.id=t.owner_message_id
               WHERE pi.problem_reference=?""",
            (problem_reference,),
        ).fetchone()
        render_rows = db.execute(
            """SELECT id, facts_json, created_at FROM problem_render_incidents
               WHERE problem_reference=? ORDER BY created_at,id""",
            (problem_reference,),
        ).fetchall()
    if row is None:
        raise LookupError(problem_reference)
    result = json.loads(row["facts_json"])
    result.update(
        {
            "recorded_at": row["recorded_at"],
            "turn_status": row["turn_status"],
            "turn_created_at": row["turn_created_at"],
            "turn_completed_at": row["turn_completed_at"],
            "owner_text": row["owner_text"],
        }
    )
    result["render_incidents"] = [
        {"id": item["id"], "recorded_at": item["created_at"], **json.loads(item["facts_json"])}
        for item in render_rows
    ]
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="capy-problem")
    parser.add_argument(
        "--chat-database",
        type=Path,
        default=Path(os.environ.get("CAPY_CHAT_DATABASE", DEFAULT_CHAT_DATABASE)),
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    inspect_parser = subparsers.add_parser("inspect")
    inspect_parser.add_argument("problem_reference")
    inspect_parser.add_argument("--json", action="store_true", required=True)
    args = parser.parse_args(argv)
    try:
        result = inspect(args.chat_database, args.problem_reference)
    except (LookupError, OSError, sqlite3.Error):
        parser.exit(2, "problem reference not found or unavailable\n")
    print(json.dumps(result, ensure_ascii=False, sort_keys=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
