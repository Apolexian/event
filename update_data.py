"""Extract masterdb tables from master.mdb into event/data/ as JSON."""

import json
import sqlite3
import sys
from pathlib import Path

TABLES = [
    "text_data",
    "single_mode_event_choice_reward",
    "single_mode_unique_chara",
    "skill_data",
]

def main():
    if len(sys.argv) != 2:
        print(f"Usage: python {sys.argv[0]} <path/to/master.mdb>", file=sys.stderr)
        sys.exit(1)

    mdb = Path(sys.argv[1])
    dst = Path(__file__).parent / "data"

    if not mdb.is_file():
        print(f"Not a file: {mdb}", file=sys.stderr)
        sys.exit(1)

    dst.mkdir(exist_ok=True)
    con = sqlite3.connect(mdb)
    con.row_factory = sqlite3.Row

    for table in TABLES:
        rows = [dict(r) for r in con.execute(f"SELECT * FROM {table}")]
        cols = list(rows[0].keys()) if rows else []
        out = {"table": table, "row_count": len(rows), "columns": cols, "rows": rows}
        (dst / f"{table}.json").write_text(json.dumps(out, ensure_ascii=False), encoding="utf-8")
        print(f"  {table} ({len(rows)} rows)")

    con.close()
    print(f"Updated {len(TABLES)} tables -> {dst}")

if __name__ == "__main__":
    main()
