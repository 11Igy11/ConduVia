"""Local-only PCAP day coverage audit. Not part of the app test suite."""
from __future__ import annotations

from datetime import date, timedelta
from pathlib import Path
import sqlite3

DB = Path(r"C:\Users\igi_t\AppData\Local\ViaNyquist\vianyquist.db")


def calendar_missing(present: set[str], first: str, last: str) -> list[str]:
    start = date.fromisoformat(first)
    end = date.fromisoformat(last)
    missing: list[str] = []
    cur = start
    while cur <= end:
        s = cur.isoformat()
        if s not in present:
            missing.append(s)
        cur += timedelta(days=1)
    return missing


def main() -> None:
    con = sqlite3.connect(DB)
    con.row_factory = sqlite3.Row

    proj = con.execute(
        "SELECT id, name FROM projects WHERE name LIKE '%veliki%' ORDER BY id DESC LIMIT 1"
    ).fetchone()
    if not proj:
        proj = con.execute("SELECT id, name FROM projects ORDER BY id DESC LIMIT 1").fetchone()
    pid = proj["id"]
    print(f"Project: {proj['name']} (id={pid})\n")

    ingest_days: set[str] = set()
    for row in con.execute(
        "SELECT observed_date FROM ingest_items WHERE project_id=? AND file_type='pcap'",
        (pid,),
    ):
        d = str(row["observed_date"] or "")[:10]
        if len(d) == 10 and d[4] == "-" and d[7] == "-":
            ingest_days.add(d)

    source_days: set[str] = set()
    first_seen_min = ""
    last_seen_max = ""
    for row in con.execute(
        "SELECT first_seen, last_seen FROM pcap_sources WHERE project_id=?",
        (pid,),
    ):
        for key in ("first_seen", "last_seen"):
            d = str(row[key] or "")[:10]
            if len(d) == 10 and d[4] == "-" and d[7] == "-":
                source_days.add(d)
                if key == "first_seen" and (not first_seen_min or d < first_seen_min):
                    first_seen_min = d
                if key == "last_seen" and (not last_seen_max or d > last_seen_max):
                    last_seen_max = d

    all_days = sorted(ingest_days | source_days)
    present = set(all_days)

    print(f"Ingest PCAP days:        {len(ingest_days):,}")
    print(f"Saved source day stamps: {len(source_days):,}")
    print(f"Union (UI '318 days'):   {len(all_days):,}")
    if all_days:
        print(f"First indexed day:       {all_days[0]}")
        print(f"Last indexed day:        {all_days[-1]}")

    if all_days:
        first, last = all_days[0], all_days[-1]
        expected = (date.fromisoformat(last) - date.fromisoformat(first)).days + 1
        missing = calendar_missing(present, first, last)
        print("\n--- Gaps inside indexed span (what 'Missing days' banner uses) ---")
        print(f"Calendar days in span:   {expected:,}")
        print(f"Present:                 {len(present):,}")
        print(f"Missing:                 {len(missing):,}")
        if missing:
            print("Missing dates:", ", ".join(missing))

    con.close()


if __name__ == "__main__":
    main()
