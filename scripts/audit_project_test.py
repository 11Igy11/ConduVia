"""Compare ViaNyquist engine vs UI labels vs JSON for a saved project."""
from __future__ import annotations

import json
import re
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from core.db import (  # noqa: E402
    DEFAULT_DB_PATH,
    _connect,
    init_db,
    list_ingest_items,
    list_pcap_sources,
    list_recent_dataset_sources,
)
from core.pcap_analyzer import (  # noqa: E402
    METADATA_TOP_DNS_ROWS,
    analyze_pcap,
    analyze_pcap_files,
    metadata_count_label,
)
from core.pcap_rollup import pcap_day_key, rollup_pcap_sources
from core.project_profile import build_project_activity_profile


def _find_project(con, name: str) -> dict | None:
    row = con.execute(
        "SELECT id, name, base_folder FROM projects WHERE lower(name) = lower(?) ORDER BY updated_at DESC LIMIT 1;",
        (name,),
    ).fetchone()
    return dict(row) if row else None


def _parse_summary_dns_total(summary_text: str) -> int | None:
    match = re.search(r"Visible DNS names:\s*([0-9,]+)", summary_text or "")
    if not match:
        return None
    return int(match.group(1).replace(",", ""))


def _json_day_stats(paths: list[Path]) -> dict:
    flows_total = 0
    bytes_total = 0
    hosts: Counter[str] = Counter()
    files_ok = 0
    for path in paths:
        if not path.exists():
            continue
        try:
            data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
        except Exception:
            continue
        flows = data.get("flow") if isinstance(data, dict) else None
        if not isinstance(flows, list):
            continue
        files_ok += 1
        flows_total += len(flows)
        for flow in flows:
            if not isinstance(flow, dict):
                continue
            bytes_total += int(flow.get("bidirectional_bytes") or 0)
            host = str(flow.get("requested_server_name") or "").strip()
            if host:
                hosts[host] += 1
    return {
        "files": files_ok,
        "flows": flows_total,
        "mb": bytes_total / 1_000_000,
        "unique_hosts": len(hosts),
    }


def _group_json_by_day(project_id: int, db_path: Path) -> dict[str, list[Path]]:
    out: dict[str, list[Path]] = {}
    for item in list_ingest_items(project_id, file_type="json", limit=50000, db_path=db_path):
        day = str(item.observed_date or "").strip() or "undated"
        out.setdefault(day, []).append(Path(str(item.file_path)))
    return out


def _group_pcap_paths_by_day(project_id: int, db_path: Path) -> dict[str, list[str]]:
    by_day: dict[str, list[str]] = {}
    for item in list_ingest_items(project_id, file_type="pcap", limit=50000, db_path=db_path):
        day = str(item.observed_date or "").strip() or "undated"
        path = str(item.file_path or "").strip()
        if path:
            by_day.setdefault(day, []).append(path)
    return by_day


def main() -> int:
    project_name = (sys.argv[1] if len(sys.argv) > 1 else "test").strip()
    db_path = Path(sys.argv[2]) if len(sys.argv) > 2 else DEFAULT_DB_PATH
    init_db(db_path)

    with _connect(db_path) as con:
        project = _find_project(con, project_name)
        if not project:
            print(f"Project {project_name!r} not found in {db_path}")
            return 1
        project_id = int(project["id"])

    print(f"Project: {project['name']} (id={project_id})")
    print(f"Base folder: {project.get('base_folder') or '-'}")
    print(f"Database: {db_path}")
    print()

    saved_pcaps = list_pcap_sources(project_id, limit=50000, db_path=db_path)
    rollup = rollup_pcap_sources(saved_pcaps)
    profile = build_project_activity_profile(project_id, db_path=db_path)

    print("=== Profile (saved in DB) ===")
    for row in profile.get("pcap_day_rows") or []:
        print(f"  {row.get('label')}: {row.get('detail')}")
    print()

    pcap_by_day = _group_pcap_paths_by_day(project_id, db_path)
    json_by_day = _group_json_by_day(project_id, db_path)

    all_days = sorted(set(pcap_by_day) | set(json_by_day) | set(rollup.day_packets.keys()))
    all_days = [d for d in all_days if d and d != "undated"]

    print("=== Per-day: engine re-analysis | saved DB | UI-style label | JSON ===")
    print(
        f"{'Day':<12} {'PCAP files':>10} {'Engine pkt':>12} {'Engine MB':>10} "
        f"{'Engine DNS':>16} {'UI would show':>14} {'Saved pkt':>12} {'Saved MB':>10} "
        f"{'JSON flows':>11} {'JSON MB':>9} {'JSON hosts':>11}"
    )
    print("-" * 130)

    for day in all_days:
        paths = [p for p in pcap_by_day.get(day, []) if Path(p).exists()]
        missing = len(pcap_by_day.get(day, []) or []) - len(paths)

        engine_dns = engine_pkt = engine_mb = 0
        ui_dns_label = "-"
        comm = 0
        if paths:
            try:
                summary = (
                    analyze_pcap(paths[0])
                    if len(paths) == 1
                    else analyze_pcap_files(paths, label=f"{day} aggregate")
                )
                engine_pkt = int(summary.packet_count or 0)
                engine_mb = float(summary.wire_bytes or 0) / 1_000_000
                engine_dns = int(summary.total_dns_names or 0)
                ui_dns_label = metadata_count_label(
                    engine_dns,
                    len(summary.dns_queries or []),
                )
                comm = len(summary.communication_rows or [])
            except Exception as exc:
                ui_dns_label = f"ERR: {exc}"

        saved_pkt = int(rollup.day_packets.get(day, 0))
        saved_mb = int(rollup.day_bytes.get(day, 0)) / 1_000_000
        saved_dns_from_summary = None
        for s in saved_pcaps:
            if pcap_day_key(s) != day:
                continue
            val = _parse_summary_dns_total(s.summary_text)
            if val is not None:
                saved_dns_from_summary = val
                break

        json_stats = _json_day_stats(json_by_day.get(day, []))

        day_label = f"{day[8:10]}/{day[5:7]}/{day[:4]}" if len(day) == 10 else day
        print(
            f"{day_label:<12} {len(paths):>10} {engine_pkt:>12,} {engine_mb:>10.2f} "
            f"{engine_dns:>16} {ui_dns_label:>14} {saved_pkt:>12,} {saved_mb:>10.2f} "
            f"{json_stats['flows']:>11,} {json_stats['mb']:>9.2f} {json_stats['unique_hosts']:>11}"
        )
        if missing:
            print(f"  ! {missing} PCAP path(s) missing on disk for {day}")
        if saved_dns_from_summary is not None and saved_dns_from_summary != engine_dns and paths:
            print(
                f"  ! Saved summary_text DNS ({saved_dns_from_summary}) != fresh engine ({engine_dns}) "
                f"— re-save period or re-import"
            )
        if paths and json_stats["files"] and abs(engine_mb - json_stats["mb"]) > max(0.5, engine_mb * 0.05):
            print(
                f"  ! MB gap >5%: engine {engine_mb:.2f} vs JSON {json_stats['mb']:.2f}"
            )
        if paths and comm == 0 and engine_pkt > 1000:
            print("  ! Engine communication_rows=0 on busy day (check app build / Apple rules)")

    print()
    print(f"Saved PCAP period rows in DB: {len(saved_pcaps)} (rolled days: {rollup.pcap_day_count})")
    print(f"UI Evidence cap: top {METADATA_TOP_DNS_ROWS} DNS names in table; total in label after fix.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
