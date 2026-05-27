"""Full calculation audit: raw dataset vs engine vs DB vs UI display caps."""
from __future__ import annotations

import json
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from core.analysis_limits import (  # noqa: E402
    MAX_BEHAVIOR_DAY_ROWS,
    MAX_PCAP_FLOWS,
    MAX_PCAP_READABLE_SAMPLES,
    METADATA_TOP_DNS_ROWS,
    METADATA_TOP_HTTP_ROWS,
    METADATA_TOP_TLS_ROWS,
    PROFILE_CHART_MAX_DAYS,
)
from core.behavior_profile import build_flow_behavior_profile
from core.db import (  # noqa: E402
    DEFAULT_DB_PATH,
    _connect,
    get_project_behavior_profile,
    init_db,
    list_ingest_items,
    list_pcap_sources,
)
from core.pcap_analyzer import analyze_pcap_files, metadata_count_label
from core.pcap_rollup import collect_device_ip_stats, pcap_day_key, rollup_pcap_sources
from core.period_comparison import build_period_comparison_rows
from core.project_datasets import count_project_json_datasets, load_project_dataset_flows
from core.project_profile import build_project_activity_profile


def _find_project(con, name: str) -> dict | None:
    row = con.execute(
        "SELECT id, name, base_folder FROM projects WHERE lower(name) = lower(?) ORDER BY updated_at DESC LIMIT 1;",
        (name,),
    ).fetchone()
    return dict(row) if row else None


def _json_stats_all(paths: list[Path]) -> dict:
    day_flows: Counter[str] = Counter()
    day_bytes: Counter[str] = Counter()
    total_flows = 0
    total_bytes = 0
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
        for flow in flows:
            if not isinstance(flow, dict):
                continue
            total_flows += 1
            b = int(flow.get("bidirectional_bytes") or 0)
            total_bytes += b
            ts = str(flow.get("bidirectional_first_seen_ms") or flow.get("first_seen") or "")
            day = ts[:10] if len(ts) >= 10 else "undated"
            day_flows[day] += 1
            day_bytes[day] += b
    return {
        "files": files_ok,
        "flows": total_flows,
        "bytes": total_bytes,
        "day_flows": day_flows,
        "day_bytes": day_bytes,
    }


def main() -> int:
    project_name = (sys.argv[1] if len(sys.argv) > 1 else "test").strip()
    db_path = Path(sys.argv[2]) if len(sys.argv) > 2 else DEFAULT_DB_PATH
    init_db(db_path)

    with _connect(db_path) as con:
        project = _find_project(con, project_name)
        if not project:
            print(f"Project {project_name!r} not found")
            return 1
        project_id = int(project["id"])

    print("=" * 72)
    print(f"FULL CALCULATION AUDIT — project {project['name']} (id={project_id})")
    print("=" * 72)

    profile = build_project_activity_profile(project_id, db_path=db_path)
    behavior_index = get_project_behavior_profile(project_id, db_path=db_path) or {}
    pcaps = list_pcap_sources(project_id, limit=50000, db_path=db_path)
    rollup = rollup_pcap_sources(pcaps)
    ip_counter, ip_rows = collect_device_ip_stats(pcaps)

    json_items = list_ingest_items(project_id, file_type="json", limit=50000, db_path=db_path)
    pcap_items = list_ingest_items(project_id, file_type="pcap", limit=50000, db_path=db_path)
    json_paths = [Path(str(i.file_path)) for i in json_items if str(i.file_path or "").strip()]
    raw_json = _json_stats_all(json_paths)

    dataset_count = count_project_json_datasets(project_id, db_path=db_path)
    loaded = load_project_dataset_flows(project_id, db_path=db_path)

    print("\n--- 1. PROJECT TOTALS ---")
    print(f"JSON ingest items:        {len(json_items):,}")
    print(f"JSON files readable:      {raw_json['files']:,}")
    print(f"JSON dataset count (UI):  {dataset_count:,}")
    print(f"Loaded flows (UI cache):  {loaded['flow_count']:,} from {loaded['loaded_json_file_count']:,}/{loaded['json_file_count']:,} files")
    print(f"Raw JSON total flows:     {raw_json['flows']:,}")
    print(f"Raw JSON total bytes:     {raw_json['bytes'] / 1_000_000:.2f} MB (decimal)")
    print(f"PCAP ingest items:        {len(pcap_items):,}")
    print(f"Saved PCAP period rows:   {len(pcaps):,} (unique days rolled: {rollup.pcap_day_count})")
    print(f"Rollup total packets:     {rollup.total_packets:,}")
    print(f"Rollup total bytes:       {rollup.total_bytes / 1_000_000:.2f} MB (decimal)")
    print(f"Profile total packets:    {profile['total_pcap_packets']:,}")
    print(f"Profile total bytes:      {profile['total_pcap_bytes_label']}")

    if loaded["flow_count"] != raw_json["flows"]:
        print(f"  ! Loaded flows ({loaded['flow_count']:,}) != raw JSON flows ({raw_json['flows']:,})")
    if loaded["json_file_count"] != raw_json["files"]:
        print(f"  ! Loaded JSON files ({loaded['json_file_count']:,}) != readable ({raw_json['files']:,})")

    print("\n--- 2. DEVICE IPs ---")
    print(f"Distinct device IPs (collect_device_ip_stats): {len(ip_rows)}")
    print(f"Profile metric Device IPs value:             {next(m['value'] for m in profile['metrics'] if m['label']=='Device IPs')}")
    print(f"Profile chart rows:                          {len(profile['pcap_device_ip_rows'])}")
    print(f"Summary line top IPs:                        {profile['summary_lines'][8] if len(profile['summary_lines'])>8 else '-'}")
    if len(ip_rows) != len(profile["pcap_device_ip_rows"]):
        print("  ! IP row count mismatch between stats and profile")
    print("All device IPs:")
    for row in ip_rows:
        print(f"  {row['label']}: {row['detail']}")

    print("\n--- 3. DAY COVERAGE (JSON vs PCAP vs Profile) ---")
    json_days = set(raw_json["day_flows"]) - {"undated"}
    pcap_days = set(rollup.day_packets) - {"undated", ""}
    index_days = {str(r.get("date") or "") for r in (behavior_index.get("day_rows") or []) if r.get("date")}
    profile_json_days = {str(r.get("date") or "") for r in (profile.get("json_day_rows") or []) if r.get("date")}
    profile_pcap_days = {str(r.get("date") or "") for r in (profile.get("pcap_day_rows") or []) if r.get("date")}

    print(f"JSON days (from flow timestamps):  {len(json_days)}")
    print(f"PCAP saved days:                 {len(pcap_days)}")
    print(f"Behavior index day_rows:           {len(index_days)}")
    print(f"Profile json_day_rows:             {len(profile_json_days)}")
    print(f"Profile pcap_day_rows:             {len(profile_pcap_days)}")
    print(f"Comparison chart rows:             {len(profile.get('period_comparison_rows') or [])}")

    json_only = sorted(json_days - pcap_days)
    pcap_only = sorted(pcap_days - json_days)
    if json_only:
        print(f"  JSON-only days ({len(json_only)}): {', '.join(json_only[:10])}{'...' if len(json_only)>10 else ''}")
    if pcap_only:
        print(f"  PCAP-only days ({len(pcap_only)}): {', '.join(pcap_only)}")

    mismatches = []
    for row in profile.get("period_comparison_rows") or []:
        day = row.get("date")
        if not day:
            continue
        jf = int(row.get("json_flows") or 0)
        pf = int(row.get("pcap_packets") or 0)
        raw_jf = raw_json["day_flows"].get(day, 0)
        raw_pk = rollup.day_packets.get(day, 0)
        if jf != raw_jf:
            mismatches.append(f"{day}: profile json_flows {jf} != raw {raw_jf}")
        if pf != raw_pk:
            mismatches.append(f"{day}: profile pcap_packets {pf} != rollup {raw_pk}")
    if mismatches:
        print("  Day count mismatches vs raw:")
        for line in mismatches[:15]:
            print(f"    ! {line}")
    else:
        print("  Per-day profile counts match raw JSON + DB rollup.")

    print("\n--- 4. UI DISPLAY CAPS (data exists but not all shown) ---")
    caps = [
        ("Profile chart max days", PROFILE_CHART_MAX_DAYS, "0 = all"),
        ("Behavior day_rows limit", MAX_BEHAVIOR_DAY_ROWS, "days in index"),
        ("PCAP flows table", MAX_PCAP_FLOWS, "top flows by volume"),
        ("PCAP readable samples", MAX_PCAP_READABLE_SAMPLES, "payload snippets"),
        ("Evidence DNS table", METADATA_TOP_DNS_ROWS, "top by count"),
        ("Evidence TLS table", METADATA_TOP_TLS_ROWS, "top by count"),
        ("Evidence HTTP table", METADATA_TOP_HTTP_ROWS, "top by count"),
        ("Service/domain charts (default)", 10, "top N in Profile behavior tab"),
        ("Activity timeline in export", 12, "recent events"),
        ("Activity log query", 200, "events loaded for profile"),
    ]
    for name, cap, note in caps:
        print(f"  {name}: {cap} ({note})")

    # Sample busiest PCAP day for engine caps
    busiest = max(rollup.day_packets.items(), key=lambda x: x[1]) if rollup.day_packets else ("", 0)
    if busiest[0]:
        day = busiest[0]
        paths = [str(i.file_path) for i in pcap_items if str(i.observed_date or "") == day and Path(str(i.file_path)).exists()]
        if paths:
            summary = analyze_pcap_files(paths, label=f"{day} audit")
            print(f"\n--- 5. BUSIEST DAY SAMPLE ({day}, {summary.packet_count:,} packets) ---")
            print(f"  total_flows (engine):           {summary.total_flows:,}")
            print(f"  flows shown in UI table:        {len(summary.flows or []):,} — {metadata_count_label(summary.total_flows, len(summary.flows or []))}")
            print(f"  total_readable_samples:         {summary.total_readable_samples:,}")
            print(f"  readable shown in UI:           {len(summary.readable_samples or []):,} — {metadata_count_label(summary.total_readable_samples, len(summary.readable_samples or []))}")
            print(f"  DNS total / table top:          {metadata_count_label(summary.total_dns_names, len(summary.dns_queries or []))}")
            print(f"  TLS total / table top:          {metadata_count_label(summary.total_tls_sni_hosts, len(summary.tls_sni or []))}")
            print(f"  HTTP total / table top:         {metadata_count_label(summary.total_http_hosts, len(summary.http_hosts or []))}")
            print(f"  communication_rows:             {len(summary.communication_rows or []):,}")
            print(f"  artifacts:                      {len(summary.artifacts or []):,}")
            hidden_dns = max(0, int(summary.total_dns_names or 0) - len(summary.dns_queries or []))
            hidden_flows = max(0, int(summary.total_flows or 0) - len(summary.flows or []))
            hidden_samples = max(0, int(summary.total_readable_samples or 0) - len(summary.readable_samples or []))
            if hidden_dns:
                print(f"  → {hidden_dns:,} DNS names NOT in Evidence table (export full DNS CSV for all)")
            if hidden_flows:
                print(f"  → {hidden_flows:,} flows NOT in Connections table")
            if hidden_samples:
                print(f"  → {hidden_samples:,} readable samples NOT in samples table")

    print("\n--- 6. JSON BEHAVIOR INDEX vs IN-MEMORY PROFILE ---")
    index_flows = int(behavior_index.get("flow_count") or 0)
    index_day_rows = len(behavior_index.get("day_rows") or [])
    if index_flows:
        ui_behavior = build_flow_behavior_profile([], limit=10)
        print(f"  Index flow_count: {index_flows:,}")
        print(f"  Index day_rows:   {index_day_rows} (limit {MAX_BEHAVIOR_DAY_ROWS})")
        print(f"  Index service_rows stored: {len(behavior_index.get('service_rows') or [])} (UI re-shows top 10 when flows loaded)")
    else:
        print("  No behavior index persisted — Profile JSON charts may be empty until index rebuild.")

    print("\n--- 7. MISSING ON DISK ---")
    missing_json = sum(1 for p in json_paths if not p.exists())
    missing_pcap = sum(1 for p in [Path(str(i.file_path)) for i in pcap_items] if not p.exists())
    print(f"  Missing JSON paths: {missing_json}/{len(json_paths)}")
    print(f"  Missing PCAP paths: {missing_pcap}/{len(pcap_items)}")

    print("\n--- 8. SUMMARY: WHAT IS NOT FULLY DISPLAYED ---")
    findings = []
    if MAX_PCAP_FLOWS < 1_000_000:
        findings.append("Connections tab shows capped flow summaries, not every flow.")
    if METADATA_TOP_DNS_ROWS < 10000:
        findings.append("Evidence metadata table is top-N; full counts in labels + Export full DNS/TLS CSV.")
    if loaded["loaded_json_file_count"] < loaded["json_file_count"]:
        findings.append(f"Only {loaded['loaded_json_file_count']}/{loaded['json_file_count']} JSON files loaded into memory for behavior charts.")
    if json_only or pcap_only:
        findings.append(f"Calendar gap: {len(json_only)} JSON-only days, {len(pcap_only)} PCAP-only days.")
    if index_day_rows < len(json_days):
        findings.append(f"Behavior index has {index_day_rows} day rows vs {len(json_days)} JSON calendar days.")
    for i, f in enumerate(findings, 1):
        print(f"  {i}. {f}")
    if not findings:
        print("  No structural display gaps detected beyond intentional UI caps.")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
