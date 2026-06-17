from __future__ import annotations

from collections import Counter
from pathlib import Path
from typing import Any

from core.db import DEFAULT_DB_PATH, get_project_behavior_profile, save_project_behavior_profile
from core.osint.normalize import ip_scope, normalize_ip


def is_public_ip(value: str) -> bool:
    return ip_scope(value) == "public"


def collect_public_ips_from_flow(flow: dict[str, Any], *, weight: int = 1) -> Counter[str]:
    counts: Counter[str] = Counter()
    amount = max(1, int(weight or 1))
    for key in ("dst_ip", "src_ip"):
        ip = normalize_ip(str(flow.get(key) or ""))
        if ip and is_public_ip(ip):
            counts[ip] += amount
    return counts


def collect_public_ips_from_pcap_summary(summary: Any) -> Counter[str]:
    counts: Counter[str] = Counter()
    device_ip = normalize_ip(str(getattr(summary, "likely_device_ip", "") or ""))

    for flow in getattr(summary, "flows", None) or []:
        if not isinstance(flow, dict):
            continue
        packet_weight = max(1, int(flow.get("bidirectional_packets") or 0))
        for key in ("dst_ip", "src_ip"):
            ip = normalize_ip(str(flow.get(key) or ""))
            if not ip or not is_public_ip(ip) or ip == device_ip:
                continue
            counts[ip] += packet_weight

    for row in getattr(summary, "top_endpoints", None) or []:
        if not isinstance(row, dict):
            continue
        ip = normalize_ip(str(row.get("ip") or ""))
        if not ip or not is_public_ip(ip) or ip == device_ip:
            continue
        counts[ip] += max(1, int(row.get("packets") or 0))

    return counts


def public_ip_rows_from_counter(
    counts: Counter[str],
    *,
    source: str = "case",
    limit: int = 500,
) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for value, count in counts.most_common(limit):
        if not value or not is_public_ip(value):
            continue
        rows.append(
            {
                "value": value,
                "count": int(count or 0),
                "source": source,
            }
        )
    return rows


def merge_public_ip_row_lists(*row_lists: list[dict[str, Any]]) -> list[dict[str, Any]]:
    counts: Counter[str] = Counter()
    for rows in row_lists:
        for row in rows or []:
            value = normalize_ip(str(row.get("value") or ""))
            if not value or not is_public_ip(value):
                continue
            counts[value] += int(row.get("count") or 0)
    return public_ip_rows_from_counter(counts, source="case", limit=500)


def merge_public_ips_into_profile(
    project_id: int,
    new_counts: Counter[str],
    *,
    source: str = "pcap",
    db_path: Path = DEFAULT_DB_PATH,
) -> None:
    if not new_counts:
        return

    profile = dict(get_project_behavior_profile(project_id, db_path=db_path) or {})
    existing_rows = list(profile.get("public_ip_rows") or [])
    kept_rows = [row for row in existing_rows if str(row.get("source") or "") != source]
    fresh_rows = public_ip_rows_from_counter(new_counts, source=source)
    profile["public_ip_rows"] = merge_public_ip_row_lists(kept_rows, fresh_rows)
    save_project_behavior_profile(
        project_id,
        profile,
        source_key=str(profile.get("source_key") or ""),
        json_file_count=int(profile.get("json_file_count") or 0),
        db_path=db_path,
    )
