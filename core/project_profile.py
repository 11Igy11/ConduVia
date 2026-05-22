from __future__ import annotations

from collections import Counter
from pathlib import Path
from typing import Any

from core.db import (
    DEFAULT_DB_PATH,
    get_project,
    list_activity,
    list_findings,
    list_pcap_sources,
    list_recent_datasets,
)
from core.evidence_policy import format_period_day_label
from core.formatters import human_bytes
from core.db import list_ingest_items, list_saved_pcap_period_days
from core.pcap_rollup import pcap_day_key, rollup_pcap_sources
from core.project_datasets import count_project_json_datasets, list_project_json_dataset_files
from core.project_identity import project_identifiers_text, subject_display_label, target_display_label
from core.timeutils import parse_timestamp


def build_project_activity_profile(
    project_id: int,
    *,
    db_path: Path = DEFAULT_DB_PATH,
) -> dict[str, Any]:
    project = get_project(project_id, db_path=db_path)
    if not project:
        return {
            "summary_lines": ["Project not found."],
            "timeline_lines": [],
            "recommendation_lines": [],
            "metrics": [],
            "evidence_counts": [],
            "pcap_device_ip_rows": [],
            "activity_type_rows": [],
            "capture_range": {"first_seen": "", "last_seen": "", "label": "-"},
            "dataset_count": 0,
            "pcap_count": 0,
            "pcap_day_count": 0,
            "finding_count": 0,
            "pcap_device_ips": {},
            "total_pcap_packets": 0,
            "total_pcap_bytes": 0,
            "total_pcap_bytes_label": human_bytes(0, precision=2),
        }

    dataset_sources = list_recent_datasets(project_id, limit=50000, db_path=db_path)
    dataset_files = [
        row for row in list_project_json_dataset_files(project_id, limit=50000, db_path=db_path)
        if row.get("status") == "Available"
    ]
    dataset_count = count_project_json_datasets(project_id, limit=50000, db_path=db_path)
    pcaps = list_pcap_sources(project_id, limit=50000, db_path=db_path)
    findings = list_findings(project_id, limit=50000, db_path=db_path)
    activity = list_activity(project_id, limit=200, db_path=db_path)

    pcap_rollup = rollup_pcap_sources(pcaps)
    pcap_ips = pcap_rollup.device_ips
    capture_starts = [src.first_seen for src in pcaps if src.first_seen]
    capture_ends = [src.last_seen for src in pcaps if src.last_seen]
    total_packets = pcap_rollup.total_packets
    total_pcap_bytes = pcap_rollup.total_bytes
    capture_start = min(capture_starts) if capture_starts else ""
    capture_end = max(capture_ends) if capture_ends else ""
    activity_types = Counter(str(row["event_type"] or "event") for row in activity)
    pcap_day_packets = pcap_rollup.day_packets
    pcap_day_bytes = pcap_rollup.day_bytes
    undated_pcap_packets = pcap_rollup.undated_packets
    undated_pcap_bytes = pcap_rollup.undated_bytes
    undated_pcap_count = pcap_rollup.undated_day_count
    pcap_day_count = pcap_rollup.pcap_day_count

    summary_lines = [
        "Project Activity Profile",
        f"- Case subject: {subject_display_label(project)}",
        f"- Known identifiers: {project_identifiers_text(project)}",
        f"- Target fallback: {target_display_label(project)}",
        f"- JSON datasets: {dataset_count}",
        f"- PCAP days: {pcap_day_count}",
        f"- Findings: {len(findings)}",
    ]

    if pcaps:
        summary_lines.extend([
            f"- PCAP packet volume: {total_packets:,} packets / {human_bytes(total_pcap_bytes, precision=2)}",
            f"- PCAP capture range: {capture_start or '-'} to {capture_end or '-'}",
            f"- PCAP device IPs: {_counter_label(pcap_ips)}",
        ])
    else:
        summary_lines.append("- PCAP capture range: no PCAP sources saved yet")

    if dataset_files:
        summary_lines.append(f"- Most recent dataset: {dataset_files[0].get('path')}")
    elif dataset_sources:
        summary_lines.append(f"- Most recent dataset source: {dataset_sources[0]}")
    else:
        summary_lines.append("- Most recent dataset: none")

    timeline_lines = []
    for row in activity:
        created = str(row["created_at"] or "")
        event_type = str(row["event_type"] or "event")
        message = str(row["message"] or "")
        timeline_lines.append(f"- {created}: {_event_label(event_type)}{(': ' + message) if message else ''}")

    pcap_period_coverage = _pcap_period_coverage_rows(project_id, db_path=db_path)
    recommendation_lines = _recommendations(
        dataset_count=dataset_count,
        pcap_count=pcap_day_count,
        finding_count=len(findings),
        pcap_ips=pcap_ips,
        pcap_period_coverage=pcap_period_coverage,
    )
    pcap_day_rows = [
        {
            "label": format_period_day_label(day),
            "date": day,
            "count": packets,
            "bytes": pcap_day_bytes[day],
            "bytes_label": human_bytes(pcap_day_bytes[day], precision=2),
            "detail": f"{packets:,} packets / {human_bytes(pcap_day_bytes[day], precision=2)}",
        }
        for day, packets in sorted(pcap_day_packets.items())
    ]
    if undated_pcap_count:
        pcap_day_rows.append({
            "label": "Undated PCAP",
            "date": "",
            "count": undated_pcap_packets,
            "bytes": undated_pcap_bytes,
            "bytes_label": human_bytes(undated_pcap_bytes, precision=2),
            "detail": f"{undated_pcap_packets:,} packets / {human_bytes(undated_pcap_bytes, precision=2)}",
        })

    return {
        "summary_lines": summary_lines,
        "timeline_lines": timeline_lines,
        "recommendation_lines": recommendation_lines,
        "metrics": [
            {"label": "JSON Files", "value": dataset_count, "detail": "indexed in project"},
            {"label": "PCAP Periods", "value": pcap_day_count, "detail": f"{pcap_rollup.pcap_source_rows:,} saved analysis rows"},
            {"label": "Findings", "value": len(findings), "detail": "saved"},
            {"label": "Device IPs", "value": len(pcap_ips), "detail": "from saved PCAP"},
        ],
        "dataset_count": dataset_count,
        "pcap_count": len(pcaps),
        "pcap_day_count": pcap_day_count,
        "finding_count": len(findings),
        "pcap_device_ips": dict(pcap_ips),
        "evidence_counts": [
            {"label": "JSON Files", "count": dataset_count},
            {"label": "PCAP Periods", "count": pcap_day_count},
            {"label": "Findings", "count": len(findings)},
        ],
        "pcap_device_ip_rows": [
            {"label": ip, "count": count}
            for ip, count in pcap_ips.most_common()
        ],
        "activity_type_rows": [
            {"label": _event_label(event_type), "count": count}
            for event_type, count in activity_types.most_common()
        ],
        "pcap_day_rows": pcap_day_rows,
        "pcap_period_coverage": pcap_period_coverage,
        "capture_range": {
            "first_seen": capture_start,
            "last_seen": capture_end,
            "label": f"{capture_start} to {capture_end}" if capture_start and capture_end else "-",
        },
        "total_pcap_packets": total_packets,
        "total_pcap_bytes": total_pcap_bytes,
        "total_pcap_bytes_label": human_bytes(total_pcap_bytes, precision=2),
    }


def format_project_activity_profile(profile: dict[str, Any]) -> str:
    lines = list(profile.get("summary_lines") or [])
    recommendations = list(profile.get("recommendation_lines") or [])
    timeline = list(profile.get("timeline_lines") or [])

    if recommendations:
        lines.extend(["", "Next review:"])
        lines.extend(recommendations)

    if timeline:
        lines.extend(["", "Recent project activity:"])
        lines.extend(timeline[:12])

    return "\n".join(lines)


def _day_key(value: str) -> str:
    dt = parse_timestamp(value)
    return "" if dt is None else dt.strftime("%Y-%m-%d")


def _pcap_period_coverage_rows(project_id: int, *, db_path: Path) -> list[dict[str, Any]]:
    indexed: dict[str, int] = {}
    for item in list_ingest_items(project_id, file_type="pcap", limit=50000, db_path=db_path):
        day = str(item.observed_date or "").strip() or "undated"
        if day == "undated":
            continue
        indexed[day] = indexed.get(day, 0) + 1

    saved_days = set(list_saved_pcap_period_days(project_id, db_path=db_path))
    rows: list[dict[str, Any]] = []
    for day in sorted(indexed):
        file_count = indexed[day]
        saved = day in saved_days
        rows.append({
            "label": format_period_day_label(day),
            "date": day,
            "count": file_count,
            "detail": f"{file_count:,} PCAP files indexed",
            "status": "Saved to project" if saved else "Not saved yet",
        })
    for day in sorted(saved_days - set(indexed)):
        rows.append({
            "label": format_period_day_label(day),
            "date": day,
            "count": 0,
            "detail": "Saved summary without indexed files",
            "status": "Saved to project",
        })
    return rows


def _counter_label(values: Counter[str]) -> str:
    if not values:
        return "-"
    return ", ".join(f"{value} ({count})" for value, count in values.most_common(5))


def _event_label(event_type: str) -> str:
    labels = {
        "dataset_loaded": "JSON dataset loaded",
        "finding_created": "Finding created",
        "finding_updated": "Finding updated",
        "finding_deleted": "Finding deleted",
        "pcap_saved": "PCAP saved",
        "pcap_notes_added": "PCAP notes added",
    }
    return labels.get(event_type, event_type.replace("_", " ").title())


def _recommendations(
    *,
    dataset_count: int,
    pcap_count: int,
    finding_count: int,
    pcap_ips: Counter[str],
    pcap_period_coverage: list[dict[str, Any]] | None = None,
) -> list[str]:
    recommendations: list[str] = []

    if dataset_count and pcap_count:
        recommendations.append("- Compare JSON flow datasets with saved PCAP windows for the same time period.")
    elif dataset_count:
        recommendations.append("- Add PCAP evidence when available to validate metadata with packet-level context.")
    elif pcap_count:
        recommendations.append("- Add JSON flow datasets when available to compare PCAP evidence with longer-term behavior.")
    else:
        recommendations.append("- Load a dataset or save a PCAP source to start building the project profile.")

    if pcap_ips:
        recommendations.append("- Treat observed PCAP device IPs as session/context indicators; mobile devices may change IP over time.")

    missing_periods = [
        row for row in (pcap_period_coverage or [])
        if str(row.get("status") or "") == "Not saved yet"
    ]
    if missing_periods:
        labels = ", ".join(str(row.get("label") or "") for row in missing_periods[:8])
        extra = f" (+{len(missing_periods) - 8} more)" if len(missing_periods) > 8 else ""
        recommendations.append(
            f"- PCAP periods not saved to project yet: {labels}{extra}. "
            "Use Save Period to Project or Save All Periods on the PCAP page."
        )

    if finding_count:
        recommendations.append("- Review saved findings against the newest datasets and PCAP artifacts.")
    else:
        recommendations.append("- Promote notable flows, artifacts, or time windows to findings as the case develops.")

    return recommendations
