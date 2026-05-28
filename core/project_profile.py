from __future__ import annotations

from collections import Counter
from pathlib import Path
from typing import Any

from core.db import (
    DEFAULT_DB_PATH,
    get_project,
    get_project_behavior_profile,
    list_activity,
    list_findings,
)
from core.formatters import human_bytes
from core.analysis_limits import MAX_PROFILE_ACTIVITY_EVENTS, MAX_PROFILE_TIMELINE_LINES
from core.period_comparison import build_period_comparison_rows
from core.project_evidence import build_project_evidence_snapshot
from core.project_identity import project_identifiers_text, subject_display_label, target_display_label


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
            "period_comparison_rows": [],
            "json_day_rows": [],
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

    evidence = build_project_evidence_snapshot(project_id, db_path=db_path)
    json_evidence = evidence["json"]
    pcap_evidence = evidence["pcap"]

    dataset_sources = json_evidence["dataset_sources"]
    dataset_files = json_evidence["available_files"]
    dataset_count = json_evidence["count"]
    pcaps = pcap_evidence["sources"]
    findings = list_findings(project_id, limit=50000, db_path=db_path)
    activity = list_activity(project_id, limit=50000 if MAX_PROFILE_ACTIVITY_EVENTS <= 0 else MAX_PROFILE_ACTIVITY_EVENTS, db_path=db_path)

    pcap_ips = Counter(pcap_evidence["device_ip_counts"])
    pcap_device_ip_rows = list(pcap_evidence["device_ip_rows"])
    behavior_index = get_project_behavior_profile(project_id, db_path=db_path) or {}
    json_day_rows = list(behavior_index.get("day_rows") or [])
    total_packets = int(pcap_evidence["total_packets"] or 0)
    total_pcap_bytes = int(pcap_evidence["total_bytes"] or 0)
    capture_start = str(pcap_evidence["capture_range"].get("first_seen") or "")
    capture_end = str(pcap_evidence["capture_range"].get("last_seen") or "")
    activity_types = Counter(str(row["event_type"] or "event") for row in activity)
    pcap_day_count = int(pcap_evidence["day_count"] or 0)
    pcap_file_count = int(pcap_evidence["source_count"] or 0)
    pcap_day_rows = list(pcap_evidence["day_rows"])
    pcap_period_coverage = list(pcap_evidence["period_coverage"])

    json_day_count = len(json_day_rows)

    summary_lines = [
        "Project Activity Profile",
        f"- Case subject: {subject_display_label(project)}",
        f"- Known identifiers: {project_identifiers_text(project)}",
        f"- Target fallback: {target_display_label(project)}",
        f"- JSON datasets: {dataset_count:,} files / {json_day_count:,} days",
        f"- PCAP periods: {pcap_file_count:,} files / {pcap_day_count:,} days",
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

    recommendation_lines = _recommendations(
        dataset_count=dataset_count,
        pcap_count=pcap_day_count,
        finding_count=len(findings),
        pcap_ips=pcap_ips,
        pcap_period_coverage=pcap_period_coverage,
    )
    period_comparison_rows = build_period_comparison_rows(json_day_rows, pcap_day_rows)

    return {
        "summary_lines": summary_lines,
        "timeline_lines": timeline_lines,
        "recommendation_lines": recommendation_lines,
        "metrics": [
            {
                "label": "JSON",
                "value": f"{dataset_count:,} files / {json_day_count:,} days",
                "detail": f"{dataset_count:,} JSON files across {json_day_count:,} activity days",
            },
            {
                "label": "PCAP",
                "value": f"{pcap_file_count:,} files / {pcap_day_count:,} days",
                "detail": f"{pcap_file_count:,} saved PCAP sources across {pcap_day_count:,} daily periods",
            },
            {"label": "Findings", "value": len(findings), "detail": "saved"},
            {"label": "Device IPs", "value": len(pcap_device_ip_rows), "detail": f"{len(pcap_device_ip_rows)} unique IPs across {pcap_day_count} PCAP periods"},
        ],
        "dataset_count": dataset_count,
        "pcap_count": len(pcaps),
        "pcap_day_count": pcap_day_count,
        "finding_count": len(findings),
        "pcap_device_ips": dict(pcap_ips),
        "evidence_counts": [
            {"label": "JSON", "count": dataset_count, "badge_label": f"{dataset_count:,} / {json_day_count:,} d"},
            {"label": "PCAP", "count": pcap_file_count, "badge_label": f"{pcap_file_count:,} / {pcap_day_count:,} d"},
            {"label": "Findings", "count": len(findings), "badge_label": str(len(findings))},
        ],
        "pcap_device_ip_rows": pcap_device_ip_rows,
        "activity_type_rows": _activity_type_rows(activity_types, pcap_day_count=pcap_day_count),
        "pcap_day_rows": pcap_day_rows,
        "pcap_period_coverage": pcap_period_coverage,
        "period_comparison_rows": period_comparison_rows,
        "json_day_rows": json_day_rows,
        "capture_range": {
            "first_seen": capture_start,
            "last_seen": capture_end,
            "label": f"{capture_start} to {capture_end}" if capture_start and capture_end else "-",
        },
        "total_pcap_packets": total_packets,
        "total_pcap_bytes": total_pcap_bytes,
        "total_pcap_bytes_label": pcap_evidence["total_bytes_label"],
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
        visible_timeline = timeline if MAX_PROFILE_TIMELINE_LINES <= 0 else timeline[:MAX_PROFILE_TIMELINE_LINES]
        lines.extend(visible_timeline)

    return "\n".join(lines)


def _counter_label(values: Counter[str]) -> str:
    if not values:
        return "-"
    return ", ".join(f"{value} ({count})" for value, count in values.most_common())


def _activity_type_rows(activity_types: Counter[str], *, pcap_day_count: int) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    pcap_events = int(activity_types.get("pcap_saved") or 0)
    if pcap_day_count:
        rows.append({"label": "PCAP periods saved", "count": pcap_day_count, "detail": f"{pcap_day_count} daily PCAP periods in project (not IP count)"})
    if pcap_events and pcap_events != pcap_day_count:
        rows.append({"label": "PCAP save log events", "count": pcap_events})
    for event_type, count in activity_types.most_common():
        if event_type == "pcap_saved":
            continue
        rows.append({"label": _event_label(event_type), "count": count})
    return rows


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
