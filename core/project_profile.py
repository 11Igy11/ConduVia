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
from core.formatters import human_bytes


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
            "finding_count": 0,
            "pcap_device_ips": {},
            "total_pcap_packets": 0,
            "total_pcap_bytes": 0,
            "total_pcap_bytes_label": human_bytes(0, precision=2),
        }

    datasets = list_recent_datasets(project_id, limit=1000, db_path=db_path)
    pcaps = list_pcap_sources(project_id, limit=1000, db_path=db_path)
    findings = list_findings(project_id, limit=1000, db_path=db_path)
    activity = list_activity(project_id, limit=200, db_path=db_path)

    pcap_ips = Counter(src.likely_device_ip for src in pcaps if src.likely_device_ip)
    capture_starts = [src.first_seen for src in pcaps if src.first_seen]
    capture_ends = [src.last_seen for src in pcaps if src.last_seen]
    total_packets = sum(src.packet_count for src in pcaps)
    total_pcap_bytes = sum(src.wire_bytes for src in pcaps)
    capture_start = min(capture_starts) if capture_starts else ""
    capture_end = max(capture_ends) if capture_ends else ""
    activity_types = Counter(str(row["event_type"] or "event") for row in activity)

    summary_lines = [
        "Project Activity Profile",
        f"- Target: {_target_label(project.target_identifier, project.target_type)}",
        f"- Dataset loads: {len(datasets)}",
        f"- PCAP sources: {len(pcaps)}",
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

    if datasets:
        summary_lines.append(f"- Most recent dataset: {datasets[0]}")
    else:
        summary_lines.append("- Most recent dataset: none")

    timeline_lines = []
    for row in activity:
        created = str(row["created_at"] or "")
        event_type = str(row["event_type"] or "event")
        message = str(row["message"] or "")
        timeline_lines.append(f"- {created}: {_event_label(event_type)}{(': ' + message) if message else ''}")

    recommendation_lines = _recommendations(
        dataset_count=len(datasets),
        pcap_count=len(pcaps),
        finding_count=len(findings),
        pcap_ips=pcap_ips,
    )

    return {
        "summary_lines": summary_lines,
        "timeline_lines": timeline_lines,
        "recommendation_lines": recommendation_lines,
        "metrics": [
            {"label": "Datasets", "value": len(datasets), "detail": "loaded"},
            {"label": "PCAP Sources", "value": len(pcaps), "detail": "saved"},
            {"label": "Findings", "value": len(findings), "detail": "saved"},
            {"label": "Device IPs", "value": len(pcap_ips), "detail": "from PCAP"},
        ],
        "dataset_count": len(datasets),
        "pcap_count": len(pcaps),
        "finding_count": len(findings),
        "pcap_device_ips": dict(pcap_ips),
        "evidence_counts": [
            {"label": "Datasets", "count": len(datasets)},
            {"label": "PCAP Sources", "count": len(pcaps)},
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


def _target_label(identifier: str, target_type: str) -> str:
    identifier = (identifier or "").strip()
    target_type = (target_type or "").strip()
    if identifier and target_type:
        return f"{target_type} / {identifier}"
    if identifier:
        return identifier
    if target_type:
        return target_type
    return "-"


def _counter_label(values: Counter[str]) -> str:
    if not values:
        return "-"
    return ", ".join(f"{value} ({count})" for value, count in values.most_common(5))


def _event_label(event_type: str) -> str:
    labels = {
        "dataset_loaded": "Dataset loaded",
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

    if len(pcap_ips) > 1:
        recommendations.append("- Review PCAP device IP consistency before treating all captures as the same target.")
    elif len(pcap_ips) == 1:
        recommendations.append("- Device IP is consistent across saved PCAP sources so far.")

    if finding_count:
        recommendations.append("- Review saved findings against the newest datasets and PCAP artifacts.")
    else:
        recommendations.append("- Promote notable flows, artifacts, or time windows to findings as the case develops.")

    return recommendations
