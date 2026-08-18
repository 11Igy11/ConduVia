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
from core.evidence_policy import format_period_day_label
from core.formatters import human_bytes
from core.analysis_limits import (
    MAX_EVIDENCE_SNAPSHOT_ITEMS,
    MAX_PROFILE_ACTIVITY_EVENTS,
    MAX_PROFILE_TIMELINE_LINES,
)
from core.period_comparison import build_period_comparison_rows
from core.project_evidence import build_project_evidence_snapshot, get_project_evidence_totals
from core.project_identity import project_identifiers_text, subject_display_label, target_display_label
from core.project_readiness import evaluate_profile_readiness
from core.case_metadata import (
    format_active_order_validity,
    LAWFUL_INTERCEPTION_DATES_ACTIVE_LABEL,
    format_klasa_summary,
    format_urbroj_summary,
    load_case_metadata,
)


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

    evidence = build_project_evidence_snapshot(project_id, db_path=db_path, limit=MAX_EVIDENCE_SNAPSHOT_ITEMS)
    totals = dict(evidence.get("totals") or get_project_evidence_totals(project_id, db_path=db_path))
    json_evidence = evidence["json"]
    pcap_evidence = evidence["pcap"]

    dataset_sources = json_evidence["dataset_sources"]
    dataset_files = json_evidence["available_files"]
    dataset_count = int(
        totals.get("json_file_count")
        or json_evidence.get("count")
        or 0
    )
    pcaps = pcap_evidence["sources"]
    findings = list_findings(project_id, limit=50000, db_path=db_path)
    activity = list_activity(project_id, limit=50000 if MAX_PROFILE_ACTIVITY_EVENTS <= 0 else MAX_PROFILE_ACTIVITY_EVENTS, db_path=db_path)

    pcap_ips = Counter(pcap_evidence["device_ip_counts"])
    pcap_device_ip_rows = list(pcap_evidence["device_ip_rows"])
    behavior_index = get_project_behavior_profile(project_id, db_path=db_path) or {}
    behavior_flow_day_rows = list(behavior_index.get("day_rows") or [])
    json_day_rows = _merge_json_profile_day_rows(
        list(json_evidence.get("json_day_rows") or []),
        behavior_flow_day_rows,
    )
    total_packets = int(pcap_evidence["total_packets"] or 0)
    total_pcap_bytes = int(pcap_evidence["total_bytes"] or 0)
    capture_range = dict(pcap_evidence.get("capture_range") or {})
    capture_label = str(capture_range.get("label") or "-")
    activity_types = Counter(str(row["event_type"] or "event") for row in activity)
    pcap_day_count = int(totals.get("pcap_saved_day_count") or pcap_evidence.get("saved_day_count") or 0)
    pcap_file_count = int(totals.get("pcap_source_count") or pcap_evidence.get("source_count") or 0)
    pcap_indexed_file_count = int(totals.get("pcap_indexed_file_count") or 0)
    pcap_indexed_day_count = int(totals.get("pcap_indexed_day_count") or 0)
    if not pcap_day_count:
        pcap_day_count = int(pcap_evidence.get("day_count") or 0)
    pcap_chart_file_count = pcap_indexed_file_count or pcap_file_count
    pcap_day_rows = list(pcap_evidence["day_rows"])
    pcap_period_coverage = list(pcap_evidence["period_coverage"])

    json_file_day_count = int(totals.get("json_day_count") or json_evidence.get("day_count") or 0)
    json_index_file_count = int(behavior_index.get("json_file_count") or 0)
    index_building = bool(dataset_count and not json_day_rows and (json_index_file_count or json_file_day_count))
    readiness = evaluate_profile_readiness(
        json_file_count=dataset_count,
        json_indexed_day_count=json_file_day_count,
        pcap_day_count=pcap_day_count,
        pcap_indexed_day_count=pcap_indexed_day_count,
        behavior_index=behavior_index,
        index_building=index_building,
    )
    json_day_count = len(json_day_rows) or json_file_day_count
    flow_activity_day_count = len(behavior_flow_day_rows)
    json_metric_lines = [
        f"{dataset_count:,} files",
        f"{json_file_day_count:,} indexed days",
    ]
    if flow_activity_day_count and flow_activity_day_count != json_day_count:
        json_metric_lines.append(f"{flow_activity_day_count:,} flow-timestamp days")
    pcap_metric_lines = [
        f"{pcap_chart_file_count:,} indexed files",
        f"{(pcap_indexed_day_count or pcap_day_count):,} indexed days",
        f"{pcap_day_count:,} saved days",
    ]
    case_metadata = load_case_metadata(project_id, db_path=db_path)

    summary_lines = [
        "Project Activity Profile",
        f"- Case subject: {subject_display_label(project)}",
        f"- Known identifiers: {project_identifiers_text(project)}",
        f"- Target fallback: {target_display_label(project)}",
        f"- Klasa: {format_klasa_summary(case_metadata)}",
        f"- Urbroj: {format_urbroj_summary(case_metadata)}",
        f"- {LAWFUL_INTERCEPTION_DATES_ACTIVE_LABEL}: {format_active_order_validity(case_metadata)}",
        f"- JSON datasets: {dataset_count:,} files / {_json_summary_day_text(json_file_day_count, flow_activity_day_count)}",
        f"- PCAP evidence: {pcap_chart_file_count:,} indexed files / {(pcap_indexed_day_count or pcap_day_count):,} indexed days / {pcap_day_count:,} saved days",
        f"- Findings: {len(findings)}",
    ]

    if pcaps:
        summary_lines.extend([
            f"- PCAP packet volume: {total_packets:,} packets / {human_bytes(total_pcap_bytes, precision=2)}",
            f"- PCAP capture range: {capture_label}",
            f"- PCAP device IPs: {len(pcap_device_ip_rows):,} unique",
        ])
    else:
        summary_lines.append("- PCAP capture range: no PCAP sources saved yet")

    timeline_lines = []
    for row in activity:
        created = str(row["created_at"] or "")
        event_type = str(row["event_type"] or "event")
        message = str(row["message"] or "")
        timeline_lines.append(f"- {created}: {_event_label(event_type)}{(': ' + message) if message else ''}")

    recommendation_lines = _recommendations(
        dataset_count=dataset_count,
        pcap_count=pcap_day_count,
        pcap_indexed_day_count=pcap_indexed_day_count,
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
                "lines": json_metric_lines,
                "value": " · ".join(json_metric_lines),
                "detail": (
                    f"{dataset_count:,} JSON files — behavior index building from saved evidence"
                    if index_building
                    else (
                        f"{dataset_count:,} JSON files · {json_file_day_count:,} indexed days"
                        + (
                            f" · {flow_activity_day_count:,} flow-timestamp days"
                            if flow_activity_day_count and flow_activity_day_count != json_day_count
                            else ""
                        )
                    )
                ),
            },
            {
                "label": "PCAP",
                "lines": pcap_metric_lines,
                "value": " · ".join(pcap_metric_lines),
                "detail": (
                    f"{pcap_chart_file_count:,} PCAP files in ingest index · "
                    f"{(pcap_indexed_day_count or pcap_day_count):,} indexed file-days · "
                    f"{pcap_day_count:,} daily periods saved to project"
                ),
            },
            {"label": "Findings", "value": len(findings), "detail": "saved"},
            {"label": "Device IPs", "value": len(pcap_device_ip_rows), "detail": f"{len(pcap_device_ip_rows)} unique IPs across {pcap_day_count} saved PCAP days"},
        ],
        "dataset_count": dataset_count,
        "pcap_count": len(pcaps),
        "pcap_file_count": pcap_file_count,
        "pcap_indexed_file_count": pcap_indexed_file_count,
        "pcap_indexed_day_count": pcap_indexed_day_count,
        "pcap_day_count": pcap_day_count,
        "finding_count": len(findings),
        "pcap_device_ips": dict(pcap_ips),
        "evidence_counts": [
            {"label": "JSON", "count": dataset_count, "badge_label": f"{dataset_count:,} / {json_file_day_count:,} d"},
            {"label": "PCAP", "count": pcap_chart_file_count, "badge_label": f"{pcap_chart_file_count:,} / {pcap_day_count:,} d"},
            {"label": "Findings", "count": len(findings), "badge_label": str(len(findings))},
        ],
        "pcap_device_ip_rows": pcap_device_ip_rows,
        "activity_type_rows": _activity_type_rows(activity_types, pcap_day_count=pcap_day_count),
        "pcap_day_rows": pcap_day_rows,
        "pcap_period_coverage": pcap_period_coverage,
        "period_comparison_rows": period_comparison_rows,
        "json_day_rows": json_day_rows,
        "readiness": readiness,
        "capture_range": capture_range,
        "total_pcap_packets": total_packets,
        "total_pcap_bytes": total_pcap_bytes,
        "total_pcap_bytes_label": pcap_evidence["total_bytes_label"],
    }


def format_project_activity_profile(profile: dict[str, Any]) -> str:
    lines = list(profile.get("summary_lines") or [])
    recommendations = list(profile.get("recommendation_lines") or [])
    timeline = list(profile.get("timeline_lines") or [])

    if recommendations:
        lines.extend(["", "Recommendations:"])
        lines.extend(recommendations)

    if timeline:
        lines.extend(["", "Recent project activity:"])
        visible_timeline = timeline if MAX_PROFILE_TIMELINE_LINES <= 0 else timeline[:MAX_PROFILE_TIMELINE_LINES]
        lines.extend(visible_timeline)

    return "\n".join(lines)


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
        "project_created": "Project created",
        "project_edited": "Project edited",
        "import_period_selected": "Period selected",
        "pcap_batch_finished": "PCAP batch finished",
        "case_metadata_mismatch": "Case metadata warning",
        "repository_hit": "Repository hit",
        "ai_summary_generated": "AI summary generated",
    }
    return labels.get(event_type, event_type.replace("_", " ").title())


def _recommendations(
    *,
    dataset_count: int,
    pcap_count: int,
    pcap_indexed_day_count: int = 0,
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

    if pcap_indexed_day_count and pcap_count and pcap_indexed_day_count > pcap_count:
        recommendations.append(
            f"- PCAP ingest covers {pcap_indexed_day_count:,} indexed days but only {pcap_count:,} "
            "daily periods are saved — run Re-analyze Period on the PCAP page to save missing days."
        )

    missing_periods = [
        row for row in (pcap_period_coverage or [])
        if str(row.get("status") or "") == "Not saved yet"
    ]
    if missing_periods:
        labels = ", ".join(str(row.get("label") or "") for row in missing_periods[:8])
        extra = f" (+{len(missing_periods) - 8} more)" if len(missing_periods) > 8 else ""
        recommendations.append(
            f"- PCAP periods not saved to project yet: {labels}{extra}. "
            "Use Save Period to Project on the PCAP page."
        )

    if finding_count:
        recommendations.append("- Review saved findings against the newest datasets and PCAP artifacts.")
    else:
        recommendations.append("- Promote notable flows, artifacts, or time windows to findings as the case develops.")

    return recommendations


def _json_summary_day_text(indexed_day_count: int, flow_activity_day_count: int) -> str:
    text = f"{indexed_day_count:,} indexed days"
    if flow_activity_day_count and flow_activity_day_count != indexed_day_count:
        text += f" / {flow_activity_day_count:,} flow-timestamp days"
    return text


def _merge_json_profile_day_rows(
    evidence_day_rows: list[dict[str, Any]] | None,
    behavior_day_rows: list[dict[str, Any]] | None,
) -> list[dict[str, Any]]:
    """Align Profile JSON day charts with saved evidence calendar days."""
    flow_by_date = {
        str(row.get("date") or "").strip(): row
        for row in (behavior_day_rows or [])
        if str(row.get("date") or "").strip()
    }
    rows: list[dict[str, Any]] = []
    for day_row in evidence_day_rows or []:
        day = str(day_row.get("day") or "").strip()
        if not day or day == "undated":
            continue
        flow_row = flow_by_date.get(day) or {}
        flow_count = int(flow_row.get("count") or 0)
        file_count = int(day_row.get("file_count") or 0)
        flow_bytes = int(flow_row.get("bytes") or 0)
        rows.append({
            "label": format_period_day_label(day),
            "date": day,
            "count": flow_count or file_count,
            "bytes": flow_bytes,
            "bytes_label": str(flow_row.get("bytes_label") or human_bytes(flow_bytes, precision=2)),
            "file_count": file_count,
            "flow_count": flow_count,
            "detail": (
                f"{flow_count:,} flows / {human_bytes(flow_bytes, precision=2)}"
                if flow_count
                else f"{file_count:,} JSON files indexed"
            ),
        })
    return rows
