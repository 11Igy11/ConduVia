from __future__ import annotations

import html
from datetime import datetime
from pathlib import Path
from typing import Any

from core.db import Project
from core.exporters.case_context import build_case_context, case_context_table_html
from core.exporters.html_blocks import ranked_list_html, stats_html
from core.exporters.template_utils import load_export_template, render_template


def export_activity_profile_html(
    file_path: str,
    *,
    profile: dict[str, Any],
    project_name: str = "",
    project: Project | None = None,
) -> None:
    path = Path(file_path)
    text = _report_text()
    generated_at = datetime.now().strftime("%d.%m.%Y %H:%M:%S")
    behavior = dict(profile.get("behavior_profile") or {})
    case_context = build_case_context(project, project_name=project_name)
    project_label = html.escape(project_name or text["project_fallback"])
    period = str((profile.get("capture_range") or {}).get("label") or "").strip() or "—"
    if period in {"-", "—"}:
        period = "—"

    json_files = _metric_display(profile, "JSON Datasets", "Datasets")
    pcap_sources = _metric_display(profile, "PCAP Sources", "PCAP Days")
    scope_parts = [part for part in (json_files, pcap_sources) if part]
    scope = " · ".join(scope_parts) or "Saved project evidence"

    html_doc = render_template(load_export_template("profile_export.html"), {
        "LANG": "en",
        "TITLE": text["title"],
        "DOCUMENT_TYPE": text["document_type"],
        "REPORT_TITLE": text["title"],
        "PERIOD_LABEL": text["period"],
        "PERIOD": html.escape(period),
        "EXPORTED_LABEL": text["exported"],
        "EXPORTED_AT": generated_at,
        "SOURCE_LABEL": text["source"],
        "SOURCE": html.escape(text["source_value"]),
        "SCOPE_LABEL": text["scope"],
        "SCOPE": html.escape(scope),
        "CASE_CONTEXT_LABEL": text["case_context"],
        "CASE_TABLE": case_context_table_html(case_context, include_dataset_target=False),
        "PROJECT_NAME": project_label,
        "PREPARED_LABEL": text["prepared"],
        "EVIDENCE_SUMMARY_LABEL": text["evidence_summary"],
        "STATS_SECTION": _metrics_stats(profile, text),
        "OPERATIONAL_SUMMARY": html.escape(_operational_summary(profile.get("summary_lines"))),
        "EVIDENCE_OVERVIEW_LABEL": text["evidence_overview"],
        "EVIDENCE_SOURCES_TABLE": ranked_list_html(
            text["evidence_sources"], profile.get("evidence_counts") or [], empty_text=text["no_records"]
        ),
        "PCAP_DEVICE_IP_TABLE": ranked_list_html(
            text["pcap_device_ip_distribution"], profile.get("pcap_device_ip_rows") or [], empty_text=text["no_records"]
        ),
        "BEHAVIOR_INSIGHTS_LABEL": text["behavior_insights"],
        "SERVICE_GROUPS_TABLE": ranked_list_html(
            text["service_groups_by_volume"],
            behavior.get("service_rows") or [],
            value_key="bytes",
            value_label_key="bytes_label",
            empty_text=text["no_records"],
        ),
        "OBSERVED_DOMAINS_TABLE": ranked_list_html(
            text["observed_domains_by_volume"],
            behavior.get("domain_rows") or [],
            value_key="bytes",
            value_label_key="bytes_label",
            empty_text=text["no_records"],
        ),
        "JSON_ACTIVITY_BY_DAY_TABLE": ranked_list_html(
            text["json_activity_by_day"],
            profile.get("json_day_rows") or [],
            meta_key="detail",
            empty_text=text["no_records"],
        ),
        "PCAP_ACTIVITY_BY_DAY_TABLE": ranked_list_html(
            text["pcap_activity_by_day"],
            profile.get("pcap_day_rows") or [],
            meta_key="detail",
            empty_text=text["no_records"],
        ),
        "ACTIVITY_BY_HOUR_LABEL": text["activity_by_hour"],
        "HOURLY_ACTIVITY_TABLE": ranked_list_html(
            "", behavior.get("hour_rows") or [], empty_text=text["no_records"]
        ),
        "ACTIVITY_RHYTHM_LABEL": text["activity_rhythm"],
        "ACTIVITY_RHYTHM": html.escape(_lines(behavior.get("routine_lines"))),
        "RECENT_PROJECT_TIMELINE_LABEL": text["recent_project_timeline"],
        "RECENT_PROJECT_TIMELINE": html.escape(_lines(profile.get("timeline_lines"))),
    }, escape_values=False)

    path.write_text(html_doc, encoding="utf-8")


def _metric_display(profile: dict[str, Any], *labels: str) -> str:
    wanted = {label.casefold() for label in labels}
    for metric in profile.get("metrics") or []:
        label = str(metric.get("label") or "")
        if label.casefold() not in wanted:
            continue
        value = metric.get("lines")
        if value:
            return " · ".join(str(line) for line in value)
        return str(metric.get("value") or "").strip()
    return ""


def _metrics_stats(profile: dict[str, Any], text: dict[str, str]) -> str:
    items: list[tuple[str, Any]] = []
    for metric in profile.get("metrics") or []:
        items.append((_metric_label(str(metric.get("label") or ""), text), _metric_value(metric)))
    items.append((text["pcap_volume"], profile.get("total_pcap_bytes_label") or "-"))
    items.append((text["capture_range"], (profile.get("capture_range") or {}).get("label") or "-"))
    return stats_html(items[:6])


def _metric_value(metric: dict[str, Any]) -> str:
    lines = metric.get("lines")
    if lines:
        return " · ".join(str(line) for line in lines)
    return str(metric.get("value") or "-")


def _operational_summary(summary_lines: Any) -> str:
    lines = []
    for raw in summary_lines or []:
        line = str(raw or "").strip()
        if not line or line == "Project Activity Profile":
            continue
        lowered = line.casefold()
        if lowered.startswith("- case subject:"):
            continue
        if lowered.startswith("- known identifiers:"):
            continue
        if lowered.startswith("- target fallback:"):
            continue
        if lowered.startswith("- klasa:"):
            continue
        if lowered.startswith("- urbroj:"):
            continue
        if lowered.startswith("- lawful interception dates"):
            continue
        lines.append(line)
    return "\n".join(lines) or "-"


def _lines(value: Any) -> str:
    if isinstance(value, str):
        return value
    return "\n".join(str(line) for line in (value or [])) or "-"


def _metric_label(label: str, text: dict[str, str]) -> str:
    return {
        "Datasets": text["json_datasets"],
        "JSON Datasets": text["json_datasets"],
        "PCAP Sources": text["pcap_sources"],
        "PCAP Days": text["pcap_days"],
        "Findings": text["findings"],
        "Device IPs": text["device_ips"],
        "PCAP Volume": text["pcap_volume"],
        "Capture Range": text["capture_range"],
    }.get(label, label)


def _report_text() -> dict[str, str]:
    return {
        "title": "Activity Profile",
        "document_type": "Activity Profile",
        "project_fallback": "Project",
        "period": "Period",
        "exported": "Exported",
        "source": "Source",
        "source_value": "Saved project evidence",
        "scope": "Scope",
        "case_context": "Case context",
        "prepared": "Prepared",
        "evidence_summary": "Evidence summary",
        "evidence_overview": "Evidence Overview",
        "evidence_sources": "Evidence Sources",
        "pcap_device_ip_distribution": "PCAP Device IP Distribution",
        "behavior_insights": "Behavior Insights From Saved JSON Datasets",
        "service_groups_by_volume": "Service Groups By Volume",
        "observed_domains_by_volume": "Observed Domains By Volume",
        "json_activity_by_day": "JSON Activity By Day",
        "pcap_activity_by_day": "PCAP Volume By Day",
        "activity_by_hour": "Activity By Hour",
        "activity_rhythm": "Activity Rhythm",
        "recent_project_timeline": "Recent Project Timeline",
        "json_datasets": "JSON Datasets",
        "pcap_sources": "PCAP Sources",
        "pcap_days": "PCAP Days",
        "findings": "Findings",
        "device_ips": "Device IPs",
        "pcap_volume": "PCAP Volume",
        "capture_range": "Capture Range",
        "no_records": "No records.",
    }
