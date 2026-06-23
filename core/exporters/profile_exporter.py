from __future__ import annotations

import html
from datetime import datetime
from pathlib import Path
from typing import Any

from core.db import Project
from core.exporters.case_context import build_case_context, context_cards_html
from core.exporters.template_utils import load_template, logo_data_uri, render_template


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

    template = load_template("profile_export.html")
    html_doc = render_template(template, {
        "LANG": "en",
        "LOGO": logo_data_uri(),
        "TITLE": text["title"],
        "PROJECT_LABEL": text["project"],
        "PROJECT_NAME": html.escape(project_name or text["project_fallback"]),
        "EXPORTED_LABEL": text["exported"],
        "EXPORTED_AT": generated_at,
        "HERO_CARDS": "\n".join([
            context_cards_html(case_context, card_class="card", include_dataset_target=False),
            _metric_cards(profile, text),
        ]),
        "CASE_SNAPSHOT_LABEL": text["case_snapshot"],
        "CASE_SNAPSHOT": html.escape(_lines(profile.get("summary_lines"))),
        "EVIDENCE_OVERVIEW_LABEL": text["evidence_overview"],
        "EVIDENCE_SOURCES_TABLE": _bar_table(text["evidence_sources"], profile.get("evidence_counts") or [], "count", text=text),
        "PCAP_DEVICE_IP_TABLE": _bar_table(text["pcap_device_ip_distribution"], profile.get("pcap_device_ip_rows") or [], "count", text=text),
        "BEHAVIOR_INSIGHTS_LABEL": text["behavior_insights"],
        "BEHAVIOR_NOTE": text["behavior_note"],
        "SERVICE_GROUPS_TABLE": _bar_table(text["service_groups_by_volume"], behavior.get("service_rows") or [], "bytes", "bytes_label", text=text),
        "OBSERVED_DOMAINS_TABLE": _bar_table(text["observed_domains_by_volume"], behavior.get("domain_rows") or [], "bytes", "bytes_label", text=text),
        "JSON_ACTIVITY_BY_DAY_TABLE": _bar_table(text["json_activity_by_day"], profile.get("json_day_rows") or [], "count", "detail", text=text),
        "PCAP_ACTIVITY_BY_DAY_TABLE": _bar_table(text["pcap_activity_by_day"], profile.get("pcap_day_rows") or [], "count", "detail", text=text),
        "ACTIVITY_BY_HOUR_LABEL": text["activity_by_hour"],
        "HOURLY_ACTIVITY_TABLE": _bar_table(text["hourly_activity"], behavior.get("hour_rows") or [], "count", text=text),
        "ACTIVITY_RHYTHM_LABEL": text["activity_rhythm"],
        "ACTIVITY_RHYTHM": html.escape(_lines(behavior.get("routine_lines"))),
        "RECENT_PROJECT_TIMELINE_LABEL": text["recent_project_timeline"],
        "RECENT_PROJECT_TIMELINE": html.escape(_lines(profile.get("timeline_lines"))),
    }, escape_values=False)

    path.write_text(html_doc, encoding="utf-8")


def _metric_cards(profile: dict[str, Any], text: dict[str, str]) -> str:
    metrics = list(profile.get("metrics") or [])
    metrics.extend([
        {"label": text["pcap_volume"], "value": profile.get("total_pcap_bytes_label") or "-"},
        {"label": text["capture_range"], "value": (profile.get("capture_range") or {}).get("label") or "-"},
    ])
    return "\n".join(
        f'<div class="card"><div class="label">{html.escape(_metric_label(str(metric.get("label") or ""), text))}</div>'
        f'<div class="value">{html.escape(str(metric.get("value") or "-"))}</div></div>'
        for metric in metrics[:6]
    )


def _bar_table(title: str, rows: list[dict[str, Any]], value_key: str, value_label_key: str = "", *, text: dict[str, str] | None = None) -> str:
    labels = text or _report_text()
    if not rows:
        return f"<h2>{html.escape(title)}</h2><div class=\"plain\">{html.escape(labels['no_records'])}</div>"

    max_value = max(_safe_float(row.get(value_key)) for row in rows) or 1.0
    body = []
    for row in rows[:24]:
        label = str(row.get("label") or row.get("service") or row.get("domain") or "-")
        value = _safe_float(row.get(value_key))
        display = str(row.get(value_label_key) or row.get(value_key) or "0")
        width = max(2.0, min(100.0, (value / max_value) * 100.0)) if value else 0.0
        body.append(
            "<tr>"
            f"<td>{html.escape(label)}</td>"
            f"<td class=\"barcell\"><div class=\"bar\"><span style=\"width:{width:.1f}%\"></span></div></td>"
            f"<td>{html.escape(display)}</td>"
            "</tr>"
        )
    return (
        f"<h2>{html.escape(title)}</h2>"
        f"<table><thead><tr><th>{html.escape(labels['item'])}</th><th>{html.escape(labels['chart'])}</th><th>{html.escape(labels['value'])}</th></tr></thead>"
        f"<tbody>{''.join(body)}</tbody></table>"
    )


def _lines(value: Any) -> str:
    if isinstance(value, str):
        return value
    return "\n".join(str(line) for line in (value or [])) or "-"


def _safe_float(value: Any) -> float:
    try:
        return float(value or 0)
    except Exception:
        return 0.0


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
        "title": "ViaNyquist Activity Profile",
        "project": "Project",
        "project_fallback": "Project",
        "exported": "Exported",
        "case_snapshot": "Case Snapshot",
        "evidence_overview": "Evidence Overview",
        "evidence_sources": "Evidence Sources",
        "pcap_device_ip_distribution": "PCAP Device IP Distribution",
        "behavior_insights": "Behavior Insights From Saved JSON Datasets",
        "behavior_note": "These indicators describe observed device activity patterns. They are investigative indicators, not proof of the person's exact awake/asleep state or message content.",
        "service_groups_by_volume": "Service Groups By Volume",
        "observed_domains_by_volume": "Observed Domains By Volume",
        "json_activity_by_day": "JSON Activity By Day",
        "pcap_activity_by_day": "PCAP Volume By Day",
        "activity_by_hour": "Activity By Hour",
        "hourly_activity": "Hourly Activity",
        "activity_rhythm": "Activity Rhythm",
        "next_review": "Next Review",
        "recent_project_timeline": "Recent Project Timeline",
        "datasets": "JSON Datasets",
        "json_datasets": "JSON Datasets",
        "pcap_sources": "PCAP Sources",
        "pcap_days": "PCAP Days",
        "findings": "Findings",
        "device_ips": "Device IPs",
        "pcap_volume": "PCAP Volume",
        "capture_range": "Capture Range",
        "item": "Item",
        "chart": "Chart",
        "value": "Value",
        "no_records": "No records.",
    }

