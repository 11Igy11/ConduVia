from __future__ import annotations

import html
from datetime import datetime
from pathlib import Path
from typing import Any

from core.db import Project
from core.exporters.case_context import build_case_context, context_cards_html
from core.output_language import normalize_output_language


def export_activity_profile_html(
    file_path: str,
    *,
    profile: dict[str, Any],
    project_name: str = "",
    project: Project | None = None,
    report_language: str = "en",
) -> None:
    path = Path(file_path)
    lang = normalize_output_language(report_language, default="en")
    text = _report_text(lang)
    generated_at = datetime.now().strftime("%d.%m.%Y %H:%M:%S")
    behavior = dict(profile.get("behavior_profile") or {})
    case_context = build_case_context(project, project_name=project_name)

    html_doc = f"""<!DOCTYPE html>
<html lang="{html.escape(lang)}">
<head>
<meta charset="UTF-8">
<title>{html.escape(text['title'])}</title>
<style>
body {{ margin:0; padding:28px; font-family:"Segoe UI", Arial, sans-serif; color:#111827; background:#f3f4f6; }}
.report {{ max-width:1500px; margin:0 auto; }}
.hero {{ background:#111827; color:white; border-radius:14px; padding:24px 26px; margin-bottom:18px; }}
h1 {{ margin:0 0 8px; font-size:30px; }}
h2 {{ margin:24px 0 10px; font-size:18px; }}
.muted {{ color:#9ca3af; }}
.grid {{ display:grid; grid-template-columns:repeat(3, minmax(0, 1fr)); gap:10px; margin-top:18px; }}
.card {{ background:white; border:1px solid #e5e7eb; border-radius:10px; padding:14px; }}
.hero .card {{ background:rgba(255,255,255,.08); border-color:rgba(255,255,255,.16); color:white; }}
.label {{ font-size:11px; text-transform:uppercase; color:#6b7280; font-weight:700; letter-spacing:.08em; margin-bottom:5px; }}
.hero .label {{ color:#bfdbfe; }}
.value {{ font-size:18px; font-weight:700; word-break:break-word; }}
.plain {{ background:white; border:1px solid #e5e7eb; border-radius:12px; padding:18px 20px; font-size:14px; line-height:1.55; white-space:pre-wrap; }}
.note {{ border-left:4px solid #2563eb; padding:10px 12px; background:#eff6ff; margin:8px 0; }}
.two {{ display:grid; grid-template-columns:repeat(2, minmax(0, 1fr)); gap:14px; }}
.barcell {{ min-width:220px; }}
.bar {{ height:12px; background:#e5e7eb; border-radius:999px; overflow:hidden; }}
.bar span {{ display:block; height:100%; background:#2563eb; }}
table {{ width:100%; border-collapse:collapse; background:white; border:1px solid #e5e7eb; }}
th {{ text-align:left; background:#1f2937; color:white; font-size:12px; padding:9px; }}
td {{ border-top:1px solid #e5e7eb; padding:8px 9px; font-size:12px; vertical-align:top; }}
tr:nth-child(even) td {{ background:#f9fafb; }}
</style>
</head>
<body>
<div class="report">
  <div class="hero">
    <h1>{html.escape(text['title'])}</h1>
    <div class="muted">{html.escape(text['project'])}: {html.escape(project_name or text['project_fallback'])} | {html.escape(text['exported'])}: {html.escape(generated_at)}</div>
    <div class="grid">
      {context_cards_html(case_context, card_class="card", include_dataset_target=False)}
      {_metric_cards(profile, text)}
    </div>
  </div>

  <div class="section">
    <h2>{html.escape(text['case_snapshot'])}</h2>
    <div class="plain">{html.escape(_lines(profile.get("summary_lines")))}</div>
  </div>

  <div class="section">
    <h2>{html.escape(text['evidence_overview'])}</h2>
    <div class="two">
      <div>{_bar_table(text['evidence_sources'], profile.get("evidence_counts") or [], "count", text=text)}</div>
      <div>{_bar_table(text['pcap_device_ip_distribution'], profile.get("pcap_device_ip_rows") or [], "count", text=text)}</div>
    </div>
  </div>

  <div class="section">
    <h2>{html.escape(text['behavior_insights'])}</h2>
    <div class="note">{html.escape(text['behavior_note'])}</div>
    <div class="two">
      <div>{_bar_table(text['service_groups_by_volume'], behavior.get("service_rows") or [], "bytes", "bytes_label", text=text)}</div>
      <div>{_bar_table(text['observed_domains_by_volume'], behavior.get("domain_rows") or [], "bytes", "bytes_label", text=text)}</div>
    </div>
    <h2>{html.escape(text['activity_by_hour'])}</h2>
    {_bar_table(text['hourly_activity'], behavior.get("hour_rows") or [], "count", text=text)}
    <h2>{html.escape(text['activity_rhythm'])}</h2>
    <div class="plain">{html.escape(_lines(behavior.get("routine_lines")))}</div>
  </div>

  <div class="section">
    <h2>{html.escape(text['next_review'])}</h2>
    <div class="plain">{html.escape(_lines(profile.get("recommendation_lines")))}</div>
  </div>

  <div class="section">
    <h2>{html.escape(text['recent_project_timeline'])}</h2>
    <div class="plain">{html.escape(_lines(profile.get("timeline_lines")))}</div>
  </div>
</div>
</body>
</html>"""

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
    labels = text or _report_text("en")
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
        "Findings": text["findings"],
        "Device IPs": text["device_ips"],
        "PCAP Volume": text["pcap_volume"],
        "Capture Range": text["capture_range"],
    }.get(label, label)


def _report_text(language: str) -> dict[str, str]:
    if normalize_output_language(language, default="en") == "hr":
        return {
            "title": "ViaNyquist profil aktivnosti",
            "project": "Projekt",
            "project_fallback": "Projekt",
            "exported": "Izvezeno",
            "case_snapshot": "Snimka predmeta",
            "evidence_overview": "Pregled dokaza",
            "evidence_sources": "Izvori dokaza",
            "pcap_device_ip_distribution": "Distribucija IP adresa uredaja iz PCAP-a",
            "behavior_insights": "Uvidi u ponasanje iz spremljenih JSON datasetova",
            "behavior_note": "Ovi indikatori opisuju uocene obrasce aktivnosti uredaja. To su istrazni indikatori, a ne dokaz tocne budnosti/spavanja osobe ili sadrzaja poruka.",
            "service_groups_by_volume": "Grupe usluga po volumenu",
            "observed_domains_by_volume": "Uocene domene po volumenu",
            "activity_by_hour": "Aktivnost po satu",
            "hourly_activity": "Satna aktivnost",
            "activity_rhythm": "Ritam aktivnosti",
            "next_review": "Sljedeca provjera",
            "recent_project_timeline": "Nedavna vremenska crta projekta",
            "datasets": "JSON datasetovi",
            "json_datasets": "JSON datasetovi",
            "pcap_sources": "PCAP izvori",
            "findings": "Nalazi",
            "device_ips": "IP adrese uredaja",
            "pcap_volume": "PCAP volumen",
            "capture_range": "Raspon snimke",
            "item": "Stavka",
            "chart": "Graf",
            "value": "Vrijednost",
            "no_records": "Nema zapisa.",
        }
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
        "activity_by_hour": "Activity By Hour",
        "hourly_activity": "Hourly Activity",
        "activity_rhythm": "Activity Rhythm",
        "next_review": "Next Review",
        "recent_project_timeline": "Recent Project Timeline",
        "datasets": "JSON Datasets",
        "json_datasets": "JSON Datasets",
        "pcap_sources": "PCAP Sources",
        "findings": "Findings",
        "device_ips": "Device IPs",
        "pcap_volume": "PCAP Volume",
        "capture_range": "Capture Range",
        "item": "Item",
        "chart": "Chart",
        "value": "Value",
        "no_records": "No records.",
    }
