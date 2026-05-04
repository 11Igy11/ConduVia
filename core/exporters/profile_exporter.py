from __future__ import annotations

import html
from datetime import datetime
from pathlib import Path
from typing import Any

from core.db import Project
from core.exporters.case_context import build_case_context, context_cards_html


def export_activity_profile_html(
    file_path: str,
    *,
    profile: dict[str, Any],
    project_name: str = "",
    project: Project | None = None,
) -> None:
    path = Path(file_path)
    generated_at = datetime.now().strftime("%d.%m.%Y %H:%M:%S")
    behavior = dict(profile.get("behavior_profile") or {})
    case_context = build_case_context(project, project_name=project_name)

    html_doc = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>ViaNyquist Activity Profile</title>
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
    <h1>ViaNyquist Activity Profile</h1>
    <div class="muted">Project: {html.escape(project_name or 'Project')} | Exported: {html.escape(generated_at)}</div>
    <div class="grid">
      {context_cards_html(case_context, card_class="card", include_dataset_target=False)}
      {_metric_cards(profile)}
    </div>
  </div>

  <div class="section">
    <h2>Case Snapshot</h2>
    <div class="plain">{html.escape(_lines(profile.get("summary_lines")))}</div>
  </div>

  <div class="section">
    <h2>Evidence Overview</h2>
    <div class="two">
      <div>{_bar_table("Evidence Sources", profile.get("evidence_counts") or [], "count")}</div>
      <div>{_bar_table("PCAP Device IP Distribution", profile.get("pcap_device_ip_rows") or [], "count")}</div>
    </div>
  </div>

  <div class="section">
    <h2>Behavior Insights From Saved JSON Datasets</h2>
    <div class="note">These indicators describe observed device activity patterns. They are investigative indicators, not proof of the person's exact awake/asleep state or message content.</div>
    <div class="two">
      <div>{_bar_table("Service Groups By Volume", behavior.get("service_rows") or [], "bytes", "bytes_label")}</div>
      <div>{_bar_table("Observed Domains By Volume", behavior.get("domain_rows") or [], "bytes", "bytes_label")}</div>
    </div>
    <h2>Activity By Hour</h2>
    {_bar_table("Hourly Activity", behavior.get("hour_rows") or [], "count")}
    <h2>Activity Rhythm</h2>
    <div class="plain">{html.escape(_lines(behavior.get("routine_lines")))}</div>
  </div>

  <div class="section">
    <h2>Next Review</h2>
    <div class="plain">{html.escape(_lines(profile.get("recommendation_lines")))}</div>
  </div>

  <div class="section">
    <h2>Recent Project Timeline</h2>
    <div class="plain">{html.escape(_lines(profile.get("timeline_lines")))}</div>
  </div>
</div>
</body>
</html>"""

    path.write_text(html_doc, encoding="utf-8")


def _metric_cards(profile: dict[str, Any]) -> str:
    metrics = list(profile.get("metrics") or [])
    metrics.extend([
        {"label": "PCAP Volume", "value": profile.get("total_pcap_bytes_label") or "-"},
        {"label": "Capture Range", "value": (profile.get("capture_range") or {}).get("label") or "-"},
    ])
    return "\n".join(
        f'<div class="card"><div class="label">{html.escape(str(metric.get("label") or ""))}</div>'
        f'<div class="value">{html.escape(str(metric.get("value") or "-"))}</div></div>'
        for metric in metrics[:6]
    )


def _bar_table(title: str, rows: list[dict[str, Any]], value_key: str, value_label_key: str = "") -> str:
    if not rows:
        return f"<h2>{html.escape(title)}</h2><div class=\"plain\">No records.</div>"

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
        "<table><thead><tr><th>Item</th><th>Chart</th><th>Value</th></tr></thead>"
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
