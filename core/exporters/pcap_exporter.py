from __future__ import annotations

import html
from datetime import datetime
from pathlib import Path
from typing import Any

from core.db import Project
from core.formatters import human_bytes
from core.pcap_analyzer import PcapSummary, build_investigator_view
from core.project_identity import project_identifiers_text, subject_display_label


def export_pcap_summary_html(
    file_path: str,
    summary: PcapSummary,
    *,
    project: Project | None = None,
    project_name: str = "",
) -> None:
    path = Path(file_path)

    def rows(items: list[dict[str, Any]], columns: list[tuple[str, str]]) -> str:
        if not items:
            return "<tr><td colspan=\"99\">No records.</td></tr>"
        parts = []
        for item in items:
            cells = "".join(f"<td>{html.escape(str(item.get(key, '')))}</td>" for key, _label in columns)
            parts.append(f"<tr>{cells}</tr>")
        return "\n".join(parts)

    def headers(columns: list[tuple[str, str]]) -> str:
        return "".join(f"<th>{html.escape(label)}</th>" for _key, label in columns)

    connections = []
    for flow in summary.flows[:200]:
        connections.append({
            "source": _endpoint(flow.get("src_ip"), flow.get("src_port")),
            "destination": _endpoint(flow.get("dst_ip"), flow.get("dst_port")),
            "protocol": flow.get("protocol"),
            "application": flow.get("application_name"),
            "host": flow.get("requested_server_name"),
            "bytes": human_bytes(flow.get("bidirectional_bytes"), precision=2),
            "packets": flow.get("bidirectional_packets"),
            "first": flow.get("bidirectional_first_seen_ms"),
            "last": flow.get("bidirectional_last_seen_ms"),
            "visible": flow.get("pcap_payload_preview"),
        })

    readable = summary.readable_samples[:200]
    artifacts = summary.artifacts[:400]
    communications = [
        {
            **row,
            "bytes": human_bytes(row.get("bytes"), precision=2),
            "duration": _duration_compact(row.get("duration_ms")),
        }
        for row in (summary.communication_rows or [])[:200]
    ]
    communication_brief = _communication_brief(summary.communication_rows or [])
    investigator = build_investigator_view(summary)
    generated_at = datetime.now().strftime("%d.%m.%Y %H:%M:%S")
    period = f"{summary.first_seen or '-'} - {summary.last_seen or '-'}"
    project_label = project.name if project else (project_name or "-")
    subject_label = subject_display_label(project) if project else "-"
    identifiers_label = project_identifiers_text(project) if project else "-"

    html_doc = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>ViaNyquist PCAP Summary</title>
<style>
body {{ margin:0; padding:28px; font-family:"Segoe UI", Arial, sans-serif; color:#111827; background:#f3f4f6; }}
.report {{ max-width:1500px; margin:0 auto; }}
.hero {{ background:#111827; color:white; border-radius:14px; padding:24px 26px; margin-bottom:18px; }}
h1 {{ margin:0 0 8px; font-size:30px; }}
h2 {{ margin:24px 0 10px; font-size:18px; }}
.muted {{ color:#9ca3af; }}
.grid {{ display:grid; grid-template-columns:repeat(4, minmax(0, 1fr)); gap:10px; margin-top:18px; }}
.card {{ background:white; border:1px solid #e5e7eb; border-radius:10px; padding:14px; }}
.hero .card {{ background:rgba(255,255,255,.08); border-color:rgba(255,255,255,.16); color:white; }}
.label {{ font-size:11px; text-transform:uppercase; color:#6b7280; font-weight:700; letter-spacing:.08em; margin-bottom:5px; }}
.hero .label {{ color:#bfdbfe; }}
.value {{ font-size:17px; font-weight:700; word-break:break-word; }}
.note {{ border-left:4px solid #2563eb; padding:10px 12px; background:#eff6ff; margin:8px 0; }}
.plain {{ background:white; border:1px solid #e5e7eb; border-radius:12px; padding:18px 20px; font-size:15px; line-height:1.55; }}
.points {{ display:grid; grid-template-columns:repeat(2, minmax(0, 1fr)); gap:8px; margin-top:12px; }}
.point {{ background:#f9fafb; border:1px solid #e5e7eb; border-radius:8px; padding:10px 12px; }}
.briefgrid {{ display:grid; grid-template-columns:repeat(4, minmax(0, 1fr)); gap:10px; margin:10px 0 12px; }}
.briefcard {{ background:white; border:1px solid #dbeafe; border-radius:10px; padding:12px 14px; }}
.briefcard .value {{ font-size:20px; color:#1d4ed8; }}
.tag {{ display:inline-block; border-radius:999px; padding:3px 8px; font-size:11px; font-weight:700; background:#e5e7eb; color:#111827; }}
.tag.high {{ background:#dcfce7; color:#166534; }}
.tag.medium {{ background:#dbeafe; color:#1e40af; }}
.tag.low {{ background:#f3f4f6; color:#4b5563; }}
.evidence-grid {{ display:grid; grid-template-columns:repeat(2, minmax(0, 1fr)); gap:10px; margin-top:10px; }}
.evidence-card {{ background:white; border:1px solid #e5e7eb; border-radius:10px; padding:12px 14px; }}
.evidence-title {{ font-weight:700; margin-bottom:6px; }}
.evidence-meta {{ color:#4b5563; font-size:12px; margin-bottom:8px; }}
.evidence-text {{ font-size:12px; line-height:1.45; }}
.barcell {{ min-width:190px; }}
.bar {{ height:12px; background:#e5e7eb; border-radius:999px; overflow:hidden; }}
.bar span {{ display:block; height:100%; background:#2563eb; }}
table {{ width:100%; border-collapse:collapse; background:white; border:1px solid #e5e7eb; }}
th {{ text-align:left; background:#1f2937; color:white; font-size:12px; padding:9px; position:sticky; top:0; }}
td {{ border-top:1px solid #e5e7eb; padding:8px 9px; font-size:12px; vertical-align:top; }}
tr:nth-child(even) td {{ background:#f9fafb; }}
.section {{ margin-bottom:18px; }}
</style>
</head>
<body>
<div class="report">
  <div class="hero">
    <h1>ViaNyquist PCAP Summary</h1>
    <div class="muted">{html.escape(summary.file_name)} | Exported: {html.escape(generated_at)}</div>
    <div class="grid">
      <div class="card"><div class="label">Project</div><div class="value">{html.escape(project_label)}</div></div>
      <div class="card"><div class="label">Case Subject</div><div class="value">{html.escape(subject_label)}</div></div>
      <div class="card"><div class="label">Known Identifiers</div><div class="value">{html.escape(identifiers_label)}</div></div>
      <div class="card"><div class="label">Format</div><div class="value">{html.escape(summary.format)}</div></div>
      <div class="card"><div class="label">Packets</div><div class="value">{summary.packet_count:,}</div></div>
      <div class="card"><div class="label">Traffic Volume</div><div class="value">{html.escape(human_bytes(summary.wire_bytes, precision=2))}</div></div>
      <div class="card"><div class="label">Likely Device IP</div><div class="value">{html.escape(summary.likely_device_ip or '-')}</div></div>
      <div class="card"><div class="label">Capture Period</div><div class="value">{html.escape(period)}</div></div>
      <div class="card"><div class="label">DNS Queries</div><div class="value">{len(summary.dns_queries)}</div></div>
      <div class="card"><div class="label">TLS SNI Hosts</div><div class="value">{len(summary.tls_sni)}</div></div>
      <div class="card"><div class="label">Readable Samples</div><div class="value">{len(summary.readable_samples)}</div></div>
    </div>
  </div>

  <div class="section">
    <h2>Investigator View</h2>
    <div class="plain">
      {html.escape(str(investigator.get("plain_summary") or ""))}
      <div class="points">
        {''.join(f'<div class="point">{html.escape(str(point))}</div>' for point in investigator.get("key_points", []))}
      </div>
    </div>
  </div>

  <div class="section">
    <h2>Communication Highlights</h2>
    <div class="note">These rows are investigative indicators based on metadata such as host names, ports, protocol, duration and traffic volume. They do not prove message content or confirm a call by themselves.</div>
    <div class="briefgrid">
      <div class="briefcard"><div class="label">Classified indicators</div><div class="value">{communication_brief['total']}</div></div>
      <div class="briefcard"><div class="label">Messaging / push</div><div class="value">{communication_brief['messaging']}</div></div>
      <div class="briefcard"><div class="label">Call / media candidates</div><div class="value">{communication_brief['media']}</div></div>
      <div class="briefcard"><div class="label">Visible services</div><div class="value">{html.escape(communication_brief['services'])}</div></div>
    </div>
    <table><thead><tr>{headers([('service', 'Service'), ('activity_type', 'Indicator'), ('confidence_html', 'Confidence'), ('host', 'Host / Signal'), ('protocol', 'Protocol'), ('bytes', 'Volume'), ('packets', 'Packets'), ('duration', 'Duration'), ('first_seen', 'First Seen')])}</tr></thead><tbody>{_communication_rows(communications)}</tbody></table>
    <h2>Communication Evidence Details</h2>
    <div class="evidence-grid">
      {_communication_evidence_cards(communications[:12])}
    </div>
  </div>

  <div class="section">
    <h2>Visible Service Groups</h2>
    <table><thead><tr>{headers([('service', 'Service Group'), ('count', 'Signals'), ('share', 'Share'), ('bar_html', 'Chart'), ('example', 'Example')])}</tr></thead><tbody>{_chart_rows(investigator.get("service_rows", []), [('service', 'Service Group'), ('count', 'Signals'), ('share', 'Share'), ('bar_html', 'Chart'), ('example', 'Example')])}</tbody></table>
  </div>

  <div class="section">
    <h2>Visible vs Encrypted Indicators</h2>
    <table><thead><tr>{headers([('label', 'Visibility'), ('count', 'Signals'), ('share', 'Share'), ('bar_html', 'Chart')])}</tr></thead><tbody>{_chart_rows(investigator.get("visibility_rows", []), [('label', 'Visibility'), ('count', 'Signals'), ('share', 'Share'), ('bar_html', 'Chart')])}</tbody></table>
  </div>

  <div class="section">
    <h2>Activity Timeline By Hour</h2>
    <table><thead><tr>{headers([('hour', 'Hour'), ('packets', 'Packets'), ('share', 'Share'), ('bar_html', 'Chart')])}</tr></thead><tbody>{_chart_rows(investigator.get("activity_rows", []), [('hour', 'Hour'), ('packets', 'Packets'), ('share', 'Share'), ('bar_html', 'Chart')])}</tbody></table>
  </div>

  <div class="section">
    <h2>Interpretation Notes</h2>
    {''.join(f'<div class="note">{html.escape(note)}</div>' for note in investigator.get("limitations", summary.notes))}
  </div>

  <div class="section">
    <h2>Top DNS Queries</h2>
    <table><thead><tr>{headers([('query', 'DNS Query'), ('count', 'Count')])}</tr></thead><tbody>{rows(summary.dns_queries[:50], [('query', 'DNS Query'), ('count', 'Count')])}</tbody></table>
  </div>

  <div class="section">
    <h2>Top TLS SNI Hosts</h2>
    <table><thead><tr>{headers([('host', 'Host'), ('count', 'Count')])}</tr></thead><tbody>{rows(summary.tls_sni[:50], [('host', 'Host'), ('count', 'Count')])}</tbody></table>
  </div>

  <div class="section">
    <h2>Readable Evidence</h2>
    <table><thead><tr>{headers([('time', 'Time'), ('type', 'Type'), ('source', 'Source'), ('destination', 'Destination'), ('value', 'Visible Value')])}</tr></thead><tbody>{rows(readable, [('time', 'Time'), ('type', 'Type'), ('source', 'Source'), ('destination', 'Destination'), ('value', 'Visible Value')])}</tbody></table>
  </div>

  <div class="section">
    <h2>Extracted Artifacts</h2>
    <table><thead><tr>{headers([('category', 'Category'), ('type', 'Type'), ('value', 'Value'), ('visibility', 'Visibility'), ('source', 'Source'), ('destination', 'Destination'), ('count', 'Count'), ('explanation', 'Explanation')])}</tr></thead><tbody>{rows(artifacts, [('category', 'Category'), ('type', 'Type'), ('value', 'Value'), ('visibility', 'Visibility'), ('source', 'Source'), ('destination', 'Destination'), ('count', 'Count'), ('explanation', 'Explanation')])}</tbody></table>
  </div>

  <div class="section">
    <h2>Top Connections</h2>
    <table><thead><tr>{headers([('source', 'Source'), ('destination', 'Destination'), ('protocol', 'Protocol'), ('application', 'Application'), ('host', 'Host/Query'), ('bytes', 'Bytes'), ('packets', 'Packets'), ('first', 'First Seen'), ('last', 'Last Seen'), ('visible', 'Visible Preview')])}</tr></thead><tbody>{rows(connections, [('source', 'Source'), ('destination', 'Destination'), ('protocol', 'Protocol'), ('application', 'Application'), ('host', 'Host/Query'), ('bytes', 'Bytes'), ('packets', 'Packets'), ('first', 'First Seen'), ('last', 'Last Seen'), ('visible', 'Visible Preview')])}</tbody></table>
  </div>
</div>
</body>
</html>"""

    path.write_text(html_doc, encoding="utf-8")


def _endpoint(ip: Any, port: Any) -> str:
    ip_s = "" if ip is None else str(ip)
    port_s = "" if port is None else str(port)
    if port_s:
        return f"{ip_s}:{port_s}"
    return ip_s


def _chart_rows(items: list[dict[str, Any]], columns: list[tuple[str, str]]) -> str:
    if not items:
        return "<tr><td colspan=\"99\">No records.</td></tr>"

    parts = []
    for item in items:
        cells = []
        for key, _label in columns:
            if key == "bar_html":
                share = _safe_float(item.get("share"))
                cells.append(f"<td class=\"barcell\"><div class=\"bar\"><span style=\"width:{share:.1f}%\"></span></div></td>")
            elif key == "share":
                cells.append(f"<td>{_safe_float(item.get(key)):.1f}%</td>")
            else:
                cells.append(f"<td>{html.escape(str(item.get(key, '')))}</td>")
        parts.append(f"<tr>{''.join(cells)}</tr>")
    return "\n".join(parts)


def _communication_brief(items: list[dict[str, Any]]) -> dict[str, Any]:
    services: list[str] = []
    seen = set()
    messaging = 0
    media = 0
    for item in items:
        service = str(item.get("service") or "").strip()
        if service and service not in seen:
            seen.add(service)
            services.append(service)
        indicator = str(item.get("activity_type") or "").lower()
        if any(token in indicator for token in ("messaging", "push")):
            messaging += 1
        if any(token in indicator for token in ("media", "call")):
            media += 1

    return {
        "total": len(items),
        "messaging": messaging,
        "media": media,
        "services": ", ".join(services[:4]) if services else "-",
    }


def _communication_rows(items: list[dict[str, Any]]) -> str:
    if not items:
        return "<tr><td colspan=\"99\">No communication indicators.</td></tr>"

    columns = [
        ("service", "Service"),
        ("activity_type", "Indicator"),
        ("confidence_html", "Confidence"),
        ("host", "Host / Signal"),
        ("protocol", "Protocol"),
        ("bytes", "Volume"),
        ("packets", "Packets"),
        ("duration", "Duration"),
        ("first_seen", "First Seen"),
    ]
    parts = []
    for item in items[:80]:
        cells = []
        for key, _label in columns:
            if key == "confidence_html":
                confidence = str(item.get("confidence") or "low").lower()
                cells.append(f"<td><span class=\"tag {html.escape(confidence)}\">{html.escape(confidence)}</span></td>")
            else:
                cells.append(f"<td>{html.escape(str(item.get(key, '')))}</td>")
        parts.append(f"<tr>{''.join(cells)}</tr>")
    return "\n".join(parts)


def _communication_evidence_cards(items: list[dict[str, Any]]) -> str:
    if not items:
        return "<div class=\"evidence-card\">No communication evidence details.</div>"

    cards = []
    for item in items:
        title = f"{item.get('service') or '-'} - {item.get('activity_type') or '-'}"
        meta = (
            f"{item.get('confidence') or '-'} confidence | "
            f"{item.get('protocol') or '-'} | {item.get('bytes') or '-'} | "
            f"{item.get('packets') or 0} packets | {item.get('duration') or '-'}"
        )
        host = item.get("host") or "-"
        first_seen = item.get("first_seen") or "-"
        evidence = item.get("evidence") or "-"
        cards.append(
            "<div class=\"evidence-card\">"
            f"<div class=\"evidence-title\">{html.escape(str(title))}</div>"
            f"<div class=\"evidence-meta\">Host/signal: {html.escape(str(host))}<br>First seen: {html.escape(str(first_seen))}<br>{html.escape(str(meta))}</div>"
            f"<div class=\"evidence-text\">{html.escape(str(evidence))}</div>"
            "</div>"
        )
    return "\n".join(cards)


def _safe_float(value: Any) -> float:
    try:
        return float(value)
    except Exception:
        return 0.0


def _duration_compact(value: Any) -> str:
    try:
        seconds = int(float(value or 0) / 1000)
    except Exception:
        seconds = 0
    minutes, secs = divmod(seconds, 60)
    hours, minutes = divmod(minutes, 60)
    if hours:
        return f"{hours}h {minutes}m {secs}s"
    if minutes:
        return f"{minutes}m {secs}s"
    return f"{secs}s"
