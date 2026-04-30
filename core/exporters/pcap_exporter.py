from __future__ import annotations

import html
from datetime import datetime
from pathlib import Path
from typing import Any

from core.formatters import human_bytes
from core.pcap_analyzer import PcapSummary, build_investigator_view


def export_pcap_summary_html(file_path: str, summary: PcapSummary) -> None:
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
    investigator = build_investigator_view(summary)
    generated_at = datetime.now().strftime("%d.%m.%Y %H:%M:%S")
    period = f"{summary.first_seen or '-'} - {summary.last_seen or '-'}"

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


def _safe_float(value: Any) -> float:
    try:
        return float(value)
    except Exception:
        return 0.0
