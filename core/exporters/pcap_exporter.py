from __future__ import annotations

import html
from datetime import datetime
from pathlib import Path
from typing import Any

from core.db import Project
from core.exporters.case_context import build_case_context, context_cards_html
from core.formatters import format_flow_datetime, human_bytes
from core.output_language import normalize_output_language
from core.pcap_analyzer import PcapSummary, build_investigator_view


def export_pcap_summary_html(
    file_path: str,
    summary: PcapSummary,
    *,
    project: Project | None = None,
    project_name: str = "",
    report_language: str = "en",
) -> None:
    path = Path(file_path)
    lang = normalize_output_language(report_language, default="en")
    text = _report_text(lang)

    def rows(items: list[dict[str, Any]], columns: list[tuple[str, str]]) -> str:
        if not items:
            return f"<tr><td colspan=\"99\">{html.escape(text['no_records'])}</td></tr>"
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
    first_seen = format_flow_datetime(summary.first_seen, milliseconds=True)
    last_seen = format_flow_datetime(summary.last_seen, milliseconds=True)
    period = f"{first_seen or '-'} - {last_seen or '-'}"
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
h3 {{ margin:18px 0 8px; font-size:15px; color:#1f2937; }}
.muted {{ color:#9ca3af; }}
.nav {{ display:flex; gap:8px; flex-wrap:wrap; margin:16px 0 0; }}
.nav a {{ color:white; text-decoration:none; border:1px solid rgba(255,255,255,.28); border-radius:999px; padding:7px 11px; font-size:12px; font-weight:700; }}
.nav a:hover {{ background:rgba(255,255,255,.12); }}
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
.section-shell {{ background:#ffffff; border:1px solid #e5e7eb; border-radius:14px; padding:18px 20px; margin-bottom:18px; }}
.section-shell h2:first-child {{ margin-top:0; }}
.subsection {{ margin-top:16px; }}
.two-col {{ display:grid; grid-template-columns:repeat(2, minmax(0, 1fr)); gap:14px; }}
.report-note {{ background:#f8fafc; border:1px solid #e5e7eb; border-radius:10px; padding:12px 14px; color:#374151; line-height:1.5; }}
@media (max-width: 980px) {{
  .grid, .briefgrid, .points, .two-col, .evidence-grid {{ grid-template-columns:1fr; }}
}}
</style>
</head>
<body>
<div class="report">
  <div class="hero">
    <h1>{html.escape(text['title'])}</h1>
    <div class="muted">{html.escape(summary.file_name)} | {html.escape(text['exported'])}: {html.escape(generated_at)}</div>
    <div class="nav">
      <a href="#summary">{html.escape(text['summary'])}</a>
      <a href="#investigator">{html.escape(text['investigator'])}</a>
      <a href="#communications">{html.escape(text['communication_highlights'])}</a>
      <a href="#evidence">{html.escape(text['evidence'])}</a>
      <a href="#artifacts">{html.escape(text['artifacts'])}</a>
      <a href="#connections">{html.escape(text['connections'])}</a>
    </div>
    <div class="grid">
      {context_cards_html(case_context, card_class="card", include_dataset_target=False)}
      <div class="card"><div class="label">{html.escape(text['format'])}</div><div class="value">{html.escape(summary.format)}</div></div>
      <div class="card"><div class="label">{html.escape(text['packets'])}</div><div class="value">{summary.packet_count:,}</div></div>
      <div class="card"><div class="label">{html.escape(text['traffic_volume'])}</div><div class="value">{html.escape(human_bytes(summary.wire_bytes, precision=2))}</div></div>
      <div class="card"><div class="label">{html.escape(text['likely_device_ip'])}</div><div class="value">{html.escape(summary.likely_device_ip or '-')}</div></div>
      <div class="card"><div class="label">{html.escape(text['capture_period'])}</div><div class="value">{html.escape(period)}</div></div>
      <div class="card"><div class="label">{html.escape(text['dns_queries'])}</div><div class="value">{len(summary.dns_queries)}</div></div>
      <div class="card"><div class="label">{html.escape(text['tls_sni_hosts'])}</div><div class="value">{len(summary.tls_sni)}</div></div>
      <div class="card"><div class="label">{html.escape(text['readable_samples'])}</div><div class="value">{len(summary.readable_samples)}</div></div>
    </div>
  </div>

  <div class="section-shell" id="summary">
    <h2>{html.escape(text['summary'])}</h2>
    <div class="report-note">
      {html.escape(text['structure_note'])}
    </div>
    <div class="two-col">
      <div>
        <h3>{html.escape(text['visible_service_groups'])}</h3>
        <table><thead><tr>{headers([('service', text['service_group']), ('count', text['signals']), ('share', text['share']), ('bar_html', text['chart']), ('example', text['example'])])}</tr></thead><tbody>{_chart_rows(investigator.get("service_rows", []), [('service', text['service_group']), ('count', text['signals']), ('share', text['share']), ('bar_html', text['chart']), ('example', text['example'])], text=text)}</tbody></table>
      </div>
      <div>
        <h3>{html.escape(text['visible_vs_encrypted'])}</h3>
        <table><thead><tr>{headers([('label', text['visibility']), ('count', text['signals']), ('share', text['share']), ('bar_html', text['chart'])])}</tr></thead><tbody>{_chart_rows(investigator.get("visibility_rows", []), [('label', text['visibility']), ('count', text['signals']), ('share', text['share']), ('bar_html', text['chart'])], text=text)}</tbody></table>
      </div>
    </div>
    <div class="subsection">
      <h3>{html.escape(text['activity_timeline'])}</h3>
      <table><thead><tr>{headers([('hour', text['hour']), ('packets', text['packets']), ('share', text['share']), ('bar_html', text['chart'])])}</tr></thead><tbody>{_chart_rows(investigator.get("activity_rows", []), [('hour', text['hour']), ('packets', text['packets']), ('share', text['share']), ('bar_html', text['chart'])], text=text)}</tbody></table>
    </div>
  </div>

  <div class="section-shell" id="investigator">
    <h2>{html.escape(text['investigator'])}</h2>
    <div class="plain">
      {html.escape(str(investigator.get("plain_summary") or ""))}
      <div class="points">
        {''.join(f'<div class="point">{html.escape(str(point))}</div>' for point in investigator.get("key_points", []))}
      </div>
    </div>
  </div>

  <div class="section-shell" id="communications">
    <h2>{html.escape(text['communication_highlights'])}</h2>
    <div class="note">{html.escape(text['communication_note'])}</div>
    <div class="briefgrid">
      <div class="briefcard"><div class="label">{html.escape(text['classified_indicators'])}</div><div class="value">{communication_brief['total']}</div></div>
      <div class="briefcard"><div class="label">{html.escape(text['messaging_push'])}</div><div class="value">{communication_brief['messaging']}</div></div>
      <div class="briefcard"><div class="label">{html.escape(text['call_media_candidates'])}</div><div class="value">{communication_brief['media']}</div></div>
      <div class="briefcard"><div class="label">{html.escape(text['visible_services'])}</div><div class="value">{html.escape(communication_brief['services'])}</div></div>
    </div>
    <table><thead><tr>{headers([('service', text['service']), ('activity_type', text['indicator']), ('confidence_html', text['confidence']), ('host', text['host_signal']), ('protocol', text['protocol']), ('bytes', text['volume']), ('packets', text['packets']), ('duration', text['duration']), ('first_seen', text['first_seen'])])}</tr></thead><tbody>{_communication_rows(communications, text=text)}</tbody></table>
    <h2>{html.escape(text['communication_evidence_details'])}</h2>
    <div class="evidence-grid">
      {_communication_evidence_cards(communications[:12], text=text)}
    </div>
  </div>

  <div class="section-shell">
    <h2>{html.escape(text['interpretation_notes'])}</h2>
    {''.join(f'<div class="note">{html.escape(note)}</div>' for note in investigator.get("limitations", summary.notes))}
  </div>

  <div class="section-shell" id="evidence">
    <h2>{html.escape(text['evidence'])}</h2>
    <div class="report-note">
      {html.escape(text['evidence_note'])}
    </div>
    <div class="two-col">
      <div>
    <h2>{html.escape(text['top_dns_queries'])}</h2>
    <table><thead><tr>{headers([('query', text['dns_query']), ('count', text['count'])])}</tr></thead><tbody>{rows(summary.dns_queries[:50], [('query', text['dns_query']), ('count', text['count'])])}</tbody></table>
      </div>
      <div>
    <h2>{html.escape(text['top_tls_sni_hosts'])}</h2>
    <table><thead><tr>{headers([('host', text['host']), ('count', text['count'])])}</tr></thead><tbody>{rows(summary.tls_sni[:50], [('host', text['host']), ('count', text['count'])])}</tbody></table>
      </div>
    </div>

  <div class="subsection">
    <h2>{html.escape(text['readable_evidence'])}</h2>
    <table><thead><tr>{headers([('time', text['time']), ('type', text['type']), ('source', text['source']), ('destination', text['destination']), ('value', text['visible_value'])])}</tr></thead><tbody>{rows(readable, [('time', text['time']), ('type', text['type']), ('source', text['source']), ('destination', text['destination']), ('value', text['visible_value'])])}</tbody></table>
  </div>
  </div>

  <div class="section-shell" id="artifacts">
    <h2>{html.escape(text['artifacts'])}</h2>
    <table><thead><tr>{headers([('category', text['category']), ('type', text['type']), ('value', text['value']), ('visibility', text['visibility']), ('source', text['source']), ('destination', text['destination']), ('count', text['count']), ('explanation', text['explanation'])])}</tr></thead><tbody>{rows(artifacts, [('category', text['category']), ('type', text['type']), ('value', text['value']), ('visibility', text['visibility']), ('source', text['source']), ('destination', text['destination']), ('count', text['count']), ('explanation', text['explanation'])])}</tbody></table>
  </div>

  <div class="section-shell" id="connections">
    <h2>{html.escape(text['connections'])}</h2>
    <table><thead><tr>{headers([('source', text['source']), ('destination', text['destination']), ('protocol', text['protocol']), ('application', text['application']), ('host', text['host_query']), ('bytes', text['bytes']), ('packets', text['packets']), ('first', text['first_seen']), ('last', text['last_seen']), ('visible', text['visible_preview'])])}</tr></thead><tbody>{rows(connections, [('source', text['source']), ('destination', text['destination']), ('protocol', text['protocol']), ('application', text['application']), ('host', text['host_query']), ('bytes', text['bytes']), ('packets', text['packets']), ('first', text['first_seen']), ('last', text['last_seen']), ('visible', text['visible_preview'])])}</tbody></table>
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


def _chart_rows(items: list[dict[str, Any]], columns: list[tuple[str, str]], *, text: dict[str, str] | None = None) -> str:
    if not items:
        no_records = (text or {}).get("no_records", "No records.")
        return f"<tr><td colspan=\"99\">{html.escape(no_records)}</td></tr>"

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


def _communication_rows(items: list[dict[str, Any]], *, text: dict[str, str] | None = None) -> str:
    if not items:
        empty = (text or {}).get("no_communication_indicators", "No communication indicators.")
        return f"<tr><td colspan=\"99\">{html.escape(empty)}</td></tr>"

    labels = text or _report_text("en")
    columns = [
        ("service", labels["service"]),
        ("activity_type", labels["indicator"]),
        ("confidence_html", labels["confidence"]),
        ("host", labels["host_signal"]),
        ("protocol", labels["protocol"]),
        ("bytes", labels["volume"]),
        ("packets", labels["packets"]),
        ("duration", labels["duration"]),
        ("first_seen", labels["first_seen"]),
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


def _communication_evidence_cards(items: list[dict[str, Any]], *, text: dict[str, str] | None = None) -> str:
    if not items:
        empty = (text or {}).get("no_communication_evidence", "No communication evidence details.")
        return f"<div class=\"evidence-card\">{html.escape(empty)}</div>"

    labels = text or _report_text("en")
    cards = []
    for item in items:
        title = f"{item.get('service') or '-'} - {item.get('activity_type') or '-'}"
        meta = (
            f"{item.get('confidence') or '-'} {labels['confidence'].casefold()} | "
            f"{item.get('protocol') or '-'} | {item.get('bytes') or '-'} | "
            f"{item.get('packets') or 0} {labels['packets'].casefold()} | {item.get('duration') or '-'}"
        )
        host = item.get("host") or "-"
        first_seen = item.get("first_seen") or "-"
        evidence = item.get("evidence") or "-"
        cards.append(
            "<div class=\"evidence-card\">"
            f"<div class=\"evidence-title\">{html.escape(str(title))}</div>"
            f"<div class=\"evidence-meta\">{html.escape(labels['host_signal'])}: {html.escape(str(host))}<br>{html.escape(labels['first_seen'])}: {html.escape(str(first_seen))}<br>{html.escape(str(meta))}</div>"
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


def _report_text(language: str) -> dict[str, str]:
    if normalize_output_language(language, default="en") == "hr":
        return {
            "title": "ViaNyquist PCAP izvjestaj",
            "exported": "Izvezeno",
            "summary": "Sazetak",
            "investigator": "Pregled za istrazitelja",
            "communication_highlights": "Komunikacijski indikatori",
            "evidence": "Dokazi",
            "artifacts": "Artefakti",
            "connections": "Poveznice",
            "format": "Format",
            "packets": "Paketi",
            "traffic_volume": "Volumen prometa",
            "likely_device_ip": "IP adresa uredaja",
            "capture_period": "Razdoblje snimke",
            "dns_queries": "DNS upiti",
            "tls_sni_hosts": "TLS SNI hostovi",
            "readable_samples": "Citljivi uzorci",
            "structure_note": "Izvjestaj prati strukturu PCAP ekrana u ViaNyquistu: Sazetak objasnjava sto snimka pokazuje, a Dokazi navode vidljive zapise na kojima se zakljucci temelje.",
            "visible_service_groups": "Vidljive grupe usluga",
            "visible_vs_encrypted": "Vidljivo nasuprot kriptiranom",
            "activity_timeline": "Aktivnost po satu",
            "service_group": "Grupa usluge",
            "signals": "Signali",
            "share": "Udio",
            "chart": "Graf",
            "example": "Primjer",
            "visibility": "Vidljivost",
            "hour": "Sat",
            "communication_note": "Ovi redovi su istrazni indikatori temeljeni na metapodacima kao sto su hostovi, portovi, protokol, trajanje i volumen prometa. Sami po sebi ne dokazuju sadrzaj poruke niti potvrdu poziva.",
            "classified_indicators": "Klasificirani indikatori",
            "messaging_push": "Poruke / push",
            "call_media_candidates": "Moguci poziv / medij",
            "visible_services": "Vidljive usluge",
            "service": "Usluga",
            "indicator": "Indikator",
            "confidence": "Pouzdanost",
            "host_signal": "Host / signal",
            "protocol": "Protokol",
            "volume": "Volumen",
            "duration": "Trajanje",
            "first_seen": "Prvi put vidjeno",
            "last_seen": "Zadnji put vidjeno",
            "communication_evidence_details": "Detalji komunikacijskih indikatora",
            "interpretation_notes": "Napomene o interpretaciji",
            "evidence_note": "Ovi zapisi su vidljivi metapodaci i citljive vrijednosti izdvojene iz snimke. Kriptirani sadrzaj prometa nije dekodiran.",
            "top_dns_queries": "Najcesci DNS upiti",
            "top_tls_sni_hosts": "Najcesci TLS SNI hostovi",
            "dns_query": "DNS upit",
            "count": "Broj",
            "host": "Host",
            "readable_evidence": "Citljivi dokazi",
            "time": "Vrijeme",
            "type": "Tip",
            "source": "Izvor",
            "destination": "Odrediste",
            "visible_value": "Vidljiva vrijednost",
            "category": "Kategorija",
            "value": "Vrijednost",
            "explanation": "Objasnjenje",
            "application": "Aplikacija",
            "host_query": "Host/upit",
            "bytes": "Bajtovi",
            "visible_preview": "Vidljivi isjecak",
            "no_records": "Nema zapisa.",
            "no_communication_indicators": "Nema komunikacijskih indikatora.",
            "no_communication_evidence": "Nema detalja komunikacijskih indikatora.",
        }
    return {
        "title": "ViaNyquist PCAP Report",
        "exported": "Exported",
        "summary": "Summary",
        "investigator": "Investigator View",
        "communication_highlights": "Communication Highlights",
        "evidence": "Evidence",
        "artifacts": "Artifacts",
        "connections": "Connections",
        "format": "Format",
        "packets": "Packets",
        "traffic_volume": "Traffic Volume",
        "likely_device_ip": "Device IP",
        "capture_period": "Capture Period",
        "dns_queries": "DNS Queries",
        "tls_sni_hosts": "TLS SNI Hosts",
        "readable_samples": "Readable Samples",
        "structure_note": "This report follows the same structure as the PCAP screen in ViaNyquist: Summary explains what the capture indicates, while Evidence lists the observable records behind those conclusions.",
        "visible_service_groups": "Visible Service Groups",
        "visible_vs_encrypted": "Visible vs Encrypted Indicators",
        "activity_timeline": "Activity Timeline By Hour",
        "service_group": "Service Group",
        "signals": "Signals",
        "share": "Share",
        "chart": "Chart",
        "example": "Example",
        "visibility": "Visibility",
        "hour": "Hour",
        "communication_note": "These rows are investigative indicators based on metadata such as host names, ports, protocol, duration and traffic volume. They do not prove message content or confirm a call by themselves.",
        "classified_indicators": "Classified indicators",
        "messaging_push": "Messaging / push",
        "call_media_candidates": "Call / media candidates",
        "visible_services": "Visible services",
        "service": "Service",
        "indicator": "Indicator",
        "confidence": "Confidence",
        "host_signal": "Host / Signal",
        "protocol": "Protocol",
        "volume": "Volume",
        "duration": "Duration",
        "first_seen": "First Seen",
        "last_seen": "Last Seen",
        "communication_evidence_details": "Communication Evidence Details",
        "interpretation_notes": "Interpretation Notes",
        "evidence_note": "These records are the visible metadata and cleartext values extracted from the capture. Encrypted payload contents are not decoded.",
        "top_dns_queries": "Top DNS Queries",
        "top_tls_sni_hosts": "Top TLS SNI Hosts",
        "dns_query": "DNS Query",
        "count": "Count",
        "host": "Host",
        "readable_evidence": "Readable Evidence",
        "time": "Time",
        "type": "Type",
        "source": "Source",
        "destination": "Destination",
        "visible_value": "Visible Value",
        "category": "Category",
        "value": "Value",
        "explanation": "Explanation",
        "application": "Application",
        "host_query": "Host/Query",
        "bytes": "Bytes",
        "visible_preview": "Visible Preview",
        "no_records": "No records.",
        "no_communication_indicators": "No communication indicators.",
        "no_communication_evidence": "No communication evidence details.",
    }
