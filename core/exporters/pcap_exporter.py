from __future__ import annotations

import html
from datetime import datetime
from pathlib import Path
from typing import Any

from core.db import Project
from core.exporters.case_context import build_case_context, context_cards_html
from core.exporters.template_utils import load_template, render_template
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
    for flow in summary.flows or []:
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

    readable = summary.readable_samples or []
    artifacts = summary.artifacts or []
    communications = [
        {
            **row,
            "bytes": human_bytes(row.get("bytes"), precision=2),
            "duration": _duration_compact(row.get("duration_ms")),
        }
        for row in (summary.communication_rows or [])
    ]
    communication_brief = _communication_brief(summary.communication_rows or [])
    investigator = build_investigator_view(summary)
    generated_at = datetime.now().strftime("%d.%m.%Y %H:%M:%S")
    first_seen = format_flow_datetime(summary.first_seen, milliseconds=True)
    last_seen = format_flow_datetime(summary.last_seen, milliseconds=True)
    period = f"{first_seen or '-'} - {last_seen or '-'}"
    case_context = build_case_context(project, project_name=project_name)

    hero_cards = "\n".join([
        context_cards_html(case_context, card_class="card", include_dataset_target=False),
        _metric_card(text["format"], summary.format),
        _metric_card(text["packets"], f"{summary.packet_count:,}"),
        _metric_card(text["traffic_volume"], human_bytes(summary.wire_bytes, precision=2)),
        _metric_card(text["likely_device_ip"], summary.likely_device_ip or "-"),
        _metric_card(text["capture_period"], period),
        _metric_card(text["dns_queries"], summary.total_dns_names or len(summary.dns_queries)),
        _metric_card(text["tls_sni_hosts"], summary.total_tls_sni_hosts or len(summary.tls_sni)),
        _metric_card(text["readable_samples"], len(summary.readable_samples)),
    ])

    service_columns = [("service", text["service_group"]), ("count", text["signals"]), ("share", text["share"]), ("bar_html", text["chart"]), ("example", text["example"])]
    visibility_columns = [("label", text["visibility"]), ("count", text["signals"]), ("share", text["share"]), ("bar_html", text["chart"])]
    activity_columns = [("hour", text["hour"]), ("packets", text["packets"]), ("share", text["share"]), ("bar_html", text["chart"])]
    communication_columns = [("service", text["service"]), ("activity_type", text["indicator"]), ("confidence_html", text["confidence"]), ("host", text["host_signal"]), ("protocol", text["protocol"]), ("bytes", text["volume"]), ("packets", text["packets"]), ("duration", text["duration"]), ("first_seen", text["first_seen"])]
    dns_columns = [("query", text["dns_query"]), ("count", text["count"])]
    tls_columns = [("host", text["host"]), ("count", text["count"])]
    readable_columns = [("time", text["time"]), ("type", text["type"]), ("source", text["source"]), ("destination", text["destination"]), ("value", text["visible_value"])]
    artifact_columns = [("category", text["category"]), ("type", text["type"]), ("value", text["value"]), ("visibility", text["visibility"]), ("source", text["source"]), ("destination", text["destination"]), ("count", text["count"]), ("explanation", text["explanation"])]
    connection_columns = [("source", text["source"]), ("destination", text["destination"]), ("protocol", text["protocol"]), ("application", text["application"]), ("host", text["host_query"]), ("bytes", text["bytes"]), ("packets", text["packets"]), ("first", text["first_seen"]), ("last", text["last_seen"]), ("visible", text["visible_preview"])]

    template = load_template("pcap_export.html")
    html_doc = render_template(template, {
        "LANG": lang,
        "TITLE": text["title"],
        "FILE_NAME": html.escape(summary.file_name),
        "EXPORTED_LABEL": text["exported"],
        "EXPORTED_AT": generated_at,
        "SUMMARY_LABEL": text["summary"],
        "INVESTIGATOR_LABEL": text["investigator"],
        "COMMUNICATION_HIGHLIGHTS_LABEL": text["communication_highlights"],
        "EVIDENCE_LABEL": text["evidence"],
        "ARTIFACTS_LABEL": text["artifacts"],
        "CONNECTIONS_LABEL": text["connections"],
        "HERO_CARDS": hero_cards,
        "STRUCTURE_NOTE": text["structure_note"],
        "VISIBLE_SERVICE_GROUPS_LABEL": text["visible_service_groups"],
        "VISIBLE_VS_ENCRYPTED_LABEL": text["visible_vs_encrypted"],
        "ACTIVITY_TIMELINE_LABEL": text["activity_timeline"],
        "SERVICE_GROUPS_TABLE": _table_html(headers(service_columns), _chart_rows(investigator.get("service_rows", []), service_columns, text=text)),
        "VISIBILITY_TABLE": _table_html(headers(visibility_columns), _chart_rows(investigator.get("visibility_rows", []), visibility_columns, text=text)),
        "ACTIVITY_TABLE": _table_html(headers(activity_columns), _chart_rows(investigator.get("activity_rows", []), activity_columns, text=text)),
        "PLAIN_SUMMARY": html.escape(str(investigator.get("plain_summary") or "")),
        "KEY_POINTS": "".join(f'<div class="point">{html.escape(str(point))}</div>' for point in investigator.get("key_points", [])),
        "COMMUNICATION_NOTE": text["communication_note"],
        "COMMUNICATION_BRIEF_CARDS": _brief_cards(communication_brief, text),
        "COMMUNICATION_TABLE": _table_html(headers(communication_columns), _communication_rows(communications, text=text)),
        "COMMUNICATION_EVIDENCE_DETAILS_LABEL": text["communication_evidence_details"],
        "COMMUNICATION_EVIDENCE_CARDS": _communication_evidence_cards(communications[:12], text=text),
        "INTERPRETATION_NOTES_LABEL": text["interpretation_notes"],
        "LIMITATION_NOTES": "".join(f'<div class="note">{html.escape(note)}</div>' for note in investigator.get("limitations", summary.notes)),
        "EVIDENCE_NOTE": text["evidence_note"],
        "TOP_DNS_QUERIES_LABEL": text["top_dns_queries"],
        "TOP_TLS_SNI_HOSTS_LABEL": text["top_tls_sni_hosts"],
        "DNS_TABLE": _table_html(headers(dns_columns), rows(summary.dns_queries[:50], dns_columns)),
        "TLS_TABLE": _table_html(headers(tls_columns), rows(summary.tls_sni[:50], tls_columns)),
        "READABLE_EVIDENCE_LABEL": text["readable_evidence"],
        "READABLE_TABLE": _table_html(headers(readable_columns), rows(readable, readable_columns)),
        "ARTIFACTS_TABLE": _table_html(headers(artifact_columns), rows(artifacts, artifact_columns)),
        "CONNECTIONS_TABLE": _table_html(headers(connection_columns), rows(connections, connection_columns)),
    }, escape_values=False)

    path.write_text(html_doc, encoding="utf-8")


def _endpoint(ip: Any, port: Any) -> str:
    ip_s = "" if ip is None else str(ip)
    port_s = "" if port is None else str(port)
    if port_s:
        return f"{ip_s}:{port_s}"
    return ip_s


def _metric_card(label: Any, value: Any) -> str:
    return (
        '<div class="card">'
        f'<div class="label">{html.escape(str(label))}</div>'
        f'<div class="value">{html.escape(str(value))}</div>'
        "</div>"
    )


def _brief_cards(communication_brief: dict[str, Any], text: dict[str, str]) -> str:
    return "\n".join(
        [
            _metric_card(text["classified_indicators"], communication_brief["total"]).replace('class="card"', 'class="briefcard"'),
            _metric_card(text["messaging_push"], communication_brief["messaging"]).replace('class="card"', 'class="briefcard"'),
            _metric_card(text["call_media_candidates"], communication_brief["media"]).replace('class="card"', 'class="briefcard"'),
            _metric_card(text["visible_services"], communication_brief["services"]).replace('class="card"', 'class="briefcard"'),
        ]
    )


def _table_html(headers_html: str, body_html: str) -> str:
    return f"<table><thead><tr>{headers_html}</tr></thead><tbody>{body_html}</tbody></table>"


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
    for item in items:
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

