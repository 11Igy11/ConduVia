from __future__ import annotations

import html
from datetime import datetime
from pathlib import Path
from typing import Any

from core.db import Project
from core.exporters.case_context import build_case_context, case_context_table_html
from core.exporters.html_blocks import ranked_list_html, stats_html
from core.exporters.template_utils import load_export_template, render_template
from core.formatters import format_export_datetime, format_flow_datetime, human_bytes
from core.pcap_analyzer import PcapSummary, build_investigator_view


def export_pcap_summary_html(
    file_path: str,
    summary: PcapSummary,
    *,
    project: Project | None = None,
    project_name: str = "",
) -> None:
    path = Path(file_path)
    text = _report_text()

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
            "first": format_export_datetime(flow.get("bidirectional_first_seen_ms")),
            "last": format_export_datetime(flow.get("bidirectional_last_seen_ms")),
            "visible": flow.get("pcap_payload_preview"),
        })

    readable = summary.readable_samples or []
    artifacts = summary.artifacts or []
    communications = [
        {
            **row,
            "bytes": human_bytes(row.get("bytes"), precision=2),
            "duration": _duration_compact(row.get("duration_ms")),
            "first_seen": format_export_datetime(row.get("first_seen")),
        }
        for row in (summary.communication_rows or [])
    ]
    communication_brief = _communication_brief(summary.communication_rows or [])
    investigator = build_investigator_view(summary)
    generated_at = datetime.now().strftime("%d.%m.%Y %H:%M:%S")
    first_seen = format_flow_datetime(summary.first_seen, milliseconds=True)
    last_seen = format_flow_datetime(summary.last_seen, milliseconds=True)
    period = f"{first_seen or '—'} – {last_seen or '—'}" if first_seen or last_seen else "—"
    case_context = build_case_context(project, project_name=project_name)
    source_summary = _export_source_summary(summary)
    project_label = html.escape(project_name or case_context.get("project") or "Project")

    stats = stats_html([
        (text["format"], summary.format or "—"),
        (text["packets"], f"{summary.packet_count:,}"),
        (text["traffic_volume"], human_bytes(summary.wire_bytes, precision=2)),
        (text["likely_device_ip"], summary.likely_device_ip or "—"),
        (text["dns_queries"], summary.total_dns_names or len(summary.dns_queries)),
        (text["tls_sni_hosts"], summary.total_tls_sni_hosts or len(summary.tls_sni)),
    ])

    communication_columns = [("service", text["service"]), ("activity_type", text["indicator"]), ("confidence_html", text["confidence"]), ("host", text["host_signal"]), ("protocol", text["protocol"]), ("bytes", text["volume"]), ("packets", text["packets"]), ("duration", text["duration"]), ("first_seen", text["first_seen"])]
    readable_columns = [("time", text["time"]), ("type", text["type"]), ("source", text["source"]), ("destination", text["destination"]), ("value", text["visible_value"])]
    artifact_columns = [("category", text["category"]), ("type", text["type"]), ("value", text["value"]), ("visibility", text["visibility"]), ("source", text["source"]), ("destination", text["destination"]), ("count", text["count"]), ("explanation", text["explanation"])]
    connection_columns = [("source", text["source"]), ("destination", text["destination"]), ("protocol", text["protocol"]), ("application", text["application"]), ("host", text["host_query"]), ("bytes", text["bytes"]), ("packets", text["packets"]), ("first", text["first_seen"]), ("last", text["last_seen"]), ("visible", text["visible_preview"])]

    operational_notes = [
        note for note in (investigator.get("limitations") or summary.notes or [])
        if _is_operational_note(note)
    ]
    interpretation_section = ""
    if operational_notes:
        interpretation_section = (
            '<section class="section">'
            f"<h2>{html.escape(text['interpretation_notes'])}</h2>"
            + "".join(f'<p class="plain">{html.escape(str(note))}</p>' for note in operational_notes)
            + "</section>"
        )

    html_doc = render_template(load_export_template("pcap_export.html"), {
        "LANG": "en",
        "TITLE": text["title"],
        "DOCUMENT_TYPE": text["document_type"],
        "REPORT_TITLE": text["title"],
        "PERIOD_LABEL": text["period"],
        "PERIOD": html.escape(period),
        "EXPORTED_LABEL": text["exported"],
        "EXPORTED_AT": generated_at,
        "SOURCE_LABEL": text["source_label"],
        "SOURCE": html.escape(source_summary),
        "SCOPE_LABEL": text["scope"],
        "SCOPE": html.escape(f"{summary.packet_count:,} packets · {human_bytes(summary.wire_bytes, precision=2)}"),
        "CASE_CONTEXT_LABEL": text["case_context"],
        "CASE_TABLE": case_context_table_html(case_context, include_dataset_target=False),
        "PROJECT_NAME": project_label,
        "PREPARED_LABEL": text["prepared"],
        "SUMMARY_LABEL": text["summary"],
        "INVESTIGATOR_LABEL": text["investigator"],
        "COMMUNICATION_HIGHLIGHTS_LABEL": text["communication_highlights"],
        "EVIDENCE_LABEL": text["evidence"],
        "ARTIFACTS_LABEL": text["artifacts"],
        "CONNECTIONS_LABEL": text["connections"],
        "STATS_SECTION": f'<section class="section">{stats}</section>' if stats else "",
        "VISIBLE_SERVICE_GROUPS_LABEL": text["visible_service_groups"],
        "VISIBLE_VS_ENCRYPTED_LABEL": text["visible_vs_encrypted"],
        "ACTIVITY_TIMELINE_LABEL": text["activity_timeline"],
        "SERVICE_GROUPS_TABLE": ranked_list_html(
            "",
            investigator.get("service_rows", []),
            label_key="service",
            value_key="count",
            meta_key="example",
            empty_text=text["no_records"],
        ),
        "VISIBILITY_TABLE": ranked_list_html(
            "",
            investigator.get("visibility_rows", []),
            label_key="label",
            value_key="count",
            empty_text=text["no_records"],
        ),
        "ACTIVITY_TABLE": ranked_list_html(
            "",
            investigator.get("activity_rows", []),
            label_key="hour",
            value_key="packets",
            empty_text=text["no_records"],
        ),
        "PLAIN_SUMMARY": html.escape(str(investigator.get("plain_summary") or "")),
        "KEY_POINTS": "".join(f'<div class="point">{html.escape(str(point))}</div>' for point in investigator.get("key_points", [])),
        "COMMUNICATION_BRIEF_CARDS": _brief_cards(communication_brief, text),
        "COMMUNICATION_TABLE": _table_html(headers(communication_columns), _communication_rows(communications, text=text)),
        "COMMUNICATION_EVIDENCE_DETAILS_LABEL": text["communication_evidence_details"],
        "COMMUNICATION_EVIDENCE_CARDS": _communication_evidence_cards(communications[:12], text=text),
        "INTERPRETATION_SECTION": interpretation_section,
        "TOP_DNS_QUERIES_LABEL": text["top_dns_queries"],
        "TOP_TLS_SNI_HOSTS_LABEL": text["top_tls_sni_hosts"],
        "DNS_TABLE": ranked_list_html(
            "",
            summary.dns_queries[:50],
            label_key="query",
            value_key="count",
            empty_text=text["no_records"],
        ),
        "TLS_TABLE": ranked_list_html(
            "",
            summary.tls_sni[:50],
            label_key="host",
            value_key="count",
            empty_text=text["no_records"],
        ),
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
        '<div class="briefcard">'
        f'<div class="label">{html.escape(str(label))}</div>'
        f'<div class="value">{html.escape(str(value))}</div>'
        "</div>"
    )


def _brief_cards(communication_brief: dict[str, Any], text: dict[str, str]) -> str:
    return "\n".join(
        [
            _metric_card(text["classified_indicators"], communication_brief["total"]),
            _metric_card(text["messaging_push"], communication_brief["messaging"]),
            _metric_card(text["call_media_candidates"], communication_brief["media"]),
            _metric_card(text["visible_services"], communication_brief["services"]),
        ]
    )


def _table_html(headers_html: str, body_html: str) -> str:
    return (
        '<div class="table-wrap"><table class="data">'
        f"<thead><tr>{headers_html}</tr></thead><tbody>{body_html}</tbody></table></div>"
    )


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

    labels = text or _report_text()
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

    labels = text or _report_text()
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


def _is_operational_note(note: Any) -> bool:
    lowered = str(note or "").casefold()
    return "capped" in lowered or "samples" in lowered


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


def _export_source_summary(summary: PcapSummary) -> str:
    paths = [
        str(path)
        for path in (getattr(summary, "source_paths", None) or [])
        if str(path or "").strip()
    ]
    if not paths and getattr(summary, "file_path", ""):
        paths = [str(summary.file_path)]
    count = len(paths)
    if count == 0:
        return str(summary.file_name or "PCAP capture")
    if count == 1:
        return Path(paths[0]).name
    preview = ", ".join(Path(path).name for path in paths[:8])
    suffix = f", +{count - 8} more" if count > 8 else ""
    return f"{count:,} PCAP files analyzed ({preview}{suffix})"


def _report_text() -> dict[str, str]:
    return {
        "title": "PCAP Report",
        "document_type": "PCAP Report",
        "period": "Period",
        "exported": "Exported",
        "source_label": "Source",
        "scope": "Scope",
        "case_context": "Case context",
        "prepared": "Prepared",
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
        "dns_queries": "DNS Queries",
        "tls_sni_hosts": "TLS SNI Hosts",
        "visible_service_groups": "Visible Service Groups",
        "visible_vs_encrypted": "Visible vs Encrypted Indicators",
        "activity_timeline": "Activity Timeline By Hour",
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
        "interpretation_notes": "Capture notes",
        "top_dns_queries": "Top DNS Queries",
        "top_tls_sni_hosts": "Top TLS SNI Hosts",
        "count": "Count",
        "readable_evidence": "Readable Evidence",
        "time": "Time",
        "type": "Type",
        "source": "Source",
        "destination": "Destination",
        "visible_value": "Visible Value",
        "category": "Category",
        "value": "Value",
        "visibility": "Visibility",
        "explanation": "Explanation",
        "application": "Application",
        "host_query": "Host/Query",
        "bytes": "Bytes",
        "visible_preview": "Visible Preview",
        "no_records": "No records.",
        "no_communication_indicators": "No communication indicators.",
        "no_communication_evidence": "No communication evidence details.",
    }
