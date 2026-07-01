from __future__ import annotations

from typing import Any

from PySide6.QtCore import QModelIndex, Qt
from PySide6.QtWidgets import QFrame, QHBoxLayout, QLabel, QTableView, QWidget

from core.analysis_limits import PROFILE_CHART_PREVIEW_ROWS, embedded_expand_available, embedded_expand_tooltip
from core.formatters import format_duration_compact_ms, human_bytes
from core.pcap_analyzer import PcapSummary
from core.protocols import format_ip_proto
from ui.dict_table_model import DictTableModel
from ui.expand_dialogs import open_communication_indicators_dialog, set_dict_table_rows


class VisibilityIndicatorRow(QFrame):
    def __init__(self, label: str, value: str, kind: str, opener, parent=None):
        super().__init__(parent)
        self._kind = kind
        self._opener = opener
        self.setObjectName("ProfileCountRow")
        self.setCursor(Qt.PointingHandCursor)
        self.setToolTip(f"Open table for {label}")

        layout = QHBoxLayout(self)
        layout.setContentsMargins(10, 7, 10, 7)
        layout.setSpacing(10)

        name = QLabel(label)
        name.setWordWrap(True)
        name.setObjectName("ChartLinkLabel")

        badge = QLabel(value)
        badge.setObjectName("ProfileCountBadge")
        badge.setAlignment(Qt.AlignCenter)
        badge.setMinimumWidth(96)

        layout.addWidget(name, 1)
        layout.addWidget(badge, 0)

    def mousePressEvent(self, event) -> None:
        if event.button() == Qt.LeftButton:
            self._opener(self._kind)
        super().mousePressEvent(event)


class PcapInvestigatorMixin:
    """PCAP investigator charts, visibility indicators, and evidence tables."""

    def _apply_investigator_charts(self, investigator: dict[str, Any]) -> None:
        service_rows = self._service_chart_rows(investigator.get("service_rows") or [])
        activity_source = sorted(
            list(investigator.get("activity_rows") or []),
            key=lambda row: int(row.get("packets") or 0),
            reverse=True,
        )
        activity_rows = self._activity_chart_rows(activity_source)
        self._service_chart_full_rows = list(service_rows)
        self._activity_chart_full_rows = list(activity_rows)
        self.chart_services.set_rows(
            service_rows,
            empty_text="No visible service groups were identified.",
        )
        self.chart_activity.set_rows(
            activity_rows,
            empty_text="No hourly activity is available.",
        )
        preview = PROFILE_CHART_PREVIEW_ROWS
        service_total = len(service_rows)
        activity_total = len(activity_rows)
        self.btn_expand_chart_services.setEnabled(embedded_expand_available(service_total))
        self.btn_expand_chart_activity.setEnabled(embedded_expand_available(activity_total))
        if embedded_expand_available(service_total):
            self.btn_expand_chart_services.setToolTip(
                embedded_expand_tooltip(service_total, preview_rows=preview)
            )
        else:
            self.btn_expand_chart_services.setToolTip("")
        if embedded_expand_available(activity_total):
            self.btn_expand_chart_activity.setToolTip(
                embedded_expand_tooltip(activity_total, preview_rows=preview)
            )
        else:
            self.btn_expand_chart_activity.setToolTip("")

    def _expand_service_chart(self) -> None:
        rows = [
            {
                "label": row.get("label"),
                "count": row.get("count"),
                "value": row.get("value"),
                "tooltip": row.get("tooltip"),
            }
            for row in self._service_chart_full_rows
        ]
        self._open_rows_dialog(
            "Visible service groups",
            [("label", "Service"), ("count", "Packets"), ("value", "Share"), ("tooltip", "Example")],
            rows,
        )

    def _expand_activity_chart(self) -> None:
        rows = [
            {
                "label": row.get("label"),
                "count": row.get("count"),
                "value": row.get("value"),
            }
            for row in self._activity_chart_full_rows
        ]
        self._open_rows_dialog(
            "Hourly activity (peak hours)",
            [("label", "Hour"), ("count", "Packets"), ("value", "Share")],
            rows,
        )

    def _service_chart_rows(self, rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
        chart_rows = []
        for row in rows or []:
            count = int(row.get("count") or 0)
            share = row.get("share")
            try:
                share_text = f"{float(share):.1f}%"
            except Exception:
                share_text = str(share or "-")
            label = str(row.get("service") or "-")
            example = str(row.get("example") or "").strip()
            chart_rows.append({
                "label": label,
                "tooltip": f"{label} - {example}" if example else label,
                "count": count,
                "value": f"{count} / {share_text}",
            })
        return chart_rows

    def _activity_chart_rows(self, rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
        chart_rows = []
        for row in rows or []:
            packets = int(row.get("packets") or 0)
            share = row.get("share")
            try:
                share_text = f"{float(share):.1f}%"
            except Exception:
                share_text = str(share or "-")
            chart_rows.append({
                "label": str(row.get("hour") or "-"),
                "count": packets,
                "value": f"{packets:,} / {share_text}",
            })
        return chart_rows

    def _visibility_kind(self, label: str) -> str:
        text = str(label or "").strip().lower()
        if text.startswith("encrypted"):
            return "encrypted"
        if "dns" in text:
            return "dns"
        if "http" in text:
            return "http"
        return "other"

    def _set_visibility_indicators(self, rows: list[dict[str, Any]] | None, *, empty_text: str = "") -> None:
        while self.visibility_rows_layout.count():
            item = self.visibility_rows_layout.takeAt(0)
            widget = item.widget()
            if widget is not None:
                widget.deleteLater()
            nested = item.layout()
            if nested is not None:
                while nested.count():
                    nested_item = nested.takeAt(0)
                    nested_widget = nested_item.widget()
                    if nested_widget is not None:
                        nested_widget.deleteLater()

        if not rows:
            self.lbl_visibility_empty.setText(
                empty_text or "Open a PCAP file to show readable vs encrypted indicators."
            )
            self.lbl_visibility_empty.show()
            return

        self.lbl_visibility_empty.hide()
        for row in rows:
            label = str(row.get("label") or "-")
            count = int(row.get("count") or 0)
            share = row.get("share")
            try:
                share_text = f"{float(share):.1f}%"
            except Exception:
                share_text = str(share or "-")
            kind = self._visibility_kind(label)
            value = f"{count:,} ({share_text})"
            self.visibility_rows_layout.addWidget(
                VisibilityIndicatorRow(label, value, kind, self._open_visibility_data)
            )

    def _open_visibility_data(self, kind: str) -> None:
        summary = getattr(self, "summary", None)
        if summary is None:
            self._info("PCAP", "Open a PCAP file first.")
            return

        if kind == "encrypted":
            self._open_table_dialog("Communication indicators", self.tbl_communications)
            return

        if kind == "dns":
            rows = [
                row
                for row in self._visible_metadata_rows(summary)
                if "dns" in str(row.get("type") or "").lower()
            ]
            self._open_rows_dialog(
                "DNS metadata",
                [("type", "Type"), ("value", "Visible Value"), ("count", "Count")],
                rows,
            )
            return

        sample_columns = [
            ("time", "Time"),
            ("type", "Type"),
            ("source", "Source"),
            ("destination", "Destination"),
            ("value", "Visible Value"),
        ]
        if kind == "http":
            rows = [
                row for row in (summary.readable_samples or [])
                if str(row.get("type") or "") == "HTTP cleartext"
            ]
            self._open_rows_dialog("HTTP cleartext samples", sample_columns, rows)
            return

        rows = [
            row for row in (summary.readable_samples or [])
            if str(row.get("type") or "") != "HTTP cleartext"
        ]
        self._open_rows_dialog("Other readable samples", sample_columns, rows)

    def _visibility_chart_rows(self, rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
        chart_rows = []
        for row in rows or []:
            count = int(row.get("count") or 0)
            share = row.get("share")
            try:
                share_text = f"{float(share):.1f}%"
            except Exception:
                share_text = str(share or "-")
            chart_rows.append({
                "label": str(row.get("label") or "-"),
                "count": count,
                "value": f"{count:,} ({share_text})",
            })
        return chart_rows

    def _visible_metadata_rows(self, summary: PcapSummary) -> list[dict[str, Any]]:
        rows: list[dict[str, Any]] = []

        def _append_from_counts(counts: dict[str, int] | None, *, row_type: str, key: str) -> None:
            if not counts:
                return
            for name, count in sorted(counts.items(), key=lambda item: (-item[1], item[0].lower())):
                if str(name).strip():
                    rows.append({"type": row_type, "value": name, "count": count})

        dns_items = summary.dns_queries or []
        if dns_items:
            for item in dns_items:
                rows.append({"type": "DNS query", "value": item.get("query"), "count": item.get("count")})
        else:
            _append_from_counts(summary.dns_query_counts, row_type="DNS query", key="query")

        tls_items = summary.tls_sni or []
        if tls_items:
            for item in tls_items:
                rows.append({"type": "TLS SNI", "value": item.get("host"), "count": item.get("count")})
        else:
            _append_from_counts(summary.tls_sni_counts, row_type="TLS SNI", key="host")

        http_items = summary.http_hosts or []
        if http_items:
            for item in http_items:
                rows.append({"type": "HTTP host", "value": item.get("host"), "count": item.get("count")})
        else:
            _append_from_counts(summary.http_host_counts, row_type="HTTP host", key="host")
        return rows

    def _set_evidence_tables(self, summary: PcapSummary) -> None:
        metadata_rows = self._visible_metadata_rows(summary)
        sample_rows = summary.readable_samples or []
        self._set_table(self.tbl_visible_metadata, metadata_rows)
        self._set_table(self.tbl_samples, sample_rows)

        dns_total = int(summary.total_dns_names or len(summary.dns_query_counts or {}) or 0)
        tls_total = int(summary.total_tls_sni_hosts or len(summary.tls_sni_counts or {}) or 0)
        http_total = int(summary.total_http_hosts or len(summary.http_host_counts or {}) or 0)
        self.lbl_visible_metadata_count.setText(f"{len(metadata_rows):,} metadata rows (DNS + TLS + HTTP)")
        self.lbl_visible_metadata_breakdown.setText(
            f"DNS: {dns_total:,} | TLS SNI: {tls_total:,} | HTTP hosts: {http_total:,}"
        )
        self.lbl_samples_count.setText(f"{len(sample_rows):,} readable rows")

    def _network_overview_rows(self, summary: PcapSummary) -> list[dict[str, Any]]:
        rows: list[dict[str, Any]] = []
        for item in summary.protocols or []:
            rows.append({
                "section": "Protocol",
                "value": item.get("protocol"),
                "detail": f"Number: {item.get('number') or '-'}",
                "packets": item.get("packets"),
            })
        for item in summary.top_endpoints or []:
            rows.append({
                "section": "Endpoint",
                "value": item.get("ip"),
                "detail": "Top observed endpoint",
                "packets": item.get("packets"),
            })
        for item in summary.top_ports or []:
            protocol = item.get("protocol")
            port = item.get("port")
            rows.append({
                "section": "Port",
                "value": f"{format_ip_proto(protocol) if isinstance(protocol, int) else protocol}/{port}",
                "detail": "Top observed port",
                "packets": item.get("packets"),
            })
        return rows

    def _set_network_overview_table(self, summary: PcapSummary) -> None:
        rows = self._network_overview_rows(summary)
        self._set_table(self.tbl_network_overview, rows)
        self.lbl_network_overview_count.setText(f"{len(rows):,} rows")
        self.lbl_network_overview_breakdown.setText(
            f"Protocols: {len(summary.protocols or []):,} | "
            f"Endpoints: {len(summary.top_endpoints or []):,} | "
            f"Ports: {len(summary.top_ports or []):,}"
        )

    def _set_connections_table(self, summary: PcapSummary) -> None:
        rows = summary.flows or []
        self._set_table(self.tbl_connections, rows)
        payload_rows = sum(1 for row in rows if str(row.get("pcap_payload_preview") or "").strip())
        device_ip = summary.likely_device_ip or "-"
        self.lbl_connections_count.setText(f"{len(rows):,} flow summaries")
        self.lbl_connections_breakdown.setText(
            f"Device IP: {device_ip} | Visible previews: {payload_rows:,} | "
            f"Packets: {summary.packet_count:,} | Volume: {human_bytes(summary.wire_bytes, precision=2)}"
        )

    def _set_highlights(self, summary: PcapSummary) -> None:
        rows = summary.communication_rows or []
        media_like = sum(1 for row in rows if "media" in str(row.get("activity_type") or "").lower() or "call" in str(row.get("activity_type") or "").lower())
        messaging_like = sum(1 for row in rows if "messaging" in str(row.get("activity_type") or "").lower() or "push" in str(row.get("activity_type") or "").lower())
        services = []
        seen = set()
        for row in rows:
            service = str(row.get("service") or "").strip()
            if service and service not in seen:
                seen.add(service)
                services.append(service)

        lines = [
            f"Visible app/service indicators: {', '.join(services) if services else '-'}",
            f"Messaging/push-like indicators: {messaging_like}",
            f"Possible call/media indicators: {media_like}",
            "Classification is based on metadata such as host names, ports, protocol, duration and volume. It is an investigative indicator, not content proof.",
        ]
        self.lbl_highlights_brief.setText("\n".join(lines))
        self.lbl_communication_count.setText(f"{len(rows):,} indicators")
        self.lbl_communication_breakdown.setText(
            f"Messaging/push: {messaging_like:,} | "
            f"Possible call/media: {media_like:,} | "
            f"Services: {len(services):,}"
        )
        self._set_table(self.tbl_communications, rows)
        if rows:
            self.tbl_communications.clearSelection()
        self.txt_communication_detail.clear()
        self._selected_communication_row = None

    def _on_communication_selected(self, current: QModelIndex, previous: QModelIndex | None = None) -> None:
        model = self.tbl_communications.model()
        if not isinstance(model, DictTableModel) or not current.isValid():
            self._selected_communication_row = None
            self.txt_communication_detail.clear()
            return
        if current.row() < 0 or current.row() >= len(model.rows):
            self._selected_communication_row = None
            self.txt_communication_detail.clear()
            return

        row = model.rows[current.row()]
        self._selected_communication_row = dict(row)
        self.txt_communication_detail.setPlainText(self._communication_detail_text(row))

    def _communication_detail_text(self, row: dict[str, Any]) -> str:
        lines = [
            f"Service: {row.get('service') or '-'}",
            f"Indicator: {row.get('activity_type') or '-'}",
            f"Confidence: {row.get('confidence') or '-'}",
            f"Host / signal: {row.get('host') or '-'}",
            f"Source: {row.get('source') or '-'}",
            f"Destination: {row.get('destination') or '-'}",
            f"Protocol: {row.get('protocol') or '-'}",
            f"Volume: {human_bytes(row.get('bytes'), precision=2)}",
            f"Packets: {row.get('packets') or 0}",
            f"Duration: {format_duration_compact_ms(row.get('duration_ms'))}",
            f"First seen: {self._format_pcap_time(row.get('first_seen'))}",
            f"Last seen: {self._format_pcap_time(row.get('last_seen'))}",
            "",
            "Evidence:",
            str(row.get("evidence") or "-"),
            "",
            "Interpretation limit:",
            "This is a metadata-based indicator. It does not prove message content or confirm a call by itself.",
        ]
        return "\n".join(lines)

    def _open_communications_dialog(self) -> None:
        model = self.tbl_communications.model()
        rows = list(model.rows) if isinstance(model, DictTableModel) else []
        open_communication_indicators_dialog(
            self,
            rows=rows,
            columns=self.communication_full_columns,
            fixed_widths=self.communication_full_fixed_widths,
            detail_text=self._communication_detail_text,
            on_empty=self._info,
            append_export_footer=lambda footer, table: self._append_export_footer(
                footer, title="Communication indicators", table=table
            ),
        )

    def _set_table(self, table: QTableView, rows: list[dict[str, Any]]):
        set_dict_table_rows(table, rows)

    def _set_artifact_tables(self, artifacts: list[dict[str, Any]]) -> None:
        self._all_artifacts = artifacts or []
        counts: dict[str, int] = {}
        for artifact in self._all_artifacts:
            category = str(artifact.get("category") or "Other")
            counts[category] = counts.get(category, 0) + 1

        self.cmb_artifact_category.blockSignals(True)
        self.cmb_artifact_category.clear()
        self.cmb_artifact_category.addItem(f"All artifacts ({len(self._all_artifacts)})", "")
        for category, count in sorted(counts.items()):
            self.cmb_artifact_category.addItem(f"{category} ({count})", category)
        self.cmb_artifact_category.blockSignals(False)
        if counts:
            preview_lines = [
                f"{idx}. {category}  {count:,}"
                for idx, (category, count) in enumerate(
                    sorted(counts.items(), key=lambda item: (-item[1], item[0]))[:5],
                    start=1,
                )
            ]
            preview_text = "\n".join(preview_lines)
        else:
            preview_text = "No artifact categories loaded."
        self.lbl_artifact_preview.setText(preview_text)
        self._apply_artifact_filter()

    def _apply_artifact_filter(self, *args) -> None:
        category = self.cmb_artifact_category.currentData() if hasattr(self, "cmb_artifact_category") else ""
        rows = [
            artifact
            for artifact in self._all_artifacts
            if not category or str(artifact.get("category") or "Other") == category
        ]
        self._set_table(self.tbl_artifacts, rows)
        self.lbl_artifact_count.setText(f"{len(rows)} shown")
        selected_category = self.cmb_artifact_category.currentData() if hasattr(self, "cmb_artifact_category") else ""
        label = "artifacts" if not selected_category else f"{selected_category} artifacts"
        self.lbl_artifact_total.setText(f"{len(rows):,} {label}")
        if rows:
            self.tbl_artifacts.selectRow(0)
        else:
            self.txt_artifact_detail.clear()

    def _on_artifact_selected(self, current: QModelIndex, previous: QModelIndex | None = None) -> None:
        model = self.tbl_artifacts.model()
        if not isinstance(model, DictTableModel) or not current.isValid():
            self.txt_artifact_detail.clear()
            return
        if current.row() < 0 or current.row() >= len(model.rows):
            self.txt_artifact_detail.clear()
            return

        artifact = model.rows[current.row()]
        detail_lines = [
            f"Category: {artifact.get('category') or '-'}",
            f"Type: {artifact.get('type') or '-'}",
            f"Value: {artifact.get('value') or '-'}",
            f"Count: {artifact.get('count') or 0}",
            f"Visibility: {artifact.get('visibility') or '-'}",
            "",
            f"Source: {artifact.get('source') or '-'}",
            f"Destination: {artifact.get('destination') or '-'}",
            f"First seen: {self._format_pcap_time(artifact.get('first_seen'))}",
            f"Last seen: {self._format_pcap_time(artifact.get('last_seen'))}",
            "",
            "Meaning:",
            str(artifact.get("explanation") or "-"),
        ]
        if artifact.get("sensitive"):
            detail_lines.extend([
                "",
                "Sensitive value:",
                "The value was visible in plaintext capture data and is redacted in ViaNyquist.",
            ])
        self.txt_artifact_detail.setPlainText("\n".join(detail_lines))

    def _overview_text(self, summary: PcapSummary) -> str:
        lines = [
            "What is visible:",
            f"- DNS names: {int(summary.total_dns_names or len(summary.dns_queries or [])):,}",
            f"- TLS SNI hosts: {int(summary.total_tls_sni_hosts or len(summary.tls_sni or [])):,}",
            f"- HTTP cleartext hosts: {int(summary.total_http_hosts or len(summary.http_hosts or [])):,}",
            f"- Flow summaries: {len(summary.flows or []):,}",
            f"- Readable payload samples: {len(summary.readable_samples or []):,}",
            "",
            "Important limitation:",
            "Encrypted HTTPS, QUIC and application traffic content is not readable from packet capture alone. "
            "ViaNyquist shows the observable metadata and only the payload bytes that are actually visible.",
        ]
        return "\n".join(lines)

    def _set_investigator_text(self, investigator: dict[str, Any]) -> None:
        summary = str(investigator.get("plain_summary") or "")
        self.lbl_plain_summary.setText(summary)

        key_points = "\n".join(f"- {point}" for point in (investigator.get("key_points") or [])[:4])
        self.lbl_key_points.setText(f"Key points:\n{key_points}" if key_points else "")
        limitations = "\n".join(f"- {item}" for item in (investigator.get("limitations") or [])[:4])
        self.lbl_limitations.setText(f"Limitations:\n{limitations}" if limitations else "")
