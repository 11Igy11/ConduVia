from __future__ import annotations

from pathlib import Path
from typing import Any

from PySide6.QtCore import Qt
from PySide6.QtGui import QColor, QFont, QImage, QPainter

from core.pcap_analyzer import build_investigator_view


def available_notes_charts(
    profile: dict[str, Any],
    behavior: dict[str, Any],
    pcap_summary: Any | None = None,
) -> list[dict[str, Any]]:
    charts: list[dict[str, Any]] = [
        {
            "name": "Profile activity by hour",
            "title": "Profile activity by hour",
            "filename": "activity-by-hour",
            "rows": list(behavior.get("hour_rows") or []),
            "value_key": "count",
            "empty_text": "Save JSON datasets to the active project to build hourly activity.",
        },
        {
            "name": "Activity heatmap",
            "title": "Activity heatmap",
            "filename": "activity-heatmap",
            "rows": list(behavior.get("hour_rows") or []),
            "kind": "heatmap",
            "empty_text": "Save JSON datasets to the active project to build the 24-hour heatmap.",
        },
        {
            "name": "Service groups by volume",
            "title": "Service groups by volume",
            "filename": "service-groups",
            "rows": list(behavior.get("service_rows") or []),
            "value_key": "bytes",
            "value_label_key": "bytes_label",
            "empty_text": "Save JSON datasets to the active project to build service group volume.",
        },
        {
            "name": "Top domains by volume",
            "title": "Top domains by volume",
            "filename": "top-domains",
            "rows": list(behavior.get("domain_rows") or []),
            "value_key": "bytes",
            "value_label_key": "bytes_label",
            "empty_text": "No visible host/domain data is available in saved JSON datasets.",
        },
        {
            "name": "Evidence sources",
            "title": "Evidence sources",
            "filename": "evidence-sources",
            "rows": list(profile.get("evidence_counts") or []),
            "value_key": "count",
            "empty_text": "No saved evidence sources are available for this project.",
        },
        {
            "name": "Device IP distribution",
            "title": "Device IP distribution",
            "filename": "device-ip-distribution",
            "rows": list(profile.get("pcap_device_ip_rows") or []),
            "value_key": "count",
            "empty_text": "No saved PCAP device IP rows are available.",
        },
        {
            "name": "Activity event types",
            "title": "Activity event types",
            "filename": "activity-event-types",
            "rows": list(profile.get("activity_type_rows") or []),
            "value_key": "count",
            "empty_text": "No project activity events are available.",
        },
    ]

    if pcap_summary is not None:
        investigator = build_investigator_view(pcap_summary)
        charts.extend(
            [
                {
                    "name": "PCAP visible vs encrypted",
                    "title": "PCAP visible vs encrypted",
                    "filename": "pcap-visible-vs-encrypted",
                    "rows": _rows_from_visibility(investigator.get("visibility_rows") or []),
                    "value_key": "count",
                    "subtitle": "Generated from the currently loaded PCAP capture.",
                    "empty_text": "No PCAP visibility indicators are available.",
                },
                {
                    "name": "PCAP communication indicators",
                    "title": "PCAP communication indicators",
                    "filename": "pcap-communication-indicators",
                    "rows": _rows_from_communication(pcap_summary.communication_rows or []),
                    "value_key": "count",
                    "subtitle": "Generated from the currently loaded PCAP capture.",
                    "empty_text": "No PCAP communication indicators are available.",
                },
                {
                    "name": "PCAP protocol packets",
                    "title": "PCAP protocol packets",
                    "filename": "pcap-protocol-packets",
                    "rows": [
                        {
                            "label": str(row.get("protocol") or row.get("name") or "-"),
                            "count": int(row.get("packets") or 0),
                        }
                        for row in (pcap_summary.protocols or [])
                    ],
                    "value_key": "count",
                    "subtitle": "Generated from the currently loaded PCAP capture.",
                    "empty_text": "No PCAP protocol packet data is available.",
                },
            ]
        )
    return charts


def render_notes_chart(file_path: Path, chart: dict[str, Any], rows: list[dict[str, Any]]) -> None:
    if chart.get("kind") == "heatmap":
        render_hour_heatmap(file_path, str(chart["title"]), rows)
        return

    render_bar_chart(
        file_path,
        str(chart["title"]),
        rows,
        value_key=str(chart.get("value_key") or "count"),
        value_label_key=chart.get("value_label_key"),
        subtitle=str(chart.get("subtitle") or "Generated from the active project Activity Profile."),
    )


def _rows_from_visibility(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    out = []
    for row in rows:
        count = int(row.get("count") or 0)
        share = row.get("share")
        value = f"{count:,}"
        if isinstance(share, (int, float)):
            value += f" / {share:.1f}%"
        out.append(
            {
                "label": str(row.get("label") or row.get("visibility") or "-"),
                "count": count,
                "value": value,
            }
        )
    return out


def _rows_from_communication(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    grouped: dict[str, dict[str, Any]] = {}
    for row in rows:
        label = str(row.get("activity_type") or "Communication indicator")
        item = grouped.setdefault(label, {"label": label, "count": 0, "bytes": 0})
        item["count"] += 1
        item["bytes"] += int(row.get("bytes") or 0)
    return sorted(grouped.values(), key=lambda row: (-int(row.get("count") or 0), str(row.get("label") or "")))


def render_bar_chart(
    file_path: Path,
    title: str,
    rows: list[dict[str, Any]],
    *,
    value_key: str,
    value_label_key: str | None = None,
    subtitle: str = "Generated from the active project Activity Profile.",
) -> None:
    rows = [row for row in rows if isinstance(row, dict)][:12]
    file_path = Path(file_path)
    file_path.parent.mkdir(parents=True, exist_ok=True)

    width = 1100
    row_height = 42
    top = 94
    height = max(360, top + len(rows) * row_height + 54)
    label_width = 350
    bar_x = 410
    bar_width = 500
    value_x = bar_x + bar_width + 24

    image = QImage(width, height, QImage.Format_ARGB32)
    image.fill(QColor("#f8fafc"))
    painter = QPainter(image)
    painter.setRenderHint(QPainter.Antialiasing)

    try:
        painter.setPen(QColor("#0f172a"))
        title_font = QFont("Segoe UI", 20)
        title_font.setBold(True)
        painter.setFont(title_font)
        painter.drawText(38, 50, title)

        subtitle_font = QFont("Segoe UI", 10)
        painter.setFont(subtitle_font)
        painter.setPen(QColor("#64748b"))
        painter.drawText(40, 74, subtitle)

        max_value = max(int(row.get(value_key) or 0) for row in rows) if rows else 1
        max_value = max(max_value, 1)

        row_font = QFont("Segoe UI", 11)
        value_font = QFont("Segoe UI", 10)
        metrics = painter.fontMetrics()

        for index, row in enumerate(rows):
            y = top + index * row_height
            label = str(row.get("label") or "-")
            example = str(row.get("example") or "").strip()
            if example:
                label = f"{label} - {example}"

            painter.setFont(row_font)
            painter.setPen(QColor("#0f172a"))
            label_text = metrics.elidedText(label, Qt.ElideRight, label_width)
            painter.drawText(40, y + 25, label_text)

            painter.setPen(Qt.NoPen)
            painter.setBrush(QColor("#e2e8f0"))
            painter.drawRoundedRect(bar_x, y + 7, bar_width, 26, 7, 7)

            value = max(0, int(row.get(value_key) or 0))
            fill_width = max(3 if value else 0, int((value / max_value) * bar_width))
            painter.setBrush(QColor("#3b82f6"))
            painter.drawRoundedRect(bar_x, y + 7, fill_width, 26, 7, 7)

            if value_label_key:
                value_text = str(row.get(value_label_key) or row.get(value_key) or "0")
            elif row.get("value"):
                value_text = str(row.get("value"))
            else:
                value_text = f"{value:,}"
            share = row.get("share")
            if isinstance(share, (int, float)):
                value_text = f"{value_text} / {share:.1f}%"

            painter.setFont(value_font)
            painter.setPen(QColor("#0f172a"))
            painter.drawText(value_x, y + 25, value_text)
    finally:
        painter.end()

    image.save(str(file_path), "PNG")


def render_hour_heatmap(file_path: Path, title: str, rows: list[dict[str, Any]]) -> None:
    file_path = Path(file_path)
    file_path.parent.mkdir(parents=True, exist_ok=True)

    width = 1100
    height = 250
    image = QImage(width, height, QImage.Format_ARGB32)
    image.fill(QColor("#f8fafc"))
    painter = QPainter(image)
    painter.setRenderHint(QPainter.Antialiasing)

    values = {str(row.get("label") or "")[:2]: int(row.get("count") or 0) for row in rows if isinstance(row, dict)}
    max_value = max(values.values()) if values else 1
    max_value = max(max_value, 1)
    cell_w = 40
    cell_h = 54
    start_x = 46
    start_y = 98

    try:
        painter.setPen(QColor("#0f172a"))
        title_font = QFont("Segoe UI", 20)
        title_font.setBold(True)
        painter.setFont(title_font)
        painter.drawText(38, 50, title)

        painter.setFont(QFont("Segoe UI", 10))
        painter.setPen(QColor("#64748b"))
        painter.drawText(40, 74, "Darker cells indicate more observed flows in that hour.")

        label_font = QFont("Segoe UI", 8)
        painter.setFont(label_font)
        for hour in range(24):
            key = f"{hour:02d}"
            value = values.get(key, 0)
            intensity = value / max_value
            blue = 65 + int(120 * intensity)
            color = QColor(59, 130, min(255, blue + 70))
            if value == 0:
                color = QColor("#e2e8f0")
            x = start_x + hour * cell_w
            painter.setPen(Qt.NoPen)
            painter.setBrush(color)
            painter.drawRoundedRect(x, start_y, cell_w - 4, cell_h, 6, 6)

            painter.setPen(QColor("#0f172a"))
            painter.drawText(x + 5, start_y + cell_h + 18, f"{hour:02d}")
            if value:
                painter.setPen(QColor("#ffffff") if intensity > 0.45 else QColor("#0f172a"))
                text = f"{value:,}"
                painter.drawText(x + 5, start_y + 31, text[:5])
    finally:
        painter.end()

    image.save(str(file_path), "PNG")
