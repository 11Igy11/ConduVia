from __future__ import annotations

from typing import Any

from PySide6.QtCore import QAbstractTableModel, QModelIndex, Qt

from core.formatters import format_duration_compact_ms, format_pcap_datetime, human_bytes
from core.protocols import format_ip_proto


class DictTableModel(QAbstractTableModel):
    def __init__(self, columns: list[tuple[str, str]], rows: list[dict[str, Any]] | None = None):
        super().__init__()
        self.columns = columns
        self.rows = rows or []

    def set_rows(self, rows: list[dict[str, Any]]):
        self.beginResetModel()
        self.rows = rows or []
        self.endResetModel()

    def rowCount(self, parent=QModelIndex()):
        return len(self.rows)

    def columnCount(self, parent=QModelIndex()):
        return len(self.columns)

    def headerData(self, section, orientation, role=Qt.DisplayRole):
        if role == Qt.DisplayRole and orientation == Qt.Horizontal:
            return self.columns[section][1]
        if role == Qt.DisplayRole:
            return str(section + 1)
        return None

    def sort(self, column: int, order: Qt.SortOrder = Qt.AscendingOrder):
        if column < 0 or column >= len(self.columns):
            return
        key = self.columns[column][0]
        reverse = order == Qt.DescendingOrder
        self.layoutAboutToBeChanged.emit()
        self.rows.sort(key=lambda row: self._sort_value(key, row.get(key, "")), reverse=reverse)
        self.layoutChanged.emit()

    def _sort_value(self, key: str, value: Any):
        if value is None:
            return (1, "")
        if key in {
            "bytes",
            "bidirectional_bytes",
            "packets",
            "bidirectional_packets",
            "duration_ms",
            "bidirectional_duration_ms",
            "count",
            "share",
            "port",
            "src_port",
            "dst_port",
            "protocol",
            "protocol_number",
        }:
            try:
                return (0, float(value))
            except Exception:
                return (0, 0.0)
        if key == "confidence":
            order = {"low": 1, "medium": 2, "high": 3}
            return (0, order.get(str(value).strip().lower(), 0))
        return (0, str(value).casefold())

    def data(self, index, role=Qt.DisplayRole):
        if not index.isValid() or role not in (Qt.DisplayRole, Qt.ToolTipRole):
            return None
        key = self.columns[index.column()][0]
        value = self.rows[index.row()].get(key, "")
        if role == Qt.ToolTipRole:
            return "" if value is None else str(value)
        if key in ("protocol", "protocol_number") and isinstance(value, int):
            return format_ip_proto(value)
        if key in ("bytes", "bidirectional_bytes"):
            return human_bytes(value, precision=2)
        if key in ("bidirectional_duration_ms", "duration_ms"):
            return format_duration_compact_ms(value)
        if key in {
            "time",
            "hour",
            "first_seen",
            "last_seen",
            "bidirectional_first_seen_ms",
            "bidirectional_last_seen_ms",
        }:
            return format_pcap_datetime(value)
        if key == "share":
            try:
                return f"{float(value):.1f}%"
            except Exception:
                return str(value)
        return "" if value is None else str(value)
