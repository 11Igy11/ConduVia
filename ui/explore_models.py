from typing import Any
import ipaddress

from PySide6.QtCore import Qt, QAbstractTableModel, QModelIndex, QSortFilterProxyModel
from PySide6.QtGui import QColor

from ui.flow_columns import (
    DEFAULT_FLOW_COLUMNS,
    flow_cell_display,
    flow_cell_sort_value,
    friendly_label,
)


def is_private_ip(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_private
    except Exception:
        return False


class FlowTableModel(QAbstractTableModel):
    DEFAULT_COLUMNS = DEFAULT_FLOW_COLUMNS
    # Backward-compatible alias used by export helpers.
    COLUMNS = [(key, friendly_label(key)) for key in DEFAULT_FLOW_COLUMNS]

    def __init__(self, flows: list[dict[str, Any]] | None = None):
        super().__init__()
        self._flows: list[dict[str, Any]] = flows or []
        self._columns: list[str] = list(self.DEFAULT_COLUMNS)
        self._ip_cache: dict[str, bool] = {}
        self._bg_private = QColor("#E8F5E9")
        self._bg_public = QColor("#FFEBEE")

    def set_flows(self, flows: list[dict[str, Any]]):
        self.beginResetModel()
        self._flows = flows or []
        self._ip_cache.clear()
        self.endResetModel()

    def set_columns(self, columns: list[str] | None):
        self.beginResetModel()
        self._columns = [str(col) for col in (columns or []) if str(col).strip()]
        self._ip_cache.clear()
        self.endResetModel()

    def columns(self) -> list[str]:
        return list(self._columns)

    def column_key(self, section: int) -> str | None:
        if section < 0 or section >= len(self._columns):
            return None
        return self._columns[section]

    def column_index(self, key: str) -> int:
        try:
            return self._columns.index(key)
        except ValueError:
            return -1

    def rowCount(self, parent: QModelIndex = QModelIndex()) -> int:
        return len(self._flows)

    def columnCount(self, parent: QModelIndex = QModelIndex()) -> int:
        return len(self._columns)

    def headerData(self, section: int, orientation: Qt.Orientation, role: int = Qt.DisplayRole):
        if role != Qt.DisplayRole:
            return None
        if orientation == Qt.Horizontal:
            key = self.column_key(section)
            return friendly_label(key) if key else None
        return str(section + 1)

    def _cached_is_private(self, ip: str) -> bool:
        if ip in self._ip_cache:
            return self._ip_cache[ip]
        val = is_private_ip(ip)
        self._ip_cache[ip] = val
        return val

    def data(self, index: QModelIndex, role: int = Qt.DisplayRole):
        if not index.isValid():
            return None

        flow = self._flows[index.row()]
        key = self.column_key(index.column())
        if not key:
            return None

        if role == Qt.DisplayRole:
            return flow_cell_display(key, flow)

        if role == Qt.ToolTipRole:
            return flow_cell_display(key, flow)

        if role == Qt.UserRole:
            return flow_cell_sort_value(key, flow)

        if role == Qt.BackgroundRole and key in ("src_ip", "dst_ip"):
            ip = flow.get(key, "")
            if not isinstance(ip, str) or not ip:
                return None
            return self._bg_private if self._cached_is_private(ip) else self._bg_public

        return None


class NumericSortProxy(QSortFilterProxyModel):
    def __init__(self):
        super().__init__()
        self.filter_text = ""
        self.conv_a: str | None = None
        self.conv_b: str | None = None

    def set_filter_text(self, text: str):
        self.filter_text = (text or "").lower()
        self.invalidate()

    def set_conversation(self, a: str | None, b: str | None):
        self.conv_a = a
        self.conv_b = b
        self.invalidate()

    def clear_conversation(self):
        self.conv_a = None
        self.conv_b = None
        self.invalidate()

    def _source_column_index(self, key: str) -> int:
        model = self.sourceModel()
        if model is None or not hasattr(model, "column_index"):
            return -1
        return int(model.column_index(key))

    def filterAcceptsRow(self, row: int, parent: QModelIndex) -> bool:
        model = self.sourceModel()
        if model is None:
            return True

        if self.conv_a and self.conv_b:
            src_col = self._source_column_index("src_ip")
            dst_col = self._source_column_index("dst_ip")
            if src_col < 0 or dst_col < 0:
                return False
            src_ip = model.data(model.index(row, src_col, parent), Qt.DisplayRole) or ""
            dst_ip = model.data(model.index(row, dst_col, parent), Qt.DisplayRole) or ""
            a, b = self.conv_a, self.conv_b
            if not ((src_ip == a and dst_ip == b) or (src_ip == b and dst_ip == a)):
                return False

        if not self.filter_text:
            return True

        for col in range(model.columnCount()):
            val = model.data(model.index(row, col, parent), Qt.DisplayRole)
            if val and self.filter_text in str(val).lower():
                return True
        return False

    def lessThan(self, left: QModelIndex, right: QModelIndex) -> bool:
        l = self.sourceModel().data(left, Qt.UserRole)
        r = self.sourceModel().data(right, Qt.UserRole)
        if isinstance(l, (int, float)) and isinstance(r, (int, float)):
            return l < r
        ls = self.sourceModel().data(left, Qt.DisplayRole) or ""
        rs = self.sourceModel().data(right, Qt.DisplayRole) or ""
        return str(ls) < str(rs)
