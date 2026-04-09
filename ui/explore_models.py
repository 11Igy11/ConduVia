from typing import Any
import ipaddress

from PySide6.QtCore import Qt, QAbstractTableModel, QModelIndex, QSortFilterProxyModel
from PySide6.QtGui import QColor

from core.protocols import format_ip_proto



def is_private_ip(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_private
    except Exception:
        return False


class FlowTableModel(QAbstractTableModel):
    COLUMNS = [
        ("src_ip", "Source IP"),
        ("src_port", "Source Port"),
        ("dst_ip", "Destination IP"),
        ("dst_port", "Destination Port"),
        ("protocol", "Protocol"),
        ("application_name", "Application"),
        ("bidirectional_bytes", "Bytes"),
        ("bidirectional_duration_ms", "Duration(ms)"),
        ("requested_server_name", "SNI"),
    ]

    def __init__(self, flows: list[dict[str, Any]] | None = None):
        super().__init__()
        self._flows: list[dict[str, Any]] = flows or []
        self._ip_cache: dict[str, bool] = {}
        self._bg_private = QColor("#E8F5E9")  # light green
        self._bg_public = QColor("#FFEBEE")   # light red

    def set_flows(self, flows: list[dict[str, Any]]):
        self.beginResetModel()
        self._flows = flows
        self._ip_cache.clear()
        self.endResetModel()

    def rowCount(self, parent: QModelIndex = QModelIndex()) -> int:
        return len(self._flows)

    def columnCount(self, parent: QModelIndex = QModelIndex()) -> int:
        return len(self.COLUMNS)

    def headerData(self, section: int, orientation: Qt.Orientation, role: int = Qt.DisplayRole):
        if role != Qt.DisplayRole:
            return None
        if orientation == Qt.Horizontal:
            return self.COLUMNS[section][1]
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
        key = self.COLUMNS[index.column()][0]

        if role == Qt.DisplayRole:
            val = flow.get(key, "")
            if key == "protocol":
                return format_ip_proto(val)
            return "" if val is None else str(val)

        if role == Qt.ToolTipRole:
            val = flow.get(key, "")
            if key == "protocol":
                return format_ip_proto(val)
            return "" if val is None else str(val)

        if role == Qt.UserRole:
            val = flow.get(key)
            if isinstance(val, (int, float)):
                return val
            try:
                return int(val)
            except Exception:
                return 0

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

    def filterAcceptsRow(self, row: int, parent: QModelIndex) -> bool:
        model = self.sourceModel()

        if self.conv_a and self.conv_b:
            src_ip = model.data(model.index(row, 0, parent), Qt.DisplayRole) or ""
            dst_ip = model.data(model.index(row, 2, parent), Qt.DisplayRole) or ""
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