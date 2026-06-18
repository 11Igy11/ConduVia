"""Table models and proxies for the Registry page."""

from __future__ import annotations

from typing import Any

from PySide6.QtCore import QAbstractTableModel, QModelIndex, Qt, QSortFilterProxyModel

from core.protocols import format_ip_proto


class RegistryTableModel(QAbstractTableModel):
    def __init__(self):
        super().__init__()
        self._rows: list[dict[str, Any]] = []
        self._cols: list[str] = []

    def set_data(self, flows: list[dict[str, Any]], cols: list[str]):
        self.beginResetModel()
        self._rows = flows or []
        self._cols = cols or []
        self.endResetModel()

    def rowCount(self, parent: QModelIndex = QModelIndex()) -> int:
        return len(self._rows)

    def columnCount(self, parent: QModelIndex = QModelIndex()) -> int:
        return len(self._cols)

    def headerData(self, section: int, orientation: Qt.Orientation, role: int = Qt.DisplayRole):
        if role != Qt.DisplayRole:
            return None
        if orientation == Qt.Horizontal:
            return self._cols[section] if 0 <= section < len(self._cols) else ""
        return str(section + 1)

    def data(self, index: QModelIndex, role: int = Qt.DisplayRole):
        if not index.isValid():
            return None
        r = index.row()
        c = index.column()
        if not (0 <= r < len(self._rows) and 0 <= c < len(self._cols)):
            return None

        key = self._cols[c]
        val = self._rows[r].get(key, None)

        if role in (Qt.DisplayRole, Qt.ToolTipRole):
            if key == "protocol":
                return format_ip_proto(val)
            return "" if val is None else str(val)

        return None


class TextFilterProxy(QSortFilterProxyModel):
    def __init__(self):
        super().__init__()
        self._q = ""
        self._hour: int | None = None  # 0..23 or None

    def set_query(self, q: str):
        self._q = (q or "").strip().lower()
        self.invalidateFilter()

    def set_hour_filter(self, hour: int | None):
        if hour is None:
            self._hour = None
        else:
            h = int(hour)
            self._hour = h if 0 <= h <= 23 else None
        self.invalidateFilter()

    def filterAcceptsRow(self, row: int, parent: QModelIndex) -> bool:
        if self._hour is not None:
            sm = self.sourceModel()
            try:
                flow = sm._rows[row]  # RegistryTableModel rows
                h = int(flow.get("_cv_hour", -1))
            except Exception:
                h = -1
            if h != self._hour:
                return False

        if not self._q:
            return True
        m = self.sourceModel()
        for col in range(m.columnCount()):
            v = m.data(m.index(row, col, parent), Qt.DisplayRole)
            if v and self._q in str(v).lower():
                return True
        return False


class PairsModel(QAbstractTableModel):
    """2-col model for (key, value) lists."""

    def __init__(self):
        super().__init__()
        self._rows: list[tuple[Any, Any]] = []
        self._headers = ("Item", "Value")

    def set_rows(self, rows: list[tuple[Any, Any]], headers: tuple[str, str] | None = None):
        self.beginResetModel()
        self._rows = rows or []
        if headers:
            self._headers = headers
        self.endResetModel()

    def rowCount(self, parent: QModelIndex = QModelIndex()) -> int:
        return len(self._rows)

    def columnCount(self, parent: QModelIndex = QModelIndex()) -> int:
        return 2

    def headerData(self, section: int, orientation: Qt.Orientation, role: int = Qt.DisplayRole):
        if role != Qt.DisplayRole:
            return None
        if orientation == Qt.Horizontal:
            return self._headers[section]
        return str(section + 1)

    def data(self, index: QModelIndex, role: int = Qt.DisplayRole):
        if not index.isValid():
            return None
        r = index.row()
        c = index.column()
        if not (0 <= r < len(self._rows)):
            return None
        k, v = self._rows[r]

        if role == Qt.DisplayRole:
            return str(k) if c == 0 else str(v)

        if role == Qt.TextAlignmentRole and c == 1:
            return int(Qt.AlignCenter)

        return None
