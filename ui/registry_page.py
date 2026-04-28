from __future__ import annotations
from core.protocols import format_ip_proto
import html
from pathlib import Path
from typing import Any
from core.timeutils import parse_flow_timestamp
from core.exporters.registry_exporter import export_registry_html

from PySide6.QtCore import Qt, Signal, QAbstractTableModel, QModelIndex, QSortFilterProxyModel, QSize, QRectF
from PySide6.QtGui import QPainter, QColor, QPen, QFontMetrics
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton, QLineEdit,
    QTableView, QFileDialog, QMessageBox, QFrame, QGridLayout, QTabWidget,
    QSizePolicy, QCheckBox, QScrollArea, QProgressBar, QToolTip
)

from core.parser import extract_dataset_meta, build_registry_columns, compute_registry_summary
from core.analyst import compute_analyst_summary

# ----------------- helpers -----------------
def _human_bytes(n: int | float | None) -> str:
    try:
        v = float(n or 0)
    except Exception:
        v = 0.0
    units = ["B", "KB", "MB", "GB", "TB"]
    i = 0
    while v >= 1024 and i < len(units) - 1:
        v /= 1024.0
        i += 1
    if i == 0:
        return f"{int(v)} {units[i]}"
    return f"{v:.1f} {units[i]}"

def _safe_int(x: Any) -> int:
    if x is None:
        return 0
    if isinstance(x, bool):
        return int(x)
    if isinstance(x, int):
        return x
    try:
        return int(float(x))
    except Exception:
        return 0

def _esc(x: Any) -> str:
    return html.escape("" if x is None else str(x))

def _fmt_dt_short(x: Any) -> str:
    if not x:
        return "—"

    # datetime object
    try:
        return x.strftime("%d.%m.%Y.")
    except Exception:
        pass

    # string -> try as real ISO datetime (meta bt/et)
    try:
        from datetime import datetime
        dt = datetime.fromisoformat(str(x).strip())
        return dt.strftime("%d.%m.%Y.")
    except Exception:
        pass

    # fallback: flow timestamp parser
    try:
        dt = parse_flow_timestamp({"timestamp": x})
        if dt is not None:
            return dt.strftime("%d.%m.%Y.")
    except Exception:
        pass

    return str(x)

def _fmt_days_short(x: Any) -> str:
    try:
        v = float(x)
    except Exception:
        return "—"

    # ako je praktički cijeli broj, prikaži bez decimala
    if abs(v - round(v)) < 0.05:
        return f"{int(round(v))} days"

    return f"{v:.1f} days"

def _day_activity_html(day_hist: dict[str, Any], day_bytes: dict[str, Any], *, top_n: int = 7) -> str:
    if not isinstance(day_hist, dict) or not day_hist:
        return "<span style='color:#6b7280;'>—</span>"

    items = []
    for day, count in day_hist.items():
        try:
            c = int(count)
        except Exception:
            c = 0

        try:
            b = int((day_bytes or {}).get(day, 0))
        except Exception:
            b = 0

        items.append((str(day), c, b))

    # sort by date
    items.sort(key=lambda x: x[0])

    # latest N days
    if len(items) > top_n:
        items = items[-top_n:]

    rows = []
    for i, (day, count, total_bytes) in enumerate(items):

        mb = float(total_bytes) / (1024.0 * 1024.0)

        bg = "##273549" if i % 2 == 0 else "#2f3e55"

        rows.append(
            "<tr style='background:" + bg + ";'>"
            f"<td style='padding:7px 12px;border-top:1px solid #334155;color:#cbd5e1;'>{_esc(_fmt_dt_short(day))}</td>"
            f"<td style='padding:7px 12px;border-top:1px solid #334155;color:#f8fafc;font-weight:700;text-align:right;'>{count}</td>"
            f"<td style='padding:7px 12px;border-top:1px solid #334155;color:#cbd5e1;font-weight:600;text-align:right;'>{mb:.1f} MB</td>"
            "</tr>"
        )

    return (
            "<div style='margin-top:8px;max-width:520px;"
            "border:1px solid #475569;border-radius:10px;overflow:hidden;"
            "background:#273549;'>"
            "<table style='width:100%;border-collapse:collapse;'>"
            "<thead>"
            "<tr style='background:#1f2937;'>"
            "<th style='padding:8px 12px;text-align:left;color:#94a3b8;font-size:11px;font-weight:700;'>Date</th>"
            "<th style='padding:8px 12px;text-align:right;color:#94a3b8;font-size:11px;font-weight:700;'>Flows</th>"
            "<th style='padding:8px 12px;text-align:right;color:#94a3b8;font-size:11px;font-weight:700;'>Bytes</th>"
            "</tr>"
            "</thead>"
            "<tbody>"
            + "".join(rows) +
            "</tbody>"
            "</table>"
            "</div>"
        )

def _top_active_days_html(day_hist: dict[str, Any], day_bytes: dict[str, Any], *, top_n: int = 5) -> str:
    if not isinstance(day_hist, dict) or not day_hist:
        return "<span style='color:#6b7280;'>—</span>"

    items = []
    for day, count in day_hist.items():
        try:
            c = int(count)
        except Exception:
            c = 0

        try:
            b = int((day_bytes or {}).get(day, 0))
        except Exception:
            b = 0

        items.append((str(day), c, b)) 

    # sort by flows desc
    items.sort(key=lambda x: x[1], reverse=True)
    items = items[:top_n]

    rows = []
    for i, (day, count, total_bytes) in enumerate(items):

        mb = float(total_bytes) / (1024.0 * 1024.0)

        bg = "#273549" if i % 2 == 0 else "#2f3e55"

        rows.append(
            "<tr style='background:" + bg + ";'>"
            f"<td style='padding:7px 12px;border-top:1px solid #334155;color:#cbd5e1;'>{_esc(_fmt_dt_short(day))}</td>"
            f"<td style='padding:7px 12px;border-top:1px solid #334155;color:#f8fafc;font-weight:700;text-align:right;'>{count}</td>"
            f"<td style='padding:7px 12px;border-top:1px solid #334155;color:#cbd5e1;font-weight:600;text-align:right;'>{mb:.1f} MB</td>"
            "</tr>"
        )

    return (
        "<div style='margin-top:8px;max-width:520px;"
        "border:1px solid #475569;border-radius:10px;overflow:hidden;"
        "background:#273549;'>"
        "<table style='width:100%;border-collapse:collapse;'>"
        "<thead>"
        "<tr style='background:#1f2937;'>"
        "<th style='padding:8px 12px;text-align:left;color:#94a3b8;font-size:11px;font-weight:700;'>Date</th>"
        "<th style='padding:8px 12px;text-align:right;color:#94a3b8;font-size:11px;font-weight:700;'>Flows</th>"
        "<th style='padding:8px 12px;text-align:right;color:#94a3b8;font-size:11px;font-weight:700;'>Bytes</th>"
        "</tr>"
        "</thead>"
        "<tbody>"
        + "".join(rows) +
        "</tbody>"
        "</table>"
        "</div>"
    )

def _mini_hist_24_html(vals: list[int], *, height_px: int = 14) -> str:
    """
    Qt RichText safe mini histogram.
    Expects 24 ints. If vals are 0..100 we use them directly as percent-of-height.
    Uses nested tables + pixel heights (no % heights) to avoid Qt CSS quirks.
    """
    if not isinstance(vals, list) or len(vals) != 24:
        return ""

    # if already 0..100, keep; else normalize to 0..100
    mx = max(vals) if vals else 0
    if mx <= 0:
        norm = [0] * 24
    elif mx <= 100 and min(vals) >= 0:
        # looks like already normalized
        norm = [int(v) for v in vals]
    else:
        norm = [int(round((v / mx) * 100)) for v in vals]

    # Build 24 bars using pixel height, not % height.
    tds = []
    for h, p in enumerate(norm):
        if p < 0: p = 0
        if p > 100: p = 100
        bar_h = int(round((p / 100) * height_px))
        empty_h = height_px - bar_h

        tds.append(
            "<td style='width:4.16%;padding:0 1px;vertical-align:bottom;'>"
            f"<div title='{h:02d}:00 — {vals[h]}' "
            f"style='height:{height_px}px;border:1px solid #475569;"
            "background:#1f2937;border-radius:4px;overflow:hidden;'>"
            # empty spacer
            f"<div style='height:{empty_h}px;'></div>"
            # bar
            f"<div style='height:{bar_h}px;background:#3b82f6;'></div>"
            "</div>"
            "</td>"
        )

    bars_row = (
        "<table style='width:100%;border-collapse:collapse;' cellspacing='0' cellpadding='0'>"
        "<tr>" + "".join(tds) + "</tr>"
        "</table>"
    )

    labels_row = """
    <table style='width:100%;border-collapse:collapse;margin-top:4px;' cellspacing='0' cellpadding='0'>
      <tr>
        <td style='width:0%;font-size:11px;color:#94a3b8;'>00</td>
        <td style='width:25%;font-size:11px;color:#94a3b8;text-align:center;'>06</td>
        <td style='width:25%;font-size:11px;color:#94a3b8;text-align:center;'>12</td>
        <td style='width:25%;font-size:11px;color:#94a3b8;text-align:center;'>18</td>
        <td style='width:25%;font-size:11px;color:#94a3b8;text-align:right;'>23</td>
      </tr>
    </table>
    """

    return "<div style='margin-top:6px;'>" + bars_row + labels_row + "</div>"


def _direction_bar_html(out_pct: float, in_pct: float, *, width_px: int = 220, height_px: int = 8) -> str:
    """
    Small OUT/IN bar (single bar split) as HTML.
    """
    try:
        o = float(out_pct)
    except Exception:
        o = 0.0
    try:
        i = float(in_pct)
    except Exception:
        i = 0.0

    # normalize if needed
    s = o + i
    if s > 0:
        o = (o / s) * 100.0
        i = (i / s) * 100.0
    else:
        o = 0.0
        i = 0.0

    o = 0.0 if o < 0 else 100.0 if o > 100 else o
    i = 0.0 if i < 0 else 100.0 if i > 100 else i

    return (
        f"<div style='display:inline-block;width:{width_px}px;height:{height_px}px;"
        "border:1px solid #475569;border-radius:999px;overflow:hidden;background:#1f2937;'>"
        f"<span style='display:inline-block;height:{height_px}px;width:{o:.1f}%;background:#3b82f6;'></span>"
        f"<span style='display:inline-block;height:{height_px}px;width:{i:.1f}%;background:#64748b;'></span>"
        "</div>"
    )

class DirectionBarWidget(QWidget):
    def __init__(self, parent: QWidget | None = None):
        super().__init__(parent)
        self._out_pct = 0.0
        self._in_pct = 0.0
        self.setMinimumHeight(14)
        self.setMaximumHeight(14)

    def sizeHint(self) -> QSize:
        return QSize(260, 14)

    def set_pcts(self, out_pct: float, in_pct: float):
        try:
            o = float(out_pct)
        except Exception:
            o = 0.0
        try:
            i = float(in_pct)
        except Exception:
            i = 0.0

        s = o + i
        if s > 0:
            o = (o / s) * 100.0
            i = (i / s) * 100.0
        else:
            o = 0.0
            i = 0.0

        self._out_pct = max(0.0, min(100.0, o))
        self._in_pct = max(0.0, min(100.0, i))
        self.update()

    def paintEvent(self, _):
        p = QPainter(self)
        try:
            p.setRenderHint(QPainter.Antialiasing, True)

            w = self.width()
            h = self.height()

            border = QColor("#475569")
            bg = QColor("#1f2937")
            out_c = QColor("#3b82f6")
            in_c = QColor("#64748b")
            r = 7.0

            p.setPen(QPen(border, 1))
            p.setBrush(bg)
            p.drawRoundedRect(0.5, 0.5, w - 1.0, h - 1.0, r, r)

            inner_w = max(0.0, w - 2.0)
            inner_h = max(0.0, h - 2.0)
            x0 = 1.0
            y0 = 1.0

            out_w = (self._out_pct / 100.0) * inner_w
            in_w = max(0.0, inner_w - out_w)

            if out_w > 0:
                p.setPen(Qt.NoPen)
                p.setBrush(out_c)
                p.drawRoundedRect(x0, y0, out_w, inner_h, r, r)

            if in_w > 0:
                p.setPen(Qt.NoPen)
                p.setBrush(in_c)
                p.drawRoundedRect(x0 + out_w, y0, in_w, inner_h, r, r)

        finally:
            p.end()

class MiniHistogram24Widget(QWidget):
    hourClicked = Signal(int)   # emits 0..23
    def __init__(self, parent: QWidget | None = None):
        super().__init__(parent)
        self._vals: list[int] = [0] * 24     # RAW counts
        self._show_labels = True
        self.setMinimumHeight(46)
        self._peak_hour = -1
        self._bar_rects = [QRectF() for _ in range(24)]
        self.setMouseTracking(True)
        self._quiet_hour = -1
        self._quiet_hours: set[int] = set()
        self._mode = "bytes"   # "bytes" or "flows"

    def sizeHint(self) -> QSize:
        return QSize(520, 46)

    def set_values(self, vals: list[int] | None):
        if not isinstance(vals, list) or len(vals) != 24:
            self._vals = [0] * 24
        else:
            out = []
            for v in vals:
                try:
                    iv = int(v)
                except Exception:
                    iv = 0
                out.append(max(0, iv))
            self._vals = out

                # peak hour (allways according shown values)
        if any(self._vals):
            self._peak_hour = max(range(24), key=lambda i: self._vals[i])
        else:
            self._peak_hour = -1

        self.update()
    
    def set_mode(self, mode: str):
        self._mode = "flows" if mode == "flows" else "bytes"
        self.update()

    def set_peak_quiet(self, peak_hour: int, quiet_hour: int):
        self._peak_hour = int(peak_hour) if peak_hour is not None else -1
        self._quiet_hour = int(quiet_hour) if quiet_hour is not None else -1
        self.update()

    def set_quiet_hours(self, hours: list[int] | set[int] | None):
        if not hours:
            self._quiet_hours = set()
        else:
            self._quiet_hours = {int(h) for h in hours if 0 <= int(h) <= 23}
        self.update()

    def mouseMoveEvent(self, e):
        pos = e.position()  # Qt6
        hit = -1
        for i, r in enumerate(self._bar_rects):
            if r.contains(pos):
                hit = i
                break

        if hit >= 0:
            v = int(self._vals[hit])

            if self._mode == "flows":
                tip = f"{hit:02d}:00 — {v} flows"
            else:
                mb = v / (1024.0 * 1024.0)
                tip = f"{hit:02d}:00 — {mb:.1f} MB"

            QToolTip.showText(e.globalPosition().toPoint(), tip, self)
        else:
            QToolTip.hideText()

        super().mouseMoveEvent(e)

    def mousePressEvent(self, e):
        pos = e.position()  # Qt6
        hit = -1
        for i, r in enumerate(self._bar_rects):
            if r.contains(pos):
                hit = i
                break

        if hit >= 0:
            self.hourClicked.emit(hit)

        super().mousePressEvent(e)

    def paintEvent(self, _):
        p = QPainter(self)
        try:
            p.setRenderHint(QPainter.Antialiasing, False)  # sharper

            w = self.width()
            h = self.height()

            bar_fg = QColor("#3b82f6")
            base_c = QColor("#475569")
            text_c = QColor("#94a3b8")

            label_h = 16 if self._show_labels else 0
            top_pad = 2
            bottom_pad = 2
            bars_h = max(1, h - label_h - top_pad - bottom_pad)

            n = 24
            gap = 3
            pad_x = 6
            avail_w = max(1, w - 2 * pad_x)
            bar_w = max(2, int((avail_w - gap * (n - 1)) / n))
            used_w = bar_w * n + gap * (n - 1)
            x0 = pad_x + int((avail_w - used_w) / 2)
            y0 = top_pad

            # baseline
            p.setPen(QPen(base_c, 1))
            p.drawLine(x0, y0 + bars_h, x0 + used_w, y0 + bars_h)

            # sqrt scaling: break's “all the same” problem
            mx = max(self._vals) if self._vals else 0
            if mx <= 0:
                scaled = [0] * 24
            else:
                import math
                mxs = math.sqrt(mx)
                scaled = [math.sqrt(v) / mxs for v in self._vals]  # 0..1

            # bars (without border)
            p.setPen(Qt.NoPen)
            for i in range(24):
                frac = scaled[i]
                bh = int(frac * bars_h)
                x = x0 + i * (bar_w + gap)

                # rect for hover (whole column)
                self._bar_rects[i] = QRectF(x, y0, bar_w, bars_h)

                if bh <= 0:
                    continue

                # peak / quiet highlight
                if i == self._peak_hour:
                    p.setBrush(QColor("#2563eb"))  # peak
                elif i in self._quiet_hours:
                    p.setBrush(QColor("#f59e0b"))  # quiet
                else:
                    p.setBrush(bar_fg)

                p.drawRect(x, y0 + (bars_h - bh), bar_w, bh)
                
            # labels
            if self._show_labels:
                f = p.font()
                f.setPointSize(9)
                p.setFont(f)
                fm = QFontMetrics(p.font())
                p.setPen(text_c)

                def draw_label(hour: int, align: str):
                    x = x0 + hour * (bar_w + gap) + int(bar_w / 2)
                    text = f"{hour:02d}"
                    tw = fm.horizontalAdvance(text)
                    y = y0 + bars_h + fm.ascent() + 2
                    if align == "left":
                        p.drawText(x0, y, text)
                    elif align == "right":
                        p.drawText(x0 + used_w - tw, y, text)
                    else:
                        p.drawText(int(x - tw / 2), y, text)

                draw_label(0, "left")
                draw_label(6, "center")
                draw_label(12, "center")
                draw_label(18, "center")
                draw_label(23, "right")

        finally:
            p.end()

# ----------------- models -----------------
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
        # Hour filter (fast path) - uses cached _cv_hour in flow dict
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

        # value column centered
        if role == Qt.TextAlignmentRole and c == 1:
            return int(Qt.AlignCenter)

        return None

# ----------------- page -----------------
class RegistryPage(QWidget):
    """
    Registry page:
    - HERO (meta chips)
    - actions: search + include-full checkbox + export
    - main tabs: Report / Dataset
      - Report: stats + insights (Top 15) + note (scrollable page)
      - Dataset: full dataset table (visible only when checkbox enabled)
    """
    openExploreWithSearch = Signal(str)              # example: "1.2.3.4" or "dns"
    openExploreWithConversation = Signal(str, str)   # src_ip, dst_ip

    def __init__(self, parent: QWidget | None = None):
        super().__init__(parent)

        self._folder: Path | None = None
        self._files: list[Path] = []
        self._flows: list[dict[str, Any]] = []
        self._meta: dict[str, Any] = {}
        self._summary: dict[str, Any] = {}
        self._cols: list[str] = []
        self._analyst: dict[str, Any] = {}
        self._compare_result: dict[str, Any] | None = None

        # ---- base layout ----
        root = QVBoxLayout(self)
        root.setContentsMargins(16, 16, 16, 16)
        root.setSpacing(12)

        # ---------------- HERO ----------------
        hero = QFrame()
        hero.setObjectName("Card")
        hl = QVBoxLayout(hero)
        hl.setContentsMargins(16, 14, 16, 14)
        hl.setSpacing(10)

        top_row = QHBoxLayout()
        left = QVBoxLayout()
        left.setSpacing(4)

        self.lbl_title = QLabel("Registry")
        self.lbl_title.setObjectName("H1")

        self.lbl_folder = QLabel("No dataset loaded.")
        self.lbl_folder.setObjectName("Muted")
        self.lbl_folder.setTextInteractionFlags(Qt.TextSelectableByMouse)

        left.addWidget(self.lbl_title)
        left.addWidget(self.lbl_folder)
        top_row.addLayout(left, 1)

        self.lbl_right_hint = QLabel("")
        self.lbl_right_hint.setObjectName("Muted")
        self.lbl_right_hint.setAlignment(Qt.AlignRight | Qt.AlignVCenter)
        top_row.addWidget(self.lbl_right_hint, 0)

        hl.addLayout(top_row)

        self.lbl_meta_chips = QLabel("")
        self.lbl_meta_chips.setTextFormat(Qt.RichText)
        self.lbl_meta_chips.setWordWrap(True)
        hl.addWidget(self.lbl_meta_chips)

        root.addWidget(hero)

        # ---------------- Actions row ----------------
        actions = QHBoxLayout()
        actions.setSpacing(12)

        self.txt_search = QLineEdit()
        self.txt_search.setPlaceholderText("Search across ALL fields…")

        self.chk_full = QCheckBox("Include full dataset")
        self.chk_full.setToolTip("Show full dataset in Dataset tab and include full dataset table in export.")
        self.chk_full.setChecked(False)
        self.chk_full.toggled.connect(self._on_toggle_full)

        self.btn_export = QPushButton("Export HTML report")
        self.btn_export.setObjectName("Primary")
        self.btn_export.setFixedHeight(38)
        self.btn_export.clicked.connect(self.export_report)

        actions.addWidget(self.txt_search, 1)
        actions.addWidget(self.chk_full, 0)
        actions.addWidget(self.btn_export, 0)
        root.addLayout(actions)

        # ---------------- Main Tabs ----------------
        self.main_tabs = QTabWidget()
        self.main_tabs.setDocumentMode(True)

        # Report tab (scrollable)
        self.report_page = QWidget()
        self.report_scroll = QScrollArea()
        self.report_scroll.setWidgetResizable(True)
        self.report_scroll.setFrameShape(QFrame.NoFrame)

        self.report_inner = QWidget()
        self.report_scroll.setWidget(self.report_inner)

        report_outer = QVBoxLayout(self.report_page)
        report_outer.setContentsMargins(0, 0, 0, 0)
        report_outer.addWidget(self.report_scroll)

        rp = QVBoxLayout(self.report_inner)
        rp.setContentsMargins(14, 14, 14, 14)
        rp.setSpacing(12)

        # Dataset tab
        self.dataset_page = QWidget()
        dp = QVBoxLayout(self.dataset_page)
        dp.setContentsMargins(14, 14, 14, 14)
        dp.setSpacing(10)

        self.main_tabs.addTab(self.report_page, "Report")
        self.main_tabs.addTab(self.dataset_page, "Dataset")

        root.addWidget(self.main_tabs, 1)

        # ---------------- Report content ----------------
        self.stats_wrap = QWidget()
        stats_grid = QGridLayout(self.stats_wrap)
        stats_grid.setContentsMargins(0, 0, 0, 0)
        stats_grid.setHorizontalSpacing(12)
        stats_grid.setVerticalSpacing(12)

        self.card_total = self._make_stat_card("Total flows", "—")
        self.card_usrc = self._make_stat_card("Unique src IP", "—")
        self.card_udst = self._make_stat_card("Unique dst IP", "—")
        self.card_uapps = self._make_stat_card("Unique apps", "—")
        self.card_bytes = self._make_stat_card("Total bytes", "—")

        stats_grid.addWidget(self.card_total, 0, 0)
        stats_grid.addWidget(self.card_usrc, 0, 1)
        stats_grid.addWidget(self.card_udst, 0, 2)
        stats_grid.addWidget(self.card_uapps, 0, 3)
        stats_grid.addWidget(self.card_bytes, 0, 4)

        rp.addWidget(self.stats_wrap)

        # ---------------- Analyst Summary card ----------------
        self.analyst_card = QFrame()
        self.analyst_card.setObjectName("Card")
        al = QVBoxLayout(self.analyst_card)
        al.setContentsMargins(14, 12, 14, 12)
        al.setSpacing(8)

        hdr2 = QHBoxLayout()
        self.lbl_analyst_title = QLabel("Analyst summary")
        self.lbl_analyst_title.setStyleSheet("font-size:14px;font-weight:900;color:#f8fafc;")
        hdr2.addWidget(self.lbl_analyst_title)
        hdr2.addStretch()
        al.addLayout(hdr2)

        # Behavior deviation row: label + progress
        deviation_row = QHBoxLayout()
        self.lbl_deviation = QLabel("Behavior deviation: —")
        self.lbl_deviation.setStyleSheet("color:#e5e7eb;font-weight:700;")
        deviation_row.addWidget(self.lbl_deviation, 0)

        self.deviation_bar = QProgressBar()
        self.deviation_bar.setRange(0, 100)
        self.deviation_bar.setValue(0)
        self.deviation_bar.setTextVisible(True)
        self.deviation_bar.setFormat("%p%")
        self.deviation_bar.setFixedHeight(18)
        self.deviation_bar.setStyleSheet("""
            QProgressBar {
                border: 1px solid #475569;
                border-radius: 9px;
                background: #1f2937;
                text-align: center;
                font-weight: 700;
                color: #e5e7eb;
            }
            QProgressBar::chunk {
                background: #3b82f6;
                border-radius: 9px;
            }
        """)
        deviation_row.addWidget(self.deviation_bar, 1)
        al.addLayout(deviation_row)

        # Body text (rich)
        self.lbl_analyst_body = QLabel("")
        self.lbl_analyst_body.setTextFormat(Qt.RichText)
        self.lbl_analyst_body.setWordWrap(True)
        self.lbl_analyst_body.setStyleSheet("color:#cbd5e1;")
        self.lbl_analyst_body.setSizePolicy(QSizePolicy.Preferred, QSizePolicy.Maximum)
        al.addWidget(self.lbl_analyst_body)

        self.lbl_day_section = QLabel("")
        self.lbl_day_section.setTextFormat(Qt.RichText)
        self.lbl_day_section.setWordWrap(True)
        self.lbl_day_section.setStyleSheet("color:#cbd5e1;")
        al.addWidget(self.lbl_day_section)

        self.lbl_activity_text = QLabel("")
        self.lbl_activity_text.setTextFormat(Qt.RichText)
        self.lbl_activity_text.setWordWrap(True)
        self.lbl_activity_text.setStyleSheet("color:#cbd5e1;")
        al.addWidget(self.lbl_activity_text)
        al.addSpacing(4)

        hist_hdr = QHBoxLayout()

        self.lbl_hist_title = QLabel("Activity by bytes")
        self.lbl_hist_title.setStyleSheet("color:#cbd5e1;font-size:12px;font-weight:700;")
        hist_hdr.addWidget(self.lbl_hist_title)

        hist_hdr.addStretch()

        self.btn_hist_toggle = QPushButton("By flows")
        self.btn_hist_toggle.setFixedHeight(28)
        self.btn_hist_toggle.clicked.connect(self._on_toggle_hist_mode)
        hist_hdr.addWidget(self.btn_hist_toggle)

        al.addLayout(hist_hdr)

        self.hist24 = MiniHistogram24Widget()
        self.hist24.hourClicked.connect(self._on_hist_hour_clicked)
        self._hour_filter: int | None = None
        al.addWidget(self.hist24)

        # OUT vs IN text
        self.lbl_dir_text = QLabel("")
        self.lbl_dir_text.setTextFormat(Qt.RichText)
        self.lbl_dir_text.setWordWrap(True)
        self.lbl_dir_text.setStyleSheet("color:#cbd5e1;")
        al.addWidget(self.lbl_dir_text)

        # OUT vs IN bar widget
        self.dir_bar = DirectionBarWidget()
        al.addWidget(self.dir_bar)    

        rp.addWidget(self.analyst_card)

        # Insights card
        insights_card = QFrame()
        insights_card.setObjectName("Card")
        il = QVBoxLayout(insights_card)
        il.setContentsMargins(14, 12, 14, 12)
        il.setSpacing(10)

        hdr = QHBoxLayout()
        lbl_ins = QLabel("Insights (Top 15)")
        lbl_ins.setStyleSheet("font-size:14px;font-weight:900;color:#f8fafc;")
        hdr.addWidget(lbl_ins)
        hdr.addStretch()
        il.addLayout(hdr)

        self.ins_tabs = QTabWidget()
        self.ins_tabs.setDocumentMode(True)

        self._tab_defs: list[tuple[str, str, tuple[str, str]]] = [
            ("Top Src", "top_src", ("IP", "Count")),
            ("Top Dst", "top_dst", ("IP", "Count")),
            ("Protocols", "top_proto", ("Protocol", "Count")),
            ("Apps", "top_app", ("App", "Count")),
            ("Dates", "top_date", ("Date", "Count")),
            ("Hours", "top_hour", ("Hour", "Count")),
            ("Bytes Src", "top_bytes_src", ("Source", "Bytes")),
            ("Bytes Dst", "top_bytes_dst", ("Destination", "Bytes")),
            ("Bytes App", "top_bytes_app", ("App", "Bytes")),
        ]

        for title, _key, _hdrs in self._tab_defs:
            self.ins_tabs.addTab(QWidget(), title)

        self.ins_tabs.currentChanged.connect(self._on_insight_tab_changed)
        il.addWidget(self.ins_tabs)

        # Insights table
        self.pairs_model = PairsModel()
        self.pairs_view = QTableView()
        self.pairs_view.setModel(self.pairs_model)
        self.pairs_view.setAlternatingRowColors(True)
        self.pairs_view.verticalHeader().setVisible(False)
        self.pairs_view.horizontalHeader().setStretchLastSection(True)
        self.pairs_view.setSelectionBehavior(QTableView.SelectRows)
        self.pairs_view.setSelectionMode(QTableView.SingleSelection)

        # show all rows in the table itself; page scrolls instead
        self.pairs_view.setVerticalScrollBarPolicy(Qt.ScrollBarAlwaysOff)

        il.addWidget(self.pairs_view)
        self.pairs_view.doubleClicked.connect(self._on_insight_double_clicked)
        rp.addWidget(insights_card)

        # Note
        note = QFrame()
        note.setObjectName("Card")
        nl = QVBoxLayout(note)
        nl.setContentsMargins(14, 12, 14, 12)
        nl.setSpacing(6)

        lbl = QLabel("Note")
        lbl.setStyleSheet("font-size:14px;font-weight:900;color:#f8fafc;")
        nl.addWidget(lbl)

        self.txt_note = QLabel(
            "Passive analysis only. Findings are indicative and based on metadata "
            "(IP, protocol, app, timing, volume)."
        )
        self.txt_note.setStyleSheet("color:#cbd5e1;")
        self.txt_note.setWordWrap(True)
        nl.addWidget(self.txt_note)

        rp.addWidget(note)
        rp.addStretch()

        # ---------------- Dataset content ----------------
        top = QHBoxLayout()
        lbl_full = QLabel("Full dataset")
        lbl_full.setStyleSheet("font-size:14px;font-weight:900;color:#f8fafc;")

        self.lbl_full_hint = QLabel("")
        self.lbl_full_hint.setObjectName("Muted")
        self.lbl_full_hint.setAlignment(Qt.AlignRight | Qt.AlignVCenter)

        top.addWidget(lbl_full)
        top.addStretch()
        top.addWidget(self.lbl_full_hint)
        dp.addLayout(top)

        self.lbl_dataset_disabled = QLabel(
            "Dataset view is hidden. Enable “Include full dataset” to show the full dataset table."
        )
        self.lbl_dataset_disabled.setObjectName("Muted")
        self.lbl_dataset_disabled.setWordWrap(True)
        dp.addWidget(self.lbl_dataset_disabled)

        self.table = QTableView()
        self.table.setSortingEnabled(False)
        self.table.setAlternatingRowColors(True)
        self.table.setSelectionBehavior(QTableView.SelectRows)
        self.table.setSelectionMode(QTableView.SingleSelection)
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.verticalHeader().setVisible(False)
        self.table.setWordWrap(False)

        self.model = RegistryTableModel()
        self.proxy = TextFilterProxy()
        self.proxy.setSourceModel(self.model)
        self.table.setModel(self.proxy)
        self.table.doubleClicked.connect(self._on_dataset_double_clicked)

        self.txt_search.textChanged.connect(self.proxy.set_query)
        dp.addWidget(self.table, 1)

        # initial states
        self._hist_mode = "bytes"
        self._hour_filter = None
        self._last_activity = {}
        self.btn_export.setEnabled(False)
        self.model.set_data([], [])
        self._render_empty()
        self._on_toggle_full(self.chk_full.isChecked())

    # ----------------- UI helpers -----------------
    def _make_stat_card(self, title: str, value: str) -> QFrame:
        card = QFrame()
        card.setObjectName("Card")
        card.setFixedHeight(84)
        l = QVBoxLayout(card)
        l.setContentsMargins(14, 12, 14, 12)
        l.setSpacing(2)

        t = QLabel(title)
        t.setObjectName("Muted")
        t.setStyleSheet("font-size:12px;")

        v = QLabel(value)
        v.setStyleSheet("font-size:22px;font-weight:900;color:#f8fafc;")
        v.setProperty("stat_value", True)

        l.addWidget(t)
        l.addWidget(v)
        return card

    def _set_stat(self, card: QFrame, value: str):
        for w in card.findChildren(QLabel):
            if w.property("stat_value"):
                w.setText(value)
                return

    # ----------------- public API -----------------
    def set_dataset(self,
        folder: str | Path,
        files: list[Path],
        flows: list[dict[str, Any]],
        compare_result: dict[str, Any] | None = None,
    ):
        self._folder = Path(folder)
        self._files = files or []
        self._flows = flows or []
        self._compare_result = compare_result or None
        self._meta = {}
        if self._files:
            try:
                self._meta = extract_dataset_meta(self._files[0])
            except Exception:
                self._meta = {}

        self._summary = compute_registry_summary(self._flows, top_n=15)
        self._analyst = compute_analyst_summary(self._flows, self._meta)
        self._hist_mode = "bytes"
        self._last_activity = {}

        # build visible columns BEFORE adding internal cache keys
        self._cols = build_registry_columns(self._flows)

        # cache local hour once per flow for fast UI filtering
        for f in self._flows:
            if not isinstance(f, dict):
                continue
            dt = parse_flow_timestamp(f)
            f["_cv_hour"] = int(dt.hour) if dt is not None else -1

        self.model.set_data(self._flows, self._cols)

        self._render_meta()
        self._render_stats()
        self._render_analyst()
        self._render_full_hint()
        self._render_insight_current()

        self.btn_export.setEnabled(bool(self._flows))
        self.table.horizontalHeader().setStretchLastSection(True)

    # ----------------- rendering -----------------
    def _render_empty(self):
        self.lbl_folder.setText("No dataset loaded.")
        self.lbl_meta_chips.setText("")
        self.lbl_right_hint.setText("")
        self.lbl_full_hint.setText("")
        self._set_stat(self.card_total, "—")
        self._set_stat(self.card_usrc, "—")
        self._set_stat(self.card_udst, "—")
        self._set_stat(self.card_uapps, "—")
        self._set_stat(self.card_bytes, "—")
        self.pairs_model.set_rows([], headers=("Item", "Value"))
        self._fit_pairs_height(0)
        self.lbl_deviation.setText("Behavior deviation: —")
        self.deviation_bar.setValue(0)
        self.lbl_analyst_body.setText("")
        self.lbl_day_section.setText("")
        self.lbl_activity_text.setText("")
        self.lbl_dir_text.setText("")
        self.dir_bar.set_pcts(0.0, 0.0)

        self._hist_mode = "bytes"
        self._hour_filter = None
        self._last_activity = {}
        self.hist24.set_mode("bytes")
        self.hist24.set_quiet_hours([])
        self.hist24.set_values([0] * 24)

        self.lbl_dataset_disabled.setVisible(True)
        self.table.setVisible(False)
        self._compare_result = None

    def _render_meta(self):
        if not self._folder:
            self._render_empty()
            return

        self.lbl_folder.setText(str(self._folder))
        self.lbl_right_hint.setText(f"JSON files: {len(self._files)}")

        urbroj = str(self._meta.get("RegNo") or "")
        klasa = str(self._meta.get("OrigRegNo") or "")
        target = str(self._meta.get("target") or "")
        targettype = str(self._meta.get("targettype") or "")
        liid = str(self._meta.get("liid") or "")
        bt = str(self._meta.get("bt") or "")
        et = str(self._meta.get("et") or "")

        def chip(label: str, value: str) -> str:
            vv = _esc(value or "—")
            ll = _esc(label)
            return (
                "<span style="
                "'display:inline-block;margin:0 10px 8px 0;"
                "padding:6px 10px;border-radius:999px;"
                "background:#334155;border:1px solid #475569;"
                "color:#cbd5e1;font-size:12px;'>"
                f"<b style='color:#f8fafc;'>{ll}:</b> {vv}"
                "</span>"
            )

        chips = [
            chip("Klasa", klasa),
            chip("Urbroj", urbroj),
            chip("Target", f"{target} ({targettype})" if target or targettype else "—"),
            chip("LIID", liid),
        ]
        if bt or et:
            chips.append(chip("Period", f"{_fmt_dt_short(bt)} → {_fmt_dt_short(et)}"))

        self.lbl_meta_chips.setText("".join(chips))

    def _render_stats(self):
        s = self._summary or {}
        total_flows = _safe_int(s.get("total_flows", len(self._flows)))

        uniq_src = len({str(f.get("src_ip") or "") for f in self._flows if f.get("src_ip")})
        uniq_dst = len({str(f.get("dst_ip") or "") for f in self._flows if f.get("dst_ip")})
        uniq_apps = len({str(f.get("application_name") or "") for f in self._flows if f.get("application_name")})

        total_bytes = s.get("total_bytes", None)
        if total_bytes is None:
            total_bytes = sum(_safe_int(f.get("bidirectional_bytes")) for f in self._flows)

        self._set_stat(self.card_total, str(total_flows))
        self._set_stat(self.card_usrc, str(uniq_src))
        self._set_stat(self.card_udst, str(uniq_dst))
        self._set_stat(self.card_uapps, str(uniq_apps))
        self._set_stat(self.card_bytes, _human_bytes(total_bytes))    

    def _render_analyst(self):
        a = self._analyst or {}
        if not a:
            self.lbl_risk.setText("Behavior deviation: —")
            self.risk_bar.setValue(0)
            self.lbl_analyst_body.setText("No analyst summary available.")
            self.lbl_day_section.setText("")
            self.lbl_activity_text.setText("")
            self.lbl_dir_text.setText("")
            self.dir_bar.set_pcts(0.0, 0.0)
            self._last_activity = {}
            self.pairs_model.set_rows([], headers=("Item", "Value"))
            self._fit_pairs_height(0)

            self._hist_mode = "bytes"
            self._hour_filter = None
            self._last_activity = {}
            self.hist24.set_mode("bytes")
            self.hist24.set_quiet_hours([])
            self.hist24.set_values([0] * 24)
            return

        # ---- behavior deviation ----
        deviation = a.get("behavior_deviation", {}) or {}
        score = int(deviation.get("score", 0) or 0)
        level = str(deviation.get("level", "LOW") or "LOW")
        reasons = list(deviation.get("reasons", []) or [])

        self.lbl_deviation.setText(f"Behavior deviation: {score}/100 ({level})")
        self.deviation_bar.setValue(max(0, min(100, score)))

        # ---- dominant app ----
        cov = a.get("coverage", {}) or {}
        dom = a.get("dominant_app", {}) or {}

        active_days = int(cov.get("active_days", 0) or 0)
        active_days_pct = float(cov.get("active_days_pct", 0.0) or 0.0)
        avg_flows_per_active_day = float(cov.get("avg_flows_per_active_day", 0.0) or 0.0)
        pattern = str(cov.get("pattern", "unknown") or "unknown")
        duration_days = cov.get("duration_days", None)
        bt = str(cov.get("bt", "") or "")
        et = str(cov.get("et", "") or "")

        dom_b = (dom.get("by_bytes", {}) or {})
        dom_c = (dom.get("by_count", {}) or {})
        dom_text = (
            f"<b>Dominant app:</b> {html.escape(str(dom_b.get('name','—')))} "
            f"({float(dom_b.get('share_pct',0.0)):.1f}% bytes) "
            f"<span style='color:#94a3b8'>(count: {html.escape(str(dom_c.get('name','—')))}, "
            f"{float(dom_c.get('share_pct',0.0)):.1f}%)</span>"
        )

        # ---- bytes direction ----
        bytes_s = a.get("bytes", {}) or {}
        out_share = float(bytes_s.get("outbound_share_total_pct", 0.0) or 0.0)

        dirb = bytes_s.get("direction_bar", {}) or {}
        out_b = _human_bytes(dirb.get("outbound_bytes", 0))
        in_b = _human_bytes(dirb.get("inbound_bytes", 0))
        out_p = float(dirb.get("outbound_bytes_pct", 0.0) or 0.0)
        in_p = float(dirb.get("inbound_bytes_pct", 0.0) or 0.0)

        # ---- dominance ----
        domn = a.get("dominance", {}) or {}
        top_out = (domn.get("top_internal_outbound", {}) or {})
        top_dst = (domn.get("top_destination_outbound", {}) or {})

        # ---- activity ----
        act = a.get("activity", {}) or {}
        day_hist = act.get("day_hist", {}) or {}
        day_bytes = act.get("day_bytes", {}) or {}
        peak = act.get("peak_hour", None)
        quiet = act.get("quiet_hour", None)
        night = float(act.get("night_share_pct", 0.0) or 0.0)
        business = float(act.get("business_share_pct", 0.0) or 0.0)

        def hfmt(h):
            return "—" if h is None else f"{int(h):02d}:00"

        # ---- body text ----
        coverage_parts = [f"{int(cov.get('total_flows', 0) or 0)} flows"]

        if bt and et:
            coverage_parts.append(f"{_fmt_dt_short(bt)} → {_fmt_dt_short(et)}")

        if duration_days is not None:
            coverage_parts.append(f"{float(duration_days):.1f} days")

        if active_days > 0:
            coverage_parts.append(f"{active_days} active days")

        if active_days_pct > 0:
            coverage_parts.append(f"{active_days_pct:.1f}% active")

        if avg_flows_per_active_day > 0:
            coverage_parts.append(f"{avg_flows_per_active_day:.1f} flows/day")

        coverage_parts.append(f"pattern: {html.escape(pattern)}")

        if reasons:
            rs = "".join(f"<li>{html.escape(str(r))}</li>" for r in reasons[:3])
            reasons_html = f"<b>Top deviation signals:</b><ul style='margin:4px 0 6px 18px;'>{rs}</ul>"
        else:
            reasons_html = "<b>Top deviation signals:</b> —"

        coverage_html = (
            f"<b>Coverage:</b> " + " | ".join(coverage_parts) + " | "
            f"<b>Outbound share:</b> {out_share:.1f}%"
        )

        dominance_html = (
            f"<b>Top internal (outbound):</b> {html.escape(str(top_out.get('ip','—')))} "
            f"({float(top_out.get('share_of_outbound_pct',0.0)):.1f}%) &nbsp;&nbsp; "
            f"<b>Top dst (outbound):</b> {html.escape(str(top_dst.get('ip','—')))} "
            f"({float(top_dst.get('share_of_outbound_pct',0.0)):.1f}%)"
        )

        compare_html = ""
        cmp = self._compare_result or {}
        if cmp:
            current_unique = int(cmp.get("total_current", 0) or 0)
            previous_unique = int(cmp.get("total_previous", 0) or 0)
            new_count = len(cmp.get("new", []) or [])
            known_count = len(cmp.get("known", []) or [])

            compare_html = (
                f"<b>Dataset compare:</b> "
                f"current {current_unique} unique flows | "
                f"previous {previous_unique} unique flows | "
                f"new {new_count} | "
                f"known {known_count}<br>"
            )

        novelty_html = ""

        if cmp and cmp.get("summary_new"):
            sn = cmp["summary_new"]

            apps = sn.get("new_apps", [])
            dsts = sn.get("new_dst_ips", [])
            domains = sn.get("new_sni", [])

            novelty_html = "<br><b>New indicators:</b><br>"

            if apps:
                novelty_html += f"• Apps: {', '.join(str(x) for x in apps[:5])}"
                if len(apps) > 5:
                    novelty_html += " ..."
                novelty_html += "<br>"

            if domains:
                novelty_html += f"• Domains: {', '.join(str(x) for x in domains[:5])}"
                if len(domains) > 5:
                    novelty_html += " ..."
                novelty_html += "<br>"

            if dsts:
                novelty_html += f"• Dest IPs: {', '.join(str(x) for x in dsts[:5])}"
                if len(dsts) > 5:
                    novelty_html += " ..."
                novelty_html += "<br>"
        analyst_html = (
            f"{reasons_html}"
            f"{coverage_html}<br>"
            f"{compare_html}"
            f"{novelty_html}"
            f"{dom_text}<br>"
            f"{dominance_html}"
        )

        self.lbl_analyst_body.setText(analyst_html)

        recent_html = _day_activity_html(day_hist, day_bytes)
        top_html = _top_active_days_html(day_hist, day_bytes)

        day_section = (
            "<div style='margin-top:10px;'>"
            "<table style='width:100%;border-collapse:collapse;' cellspacing='0' cellpadding='0'>"
            "<tr>"
            "<td style='width:50%;vertical-align:top;padding-right:8px;'>"
            "<div style='font-weight:700;color:#f8fafc;margin-bottom:6px;'>Activity by day</div>"
            f"{recent_html}"
            "</td>"
            "<td style='width:50%;vertical-align:top;padding-left:8px;'>"
            "<div style='font-weight:700;color:#f8fafc;margin-bottom:6px;'>Top active days</div>"
            f"{top_html}"
            "</td>"
            "</tr>"
            "</table>"
            "</div>"
        )

        self.lbl_day_section.setText(day_section)

        self.lbl_activity_text.setText(
            "<div style='margin-top:6px;'>"
            f"<b>Activity:</b> peak {hfmt(peak)}, quiet {hfmt(quiet)} | "
            f"night {night:.1f}%, business {business:.1f}%"
            "</div>"
        )

        # ---- OUT vs IN ----
        self.lbl_dir_text.setText(
            f"<b>OUT vs IN:</b> OUT {html.escape(out_b)} ({out_p:.1f}%) &nbsp;|&nbsp; "
            f"IN {html.escape(in_b)} ({in_p:.1f}%)"
        )
        self.dir_bar.set_pcts(out_p, in_p)

        # ---- cache activity + apply histogram mode ----
        self._last_activity = act

        # button text: show what happen's on click
        self.btn_hist_toggle.setText("By bytes" if self._hist_mode == "flows" else "By flows")

        self._apply_hist_mode()

    def _on_hist_hour_clicked(self, hour: int):
        # toggle
        h = int(hour)
        if self._hour_filter == h:
            self._hour_filter = None
        else:
            self._hour_filter = h

        # ensure dataset is visible
        if self._hour_filter is not None and not self.chk_full.isChecked():
            self.chk_full.setChecked(True)

        # apply filter
        self.proxy.set_hour_filter(self._hour_filter)

        # switch to Dataset tab when selecting an hour
        if self._hour_filter is not None:
            self.main_tabs.setCurrentIndex(1)  # Dataset

        # update hint text (rows/cols + optional filter)
        self._render_full_hint()

    def _on_toggle_hist_mode(self):
        self._hist_mode = "flows" if self._hist_mode == "bytes" else "bytes"
        self.btn_hist_toggle.setText("By bytes" if self._hist_mode == "flows" else "By flows")
        self._apply_hist_mode()

    def _apply_hist_mode(self):
        act = self._last_activity or {}

        if self._hist_mode == "flows":
            self.lbl_hist_title.setText("Activity by flows")
            hh = act.get("hour_hist_24") or act.get("hour_hist") or [0] * 24
            self.hist24.set_mode("flows")
        else:
            self.lbl_hist_title.setText("Activity by bytes")
            hh = act.get("hour_bytes_24") or act.get("hour_bytes") or [0] * 24
            self.hist24.set_mode("bytes")

        if not isinstance(hh, list) or len(hh) != 24:
            hh = [0] * 24

        # quiet band: low ~20% not null hours
        vals = [int(v or 0) for v in hh]
        nonzero = sorted(v for v in vals if v > 0)

        quiet_hours: list[int] = []
        if nonzero:
            idx = int(0.20 * (len(nonzero) - 1))
            thr = nonzero[idx]
            quiet_hours = [i for i, v in enumerate(vals) if 0 < v <= thr]

        self.hist24.set_quiet_hours(quiet_hours)
        self.hist24.set_values(hh)
    
    def _render_full_hint(self):
        total = len(self._flows)
        try:
            shown = self.proxy.rowCount()
        except Exception:
            shown = total

        base = f"Rows: {shown}/{total}  |  Columns: {len(self._cols)}"
        if getattr(self, "_hour_filter", None) is not None:
            base += f"  |  Hour filter: {int(self._hour_filter):02d}:00"
        self.lbl_full_hint.setText(base)

    def _on_toggle_full(self, checked: bool):
        # Dataset tab is ALWAYS clickable; this only controls its content + export include_full.
        self.lbl_dataset_disabled.setVisible(not checked)
        self.table.setVisible(checked)
        self._render_full_hint()

    # ----------------- insights -----------------
    def _on_insight_tab_changed(self, _idx: int):
        self._render_insight_current()

    def _render_insight_current(self):
        if not self._summary:
            self.pairs_model.set_rows([], headers=("Item", "Value"))
            self._fit_pairs_height(0)
            return

        idx = self.ins_tabs.currentIndex()
        if idx < 0 or idx >= len(self._tab_defs):
            self.pairs_model.set_rows([], headers=("Item", "Value"))
            self._fit_pairs_height(0)
            return

        _title, key, hdrs = self._tab_defs[idx]
        rows = list(self._summary.get(key, []) or [])[:15]
        if key == "top_proto":
            rows = [(format_ip_proto(k), v) for (k, v) in rows]
        self.pairs_model.set_rows(rows, headers=hdrs)

        # ergonomics
        self.pairs_view.setColumnWidth(0, 620)
        self.pairs_view.setColumnWidth(1, 180)

        self._fit_pairs_height(len(rows))

    def _fit_pairs_height(self, n_rows: int):
        header_h = self.pairs_view.horizontalHeader().height()
        if header_h <= 0:
            header_h = 34

        if n_rows <= 0:
            self.pairs_view.setFixedHeight(header_h + 14)
            return

        rh = self.pairs_view.verticalHeader().defaultSectionSize()
        if rh <= 0:
            rh = 28

        show = max(1, min(15, n_rows))
        h = header_h + (rh * show) + 14
        self.pairs_view.setFixedHeight(h)

    # ----------------- export -----------------
    def export_report(self):
        if not self._folder or not self._flows:
            return

        default_name = "ViaNyquist_Registry_Report.html"
        out_path, _ = QFileDialog.getSaveFileName(
            self,
            "Export report",
            str(self._folder / default_name),
            "HTML (*.html)"
        )

        if not out_path:
            return

        try:
            export_registry_html(
                file_path=out_path,
                folder=self._folder,
                files=self._files,
                flows=self._flows,
                meta=self._meta,
                summary=self._summary,
                analyst=self._analyst,
                columns=self._cols,
                tab_defs=self._tab_defs,
                compare_result=self._compare_result,
                include_full=bool(self.chk_full.isChecked()),
            )

            QMessageBox.information(self, "Export", f"Report saved:\n{out_path}")

        except Exception as e:
            QMessageBox.critical(self, "Export failed", str(e))

    def _build_html_report(self, *, include_full: bool) -> str:
        urbroj = str(self._meta.get("RegNo") or "")
        klasa = str(self._meta.get("OrigRegNo") or "")
        target = str(self._meta.get("target") or "")
        targettype = str(self._meta.get("targettype") or "")
        liid = str(self._meta.get("liid") or "")
        bt = str(self._meta.get("bt") or "")
        et = str(self._meta.get("et") or "")

        s = self._summary or {}
        total_flows = _safe_int(s.get("total_flows", len(self._flows)))
        uniq_src = len({str(f.get("src_ip") or "") for f in self._flows if f.get("src_ip")})
        uniq_dst = len({str(f.get("dst_ip") or "") for f in self._flows if f.get("dst_ip")})
        uniq_apps = len({str(f.get("application_name") or "") for f in self._flows if f.get("application_name")})

        total_bytes = s.get("total_bytes", None)
        if total_bytes is None:
            total_bytes = sum(_safe_int(f.get("bidirectional_bytes")) for f in self._flows)

        a = self._analyst or {}

        deviation = a.get("behavior_deviation", {}) or {}
        score = int(deviation.get("score", 0) or 0)
        level = str(deviation.get("level", "LOW") or "LOW")
        reasons = list(deviation.get("reasons", []) or [])

        cov = a.get("coverage", {}) or {}
        active_days = int(cov.get("active_days", 0) or 0)
        active_days_pct = float(cov.get("active_days_pct", 0.0) or 0.0)
        avg_flows_per_active_day = float(cov.get("avg_flows_per_active_day", 0.0) or 0.0)
        pattern = str(cov.get("pattern", "unknown") or "unknown")
        duration_days = cov.get("duration_days", None)
        bt_cov = str(cov.get("bt", "") or "")
        et_cov = str(cov.get("et", "") or "")

        dom = a.get("dominant_app", {}) or {}
        dom_b = (dom.get("by_bytes", {}) or {})
        dom_c = (dom.get("by_count", {}) or {})

        bytes_s = a.get("bytes", {}) or {}
        out_share = float(bytes_s.get("outbound_share_total_pct", 0.0) or 0.0)

        dirb = bytes_s.get("direction_bar", {}) or {}
        out_b = _human_bytes(dirb.get("outbound_bytes", 0))
        in_b = _human_bytes(dirb.get("inbound_bytes", 0))
        out_p = float(dirb.get("outbound_bytes_pct", 0.0) or 0.0)
        in_p = float(dirb.get("inbound_bytes_pct", 0.0) or 0.0)

        domn = a.get("dominance", {}) or {}
        top_out = (domn.get("top_internal_outbound", {}) or {})
        top_dst = (domn.get("top_destination_outbound", {}) or {})

        act = a.get("activity", {}) or {}
        peak = act.get("peak_hour", None)
        quiet = act.get("quiet_hour", None)
        night = float(act.get("night_share_pct", 0.0) or 0.0)
        business = float(act.get("business_share_pct", 0.0) or 0.0)
        day_hist = act.get("day_hist", {}) or {}
        day_bytes = act.get("day_bytes", {}) or {}

        hour_bytes = act.get("hour_bytes_24") or act.get("hour_bytes") or [0] * 24
        if not isinstance(hour_bytes, list) or len(hour_bytes) != 24:
            hour_bytes = [0] * 24

        hour_flows = act.get("hour_hist_24") or act.get("hour_hist") or [0] * 24
        if not isinstance(hour_flows, list) or len(hour_flows) != 24:
            hour_flows = [0] * 24

        def hfmt(h):
            return "—" if h is None else f"{int(h):02d}:00"

        def table_rows(items: list[tuple[Any, Any]]) -> str:
            out = []
            for k, v in (items or [])[:15]:
                out.append(f"<tr><td>{_esc(k)}</td><td class='num'>{_esc(v)}</td></tr>")
            return "\n".join(out)

        def section_card(title: str, items: list[tuple[Any, Any]], col1: str, col2: str) -> str:
            return f"""
            <div class="card">
              <h3>{_esc(title)}</h3>
              <table>
                <thead>
                  <tr>
                    <th>{_esc(col1)}</th>
                    <th class="num">{_esc(col2)}</th>
                  </tr>
                </thead>
                <tbody>
                  {table_rows(items)}
                </tbody>
              </table>
            </div>
            """

        reasons_html = "".join(f"<li>{_esc(r)}</li>" for r in reasons[:5]) if reasons else "<li>—</li>"
        coverage_parts = [f"{int(cov.get('total_flows', 0) or 0)} flows"]

        if bt_cov and et_cov:
            coverage_parts.append(f"{_fmt_dt_short(bt_cov)} → {_fmt_dt_short(et_cov)}")

        if duration_days is not None:
            coverage_parts.append(f"{float(duration_days):.1f} days")

        if active_days > 0:
            coverage_parts.append(f"{active_days} active days")

        if active_days_pct > 0:
            coverage_parts.append(f"{active_days_pct:.1f}% active")

        if avg_flows_per_active_day > 0:
            coverage_parts.append(f"{avg_flows_per_active_day:.1f} flows/day")

        coverage_parts.append(f"pattern: {_esc(pattern)}")

        coverage_html = " | ".join(coverage_parts)

        dom_text = (
            f"<strong>Dominant app:</strong> {_esc(dom_b.get('name', '—'))} "
            f"({float(dom_b.get('share_pct', 0.0)):.1f}% bytes) "
            f"<span style='color:#6b7280'>(count: {_esc(dom_c.get('name', '—'))}, "
            f"{float(dom_c.get('share_pct', 0.0)):.1f}%)</span>"
        )

        dominance_html = (
            f"<strong>Top internal (outbound):</strong> {_esc(top_out.get('ip', '—'))} "
            f"({float(top_out.get('share_of_outbound_pct', 0.0)):.1f}%) &nbsp;&nbsp; "
            f"<strong>Top dst (outbound):</strong> {_esc(top_dst.get('ip', '—'))} "
            f"({float(top_dst.get('share_of_outbound_pct', 0.0)):.1f}%)"
        )

        activity_line_html = (
            f"<strong>Activity:</strong> peak {_esc(hfmt(peak))}, quiet {_esc(hfmt(quiet))} | "
            f"night {night:.1f}%, business {business:.1f}%"
        )

        recent_days_html = _day_activity_html(day_hist, day_bytes)
        top_days_html = _top_active_days_html(day_hist, day_bytes)

        analyst_html = f"""
        <div class="card analyst">
          <h2>Analyst Summary</h2>

        <div class="analyst-risk">
            <div class="risk-line">
              <span><strong>Behavior deviation:</strong> {_esc(score)}/100 ({_esc(level)})</span>
            </div>
            <div class="risk-bar-wrap">
              <div class="risk-bar-fill" style="width:{max(0, min(100, score))}%;"></div>
            </div>
          </div>

            <div class="section-block compact-top">
            <p><strong>Top deviation signals:</strong></p>
            <ul class="reasons-list">
              {reasons_html}
            </ul>
          </div>

          <div class="section-block compact">
            <p><strong>Coverage:</strong> {coverage_html} | <strong>Outbound share:</strong> {out_share:.1f}%</p>
          </div>

          <div class="section-block compact">
            <p>{dom_text}</p>
          </div>

          <div class="section-block compact">
            <p>{dominance_html}</p>
          </div>

          <div class="section-block compact day-split">
            <div class="day-col">
              <div class="mini-title">Activity by day</div>
              {recent_days_html}
            </div>
            <div class="day-col">
              <div class="mini-title">Top active days</div>
              {top_days_html}
            </div>
          </div>

          <div class="section-block compact">
            <p>{activity_line_html}</p>
          </div>

        <div class="section-block compact">
            <div class="hist-head">
              <p><strong>Activity by bytes</strong></p>
              <span class="hist-note">Same as Registry view</span>
            </div>
            {_mini_hist_24_html(hour_bytes, height_px=18)}
          </div>

          <div class="section-block compact">
            <div class="hist-head">
              <p><strong>Activity by flows</strong></p>
              <span class="hist-note">Same as Registry view</span>
            </div>
            {_mini_hist_24_html(hour_flows, height_px=18)}
          </div>

          <div class="section-block compact">
            <p><strong>OUT vs IN:</strong> OUT {_esc(out_b)} ({out_p:.1f}%) &nbsp;|&nbsp; IN {_esc(in_b)} ({in_p:.1f}%)</p>
            {_direction_bar_html(out_p, in_p, width_px=320, height_px=10)}
          </div>
        </div>
        """

        cards = []
        for title, key, hdrs in self._tab_defs:
            items = s.get(key, []) or []
            if key == "top_proto":
                items = [(format_ip_proto(k), v) for (k, v) in items]
            cards.append(section_card(title, items, hdrs[0], hdrs[1]))

        full_table_html = ""
        if include_full and self._cols:
            thead = "".join(f"<th>{_esc(c)}</th>" for c in self._cols)
            body_rows = []

            for row in self._flows:
                tds = []
                for c in self._cols:
                    v = row.get(c, "")
                    if c == "protocol":
                        v = format_ip_proto(v)
                    tds.append(f"<td>{_esc(v)}</td>")
                body_rows.append("<tr>" + "".join(tds) + "</tr>")

            tbody = "\n".join(body_rows)

            full_table_html = f"""
            <details open class="details">
              <summary>Full dataset (rows: {len(self._flows)}, cols: {len(self._cols)})</summary>
              <div class="tablewrap">
                <table class="full">
                  <thead><tr>{thead}</tr></thead>
                  <tbody>{tbody}</tbody>
                </table>
              </div>
            </details>
            """

        css = """
        :root{
          --bg:#f9fafb;
          --card:#ffffff;
          --border:#e5e7eb;
          --muted:#6b7280;
          --text:#111827;
          --soft:#f3f4f6;
        }

        body{
          font-family:Inter, Segoe UI, Arial, sans-serif;
          font-size:14px;
          line-height:1.5;
          margin:32px;
          background:var(--bg);
          color:var(--text);
        }

        .page{
          max-width:1100px;
          margin:0 auto;
          background:var(--card);
          border:1px solid var(--border);
          border-radius:16px;
          padding:28px;
        }

        h1{
          margin:0 0 6px 0;
          font-size:28px;
          line-height:1.2;
          font-weight:800;
        }

        h2{
          margin:0 0 12px 0;
          font-size:20px;
          line-height:1.3;
          font-weight:700;
        }

        h3{
          margin:0 0 10px 0;
          font-size:16px;
          line-height:1.3;
          font-weight:700;
        }

        p, li, td, th, summary, .sub, .chip, .footer{
          font-size:14px;
          line-height:1.5;
        }

        .sub{
          color:var(--muted);
          margin-bottom:8px;
        }

        .chips{
          display:flex;
          gap:10px;
          flex-wrap:wrap;
          margin:14px 0 20px 0;
        }

        .chip{
          background:var(--soft);
          border:1px solid var(--border);
          border-radius:999px;
          padding:6px 10px;
          color:#cbd5e1;
        }

        .chip b{
          color:var(--text);
        }

        .stats{
          display:grid;
          grid-template-columns:repeat(5,1fr);
          gap:12px;
          margin:12px 0 18px 0;
        }

        .stat{
          border:1px solid var(--border);
          border-radius:14px;
          padding:12px;
        }

        .stat .t{
          color:var(--muted);
          font-size:12px;
          line-height:1.4;
          margin-bottom:4px;
        }

        .stat .v{
          font-size:20px;
          line-height:1.2;
          font-weight:800;
        }

        .card{
          border:1px solid var(--border);
          border-radius:14px;
          padding:14px;
          background:#fff;
        }

        .grid{
          display:grid;
          grid-template-columns:repeat(3,1fr);
          gap:14px;
          margin-top:18px;
        }

        table{
          width:100%;
          border-collapse:collapse;
        }

        th, td{
          border-top:1px solid var(--border);
          padding:8px 6px;
          text-align:left;
          vertical-align:top;
        }

        th{
          background:#fafafa;
          color:#374151;
          font-weight:700;
        }

        th.num, td.num{
          text-align:center;
          font-variant-numeric:tabular-nums;
        }

        .analyst{
          margin:18px 0;
        }

        .analyst-grid{
          display:grid;
          grid-template-columns:1fr 1fr;
          gap:18px;
          margin-top:12px;
        }

        .info-block p{
          margin:0 0 8px 0;
          color:#374151;
        }

        .section-block{
          margin-top:14px;
        }

        .section-block.compact{
          margin-top:10px;
        }

        .section-block.compact-top{
          margin-top:12px;
        }

        .section-block p{
          margin:0 0 8px 0;
          color:#374151;
        }

        .mini-title{
          font-weight:700;
          color:#111827;
          margin-bottom:6px;
        }

        .day-split{
          display:grid;
          grid-template-columns:1fr 1fr;
          gap:16px;
          align-items:start;
        }

        .day-col{
          min-width:0;
        }

        .hist-head{
          display:flex;
          align-items:center;
          justify-content:space-between;
          gap:12px;
          margin-bottom:6px;
        }

        .hist-head p{
          margin:0;
        }

        .hist-note{
          color:#6b7280;
          font-size:12px;
        }

        .analyst-risk{
          margin-top:8px;
        }

        .risk-line{
          margin-bottom:8px;
          color:#111827;
          font-weight:700;
        }

        .risk-bar-wrap{
          width:100%;
          height:16px;
          background:#f3f4f6;
          border:1px solid #e5e7eb;
          border-radius:999px;
          overflow:hidden;
        }

        .risk-bar-fill{
          height:100%;
          background:#111827;
          border-radius:999px;
        }

        .reasons-list{
          margin:6px 0 0 18px;
          padding:0;
          color:#374151;
        }

        .note{
          margin-top:18px;
        }

        .note p{
          white-space:pre-wrap;
          color:#374151;
          margin:0;
        }

        .details{
          margin-top:16px;
          border:1px solid var(--border);
          border-radius:14px;
          padding:12px;
          background:#fff;
        }

        .details summary{
          cursor:pointer;
          font-weight:700;
          color:#111827;
        }

        .tablewrap{
          overflow:auto;
          margin-top:10px;
          border-radius:12px;
          border:1px solid var(--border);
        }

        table.full{
          min-width:1100px;
        }

        .footer{
          margin-top:18px;
          color:var(--muted);
        }

        @media (max-width:1100px){
          .stats{grid-template-columns:repeat(2,1fr);}
          .grid{grid-template-columns:1fr;}
          .analyst-grid{grid-template-columns:1fr;}
          .day-split{grid-template-columns:1fr;}
        }
        """

        prefilled_text = """
Izvješće je izrađeno temeljem pasivne analize mrežnih tokova.
Zaključci su indikativni i temelje se na metapodacima (IP, protokoli, aplikacije, vrijeme, volumen).
""".strip()

        folder_txt = _esc(str(self._folder)) if self._folder else "—"

        return f"""<!doctype html>
<html>
<head>
<meta charset="utf-8">
<title>ViaNyquist Report</title>
<style>{css}</style>
</head>
<body>
  <div class="page">
    <h1>ViaNyquist – Report</h1>
    <div class="sub">Registry / Summary export</div>
    <div class="sub">Folder: {folder_txt}</div>

    <div class="chips">
      <div class="chip"><b>Klasa:</b> {_esc(klasa or "—")}</div>
      <div class="chip"><b>Urbroj:</b> {_esc(urbroj or "—")}</div>
      <div class="chip"><b>Target:</b> {_esc(target or "—")} ({_esc(targettype or "—")})</div>
      <div class="chip"><b>LIID:</b> {_esc(liid or "—")}</div>
      <div class="chip"><b>Period:</b> {_fmt_dt_short(bt)} → {_fmt_dt_short(et)}</div>
    </div>

    <div class="stats">
      <div class="stat"><div class="t">Total flows</div><div class="v">{_esc(total_flows)}</div></div>
      <div class="stat"><div class="t">Unique src IP</div><div class="v">{_esc(uniq_src)}</div></div>
      <div class="stat"><div class="t">Unique dst IP</div><div class="v">{_esc(uniq_dst)}</div></div>
      <div class="stat"><div class="t">Unique apps</div><div class="v">{_esc(uniq_apps)}</div></div>
      <div class="stat"><div class="t">Total bytes</div><div class="v">{_esc(_human_bytes(total_bytes))}</div></div>
    </div>

    {analyst_html}

    <div class="grid">
      {''.join(cards)}
    </div>

    <div class="card note">
      <h3>Napomena</h3>
      <p>{_esc(prefilled_text)}</p>
    </div>

    {full_table_html}

    <div class="footer">
      Generated by ViaNyquist. by: _Igy_
    </div>
  </div>
</body>
</html>
"""
    
    def _on_dataset_double_clicked(self, index: QModelIndex):
        if not index.isValid():
            return

        src_index = self.proxy.mapToSource(index)
        row = src_index.row()

        try:
            flow = self.model._rows[row]
        except Exception:
            return

        src = str(flow.get("src_ip") or "")
        dst = str(flow.get("dst_ip") or "")
        if not src or not dst:
            return

        self.openExploreWithConversation.emit(src, dst)

    def _on_insight_double_clicked(self, index: QModelIndex):
        if not index.isValid():
            return

        # take "Item" from fist column (0) – doesn't matter where user clicked
        try:
            item = self.pairs_model.data(self.pairs_model.index(index.row(), 0), Qt.DisplayRole) or ""
        except Exception:
            item = ""

        item = str(item).strip()
        if not item:
            return

        # which insight tab is active
        idx = self.ins_tabs.currentIndex()
        if idx < 0 or idx >= len(self._tab_defs):
            return

        title, key, _hdrs = self._tab_defs[idx]

        # Mapping: doubleclick on wich tab
        # - IP/app/proto: open Explore and insert in search
        # - other: fallback on search (if make sense)
        if key in ("top_src", "top_dst", "top_bytes_src", "top_bytes_dst"):
            # item is IP
            self.openExploreWithSearch.emit(item)
            return

        if key in ("top_app", "top_bytes_app"):
            # item is app name
            self.openExploreWithSearch.emit(item)
            return

        if key == "top_proto":
            # item is formated (format_ip_proto) -> Explore search works on DisplayRole, so it's OK
            self.openExploreWithSearch.emit(item)
            return
   
        self.openExploreWithSearch.emit(item)