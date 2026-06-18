"""Registry report chart widgets."""

from __future__ import annotations

import math

from PySide6.QtCore import Qt, QRectF, QSize, Signal
from PySide6.QtGui import QColor, QFontMetrics, QPainter, QPen
from PySide6.QtWidgets import QApplication, QToolTip, QWidget

from core.formatters import human_bytes
from ui.font_utils import label_font


def is_light_theme() -> bool:
    app = QApplication.instance()
    return bool(app and app.property("ui_theme") == "light")


def registry_chart_palette() -> dict[str, str]:
    if is_light_theme():
        return {
            "border": "#cbd5e1",
            "background": "#e2e8f0",
            "primary": "#3b82f6",
            "secondary": "#94a3b8",
            "muted_text": "#64748b",
            "peak": "#2563eb",
            "quiet": "#f59e0b",
        }
    return {
        "border": "#475569",
        "background": "#1f2937",
        "primary": "#3b82f6",
        "secondary": "#64748b",
        "muted_text": "#94a3b8",
        "peak": "#2563eb",
        "quiet": "#f59e0b",
    }


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

            colors = registry_chart_palette()
            border = QColor(colors["border"])
            bg = QColor(colors["background"])
            out_c = QColor(colors["primary"])
            in_c = QColor(colors["secondary"])
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
                tip = f"{hit:02d}:00 — {human_bytes(v, precision=2)}"

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

            colors = registry_chart_palette()
            bar_fg = QColor(colors["primary"])
            base_c = QColor(colors["border"])
            text_c = QColor(colors["muted_text"])

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

            p.setPen(QPen(base_c, 1))
            p.drawLine(x0, y0 + bars_h, x0 + used_w, y0 + bars_h)

            mx = max(self._vals) if self._vals else 0
            if mx <= 0:
                scaled = [0] * 24
            else:
                mxs = math.sqrt(mx)
                scaled = [math.sqrt(v) / mxs for v in self._vals]

            p.setPen(Qt.NoPen)
            for i in range(24):
                frac = scaled[i]
                bh = int(frac * bars_h)
                x = x0 + i * (bar_w + gap)

                self._bar_rects[i] = QRectF(x, y0, bar_w, bars_h)

                if bh <= 0:
                    continue

                if i == self._peak_hour:
                    p.setBrush(QColor(colors["peak"]))
                elif i in self._quiet_hours:
                    p.setBrush(QColor(colors["quiet"]))
                else:
                    p.setBrush(bar_fg)

                p.drawRect(x, y0 + (bars_h - bh), bar_w, bh)

            if self._show_labels:
                label_font_obj = label_font(point_size=9)
                p.setFont(label_font_obj)
                fm = QFontMetrics(label_font_obj)
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
