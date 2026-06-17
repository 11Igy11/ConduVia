from __future__ import annotations

from PySide6.QtGui import QFont
from PySide6.QtWidgets import QWidget


def app_font(
    *,
    family: str = "Segoe UI",
    point_size: int | None = 10,
    pixel_size: int | None = None,
    bold: bool = False,
) -> QFont:
    font = QFont(family)
    if bold:
        font.setBold(True)
    if pixel_size is not None and pixel_size > 0:
        font.setPixelSize(int(pixel_size))
        return font
    if point_size is not None and point_size > 0:
        font.setPointSize(int(point_size))
    else:
        font.setPointSize(10)
    return font


def label_font(*, point_size: int = 10, bold: bool = False) -> QFont:
    return app_font(point_size=max(1, point_size), bold=bold)


def ensure_point_font(font: QFont, *, default: int = 10) -> QFont:
    if font.pointSize() > 0:
        return QFont(font)
    safe = QFont(font.family())
    safe.setBold(font.bold())
    safe.setItalic(font.italic())
    safe.setWeight(font.weight())
    safe.setStyle(font.style())
    safe.setStyleHint(font.styleHint())
    safe.setUnderline(font.underline())
    safe.setStrikeOut(font.strikeOut())
    pixel_size = font.pixelSize()
    if pixel_size > 0:
        safe.setPointSize(max(1, int(round(pixel_size * 0.75))))
    else:
        safe.setPointSize(max(1, default))
    return safe


def ensure_widget_point_font(widget: QWidget, *, default: int = 10) -> None:
    font = widget.font()
    if font.pointSize() > 0:
        return
    widget.setFont(ensure_point_font(font, default=default))


def repolish_widget(widget: QWidget) -> None:
    ensure_widget_point_font(widget)
    widget.style().unpolish(widget)
    widget.style().polish(widget)
    widget.update()


def refresh_widget_style(widget: QWidget) -> None:
    ensure_widget_point_font(widget)
    widget.update()


def apply_named_style(widget: QWidget, object_name: str) -> None:
    changed = widget.objectName() != object_name
    if changed:
        widget.setObjectName(object_name)
        repolish_widget(widget)
    else:
        refresh_widget_style(widget)
