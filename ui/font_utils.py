from __future__ import annotations

from shiboken6 import isValid

from PySide6.QtCore import QEvent, QObject
from PySide6.QtGui import QFont
from PySide6.QtWidgets import QApplication, QPlainTextEdit, QTextEdit, QWidget

_font_sanitizer: "_FontSanitizer | None" = None


def _widget_is_alive(widget: QWidget | None) -> bool:
    return widget is not None and isValid(widget)


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
    point_size = max(1, default)
    if pixel_size > 0:
        point_size = max(1, int(round(pixel_size * 0.75)))
    safe.setPointSize(point_size)
    return safe


def ensure_widget_point_font(widget: QWidget, *, default: int = 10) -> None:
    if not _widget_is_alive(widget):
        return
    font = widget.font()
    if font.pointSize() > 0:
        ensure_text_widget_fonts(widget, default=default)
        return
    widget.setFont(ensure_point_font(font, default=default))
    ensure_text_widget_fonts(widget, default=default)


def ensure_text_widget_fonts(widget: QWidget, *, default: int = 10) -> None:
    if not isinstance(widget, (QTextEdit, QPlainTextEdit)):
        return
    if not _widget_is_alive(widget):
        return
    doc = widget.document()
    if doc is None:
        return
    font = doc.defaultFont()
    if font.pointSize() > 0:
        return
    doc.setDefaultFont(ensure_point_font(font, default=default))


def install_font_sanitizer(qapp: QApplication) -> None:
    """Normalize widget fonts after QSS polish (avoids QFont::setPointSize(-1) warnings)."""
    global _font_sanitizer
    if _font_sanitizer is not None:
        return
    _font_sanitizer = _FontSanitizer(qapp)
    qapp.installEventFilter(_font_sanitizer)


class _FontSanitizer(QObject):
    def eventFilter(self, obj, event) -> bool:
        if event.type() != QEvent.Type.Show or not isinstance(obj, QWidget):
            return False
        if not _widget_is_alive(obj):
            return False
        ensure_widget_point_font(obj)
        return False


def ensure_dialog_fonts(root: QWidget, *, default: int = 10) -> None:
    if not _widget_is_alive(root):
        return
    ensure_widget_point_font(root, default=default)
    for child in root.findChildren(QWidget):
        ensure_widget_point_font(child, default=default)


def repolish_widget(widget: QWidget) -> None:
    if not _widget_is_alive(widget):
        return
    widget.style().unpolish(widget)
    widget.style().polish(widget)
    ensure_widget_point_font(widget)
    widget.update()


def refresh_widget_style(widget: QWidget) -> None:
    if not _widget_is_alive(widget):
        return
    ensure_widget_point_font(widget)
    widget.update()


def apply_named_style(widget: QWidget, object_name: str) -> None:
    if not _widget_is_alive(widget):
        return
    changed = widget.objectName() != object_name
    if changed:
        widget.setObjectName(object_name)
        repolish_widget(widget)
    else:
        refresh_widget_style(widget)
