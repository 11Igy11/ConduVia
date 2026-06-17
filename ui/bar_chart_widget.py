from __future__ import annotations

from typing import Any

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QFrame, QHBoxLayout, QLabel, QProgressBar, QVBoxLayout

from ui.buttons import make_action_button


def _short_label(value: str, limit: int) -> str:
    value = (value or "").strip()
    if len(value) <= limit:
        return value
    return value[: max(0, limit - 3)] + "..."


class BarChartWidget(QFrame):
    def __init__(
        self,
        title: str,
        parent=None,
        *,
        value_key: str = "count",
        value_label_key: str | None = None,
        label_limit: int = 28,
        label_width: int = 120,
        max_rows: int = 8,
        stacked_labels: bool = False,
        compact_single_counts: bool = False,
        count_list: bool = False,
    ):
        super().__init__(parent)
        self.setObjectName("Card")
        self.title = title
        self.value_key = value_key
        self.value_label_key = value_label_key
        self.label_limit = label_limit
        self.label_width = label_width
        self.max_rows = max_rows
        self.stacked_labels = stacked_labels
        self.compact_single_counts = compact_single_counts
        self.count_list = count_list
        self.layout = QVBoxLayout(self)
        self.layout.setContentsMargins(12, 10, 12, 12)
        self.layout.setSpacing(8)
        self.layout.setAlignment(Qt.AlignTop)

        header_row = QHBoxLayout()
        header_row.setSpacing(8)
        title_label = QLabel(title)
        title_label.setObjectName("SectionTitle")
        title_label.setAlignment(Qt.AlignLeft | Qt.AlignTop)
        self.btn_expand_table = make_action_button(
            "Expand table",
            object_name="SummaryExpandButton",
            enabled=False,
        )
        self.btn_expand_table.hide()
        self._expand_callback = None
        self.btn_expand_table.clicked.connect(self._on_expand_table_clicked)
        header_row.addWidget(title_label, 1)
        header_row.addWidget(self.btn_expand_table, 0, Qt.AlignRight | Qt.AlignTop)
        self.layout.addLayout(header_row)

        self.rows = QVBoxLayout()
        self.rows.setSpacing(6)
        self.rows.setAlignment(Qt.AlignTop)
        self.layout.addLayout(self.rows, 1)
        self.setMinimumHeight(140)

    def configure_expand_table(self, callback) -> None:
        self._expand_callback = callback
        self.btn_expand_table.show()

    def _on_expand_table_clicked(self) -> None:
        if self._expand_callback is not None:
            self._expand_callback()

    def set_expand_enabled(self, enabled: bool, *, tooltip: str = "") -> None:
        if self._expand_callback is None:
            return
        self.btn_expand_table.setEnabled(enabled)
        self.btn_expand_table.setToolTip(tooltip or "")

    def set_rows(
        self,
        rows: list[dict[str, Any]],
        *,
        empty_text: str = "No data yet.",
        footer_text: str = "",
    ) -> None:
        self._clear_rows()
        if not rows:
            empty = QLabel(empty_text)
            empty.setObjectName("Muted")
            empty.setWordWrap(True)
            empty.setAlignment(Qt.AlignLeft | Qt.AlignTop)
            self.rows.addWidget(empty)
            self.rows.addStretch(1)
            return

        max_count = max(int(row.get(self.value_key) or 0) for row in rows) or 1
        use_compact_counts = self.compact_single_counts and self.value_key == "count" and max_count <= 1
        visible_rows = rows if self.max_rows <= 0 else rows[: self.max_rows]
        hidden_count = max(0, len(rows) - len(visible_rows))
        for row in visible_rows:
            label = str(row.get("label") or "-")
            count = int(row.get(self.value_key) or 0)
            display_value = str(row.get(self.value_label_key) or count) if self.value_label_key else str(count)
            pct = int(round((count / max_count) * 100)) if max_count else 0
            tooltip = str(row.get("tooltip") or row.get("detail") or label)

            if self.count_list:
                self._add_count_row(label, display_value, tooltip=tooltip)
                continue

            if self.stacked_labels:
                self._add_stacked_row(label, display_value, pct, tooltip=tooltip)
                continue

            line = QHBoxLayout()
            line.setSpacing(8)
            name = QLabel(_short_label(label, self.label_limit))
            name.setMinimumWidth(self.label_width)
            name.setToolTip(str(row.get("tooltip") or label))
            value = QLabel(display_value)
            value.setMinimumWidth(72)
            value.setAlignment(Qt.AlignRight | Qt.AlignVCenter)
            line.addWidget(name)
            if not use_compact_counts:
                bar = QProgressBar()
                bar.setRange(0, 100)
                bar.setValue(pct)
                bar.setTextVisible(False)
                bar.setMinimumHeight(16)
                line.addWidget(bar, 1)
            else:
                line.addStretch(1)
            line.addWidget(value)
            self.rows.addLayout(line)

        if hidden_count:
            footer = QLabel(f"+ {hidden_count:,} more rows ({len(rows):,} total)")
            footer.setObjectName("Muted")
            footer.setWordWrap(True)
            self.rows.addWidget(footer)
        elif footer_text:
            footer = QLabel(footer_text)
            footer.setObjectName("Muted")
            footer.setWordWrap(True)
            self.rows.addWidget(footer)

        self.rows.addStretch()

    def _add_count_row(self, label: str, display_value: str, *, tooltip: str = "") -> None:
        row = QFrame()
        row.setObjectName("ProfileCountRow")
        row_layout = QHBoxLayout(row)
        row_layout.setContentsMargins(10, 7, 10, 7)
        row_layout.setSpacing(8)

        name = QLabel(label)
        name.setWordWrap(True)
        name.setToolTip(tooltip or label)
        value = QLabel(display_value)
        value.setObjectName("ProfileCountBadge")
        value.setAlignment(Qt.AlignCenter)
        value.setMinimumWidth(44)

        row_layout.addWidget(name, 1)
        row_layout.addWidget(value)
        self.rows.addWidget(row)

    def _add_stacked_row(self, label: str, display_value: str, pct: int, *, tooltip: str = "") -> None:
        label_row = QHBoxLayout()
        label_row.setSpacing(8)
        name = QLabel(label)
        name.setWordWrap(True)
        name.setToolTip(tooltip or label)
        value = QLabel(display_value)
        value.setMinimumWidth(72)
        value.setAlignment(Qt.AlignRight | Qt.AlignVCenter)
        label_row.addWidget(name, 1)
        label_row.addWidget(value)
        self.rows.addLayout(label_row)

        bar = QProgressBar()
        bar.setRange(0, 100)
        bar.setValue(pct)
        bar.setTextVisible(False)
        bar.setMinimumHeight(14)
        self.rows.addWidget(bar)

    def _clear_rows(self) -> None:
        while self.rows.count():
            item = self.rows.takeAt(0)
            child = item.widget()
            if child is not None:
                child.deleteLater()
            nested = item.layout()
            if nested is not None:
                while nested.count():
                    nested_item = nested.takeAt(0)
                    nested_child = nested_item.widget()
                    if nested_child is not None:
                        nested_child.deleteLater()
