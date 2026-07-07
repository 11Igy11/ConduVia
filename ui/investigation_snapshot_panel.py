from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QFrame, QLabel, QScrollArea, QSizePolicy, QVBoxLayout, QWidget

from core.investigation_snapshot import InvestigationSnapshot


def _compact_next_line(steps: list[str]) -> str:
    clean = [str(step).strip() for step in steps if str(step).strip()]
    if not clean:
        return ""
    short = []
    for step in clean[:3]:
        text = step
        for prefix in ("Open ", "Use "):
            if text.startswith(prefix):
                text = text[len(prefix) :]
        short.append(text)
    return "Next: " + " · ".join(short)


def format_snapshot_body(snapshot: InvestigationSnapshot) -> str:
    lines: list[str] = []

    if snapshot.findings:
        lines.append("FINDINGS")
        lines.extend(f"  • {item}" for item in snapshot.findings[:5])
        lines.append("")

    if snapshot.patterns:
        lines.append("PATTERNS")
        lines.extend(f"  • {item}" for item in snapshot.patterns[:5])
        lines.append("")

    if snapshot.apps_line:
        lines.append(str(snapshot.apps_line).strip())
        lines.append("")

    next_line = _compact_next_line(snapshot.next_steps)
    if next_line:
        lines.append(next_line)
        lines.append("")

    if snapshot.limitations:
        lines.append("LIMITATIONS")
        lines.extend(f"  • {item}" for item in snapshot.limitations[:3])

    return "\n".join(lines).strip()


class InvestigationSnapshotPanel(QFrame):
    def __init__(
        self,
        parent=None,
        *,
        title: str = "",
        empty_text: str = "",
        empty_fixed_height: int | None = None,
    ):
        super().__init__(parent)
        _ = title
        self._empty_text = empty_text or "Load evidence to see an investigation snapshot."
        self._empty_fixed_height = int(empty_fixed_height or 0) or None
        self.setObjectName("InvestigationSnapshotCard")
        self.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)

        outer = QVBoxLayout(self)
        outer.setContentsMargins(14, 12, 14, 12)
        outer.setSpacing(0)

        self._scroll = QScrollArea()
        self._scroll.setObjectName("InvestigationSnapshotScroll")
        self._scroll.setWidgetResizable(True)
        self._scroll.setFrameShape(QFrame.NoFrame)
        self._scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        self._scroll.setVerticalScrollBarPolicy(Qt.ScrollBarAsNeeded)

        content = QWidget()
        content.setObjectName("InvestigationSnapshotContent")
        content.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Minimum)
        body_layout = QVBoxLayout(content)
        body_layout.setContentsMargins(0, 0, 0, 0)
        body_layout.setSpacing(8)
        body_layout.setAlignment(Qt.AlignTop)

        self.lbl_headline = QLabel()
        self.lbl_headline.setObjectName("InvestigationSnapshotHeadline")
        self.lbl_headline.setWordWrap(True)
        self.lbl_headline.setAlignment(Qt.AlignTop | Qt.AlignLeft)
        self.lbl_headline.setTextInteractionFlags(Qt.TextSelectableByMouse)
        self.lbl_headline.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Maximum)

        self.lbl_body = QLabel()
        self.lbl_body.setObjectName("InvestigationSnapshotBody")
        self.lbl_body.setWordWrap(True)
        self.lbl_body.setAlignment(Qt.AlignTop | Qt.AlignLeft)
        self.lbl_body.setTextInteractionFlags(Qt.TextSelectableByMouse)
        self.lbl_body.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Maximum)

        body_layout.addWidget(self.lbl_headline)
        body_layout.addWidget(self.lbl_body)
        body_layout.addStretch(1)

        self._scroll.setWidget(content)
        outer.addWidget(self._scroll, 1)

        self._apply_empty_state()

    def _apply_fixed_frame_height(self) -> None:
        if self._empty_fixed_height:
            self.setFixedHeight(self._empty_fixed_height)
            self.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
            return
        self.adjustSize()
        self.setFixedHeight(max(64, self.sizeHint().height()))
        self.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)

    def _release_compact_height(self) -> None:
        self.setMinimumHeight(0)
        self.setMaximumHeight(16777215)
        self.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Minimum)

    def _apply_empty_state(self) -> None:
        self.lbl_headline.setObjectName("InvestigationSnapshotEmpty")
        self.lbl_headline.setText(self._empty_text)
        self.lbl_headline.show()
        self.lbl_body.clear()
        self.lbl_body.hide()
        self._scroll.verticalScrollBar().setValue(0)
        self._apply_fixed_frame_height()

    def set_loading(self, message: str) -> None:
        self.lbl_headline.setObjectName("InvestigationSnapshotEmpty")
        self.lbl_headline.setText(str(message or "Loading...").strip())
        self.lbl_headline.show()
        self.lbl_body.hide()
        self._scroll.verticalScrollBar().setValue(0)
        self._apply_fixed_frame_height()

    def set_snapshot(self, snapshot: InvestigationSnapshot | None) -> None:
        if snapshot is None or not (
            snapshot.headline
            or snapshot.findings
            or snapshot.patterns
            or snapshot.narrative
        ):
            self._apply_empty_state()
            return

        if not self._empty_fixed_height:
            self._release_compact_height()

        body = format_snapshot_body(snapshot)
        narrative_only = not body and bool(snapshot.narrative)

        if narrative_only:
            self.lbl_headline.hide()
            self.lbl_body.setText(snapshot.narrative.strip())
            self.lbl_body.show()
        elif snapshot.headline:
            self.lbl_headline.setObjectName("InvestigationSnapshotHeadline")
            self.lbl_headline.setText(snapshot.headline)
            self.lbl_headline.show()
            if body:
                self.lbl_body.setText(body)
                self.lbl_body.show()
            else:
                self.lbl_body.hide()
        else:
            self.lbl_headline.hide()
            if body:
                self.lbl_body.setText(body)
                self.lbl_body.show()
            else:
                self.lbl_body.hide()

        self._scroll.verticalScrollBar().setValue(0)
        if self._empty_fixed_height:
            self._apply_fixed_frame_height()

    def clear(self) -> None:
        self._apply_empty_state()
