from __future__ import annotations

from typing import Any

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QPushButton,
    QLabel, QComboBox, QLineEdit, QSplitter,
    QListWidget, QTextEdit
)


class FindingsPage(QWidget):
    jumpRequested = Signal()
    editRequested = Signal()
    deleteRequested = Signal()
    selectionChanged = Signal()
    doubleClickedFinding = Signal()
    contextMenuRequestedFromList = Signal(object)

    def __init__(self, parent: QWidget | None = None):
        super().__init__(parent)

        root = QVBoxLayout(self)

        actions = QHBoxLayout()
        self.btn_finding_edit = QPushButton("Edit")
        self.btn_finding_delete = QPushButton("Delete")
        self.btn_finding_jump = QPushButton("Jump to Flow")

        actions.addWidget(self.btn_finding_edit)
        actions.addWidget(self.btn_finding_delete)
        actions.addWidget(self.btn_finding_jump)
        actions.addStretch()
        root.addLayout(actions)

        frow = QHBoxLayout()
        frow.addWidget(QLabel("Status:"))

        self.cmb_find_status = QComboBox()
        self.cmb_find_status.addItems(["All", "New", "Investigating", "Confirmed", "False Positive"])
        frow.addWidget(self.cmb_find_status)

        frow.addSpacing(12)
        frow.addWidget(QLabel("Search:"))

        self.txt_find_search = QLineEdit()
        self.txt_find_search.setPlaceholderText("title / ip / app / sni / note...")
        frow.addWidget(self.txt_find_search, 2)

        frow.addSpacing(12)
        frow.addWidget(QLabel("Tag contains:"))

        self.txt_find_tag = QLineEdit()
        self.txt_find_tag.setPlaceholderText("e.g. c2, dns, exfil ...")
        frow.addWidget(self.txt_find_tag, 1)

        frow.addSpacing(12)
        frow.addWidget(QLabel("Sort:"))

        self.cmb_find_sort = QComboBox()
        self.cmb_find_sort.addItems(["Newest", "Oldest", "Status", "Title"])
        frow.addWidget(self.cmb_find_sort)

        self.btn_find_clear = QPushButton("Clear")
        frow.addWidget(self.btn_find_clear)

        root.addLayout(frow)

        self.findings_split = QSplitter(Qt.Horizontal)
        self.findings_list = QListWidget()
        self.finding_detail = QTextEdit()
        self.finding_detail.setReadOnly(True)
        self.finding_detail.setPlaceholderText("Select a finding to see details...")

        self.findings_split.addWidget(self.findings_list)
        self.findings_split.addWidget(self.finding_detail)
        self.findings_split.setSizes([420, 700])

        root.addWidget(self.findings_split)

        self._wire_ui()

    def _wire_ui(self):
        self.btn_finding_jump.clicked.connect(self.jumpRequested.emit)
        self.btn_finding_edit.clicked.connect(self.editRequested.emit)
        self.btn_finding_delete.clicked.connect(self.deleteRequested.emit)

        self.findings_list.itemSelectionChanged.connect(self.selectionChanged.emit)
        self.findings_list.itemDoubleClicked.connect(lambda _: self.doubleClickedFinding.emit())

        self.findings_list.setContextMenuPolicy(Qt.CustomContextMenu)
        self.findings_list.customContextMenuRequested.connect(self.contextMenuRequestedFromList.emit)

    def set_actions_enabled(self, enabled: bool):
        self.btn_finding_edit.setEnabled(enabled)
        self.btn_finding_delete.setEnabled(enabled)
        self.btn_finding_jump.setEnabled(enabled)

    def selected_finding_id(self) -> int | None:
        item = self.findings_list.currentItem()
        if not item:
            return None

        fid = item.data(Qt.UserRole)

        if not fid or str(item.text()).startswith("("):
            return None

        try:
            return int(fid)
        except Exception:
            return None


    def clear_detail(self):
        self.finding_detail.setText("")
        self.set_actions_enabled(False)


    def show_detail(self, text: str):
        self.finding_detail.setText(text)
        self.set_actions_enabled(True)


    def clear_list(self):
        self.findings_list.clear()


    def add_list_item(self, text: str, fid: int | None):
        from PySide6.QtWidgets import QListWidgetItem

        item = QListWidgetItem(text)
        if fid is not None:
            item.setData(Qt.UserRole, fid)

        self.findings_list.addItem(item)

    def select_finding_by_id(self, fid: int) -> bool:
        for i in range(self.findings_list.count()):
            it = self.findings_list.item(i)
            try:
                if int(it.data(Qt.UserRole) or 0) == fid:
                    self.findings_list.setCurrentItem(it)
                    return True
            except Exception:
                pass
        return False
    
    def matches_filters(self, r: Any, status_sel: str, search: str, tagq: str) -> bool:
        if status_sel != "All":
            if (r["status"] or "New") != status_sel:
                return False

        if tagq:
            tags = (r["tags"] or "").lower()
            if tagq not in tags:
                return False

        if search:
            hay = " ".join([
                str(r["title"] or ""),
                str(r["note"] or ""),
                str(r["src_ip"] or ""),
                str(r["dst_ip"] or ""),
                str(r["application_name"] or ""),
                str(r["requested_server_name"] or ""),
                str(r["protocol"] or ""),
                str(r["tags"] or ""),
                str(r["created_at"] or ""),
            ]).lower()

            if search not in hay:
                return False

        return True


    def sort_rows(self, rows: list[Any], mode: str) -> list[Any]:

        def status_rank(s: str) -> int:
            order = {
                "Confirmed": 0,
                "Investigating": 1,
                "New": 2,
                "False Positive": 3
            }
            return order.get((s or "New"), 9)

        if mode == "Oldest":
            return sorted(rows, key=lambda r: (r["created_at"], int(r["id"])))

        if mode == "Status":
            return sorted(
                rows,
                key=lambda r: (status_rank(r["status"]), r["created_at"], int(r["id"])),
                reverse=False,
            )

        if mode == "Title":
            return sorted(
                rows,
                key=lambda r: ((r["title"] or "").lower(), r["created_at"]),
                reverse=False,
            )

        # default = Newest
        return sorted(
            rows,
            key=lambda r: (r["created_at"], int(r["id"])),
            reverse=True,
        )
    
    def render_list(self, rows, current_project_id, keep_id):
        self.findings_list.blockSignals(True)

        self.clear_list()
        self.clear_detail()

        if current_project_id is None:
            self.add_list_item("(no active project)", None)
            self.findings_list.blockSignals(False)
            return

        if not rows:
            self.add_list_item("(no findings match filters)", None)
            self.findings_list.blockSignals(False)
            return

        for r in rows:
            badge = r.get("status_emoji", "")
            title = r["title"]
            src = f"{r['src_ip']}:{r['src_port'] or ''}"
            dst = f"{r['dst_ip']}:{r['dst_port'] or ''}"
            app = r["application_name"] or ""
            created = r["created_at"]

            tags = (r["tags"] or "").strip()
            tag_part = f" | #{tags}" if tags else ""

            label = f"{created} | {badge} {title} | {src} -> {dst} | {app}{tag_part}"

            self.add_list_item(label, int(r["id"]))

        self.findings_list.blockSignals(False)

        if keep_id is not None:
            self.select_finding_by_id(keep_id)