from __future__ import annotations
from core.protocols import format_ip_proto
import html
from pathlib import Path
from typing import Any

from PySide6.QtCore import Qt, QAbstractTableModel, QModelIndex, QSortFilterProxyModel
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton, QLineEdit,
    QTableView, QFileDialog, QMessageBox, QFrame, QGridLayout, QTabWidget,
    QSizePolicy, QCheckBox, QScrollArea
)

from core.parser import extract_dataset_meta, build_registry_columns, compute_registry_summary


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

    def set_query(self, q: str):
        self._q = (q or "").strip().lower()
        self.invalidateFilter()

    def filterAcceptsRow(self, row: int, parent: QModelIndex) -> bool:
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

    def __init__(self, parent: QWidget | None = None):
        super().__init__(parent)

        self._folder: Path | None = None
        self._files: list[Path] = []
        self._flows: list[dict[str, Any]] = []
        self._meta: dict[str, Any] = {}
        self._summary: dict[str, Any] = {}
        self._cols: list[str] = []

        # ---- base layout ----
        root = QVBoxLayout(self)
        root.setContentsMargins(16, 16, 16, 16)
        root.setSpacing(12)

        # ---- style (only for this page) ----
        self.setStyleSheet("""
            QWidget { font-family: Segoe UI, Inter, Arial; }
            QScrollArea { background: transparent; }
            QScrollBar:vertical { width: 12px; background: transparent; }

            QLineEdit {
                padding: 9px 10px;
                border: 1px solid #e5e7eb;
                border-radius: 10px;
                background: #ffffff;
            }
            QLineEdit:focus { border: 1px solid #cbd5e1; }

            QCheckBox { color: #111827; }
            QCheckBox::indicator { width: 18px; height: 18px; }

            QPushButton {
                padding: 8px 12px;
                border-radius: 10px;
                border: 1px solid #e5e7eb;
                background: #ffffff;
                color: #111827;
            }
            QPushButton:hover { background: #f9fafb; }
            QPushButton:disabled { color: #9ca3af; background: #f3f4f6; }

            QPushButton#Primary {
                background: #111827;
                border: 1px solid #111827;
                color: white;
                font-weight: 600;
            }
            QPushButton#Primary:hover { background: #0b1220; }

            QFrame#Card {
                background: #ffffff;
                border: 1px solid #e5e7eb;
                border-radius: 14px;
            }

            QLabel#H1 { font-size: 22px; font-weight: 800; color: #111827; }
            QLabel#Muted { color: #6b7280; }

            /* Tabs */
            QTabWidget::pane {
                border: 1px solid #e5e7eb;
                border-radius: 12px;
                background: #ffffff;
            }
            QTabBar::tab {
                padding: 8px 14px;
                background: #f9fafb;
                border: 1px solid #e5e7eb;
                border-bottom: none;
                border-top-left-radius: 10px;
                border-top-right-radius: 10px;
                margin-right: 6px;
                color: #374151;
            }
            QTabBar::tab:selected {
                background: #ffffff;
                color: #111827;
                font-weight: 600;
            }

            QTableView {
                border: 1px solid #e5e7eb;
                border-radius: 12px;
                background: #ffffff;
                gridline-color: #eef2f7;
            }
            QHeaderView::section {
                padding: 8px 6px;
                border: none;
                border-bottom: 1px solid #e5e7eb;
                background: #fafafa;
                color: #374151;
                font-weight: 800;
            }
        """)

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

        # Insights card
        insights_card = QFrame()
        insights_card.setObjectName("Card")
        il = QVBoxLayout(insights_card)
        il.setContentsMargins(14, 12, 14, 12)
        il.setSpacing(10)

        hdr = QHBoxLayout()
        lbl_ins = QLabel("Insights (Top 15)")
        lbl_ins.setStyleSheet("font-size:14px;font-weight:900;color:#111827;")
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
        rp.addWidget(insights_card)

        # Note
        note = QFrame()
        note.setObjectName("Card")
        nl = QVBoxLayout(note)
        nl.setContentsMargins(14, 12, 14, 12)
        nl.setSpacing(6)

        lbl = QLabel("Note")
        lbl.setStyleSheet("font-size:14px;font-weight:900;color:#111827;")
        nl.addWidget(lbl)

        self.txt_note = QLabel(
            "Passive analysis only. Findings are indicative and based on metadata "
            "(IP, protocol, app, timing, volume)."
        )
        self.txt_note.setStyleSheet("color:#374151;")
        self.txt_note.setWordWrap(True)
        nl.addWidget(self.txt_note)

        rp.addWidget(note)
        rp.addStretch()

        # ---------------- Dataset content ----------------
        top = QHBoxLayout()
        lbl_full = QLabel("Full dataset")
        lbl_full.setStyleSheet("font-size:14px;font-weight:900;color:#111827;")

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

        self.txt_search.textChanged.connect(self.proxy.set_query)
        dp.addWidget(self.table, 1)

        # initial states
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
        v.setStyleSheet("font-size:22px;font-weight:900;color:#111827;")
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
    def set_dataset(self, folder: str | Path, files: list[Path], flows: list[dict[str, Any]]):
        self._folder = Path(folder)
        self._files = files or []
        self._flows = flows or []

        self._meta = {}
        if self._files:
            try:
                self._meta = extract_dataset_meta(self._files[0])
            except Exception:
                self._meta = {}

        self._summary = compute_registry_summary(self._flows, top_n=15)
        self._cols = build_registry_columns(self._flows)

        self.model.set_data(self._flows, self._cols)

        self._render_meta()
        self._render_stats()
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
                "background:#f3f4f6;border:1px solid #e5e7eb;"
                "color:#374151;font-size:12px;'>"
                f"<b style='color:#111827;'>{ll}:</b> {vv}"
                "</span>"
            )

        chips = [
            chip("Klasa", klasa),
            chip("Urbroj", urbroj),
            chip("Target", f"{target} ({targettype})" if target or targettype else "—"),
            chip("LIID", liid),
        ]
        if bt or et:
            chips.append(chip("Period", f"{bt} → {et}".strip()))

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

    def _render_full_hint(self):
        self.lbl_full_hint.setText(f"Rows: {len(self._flows)}  |  Columns: {len(self._cols)}")

    def _on_toggle_full(self, checked: bool):
        # Dataset tab is ALWAYS clickable; this only controls its content + export include_full.
        self.lbl_dataset_disabled.setVisible(not checked)
        self.table.setVisible(checked)

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

        default_name = "ConduVia_Report.html"
        out_path, _ = QFileDialog.getSaveFileName(
            self,
            "Export report",
            str(self._folder / default_name),
            "HTML (*.html)"
        )
        if not out_path:
            return

        try:
            html_report = self._build_html_report(include_full=bool(self.chk_full.isChecked()))
            Path(out_path).write_text(html_report, encoding="utf-8")
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
                <thead><tr><th>{_esc(col1)}</th><th class="num">{_esc(col2)}</th></tr></thead>
                <tbody>
                  {table_rows(items)}
                </tbody>
              </table>
            </div>
            """

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
          --bg:#f9fafb; --card:#ffffff; --border:#e5e7eb; --muted:#6b7280; --text:#111827;
          --soft:#f3f4f6;
        }
        body{font-family:Inter,Segoe UI,Arial,sans-serif;margin:32px;background:var(--bg);color:var(--text);}
        .page{max-width:1100px;margin:0 auto;background:var(--card);border:1px solid var(--border);border-radius:16px;padding:28px;}
        h1{margin:0 0 6px 0;font-size:26px;}
        .sub{color:var(--muted);margin-bottom:18px;}
        .chips{display:flex;gap:10px;flex-wrap:wrap;margin:10px 0 18px 0;}
        .chip{background:var(--soft);border:1px solid var(--border);border-radius:999px;padding:6px 10px;font-size:12px;color:#374151;}
        .chip b{color:var(--text);}
        .stats{display:grid;grid-template-columns:repeat(5,1fr);gap:12px;margin:12px 0 18px 0;}
        .stat{border:1px solid var(--border);border-radius:14px;padding:12px;}
        .stat .t{color:var(--muted);font-size:12px;margin-bottom:2px;}
        .stat .v{font-size:20px;font-weight:900;}
        .grid{display:grid;grid-template-columns:repeat(3,1fr);gap:14px;margin-top:12px;}
        .card{border:1px solid var(--border);border-radius:14px;padding:14px;}
        .card h3{margin:0 0 10px 0;font-size:14px;}
        table{width:100%;border-collapse:collapse;font-size:13px;}
        th,td{border-top:1px solid var(--border);padding:8px 6px;text-align:left;vertical-align:top;}
        th{background:#fafafa;color:#374151;font-weight:900;}
        th.num, td.num{text-align:center;font-variant-numeric:tabular-nums;}
        .note{margin-top:18px;}
        .note p{white-space:pre-wrap;color:#374151;margin:0;}
        .details{margin-top:16px;border:1px solid var(--border);border-radius:14px;padding:12px;background:#fff;}
        .details summary{cursor:pointer;font-weight:900;color:#111827;}
        .tablewrap{overflow:auto;margin-top:10px;border-radius:12px;border:1px solid var(--border);}
        table.full{min-width:1100px;}
        .footer{margin-top:18px;color:var(--muted);font-size:12px;}
        @media (max-width:1100px){
          .stats{grid-template-columns:repeat(2,1fr);}
          .grid{grid-template-columns:1fr;}
        }
        """

        prefilled_text = """
Predmet je izrađen temeljem pasivne analize mrežnih tokova.
Zaključci su indikativni i temelje se na metapodacima (IP, protokoli, aplikacije, vrijeme, volumen).
""".strip()

        cards = []
        for title, key, hdrs in self._tab_defs:
            items = s.get(key, []) or []
            if key == "top_proto":
                items = [(format_ip_proto(k), v) for (k, v) in items]
            cards.append(section_card(title, items, hdrs[0], hdrs[1]))

        folder_txt = _esc(str(self._folder)) if self._folder else "—"

        return f"""<!doctype html>
<html>
<head>
<meta charset="utf-8">
<title>ConduVia Report</title>
<style>{css}</style>
</head>
<body>
  <div class="page">
    <h1>ConduVia – Report</h1>
    <div class="sub">Registry / Summary export</div>
    <div class="sub" style="margin-top:-10px;">Folder: {folder_txt}</div>

    <div class="chips">
      <div class="chip"><b>Klasa:</b> {_esc(klasa or "—")}</div>
      <div class="chip"><b>Urbroj:</b> {_esc(urbroj or "—")}</div>
      <div class="chip"><b>Target:</b> {_esc(target or "—")} ({_esc(targettype or "—")})</div>
      <div class="chip"><b>LIID:</b> {_esc(liid or "—")}</div>
      <div class="chip"><b>Period:</b> {_esc(bt or "—")} → {_esc(et or "—")}</div>
    </div>

    <div class="stats">
      <div class="stat"><div class="t">Total flows</div><div class="v">{_esc(total_flows)}</div></div>
      <div class="stat"><div class="t">Unique src IP</div><div class="v">{_esc(uniq_src)}</div></div>
      <div class="stat"><div class="t">Unique dst IP</div><div class="v">{_esc(uniq_dst)}</div></div>
      <div class="stat"><div class="t">Unique apps</div><div class="v">{_esc(uniq_apps)}</div></div>
      <div class="stat"><div class="t">Total bytes</div><div class="v">{_esc(_human_bytes(total_bytes))}</div></div>
    </div>

    <div class="grid">
      {''.join(cards)}
    </div>

    <div class="card note">
      <h3>Napomena</h3>
      <p>{_esc(prefilled_text)}</p>
    </div>

    {full_table_html}

    <div class="footer">
      Generated by ConduVia.
    </div>
  </div>
</body>
</html>
"""