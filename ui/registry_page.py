from __future__ import annotations
from core.protocols import format_ip_proto
import html
from pathlib import Path
from typing import Any
from core.formatters import bytes_mb_or_b, human_bytes, safe_int, format_short_date
from core.timeutils import parse_flow_timestamp
from core.exporters.registry_exporter import export_registry_html
from ui.table_export import append_table_export_footer
from ui.buttons import make_action_button, make_dialog_button
from core.db import get_app_settings, get_project
from core.workspace import workspace_export_path

from PySide6.QtCore import Qt, Signal, QModelIndex
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton, QLineEdit,
    QTableView, QFileDialog, QMessageBox, QFrame, QGridLayout, QTabWidget,
    QDialog, QHeaderView,
    QSizePolicy, QCheckBox, QScrollArea, QProgressBar, QApplication
)

from core.flow_stats import build_daily_activity_rows
from core.parser import extract_dataset_meta, build_registry_columns, compute_registry_summary
from core.analyst import compute_analyst_summary
from ui.explore_widgets import CopyableTableView
from ui.project_rows_dialog import open_project_rows_dialog
from ui.registry_models import PairsModel, RegistryTableModel, TextFilterProxy
from ui.registry_widgets import (
    DirectionBarWidget,
    MiniHistogram24Widget,
    registry_chart_palette,
)
from core.analysis_limits import EMBEDDED_SUMMARY_TOP_N, embedded_expand_available, embedded_expand_tooltip

# ----------------- helpers -----------------
def _esc(x: Any) -> str:
    return html.escape("" if x is None else str(x))

def _fmt_dt_short(x: Any) -> str:
    return format_short_date(x, missing="—")

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
        return "<span>—</span>"

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

        volume = human_bytes(total_bytes, precision=2)

        rows.append(
            "<tr>"
            f"<td style='padding:7px 12px;'>{_esc(_fmt_dt_short(day))}</td>"
            f"<td style='padding:7px 12px;font-weight:700;text-align:right;'>{count}</td>"
            f"<td style='padding:7px 12px;font-weight:600;text-align:right;'>{_esc(volume)}</td>"
            "</tr>"
        )

    return (
            "<div style='margin-top:8px;max-width:520px;"
            "border-radius:10px;overflow:hidden;'>"
            "<table style='width:100%;border-collapse:collapse;'>"
            "<thead>"
            "<tr>"
            "<th style='padding:8px 12px;text-align:left;font-size:11px;font-weight:700;'>Date</th>"
            "<th style='padding:8px 12px;text-align:right;font-size:11px;font-weight:700;'>Flows</th>"
            "<th style='padding:8px 12px;text-align:right;font-size:11px;font-weight:700;'>Bytes</th>"
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
        return "<span>—</span>"

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

        volume = human_bytes(total_bytes, precision=2)

        rows.append(
            "<tr>"
            f"<td style='padding:7px 12px;'>{_esc(_fmt_dt_short(day))}</td>"
            f"<td style='padding:7px 12px;font-weight:700;text-align:right;'>{count}</td>"
            f"<td style='padding:7px 12px;font-weight:600;text-align:right;'>{_esc(volume)}</td>"
            "</tr>"
        )

    return (
        "<div style='margin-top:8px;max-width:520px;"
        "border-radius:10px;overflow:hidden;'>"
        "<table style='width:100%;border-collapse:collapse;'>"
        "<thead>"
        "<tr>"
        "<th style='padding:8px 12px;text-align:left;font-size:11px;font-weight:700;'>Date</th>"
        "<th style='padding:8px 12px;text-align:right;font-size:11px;font-weight:700;'>Flows</th>"
        "<th style='padding:8px 12px;text-align:right;font-size:11px;font-weight:700;'>Bytes</th>"
        "</tr>"
        "</thead>"
        "<tbody>"
        + "".join(rows) +
        "</tbody>"
        "</table>"
        "</div>"
    )


def _daily_activity_rows(day_hist: dict[str, Any], day_bytes: dict[str, Any]) -> list[dict[str, Any]]:
    return build_daily_activity_rows(day_hist, day_bytes)


def _daily_activity_preview_html(rows: list[dict[str, Any]], *, top_n: int = EMBEDDED_SUMMARY_TOP_N) -> str:
    if not rows:
        return "<span>—</span>"
    preview = rows[:top_n]
    body = []
    for row in preview:
        body.append(
            "<tr>"
            f"<td style='padding:7px 12px;'>{_esc(row.get('date_label') or row.get('date') or '—')}</td>"
            f"<td style='padding:7px 12px;font-weight:700;text-align:right;'>{int(row.get('flows') or 0):,}</td>"
            f"<td style='padding:7px 12px;font-weight:600;text-align:right;'>{_esc(row.get('bytes_label') or '')}</td>"
            "</tr>"
        )
    return (
        "<div style='margin-top:4px;max-width:640px;border-radius:10px;overflow:hidden;'>"
        "<table style='width:100%;border-collapse:collapse;'>"
        "<thead><tr>"
        "<th style='padding:8px 12px;text-align:left;font-size:11px;font-weight:700;'>Date</th>"
        "<th style='padding:8px 12px;text-align:right;font-size:11px;font-weight:700;'>Flows</th>"
        "<th style='padding:8px 12px;text-align:right;font-size:11px;font-weight:700;'>Volume</th>"
        "</tr></thead><tbody>"
        + "".join(body)
        + "</tbody></table></div>"
    )


def _mini_hist_24_html(vals: list[int], *, height_px: int = 14) -> str:
    """
    Qt RichText safe mini histogram.
    Expects 24 ints. If vals are 0..100 we use them directly as percent-of-height.
    Uses nested tables + pixel heights (no % heights) to avoid Qt CSS quirks.
    """
    if not isinstance(vals, list) or len(vals) != 24:
        return ""
    colors = registry_chart_palette()

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
            f"style='height:{height_px}px;border:1px solid {colors['border']};"
            f"background:{colors['background']};border-radius:4px;overflow:hidden;'>"
            # empty spacer
            f"<div style='height:{empty_h}px;'></div>"
            # bar
            f"<div style='height:{bar_h}px;background:{colors['primary']};'></div>"
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
        <td style='width:0%;font-size:11px;'>00</td>
        <td style='width:25%;font-size:11px;text-align:center;'>06</td>
        <td style='width:25%;font-size:11px;text-align:center;'>12</td>
        <td style='width:25%;font-size:11px;text-align:center;'>18</td>
        <td style='width:25%;font-size:11px;text-align:right;'>23</td>
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
    colors = registry_chart_palette()

    return (
        f"<div style='display:inline-block;width:{width_px}px;height:{height_px}px;"
        f"border:1px solid {colors['border']};border-radius:999px;overflow:hidden;background:{colors['background']};'>"
        f"<span style='display:inline-block;height:{height_px}px;width:{o:.1f}%;background:{colors['primary']};'></span>"
        f"<span style='display:inline-block;height:{height_px}px;width:{i:.1f}%;background:{colors['secondary']};'></span>"
        "</div>"
    )

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
        self.app = parent

        self._folder: Path | None = None
        self._files: list[Path] = []
        self._flows: list[dict[str, Any]] = []
        self._meta: dict[str, Any] = {}
        self._summary: dict[str, Any] = {}
        self._cols: list[str] = []
        self._analyst: dict[str, Any] = {}
        self._compare_result: dict[str, Any] | None = None
        self._daily_activity_rows: list[dict[str, Any]] = []

        # ---- base layout ----
        root = QVBoxLayout(self)
        root.setContentsMargins(16, 16, 16, 16)
        root.setSpacing(12)

        # ---------------- HERO ----------------
        hero = QFrame()
        hero.setObjectName("Card")
        hl = QVBoxLayout(hero)
        hl.setContentsMargins(12, 8, 12, 8)
        hl.setSpacing(8)

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
        self.lbl_meta_chips.setTextFormat(Qt.PlainText)
        self.lbl_meta_chips.setWordWrap(True)
        self.lbl_meta_chips.setTextInteractionFlags(Qt.TextSelectableByMouse)
        hl.addWidget(self.lbl_meta_chips)

        root.addWidget(hero)
        hero.hide()

        # ---------------- Actions row ----------------
        actions = QHBoxLayout()
        actions.setSpacing(12)
        actions.setContentsMargins(0, 0, 0, 0)

        self.txt_search = QLineEdit()
        self.txt_search.hide()
        self.txt_search.setPlaceholderText("Search across ALL fields…")

        self.chk_full = QCheckBox("Include full dataset")
        self.chk_full.setToolTip("Show full dataset in Dataset tab and include full dataset table in export.")
        self.chk_full.setChecked(False)
        self.chk_full.toggled.connect(self._on_toggle_full)

        self.btn_export = make_action_button("Export HTML report")
        self.btn_export.clicked.connect(self.export_report)

        actions.addWidget(self.chk_full, 0)
        actions.addWidget(self.btn_export, 0)
        actions_widget = QWidget()
        actions_widget.setLayout(actions)

        # ---------------- Main Tabs ----------------
        self.main_tabs = QTabWidget()
        self.main_tabs.setDocumentMode(True)
        self.main_tabs.setCornerWidget(actions_widget, Qt.TopRightCorner)

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
        rp.setContentsMargins(10, 10, 10, 10)
        rp.setSpacing(8)

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
        stats_grid.setHorizontalSpacing(8)
        stats_grid.setVerticalSpacing(8)

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
        self.lbl_analyst_title = QLabel("Observed activity")
        self.lbl_analyst_title.setObjectName("RegistryStrongTitle")
        hdr2.addWidget(self.lbl_analyst_title)
        hdr2.addStretch()
        al.addLayout(hdr2)

        self.lbl_period_context = QLabel("")
        self.lbl_period_context.setObjectName("Muted")
        self.lbl_period_context.setWordWrap(True)
        al.addWidget(self.lbl_period_context)

        self.lbl_deviation = QLabel("Traffic pattern flags")
        self.lbl_deviation.setObjectName("RegistrySmallTitle")
        self.lbl_deviation.setToolTip(
            "Rule-based indicators from flow metadata, not a legal assessment."
        )
        al.addWidget(self.lbl_deviation)

        self.lbl_flags_body = QLabel("")
        self.lbl_flags_body.setTextFormat(Qt.RichText)
        self.lbl_flags_body.setWordWrap(True)
        self.lbl_flags_body.setObjectName("RegistryBodyText")
        al.addWidget(self.lbl_flags_body)

        self.deviation_bar = QProgressBar()
        self.deviation_bar.hide()

        # Body text (rich)
        self.lbl_analyst_body = QLabel("")
        self.lbl_analyst_body.setTextFormat(Qt.RichText)
        self.lbl_analyst_body.setWordWrap(True)
        self.lbl_analyst_body.setObjectName("RegistryBodyText")
        self.lbl_analyst_body.setSizePolicy(QSizePolicy.Preferred, QSizePolicy.Maximum)
        al.addWidget(self.lbl_analyst_body)

        daily_hdr = QHBoxLayout()
        self.lbl_daily_activity_title = QLabel("Daily activity (top by volume)")
        self.lbl_daily_activity_title.setObjectName("RegistrySmallTitle")
        daily_hdr.addWidget(self.lbl_daily_activity_title)
        daily_hdr.addStretch()
        self.btn_expand_daily_activity = make_action_button(
            "Expand table",
            object_name="SummaryExpandButton",
            enabled=False,
        )
        self.btn_expand_daily_activity.clicked.connect(self._expand_daily_activity)
        daily_hdr.addWidget(self.btn_expand_daily_activity)
        al.addLayout(daily_hdr)

        self.lbl_day_section = QLabel("")
        self.lbl_day_section.setTextFormat(Qt.RichText)
        self.lbl_day_section.setWordWrap(True)
        self.lbl_day_section.setObjectName("RegistryBodyText")
        al.addWidget(self.lbl_day_section)

        self.lbl_activity_text = QLabel("")
        self.lbl_activity_text.setTextFormat(Qt.RichText)
        self.lbl_activity_text.setWordWrap(True)
        self.lbl_activity_text.setObjectName("RegistryBodyText")
        al.addWidget(self.lbl_activity_text)
        al.addSpacing(4)

        hist_hdr = QHBoxLayout()

        self.lbl_hist_title = QLabel("Hourly pattern (loaded period · by bytes)")
        self.lbl_hist_title.setObjectName("RegistrySmallTitle")
        hist_hdr.addWidget(self.lbl_hist_title)

        hist_hdr.addStretch()

        self.btn_hist_toggle = make_action_button("By flows")
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
        self.lbl_dir_text.setObjectName("RegistryBodyText")
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
        lbl_ins = QLabel("Rankings")
        lbl_ins.setObjectName("RegistryStrongTitle")
        hdr.addWidget(lbl_ins)
        hdr.addStretch()
        self.btn_expand_insights = make_action_button(
            "Expand table",
            object_name="SummaryExpandButton",
            enabled=False,
        )
        self.btn_expand_insights.clicked.connect(self._expand_insight_current)
        hdr.addWidget(self.btn_expand_insights)
        il.addLayout(hdr)

        self._insight_groups: list[tuple[str, list[tuple[str, str, tuple[str, str]]]]] = [
            (
                "Endpoints",
                [
                    ("Top Src", "top_src", ("IP", "Count")),
                    ("Top Dst", "top_dst", ("IP", "Count")),
                ],
            ),
            (
                "Applications & protocols",
                [
                    ("Apps", "top_app", ("App", "Count")),
                    ("Protocols", "top_proto", ("Protocol", "Count")),
                ],
            ),
            (
                "Volume",
                [
                    ("Bytes Src", "top_bytes_src", ("Source", "Bytes")),
                    ("Bytes Dst", "top_bytes_dst", ("Destination", "Bytes")),
                    ("Bytes App", "top_bytes_app", ("App", "Bytes")),
                ],
            ),
        ]
        self._tab_defs = [tab for _group, tabs in self._insight_groups for tab in tabs]

        self.ins_group_tabs = QTabWidget()
        self.ins_group_tabs.setDocumentMode(True)
        self.ins_tabs_by_group: list[QTabWidget] = []
        for group_name, tabs in self._insight_groups:
            inner = QTabWidget()
            inner.setDocumentMode(True)
            for title, _key, _hdrs in tabs:
                inner.addTab(QWidget(), title)
            inner.currentChanged.connect(self._on_insight_tab_changed)
            self.ins_tabs_by_group.append(inner)
            self.ins_group_tabs.addTab(inner, group_name)
        self.ins_group_tabs.currentChanged.connect(self._on_insight_tab_changed)
        il.addWidget(self.ins_group_tabs)

        # Insights table
        self.pairs_model = PairsModel()
        self.pairs_view = CopyableTableView(self.app)
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
        lbl.setObjectName("RegistryStrongTitle")
        nl.addWidget(lbl)

        self.txt_note = QLabel(
            "Passive analysis only. Findings are indicative and based on metadata "
            "(IP, protocol, app, timing, volume)."
        )
        self.txt_note.setObjectName("RegistryBodyText")
        self.txt_note.setWordWrap(True)
        nl.addWidget(self.txt_note)

        rp.addWidget(note)
        rp.addStretch()

        # ---------------- Dataset content ----------------
        top = QHBoxLayout()
        lbl_full = QLabel("Full dataset")
        lbl_full.setObjectName("RegistryStrongTitle")

        self.lbl_full_hint = QLabel("")
        self.lbl_full_hint.setObjectName("Muted")
        self.lbl_full_hint.setAlignment(Qt.AlignRight | Qt.AlignVCenter)

        top.addWidget(lbl_full)
        top.addStretch()
        top.addWidget(self.lbl_full_hint)
        self.btn_expand_dataset = make_action_button("Open dataset table")
        self.btn_expand_dataset.clicked.connect(self._open_dataset_table_dialog)
        top.addWidget(self.btn_expand_dataset)
        dp.addLayout(top)

        self.lbl_dataset_disabled = QLabel(
            "Dataset view is hidden. Enable “Include full dataset” to show the full dataset table."
        )
        self.lbl_dataset_disabled.setObjectName("Muted")
        self.lbl_dataset_disabled.setWordWrap(True)
        dp.addWidget(self.lbl_dataset_disabled)

        self.table = CopyableTableView(self.app)
        self.table.setSortingEnabled(True)
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
        self.btn_expand_dataset.setEnabled(False)
        self.model.set_data([], [])
        self._render_empty()
        self._on_toggle_full(self.chk_full.isChecked())

    # ----------------- UI helpers -----------------
    def _make_stat_card(self, title: str, value: str) -> QFrame:
        card = QFrame()
        card.setObjectName("Card")
        card.setFixedHeight(64)
        l = QVBoxLayout(card)
        l.setContentsMargins(12, 7, 12, 7)
        l.setSpacing(0)

        t = QLabel(title)
        t.setObjectName("Muted")

        v = QLabel(value)
        v.setObjectName("RegistryMetricValue")
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

        self._summary = compute_registry_summary(self._flows, top_n=100)
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
        self.btn_expand_dataset.setEnabled(bool(self._flows))
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
        self.btn_expand_insights.setEnabled(False)
        self.lbl_deviation.setText("Traffic pattern flags")
        self.lbl_flags_body.setText("")
        self.lbl_period_context.setText("")
        self.deviation_bar.setValue(0)
        self.lbl_analyst_body.setText("")
        self.lbl_day_section.setText("")
        self.btn_expand_daily_activity.setEnabled(False)
        self._daily_activity_rows = []
        self.lbl_activity_text.setText("")
        self.lbl_dir_text.setText("")
        self.dir_bar.set_pcts(0.0, 0.0)

        self._hist_mode = "bytes"
        self._hour_filter = None
        self._last_activity = {}
        self.hist24.set_mode("bytes")
        self.hist24.set_quiet_hours([])
        self.hist24.set_values([0] * 24)
        self.btn_expand_dataset.setEnabled(False)

        self.lbl_dataset_disabled.setVisible(True)
        self.table.setVisible(False)
        self._compare_result = None

    def _render_meta(self):
        from core.case_metadata import LAWFUL_INTERCEPTION_DATES_LABEL

        if not self._folder:
            self._render_empty()
            return

        self.lbl_folder.setText("Order and target metadata from the loaded JSON dataset.")
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
                "<span style='display:inline-block;margin:0 10px 8px 0;font-size:12px;'>"
                f"<b>{ll}:</b> {vv}"
                "</span>"
            )

        chips = [
            chip("Klasa", klasa),
            chip("Urbroj", urbroj),
            chip("Target", f"{target} ({targettype})" if target or targettype else "—"),
            chip("LIID", liid),
        ]
        if bt or et:
            chips.append(chip(LAWFUL_INTERCEPTION_DATES_LABEL, f"{_fmt_dt_short(bt)} → {_fmt_dt_short(et)}"))

        self.lbl_meta_chips.setText(
            "  |  ".join(
                [
                    f"Klasa: {klasa or '-'}",
                    f"Urbroj: {urbroj or '-'}",
                    f"Target: {f'{target} ({targettype})' if target or targettype else '-'}",
                    f"LIID: {liid or '-'}",
                    (
                        f"{LAWFUL_INTERCEPTION_DATES_LABEL}: {_fmt_dt_short(bt)} -> {_fmt_dt_short(et)}"
                        if bt or et
                        else ""
                    ),
                ]
            ).strip("  |")
        )

    def _render_stats(self):
        s = self._summary or {}
        total_flows = safe_int(s.get("total_flows", len(self._flows)))

        uniq_src = len({str(f.get("src_ip") or "") for f in self._flows if f.get("src_ip")})
        uniq_dst = len({str(f.get("dst_ip") or "") for f in self._flows if f.get("dst_ip")})
        uniq_apps = len({str(f.get("application_name") or "") for f in self._flows if f.get("application_name")})

        total_bytes = s.get("total_bytes", None)
        if total_bytes is None:
            total_bytes = sum(safe_int(f.get("bidirectional_bytes")) for f in self._flows)

        self._set_stat(self.card_total, str(total_flows))
        self._set_stat(self.card_usrc, str(uniq_src))
        self._set_stat(self.card_udst, str(uniq_dst))
        self._set_stat(self.card_uapps, str(uniq_apps))
        self._set_stat(self.card_bytes, human_bytes(total_bytes))    

    def _render_analyst(self):
        a = self._analyst or {}
        if not a:
            self.lbl_deviation.setText("Traffic pattern flags")
            self.lbl_flags_body.setText("No pattern flags for the loaded period.")
            self.lbl_period_context.setText("")
            self.lbl_analyst_body.setText("No activity summary available.")
            self.lbl_day_section.setText("")
            self.lbl_activity_text.setText("")
            self.lbl_dir_text.setText("")
            self.dir_bar.set_pcts(0.0, 0.0)
            self._last_activity = {}
            self.btn_expand_daily_activity.setEnabled(False)
            self._daily_activity_rows = []

            self._hist_mode = "bytes"
            self._hour_filter = None
            self.hist24.set_mode("bytes")
            self.hist24.set_quiet_hours([])
            self.hist24.set_values([0] * 24)
            return

        deviation = a.get("behavior_deviation", {}) or {}
        reasons = list(deviation.get("reasons", []) or [])
        self.lbl_deviation.setText("Traffic pattern flags")
        if reasons:
            rs = "".join(f"<li>{html.escape(str(r))}</li>" for r in reasons)
            self.lbl_flags_body.setText(
                "<ul style='margin:4px 0 6px 18px;'>" + rs + "</ul>"
            )
        else:
            self.lbl_flags_body.setText(
                "<span>No unusual traffic pattern flags detected for the loaded period.</span>"
            )

        cov = a.get("coverage", {}) or {}
        dom = a.get("dominant_app", {}) or {}

        dom_b = (dom.get("by_bytes", {}) or {})
        dom_c = (dom.get("by_count", {}) or {})
        dom_text = (
            f"<b>Dominant app:</b> {html.escape(str(dom_b.get('name','—')))} "
            f"({float(dom_b.get('share_pct',0.0)):.1f}% bytes) "
            f"<span>(count: {html.escape(str(dom_c.get('name','—')))}, "
            f"{float(dom_c.get('share_pct',0.0)):.1f}%)</span>"
        )

        # ---- bytes direction ----
        bytes_s = a.get("bytes", {}) or {}
        out_share = float(bytes_s.get("outbound_share_total_pct", 0.0) or 0.0)

        dirb = bytes_s.get("direction_bar", {}) or {}
        out_b = human_bytes(dirb.get("outbound_bytes", 0))
        in_b = human_bytes(dirb.get("inbound_bytes", 0))
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

        controller = getattr(self.app, "dataset_controller", None)
        active_day = str(getattr(controller, "_json_active_day", "") or "") if controller is not None else ""
        period_mode = str(getattr(controller, "_json_period_granularity", "day") or "day")
        from core.evidence_policy import format_period_day_label

        if active_day:
            period_label = format_period_day_label(active_day) or active_day
            flow_count = len(self._flows)
            if period_mode == "month":
                self.lbl_period_context.setText(
                    f"Month aggregate: {period_label} · {flow_count:,} flows loaded from selected JSON period"
                )
            else:
                self.lbl_period_context.setText(
                    f"Day view: {period_label} · {flow_count:,} flows loaded"
                )
        else:
            self.lbl_period_context.setText(f"{len(self._flows):,} flows loaded")

        coverage_parts = [f"{int(cov.get('total_flows', 0) or 0):,} flows in loaded period"]
        if active_day:
            coverage_parts.append(f"Period: {format_period_day_label(active_day) or active_day}")

        if period_mode != "month":
            avg_flows_per_active_day = float(cov.get("avg_flows_per_active_day", 0.0) or 0.0)
            if avg_flows_per_active_day > 0:
                coverage_parts.append(f"{avg_flows_per_active_day:.1f} flows/day avg")

        coverage_html = (
            f"<b>Traffic summary:</b> " + " | ".join(coverage_parts) + " | "
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
            f"{coverage_html}<br>"
            f"{compare_html}"
            f"{novelty_html}"
            f"{dom_text}<br>"
            f"{dominance_html}"
        )

        self.lbl_analyst_body.setText(analyst_html)

        self._daily_activity_rows = _daily_activity_rows(day_hist, day_bytes)
        self.lbl_day_section.setText(_daily_activity_preview_html(self._daily_activity_rows))
        total_days = len(self._daily_activity_rows)
        self.btn_expand_daily_activity.setEnabled(embedded_expand_available(total_days))
        self.btn_expand_daily_activity.setToolTip(
            embedded_expand_tooltip(total_days, preview_rows=EMBEDDED_SUMMARY_TOP_N)
        )

        self.lbl_hist_title.setText(
            "Hourly pattern (loaded period · by bytes)"
            if self._hist_mode == "bytes"
            else "Hourly pattern (loaded period · by flows)"
        )

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

    def _expand_daily_activity(self) -> None:
        if not self._daily_activity_rows:
            return
        open_project_rows_dialog(
            self.app,
            "Daily activity by volume",
            [
                ("date_label", "Date"),
                ("flows", "Flows"),
                ("bytes_label", "Volume"),
                ("bytes", "Bytes (raw)"),
            ],
            self._daily_activity_rows,
            export_source_label=str(self._folder or ""),
        )

    def _apply_hist_mode(self):
        act = self._last_activity or {}

        if self._hist_mode == "flows":
            self.lbl_hist_title.setText("Hourly pattern (loaded period · by flows)")
            hh = act.get("hour_hist_24") or act.get("hour_hist") or [0] * 24
            self.hist24.set_mode("flows")
        else:
            self.lbl_hist_title.setText("Hourly pattern (loaded period · by bytes)")
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

    def _format_insight_rows(self, key: str, rows: list[tuple[Any, Any]]) -> list[tuple[Any, Any]]:
        formatted = list(rows or [])
        if key == "top_proto":
            formatted = [(format_ip_proto(k), v) for (k, v) in formatted]
        if key in ("top_bytes_src", "top_bytes_dst", "top_bytes_app"):
            formatted = [(k, bytes_mb_or_b(v, precision=2)) for (k, v) in formatted]
        return formatted

    def _current_insight_tab_def(self) -> tuple[str, str, tuple[str, str]] | None:
        group_idx = self.ins_group_tabs.currentIndex()
        if group_idx < 0 or group_idx >= len(self._insight_groups):
            return None
        inner = self.ins_tabs_by_group[group_idx]
        tab_idx = inner.currentIndex()
        tabs = self._insight_groups[group_idx][1]
        if tab_idx < 0 or tab_idx >= len(tabs):
            return None
        return tabs[tab_idx]

    def _render_insight_current(self):
        if not self._summary:
            self.pairs_model.set_rows([], headers=("Item", "Value"))
            self._fit_pairs_height(0)
            self.btn_expand_insights.setEnabled(False)
            return

        current = self._current_insight_tab_def()
        if current is None:
            self.pairs_model.set_rows([], headers=("Item", "Value"))
            self._fit_pairs_height(0)
            self.btn_expand_insights.setEnabled(False)
            return

        title, key, hdrs = current
        all_rows = list(self._summary.get(key, []) or [])
        rows = self._format_insight_rows(key, all_rows[:EMBEDDED_SUMMARY_TOP_N])
        self.pairs_model.set_rows(rows, headers=hdrs)

        # ergonomics
        self.pairs_view.setColumnWidth(0, 620)
        self.pairs_view.setColumnWidth(1, 180)

        self._fit_pairs_height(len(rows))
        total = len(all_rows)
        self.btn_expand_insights.setEnabled(embedded_expand_available(total))
        self.btn_expand_insights.setToolTip(
            embedded_expand_tooltip(total, preview_rows=EMBEDDED_SUMMARY_TOP_N)
        )

    def _expand_insight_current(self) -> None:
        if not self._summary:
            return
        current = self._current_insight_tab_def()
        if current is None:
            return
        title, key, hdrs = current
        all_rows = list(self._summary.get(key, []) or [])
        if not all_rows:
            return
        formatted = self._format_insight_rows(key, all_rows)
        open_project_rows_dialog(
            self.app,
            f"{title} — full table",
            [
                ("item", hdrs[0]),
                ("value", hdrs[1]),
            ],
            [{"item": row[0], "value": row[1]} for row in formatted],
            export_source_label=str(self._folder or ""),
        )

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

        show = max(1, min(EMBEDDED_SUMMARY_TOP_N, n_rows))
        h = header_h + (rh * show) + 14
        self.pairs_view.setFixedHeight(h)

    def _export_period_context(self) -> str:
        controller = getattr(self.app, "dataset_controller", None)
        active_day = str(getattr(controller, "_json_active_day", "") or "") if controller is not None else ""
        period_mode = str(getattr(controller, "_json_period_granularity", "day") or "day")
        from core.evidence_policy import format_period_day_label

        flow_count = len(self._flows)
        if not active_day:
            return f"{flow_count:,} flows loaded"
        period_label = format_period_day_label(active_day) or active_day
        if period_mode == "month":
            return f"Month aggregate: {period_label} · {flow_count:,} flows loaded from selected JSON period"
        return f"Day view: {period_label} · {flow_count:,} flows loaded"

    # ----------------- export -----------------
    def export_report(self):
        if not self._folder or not self._flows:
            return

        default_name = "ViaNyquist_Registry_Report.html"
        project = self._current_project()
        default_path = (
            str(workspace_export_path(project.base_folder, default_name, category="json"))
            if project and project.base_folder
            else str(self._folder / default_name)
        )
        out_path, _ = QFileDialog.getSaveFileName(
            self,
            "Export report",
            default_path,
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
                project=project,
                project_name=getattr(self.app, "current_project_name", "") or "",
                period_context=self._export_period_context(),
            )

            QMessageBox.information(self, "Export", f"Report saved:\n{out_path}")

        except Exception as e:
            QMessageBox.critical(self, "Export failed", str(e))

    def _dialog_size(self, preferred_width: int, preferred_height: int) -> tuple[int, int]:
        screen = QApplication.primaryScreen()
        if screen is None:
            return preferred_width, preferred_height
        available = screen.availableGeometry()
        width = min(preferred_width, max(760, available.width() - 120))
        height = min(preferred_height, max(520, available.height() - 120))
        return width, height

    def _open_dataset_table_dialog(self):
        if not self._flows or not self._cols:
            QMessageBox.information(self, "Dataset table", "No dataset rows are loaded.")
            return

        dlg = QDialog(self)
        dlg.setWindowTitle("Registry dataset table")
        dlg.resize(*self._dialog_size(1240, 760))

        layout = QVBoxLayout(dlg)
        layout.setContentsMargins(14, 14, 14, 28)
        layout.setSpacing(10)

        hint = QLabel(
            "Expanded JSON dataset view. Sort columns, select rows, double-click a flow to open it in Explore, "
            "or right-click to copy values."
        )
        hint.setObjectName("Muted")
        hint.setWordWrap(True)
        layout.addWidget(hint)

        table = CopyableTableView(self.app)
        table.setAlternatingRowColors(True)
        table.setSortingEnabled(True)
        table.setSelectionBehavior(QTableView.SelectRows)
        table.setSelectionMode(QTableView.SingleSelection)
        table.setWordWrap(False)
        table.verticalHeader().setVisible(True)
        table.verticalHeader().setDefaultSectionSize(34)
        table.horizontalHeader().setSectionResizeMode(QHeaderView.Interactive)
        table.horizontalHeader().setStretchLastSection(False)

        model = RegistryTableModel()
        model.set_data(list(self._flows), list(self._cols))
        proxy = TextFilterProxy()
        proxy.setSourceModel(model)
        proxy.set_query(self.txt_search.text())
        proxy.set_hour_filter(getattr(self, "_hour_filter", None))
        table.setModel(proxy)
        table.doubleClicked.connect(lambda idx: self._open_expanded_dataset_row(idx, proxy, model))

        for col, key in enumerate(self._cols):
            table.setColumnWidth(col, self._dataset_column_width(key))

        layout.addWidget(table, 1)

        footer = QHBoxLayout()
        append_table_export_footer(
            self,
            footer,
            title="Registry dataset",
            table=table,
            project_id=getattr(self.app, "current_project_id", None),
            category="json",
            source_label=str(self._folder or ""),
        )
        footer.addStretch()
        btn_close = make_dialog_button("Close")
        btn_close.clicked.connect(dlg.accept)
        footer.addWidget(btn_close)
        layout.addSpacing(6)
        layout.addLayout(footer)

        dlg.exec()

    def _open_expanded_dataset_row(
        self,
        index: QModelIndex,
        proxy: TextFilterProxy,
        model: RegistryTableModel,
    ):
        if not index.isValid():
            return
        src_index = proxy.mapToSource(index)
        try:
            flow = model._rows[src_index.row()]
        except Exception:
            return
        src = str(flow.get("src_ip") or "")
        dst = str(flow.get("dst_ip") or "")
        if src and dst:
            self.openExploreWithConversation.emit(src, dst)

    def _dataset_column_width(self, key: str) -> int:
        name = str(key or "").lower()
        if "time" in name or "date" in name:
            return 170
        if name in {"src_ip", "dst_ip"} or name.endswith("_ip"):
            return 150
        if "port" in name or "proto" in name or "packet" in name:
            return 120
        if "byte" in name:
            return 130
        if "app" in name or "host" in name or "sni" in name or "domain" in name:
            return 230
        if "url" in name or "path" in name or "user" in name:
            return 300
        return 150

    def _current_project(self):
        project_id = getattr(self.app, "current_project_id", None)
        if project_id is None:
            return None
        return get_project(project_id)

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

        current = self._current_insight_tab_def()
        if current is None:
            return

        title, key, _hdrs = current
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
