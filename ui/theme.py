from __future__ import annotations

from pathlib import Path

from PySide6.QtWidgets import QApplication

from ui.app_helpers import normalize_ui_theme
from ui.font_utils import app_font, install_font_sanitizer

LIGHT_THEME_OVERRIDES = """
QWidget {
    background: #f4f7fb;
    color: #111827;
}

QLabel {
    background: transparent;
    color: #111827;
}

QFrame#Card,
QFrame#ProfileHero,
QFrame#ProfilePanel,
QFrame#ExploreHeaderCard,
QFrame#ListingHeaderCard,
QFrame#CaseDashboardCompact,
QFrame#PanelCard,
QFrame#FlowDetailsCard,
QFrame#FlowToolbarCard,
QFrame#NotesEditorPanel,
QFrame#NotesEditorContent,
QFrame#NotesListPanel,
QFrame#NotesPreviewPanel,
QFrame#PcapInvestigatorCard,
QGroupBox {
    background: #ffffff;
    border-color: #cbd5e1;
}

QFrame#Card QLabel,
QFrame#ProfileHero QLabel,
QFrame#ProfilePanel QLabel,
QFrame#ExploreHeaderCard QLabel,
QFrame#ListingHeaderCard QLabel,
QFrame#CaseDashboardCompact QLabel,
QFrame#PanelCard QLabel,
QFrame#PcapInvestigatorCard QLabel,
QFrame#FlowToolbarCard QLabel,
QFrame#NotesEditorPanel QLabel,
QFrame#NotesEditorContent QLabel,
QFrame#NotesListPanel QLabel,
QFrame#NotesPreviewPanel QLabel,
QGroupBox QLabel {
    background: transparent;
    color: #111827;
}

QLabel#H1,
QLabel#SectionTitle,
QLabel#ProfileTitle,
QLabel#ProfilePanelTitle,
QLabel#CaseDashboardTitle,
QLabel#HeaderProjectLabel,
QLabel#DialogMessageLabel,
QLabel#DialogSectionLabel {
    background: transparent;
    color: #0f172a;
}

QLabel#Muted,
QLabel#ProfileSubtitle,
QLabel#HeaderPathLabel,
QLabel#HeaderStatLabel,
QLabel#PcapKeyPoints,
QLabel#PcapLimitations,
QLabel#FlowFieldLabel,
QLabel#MutedLabel,
QLabel#DialogDetailsLabel {
    background: transparent;
    color: #475569;
}

QLabel#PcapPlainSummary {
    background: transparent;
    color: #111827;
}

QLabel#PcapLoadingStatus {
    background: transparent;
    color: #16a34a;
}

QLabel#ProfileMetric,
QLabel#CaseMetricCompact {
    background: #f8fafc;
    border: 1px solid #cbd5e1;
    color: #0f172a;
}

QFrame#ProfileEvidencePanel {
    background: #f8fafc;
    border: 1px solid #cbd5e1;
}

QWidget#ProfileEvidenceCell {
    background: transparent;
}

QFrame#ProfileEvidenceDivider {
    background: #e2e8f0;
    border: none;
}

QLabel#ProfileEvidenceMetricTitle {
    background: transparent;
    color: #0f172a;
    font-size: 12px;
    font-weight: 700;
}

QLabel#ProfileEvidenceMetricBody {
    background: transparent;
    color: #475569;
    font-size: 11px;
    font-weight: 400;
}

QFrame#ProfileCountRow {
    background: #f8fafc;
    border-color: #cbd5e1;
}

QLabel#ProfileCountBadge {
    background: #3b82f6;
    color: #ffffff;
}

QLabel#RegistryStrongTitle {
    background: transparent;
    color: #0f172a;
}

QLabel#RegistryMetricValue {
    background: transparent;
    color: #0f172a;
}

QLabel#RegistryDeviationLabel {
    background: transparent;
    color: #334155;
}

QLabel#RegistryBodyText,
QLabel#RegistrySmallTitle {
    background: transparent;
    color: #475569;
}

QProgressBar#RegistryDeviationBar {
    background: #e2e8f0;
    border: 1px solid #cbd5e1;
    color: #0f172a;
}

QProgressBar#RegistryDeviationBar::chunk {
    background: #3b82f6;
}

QLineEdit,
QTextEdit,
QPlainTextEdit,
QComboBox,
QListWidget,
QTableView {
    background: #ffffff;
    color: #111827;
    border-color: #cbd5e1;
}

QComboBox#CompactControl,
QLineEdit#CompactControl {
    background: #ffffff;
    color: #111827;
    border: 1px solid #cbd5e1;
}

QComboBox#CompactControl:focus,
QLineEdit#CompactControl:focus {
    border-color: #2563eb;
}

QComboBox#CompactControl::drop-down {
    border: none;
    background: transparent;
}

QComboBox#CompactControl QAbstractItemView {
    background: #ffffff;
    color: #111827;
    border: 1px solid #cbd5e1;
    selection-background-color: #3b82f6;
    selection-color: #ffffff;
}

QTextEdit#SummaryTextBox,
QPlainTextEdit#SummaryTextBox {
    background: transparent;
    color: #334155;
    border: none;
}

QLineEdit:focus,
QTextEdit:focus,
QPlainTextEdit:focus,
QComboBox:focus {
    border-color: #2563eb;
}

QLineEdit#SettingsField,
QComboBox#SettingsField {
    min-height: 28px;
    max-height: 28px;
    padding: 4px 8px;
    border-radius: 8px;
    background: #ffffff;
    color: #111827;
    border: 1px solid #cbd5e1;
}

QComboBox#SettingsField::drop-down {
    border: none;
    background: transparent;
}

QComboBox#SettingsField QAbstractItemView,
QComboBox#SettingsField QListView {
    background-color: #ffffff;
    color: #111827;
    border: 1px solid #cbd5e1;
    selection-background-color: #3b82f6;
    selection-color: #ffffff;
    outline: none;
}

QComboBox#SettingsField QAbstractItemView::item,
QComboBox#SettingsField QListView::item {
    color: #111827;
    background-color: #ffffff;
    min-height: 24px;
    padding: 4px 8px;
}

QComboBox#SettingsField QAbstractItemView::item:selected,
QComboBox#SettingsField QListView::item:selected {
    background-color: #3b82f6;
    color: #ffffff;
}

QComboBox#SettingsField QAbstractItemView::item:hover,
QComboBox#SettingsField QListView::item:hover {
    background-color: #eff6ff;
    color: #111827;
}

QLabel#SettingsFieldLabel,
QLabel#DialogFieldLabel {
    font-size: 12px;
    font-weight: 600;
    color: #94a3b8;
}

QFrame#SettingsSectionRule {
    color: #cbd5e1;
    background: #cbd5e1;
    border: none;
    margin: 4px 0 2px;
}

QComboBox QAbstractItemView,
QComboBox QListView {
    background-color: #ffffff;
    color: #111827;
    border: 1px solid #cbd5e1;
    selection-background-color: #3b82f6;
    selection-color: #ffffff;
    outline: none;
}

QComboBox QAbstractItemView::item,
QComboBox QListView::item {
    color: #111827;
    background-color: #ffffff;
    min-height: 24px;
    padding: 4px 8px;
}

QComboBox QAbstractItemView::item:selected,
QComboBox QListView::item:selected {
    background-color: #3b82f6;
    color: #ffffff;
}

QComboBox QAbstractItemView::item:hover,
QComboBox QListView::item:hover {
    background-color: #eff6ff;
    color: #111827;
}

QTabWidget::pane {
    background: #ffffff;
    border-color: #cbd5e1;
}

QTabBar::tab {
    background: #e2e8f0;
    border-color: #cbd5e1;
    color: #334155;
}

QTabBar::tab:hover {
    background: #dbeafe;
    color: #0f172a;
}

QTabBar::tab:selected {
    background: #ffffff;
    color: #0f172a;
}

QHeaderView::section {
    background: #e2e8f0;
    color: #111827;
    border-color: #cbd5e1;
}

QTableView {
    alternate-background-color: #f1f5f9;
    gridline-color: #cbd5e1;
    selection-background-color: #3b82f6;
    selection-color: #ffffff;
}

QTableView QTableCornerButton::section {
    background: #e2e8f0;
    border: 1px solid #cbd5e1;
}

QPushButton {
    background: #eff6ff;
    color: #1d4ed8;
    border: 1px solid #3b82f6;
}

QPushButton:hover {
    background: #dbeafe;
    border: 1px solid #2563eb;
    color: #1e40af;
}

QPushButton:disabled {
    background: #f1f5f9;
    border: 1px solid #d7dee9;
    color: #94a3b8;
}

QPushButton#ProjectToolbarButton {
    background: #3b82f6;
    border: 1px solid #3b82f6;
    color: #ffffff;
}

QPushButton#ProjectToolbarButton:hover {
    background: #2563eb;
    border: 1px solid #2563eb;
}

QPushButton#ProjectToolbarButton:disabled {
    background: #f1f5f9;
    border: 1px solid #d7dee9;
    color: #94a3b8;
}

QToolButton#RoundRefreshToolButton {
    background: #eff6ff;
    border: 1px solid #3b82f6;
    color: #1d4ed8;
}

QToolButton#RoundRefreshToolButton:hover {
    background: #dbeafe;
    border: 1px solid #2563eb;
    color: #1e40af;
}

QToolButton#RoundRefreshToolButton:disabled {
    background: #f1f5f9;
    border: 1px solid #d7dee9;
    color: #94a3b8;
}

QToolButton#CompactToolButton {
    background: #eff6ff;
    border: 1px solid #3b82f6;
    color: #1d4ed8;
}

QToolButton#CompactToolButton:hover {
    background: #dbeafe;
    border: 1px solid #2563eb;
    color: #1e40af;
}

QPushButton#NavButton {
    background: transparent;
    color: #111827;
    border: none;
}

QFrame#SidebarFrame {
    background: transparent;
    border-right: 1px solid #cbd5e1;
}

QPushButton#NavButton:hover {
    background: #e2e8f0;
    border: 1px solid #cbd5e1;
}

QPushButton#NavButton[active="true"] {
    background: #3b82f6;
    color: #ffffff;
}

QLabel#ProjectSelectionBadge {
    background: #eff6ff;
    border: 1px solid #93c5fd;
    border-radius: 8px;
    color: #1d4ed8;
    padding: 2px 8px;
}

QPushButton#CompactButton,
QPushButton#CompactDangerButton,
QPushButton#RepositoryActionButton,
QPushButton#RepositoryDangerButton,
QPushButton#SetActiveButton {
    padding: 4px 10px;
    min-height: 0;
    max-height: 32px;
}

QPushButton#SetActiveButton:disabled {
    background: #f1f5f9;
    border-color: #d7dee9;
    color: #94a3b8;
}

QToolButton#CompactToolButton {
    padding: 2px;
    min-height: 0;
    max-width: 32px;
    max-height: 32px;
}

QProgressBar {
    background: #e2e8f0;
    border-color: #cbd5e1;
}

QProgressBar::chunk {
    background: #3b82f6;
}

QScrollArea,
QScrollArea QWidget {
    background: transparent;
}

QSplitter::handle {
    background: #cbd5e1;
}

QSplitter::handle:hover {
    background: #94a3b8;
}

QScrollBar:vertical,
QScrollBar:horizontal {
    background: #f1f5f9;
    border: 1px solid #cbd5e1;
    margin: 0;
}

QScrollBar::handle:vertical,
QScrollBar::handle:horizontal {
    background: #cbd5e1;
    border-radius: 4px;
    min-height: 24px;
    min-width: 24px;
}

QScrollBar::handle:vertical:hover,
QScrollBar::handle:horizontal:hover {
    background: #94a3b8;
}

QScrollBar::add-line,
QScrollBar::sub-line,
QScrollBar::add-page,
QScrollBar::sub-page {
    background: transparent;
    border: none;
}

QFrame#FlowToolbarCard,
QGroupBox#SummaryCard,
QGroupBox#FlowDetailsCard,
QFrame#NotesEditorPanel,
QFrame#ListingHeaderCard {
    background: #ffffff;
    border: 1px solid #cbd5e1;
    color: #111827;
}

QGroupBox::title,
QGroupBox#SummaryCard::title,
QGroupBox#FlowDetailsCard::title {
    background: #ffffff;
    color: #0f172a;
}

QFrame#InvestigationSnapshotCard {
    background: #ffffff;
    border: 1px solid #60a5fa;
    color: #111827;
}

QFrame#InvestigationSnapshotCard QLabel {
    background: transparent;
    color: #111827;
}

QLabel#InvestigationSnapshotEmpty {
    color: #0f172a;
    font-size: 13px;
    font-weight: 600;
}

QFrame#InvestigationSnapshotCard QScrollArea,
QScrollArea#InvestigationSnapshotScroll,
QWidget#InvestigationSnapshotContent {
    background: #ffffff;
    border: none;
}

QScrollArea#InvestigationSnapshotScroll QAbstractScrollArea::viewport {
    background: #ffffff;
}

QLabel#InvestigationSnapshotHeadline {
    color: #0f172a;
}

QLabel#InvestigationSnapshotBody {
    color: #334155;
}

QGroupBox#SummaryCard:hover {
    background: #f8fafc;
}

QLabel#SummaryPreviewName,
QLabel#SummaryPreviewCount {
    color: #334155;
}

QFrame#PcapInvestigatorCard {
    border: 1px solid #60a5fa;
}

QScrollArea#PcapInvestigatorSummaryScroll,
QWidget#PcapInvestigatorSummaryBody {
    background: #ffffff;
    border: none;
}

QScrollArea#PcapInvestigatorSummaryScroll QAbstractScrollArea::viewport {
    background: #ffffff;
}

QLabel#FlowFieldValue {
    background: #f8fafc;
    border: 1px solid #cbd5e1;
    color: #111827;
}

QLabel#Signature {
    color: #64748b;
}

QPushButton:disabled {
    background: #f1f5f9;
    border-color: #d7dee9;
    color: #94a3b8;
}

QPushButton#NotesToolButton,
QPushButton#NotesColorButton {
    background: #ffffff;
    border: 1px solid #cbd5e1;
    color: #111827;
}

QPushButton#NotesColorButton {
    color: #ef4444;
}

QPushButton#NotesToolButton:hover,
QPushButton#NotesColorButton:hover {
    background: #e2e8f0;
}

QPushButton#NotesToolButton:checked {
    background: #3b82f6;
    border-color: #2563eb;
    color: #ffffff;
}

QLabel#NotesPanelLabel {
    color: #475569;
}

QSpinBox {
    background: #ffffff;
    color: #111827;
    border: 1px solid #cbd5e1;
    border-radius: 10px;
    padding: 6px 8px;
    selection-background-color: #3b82f6;
    selection-color: #ffffff;
}

QSpinBox:focus {
    border-color: #2563eb;
}

QCheckBox {
    color: #111827;
    spacing: 8px;
}

QCheckBox::indicator {
    width: 18px;
    height: 18px;
    border: 1px solid #94a3b8;
    border-radius: 5px;
    background: #ffffff;
}

QCheckBox::indicator:hover {
    border-color: #2563eb;
    background: #eff6ff;
}

QCheckBox::indicator:unchecked {
    border: 1px solid #94a3b8;
    border-radius: 5px;
    background: #ffffff;
}

QCheckBox::indicator:checked {
    border: 1px solid #2563eb;
    border-radius: 5px;
    background-color: #3b82f6;
}

QTableView::item {
    color: #111827;
}

QTableView::item:selected {
    background: #3b82f6;
    color: #ffffff;
}

QListWidget::item {
    color: #111827;
}

QListWidget::item:hover {
    background: #e2e8f0;
}

QListWidget::item:selected {
    background: #3b82f6;
    color: #ffffff;
}

QMenu,
QDialog,
QMessageBox,
QInputDialog,
QFileDialog {
    background: #f8fafc;
    color: #111827;
}

QMenu::item:selected {
    background: #3b82f6;
    color: #ffffff;
}

QDialog QLabel,
QMessageBox QLabel,
QInputDialog QLabel {
    background: transparent;
    color: #111827;
}

QDialog QLineEdit,
QDialog QPlainTextEdit,
QDialog QComboBox,
QDialog QLineEdit#DialogField,
QDialog QPlainTextEdit#DialogField,
QDialog QComboBox#DialogField {
    background: #ffffff;
    border-color: #cbd5e1;
    color: #111827;
}
"""

COMBO_POPUP_LIGHT_QSS = """
QListView {
    background-color: #ffffff;
    color: #111827;
    border: 1px solid #cbd5e1;
    outline: none;
}
QListView::item {
    color: #111827;
    background-color: #ffffff;
    padding: 6px 8px;
}
QListView::item:selected {
    background-color: #3b82f6;
    color: #ffffff;
}
QListView::item:hover {
    background-color: #eff6ff;
    color: #111827;
}
"""


def polish_combo_popups(root, theme: str | None = "dark") -> None:
    """Combo dropdown lists are separate views; give them explicit light styling."""
    from PySide6.QtWidgets import QComboBox, QWidget

    if not isinstance(root, QWidget):
        return
    popup_qss = COMBO_POPUP_LIGHT_QSS if normalize_ui_theme(theme) == "light" else ""
    for combo in root.findChildren(QComboBox):
        view = combo.view()
        if view is not None:
            view.setStyleSheet(popup_qss)


def app_stylesheet(theme: str | None = "dark") -> str:
    qss_path = Path(__file__).resolve().parent / "style.qss"
    if not qss_path.exists():
        return ""
    qss = qss_path.read_text(encoding="utf-8")
    if normalize_ui_theme(theme) == "light":
        qss += "\n\n/* light theme overrides */\n" + LIGHT_THEME_OVERRIDES
    return qss

def apply_app_stylesheet(qapp: QApplication, theme: str | None = "dark") -> None:
    normalized_theme = normalize_ui_theme(theme)
    qapp.setProperty("ui_theme", normalized_theme)
    qapp.setFont(app_font(point_size=10))
    qapp.setStyleSheet(app_stylesheet(normalized_theme))
    install_font_sanitizer(qapp)
    for widget in qapp.topLevelWidgets():
        polish_combo_popups(widget, normalized_theme)
