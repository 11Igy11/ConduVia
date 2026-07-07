from PySide6.QtWidgets import QWidget, QVBoxLayout, QLabel, QFrame, QTableView, QHeaderView, QHBoxLayout, QComboBox, QFileDialog, QInputDialog, QMenu
from ui.buttons import make_action_button
from ui.column_picker_dialog import ColumnPickerDialog
from ui.dialogs import message_dialog
from ui.export_menu import popup_export_menu
from PySide6.QtCore import Qt, QAbstractTableModel, QModelIndex
from core.formatters import (
    format_duration_compact_ms,
    format_export_cell,
    format_flow_date,
    format_flow_datetime,
    format_flow_time,
    human_bytes,
)
from core.protocols import format_ip_proto
from core.exporters.listing_exporter import export_listing_csv, export_listing_excel, export_listing_html
from core.db import get_app_settings, get_project, get_app_setting, set_app_setting
from core.parser import extract_dataset_meta
from core.timeutils import parse_timestamp
from ui.explore_widgets import CopyableTableView
from ui.table_export import notify_export_error, notify_export_empty, notify_export_success, table_export_default_path


class ListingTableModel(QAbstractTableModel):
    HEADER_LABELS = {
            "date": "Date",
            "time": "Time",
            "src_ip": "Source IP",
            "src_port": "Source Port",
            "dst_ip": "Destination IP",
            "dst_port": "Destination Port",
            "protocol": "Protocol",
            "application_name": "Application",
            "requested_server_name": "Server Name",
            "bidirectional_bytes": "Volume",
            "bidirectional_packets": "Packets",
            "bidirectional_duration_ms": "Duration",
        }
    FRIENDLY_OVERRIDES = {
            "id": "ID",
            "expiration_id": "Expiration ID",
            "src_mac": "Source MAC",
            "dst_mac": "Destination MAC",
            "src_oui": "Source OUI",
            "dst_oui": "Destination OUI",
            "ip_version": "IP Version",
            "vlan_id": "VLAN ID",
            "tunnel_id": "Tunnel ID",

            "bidirectional_first_seen_ms": "First Seen",
            "bidirectional_last_seen_ms": "Last Seen",
            "src2dst_first_seen_ms": "Src → Dst First Seen",
            "src2dst_last_seen_ms": "Src → Dst Last Seen",
            "dst2src_first_seen_ms": "Dst → Src First Seen",
            "dst2src_last_seen_ms": "Dst → Src Last Seen",

            "src2dst_duration_ms": "Src → Dst Duration",
            "dst2src_duration_ms": "Dst → Src Duration",

            "src2dst_bytes": "Src → Dst Volume",
            "dst2src_bytes": "Dst → Src Volume",

            "src2dst_packets": "Src → Dst Packets",
            "dst2src_packets": "Dst → Src Packets",
        }

    def _friendly_label(self, key: str) -> str:
        if key in self.HEADER_LABELS:
            return self.HEADER_LABELS[key]

        if key in self.FRIENDLY_OVERRIDES:
            return self.FRIENDLY_OVERRIDES[key]

        return key.replace("_", " ").title()
                         
    def __init__(self, flows=None):
        super().__init__()
        self._flows = flows or []
        self._columns = [
            "date",
            "time",
            "src_ip",
            "src_port",
            "dst_ip",
            "dst_port",
            "protocol",
            "application_name",
            "requested_server_name",
            "bidirectional_bytes",
            "bidirectional_packets",
            "bidirectional_duration_ms",
        ]    

    def set_data(self, flows):
        self.beginResetModel()
        self._flows = flows or []
        self._columns = self._detect_columns()
        self.endResetModel()

    def set_columns(self, columns):
        self.beginResetModel()
        self._columns = columns or []
        self.endResetModel()

    def _detect_columns(self):
        return list(self._columns)

        # uzmi sve ključeve iz prvog flowa
        return list(self._flows[0].keys())

    def rowCount(self, parent=QModelIndex()):
        return len(self._flows)

    def columnCount(self, parent=QModelIndex()):
        return len(self._columns)

    def headerData(self, section, orientation, role=Qt.DisplayRole):
        if section < 0:
            return None

        if orientation == Qt.Horizontal:
            if section >= len(self._columns):
                return None

            key = self._columns[section]

            if role == Qt.DisplayRole:
                return self._friendly_label(key)

            if role == Qt.ToolTipRole:
                tooltips = {
                    "date": "Connection date",
                    "time": "Connection time",
                    "src_ip": "Source IP address",
                    "src_port": "Source port",
                    "dst_ip": "Destination IP address",
                    "dst_port": "Destination port",
                    "protocol": "IP protocol",
                    "application_name": "Detected application",
                    "requested_server_name": "Server name / SNI",
                    "bidirectional_bytes": "Total traffic volume",
                    "bidirectional_packets": "Total packet count",
                    "bidirectional_duration_ms": "Duration of connection",
                }
                return tooltips.get(key, key)

        if role == Qt.DisplayRole and section < len(self._flows):
            return str(section + 1)

        return None

    def data(self, index, role=Qt.DisplayRole):
        if not index.isValid():
            return None

        row = index.row()
        col = index.column()

        if row >= len(self._flows) or col >= len(self._columns):
            return None

        key = self._columns[col]
        flow = self._flows[row]
        value = flow.get(key, "")

        if role != Qt.DisplayRole:
            return None

        if value is None:
            value = ""

        # ---------- DATE / TIME SPLIT ----------
        if key in ("date", "time"):
            raw_value = flow.get("bidirectional_first_seen_ms", "")
            if key == "date":
                return format_flow_date(raw_value) or str(raw_value)
            return format_flow_time(raw_value) or str(raw_value)
            
        # ---------- GENERIC TIMESTAMP (*_seen_ms) ----------
        if key.endswith("_seen_ms"):
            return format_flow_datetime(value)

        # ---------- BYTES ----------
        if key == "bidirectional_bytes":
            return human_bytes(value, precision=2)

        # ---------- DURATION ----------
        if key == "bidirectional_duration_ms":
            return format_duration_compact_ms(value)
            
        # ---------- PROTOCOL ----------
        if key == "protocol":
            return format_ip_proto(value)

        return str(value)
    
    def sort(self, column, order):
        key = self._columns[column]

        def get_sort_value(flow):
            value = flow.get(key)

            # ---------- DATE / TIME ----------
            if key in ("date", "time"):
                raw = flow.get("bidirectional_first_seen_ms")
                try:
                    dt = parse_timestamp(raw)
                    if dt is None:
                        return ""
                    return dt.timestamp()
                except Exception:
                    return 0

            # ---------- BYTES ----------
            if key == "bidirectional_bytes":
                try:
                    return float(value)
                except Exception:
                    return 0

            # ---------- DURATION ----------
            if key == "bidirectional_duration_ms":
                try:
                    return float(value)
                except Exception:
                    return 0

            # ---------- PORTS / PACKETS / NUMERIC ----------
            if key in ("src_port", "dst_port", "bidirectional_packets", "protocol"):
                try:
                    return float(value)
                except Exception:
                    return 0

            # ---------- DEFAULT ----------
            return str(value or "").lower()

        self.layoutAboutToBeChanged.emit()

        self._flows.sort(
            key=get_sort_value,
            reverse=(order == Qt.DescendingOrder)
        )

        self.layoutChanged.emit()        


LISTING_VIEW_PRESETS_KEY = "listing_view_presets"
LISTING_VIEW_MODES = ("Default", "All fields", "Custom")


class ListingPage(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.app = parent

        self.dataset_path = ""
        self.files = []
        self.flows = []

        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(12)

        self.lbl_dataset = QLabel("Loaded JSON summary")
        self.lbl_files = QLabel("Files: 0")
        self.lbl_flows = QLabel("Flows: 0")

        # Card container (vizualno kao Explore header)
        self.card = QFrame()
        self.card.setObjectName("ListingHeaderCard")

        card_layout = QVBoxLayout(self.card)
        card_layout.setContentsMargins(14, 12, 14, 12)
        card_layout.setSpacing(6)

        card_layout.addWidget(self.lbl_dataset)
        card_layout.addWidget(self.lbl_files)
        card_layout.addWidget(self.lbl_flows)

        # ---------- VIEW TOOLBAR ----------
        self.view_bar = QHBoxLayout()
        self.view_bar.setSpacing(10)

        self.lbl_view_mode = QLabel("View:")
        self.cmb_view_mode = QComboBox()
        self.cmb_view_mode.setMinimumWidth(160)
        self.cmb_view_mode.setSizeAdjustPolicy(QComboBox.SizeAdjustPolicy.AdjustToContents)
        self.cmb_view_mode.setMinimumContentsLength(18)
        self.cmb_view_mode.currentIndexChanged.connect(self._on_view_mode_changed)

        self.btn_customize_view = make_action_button("Customize")
        self.btn_customize_view.clicked.connect(self._open_customize_dialog)
        self.btn_customize_view.hide()

        self.btn_presets = make_action_button("Presets ▾")
        self.btn_presets.clicked.connect(self._open_presets_menu)
        self.btn_presets.hide()

        self.btn_export = make_action_button("Export table")
        self.btn_export.clicked.connect(self._open_export_dialog)

        self.view_bar.addWidget(self.lbl_view_mode)
        self.view_bar.addWidget(self.cmb_view_mode)
        self.view_bar.addWidget(self.btn_customize_view)
        self.view_bar.addWidget(self.btn_presets)
        self.view_bar.addWidget(self.btn_export)
        self.view_bar.addStretch()

        self._reload_view_mode_combo()

        layout.addLayout(self.view_bar)
        layout.addWidget(self.card)
        self.card.hide()

        # ---------- TABLE ----------
        self.table = CopyableTableView(self.app)

        self.model = ListingTableModel()
        self.table.setModel(self.model)

        self.table.setSortingEnabled(True)
        self.table.setAlternatingRowColors(True)
        self.table.setSelectionBehavior(QTableView.SelectRows)
        self.table.setSelectionMode(QTableView.SingleSelection)

        header = self.table.horizontalHeader()
        header.setStretchLastSection(False)
        header.setSectionResizeMode(QHeaderView.ResizeToContents)

        layout.addWidget(self.table, 1)
    
    DEFAULT_COLUMNS = [
        "date",
        "time",
        "src_ip",
        "src_port",
        "dst_ip",
        "dst_port",
        "protocol",
        "application_name",
        "requested_server_name",
        "bidirectional_bytes",
        "bidirectional_packets",
        "bidirectional_duration_ms",
    ]
    # ---------- DATA INPUT ----------
    def set_dataset(self, dataset_path, files, flows, compare_result=None):
        self.dataset_path = dataset_path
        self.files = files or []
        self.flows = flows or []

        self._update_ui()

    # ---------- UI UPDATE ----------
    def _update_ui(self):
        if not self.dataset_path:
            self.lbl_dataset.setText("No JSON dataset loaded.")
        else:
            self.lbl_dataset.setText("Loaded JSON dataset")

        self.lbl_files.setText(f"Files: {len(self.files)}")
        self.lbl_flows.setText(f"Flows: {len(self.flows)}")

        # limit za performance (kasnije ću napraviti paging)
        self.model.set_data(self.flows)

        # reset na default kad se učita novi dataset
        self._reload_view_mode_combo(select="Default")
        self.model.set_columns(self.DEFAULT_COLUMNS)

    def _load_view_presets(self) -> list[dict]:
        import json

        raw = get_app_setting(LISTING_VIEW_PRESETS_KEY, "[]")
        try:
            data = json.loads(raw)
        except Exception:
            return []
        presets: list[dict] = []
        for item in data or []:
            if not isinstance(item, dict):
                continue
            name = str(item.get("name") or "").strip()
            columns = [str(col) for col in (item.get("columns") or []) if str(col).strip()]
            if name and columns:
                presets.append({"name": name, "columns": columns})
        return presets

    def _save_view_presets(self, presets: list[dict]) -> None:
        import json

        set_app_setting(LISTING_VIEW_PRESETS_KEY, json.dumps(presets))

    def _reload_view_mode_combo(self, *, select: str = "") -> None:
        self.cmb_view_mode.blockSignals(True)
        previous = select or self.cmb_view_mode.currentText()
        self.cmb_view_mode.clear()
        for mode in LISTING_VIEW_MODES:
            self.cmb_view_mode.addItem(mode, mode)
        for preset in self._load_view_presets():
            self.cmb_view_mode.addItem(str(preset["name"]), preset)
        self.cmb_view_mode.adjustSize()
        if previous:
            index = self.cmb_view_mode.findText(previous)
            if index < 0:
                index = self.cmb_view_mode.findData({"name": previous, "columns": []})
            if index >= 0:
                self.cmb_view_mode.setCurrentIndex(index)
        self.cmb_view_mode.blockSignals(False)
        if self.flows and self.cmb_view_mode.currentIndex() >= 0:
            self._on_view_mode_changed(self.cmb_view_mode.currentIndex())

    def _current_named_preset(self) -> str:
        index = self.cmb_view_mode.currentIndex()
        if index < 0:
            return ""
        data = self.cmb_view_mode.itemData(index)
        if isinstance(data, dict):
            return str(data.get("name") or "").strip()
        return ""

    def _open_presets_menu(self) -> None:
        menu = QMenu(self)
        menu.addAction("Save as new preset…", self._save_current_view_preset)
        preset_name = self._current_named_preset()
        if preset_name:
            menu.addAction(f"Update “{preset_name}”", lambda: self._update_named_preset(preset_name))
            menu.addAction(f"Delete “{preset_name}”", lambda: self._delete_named_preset(preset_name))
        menu.exec(self.btn_presets.mapToGlobal(self.btn_presets.rect().bottomLeft()))

    def _update_named_preset(self, preset_name: str) -> None:
        columns = [str(col) for col in (self.model._columns or []) if str(col).strip()]
        if not columns:
            message_dialog(self, "Update preset", "Select at least one column first.", width=420)
            return
        presets = self._load_view_presets()
        updated = False
        for preset in presets:
            if str(preset.get("name") or "") == preset_name:
                preset["columns"] = columns
                updated = True
                break
        if not updated:
            return
        self._save_view_presets(presets)
        self._reload_view_mode_combo(select=preset_name)

    def _delete_named_preset(self, preset_name: str) -> None:
        presets = [preset for preset in self._load_view_presets() if str(preset.get("name") or "") != preset_name]
        self._save_view_presets(presets)
        self._reload_view_mode_combo(select="Custom")

    def _on_view_mode_changed(self, index: int) -> None:
        if index < 0 or not self.flows:
            self.btn_customize_view.hide()
            self.btn_presets.hide()
            return

        data = self.cmb_view_mode.itemData(index)
        if isinstance(data, dict) and data.get("columns"):
            self.btn_customize_view.show()
            self.btn_presets.show()
            self.model.set_columns(list(data["columns"]))
            return

        mode = str(self.cmb_view_mode.itemText(index) or "")
        if mode == "Default":
            self.btn_customize_view.hide()
            self.btn_presets.hide()
            self.model.set_columns(self.DEFAULT_COLUMNS)
        elif mode == "All fields":
            self.btn_customize_view.hide()
            self.btn_presets.hide()
            all_cols = list(self.flows[0].keys())
            self.model.set_columns(all_cols)
        elif mode == "Custom":
            self.btn_customize_view.show()
            self.btn_presets.show()

    def _get_all_available_columns(self):
        if not self.flows:
            return list(self.DEFAULT_COLUMNS)

        raw_keys = list(self.flows[0].keys())

        derived = ["date", "time"]
        excluded = {"bidirectional_first_seen_ms"}

        result = list(derived)

        for key in raw_keys:
            if key not in excluded:
                result.append(key)

        return result

    def _open_customize_dialog(self):
        dlg = ColumnPickerDialog(
            current_columns=self.model._columns,
            all_columns=self._get_all_available_columns(),
            parent=self
        )

        if dlg.exec():
            selected_columns = dlg.get_selected_columns()
            if not selected_columns:
                return
            self.model.set_columns(selected_columns)
            index = self.cmb_view_mode.findText("Custom")
            if index >= 0:
                self.cmb_view_mode.setCurrentIndex(index)

    def _save_current_view_preset(self) -> None:
        columns = [str(col) for col in (self.model._columns or []) if str(col).strip()]
        if not columns:
            message_dialog(self, "Save preset", "Select at least one column first.", width=420)
            return
        name, ok = QInputDialog.getText(self, "Save view preset", "Preset name:")
        if not ok:
            return
        preset_name = str(name or "").strip()
        if not preset_name:
            return
        if preset_name in LISTING_VIEW_MODES:
            message_dialog(self, "Save preset", "That name is reserved. Choose another name.", width=440)
            return
        presets = self._load_view_presets()
        updated = False
        for preset in presets:
            if str(preset.get("name") or "") == preset_name:
                preset["columns"] = columns
                updated = True
                break
        if not updated:
            presets.append({"name": preset_name, "columns": columns})
        self._save_view_presets(presets)
        self._reload_view_mode_combo(select=preset_name)

    def _open_export_dialog(self):
        if not self.flows or not self.model._columns:
            notify_export_empty(self, title="Export")
            return

        popup_export_menu(
            self.btn_export,
            {
                "csv": self._export_csv_selected,
                "xlsx": self._export_excel_selected,
                "html": self._export_html_selected,
            },
        )

    def _export_csv_selected(self) -> None:
        headers, rows = self._get_export_rows()
        self._export_csv(headers, rows)

    def _export_excel_selected(self) -> None:
        headers, rows = self._get_export_rows()
        self._export_excel(headers, rows)

    def _export_html_selected(self) -> None:
        headers, rows = self._get_export_rows()
        self._export_html(headers, rows)
        
    def _get_export_rows(self):
        headers = []
        rows = []

        columns = list(self.model._columns or [])

        for key in columns:
            headers.append(self.model._friendly_label(key))

        # Export mora koristiti cijeli dataset, ne samo preview iz tablice.
        export_model = ListingTableModel(self.flows)
        export_model.set_columns(columns)

        for row_idx in range(export_model.rowCount()):
            row_values = []
            flow = self.flows[row_idx] if row_idx < len(self.flows) else {}

            for col_idx, key in enumerate(columns):
                value = flow.get(key, "")
                row_values.append(format_export_cell(key, value, flow=flow))

            rows.append(row_values)

        return headers, rows
    
    def _export_dataset_meta(self) -> dict:
        try:
            if self.files:
                return extract_dataset_meta(self.files[0])
            if self.dataset_path:
                return extract_dataset_meta(self.dataset_path)
        except Exception:
            pass
        return {}

    def _export_csv(self, headers, rows):
        file_path, _ = QFileDialog.getSaveFileName(
            self,
            "Export CSV",
            table_export_default_path(
                "Listing export",
                "csv",
                project_id=getattr(self.app, "current_project_id", None),
                category="json",
            ),
            "CSV files (*.csv)"
        )

        if not file_path:
            return

        try:
            export_listing_csv(
                file_path,
                headers,
                rows,
                project=self._current_project(),
                project_name=getattr(self.app, "current_project_name", "") or "",
                dataset_meta=self._export_dataset_meta(),
            )
            notify_export_success(self, file_path, title="Export")
        except Exception as e:
            notify_export_error(self, str(e))

    def _export_excel(self, headers, rows):
        file_path, _ = QFileDialog.getSaveFileName(
            self,
            "Export Excel",
            table_export_default_path(
                "Listing export",
                "xlsx",
                project_id=getattr(self.app, "current_project_id", None),
                category="json",
            ),
            "Excel files (*.xlsx)"
        )

        if not file_path:
            return

        try:
            export_listing_excel(
                file_path,
                headers,
                rows,
                project=self._current_project(),
                project_name=getattr(self.app, "current_project_name", "") or "",
                dataset_meta=self._export_dataset_meta(),
            )
            notify_export_success(self, file_path, title="Export")
        except Exception as e:
            notify_export_error(self, str(e))

    def _export_html(self, headers, rows):
        file_path, _ = QFileDialog.getSaveFileName(
            self,
            "Export HTML",
            table_export_default_path(
                "Listing export",
                "html",
                project_id=getattr(self.app, "current_project_id", None),
                category="json",
            ),
            "HTML files (*.html)"
        )

        if not file_path:
            return

        try:
            meta = self._export_dataset_meta()

            export_listing_html(
                file_path=file_path,
                headers=headers,
                rows=rows,
                dataset=self.dataset_path,
                view_mode=self.cmb_view_mode.currentText(),
                files_count=len(self.files),
                meta=meta,
                project=self._current_project(),
                project_name=getattr(self.app, "current_project_name", "") or "",
            )
            notify_export_success(self, file_path, title="Export")
        except Exception as e:
            notify_export_error(self, str(e))

    def _current_project(self):
        project_id = getattr(self.app, "current_project_id", None)
        if project_id is None:
            return None
        return get_project(project_id)
