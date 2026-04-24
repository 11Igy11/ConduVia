from PySide6.QtWidgets import QWidget, QVBoxLayout, QLabel, QFrame, QTableView, QHeaderView, QHBoxLayout, QComboBox, QPushButton, QDialog, QDialogButtonBox, QListWidget, QListWidgetItem, QMessageBox, QFileDialog
from PySide6.QtGui import QFont
from PySide6.QtCore import Qt, QAbstractTableModel, QModelIndex
from core.protocols import format_ip_proto
from core.exporters.listing_exporter import export_listing_csv, export_listing_excel, export_listing_html
from core.parser import extract_dataset_meta


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
        if section < 0 or section >= len(self._columns):
            return None

        key = self._columns[section]

        if orientation == Qt.Horizontal:
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

        if role == Qt.DisplayRole:
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

        def parse_first_seen(raw_value):
            from datetime import datetime

            # 1) int/float epoch
            if isinstance(raw_value, (int, float)):
                raw = float(raw_value)
                if raw > 1e12:
                    return datetime.fromtimestamp(raw / 1000)
                return datetime.fromtimestamp(raw)

            text = str(raw_value).strip()

            # 2) numeric string epoch
            if text.isdigit():
                raw = float(text)
                if raw > 1e12:
                    return datetime.fromtimestamp(raw / 1000)
                return datetime.fromtimestamp(raw)

            # 3) timestamp string with microseconds
            try:
                return datetime.strptime(text, "%Y-%m-%d %H:%M:%S.%f")
            except Exception:
                pass

            # 4) timestamp string without microseconds
            try:
                return datetime.strptime(text, "%Y-%m-%d %H:%M:%S")
            except Exception:
                pass

            return None

        # ---------- DATE / TIME SPLIT ----------
        if key in ("date", "time"):
            raw_value = flow.get("bidirectional_first_seen_ms", "")
            try:
                dt = parse_first_seen(raw_value)
                if dt is None:
                    return str(raw_value)

                if key == "date":
                    return dt.strftime("%d.%m.%Y")
                return dt.strftime("%H:%M:%S")
            except Exception:
                return str(raw_value)
            
        # ---------- GENERIC TIMESTAMP (*_seen_ms) ----------
        if key.endswith("_seen_ms"):
            try:
                dt = parse_first_seen(value)
                if dt is None:
                    return str(value)

                return dt.strftime("%d.%m.%Y %H:%M:%S")
            except Exception:
                return str(value)

        # ---------- BYTES ----------
        if key == "bidirectional_bytes":
            try:
                num = float(value)

                if num < 1024:
                    return f"{int(num)} B"
                elif num < 1024 * 1024:
                    kb = num / 1024
                    return f"{kb:.2f} KB"
                else:
                    mb = num / (1024 * 1024)
                    return f"{mb:.2f} MB"
            except Exception:
                return str(value)

        # ---------- DURATION ----------
        if key == "bidirectional_duration_ms":
            try:
                total_sec = int(float(value)) / 1000
                minutes = int(total_sec // 60)
                seconds = int(total_sec % 60)
                return f"{minutes}m {seconds}s"
            except Exception:
                return str(value)
            
        # ---------- PROTOCOL ----------
        if key == "protocol":
            return format_ip_proto(value)

        return str(value)
    
    def sort(self, column, order):
        key = self._columns[column]

        def parse_first_seen(raw_value):
            from datetime import datetime

            # 1) int/float epoch
            if isinstance(raw_value, (int, float)):
                raw = float(raw_value)
                if raw > 1e12:
                    return datetime.fromtimestamp(raw / 1000)
                return datetime.fromtimestamp(raw)

            text = str(raw_value).strip()

            # 2) numeric string epoch
            if text.isdigit():
                raw = float(text)
                if raw > 1e12:
                    return datetime.fromtimestamp(raw / 1000)
                return datetime.fromtimestamp(raw)

            # 3) timestamp string with microseconds
            try:
                return datetime.strptime(text, "%Y-%m-%d %H:%M:%S.%f")
            except Exception:
                pass

            # 4) timestamp string without microseconds
            try:
                return datetime.strptime(text, "%Y-%m-%d %H:%M:%S")
            except Exception:
                pass

            return None

        def get_sort_value(flow):
            value = flow.get(key)

            # ---------- DATE / TIME ----------
            if key in ("date", "time"):
                raw = flow.get("bidirectional_first_seen_ms")
                try:
                    dt = parse_first_seen(raw)
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

class ColumnPickerDialog(QDialog):
    
    def __init__(self, current_columns=None, all_columns=None, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Customize View")
        self.setMinimumWidth(700)
        self.setMinimumHeight(400)

        self.current_columns = list(current_columns or [])
        self.all_columns = list(all_columns or [])

        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(12)

        self.lbl_title = QLabel("Customize visible columns")
        self.lbl_hint = QLabel("Move columns between lists and reorder them.")
        self.lbl_hint.setStyleSheet("color: #9ca3af;")

        layout.addWidget(self.lbl_title)
        layout.addWidget(self.lbl_hint)

        # ---------- MAIN AREA ----------
        main_layout = QHBoxLayout()
        main_layout.setSpacing(12)

        # ---------- LEFT: AVAILABLE ----------
        left_layout = QVBoxLayout()
        self.lbl_available = QLabel("Available columns")
        self.list_available = QListWidget()

        left_layout.addWidget(self.lbl_available)
        left_layout.addWidget(self.list_available)

        # ---------- CENTER: BUTTONS ----------
        center_layout = QVBoxLayout()
        center_layout.setSpacing(10)

        self.btn_add = QPushButton("Add →")
        self.btn_remove = QPushButton("← Remove")

        center_layout.addStretch()
        center_layout.addWidget(self.btn_add)
        center_layout.addWidget(self.btn_remove)
        center_layout.addStretch()

        # ---------- RIGHT: SELECTED ----------
        right_layout = QVBoxLayout()
        self.lbl_selected = QLabel("Selected columns")
        self.list_selected = QListWidget()
        self.list_selected.setDragDropMode(QListWidget.InternalMove)

        right_layout.addWidget(self.lbl_selected)
        right_layout.addWidget(self.list_selected)

        main_layout.addLayout(left_layout, 3)
        main_layout.addLayout(center_layout, 1)
        main_layout.addLayout(right_layout, 3)

        layout.addLayout(main_layout)

        # ---------- BUTTONS ----------
        self.buttons = QDialogButtonBox(
            QDialogButtonBox.Ok | QDialogButtonBox.Cancel
        )
        self.buttons.accepted.connect(self.accept)
        self.buttons.rejected.connect(self.reject)

        layout.addWidget(self.buttons)

        # ---------- SIGNALS ----------
        self.btn_add.clicked.connect(self._move_to_selected)
        self.btn_remove.clicked.connect(self._move_to_available)

        # optional double click UX
        self.list_available.itemDoubleClicked.connect(lambda _: self._move_to_selected())
        self.list_selected.itemDoubleClicked.connect(lambda _: self._move_to_available())

        self._populate_lists()

    def _make_item(self, key: str) -> QListWidgetItem:
        label = self._friendly_label(key)

        item = QListWidgetItem(label)
        item.setData(Qt.UserRole, key)

        # tooltip = original key (za power usere)
        item.setToolTip(key)

        return item

    def _populate_lists(self):
        self.list_available.clear()
        self.list_selected.clear()

        selected_set = set(self.current_columns)

        # selected ostaje u redoslijedu kako ga user trenutno vidi
        for key in self.current_columns:
            self.list_selected.addItem(self._make_item(key))

        # available sortiramo po friendly labeli
        available_keys = [key for key in self.all_columns if key not in selected_set]
        available_keys.sort(key=lambda k: self._friendly_label(k).lower())

        for key in available_keys:
            self.list_available.addItem(self._make_item(key))

    def _move_to_selected(self):
        row = self.list_available.currentRow()
        if row < 0:
            return

        item = self.list_available.takeItem(row)
        self.list_selected.addItem(item)

    def _move_to_available(self):
        row = self.list_selected.currentRow()
        if row < 0:
            return

        item = self.list_selected.takeItem(row)
        self.list_available.addItem(item)

    def get_selected_columns(self):
        selected = []

        for i in range(self.list_selected.count()):
            item = self.list_selected.item(i)
            key = item.data(Qt.UserRole)
            if key:
                selected.append(key)

        if not selected:
            return None

        return selected
    
    FRIENDLY_OVERRIDES = {
        "src2dst_duration_ms": "Src → Dst Duration",
        "dst2src_duration_ms": "Dst → Src Duration",
        "src2dst_bytes": "Src → Dst Volume",
        "dst2src_bytes": "Dst → Src Volume",
        "src2dst_packets": "Src → Dst Packets",
        "dst2src_packets": "Dst → Src Packets",
        "src2dst_first_seen_ms": "Src → Dst First Seen",
        "src2dst_last_seen_ms": "Src → Dst Last Seen",
        "dst2src_first_seen_ms": "Dst → Src First Seen",
        "dst2src_last_seen_ms": "Dst → Src Last Seen",
    }
    
    def _friendly_label(self, key: str) -> str:
        if key in self.FRIENDLY_OVERRIDES:
            return self.FRIENDLY_OVERRIDES[key]

        from ui.listing_page import ListingTableModel

        if key in ListingTableModel.HEADER_LABELS:
            return ListingTableModel.HEADER_LABELS[key]

        return key.replace("_", " ").title()

class ListingPage(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)

        self.dataset_path = ""
        self.files = []
        self.flows = []

        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(12)

        # ---------- Header ----------
        self.lbl_title = QLabel("Listing")
        font = QFont()
        font.setPointSize(20)
        font.setBold(True)
        self.lbl_title.setFont(font)

        self.lbl_dataset = QLabel("Dataset: (none)")
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

        # layout
        layout.addWidget(self.lbl_title)

        # ---------- VIEW TOOLBAR ----------
        self.view_bar = QHBoxLayout()
        self.view_bar.setSpacing(10)

        self.lbl_view_mode = QLabel("View:")
        self.cmb_view_mode = QComboBox()
        self.cmb_view_mode.addItems(["Default", "All fields", "Custom"])
        self.cmb_view_mode.currentTextChanged.connect(self._on_view_mode_changed)

        self.btn_customize_view = QPushButton("Customize")
        self.btn_customize_view.clicked.connect(self._open_customize_dialog)
        self.btn_customize_view.hide()

        self.btn_export = QPushButton("Export")
        self.btn_export.clicked.connect(self._open_export_dialog)

        self.view_bar.addWidget(self.lbl_view_mode)
        self.view_bar.addWidget(self.cmb_view_mode)
        self.view_bar.addWidget(self.btn_customize_view)
        self.view_bar.addWidget(self.btn_export)
        self.view_bar.addStretch()

        layout.addLayout(self.view_bar)
        layout.addWidget(self.card)

        # ---------- TABLE ----------
        self.table = QTableView()

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
            self.lbl_dataset.setText("Dataset: (none)")
        else:
            self.lbl_dataset.setText(f"Dataset: {self.dataset_path}")

        self.lbl_files.setText(f"Files: {len(self.files)}")
        self.lbl_flows.setText(f"Flows: {len(self.flows)}")

        # limit za performance (kasnije ću napraviti paging)
        preview = self.flows[:1000]
        self.model.set_data(preview)

        # reset na default kad se učita novi dataset
        self.cmb_view_mode.setCurrentText("Default")
        self.model.set_columns(self.DEFAULT_COLUMNS)

    def _on_view_mode_changed(self, mode):
        if not self.flows:
            return

        if mode == "Default":
            self.btn_customize_view.hide()
            self.model.set_columns(self.DEFAULT_COLUMNS)

        elif mode == "All fields":
            self.btn_customize_view.hide()
            all_cols = list(self.flows[0].keys())
            self.model.set_columns(all_cols)

        elif mode == "Custom":
            self.btn_customize_view.show()

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

    def _open_export_dialog(self):
        if not self.flows or not self.model._columns:
            QMessageBox.information(self, "Export", "There is no data to export.")
            return

        format_name = self._choose_export_format()
        if not format_name:
            return

        headers, rows = self._get_export_rows()

        if format_name == "csv":
            self._export_csv(headers, rows)
            return
        
        if format_name == "xlsx":
            self._export_excel(headers, rows)
            return
        
        if format_name == "html":
            self._export_html(headers, rows)
            return

        print(f"Export format selected: {format_name}")
        print(f"Headers: {headers}")
        print(f"Rows: {len(rows)}")

    def _choose_export_format(self):
        dlg = QDialog(self)
        dlg.setWindowTitle("Export")
        dlg.setModal(True)
        dlg.setMinimumWidth(360)

        layout = QVBoxLayout(dlg)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(12)

        lbl = QLabel("Choose export format:")
        layout.addWidget(lbl)

        btn_csv = QPushButton("CSV")
        btn_excel = QPushButton("Excel")
        btn_html = QPushButton("HTML")

        result = {"value": None}

        def choose(value):
            result["value"] = value
            dlg.accept()

        btn_csv.clicked.connect(lambda: choose("csv"))
        btn_excel.clicked.connect(lambda: choose("xlsx"))
        btn_html.clicked.connect(lambda: choose("html"))

        layout.addWidget(btn_csv)
        layout.addWidget(btn_excel)
        layout.addWidget(btn_html)

        buttons = QDialogButtonBox(QDialogButtonBox.Cancel)
        buttons.rejected.connect(dlg.reject)
        layout.addWidget(buttons)

        ok = dlg.exec() == QDialog.Accepted
        return result["value"] if ok else None
        
    def _get_export_rows(self):
        headers = []
        rows = []

        for key in self.model._columns:
            headers.append(self.model._friendly_label(key))

        for row_idx in range(self.model.rowCount()):
            row_values = []
            for col_idx in range(self.model.columnCount()):
                index = self.model.index(row_idx, col_idx)
                value = self.model.data(index, Qt.DisplayRole)
                row_values.append("" if value is None else str(value))
            rows.append(row_values)

        return headers, rows
    
    def _export_csv(self, headers, rows):
        file_path, _ = QFileDialog.getSaveFileName(
            self,
            "Export CSV",
            "listing_export.csv",
            "CSV files (*.csv)"
        )

        if not file_path:
            return

        try:
            export_listing_csv(file_path, headers, rows)

            QMessageBox.information(
                self,
                "Export",
                f"CSV export completed successfully.\n\n{file_path}"
            )
        except Exception as e:
            QMessageBox.critical(
                self,
                "Export Error",
                f"Failed to export CSV.\n\n{str(e)}"
            )

    def _export_excel(self, headers, rows):
        file_path, _ = QFileDialog.getSaveFileName(
            self,
            "Export Excel",
            "listing_export.xlsx",
            "Excel files (*.xlsx)"
        )

        if not file_path:
            return

        try:
            export_listing_excel(file_path, headers, rows)

            QMessageBox.information(
                self,
                "Export",
                f"Excel export completed successfully.\n\n{file_path}"
            )
        except Exception as e:
            QMessageBox.critical(
                self,
                "Export Error",
                f"Failed to export Excel.\n\n{str(e)}"
            )

    def _export_html(self, headers, rows):
        file_path, _ = QFileDialog.getSaveFileName(
            self,
            "Export HTML",
            "listing_export.html",
            "HTML files (*.html)"
        )

        if not file_path:
            return

        try:
            meta = {}

            try:
                if self.files:
                    meta = extract_dataset_meta(self.files[0])
                elif self.dataset_path:
                    meta = extract_dataset_meta(self.dataset_path)
            except Exception:
                meta = {}

            export_listing_html(
                file_path=file_path,
                headers=headers,
                rows=rows,
                dataset=self.dataset_path,
                view_mode=self.cmb_view_mode.currentText(),
                files_count=len(self.files),
                meta=meta,
            )

            QMessageBox.information(
                self,
                "Export",
                f"HTML export completed successfully.\n\n{file_path}"
            )
        except Exception as e:
            QMessageBox.critical(
                self,
                "Export Error",
                f"Failed to export HTML.\n\n{str(e)}"
            )