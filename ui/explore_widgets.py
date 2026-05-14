from PySide6.QtCore import QObject, Signal, Qt, QItemSelectionModel
from PySide6.QtGui import QContextMenuEvent
from PySide6.QtWidgets import QApplication, QTableView, QMenu

from core.formatters import human_bytes
from core.protocols import format_ip_proto


class AITextWorker(QObject):
    finished = Signal(str)
    error = Signal(str)

    def __init__(self, fn, *args, **kwargs):
        super().__init__()
        self.fn = fn
        self.args = args
        self.kwargs = kwargs

    def run(self):
        try:
            result = self.fn(*self.args, **self.kwargs)
            self.finished.emit(result)
        except Exception as e:
            self.error.emit(str(e))


def _copy_text(parent_app, text: str):
    if parent_app is not None and hasattr(parent_app, "copy_text"):
        parent_app.copy_text(text)
        return

    app = QApplication.instance()
    if app is not None:
        app.clipboard().setText(text)


def _table_row_text(model, row: int) -> str:
    lines = []
    for col in range(model.columnCount()):
        header = model.headerData(col, Qt.Horizontal, Qt.DisplayRole) or f"Column {col + 1}"
        value = model.data(model.index(row, col), Qt.DisplayRole)
        lines.append(f"{header}: {'' if value is None else value}")
    return "\n".join(lines)


class CopyableTableView(QTableView):
    def __init__(self, parent_app=None, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.parent_app = parent_app

    def contextMenuEvent(self, event: QContextMenuEvent):
        index = self.indexAt(event.pos())
        if not index.isValid():
            event.ignore()
            return

        self.setCurrentIndex(index)
        if self.selectionModel() is not None:
            self.selectionModel().select(
                index,
                QItemSelectionModel.ClearAndSelect | QItemSelectionModel.Rows
            )

        menu = QMenu(self)
        act_copy_value = menu.addAction("Copy value")
        act_copy_row = menu.addAction("Copy row")

        chosen = menu.exec(event.globalPos())
        if not chosen:
            return

        model = self.model()
        if model is None:
            return

        if chosen == act_copy_value:
            value = model.data(index, Qt.DisplayRole)
            if value is not None:
                _copy_text(self.parent_app, str(value))
            return

        if chosen == act_copy_row:
            _copy_text(self.parent_app, _table_row_text(model, index.row()))


class FlowTableView(QTableView):
    def __init__(self, parent_app, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.parent_app = parent_app

    def contextMenuEvent(self, event: QContextMenuEvent):
        index = self.indexAt(event.pos())
        if not index.isValid():
            event.ignore()
            return

        self.setCurrentIndex(index)
        self.selectionModel().select(
            index,
            QItemSelectionModel.ClearAndSelect | QItemSelectionModel.Rows
        )
        menu = QMenu(self)

        act_copy_value = menu.addAction("Copy value")
        act_copy_flow = menu.addAction("Copy flow")

        chosen = menu.exec(event.globalPos())
        if not chosen:
            return

        if chosen == act_copy_value:
            value = self.model().data(index, Qt.DisplayRole)
            if value is not None:
                self.parent_app.copy_text(str(value))
            return

        if chosen == act_copy_flow:
            proxy = self.parent_app.proxy
            source_index = proxy.mapToSource(index)
            row = source_index.row()

            flows = self.parent_app.flow_controller.get_loaded()

            if 0 <= row < len(flows):
                flow = flows[row]
                lines = [
                    f"Source IP: {flow.get('src_ip', '')}",
                    f"Source Port: {flow.get('src_port', '')}",
                    f"Destination IP: {flow.get('dst_ip', '')}",
                    f"Destination Port: {flow.get('dst_port', '')}",
                    f"Protocol: {format_ip_proto(flow.get('protocol', ''))}",
                    f"Application: {flow.get('application_name', '')}",
                    f"Bytes: {human_bytes(flow.get('bidirectional_bytes', 0), precision=2)}",
                    f"Duration(ms): {flow.get('bidirectional_duration_ms', '')}",
                    f"SNI: {flow.get('requested_server_name', '')}",
                ]
                self.parent_app.copy_text("\n".join(lines))
