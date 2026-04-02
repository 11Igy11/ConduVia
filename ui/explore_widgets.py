from PySide6.QtCore import QObject, Signal, Qt, QItemSelectionModel
from PySide6.QtGui import QContextMenuEvent
from PySide6.QtWidgets import QTableView, QMenu

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

            if 0 <= row < len(self.parent_app.loaded_flows):
                flow = self.parent_app.loaded_flows[row]
                lines = [
                    f"Source IP: {flow.get('src_ip', '')}",
                    f"Source Port: {flow.get('src_port', '')}",
                    f"Destination IP: {flow.get('dst_ip', '')}",
                    f"Destination Port: {flow.get('dst_port', '')}",
                    f"Protocol: {format_ip_proto(flow.get('protocol', ''))}",
                    f"Application: {flow.get('application_name', '')}",
                    f"Bytes: {flow.get('bidirectional_bytes', '')}",
                    f"Duration(ms): {flow.get('bidirectional_duration_ms', '')}",
                    f"SNI: {flow.get('requested_server_name', '')}",
                ]
                self.parent_app.copy_text("\n".join(lines))