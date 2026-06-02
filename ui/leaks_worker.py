from __future__ import annotations

from PySide6.QtCore import QObject, Signal, Slot


class LeakImportWorker(QObject):
    progress = Signal(int, int)  # read, inserted
    finished = Signal(object)    # summary dict
    error = Signal(str)

    def __init__(self, options: dict):
        super().__init__()
        self._options = dict(options)
        self._cancelled = False

    def cancel(self) -> None:
        self._cancelled = True

    @Slot()
    def run(self) -> None:
        try:
            from core.leaks.importer import import_dataset

            def _progress(read: int, inserted: int) -> None:
                self.progress.emit(int(read), int(inserted))

            summary = import_dataset(
                self._options["path"],
                name=self._options["name"],
                delimiter=self._options["delimiter"],
                encoding=self._options["encoding"],
                columns=self._options["columns"],
                display_columns=self._options.get("display_columns"),
                has_header=self._options.get("has_header", False),
                source_note=self._options.get("source_note", ""),
                profile_name=self._options.get("profile_name", ""),
                keep_raw=self._options.get("keep_raw", True),
                progress=_progress,
                cancel=lambda: self._cancelled,
            )
            self.finished.emit(summary)
        except Exception as exc:
            self.error.emit(str(exc))
