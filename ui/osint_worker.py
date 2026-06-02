from __future__ import annotations

from PySide6.QtCore import QObject, Signal, Slot


class OsintEnrichWorker(QObject):
    finished = Signal(object)
    error = Signal(str)

    def __init__(self, enricher: str, entity_kind: str, entity_value: str):
        super().__init__()
        self.enricher = enricher
        self.entity_kind = entity_kind
        self.entity_value = entity_value

    @Slot()
    def run(self) -> None:
        try:
            from core.osint.service import enrich_entity

            result = enrich_entity(self.enricher, self.entity_kind, self.entity_value)
            self.finished.emit(result)
        except Exception as exc:
            self.error.emit(str(exc))
