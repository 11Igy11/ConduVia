from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class EnrichResult:
    enricher: str
    entity_kind: str
    entity_value: str
    status: str = "ok"
    summary: str = ""
    details: dict[str, Any] = field(default_factory=dict)

    def as_text(self) -> str:
        lines = [self.summary.strip()] if self.summary.strip() else []
        for key, value in self.details.items():
            if isinstance(value, list):
                if value:
                    lines.append(f"{key}: {', '.join(str(v) for v in value)}")
            elif value not in (None, ""):
                lines.append(f"{key}: {value}")
        return "\n".join(lines).strip()
