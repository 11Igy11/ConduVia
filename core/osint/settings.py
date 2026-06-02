from __future__ import annotations

from dataclasses import dataclass

from core.db import get_app_settings


@dataclass
class OsintSettings:
    virustotal_api_key: str = ""
    shodan_api_key: str = ""

    @classmethod
    def from_mapping(cls, mapping: dict[str, str] | None) -> OsintSettings:
        data = mapping or {}
        return cls(
            virustotal_api_key=str(data.get("osint.virustotal_api_key", "") or "").strip(),
            shodan_api_key=str(data.get("osint.shodan_api_key", "") or "").strip(),
        )

    def to_mapping(self) -> dict[str, str]:
        return {
            "osint.virustotal_api_key": self.virustotal_api_key,
            "osint.shodan_api_key": self.shodan_api_key,
        }


def load_osint_settings() -> OsintSettings:
    return OsintSettings.from_mapping(get_app_settings())
