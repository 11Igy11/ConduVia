from __future__ import annotations

from typing import Any

from core.exporters.listing_exporter import export_listing_csv
from core.pcap_analyzer import PcapSummary


def _metadata_count_map(
    counts: dict[str, int] | None,
    rows: list[dict[str, Any]] | None,
    *,
    key_name: str,
) -> dict[str, int]:
    merged: dict[str, int] = {}
    if counts:
        for key, value in counts.items():
            name = str(key or "").strip()
            if name:
                merged[name] = merged.get(name, 0) + int(value or 0)
        return merged
    for row in rows or []:
        name = str(row.get(key_name) or "").strip()
        if name:
            merged[name] = merged.get(name, 0) + int(row.get("count") or 0)
    return merged


def _sorted_count_rows(counts: dict[str, int]) -> list[list[str]]:
    rows: list[list[str]] = []
    for name, count in sorted(counts.items(), key=lambda item: (-item[1], item[0].lower())):
        rows.append([name, f"{count:,}"])
    return rows


def export_pcap_dns_csv(file_path: str, summary: PcapSummary) -> int:
    counts = _metadata_count_map(summary.dns_query_counts, summary.dns_queries, key_name="query")
    export_listing_csv(file_path, ["DNS query", "Count"], _sorted_count_rows(counts))
    return len(counts)


def export_pcap_tls_csv(file_path: str, summary: PcapSummary) -> int:
    counts = _metadata_count_map(summary.tls_sni_counts, summary.tls_sni, key_name="host")
    export_listing_csv(file_path, ["TLS SNI host", "Count"], _sorted_count_rows(counts))
    return len(counts)
