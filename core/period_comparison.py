from __future__ import annotations

from typing import Any

from core.evidence_policy import format_period_day_label
from core.formatters import human_bytes


def build_period_comparison_rows(
    json_day_rows: list[dict[str, Any]] | None,
    pcap_day_rows: list[dict[str, Any]] | None,
) -> list[dict[str, Any]]:
    """Align JSON and PCAP daily totals for Profile comparison."""
    json_by_date = {
        str(row.get("date") or ""): row
        for row in (json_day_rows or [])
        if str(row.get("date") or "").strip()
    }
    pcap_by_date = {
        str(row.get("date") or ""): row
        for row in (pcap_day_rows or [])
        if str(row.get("date") or "").strip()
    }

    rows: list[dict[str, Any]] = []
    for day in sorted(set(json_by_date) | set(pcap_by_date)):
        json_row = json_by_date.get(day) or {}
        pcap_row = pcap_by_date.get(day) or {}
        json_flows = int(json_row.get("count") or 0)
        pcap_packets = int(pcap_row.get("count") or 0)
        json_bytes = int(json_row.get("bytes") or 0)
        pcap_bytes = int(pcap_row.get("bytes") or 0)
        delta_pct = _volume_delta_pct(json_bytes, pcap_bytes)
        chart_volume = max(json_bytes, pcap_bytes)
        rows.append({
            "label": format_period_day_label(day),
            "date": day,
            "count": chart_volume,
            "json_flows": json_flows,
            "pcap_packets": pcap_packets,
            "json_bytes": json_bytes,
            "pcap_bytes": pcap_bytes,
            "json_mb_label": human_bytes(json_bytes, precision=2),
            "pcap_mb_label": human_bytes(pcap_bytes, precision=2),
            "delta_pct": delta_pct,
            "detail": (
                f"JSON {json_flows:,} flows / {human_bytes(json_bytes, precision=2)} | "
                f"PCAP {pcap_packets:,} pkt / {human_bytes(pcap_bytes, precision=2)}"
                + (f" | Δvol {delta_pct:+.1f}%" if delta_pct is not None else "")
            ),
            "status": _comparison_status(json_flows, pcap_packets, json_bytes, pcap_bytes, delta_pct),
        })
    return rows


def _volume_delta_pct(json_bytes: int, pcap_bytes: int) -> float | None:
    if json_bytes <= 0 or pcap_bytes <= 0:
        return None
    return round(((pcap_bytes - json_bytes) / json_bytes) * 100.0, 1)


def _comparison_status(
    json_flows: int,
    pcap_packets: int,
    json_bytes: int,
    pcap_bytes: int,
    delta_pct: float | None,
) -> str:
    if json_flows and pcap_packets:
        if delta_pct is not None and abs(delta_pct) <= 5.0:
            return "Aligned"
        if delta_pct is not None and abs(delta_pct) <= 15.0:
            return "Close"
        return "Review"
    if json_flows and not pcap_packets:
        return "JSON only"
    if pcap_packets and not json_flows:
        return "PCAP only"
    return "No data"
