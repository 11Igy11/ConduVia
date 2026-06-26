from __future__ import annotations

from typing import Any

from core.evidence_policy import format_period_day_label
from core.formatters import human_bytes

PERIOD_COMPARISON_CHART_FOOTER = (
    "Bar height uses the larger daily volume (bytes). "
    "JSON flow counts and PCAP packet counts are different units and are shown separately."
)


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
        delta_pct = volume_delta_pct(json_bytes, pcap_bytes)
        chart_volume = max(json_bytes, pcap_bytes)
        json_volume_label = human_bytes(json_bytes, precision=2)
        pcap_volume_label = human_bytes(pcap_bytes, precision=2)
        rows.append({
            "label": format_period_day_label(day),
            "date": day,
            "count": chart_volume,
            "json_flows": json_flows,
            "pcap_packets": pcap_packets,
            "json_bytes": json_bytes,
            "pcap_bytes": pcap_bytes,
            "json_flows_label": f"{json_flows:,}",
            "json_volume_label": json_volume_label,
            "pcap_packets_label": f"{pcap_packets:,}",
            "pcap_volume_label": pcap_volume_label,
            "json_mb_label": json_volume_label,
            "pcap_mb_label": pcap_volume_label,
            "volume_compare_label": f"JSON {json_volume_label} · PCAP {pcap_volume_label}",
            "delta_pct": delta_pct,
            "delta_vol_label": f"{delta_pct:+.1f}%" if delta_pct is not None else "—",
            "detail": (
                f"JSON {json_flows:,} flows / {json_volume_label} | "
                f"PCAP {pcap_packets:,} pkt / {pcap_volume_label}"
                + (f" | Δvol {delta_pct:+.1f}%" if delta_pct is not None else "")
            ),
            "tooltip": (
                f"{format_period_day_label(day)}\n"
                f"JSON: {json_flows:,} flows, {json_volume_label}\n"
                f"PCAP: {pcap_packets:,} packets, {pcap_volume_label}\n"
                + (
                    f"Volume delta (PCAP vs JSON): {delta_pct:+.1f}%"
                    if delta_pct is not None
                    else "Volume delta: not available (missing bytes on one side)"
                )
            ),
            "status": comparison_status(json_flows, pcap_packets, json_bytes, pcap_bytes, delta_pct),
        })
    return rows


def volume_delta_pct(json_bytes: int, pcap_bytes: int) -> float | None:
    if json_bytes <= 0 or pcap_bytes <= 0:
        return None
    return round(((pcap_bytes - json_bytes) / json_bytes) * 100.0, 1)


def comparison_status(
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


# Backwards-compatible aliases for internal callers/tests.
_volume_delta_pct = volume_delta_pct
_comparison_status = comparison_status
