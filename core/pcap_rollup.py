from __future__ import annotations

import re
from collections import Counter
from dataclasses import dataclass
from typing import Any

from core.timeutils import parse_timestamp


@dataclass(frozen=True)
class PcapRollupTotals:
    total_packets: int
    total_bytes: int
    pcap_day_count: int
    pcap_source_rows: int
    device_ips: Counter[str]
    day_packets: Counter[str]
    day_bytes: Counter[str]
    undated_packets: int
    undated_bytes: int
    undated_day_count: int


def is_aggregate_pcap_source(source: Any) -> bool:
    sha = str(getattr(source, "file_sha256", "") or "").strip()
    if sha.startswith("aggregate:"):
        return True

    file_name = str(getattr(source, "file_name", "") or "").strip().casefold()
    return "pcap files" in file_name


def rollup_pcap_sources(sources: list[Any]) -> PcapRollupTotals:
    """Avoid double-counting when both day aggregates and per-file rows are saved."""
    items = [source for source in (sources or []) if source is not None]
    if not items:
        return PcapRollupTotals(
            total_packets=0,
            total_bytes=0,
            pcap_day_count=0,
            pcap_source_rows=0,
            device_ips=Counter(),
            day_packets=Counter(),
            day_bytes=Counter(),
            undated_packets=0,
            undated_bytes=0,
            undated_day_count=0,
        )

    by_day: dict[str, list[Any]] = {}
    for source in items:
        by_day.setdefault(pcap_day_key(source) or "", []).append(source)

    day_packets: Counter[str] = Counter()
    day_bytes: Counter[str] = Counter()
    device_ips: Counter[str] = Counter()
    undated_packets = 0
    undated_bytes = 0
    undated_day_count = 0

    for day, group in by_day.items():
        packets, wire_bytes, ips = _rollup_day_group(group)
        device_ips.update(ips)
        if not day:
            undated_packets += packets
            undated_bytes += wire_bytes
            if packets or wire_bytes:
                undated_day_count = 1
            continue
        day_packets[day] += packets
        day_bytes[day] += wire_bytes

    total_packets = sum(day_packets.values()) + undated_packets
    total_bytes = sum(day_bytes.values()) + undated_bytes

    return PcapRollupTotals(
        total_packets=total_packets,
        total_bytes=total_bytes,
        pcap_day_count=len(day_packets) + (1 if undated_day_count else 0),
        pcap_source_rows=len(items),
        device_ips=device_ips,
        day_packets=day_packets,
        day_bytes=day_bytes,
        undated_packets=undated_packets,
        undated_bytes=undated_bytes,
        undated_day_count=undated_day_count,
    )


def _rollup_day_group(group: list[Any]) -> tuple[int, int, Counter[str]]:
    aggregates = [item for item in group if is_aggregate_pcap_source(item)]
    singles = [item for item in group if not is_aggregate_pcap_source(item)]

    if aggregates:
        best = max(aggregates, key=lambda item: int(getattr(item, "packet_count", 0) or 0))
        packets = int(getattr(best, "packet_count", 0) or 0)
        wire_bytes = int(getattr(best, "wire_bytes", 0) or 0)
        ips: Counter[str] = Counter()
        ip = str(getattr(best, "likely_device_ip", "") or "").strip()
        if ip:
            ips[ip] += 1
        return packets, wire_bytes, ips

    packets = sum(int(getattr(item, "packet_count", 0) or 0) for item in singles)
    wire_bytes = sum(int(getattr(item, "wire_bytes", 0) or 0) for item in singles)
    ips: Counter[str] = Counter()
    for item in singles:
        ip = str(getattr(item, "likely_device_ip", "") or "").strip()
        if ip:
            ips[ip] += 1
    return packets, wire_bytes, ips


def collect_device_ip_stats(sources: list[Any]) -> tuple[Counter[str], list[dict[str, Any]]]:
    """Distinct likely device IPs with period counts; includes legacy per-file rows."""
    period_ips: Counter[str] = Counter()
    packet_weight: Counter[str] = Counter()
    all_ips: set[str] = set()

    by_day: dict[str, list[Any]] = {}
    for source in sources or []:
        ip = str(getattr(source, "likely_device_ip", "") or "").strip()
        if ip:
            all_ips.add(ip)
        by_day.setdefault(pcap_day_key(source) or f"row-{getattr(source, 'id', 0)}", []).append(source)

    for group in by_day.values():
        _packets, _wire_bytes, day_ips = _rollup_day_group(group)
        for ip, count in day_ips.items():
            period_ips[ip] += count
            best = max(
                group,
                key=lambda item: int(getattr(item, "packet_count", 0) or 0),
            )
            if str(getattr(best, "likely_device_ip", "") or "").strip() == ip:
                packet_weight[ip] += int(getattr(best, "packet_count", 0) or 0)

    rows = []
    for ip in sorted(all_ips):
        period_count = int(period_ips.get(ip, 0) or 0)
        packet_count = int(packet_weight.get(ip, 0) or 0)
        rows.append({
            "label": ip,
            "count": packet_count,
            "periods": period_count or 1,
            "badge_label": f"{packet_count:,} pkts",
            "detail": f"Seen in {period_count or 1} PCAP period(s) · {packet_count:,} packets",
            "packets": packet_count,
            "tooltip": f"{ip} — {period_count or 1} period(s), {packet_count:,} packets",
        })
    rows.sort(key=lambda row: (-int(row.get("packets") or 0), str(row.get("label") or "")))
    counter = Counter({row["label"]: int(row["count"]) for row in rows})
    return counter, rows


def pcap_day_key(source: Any) -> str:
    period_day = str(getattr(source, "period_day", "") or "").strip()
    if period_day and period_day != "undated":
        return period_day

    for value in (
        getattr(source, "first_seen", ""),
        getattr(source, "last_seen", ""),
        getattr(source, "file_name", ""),
        getattr(source, "file_path", ""),
    ):
        day = _day_key(str(value or ""))
        if day:
            return day
        day = _day_key_from_text(str(value or ""))
        if day:
            return day
    return ""


def _day_key(value: str) -> str:
    dt = parse_timestamp(value)
    return "" if dt is None else dt.strftime("%Y-%m-%d")


def _day_key_from_text(value: str) -> str:
    text = str(value or "")
    for pattern in (
        r"(20\d{2})[-_/\.]([01]\d)[-_/\.]([0-3]\d)",
        r"([0-3]\d)[-_/\.]([01]\d)[-_/\.](20\d{2})",
        r"(20\d{2})([01]\d)([0-3]\d)",
    ):
        match = re.search(pattern, text)
        if not match:
            continue
        groups = match.groups()
        if len(groups[0]) == 4:
            year, month, day = groups
        else:
            day, month, year = groups
        try:
            return f"{int(year):04d}-{int(month):02d}-{int(day):02d}"
        except Exception:
            continue
    return ""
