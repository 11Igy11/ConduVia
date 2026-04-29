from __future__ import annotations

from collections import Counter, defaultdict
from typing import Any

from core.formatters import safe_int
from core.timeutils import date_key, hour_key, parse_flow_timestamp


def top_field_values(
    flows: list[dict[str, Any]],
    field: str,
    *,
    limit: int = 10,
    stringify: bool = True,
    include_empty: bool = False,
    empty_label: str = "",
) -> list[tuple[str, int]]:
    counter = Counter()

    for flow in flows:
        if not isinstance(flow, dict):
            continue

        value = flow.get(field)
        if value is None or value == "":
            if not include_empty:
                continue
            value = empty_label

        key = str(value) if stringify else value
        counter[key] += 1

    return counter.most_common(limit)


def top_field_by_bytes(
    flows: list[dict[str, Any]],
    field: str,
    *,
    limit: int = 10,
    bytes_field: str = "bidirectional_bytes",
    include_empty: bool = False,
    empty_label: str = "",
) -> list[tuple[str, int]]:
    totals = defaultdict(int)

    for flow in flows:
        if not isinstance(flow, dict):
            continue

        value = flow.get(field)
        if value is None or value == "":
            if not include_empty:
                continue
            value = empty_label

        totals[str(value)] += safe_int(flow.get(bytes_field))

    return sorted(totals.items(), key=lambda kv: kv[1], reverse=True)[:limit]


def top_flows_by_bytes(
    flows: list[dict[str, Any]],
    *,
    limit: int = 10,
    bytes_field: str = "bidirectional_bytes",
) -> list[dict[str, Any]]:
    top = sorted(
        [f for f in flows if isinstance(f, dict)],
        key=lambda f: safe_int(f.get(bytes_field)),
        reverse=True,
    )[:limit]

    return [
        {
            "src_ip": f.get("src_ip"),
            "src_port": f.get("src_port"),
            "dst_ip": f.get("dst_ip"),
            "dst_port": f.get("dst_port"),
            "protocol": f.get("protocol"),
            "app": f.get("application_name"),
            "bytes": safe_int(f.get(bytes_field)),
            "packets": safe_int(f.get("bidirectional_packets")),
            "duration_ms": safe_int(f.get("bidirectional_duration_ms")),
            "sni": f.get("requested_server_name", ""),
        }
        for f in top
    ]


def compute_registry_summary(flows: list[dict[str, Any]], top_n: int = 10) -> dict[str, Any]:
    src_c = Counter()
    dst_c = Counter()
    proto_c = Counter()
    app_c = Counter()

    bytes_by_src = defaultdict(int)
    bytes_by_dst = defaultdict(int)
    bytes_by_app = defaultdict(int)

    by_date = Counter()
    by_hour = Counter()
    total_bytes = 0

    for flow in flows:
        if not isinstance(flow, dict):
            continue

        src = str(flow.get("src_ip") or "")
        dst = str(flow.get("dst_ip") or "")
        proto = str(flow.get("protocol") or "")
        app = str(flow.get("application_name") or "")
        flow_bytes = safe_int(flow.get("bidirectional_bytes"))
        total_bytes += flow_bytes

        if src:
            src_c[src] += 1
            bytes_by_src[src] += flow_bytes

        if dst:
            dst_c[dst] += 1
            bytes_by_dst[dst] += flow_bytes

        if proto:
            proto_c[proto] += 1

        if app:
            app_c[app] += 1
            bytes_by_app[app] += flow_bytes

        dt = parse_flow_timestamp(flow)
        if dt is not None:
            by_date[date_key(dt)] += 1
            by_hour[hour_key(dt)] += 1

    def top_bytes(items: dict[str, int]) -> list[tuple[str, int]]:
        return sorted(items.items(), key=lambda kv: kv[1], reverse=True)[:top_n]

    return {
        "top_src": src_c.most_common(top_n),
        "top_dst": dst_c.most_common(top_n),
        "top_proto": proto_c.most_common(top_n),
        "top_app": app_c.most_common(top_n),
        "top_date": by_date.most_common(top_n),
        "top_hour": by_hour.most_common(top_n),
        "top_bytes_src": top_bytes(bytes_by_src),
        "top_bytes_dst": top_bytes(bytes_by_dst),
        "top_bytes_app": top_bytes(bytes_by_app),
        "total_flows": len(flows),
        "total_bytes": int(total_bytes),
    }
