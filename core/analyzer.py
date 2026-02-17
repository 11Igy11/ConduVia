from collections import Counter, defaultdict
from typing import Any


def top_src_ips(flows: list[dict[str, Any]], limit: int = 10) -> list[tuple[str, int]]:
    counter = Counter()
    for flow in flows:
        ip = flow.get("src_ip")
        if ip:
            counter[ip] += 1
    return counter.most_common(limit)


def top_dst_ips(flows: list[dict[str, Any]], limit: int = 10) -> list[tuple[str, int]]:
    counter = Counter()
    for flow in flows:
        ip = flow.get("dst_ip")
        if ip:
            counter[ip] += 1
    return counter.most_common(limit)


def top_protocols(flows: list[dict[str, Any]], limit: int = 10) -> list[tuple[str, int]]:
    counter = Counter()
    for flow in flows:
        proto = flow.get("protocol")
        if proto is not None:
            counter[str(proto)] += 1
    return counter.most_common(limit)


def top_applications(flows: list[dict[str, Any]], limit: int = 10) -> list[tuple[str, int]]:
    counter = Counter()
    for flow in flows:
        app = flow.get("application_name")
        if app:
            counter[str(app)] += 1
    return counter.most_common(limit)


# -------- BYTES-BASED (najkorisnije) --------
def _as_int(v: Any) -> int:
    try:
        return int(v)
    except Exception:
        return 0


def top_src_ips_by_bytes(
    flows: list[dict[str, Any]],
    limit: int = 10,
    bytes_field: str = "bidirectional_bytes",
) -> list[tuple[str, int]]:
    totals = defaultdict(int)
    for f in flows:
        ip = f.get("src_ip")
        if ip:
            totals[ip] += _as_int(f.get(bytes_field))
    return sorted(totals.items(), key=lambda kv: kv[1], reverse=True)[:limit]


def top_dst_ips_by_bytes(
    flows: list[dict[str, Any]],
    limit: int = 10,
    bytes_field: str = "bidirectional_bytes",
) -> list[tuple[str, int]]:
    totals = defaultdict(int)
    for f in flows:
        ip = f.get("dst_ip")
        if ip:
            totals[ip] += _as_int(f.get(bytes_field))
    return sorted(totals.items(), key=lambda kv: kv[1], reverse=True)[:limit]


def top_apps_by_bytes(
    flows: list[dict[str, Any]],
    limit: int = 10,
    bytes_field: str = "bidirectional_bytes",
) -> list[tuple[str, int]]:
    totals = defaultdict(int)
    for f in flows:
        app = f.get("application_name") or "Unknown"
        totals[str(app)] += _as_int(f.get(bytes_field))
    return sorted(totals.items(), key=lambda kv: kv[1], reverse=True)[:limit]


def top_sni_by_bytes(
    flows: list[dict[str, Any]],
    limit: int = 10,
    bytes_field: str = "bidirectional_bytes",
) -> list[tuple[str, int]]:
    """SNI/hostname iz requested_server_name (korisno za TLS/DNS)."""
    totals = defaultdict(int)
    for f in flows:
        sni = f.get("requested_server_name") or ""
        if sni:
            totals[sni] += _as_int(f.get(bytes_field))
    return sorted(totals.items(), key=lambda kv: kv[1], reverse=True)[:limit]


def top_flows_by_bytes(
    flows: list[dict[str, Any]],
    limit: int = 10,
    bytes_field: str = "bidirectional_bytes",
) -> list[dict[str, Any]]:
    """Vrati 'najveće' flow zapise (za brzo forenzičko kopanje)."""
    def key_fn(f: dict[str, Any]) -> int:
        return _as_int(f.get(bytes_field))

    top = sorted(flows, key=key_fn, reverse=True)[:limit]

    out = []
    for f in top:
        out.append({
            "src_ip": f.get("src_ip"),
            "src_port": f.get("src_port"),
            "dst_ip": f.get("dst_ip"),
            "dst_port": f.get("dst_port"),
            "protocol": f.get("protocol"),
            "app": f.get("application_name"),
            "bytes": _as_int(f.get(bytes_field)),
            "packets": _as_int(f.get("bidirectional_packets")),
            "duration_ms": _as_int(f.get("bidirectional_duration_ms")),
            "sni": f.get("requested_server_name", ""),
        })
    return out
