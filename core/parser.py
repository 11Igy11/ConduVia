from __future__ import annotations
from core.timeutils import parse_flow_timestamp, date_key, hour_key

import json
from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

PREFERRED_COLUMNS = [
    "src_ip", "src_port", "dst_ip", "dst_port",
    "protocol", "application_name", "requested_server_name",
    "bidirectional_first_seen_ms", "bidirectional_last_seen_ms",
    "bidirectional_duration_ms",
    "bidirectional_packets", "bidirectional_bytes",
]

def extract_dataset_meta(json_path: str | Path) -> dict[str, Any]:
    """
    Reads wrapper fields from one JSON file (liid/target/case/etc).
    Safe: if structure differs, returns partial meta.
    """
    p = Path(json_path)
    with p.open("r", encoding="utf-8") as f:
        data = json.load(f)

    if not isinstance(data, dict):
        return {"source_file": p.name}

    meta: dict[str, Any] = {"source_file": p.name}

    # direct wrapper fields
    for k in ("liid", "target", "targettype", "interceptId", "intercept_id"):
        if k in data and data[k] is not None:
            meta[k] = data[k]

    # case list (your sample uses case[0].RegNo / OrigRegNo / bt / et)
    case_list = data.get("case")
    if isinstance(case_list, list) and case_list and isinstance(case_list[0], dict):
        c0 = case_list[0]
        meta["RegNo"] = c0.get("RegNo")            # map -> Urbroj
        meta["OrigRegNo"] = c0.get("OrigRegNo")    # map -> Klasa
        meta["bt"] = c0.get("bt")
        meta["et"] = c0.get("et")

    return meta

def build_registry_columns(flows: list[dict[str, Any]]) -> list[str]:
    all_cols: set[str] = set()
    for f in flows:
        if isinstance(f, dict):
            all_cols.update(f.keys())

    cols: list[str] = []
    for c in PREFERRED_COLUMNS:
        if c in all_cols:
            cols.append(c)

    # add the rest alphabetically
    for c in sorted(all_cols):
        if c not in cols:
            cols.append(c)

    return cols

def _parse_ts_prefix(ts: Any, mode: str) -> str:
    """
    mode: 'date' -> YYYY-MM-DD
          'hour' -> YYYY-MM-DD HH
    Handles strings like '2024-08-18 00:00:01.123456'
    """
    if not ts:
        return ""
    s = str(ts)
    if len(s) < 10:
        return ""
    if mode == "date":
        return s[:10]
    if mode == "hour":
        return s[:13]  # YYYY-MM-DD HH
    return ""

def compute_registry_summary(flows: list[dict[str, Any]], top_n: int = 10) -> dict[str, Any]:
    src_c = Counter()
    dst_c = Counter()
    proto_c = Counter()
    app_c = Counter()

    # bytes aggregation
    bytes_by_src = defaultdict(int)
    bytes_by_dst = defaultdict(int)
    bytes_by_app = defaultdict(int)

    # time aggregation
    by_date = Counter()
    by_hour = Counter()

    for f in flows:
        if not isinstance(f, dict):
            continue

        src = str(f.get("src_ip") or "")
        dst = str(f.get("dst_ip") or "")
        proto = str(f.get("protocol") or "")
        app = str(f.get("application_name") or "")
        b = f.get("bidirectional_bytes")

        try:
            b_int = int(b) if b is not None and b != "" else 0
        except Exception:
            b_int = 0

        if src:
            src_c[src] += 1
            bytes_by_src[src] += b_int
        if dst:
            dst_c[dst] += 1
            bytes_by_dst[dst] += b_int
        if proto:
            proto_c[proto] += 1
        if app:
            app_c[app] += 1
            bytes_by_app[app] += b_int

        dt = parse_flow_timestamp(f)
        if dt is not None:
            by_date[date_key(dt)] += 1
            by_hour[hour_key(dt)] += 1

    def top_counter(c: Counter, n: int):
        return c.most_common(n)

    def top_bytes_map(m: dict[str, int], n: int):
        return sorted(m.items(), key=lambda kv: kv[1], reverse=True)[:n]

    return {
        "top_src": top_counter(src_c, top_n),
        "top_dst": top_counter(dst_c, top_n),
        "top_proto": top_counter(proto_c, top_n),
        "top_app": top_counter(app_c, top_n),
        "top_date": by_date.most_common(top_n),
        "top_hour": by_hour.most_common(top_n),
        "top_bytes_src": top_bytes_map(bytes_by_src, top_n),
        "top_bytes_dst": top_bytes_map(bytes_by_dst, top_n),
        "top_bytes_app": top_bytes_map(bytes_by_app, top_n),
        "total_flows": len(flows),
    }