from __future__ import annotations
from core.flow_stats import compute_registry_summary as _compute_registry_summary

import json
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

def compute_registry_summary(flows: list[dict[str, Any]], top_n: int = 10) -> dict[str, Any]:
    return _compute_registry_summary(flows, top_n=top_n)
