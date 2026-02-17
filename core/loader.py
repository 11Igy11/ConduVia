from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def list_json_files(folder: str | Path) -> list[Path]:
    """
    Return all .json files in folder (non-recursive) sorted by name.
    """
    p = Path(folder)
    if not p.exists() or not p.is_dir():
        raise FileNotFoundError(f"Folder not found: {p}")

    return sorted(
        [x for x in p.iterdir() if x.is_file() and x.suffix.lower() == ".json"],
        key=lambda x: x.name,
    )


def load_json_file(path: str | Path, *, debug: bool = False) -> list[dict[str, Any]]:
    """
    Load one JSON file and return a list of flow dicts.

    Supported structures:
    1) Top-level list: [ {...flow...}, {...flow...}, ... ]
    2) Top-level dict wrapper, common keys:
       { "flow": [ ... ] } (your case)
       { "flows": [ ... ] }
       { "data": [ ... ] }
       { "items": [ ... ] }
       { "records": [ ... ] }
    3) Top-level dict wrapper where the key contains a single flow object:
       { "flow": { ... } } -> returns [ { ... } ]
    """
    p = Path(path)
    with p.open("r", encoding="utf-8") as f:
        data = json.load(f)

    if debug:
        if isinstance(data, dict):
            print(f"[DEBUG] {p.name}: top-level dict keys = {list(data.keys())[:30]}")
            if "flow" in data:
                print(f"[DEBUG] {p.name}: type(flow) = {type(data['flow']).__name__}")
        else:
            print(f"[DEBUG] {p.name}: top-level type = {type(data).__name__}")

    # Case 1: list of flows
    if isinstance(data, list):
        return [x for x in data if isinstance(x, dict)]

    # Case 2/3: dict wrapper
    if isinstance(data, dict):
        for key in ("flow", "flows", "data", "records", "items"):
            if key in data:
                val = data[key]
                if isinstance(val, list):
                    return [x for x in val if isinstance(x, dict)]
                if isinstance(val, dict):
                    return [val]

    raise ValueError(
        f"Unsupported JSON structure in: {p.name} "
        f"(top-level type: {type(data).__name__})"
    )


def load_folder(folder: str | Path, *, debug: bool = False) -> tuple[list[Path], list[dict[str, Any]]]:
    """
    Load all JSON files from a folder and merge flows into one list.

    Returns: (files, flows)
    """
    files = list_json_files(folder)
    all_flows: list[dict[str, Any]] = []

    for fp in files:
        flows = load_json_file(fp, debug=debug)
        all_flows.extend(flows)

    return files, all_flows
