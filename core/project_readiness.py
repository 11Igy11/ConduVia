from __future__ import annotations

from typing import Any, Literal

ProfileReadinessState = Literal["no_index", "building", "ready", "stale"]


def evaluate_profile_readiness(
    *,
    json_file_count: int,
    json_indexed_day_count: int,
    pcap_day_count: int,
    pcap_indexed_day_count: int = 0,
    behavior_index: dict[str, Any] | None,
    index_building: bool = False,
) -> dict[str, Any]:
    """Derive Profile readiness from evidence snapshot + cached behavior index."""
    behavior = dict(behavior_index or {})
    indexed_file_count = int(behavior.get("json_file_count") or 0)
    loaded_file_count = int(behavior.get("loaded_json_file_count") or 0)
    skipped_file_count = int(behavior.get("skipped_json_file_count") or 0)
    failed_file_count = int(behavior.get("failed_json_file_count") or 0)
    flow_count = int(behavior.get("flow_count") or 0)
    flow_day_count = len(behavior.get("day_rows") or [])

    json_file_count = max(0, int(json_file_count or 0))
    json_indexed_day_count = max(0, int(json_indexed_day_count or 0))
    pcap_day_count = max(0, int(pcap_day_count or 0))
    pcap_indexed_day_count = max(0, int(pcap_indexed_day_count or 0))
    has_evidence = json_file_count > 0 or pcap_day_count > 0 or pcap_indexed_day_count > 0

    if not has_evidence:
        return _result(
            "no_index",
            "No saved evidence yet — load JSON or save PCAP periods to build the profile.",
            detail="0 JSON files · 0 PCAP days",
            json_file_count=json_file_count,
            indexed_file_count=indexed_file_count,
            flow_count=flow_count,
            flow_day_count=flow_day_count,
        )

    if index_building:
        return _result(
            "building",
            "Behavior index is building from saved JSON evidence…",
            detail=(
                f"{json_file_count:,} JSON files · {json_indexed_day_count:,} indexed file-days · "
                f"{loaded_file_count:,} loaded so far"
            ),
            json_file_count=json_file_count,
            indexed_file_count=indexed_file_count,
            flow_count=flow_count,
            flow_day_count=flow_day_count,
        )

    if json_file_count and not flow_count:
        if loaded_file_count and failed_file_count >= loaded_file_count:
            return _result(
                "stale",
                "Behavior index could not be built from saved JSON — check files and refresh Profile.",
                detail=f"{json_file_count:,} JSON files · {failed_file_count:,} failed to load",
                json_file_count=json_file_count,
                indexed_file_count=indexed_file_count,
                flow_count=flow_count,
                flow_day_count=flow_day_count,
            )
        return _result(
            "building",
            "Behavior index is building from saved JSON evidence…",
            detail=f"{json_file_count:,} JSON files · {json_indexed_day_count:,} indexed file-days",
            json_file_count=json_file_count,
            indexed_file_count=indexed_file_count,
            flow_count=flow_count,
            flow_day_count=flow_day_count,
        )

    if json_file_count and (
        indexed_file_count < json_file_count
        or skipped_file_count > 0
        or loaded_file_count < min(json_file_count, indexed_file_count or json_file_count)
    ):
        return _result(
            "stale",
            "New JSON evidence since last index — refresh Profile to include it.",
            detail=(
                f"{json_file_count:,} JSON files saved · index covers "
                f"{indexed_file_count:,} ({skipped_file_count:,} skipped)"
            ),
            json_file_count=json_file_count,
            indexed_file_count=indexed_file_count,
            flow_count=flow_count,
            flow_day_count=flow_day_count,
        )

    if flow_count:
        detail = (
            f"{json_file_count:,} JSON files · {json_indexed_day_count:,} indexed file-days · "
            f"{flow_day_count:,} flow-activity days · "
            f"{pcap_indexed_day_count:,} PCAP indexed days · {pcap_day_count:,} PCAP saved days"
        )
        return _result(
            "ready",
            f"Profile ready — {flow_count:,} flows indexed across {flow_day_count:,} activity days.",
            detail=detail,
            json_file_count=json_file_count,
            indexed_file_count=indexed_file_count,
            flow_count=flow_count,
            flow_day_count=flow_day_count,
        )

    return _result(
        "ready",
        f"Profile ready — PCAP evidence only ({pcap_day_count:,} saved days).",
        detail=f"{pcap_day_count:,} PCAP days · no JSON behavior index",
        json_file_count=json_file_count,
        indexed_file_count=indexed_file_count,
        flow_count=flow_count,
        flow_day_count=flow_day_count,
    )


def _result(
    state: ProfileReadinessState,
    label: str,
    *,
    detail: str,
    json_file_count: int,
    indexed_file_count: int,
    flow_count: int,
    flow_day_count: int,
) -> dict[str, Any]:
    return {
        "state": state,
        "label": label,
        "detail": detail,
        "json_file_count": json_file_count,
        "indexed_file_count": indexed_file_count,
        "flow_count": flow_count,
        "flow_day_count": flow_day_count,
    }
