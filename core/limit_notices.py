from __future__ import annotations

from core.analysis_limits import MAX_BEHAVIOR_INDEX_JSON_FILES, MAX_PCAP_FLOW_MAP_HARD_CAP


def pcap_flow_cap_notice(
    *,
    flows_capped: bool,
    flow_map_limit: int = 0,
    total_flows: int = 0,
) -> str:
    if not flows_capped:
        return ""
    limit = int(flow_map_limit or 0) or MAX_PCAP_FLOW_MAP_HARD_CAP
    tracked = f"{total_flows:,} unique connections tracked" if total_flows else "unique connection tracking"
    return (
        f"Memory safety cap: {tracked} stopped at {limit:,} flows. "
        "Packet counts, DNS/TLS metadata, and hourly activity still include all traffic."
    )


def profile_skipped_json_notice(
    *,
    skipped_count: int,
    loaded_count: int = 0,
    indexed_file_count: int = 0,
) -> str:
    skipped = max(0, int(skipped_count or 0))
    if skipped <= 0:
        return ""
    loaded = max(0, int(loaded_count or 0))
    indexed = max(0, int(indexed_file_count or 0))
    total = max(indexed, loaded + skipped)
    return (
        f"Behavior index limit: {loaded:,} of {total:,} JSON files loaded into charts "
        f"({skipped:,} indexed files skipped — cap is {MAX_BEHAVIOR_INDEX_JSON_FILES:,}). "
        "Refresh Profile after reducing the project JSON set or use Explore/Listing for full files."
    )


def pcap_summary_limit_notes(
    *,
    flows_capped: bool,
    flow_map_limit: int = 0,
    total_flows: int = 0,
) -> list[str]:
    note = pcap_flow_cap_notice(
        flows_capped=flows_capped,
        flow_map_limit=flow_map_limit,
        total_flows=total_flows,
    )
    return [note] if note else []
