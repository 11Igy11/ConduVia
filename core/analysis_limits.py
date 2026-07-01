from __future__ import annotations

"""Shared analysis and UI preview limits.

Semantics
---------
* **0** on most counters/row limits means *unlimited* for export, tables, and stored output.
* **Hard caps** (positive constants) still apply during PCAP parsing to avoid OOM; the UI must
  surface those via ``core.limit_notices`` banners on PCAP / Profile.
* **Preview caps** (e.g. ``PROFILE_CHART_PREVIEW_ROWS``) only affect embedded charts; expand
  tables and exports use the full dataset unless another limit applies.

Where limits surface in the UI
------------------------------
+-------------------------------+--------------------------------+---------------------------+
| Constant                      | Meaning when 0                 | User-visible when capped  |
+===============================+================================+===========================+
| MAX_PCAP_FLOWS                | All flows in output            | PCAP header + Summary     |
| MAX_PCAP_FLOW_MAP_HARD_CAP    | N/A (always 75k safety)        | PCAP header + Summary     |
| MAX_PCAP_READABLE_SAMPLES     | All readable payload samples   | PCAP Summary limitations  |
| MAX_BEHAVIOR_INDEX_JSON_FILES | N/A (50k in behavior index)    | Profile limit banner      |
| MAX_BEHAVIOR_*_ROWS           | Full behavior tables           | Expand table only         |
| PROFILE_CHART_PREVIEW_ROWS    | N/A (embedded preview = 5)     | Expand table tooltip      |
| MAX_EVIDENCE_SNAPSHOT_ITEMS   | N/A (50k query cap)            | Internal / OSINT snapshot |
+-------------------------------+--------------------------------+---------------------------+
"""

# PCAP analysis engine — 0 keeps every flow, sample, and metadata row in output
MAX_PCAP_FLOWS = 0
MAX_PCAP_READABLE_SAMPLES = 0

# Hard safety caps during parsing when configured limits are 0 (unlimited). 0 = no cap.
MAX_PCAP_FLOW_MAP_HARD_CAP = 75_000
MAX_PCAP_OUTPUT_FLOWS_HARD_CAP = 0
MAX_PCAP_ARTIFACTS_HARD_CAP = 10_000
MAX_PCAP_PACKET_SLICE_BYTES = 4_194_304
MAX_PCAP_READABLE_SAMPLES_HARD_CAP = 0
MAX_PCAP_METADATA_COUNTER_HARD_CAP = 0
MAX_PCAP_COUNTER_HARD_CAP = 0
MAX_COMMUNICATION_ROWS_HARD_CAP = 0
MAX_COMMUNICATION_SCAN_HARD_CAP = 0
METADATA_TOP_DNS_ROWS = 0
METADATA_TOP_TLS_ROWS = 0
METADATA_TOP_HTTP_ROWS = 0
MAX_PCAP_PROTOCOL_ROWS = 0
MAX_PCAP_ENDPOINT_ROWS = 0
MAX_PCAP_PORT_ROWS = 0
MAX_COMMUNICATION_ROWS = 0
MAX_PCAP_ARTIFACTS_PER_KIND = 0
MAX_INVESTIGATOR_SERVICE_ROWS = 0

# Profile / behavior charts — compact embedded preview; use expand table for full lists
PROFILE_CHART_MAX_DAYS = 31  # legacy cap; embedded day charts use PROFILE_CHART_PREVIEW_ROWS
PROFILE_CHART_MAX_DEVICE_IPS = 40
EMBEDDED_SUMMARY_TOP_N = 5
SUMMARY_CARD_WIDTH = 232
SUMMARY_CARD_PADDING = 16
SUMMARY_VALUE_COL_WIDTH = 48
SUMMARY_CARD_HEIGHT = 168
SUMMARY_CARDS_WRAP_WIDTH = SUMMARY_CARD_WIDTH * 2 + 10
SUMMARY_CARDS_WRAP_HEIGHT = SUMMARY_CARD_HEIGHT * 2 + 8
LARGE_DATASET_DAY_THRESHOLD = 31
MAX_BEHAVIOR_DAY_ROWS = 0
MAX_BEHAVIOR_SERVICE_ROWS = 0
MAX_BEHAVIOR_DOMAIN_ROWS = 0
MAX_PROFILE_ACTIVITY_EVENTS = 0
MAX_PROFILE_TIMELINE_LINES = 0
MAX_BEHAVIOR_INDEX_JSON_FILES = 50_000

# Evidence queries — single cap for snapshot/index queries (0 = unlimited in slice helpers only)
MAX_EVIDENCE_SNAPSHOT_ITEMS = 50000
MAX_RECENT_UI_ROWS = 500

# Embedded profile/investigator charts: preview rows only (full data lives in tables / expand dialogs)
PROFILE_CHART_PREVIEW_ROWS = 5


def embedded_expand_available(row_count: int, *, preview_rows: int = PROFILE_CHART_PREVIEW_ROWS) -> bool:
    """Expand/export is available whenever there is at least one row."""
    return int(row_count or 0) > 0


def embedded_expand_tooltip(row_count: int, *, preview_rows: int = PROFILE_CHART_PREVIEW_ROWS) -> str:
    count = int(row_count or 0)
    if count <= 0:
        return ""
    if count > preview_rows:
        return f"{count:,} rows available — embedded chart shows top {preview_rows}."
    return f"{count:,} rows — open the full table to sort or export."


def counter_most_common(counter, limit: int):
    if limit <= 0:
        return counter.most_common()
    return counter.most_common(limit)


def slice_rows(items, limit: int):
    rows = list(items)
    if limit <= 0:
        return rows
    return rows[:limit]
