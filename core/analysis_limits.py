from __future__ import annotations

"""Shared analysis limits. 0 = unlimited (show and store everything)."""

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

# Evidence queries — single cap for snapshot/index queries (0 = unlimited in slice helpers only)
MAX_EVIDENCE_SNAPSHOT_ITEMS = 50000
MAX_RECENT_UI_ROWS = 500

# Embedded profile/investigator charts: preview rows only (full data lives in tables / expand dialogs)
PROFILE_CHART_PREVIEW_ROWS = 5


def counter_most_common(counter, limit: int):
    if limit <= 0:
        return counter.most_common()
    return counter.most_common(limit)


def slice_rows(items, limit: int):
    rows = list(items)
    if limit <= 0:
        return rows
    return rows[:limit]
