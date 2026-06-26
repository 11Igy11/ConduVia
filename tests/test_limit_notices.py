from __future__ import annotations

import unittest

from core.analysis_limits import MAX_BEHAVIOR_INDEX_JSON_FILES, MAX_PCAP_FLOW_MAP_HARD_CAP
from core.limit_notices import pcap_flow_cap_notice, profile_skipped_json_notice
from core.pcap_analyzer import PcapSummary, build_investigator_view


class LimitNoticeTests(unittest.TestCase):
    def test_pcap_flow_cap_notice_empty_when_not_capped(self):
        self.assertEqual(pcap_flow_cap_notice(flows_capped=False), "")

    def test_pcap_flow_cap_notice_uses_hard_cap_default(self):
        text = pcap_flow_cap_notice(flows_capped=True, total_flows=80_000)
        self.assertIn(f"{MAX_PCAP_FLOW_MAP_HARD_CAP:,}", text)
        self.assertIn("80,000", text)

    def test_profile_skipped_json_notice_empty_when_none_skipped(self):
        self.assertEqual(profile_skipped_json_notice(skipped_count=0), "")

    def test_profile_skipped_json_notice_mentions_cap(self):
        text = profile_skipped_json_notice(
            skipped_count=501,
            loaded_count=50_000,
            indexed_file_count=50_501,
        )
        self.assertIn("501", text)
        self.assertIn(f"{MAX_BEHAVIOR_INDEX_JSON_FILES:,}", text)

    def test_investigator_view_includes_flow_cap_limitation(self):
        summary = PcapSummary(
            flows_capped=True,
            flow_map_limit=MAX_PCAP_FLOW_MAP_HARD_CAP,
            total_flows=MAX_PCAP_FLOW_MAP_HARD_CAP,
        )
        view = build_investigator_view(summary)
        limitations = view.get("limitations") or []
        self.assertTrue(any("Memory safety cap" in item for item in limitations))


if __name__ == "__main__":
    unittest.main()
