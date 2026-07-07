from __future__ import annotations

import unittest

from core.investigation_snapshot import build_json_snapshot
from core.summary_heuristics import burst_hour_labels, service_groups_from_flows


class SummaryHeuristicsTests(unittest.TestCase):
    def test_burst_hour_labels_detects_spike(self) -> None:
        hour_hist = [2] * 24
        hour_hist[21] = 40
        hour_hist[22] = 35
        bursts = burst_hour_labels(hour_hist, min_flows=2, ratio=1.5)
        self.assertTrue(any("21:00" in item for item in bursts))

    def test_service_groups_from_flows_groups_whatsapp(self) -> None:
        flows = [
            {
                "application_name": "TLS",
                "requested_server_name": "media.whatsapp.net",
                "bidirectional_bytes": 5000,
            },
            {
                "application_name": "DNS",
                "requested_server_name": "dns.google",
                "bidirectional_bytes": 100,
            },
        ]
        groups = service_groups_from_flows(flows)
        self.assertTrue(groups)
        self.assertEqual(groups[0][0], "WhatsApp")

    def test_json_snapshot_mentions_peak_and_services(self) -> None:
        flows = []
        for hour in (21, 21, 22, 22, 22, 10, 10):
            flows.append(
                {
                    "src_ip": "10.0.0.2",
                    "dst_ip": "8.8.8.8",
                    "application_name": "TLS.ApplePush",
                    "requested_server_name": "courier.push.apple.com",
                    "bidirectional_bytes": 800 if hour >= 21 else 100,
                    "src2dst_bytes": 800 if hour >= 21 else 100,
                    "bidirectional_first_seen_ms": f"2024-07-23T{hour:02d}:15:00.000+00:00",
                }
            )
        snapshot = build_json_snapshot(flows, period_label="23/07/2024")
        joined = " ".join([snapshot.headline, *snapshot.findings, *snapshot.patterns, snapshot.apps_line])
        self.assertIn("23/07/2024", joined)
        self.assertIn("Apple", joined)
        self.assertNotIn("10.0.0.2", joined)


if __name__ == "__main__":
    unittest.main()
