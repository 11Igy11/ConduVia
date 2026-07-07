from __future__ import annotations

import unittest

from core.pcap_analyzer import build_communication_rows
from core.service_classification import communication_indicator_tier


class CommunicationAggregationTests(unittest.TestCase):
    def test_identical_flows_aggregate_into_one_row(self) -> None:
        base = {
            "src_ip": "10.0.0.10",
            "src_port": 51000,
            "dst_ip": "17.253.144.10",
            "dst_port": 443,
            "protocol": 6,
            "application_name": "TLS",
            "requested_server_name": "courier2.push.apple.com",
            "bidirectional_bytes": 4200,
            "bidirectional_packets": 12,
            "bidirectional_duration_ms": 4500,
            "bidirectional_first_seen_ms": "2024-02-01 09:00:00.000",
            "bidirectional_last_seen_ms": "2024-02-01 09:00:04.500",
        }
        flows = [dict(base) for _ in range(12)]

        rows = build_communication_rows(flows)

        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["sessions"], 12)
        self.assertEqual(rows[0]["service"], "Apple / iCloud")
        self.assertEqual(rows[0]["tier"], "routine")
        self.assertIn("Push channel", rows[0]["activity_label"])

    def test_whatsapp_udp_session_is_review_tier(self) -> None:
        flows = [
            {
                "src_ip": "10.0.0.10",
                "src_port": 51000,
                "dst_ip": "31.13.84.51",
                "dst_port": 443,
                "protocol": 17,
                "application_name": "QUIC/HTTP3",
                "requested_server_name": "media.whatsapp.net",
                "bidirectional_bytes": 900000,
                "bidirectional_packets": 350,
                "bidirectional_duration_ms": 65000,
                "bidirectional_first_seen_ms": "2026-01-04 09:00:00.000",
                "bidirectional_last_seen_ms": "2026-01-04 09:01:05.000",
            }
        ]

        rows = build_communication_rows(flows)

        self.assertEqual(rows[0]["service"], "WhatsApp")
        self.assertEqual(rows[0]["tier"], "review")
        self.assertIn("call", rows[0]["type"].lower())

    def test_tier_helper_marks_background_as_routine(self) -> None:
        row = {
            "activity_type": "Background keepalive / sync connection",
            "confidence": "low",
            "family": "background",
        }
        self.assertEqual(communication_indicator_tier(row), "routine")


if __name__ == "__main__":
    unittest.main()
