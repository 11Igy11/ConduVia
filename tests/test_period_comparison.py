from __future__ import annotations

import unittest

from core.period_comparison import (
    PERIOD_COMPARISON_CHART_FOOTER,
    build_period_comparison_rows,
    comparison_status,
    volume_delta_pct,
)


class PeriodComparisonTests(unittest.TestCase):
    def test_chart_count_uses_bytes_not_flow_or_packet_counts(self):
        rows = build_period_comparison_rows(
            [{"date": "2026-01-01", "count": 1_000_000, "bytes": 500}],
            [{"date": "2026-01-01", "count": 10, "bytes": 2_000_000}],
        )
        self.assertEqual(len(rows), 1)
        row = rows[0]
        self.assertEqual(row["json_flows"], 1_000_000)
        self.assertEqual(row["pcap_packets"], 10)
        self.assertEqual(row["count"], 2_000_000)

    def test_rows_expose_separate_flow_packet_and_volume_columns(self):
        rows = build_period_comparison_rows(
            [{"date": "2026-01-01", "count": 100, "bytes": 1_000_000}],
            [{"date": "2026-01-01", "count": 95, "bytes": 1_020_000}],
        )
        row = rows[0]
        self.assertEqual(row["json_flows_label"], "100")
        self.assertEqual(row["pcap_packets_label"], "95")
        self.assertIn("KB", row["json_volume_label"])
        self.assertIn("KB", row["pcap_volume_label"])
        self.assertIn("JSON", row["volume_compare_label"])
        self.assertIn("PCAP", row["volume_compare_label"])
        self.assertEqual(row["delta_vol_label"], "+2.0%")

    def test_alignment_status_unchanged(self):
        rows = build_period_comparison_rows(
            [{"date": "2026-01-01", "count": 100, "bytes": 1_000_000}],
            [{"date": "2026-01-01", "count": 10, "bytes": 100_000}],
        )
        by_date = {row["date"]: row["status"] for row in rows}
        self.assertEqual(by_date["2026-01-01"], "Review")
        rows2 = build_period_comparison_rows(
            [{"date": "2026-01-01", "count": 100, "bytes": 1_000_000}],
            [{"date": "2026-01-01", "count": 95, "bytes": 1_020_000}],
        )
        self.assertEqual(rows2[0]["status"], "Aligned")
        rows3 = build_period_comparison_rows(
            [{"date": "2026-01-01", "count": 100, "bytes": 1_000_000}],
            [{"date": "2026-01-03", "count": 10, "bytes": 100_000}],
        )
        by_date3 = {row["date"]: row["status"] for row in rows3}
        self.assertEqual(by_date3["2026-01-01"], "JSON only")
        self.assertEqual(by_date3["2026-01-03"], "PCAP only")

    def test_volume_delta_pct_requires_both_sides(self):
        self.assertIsNone(volume_delta_pct(0, 100))
        self.assertIsNone(volume_delta_pct(100, 0))
        self.assertEqual(volume_delta_pct(100, 110), 10.0)

    def test_comparison_status_helpers(self):
        self.assertEqual(comparison_status(10, 10, 100, 100, 0.0), "Aligned")
        self.assertEqual(comparison_status(10, 0, 100, 0, None), "JSON only")

    def test_chart_footer_documents_units(self):
        self.assertIn("bytes", PERIOD_COMPARISON_CHART_FOOTER.lower())
        self.assertIn("flow", PERIOD_COMPARISON_CHART_FOOTER.lower())


if __name__ == "__main__":
    unittest.main()
