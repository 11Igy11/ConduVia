from __future__ import annotations

import unittest
from datetime import datetime

from core.period_calendar import (
    calendar_day_coverage_note,
    filter_hourly_activity_to_calendar_day,
    format_calendar_day_window,
    flow_on_calendar_day,
    refine_pcap_summary_for_calendar_day,
)
from core.pcap_analyzer import PcapSummary
from core.timeutils import LOCAL_TZ


class PeriodCalendarTests(unittest.TestCase):
    def test_format_calendar_day_window_is_full_day(self) -> None:
        start, end = format_calendar_day_window("2024-07-23")
        self.assertEqual(start, "2024-07-23 00:00:00.000")
        self.assertEqual(end, "2024-07-23 23:59:59.999")

    def test_coverage_note_reports_activity_not_window_span(self) -> None:
        day = "2024-07-25"
        start = datetime(2024, 7, 25, 0, 0, 15, 217000, tzinfo=LOCAL_TZ)
        end = datetime(2024, 7, 25, 23, 59, 10, 874000, tzinfo=LOCAL_TZ)
        flows = [
            {"bidirectional_first_seen_ms": int(start.timestamp() * 1000)},
            {"bidirectional_last_seen_ms": int(end.timestamp() * 1000)},
        ]
        note = calendar_day_coverage_note(flows, day)
        self.assertIn("Traffic observed", note)
        self.assertNotIn("Calendar day coverage:", note)
        self.assertIn("00:00:15", note)
        self.assertIn("23:59:10", note)

    def test_flow_on_calendar_day_respects_midnight_boundary(self) -> None:
        inside = datetime(2024, 7, 3, 23, 59, 57, tzinfo=LOCAL_TZ)
        outside = datetime(2024, 7, 4, 0, 0, 1, tzinfo=LOCAL_TZ)
        self.assertTrue(
            flow_on_calendar_day(
                {"bidirectional_first_seen_ms": int(inside.timestamp() * 1000)},
                "2024-07-03",
            )
        )
        self.assertFalse(
            flow_on_calendar_day(
                {"bidirectional_first_seen_ms": int(outside.timestamp() * 1000)},
                "2024-07-03",
            )
        )

    def test_filter_hourly_activity_to_calendar_day(self) -> None:
        rows = [
            {"hour": "2024-05-30 11:00", "packets": 55479},
            {"hour": "2024-05-31 11:00", "packets": 21761},
            {"hour": "2024-05-31 12:00", "packets": 9000},
        ]
        filtered = filter_hourly_activity_to_calendar_day(rows, "2024-05-31")
        self.assertEqual([row["hour"] for row in filtered], ["2024-05-31 11:00", "2024-05-31 12:00"])
        self.assertEqual(sum(int(row["packets"]) for row in filtered), 30761)

    def test_refine_pcap_summary_filters_hourly_and_service_metadata(self) -> None:
        inside = datetime(2024, 5, 31, 11, 30, tzinfo=LOCAL_TZ)
        summary = PcapSummary(
            packet_count=120000,
            hourly_activity=[
                {"hour": "2024-05-30 11:00", "packets": 55479},
                {"hour": "2024-05-31 11:00", "packets": 21761},
            ],
            tls_sni=[{"host": "old.example", "count": 99999}],
            flows=[
                {
                    "bidirectional_first_seen_ms": int(inside.timestamp() * 1000),
                    "bidirectional_packets": 500,
                    "bidirectional_bytes": 12000,
                    "requested_server_name": "gateway.icloud.com",
                }
            ],
        )
        refined, _note = refine_pcap_summary_for_calendar_day(summary, "2024-05-31")
        hours = [row["hour"] for row in refined.hourly_activity]
        self.assertEqual(hours, ["2024-05-31 11:00"])
        self.assertEqual(int(refined.hourly_activity[0]["packets"]), 21761)
        self.assertEqual(refined.packet_count, 500)
        self.assertTrue(any("icloud" in str(row.get("host") or "").lower() for row in refined.tls_sni))
        self.assertFalse(any("old.example" in str(row.get("host") or "") for row in refined.tls_sni))


if __name__ == "__main__":
    unittest.main()
