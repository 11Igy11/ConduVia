from __future__ import annotations

import unittest

from core.pcap_batch import batch_progress_ui_interval, format_batch_status_text


class PcapBatchHelperTests(unittest.TestCase):
    def test_batch_progress_ui_interval_scales_with_total(self):
        self.assertEqual(batch_progress_ui_interval(10), 0.15)
        self.assertEqual(batch_progress_ui_interval(100), 0.25)
        self.assertEqual(batch_progress_ui_interval(500), 0.5)
        self.assertEqual(batch_progress_ui_interval(2000), 1.0)

    def test_format_batch_status_text_hidden_when_idle(self):
        self.assertIsNone(
            format_batch_status_text(
                queue_auto_process=False,
                batch_running=False,
                queue_length=0,
                batch_processed=0,
                batch_total=0,
                batch_failed=0,
            )
        )

    def test_format_batch_status_text_includes_context_day(self):
        text = format_batch_status_text(
            queue_auto_process=True,
            batch_running=True,
            queue_length=0,
            batch_processed=2,
            batch_total=10,
            batch_failed=0,
            context_day="Mon 2026-01-01",
        )
        self.assertIn("Auto batch", text or "")
        self.assertIn("Mon 2026-01-01", text or "")
        self.assertIn("2 / 10", text or "")


if __name__ == "__main__":
    unittest.main()
