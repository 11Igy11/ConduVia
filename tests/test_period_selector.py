from __future__ import annotations

import unittest


class PeriodSelectorTests(unittest.TestCase):
    def test_normalize_period_mode(self):
        from core.period_selector import normalize_period_mode

        self.assertEqual(normalize_period_mode("day"), "day")
        self.assertEqual(normalize_period_mode("Month"), "month")
        self.assertEqual(normalize_period_mode("selected period"), "range")
        self.assertEqual(normalize_period_mode("selected_period"), "range")

    def test_compute_period_day_groups_falls_back_from_month(self):
        from core.period_selector import compute_period_day_groups

        raw = {f"2024-09-{day:02d}": [f"/tmp/{day}.json"] for day in range(1, 9)}
        groups, granularity, changed = compute_period_day_groups(raw, granularity="month")
        self.assertEqual(granularity, "day")
        self.assertTrue(changed)
        self.assertEqual(len(groups), 8)

    def test_compute_period_day_groups_sorts_day_view(self):
        from core.period_selector import compute_period_day_groups

        raw = {
            "2024-03-01": ["/a.pcap"],
            "2024-03-03": ["/c.pcap"],
            "2024-03-02": ["/b.pcap"],
        }
        groups, granularity, changed = compute_period_day_groups(
            raw,
            granularity="day",
            sort_day_view=True,
        )
        self.assertEqual(granularity, "day")
        self.assertFalse(changed)
        self.assertEqual(list(groups.keys()), ["2024-03-03", "2024-03-02", "2024-03-01"])

    def test_restore_range_from_raw_keys(self):
        from core.period_selector import PeriodSelectorState, restore_range_from_raw_keys

        state = PeriodSelectorState(
            granularity="day",
            day_groups_raw={"range:2024-03-01:2024-03-08": ["/merged.json"]},
        )
        self.assertTrue(restore_range_from_raw_keys(state))
        self.assertEqual(state.granularity, "range")
        self.assertEqual(state.range_start, "2024-03-01")
        self.assertEqual(state.range_end, "2024-03-08")

    def test_build_period_combo_entries_marks_saved_pcap_days(self):
        from core.period_selector import build_period_combo_entries

        entries = build_period_combo_entries(
            {"2024-03-01": []},
            granularity="day",
            kind="PCAP",
            label_saved_empty=True,
        )
        self.assertEqual(len(entries), 1)
        self.assertIn("(saved)", entries[0][1])

    def test_rebuild_period_selector_preserves_previous_key(self):
        from core.period_selector import PeriodSelectorState, rebuild_period_selector

        raw = {
            "2024-03-01": ["/a.json"],
            "2024-03-02": ["/b.json"],
        }
        state = PeriodSelectorState(day_groups_raw=raw, active_key="2024-03-01")
        paths = rebuild_period_selector(
            state,
            kind="JSON",
            previous_key="2024-03-02",
        )
        self.assertEqual(state.active_key, "2024-03-02")
        self.assertEqual(paths, ["/b.json"])

    def test_month_view_available_requires_complete_month(self):
        from core.period_selector import month_view_available

        partial = [f"2024-09-{day:02d}" for day in range(1, 9)]
        full = [f"2024-09-{day:02d}" for day in range(1, 31)]
        self.assertFalse(month_view_available(partial))
        self.assertTrue(month_view_available(full))


    def test_pick_range_button_visible_only_in_range_mode(self):
        from core.period_selector import pick_range_button_visible

        self.assertTrue(pick_range_button_visible(granularity="range", has_periods=True))
        self.assertFalse(pick_range_button_visible(granularity="day", has_periods=True))
        self.assertFalse(pick_range_button_visible(granularity="range", has_periods=False))


if __name__ == "__main__":
    unittest.main()
