import tempfile
import unittest
from pathlib import Path

from core.db import (
    create_project,
    init_db,
    mark_ingest_item,
    save_pcap_period_summary,
    upsert_ingest_items,
)
from core.project_evidence import (
    build_project_evidence_snapshot,
    get_project_evidence_totals,
    invalidate_project_evidence_cache,
    json_day_groups_from_ingest,
    list_saved_json_days,
    list_saved_pcap_days,
    resolve_saved_pcap_day_row,
)


class ProjectEvidenceTests(unittest.TestCase):
    def _seed_project(self, db_path: Path, tmp: str) -> int:
        init_db(db_path)
        return create_project("Evidence case", base_folder=tmp, db_path=db_path)

    def test_pcap_day_rows_share_paths_and_counts(self):
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "evidence.db"
            project_id = self._seed_project(db_path, tmp)
            pcap_a = Path(tmp) / "a.pcap"
            pcap_b = Path(tmp) / "b.pcap"
            pcap_a.write_bytes(b"pcap-a")
            pcap_b.write_bytes(b"pcap-b")

            save_pcap_period_summary(
                project_id,
                period_day="2024-02-25",
                file_path="25/02/2024 (3 PCAP files)",
                file_sha256_value="aggregate:one",
                file_size=1000,
                file_name="25/02/2024 (3 PCAP files)",
                packet_count=100,
                wire_bytes=500,
                first_seen="2024-02-25 00:10:00.000",
                last_seen="2024-02-25 23:50:00.000",
                db_path=db_path,
            )
            upsert_ingest_items(
                project_id,
                tmp,
                [
                    {
                        "file_path": str(pcap_a),
                        "file_name": "a.pcap",
                        "file_type": "pcap",
                        "file_size": 100,
                        "observed_date": "2024-02-25",
                    },
                    {
                        "file_path": str(pcap_b),
                        "file_name": "b.pcap",
                        "file_type": "pcap",
                        "file_size": 100,
                        "observed_date": "2024-02-25",
                    },
                ],
                db_path=db_path,
            )
            mark_ingest_item(project_id, str(pcap_a), "done", db_path=db_path)
            mark_ingest_item(project_id, str(pcap_b), "done", db_path=db_path)

            totals = get_project_evidence_totals(project_id, db_path=db_path)
            pcap_days = list_saved_pcap_days(project_id, db_path=db_path)
            snapshot = build_project_evidence_snapshot(project_id, db_path=db_path)

        self.assertEqual(totals["pcap_saved_day_count"], 1)
        self.assertEqual(len(pcap_days), 1)
        self.assertEqual(pcap_days[0]["day"], "2024-02-25")
        self.assertEqual(len(pcap_days[0]["paths"]), 2)
        self.assertEqual(snapshot["pcap"]["recent_day_rows"], pcap_days)
        self.assertEqual(snapshot["pcap"]["day_rows"][0]["date"], "2024-02-25")

    def test_json_days_aggregate_by_calendar_day(self):
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "evidence.db"
            project_id = self._seed_project(db_path, tmp)
            upsert_ingest_items(
                project_id,
                tmp,
                [
                    {
                        "file_path": str(Path(tmp) / "one.json"),
                        "file_name": "one.json",
                        "file_type": "json",
                        "file_size": 10,
                        "observed_date": "2024-03-01",
                    },
                    {
                        "file_path": str(Path(tmp) / "two.json"),
                        "file_name": "two.json",
                        "file_type": "json",
                        "file_size": 10,
                        "observed_date": "2024-03-01",
                    },
                ],
                db_path=db_path,
            )

            totals = get_project_evidence_totals(project_id, db_path=db_path)
            json_days = list_saved_json_days(project_id, db_path=db_path)

        self.assertEqual(totals["json_file_count"], 2)
        self.assertEqual(totals["json_day_count"], 1)
        self.assertEqual(len(json_days), 1)
        self.assertEqual(json_days[0]["file_count"], 2)
        self.assertEqual(len(json_days[0]["paths"]), 2)

    def test_json_day_groups_from_ingest_groups_loadable_paths(self):
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "evidence.db"
            project_id = self._seed_project(db_path, tmp)
            json_a = Path(tmp) / "a.json"
            json_b = Path(tmp) / "b.json"
            json_a.write_text("[]", encoding="utf-8")
            json_b.write_text("[]", encoding="utf-8")
            upsert_ingest_items(
                project_id,
                tmp,
                [
                    {
                        "file_path": str(json_a),
                        "file_name": "a.json",
                        "file_type": "json",
                        "file_size": 10,
                        "observed_date": "2024-03-01",
                    },
                    {
                        "file_path": str(json_b),
                        "file_name": "b.json",
                        "file_type": "json",
                        "file_size": 10,
                        "observed_date": "2024-03-02",
                    },
                ],
                db_path=db_path,
            )

            by_day = json_day_groups_from_ingest(project_id, db_path=db_path)

        self.assertEqual(list(by_day.keys()), ["2024-03-02", "2024-03-01"])
        self.assertEqual(len(by_day["2024-03-01"]), 1)
        self.assertEqual(len(by_day["2024-03-02"]), 1)

    def test_resolve_saved_pcap_day_row_uses_day_key(self):
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "evidence.db"
            project_id = self._seed_project(db_path, tmp)
            save_pcap_period_summary(
                project_id,
                period_day="2024-02-25",
                file_path="25/02/2024 (3 PCAP files)",
                file_sha256_value="aggregate:one",
                file_size=1000,
                file_name="25/02/2024 (3 PCAP files)",
                packet_count=100,
                wire_bytes=500,
                first_seen="2024-02-25 00:10:00.000",
                last_seen="2024-02-25 23:50:00.000",
                db_path=db_path,
            )

            row = resolve_saved_pcap_day_row(project_id, day="2024-02-25", db_path=db_path)

        self.assertIsNotNone(row)
        assert row is not None
        self.assertEqual(row["day"], "2024-02-25")
        self.assertIn("paths", row)

    def test_snapshot_cache_invalidates(self):
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "evidence.db"
            project_id = self._seed_project(db_path, tmp)
            first = get_project_evidence_totals(project_id, db_path=db_path)
            build_project_evidence_snapshot(project_id, db_path=db_path)
            invalidate_project_evidence_cache(project_id, db_path=db_path)
            upsert_ingest_items(
                project_id,
                tmp,
                [
                    {
                        "file_path": str(Path(tmp) / "one.json"),
                        "file_name": "one.json",
                        "file_type": "json",
                        "file_size": 10,
                        "observed_date": "2024-04-01",
                    },
                ],
                db_path=db_path,
            )
            second = get_project_evidence_totals(project_id, db_path=db_path)

        self.assertEqual(first["json_file_count"], 0)
        self.assertEqual(second["json_file_count"], 1)


if __name__ == "__main__":
    unittest.main()
