import unittest
from unittest.mock import patch

from ui.controllers.dataset_ingest_mixin import DatasetIngestMixin


class _FakeApp:
    current_project_id = 1


class _FakeController(DatasetIngestMixin):
    def __init__(self):
        self.app = _FakeApp()
        self._import_plan = {"phase": "done"}
        self._import_finalize_running = True
        self._import_finalize_pending = False
        self._import_finalize_completed = False
        self._defer_import_finalize = False
        self._load_thread = object()
        self._pending_import_banner_message = ""
        self.progress_calls = []
        self.deferred_sync_calls = []
        self.refresh_calls = 0
        self.end_calls = 0
        self.completed_calls = 0

    def _thread_is_running(self, thread):
        return thread is self._load_thread

    def update_import_progress(self, **kwargs):
        self.progress_calls.append(kwargs)

    def deferred_sync_project_periods(self, project_id):
        self.deferred_sync_calls.append(project_id)

    def _finalize_import_refresh(self):
        self.refresh_calls += 1

    def end_import_session(self):
        self.end_calls += 1

    def _record_import_completed(self, project_id):
        self.completed_calls += 1


class ImportFinalizeTests(unittest.TestCase):
    def test_finish_import_defers_while_json_load_thread_running(self):
        controller = _FakeController()

        controller._finish_import_processing("json")

        self.assertIsNone(controller._import_plan)
        self.assertFalse(controller._import_finalize_running)
        self.assertTrue(controller._defer_import_finalize)
        self.assertFalse(controller._import_finalize_completed)
        self.assertEqual(controller.deferred_sync_calls, [])
        self.assertEqual(controller.refresh_calls, 0)
        self.assertEqual(controller.end_calls, 0)
        self.assertEqual(controller.completed_calls, 0)
        self.assertEqual(len(controller.progress_calls), 1)
        self.assertEqual(controller.progress_calls[0]["phase"], "Loading JSON flows")

    def test_pending_pcap_plan_will_batch(self):
        controller = _FakeController()
        scan = type("Scan", (), {"json_files": [], "pcap_files": [], "pcap_size": 0})()
        with patch.object(
            controller,
            "_plan_scanned_pcap_import",
            return_value={"save_all_periods": True},
        ):
            self.assertTrue(controller._pending_pcap_plan_will_batch(("folder", scan)))


if __name__ == "__main__":
    unittest.main()
