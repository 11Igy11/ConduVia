import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from core.db import create_project, get_project, init_db
from core.project_audit import append_project_workspace_log, record_project_activity
from ui.controllers.projects_ui_controller import ProjectsUIController


class ProjectAuditTests(unittest.TestCase):
    def test_append_project_workspace_log(self):
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "test.db"
            init_db(db_path)
            project_id = create_project("Audit test", base_folder=tmp, db_path=db_path)

            project = get_project(project_id, db_path=db_path)

            with patch("core.project_audit.get_project", return_value=project):
                append_project_workspace_log(project_id, "import_started | folder")

            log_path = Path(tmp) / "logs" / "via_nyquist.log"
            self.assertTrue(log_path.is_file())
            self.assertIn("import_started", log_path.read_text(encoding="utf-8"))

    def test_record_project_activity(self):
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "test.db"
            init_db(db_path)
            project_id = create_project("Audit test", base_folder=tmp, db_path=db_path)
            project = get_project(project_id, db_path=db_path)

            with patch("core.project_audit.add_activity") as mock_add:
                with patch("core.project_audit.get_project", return_value=project):
                    record_project_activity(project_id, "import_completed", "done")
            mock_add.assert_called_once_with(project_id, "import_completed", "done")

    def test_activity_label_maps_audit_events(self):
        controller = ProjectsUIController.__new__(ProjectsUIController)
        self.assertEqual(
            ProjectsUIController.activity_label(controller, "import_completed", ""),
            "Import completed",
        )
        self.assertIn(
            "Evidence deleted",
            ProjectsUIController.activity_label(controller, "evidence_deleted", "JSON | 1 file"),
        )


if __name__ == "__main__":
    unittest.main()
