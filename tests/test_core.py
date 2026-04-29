from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from core.ai.assistant_service import AIAssistantService, AISettings
from core.ai.context_builder import build_dataset_context
from core.ai.prompts import build_dataset_summary_prompt
from core.compare import compare_flows, summarize_new_flows
from core.flow_stats import compute_registry_summary, top_field_by_bytes, top_field_values
from core.formatters import (
    format_duration_hms_ms,
    format_flow_date,
    format_flow_datetime,
    format_flow_time,
    format_short_date,
    human_bytes,
    safe_int,
)
from core.loader import list_json_files, load_folder, load_json_file
from core.protocols import describe_ip_proto, format_ip_proto_with_description
from core.timeutils import LOCAL_TZ, parse_timestamp
from core.workspace import (
    WORKSPACE_MARKER,
    ensure_workspace_structure,
    looks_like_vianyquist_workspace,
    make_safe_project_folder_name,
)


def _temp_parent() -> Path:
    configured = os.environ.get("VIANYQUIST_TEST_TMP")
    parent = Path(configured) if configured else Path(tempfile.gettempdir()) / "vianyquist-tests"
    parent.mkdir(parents=True, exist_ok=True)
    return parent


def temporary_directory():
    return tempfile.TemporaryDirectory(dir=_temp_parent())


class LoaderTests(unittest.TestCase):
    def test_load_json_file_supports_wrapped_flow_list(self):
        with temporary_directory() as tmp:
            path = Path(tmp) / "sample.json"
            path.write_text(
                json.dumps({
                    "liid": "L-1",
                    "flow": [
                        {"src_ip": "10.0.0.1"},
                        "ignored",
                        {"src_ip": "10.0.0.2"},
                    ],
                }),
                encoding="utf-8",
            )

            flows = load_json_file(path)

        self.assertEqual(flows, [{"src_ip": "10.0.0.1"}, {"src_ip": "10.0.0.2"}])

    def test_load_folder_uses_sorted_json_files_only(self):
        with temporary_directory() as tmp:
            root = Path(tmp)
            (root / "b.json").write_text(json.dumps([{"id": "b"}]), encoding="utf-8")
            (root / "a.json").write_text(json.dumps([{"id": "a"}]), encoding="utf-8")
            (root / "ignore.txt").write_text("{}", encoding="utf-8")

            files = list_json_files(root)
            _loaded_files, flows = load_folder(root)

        self.assertEqual([p.name for p in files], ["a.json", "b.json"])
        self.assertEqual([f["id"] for f in flows], ["a", "b"])


class TimeAndFormatterTests(unittest.TestCase):
    def test_parse_timestamp_uses_local_timezone_for_naive_strings(self):
        dt = parse_timestamp("2024-05-28 22:00:00")

        self.assertIsNotNone(dt)
        self.assertEqual(dt.tzinfo, LOCAL_TZ)
        self.assertEqual(dt.strftime("%Y-%m-%d %H:%M:%S"), "2024-05-28 22:00:00")

    def test_formatters_cover_common_report_values(self):
        self.assertEqual(safe_int("12.9"), 12)
        self.assertEqual(safe_int("bad"), 0)
        self.assertEqual(human_bytes(1536, precision=1), "1.5 KB")
        self.assertEqual(format_duration_hms_ms(3_723_004), "01:02:03.004")
        self.assertEqual(format_flow_date("2024-05-28 22:01:02"), "28.05.2024")
        self.assertEqual(format_flow_time("2024-05-28 22:01:02"), "22:01:02")
        self.assertEqual(format_flow_datetime("2024-05-28 22:01:02.123456", milliseconds=True), "28.05.2024 22:01:02.123")

    def test_short_date_converts_offset_timestamp_to_local_date(self):
        self.assertEqual(format_short_date("2024-05-28T22:00:00.000+00:00"), "29.05.2024.")


class FlowStatsTests(unittest.TestCase):
    def test_top_values_and_bytes_share_one_implementation(self):
        flows = [
            {"src_ip": "10.0.0.1", "application_name": "A", "bidirectional_bytes": "100"},
            {"src_ip": "10.0.0.1", "application_name": "", "bidirectional_bytes": 50},
            {"src_ip": "10.0.0.2", "application_name": "A", "bidirectional_bytes": "bad"},
        ]

        self.assertEqual(top_field_values(flows, "src_ip"), [("10.0.0.1", 2), ("10.0.0.2", 1)])
        self.assertEqual(
            top_field_by_bytes(flows, "application_name", include_empty=True, empty_label="Unknown"),
            [("A", 100), ("Unknown", 50)],
        )

    def test_registry_summary_includes_counts_bytes_and_time_buckets(self):
        flows = [
            {
                "src_ip": "10.0.0.1",
                "dst_ip": "8.8.8.8",
                "protocol": 6,
                "application_name": "A",
                "bidirectional_bytes": "100",
                "bidirectional_first_seen_ms": "2024-01-01 10:00:00",
            },
            {
                "src_ip": "10.0.0.1",
                "dst_ip": "1.1.1.1",
                "protocol": 17,
                "application_name": "B",
                "bidirectional_bytes": 50,
                "bidirectional_first_seen_ms": "2024-01-01 11:00:00",
            },
        ]

        summary = compute_registry_summary(flows, top_n=5)

        self.assertEqual(summary["total_flows"], 2)
        self.assertEqual(summary["total_bytes"], 150)
        self.assertEqual(summary["top_src"], [("10.0.0.1", 2)])
        self.assertEqual(summary["top_bytes_dst"], [("8.8.8.8", 100), ("1.1.1.1", 50)])
        self.assertEqual(summary["top_date"], [("2024-01-01", 2)])
        self.assertEqual(summary["top_hour"], [("2024-01-01 10", 1), ("2024-01-01 11", 1)])


class CompareTests(unittest.TestCase):
    def test_compare_flows_reports_new_and_known_fingerprints(self):
        previous = [
            {"src_ip": "10.0.0.1", "dst_ip": "8.8.8.8", "application_name": "A", "protocol": 6, "requested_server_name": "a.test"}
        ]
        current = previous + [
            {"src_ip": "10.0.0.2", "dst_ip": "1.1.1.1", "application_name": "B", "protocol": 17, "requested_server_name": "b.test"}
        ]

        result = compare_flows(current, previous)
        new_summary = summarize_new_flows(result["new"])

        self.assertEqual(result["total_current"], 2)
        self.assertEqual(result["total_previous"], 1)
        self.assertEqual(len(result["known"]), 1)
        self.assertEqual(new_summary["new_apps"], ["B"])
        self.assertEqual(new_summary["new_dst_ips"], ["1.1.1.1"])
        self.assertEqual(new_summary["new_sni"], ["b.test"])


class ProtocolTests(unittest.TestCase):
    def test_protocol_descriptions_explain_without_confirming_service(self):
        self.assertIn("Connection-oriented transport", describe_ip_proto(6))
        self.assertIn("Connectionless transport", describe_ip_proto("UDP"))
        self.assertIn("purpose is not confirmed", describe_ip_proto(250))
        self.assertIn("TCP (6) - Connection-oriented transport", format_ip_proto_with_description(6))


class WorkspaceTests(unittest.TestCase):
    def test_workspace_marker_controls_vianyquist_workspace_detection(self):
        with temporary_directory() as tmp:
            root = Path(tmp) / "case"
            (root / "notes").mkdir(parents=True)

            self.assertFalse(looks_like_vianyquist_workspace(str(root)))

            ensure_workspace_structure(str(root))

            self.assertTrue((root / WORKSPACE_MARKER).exists())
            self.assertTrue(looks_like_vianyquist_workspace(str(root)))

    def test_project_folder_name_is_windows_safe(self):
        self.assertEqual(make_safe_project_folder_name(' Case: A/B? '), "Case_A_B")


class AIServiceTests(unittest.TestCase):
    def test_ai_settings_builds_generate_url(self):
        settings = AISettings(base_url="http://localhost:11434/", model="m", timeout_seconds=5)

        self.assertEqual(settings.generate_url, "http://localhost:11434/api/generate")

    def test_generate_uses_configured_endpoint_model_and_timeout(self):
        class FakeResponse:
            status_code = 200

            def json(self):
                return {"response": "ok"}

        service = AIAssistantService(
            AISettings(base_url="http://ai.local", model="custom-model", timeout_seconds=7)
        )

        with patch.object(service, "_post_generate", return_value=FakeResponse()) as post:
            result = service._generate("hello")

        self.assertEqual(result, "ok")
        post.assert_called_once()
        self.assertEqual(post.call_args.args, ("hello",))
        self.assertEqual(service.settings.model, "custom-model")
        self.assertEqual(service.settings.timeout_seconds, 7)

    def test_dataset_context_includes_behavior_indicators(self):
        flows = [
            {
                "src_ip": "10.0.0.1",
                "dst_ip": "8.8.8.8",
                "protocol": 6,
                "application_name": "A",
                "bidirectional_bytes": "2048",
                "bidirectional_packets": 10,
                "bidirectional_duration_ms": 1000,
                "bidirectional_first_seen_ms": "2024-01-01 10:00:00",
            }
        ]

        context = build_dataset_context(flows)

        self.assertIn("Dataset-level behavior indicators", context)
        self.assertIn("Top source IPs by bytes", context)
        self.assertIn("Largest individual flows", context)
        self.assertIn("Connection-oriented transport", context)

    def test_dataset_prompt_encourages_interpretation_without_cyber_mode(self):
        prompt = build_dataset_summary_prompt("context")

        self.assertIn("The user wants interpretation", prompt)
        self.assertIn("Do not jump into cybersecurity mode", prompt)
        self.assertIn("Limits Of Interpretation", prompt)


if __name__ == "__main__":
    unittest.main()
