from __future__ import annotations

import json
import os
import struct
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from core.ai.assistant_service import AIAssistantService, AISettings
from core.ai.context_builder import build_activity_profile_context, build_dataset_context, build_pcap_context
from core.ai.prompts import build_activity_profile_summary_prompt, build_dataset_summary_prompt, build_pcap_summary_prompt
from core.behavior_profile import build_flow_behavior_profile
from core.compare import compare_flows, summarize_new_flows
from core.db import (
    add_dataset_load,
    add_finding,
    add_pcap_source,
    create_project,
    file_sha256,
    get_app_setting,
    get_app_settings,
    get_project,
    init_db,
    list_pcap_sources,
    list_project_pcap_device_ips,
    list_recent_datasets,
    set_app_setting,
    set_project_subject,
    set_project_target,
)
from core.flow_stats import compute_registry_summary, top_field_by_bytes, top_field_values
from core.formatters import (
    format_duration_hms_ms,
    format_flow_date,
    format_flow_datetime,
    format_flow_time,
    format_pcap_datetime,
    format_short_date,
    human_bytes,
    safe_int,
)
from core.exporters.listing_exporter import export_listing_html
from core.exporters.profile_exporter import export_activity_profile_html
from core.exporters.pcap_exporter import export_pcap_summary_html
from core.exporters.registry_exporter import export_registry_html
from core.loader import list_json_files, load_folder, load_json_file
from core.parser import extract_dataset_meta
from core.pcap_analyzer import analyze_pcap, build_communication_rows, build_investigator_view
from core.project_datasets import load_project_dataset_flows
from core.project_identity import identifier_values_match, is_valid_oib, normalize_identifier_value
from core.project_profile import build_project_activity_profile, format_project_activity_profile
from core.protocols import describe_ip_proto, format_ip_proto_with_description
from core.timeutils import LOCAL_TZ, parse_timestamp
from core.workspace import (
    WORKSPACE_MARKER,
    ensure_workspace_structure,
    looks_like_vianyquist_workspace,
    make_safe_project_folder_name,
    workspace_export_path,
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
        self.assertEqual(format_pcap_datetime("2024-05-28 22:01:02.123456"), "28/05/2024 22:01:02.123")

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


class BehaviorProfileTests(unittest.TestCase):
    def test_project_dataset_loader_aggregates_saved_project_sources(self):
        with temporary_directory() as tmp:
            root = Path(tmp)
            db_path = root / "project-datasets.db"
            one = root / "one.json"
            two = root / "two.json"
            missing = root / "missing.json"
            one.write_text(json.dumps([{"id": "one", "requested_server_name": "web.facebook.com"}]), encoding="utf-8")
            two.write_text(json.dumps([{"id": "two", "requested_server_name": "www.youtube.com"}]), encoding="utf-8")
            init_db(db_path)
            project_id = create_project("Case A", db_path=db_path)
            add_dataset_load(project_id, str(one), db_path=db_path)
            add_dataset_load(project_id, str(two), db_path=db_path)
            add_dataset_load(project_id, str(missing), db_path=db_path)
            add_dataset_load(project_id, str(one), db_path=db_path)

            result = load_project_dataset_flows(project_id, db_path=db_path)
            recent = list_recent_datasets(project_id, db_path=db_path)

        self.assertEqual(result["saved_path_count"], 3)
        self.assertEqual(result["deduped_path_count"], 3)
        self.assertEqual(result["loaded_source_count"], 2)
        self.assertEqual(result["source_count"], 3)
        self.assertEqual(result["flow_count"], 2)
        self.assertEqual([flow["id"] for flow in result["flows"]], ["one", "two"])
        self.assertEqual(len(result["missing_rows"]), 1)
        self.assertEqual(recent[0], str(one))
        self.assertEqual(len(recent), 3)

    def test_behavior_profile_groups_services_domains_and_hours(self):
        flows = [
            {
                "requested_server_name": "web.facebook.com",
                "application_name": "TLS",
                "bidirectional_bytes": 2048,
                "bidirectional_first_seen_ms": "2026-01-04 07:10:00",
            },
            {
                "requested_server_name": "video.twimg.com",
                "application_name": "TLS",
                "bidirectional_bytes": 1024,
                "bidirectional_first_seen_ms": "2026-01-04 23:05:00",
            },
            {
                "requested_server_name": "rr4---sn.googlevideo.com",
                "application_name": "TLS",
                "bidirectional_bytes": 4096,
                "bidirectional_first_seen_ms": "2026-01-04 23:30:00",
            },
            {
                "requested_server_name": "api.tiktokv.com",
                "application_name": "TLS",
                "bidirectional_bytes": 512,
                "bidirectional_first_seen_ms": "2026-01-04 12:00:00",
            },
        ]

        profile = build_flow_behavior_profile(flows)

        self.assertEqual(profile["flow_count"], 4)
        self.assertEqual(profile["timestamp_count"], 4)
        self.assertEqual(profile["total_bytes"], 7680)
        self.assertTrue(any(row["label"] == "Facebook / Meta" for row in profile["service_rows"]))
        self.assertTrue(any(row["label"] == "Google / YouTube" for row in profile["service_rows"]))
        self.assertTrue(any(row["label"] == "TikTok" for row in profile["service_rows"]))
        self.assertEqual(profile["domain_rows"][0]["label"], "rr4---sn.googlevideo.com")
        self.assertTrue(any(row["label"] == "23:00" and row["count"] == 2 for row in profile["hour_rows"]))
        self.assertTrue(any(line.startswith("Most active hour: 23:00") for line in profile["routine_lines"]))
        self.assertTrue(any("not proof" in line for line in profile["routine_lines"]))

    def test_behavior_profile_returns_valid_empty_structures(self):
        profile = build_flow_behavior_profile([])

        self.assertEqual(profile["flow_count"], 0)
        self.assertEqual(profile["total_bytes"], 0)
        self.assertEqual(profile["service_rows"], [])
        self.assertEqual(profile["domain_rows"], [])
        self.assertEqual(profile["hour_rows"], [])
        self.assertTrue(profile["routine_lines"])

    def test_activity_profile_html_export_includes_behavior_sections(self):
        with temporary_directory() as tmp:
            output = Path(tmp) / "profile.html"
            profile = {
                "summary_lines": ["Project Activity Profile", "- Case subject: Ana Horvat"],
                "recommendation_lines": ["- Compare JSON and PCAP evidence."],
                "timeline_lines": ["- 2026-01-04 09:00:00: Dataset loaded"],
                "metrics": [{"label": "JSON Datasets", "value": 1}],
                "evidence_counts": [{"label": "JSON Datasets", "count": 1}],
                "pcap_device_ip_rows": [{"label": "10.0.0.10", "count": 1}],
                "capture_range": {"label": "04/01/2026 09:00:00.000"},
                "total_pcap_bytes_label": "86.10 MB",
                "behavior_profile": {
                    "service_rows": [{"label": "WhatsApp", "bytes": 2048, "bytes_label": "2.00 KB"}],
                    "domain_rows": [{"label": "web.whatsapp.com", "bytes": 2048, "bytes_label": "2.00 KB"}],
                    "hour_rows": [{"label": "09:00", "count": 4}],
                    "routine_lines": ["Most active hour: 09:00 (4 flows)."],
                },
            }

            export_activity_profile_html(str(output), profile=profile, project_name="Case A")
            content = output.read_text(encoding="utf-8")
            hr_output = Path(tmp) / "profile-hr.html"
            export_activity_profile_html(str(hr_output), profile=profile, project_name="Case A", report_language="hr")
            hr_content = hr_output.read_text(encoding="utf-8")

        self.assertIn("ViaNyquist Activity Profile", content)
        self.assertIn("Case A", content)
        self.assertIn("Behavior Insights", content)
        self.assertIn("WhatsApp", content)
        self.assertIn("Most active hour", content)
        self.assertIn("ViaNyquist profil aktivnosti", hr_content)
        self.assertIn("Pregled dokaza", hr_content)
        self.assertIn("Uvidi u ponasanje", hr_content)


class ExportContextTests(unittest.TestCase):
    def test_listing_html_export_includes_project_case_context(self):
        with temporary_directory() as tmp:
            root = Path(tmp)
            db_path = root / "listing-export.db"
            output = root / "listing.html"
            init_db(db_path)

            project_id = create_project("Case A", db_path=db_path)
            set_project_subject(
                project_id,
                first_name="Ana",
                last_name="Horvat",
                msisdn="385911234567",
                oib="12345678901",
                db_path=db_path,
            )
            project = get_project(project_id, db_path=db_path)

            export_listing_html(
                file_path=str(output),
                headers=["Time", "Application"],
                rows=[["09:00", "WhatsApp"]],
                dataset=str(root / "dataset.json"),
                view_mode="All",
                files_count=1,
                meta={"target": "385911234567", "targettype": "MSISDN"},
                project=project,
            )
            content = output.read_text(encoding="utf-8")
            hr_output = root / "listing-hr.html"
            export_listing_html(
                file_path=str(hr_output),
                headers=["Time", "Application"],
                rows=[["09:00", "WhatsApp"]],
                dataset=str(root / "dataset.json"),
                view_mode="All",
                files_count=1,
                meta={"target": "385911234567", "targettype": "MSISDN"},
                project=project,
                report_language="hr",
            )
            hr_content = hr_output.read_text(encoding="utf-8")

        self.assertIn("Case Subject", content)
        self.assertIn("Ana Horvat", content)
        self.assertIn("MSISDN: 385911234567", content)
        self.assertIn("Dataset Target", content)
        self.assertIn("ViaNyquist listing izvjestaj", hr_content)
        self.assertIn("Valjanost naloga", hr_content)
        self.assertIn("Listing podaci", hr_content)

    def test_registry_html_export_includes_project_case_context(self):
        with temporary_directory() as tmp:
            root = Path(tmp)
            db_path = root / "registry-export.db"
            output = root / "registry.html"
            init_db(db_path)

            project_id = create_project("Case B", db_path=db_path)
            set_project_subject(
                project_id,
                first_name="Pero",
                last_name="Peric",
                msisdn="38598111222",
                ip="10.0.0.5",
                db_path=db_path,
            )
            project = get_project(project_id, db_path=db_path)

            export_registry_html(
                file_path=str(output),
                folder=root,
                files=[root / "dataset.json"],
                flows=[{"src_ip": "10.0.0.5", "dst_ip": "8.8.8.8", "application_name": "DNS", "bidirectional_bytes": 100}],
                meta={"target": "38598111222", "targettype": "MSISDN"},
                summary={"total_flows": 1, "total_bytes": 100},
                analyst={},
                columns=["src_ip", "dst_ip", "application_name"],
                tab_defs=[],
                project=project,
            )
            content = output.read_text(encoding="utf-8")

            hr_output = root / "registry-hr.html"
            export_registry_html(
                file_path=str(hr_output),
                folder=root,
                files=[root / "dataset.json"],
                flows=[{"src_ip": "10.0.0.5", "dst_ip": "8.8.8.8", "application_name": "DNS", "bidirectional_bytes": 100}],
                meta={"target": "38598111222", "targettype": "MSISDN"},
                summary={"total_flows": 1, "total_bytes": 100},
                analyst={},
                columns=["src_ip", "dst_ip", "application_name"],
                tab_defs=[],
                project=project,
                report_language="hr",
            )
            hr_content = hr_output.read_text(encoding="utf-8")

        self.assertIn("Case B", content)
        self.assertIn("Pero Peric", content)
        self.assertIn("MSISDN: 38598111222", content)
        self.assertIn("Known IP", content)
        self.assertIn("ViaNyquist registry izvjestaj", hr_content)
        self.assertIn("Valjanost naloga", hr_content)
        self.assertIn("Analiticki sazetak", hr_content)


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

    def test_workspace_export_path_uses_project_exports_folder(self):
        with temporary_directory() as tmp:
            root = Path(tmp) / "case"
            ensure_workspace_structure(str(root))

            export_path = workspace_export_path(str(root), "report.html")
            exports_exists = export_path.parent.exists()

        self.assertEqual(export_path.name, "report.html")
        self.assertEqual(export_path.parent.name, "exports")
        self.assertTrue(exports_exists)

    def test_project_folder_name_is_windows_safe(self):
        self.assertEqual(make_safe_project_folder_name(' Case: A/B? '), "Case_A_B")


class AppSettingsTests(unittest.TestCase):
    def test_app_settings_are_persisted_in_database(self):
        with temporary_directory() as tmp:
            db_path = Path(tmp) / "settings.db"
            init_db(db_path)

            set_app_setting("ai.model", "model-a", db_path=db_path)
            set_app_setting("ai.timeout_seconds", "42", db_path=db_path)

            self.assertEqual(get_app_setting("ai.model", db_path=db_path), "model-a")
            self.assertEqual(
                get_app_settings("ai.", db_path=db_path),
                {"ai.model": "model-a", "ai.timeout_seconds": "42"},
            )


class ProjectTargetTests(unittest.TestCase):
    def test_project_target_is_persisted_in_database(self):
        with temporary_directory() as tmp:
            db_path = Path(tmp) / "projects.db"
            init_db(db_path)

            project_id = create_project("Case A", db_path=db_path)
            set_project_target(project_id, "385911234567", "MSISDN", db_path=db_path)

            project = get_project(project_id, db_path=db_path)

        self.assertIsNotNone(project)
        self.assertEqual(project.target_identifier, "385911234567")
        self.assertEqual(project.target_type, "MSISDN")

    def test_project_subject_identifiers_are_persisted_in_database(self):
        with temporary_directory() as tmp:
            db_path = Path(tmp) / "projects.db"
            init_db(db_path)

            project_id = create_project("Case A", db_path=db_path)
            set_project_subject(
                project_id,
                first_name="Ana",
                last_name="Horvat",
                oib="12345678901",
                msisdn="385911234567",
                imsi="219011234567890",
                imei="356789012345678",
                ip="10.0.0.10",
                extra_identifiers="email: ana@example.test",
                db_path=db_path,
            )

            project = get_project(project_id, db_path=db_path)

        self.assertIsNotNone(project)
        self.assertEqual(project.subject_first_name, "Ana")
        self.assertEqual(project.subject_last_name, "Horvat")
        self.assertEqual(project.subject_oib, "12345678901")
        self.assertEqual(project.subject_msisdn, "385911234567")
        self.assertEqual(project.subject_imsi, "219011234567890")
        self.assertEqual(project.subject_imei, "356789012345678")
        self.assertEqual(project.subject_ip, "10.0.0.10")
        self.assertIn("ana@example.test", project.subject_extra_identifiers)

    def test_oib_validation_checks_length_digits_and_control_number(self):
        self.assertTrue(is_valid_oib("61154777813"))
        self.assertTrue(is_valid_oib("611 547 77813"))
        self.assertFalse(is_valid_oib("61154777812"))
        self.assertFalse(is_valid_oib("6115477781"))
        self.assertFalse(is_valid_oib("6115477781A"))

    def test_identifier_matching_tolerates_phone_formatting_and_dataset_aliases(self):
        self.assertEqual(normalize_identifier_value("+385 91 123-4567", "MSISDN"), "385911234567")
        self.assertTrue(
            identifier_values_match(
                "+385 91 123 4567",
                "385911234567",
                project_type="MSISDN",
                dataset_type="ISDNDataOnly",
            )
        )
        self.assertFalse(
            identifier_values_match(
                "+385 91 123 4567",
                "385981111111",
                project_type="MSISDN",
                dataset_type="ISDNDataOnly",
            )
        )

    def test_extract_dataset_meta_normalizes_target_type_alias(self):
        with temporary_directory() as tmp:
            path = Path(tmp) / "sample.json"
            path.write_text(
                json.dumps({
                    "target": "385911234567",
                    "targetType": "MSISDN",
                    "flow": [],
                }),
                encoding="utf-8",
            )

            meta = extract_dataset_meta(path)

        self.assertEqual(meta["target"], "385911234567")
        self.assertEqual(meta["targettype"], "MSISDN")


class PcapAnalyzerTests(unittest.TestCase):
    def test_pcap_communication_rows_classify_app_activity_indicators(self):
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
            },
            {
                "src_ip": "10.0.0.10",
                "src_port": 52000,
                "dst_ip": "31.13.84.52",
                "dst_port": 443,
                "protocol": 6,
                "application_name": "TLS/HTTPS",
                "requested_server_name": "edge-mqtt.facebook.com",
                "bidirectional_bytes": 12000,
                "bidirectional_packets": 8,
                "bidirectional_duration_ms": 3000,
                "bidirectional_first_seen_ms": "2026-01-04 09:05:00.000",
                "bidirectional_last_seen_ms": "2026-01-04 09:05:03.000",
            },
        ]

        rows = build_communication_rows(flows)

        self.assertEqual(rows[0]["service"], "WhatsApp")
        self.assertEqual(rows[0]["activity_type"], "Possible voice/video media session")
        self.assertEqual(rows[0]["confidence"], "medium")
        self.assertTrue(any(row["activity_type"] == "Push/background messaging transport" for row in rows))

    def test_analyze_pcap_extracts_dns_http_and_flows(self):
        with temporary_directory() as tmp:
            path = Path(tmp) / "sample.pcap"
            _write_sample_pcap(path)

            summary = analyze_pcap(path)

        self.assertEqual(summary.format, "PCAP")
        self.assertEqual(summary.packet_count, 2)
        self.assertEqual(summary.likely_device_ip, "10.0.0.10")
        self.assertEqual(summary.dns_queries[0]["query"], "example.com")
        self.assertEqual(summary.http_hosts[0]["host"], "example.com")
        self.assertTrue(any(sample["type"] == "HTTP cleartext" for sample in summary.readable_samples))
        self.assertEqual(len(summary.flows), 2)
        self.assertTrue(summary.hourly_activity)
        self.assertTrue(any(a["category"] == "Web" and a["type"] == "HTTP host" for a in summary.artifacts))
        self.assertTrue(any(a["category"] == "Web" and a["type"] == "HTTP user-agent" for a in summary.artifacts))

        investigator = build_investigator_view(summary)

        self.assertIn("The capture covers", investigator["plain_summary"])
        self.assertTrue(investigator["service_rows"])
        self.assertTrue(investigator["activity_rows"])
        self.assertTrue(investigator["visibility_rows"])

    def test_pcap_artifacts_redact_sensitive_http_values(self):
        with temporary_directory() as tmp:
            path = Path(tmp) / "sensitive.pcap"
            _write_sample_pcap(
                path,
                http_payload=(
                    b"GET /private HTTP/1.1\r\n"
                    b"Host: example.com\r\n"
                    b"Authorization: Basic dXNlcjpwYXNz\r\n"
                    b"Cookie: session=abcdef1234567890\r\n"
                    b"\r\n"
                ),
            )

            summary = analyze_pcap(path)

        sensitive = [a for a in summary.artifacts if a["category"] == "Credentials"]

        self.assertTrue(any(a["type"] == "HTTP Basic credentials" for a in sensitive))
        self.assertTrue(any("[redacted]" in a["value"] or set(a["value"]) == {"*"} for a in sensitive))
        self.assertFalse(any("user:pass" == a["value"] for a in sensitive))

    def test_pcap_sources_are_persisted_per_project(self):
        with temporary_directory() as tmp:
            root = Path(tmp)
            db_path = root / "pcap-sources.db"
            pcap_path = root / "sample.pcap"
            _write_sample_pcap(pcap_path)
            init_db(db_path)

            project_id = create_project("Case A", db_path=db_path)
            summary = analyze_pcap(pcap_path)
            digest = file_sha256(pcap_path)
            source_id = add_pcap_source(
                project_id,
                file_path=str(pcap_path),
                file_name=pcap_path.name,
                file_sha256_value=digest,
                file_size=pcap_path.stat().st_size,
                format=summary.format,
                packet_count=summary.packet_count,
                wire_bytes=summary.wire_bytes,
                first_seen=summary.first_seen,
                last_seen=summary.last_seen,
                duration_seconds=summary.duration_seconds,
                likely_device_ip=summary.likely_device_ip,
                summary_text=build_investigator_view(summary)["plain_summary"],
                db_path=db_path,
            )
            duplicate_source_id = add_pcap_source(
                project_id,
                file_path=str(pcap_path),
                file_name=pcap_path.name,
                file_sha256_value=digest,
                file_size=pcap_path.stat().st_size,
                format=summary.format,
                packet_count=summary.packet_count,
                wire_bytes=summary.wire_bytes,
                first_seen=summary.first_seen,
                last_seen=summary.last_seen,
                duration_seconds=summary.duration_seconds,
                likely_device_ip=summary.likely_device_ip,
                summary_text=build_investigator_view(summary)["plain_summary"],
                db_path=db_path,
            )

            sources = list_pcap_sources(project_id, db_path=db_path)
            device_ips = list_project_pcap_device_ips(project_id, db_path=db_path)

        self.assertEqual(len(sources), 1)
        self.assertEqual(sources[0].id, source_id)
        self.assertEqual(duplicate_source_id, source_id)
        self.assertEqual(sources[0].file_sha256, digest)
        self.assertEqual(sources[0].likely_device_ip, "10.0.0.10")
        self.assertEqual(device_ips, ["10.0.0.10"])

    def test_pcap_html_export_includes_project_context_when_available(self):
        with temporary_directory() as tmp:
            root = Path(tmp)
            db_path = root / "pcap-export.db"
            pcap_path = root / "sample.pcap"
            output = root / "pcap.html"
            _write_sample_pcap(pcap_path)
            init_db(db_path)

            project_id = create_project("Case A", db_path=db_path)
            set_project_subject(
                project_id,
                first_name="Ana",
                last_name="Horvat",
                msisdn="385911234567",
                ip="10.0.0.10",
                db_path=db_path,
            )
            project = get_project(project_id, db_path=db_path)
            summary = analyze_pcap(pcap_path)

            export_pcap_summary_html(str(output), summary, project=project)
            content = output.read_text(encoding="utf-8")
            hr_output = root / "pcap-hr.html"
            export_pcap_summary_html(str(hr_output), summary, project=project, report_language="hr")
            hr_content = hr_output.read_text(encoding="utf-8")

        self.assertIn("Case A", content)
        self.assertIn("Ana Horvat", content)
        self.assertIn("MSISDN: 385911234567", content)
        self.assertIn("Device IP", content)
        self.assertIn("ViaNyquist PCAP Report", content)
        self.assertIn('href="#summary"', content)
        self.assertIn('id="evidence"', content)
        self.assertIn("Communication Highlights", content)
        self.assertIn("ViaNyquist PCAP izvjestaj", hr_content)
        self.assertIn("Komunikacijski indikatori", hr_content)
        self.assertIn("Dokazi", hr_content)

    def test_project_activity_profile_summarizes_saved_evidence(self):
        with temporary_directory() as tmp:
            root = Path(tmp)
            db_path = root / "profile.db"
            pcap_path = root / "sample.pcap"
            _write_sample_pcap(pcap_path)
            init_db(db_path)

            project_id = create_project("Case A", db_path=db_path)
            set_project_subject(
                project_id,
                first_name="Ana",
                last_name="Horvat",
                msisdn="385911234567",
                db_path=db_path,
            )
            empty_project_id = create_project("Empty Case", db_path=db_path)
            add_dataset_load(project_id, str(root / "dataset"), db_path=db_path)

            summary = analyze_pcap(pcap_path)
            add_pcap_source(
                project_id,
                file_path=str(pcap_path),
                file_name=pcap_path.name,
                file_sha256_value=file_sha256(pcap_path),
                file_size=pcap_path.stat().st_size,
                format=summary.format,
                packet_count=summary.packet_count,
                wire_bytes=summary.wire_bytes,
                first_seen=summary.first_seen,
                last_seen=summary.last_seen,
                duration_seconds=summary.duration_seconds,
                likely_device_ip=summary.likely_device_ip,
                summary_text=build_investigator_view(summary)["plain_summary"],
                db_path=db_path,
            )
            add_finding(
                project_id,
                {
                    "src_ip": "10.0.0.10",
                    "dst_ip": "93.184.216.34",
                    "protocol": 6,
                    "application_name": "HTTP",
                    "bidirectional_bytes": 1000,
                },
                title="Example flow",
                db_path=db_path,
            )

            profile = build_project_activity_profile(project_id, db_path=db_path)
            empty_profile = build_project_activity_profile(empty_project_id, db_path=db_path)
            rendered = format_project_activity_profile(profile)

        self.assertEqual(profile["dataset_count"], 1)
        self.assertEqual(profile["pcap_count"], 1)
        self.assertEqual(profile["finding_count"], 1)
        self.assertEqual(profile["pcap_device_ips"], {"10.0.0.10": 1})
        self.assertEqual(profile["evidence_counts"], [
            {"label": "JSON Datasets", "count": 1},
            {"label": "PCAP Sources", "count": 1},
            {"label": "Findings", "count": 1},
        ])
        self.assertEqual(profile["pcap_device_ip_rows"], [{"label": "10.0.0.10", "count": 1}])
        self.assertTrue(any(row["label"] == "JSON dataset loaded" for row in profile["activity_type_rows"]))
        self.assertTrue(any(row["label"] == "PCAP saved" for row in profile["activity_type_rows"]))
        self.assertTrue(profile["capture_range"]["first_seen"])
        self.assertTrue(profile["capture_range"]["last_seen"])
        self.assertEqual(empty_profile["dataset_count"], 0)
        self.assertEqual(empty_profile["evidence_counts"][0]["count"], 0)
        self.assertEqual(empty_profile["pcap_device_ip_rows"], [])
        self.assertEqual(empty_profile["activity_type_rows"], [])
        self.assertEqual(empty_profile["capture_range"]["label"], "-")
        self.assertIn("Project Activity Profile", rendered)
        self.assertIn("Case subject: Ana Horvat", rendered)
        self.assertIn("MSISDN: 385911234567", rendered)
        self.assertIn("Compare JSON flow datasets", rendered)
        self.assertIn("Recent project activity", rendered)


class AIServiceTests(unittest.TestCase):
    def test_ai_settings_builds_generate_url(self):
        settings = AISettings(base_url="http://localhost:11434/", model="m", timeout_seconds=5)

        self.assertEqual(settings.generate_url, "http://localhost:11434/api/generate")

    def test_ai_settings_loads_from_persisted_mapping(self):
        settings = AISettings.from_mapping({
            "ai.base_url": "http://saved.local",
            "ai.model": "saved-model",
            "ai.timeout_seconds": "33",
            "output.language": "en",
        })

        self.assertEqual(settings.base_url, "http://saved.local")
        self.assertEqual(settings.model, "saved-model")
        self.assertEqual(settings.timeout_seconds, 33)
        self.assertEqual(settings.output_language, "en")
        self.assertEqual(settings.to_mapping()["ai.model"], "saved-model")
        self.assertEqual(settings.to_mapping()["output.language"], "en")

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

    def test_pcap_context_and_prompt_are_grounded_in_visible_evidence(self):
        with temporary_directory() as tmp:
            path = Path(tmp) / "sample.pcap"
            _write_sample_pcap(path)
            summary = analyze_pcap(path)

        context = build_pcap_context(summary, project_name="Case A")
        prompt = build_pcap_summary_prompt(context)

        self.assertIn("PCAP file: sample.pcap", context)
        self.assertIn("Top extracted artifacts", context)
        self.assertIn("HTTP host", context)
        self.assertIn("no plaintext credentials were observed", prompt)
        self.assertIn("Do not invent malware", prompt)
        self.assertIn("Write the response in Croatian", prompt)

    def test_pcap_ai_summary_uses_pcap_prompt(self):
        class FakeResponse:
            status_code = 200

            def json(self):
                return {"response": "pcap ok"}

        with temporary_directory() as tmp:
            path = Path(tmp) / "sample.pcap"
            _write_sample_pcap(path)
            summary = analyze_pcap(path)

        service = AIAssistantService(AISettings(base_url="http://ai.local", model="m", timeout_seconds=7, output_language="en"))
        with patch.object(service, "_post_generate", return_value=FakeResponse()) as post:
            result = service.generate_pcap_summary(summary, project_name="Case A")

        self.assertEqual(result, "pcap ok")
        prompt = post.call_args.args[0]
        self.assertIn("You are analyzing a packet capture summary", prompt)
        self.assertIn("PCAP file: sample.pcap", prompt)
        self.assertIn("Limits Of Interpretation", prompt)
        self.assertIn("Write the response in English", prompt)

    def test_activity_profile_context_and_prompt_are_grounded(self):
        profile = {
            "summary_lines": ["Project Activity Profile", "- Target: MSISDN / 123"],
            "evidence_counts": [
                {"label": "JSON Datasets", "count": 2},
                {"label": "PCAP Sources", "count": 1},
            ],
            "pcap_device_ip_rows": [{"label": "10.0.0.10", "count": 1}],
            "activity_type_rows": [{"label": "Dataset loaded", "count": 2}],
            "capture_range": {"label": "2026-01-01 to 2026-01-02"},
            "behavior_profile": {
                "flow_count": 3,
                "total_bytes_label": "7.5 KB",
                "service_rows": [{"label": "Facebook / Meta", "count": 2, "bytes_label": "6.0 KB", "example": "web.facebook.com"}],
                "domain_rows": [{"label": "web.facebook.com", "count": 2, "bytes_label": "6.0 KB"}],
                "routine_lines": ["Most active hour: 23:00 (2 flows)."],
            },
            "recommendation_lines": ["- Compare datasets with PCAP windows."],
            "timeline_lines": ["- 2026-04-30: Dataset loaded: sample"],
        }

        context = build_activity_profile_context(profile, project_name="Case A")
        prompt = build_activity_profile_summary_prompt(context)

        self.assertIn("Project: Case A", context)
        self.assertIn("Evidence counts", context)
        self.assertIn("PCAP device IP distribution", context)
        self.assertIn("Loaded-dataset behavior indicators", context)
        self.assertIn("Facebook / Meta", context)
        self.assertIn("Do not identify a real person", prompt)
        self.assertIn("Activity Profile Summary", prompt)
        self.assertIn("Write the response in Croatian", prompt)

    def test_activity_profile_ai_summary_uses_profile_prompt(self):
        class FakeResponse:
            status_code = 200

            def json(self):
                return {"response": "profile ok"}

        profile = {
            "summary_lines": ["Project Activity Profile"],
            "evidence_counts": [{"label": "JSON Datasets", "count": 1}],
            "recommendation_lines": ["- Review saved findings."],
        }
        service = AIAssistantService(AISettings(base_url="http://ai.local", model="m", timeout_seconds=7))
        with patch.object(service, "_post_generate", return_value=FakeResponse()) as post:
            result = service.generate_activity_profile_summary(profile, project_name="Case A")

        self.assertEqual(result, "profile ok")
        prompt = post.call_args.args[0]
        self.assertIn("ViaNyquist Activity Profile", prompt)
        self.assertIn("Project: Case A", prompt)
        self.assertIn("Limits Of Interpretation", prompt)


def _write_sample_pcap(path: Path, http_payload: bytes | None = None) -> None:
    http_payload = http_payload or b"GET / HTTP/1.1\r\nHost: example.com\r\nUser-Agent: ViaNyquistTest\r\n\r\n"
    packets = [
        _ether_ipv4_udp_packet(
            "10.0.0.10",
            "8.8.8.8",
            53000,
            53,
            _dns_query_payload("example.com"),
        ),
        _ether_ipv4_tcp_packet(
            "10.0.0.10",
            "93.184.216.34",
            50000,
            80,
            http_payload,
        ),
    ]

    with path.open("wb") as f:
        f.write(struct.pack("<IHHiiii", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        for i, packet in enumerate(packets, start=1):
            f.write(struct.pack("<IIII", 1_704_067_200 + i, 0, len(packet), len(packet)))
            f.write(packet)


def _dns_query_payload(name: str) -> bytes:
    labels = b"".join(bytes([len(part)]) + part.encode("ascii") for part in name.split("."))
    qname = labels + b"\x00"
    return (
        b"\x12\x34"
        + b"\x01\x00"
        + b"\x00\x01"
        + b"\x00\x00"
        + b"\x00\x00"
        + b"\x00\x00"
        + qname
        + b"\x00\x01"
        + b"\x00\x01"
    )


def _ether_ipv4_udp_packet(src_ip: str, dst_ip: str, src_port: int, dst_port: int, payload: bytes) -> bytes:
    udp_len = 8 + len(payload)
    udp = struct.pack("!HHHH", src_port, dst_port, udp_len, 0) + payload
    return _ether_ipv4_packet(src_ip, dst_ip, 17, udp)


def _ether_ipv4_tcp_packet(src_ip: str, dst_ip: str, src_port: int, dst_port: int, payload: bytes) -> bytes:
    tcp = (
        struct.pack("!HHII", src_port, dst_port, 1, 0)
        + bytes([0x50, 0x18])
        + struct.pack("!HHH", 8192, 0, 0)
        + payload
    )
    return _ether_ipv4_packet(src_ip, dst_ip, 6, tcp)


def _ether_ipv4_packet(src_ip: str, dst_ip: str, proto: int, l4: bytes) -> bytes:
    import socket

    eth = b"\xaa\xbb\xcc\xdd\xee\xff" + b"\x11\x22\x33\x44\x55\x66" + struct.pack("!H", 0x0800)
    total_len = 20 + len(l4)
    ip = (
        b"\x45\x00"
        + struct.pack("!H", total_len)
        + b"\x00\x01"
        + b"\x00\x00"
        + b"\x40"
        + bytes([proto])
        + b"\x00\x00"
        + socket.inet_aton(src_ip)
        + socket.inet_aton(dst_ip)
    )
    return eth + ip + l4


if __name__ == "__main__":
    unittest.main()
