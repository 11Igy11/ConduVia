import unittest

from core.pcap_analyzer import PcapSummary
from core.pcap_finding import (
    default_communication_finding_title,
    default_period_finding_title,
    flow_from_communication_row,
    flow_from_pcap_summary,
    parse_endpoint,
)


class PcapFindingTests(unittest.TestCase):
    def test_parse_endpoint_splits_host_and_port(self):
        self.assertEqual(parse_endpoint("10.0.0.1:443"), ("10.0.0.1", 443))
        self.assertEqual(parse_endpoint("api.example.com"), ("api.example.com", None))
        self.assertEqual(parse_endpoint(""), ("", None))

    def test_flow_from_communication_row_maps_endpoints(self):
        row = {
            "source": "192.168.1.10:51234",
            "destination": "93.184.216.34:443",
            "service": "HTTPS",
            "host": "example.com",
            "protocol": "TCP",
            "bytes": 1200,
            "packets": 8,
            "duration_ms": 500,
            "activity_type": "encrypted web",
        }
        flow = flow_from_communication_row(row)
        self.assertEqual(flow["src_ip"], "192.168.1.10")
        self.assertEqual(flow["dst_ip"], "93.184.216.34")
        self.assertEqual(flow["src_port"], 51234)
        self.assertEqual(flow["dst_port"], 443)
        self.assertEqual(flow["application_name"], "HTTPS")
        self.assertEqual(flow["requested_server_name"], "example.com")
        self.assertEqual(default_communication_finding_title(row), "PCAP: HTTPS — encrypted web")

    def test_flow_from_pcap_summary_uses_device_ip_and_top_endpoint(self):
        summary = PcapSummary(
            file_name="capture.pcap",
            file_path="/tmp/capture.pcap",
            likely_device_ip="10.1.2.3",
            packet_count=42,
            wire_bytes=9000,
            duration_seconds=12.5,
            top_endpoints=[{"ip": "8.8.8.8", "label": "8.8.8.8:53"}],
            communication_rows=[],
        )
        flow = flow_from_pcap_summary(summary)
        self.assertEqual(flow["src_ip"], "10.1.2.3")
        self.assertEqual(flow["dst_ip"], "8.8.8.8")
        self.assertEqual(flow["bidirectional_packets"], 42)
        self.assertEqual(
            default_period_finding_title(summary, period_label="2024-01-20"),
            "PCAP period: 2024-01-20",
        )

    def test_flow_from_pcap_summary_prefers_first_communication_row(self):
        summary = PcapSummary(
            file_name="capture.pcap",
            file_path="/tmp/capture.pcap",
            likely_device_ip="10.1.2.3",
            communication_rows=[
                {
                    "source": "10.1.2.3:40000",
                    "destination": "1.2.3.4:443",
                    "service": "TLS",
                }
            ],
        )
        flow = flow_from_pcap_summary(summary)
        self.assertEqual(flow["src_ip"], "10.1.2.3")
        self.assertEqual(flow["dst_ip"], "1.2.3.4")
        self.assertEqual(flow["application_name"], "TLS")


if __name__ == "__main__":
    unittest.main()
