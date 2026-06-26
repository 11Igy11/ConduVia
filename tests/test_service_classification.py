from __future__ import annotations

import unittest

from core.service_classification import (
    classify_behavior_service,
    classify_communication_service,
    classify_pcap_investigator_service,
    match_service,
)


class ServiceClassificationTests(unittest.TestCase):
    def test_apple_push_host_matches_in_all_contexts(self):
        host = "courier.push.apple.com"
        self.assertEqual(match_service(host), "Apple / iCloud")
        self.assertEqual(classify_behavior_service(host), "Apple / iCloud")
        self.assertEqual(classify_pcap_investigator_service(host), "Apple / iCloud")
        self.assertEqual(
            classify_communication_service({"requested_server_name": host}),
            "Apple / iCloud",
        )

    def test_whatsapp_host_matches_in_all_contexts(self):
        host = "media.whatsapp.net"
        self.assertEqual(match_service(host), "WhatsApp")
        self.assertEqual(classify_behavior_service(host), "WhatsApp")
        self.assertEqual(classify_pcap_investigator_service(host), "WhatsApp")

    def test_facebook_meta_unifies_messenger_signals(self):
        host = "edge-mqtt.facebook.com"
        self.assertEqual(match_service(host), "Facebook / Meta")
        self.assertEqual(
            classify_communication_service({"application_name": "Facebook Messenger"}),
            "Facebook / Meta",
        )

    def test_behavior_unknown_domain_falls_back_to_other_visible_services(self):
        self.assertEqual(classify_behavior_service("cdn.example.org"), "Other visible services")
        self.assertEqual(classify_behavior_service("MyApp"), "")

    def test_pcap_investigator_extended_rules(self):
        self.assertEqual(classify_pcap_investigator_service("api.linkedin.com"), "LinkedIn")
        self.assertEqual(classify_pcap_investigator_service("unknown.example.org"), "Other visible services")


if __name__ == "__main__":
    unittest.main()
