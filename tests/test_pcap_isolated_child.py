import sys
import unittest
from unittest.mock import patch

from core.pcap_analyzer import isolated_pcap_child_command


class PcapIsolatedChildCommandTests(unittest.TestCase):
    def test_dev_uses_python_module(self):
        with patch.object(sys, "executable", "C:\\Python\\python.exe"), patch.object(
            sys, "frozen", False, create=True
        ):
            self.assertEqual(
                isolated_pcap_child_command(["--batch"]),
                ["C:\\Python\\python.exe", "-m", "core.pcap_isolated", "--batch"],
            )

    def test_frozen_exe_uses_child_flag(self):
        with patch.object(sys, "executable", "C:\\ViaNyquist\\ViaNyquist.exe"), patch.object(
            sys, "frozen", True, create=True
        ):
            self.assertEqual(
                isolated_pcap_child_command(["sample.pcap", "0", "0"]),
                ["C:\\ViaNyquist\\ViaNyquist.exe", "--pcap-isolated", "sample.pcap", "0", "0"],
            )


if __name__ == "__main__":
    unittest.main()
