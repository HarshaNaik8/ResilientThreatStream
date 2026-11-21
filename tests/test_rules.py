"""
test_rules.py — Unit tests for the deterministic baseline threat detector.

Validates that individual heuristic rules, data-quality checks, and combined
decisions execute as expected on synthetic test cases.
"""

import unittest
from threat_detector import detect_threat, DetectorConfig


class TestThreatDetector(unittest.TestCase):

    def setUp(self):
        self.config = DetectorConfig()

    def test_normal_benign_packet(self):
        """Standard Windows client HTTP packet with normal pacing and length."""
        res = detect_threat(
            ttl=128,
            total_len=540,
            protocol="tcp",
            t_delta=0.015,
            config=self.config
        )
        self.assertEqual(res["predicted_attack"], 0)
        self.assertEqual(res["alert_reason"], "NORMAL")
        self.assertEqual(res["rule_burst_delta"], 0)
        self.assertEqual(res["rule_suspicious_ttl"], 0)
        self.assertEqual(res["rule_anomalous_len"], 0)
        self.assertEqual(res["is_invalid_metadata"], 0)

    def test_burst_with_suspicious_ttl(self):
        """Sub-50us burst arriving from a 2-hop Linux attack host (TTL=62)."""
        res = detect_threat(
            ttl=62,
            total_len=350,
            protocol="tcp",
            t_delta=0.00001,
            config=self.config
        )
        self.assertEqual(res["predicted_attack"], 1)
        self.assertEqual(res["rule_burst_delta"], 1)
        self.assertEqual(res["rule_suspicious_ttl"], 1)
        self.assertIn("RAPID_BURST_DELTA", res["triggered_rules"])
        self.assertIn("KNOWN_ATTACK_ORIGIN_TTL", res["triggered_rules"])

    def test_burst_with_minimal_tcp_header_len(self):
        """Sub-50us burst with 40-byte TCP SYN/RST control frame (potential flood)."""
        res = detect_threat(
            ttl=128,
            total_len=40,
            protocol="tcp",
            t_delta=0.00002,
            config=self.config
        )
        self.assertEqual(res["predicted_attack"], 1)
        self.assertEqual(res["rule_burst_delta"], 1)
        self.assertEqual(res["rule_anomalous_len"], 1)
        self.assertIn("HEADER_ONLY_TCP_LEN", res["triggered_rules"])

    def test_invalid_ttl_data_quality(self):
        """Impossible TTL values (< 1 or > 255) must trigger invalid metadata alert."""
        res_zero = detect_threat(ttl=0, total_len=100, protocol="tcp", t_delta=0.1)
        self.assertEqual(res_zero["predicted_attack"], 1)
        self.assertEqual(res_zero["is_invalid_metadata"], 1)
        self.assertIn("INVALID_TTL", res_zero["triggered_rules"])

        res_high = detect_threat(ttl=300, total_len=100, protocol="tcp", t_delta=0.1)
        self.assertEqual(res_high["predicted_attack"], 1)
        self.assertEqual(res_high["is_invalid_metadata"], 1)

    def test_invalid_packet_length(self):
        """Impossible IPv4 packet length (< 28 bytes) must trigger data quality alert."""
        res = detect_threat(ttl=64, total_len=15, protocol="udp", t_delta=0.1)
        self.assertEqual(res["predicted_attack"], 1)
        self.assertEqual(res["is_invalid_metadata"], 1)
        self.assertIn("INVALID_PACKET_LEN", res["triggered_rules"])

    def test_missing_and_null_fields(self):
        """Missing or None metadata values must be handled gracefully without crashing."""
        res = detect_threat(ttl=None, total_len=None, protocol=None, t_delta=None)
        self.assertEqual(res["predicted_attack"], 0)
        self.assertEqual(res["alert_reason"], "NORMAL")
        self.assertEqual(res["triggered_rules"], [])

    def test_negative_timestamp_jitter(self):
        """Negative t_delta (clock jitter) must not trigger burst alert."""
        res = detect_threat(ttl=128, total_len=200, protocol="tcp", t_delta=-0.000005)
        self.assertEqual(res["rule_burst_delta"], 0)
        self.assertEqual(res["predicted_attack"], 0)


if __name__ == "__main__":
    unittest.main()
