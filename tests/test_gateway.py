"""
Automated end-to-end integration tests for the Email Gateway.
"""

import os
import unittest
from gateway.gateway_controller import EmailGateway
from gateway.dns_manager import dns_manager


class TestEmailGatewayEndToEnd(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.gateway = EmailGateway(dns_manager)
        cls.samples_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "samples")

    def _read_sample(self, filename: str) -> str:
        with open(os.path.join(self.samples_dir, filename), "r", encoding="utf-8") as f:
            return f.read()

    def test_legitimate_corporate_invoice(self):
        raw = self._read_sample("legitimate_invoice.eml")
        res = self.gateway.inspect(raw)

        self.assertEqual(res.security_verdict, "PASS")
        self.assertEqual(res.threat_level, "CLEAN")
        self.assertEqual(res.spf["status"], "Pass")
        self.assertEqual(res.dkim["status"], "Pass")
        self.assertEqual(res.dmarc["status"], "Pass")
        self.assertIn("Authentication-Results:", res.auth_results_header)
        self.assertIn("spf=pass", res.auth_results_header)
        self.assertIn("dkim=pass", res.auth_results_header)
        self.assertIn("dmarc=pass", res.auth_results_header)

    def test_spoofed_ceo_fraud_rejection(self):
        raw = self._read_sample("spoofed_ceo_fraud.eml")
        res = self.gateway.inspect(raw)

        self.assertEqual(res.security_verdict, "REJECT")
        self.assertEqual(res.threat_level, "CRITICAL")
        self.assertEqual(res.dmarc["status"], "Fail")
        self.assertEqual(res.dmarc["disposition"], "reject")
        self.assertIn("dmarc=fail", res.auth_results_header)

    def test_tampered_in_transit_wire_transfer(self):
        raw = self._read_sample("tampered_dkim_transfer.eml")
        res = self.gateway.inspect(raw)

        self.assertEqual(res.security_verdict, "REJECT")
        self.assertEqual(res.dkim["status"], "Fail")
        self.assertFalse(res.dkim["body_hash_match"])
        self.assertEqual(res.dmarc["status"], "Fail")

    def test_dmarc_monitoring_phase(self):
        raw = self._read_sample("dmarc_monitoring_marketing.eml")
        res = self.gateway.inspect(raw)

        self.assertEqual(res.security_verdict, "MONITOR")
        self.assertEqual(res.threat_level, "MEDIUM")
        self.assertEqual(res.dmarc["published_policy"], "none")
        self.assertEqual(res.dmarc["disposition"], "none")

    def test_dmarc_quarantine_phase(self):
        raw = self._read_sample("quarantine_hr_notice.eml")
        res = self.gateway.inspect(raw)

        self.assertEqual(res.security_verdict, "QUARANTINE")
        self.assertEqual(res.threat_level, "HIGH")
        self.assertEqual(res.dmarc["published_policy"], "quarantine")
        self.assertEqual(res.dmarc["disposition"], "quarantine")


if __name__ == "__main__":
    unittest.main()
