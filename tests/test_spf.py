"""
Automated unit tests for RFC 7208 SPF Validator.
"""

import unittest
from gateway.dns_manager import DNSManager
from gateway.spf_validator import SPFValidator


class TestSPFValidator(unittest.TestCase):

    def setUp(self):
        self.dns = DNSManager(storage_file=":memory:")
        self.dns.records = {
            "example.com": {
                "TXT": ["v=spf1 ip4:198.51.100.0/24 ip4:203.0.113.10 include:_spf.example.com -all"]
            },
            "_spf.example.com": {
                "TXT": ["v=spf1 ip4:198.51.100.50 ip4:198.51.100.51 -all"]
            },
            "softfail-domain.com": {
                "TXT": ["v=spf1 ip4:192.0.2.0/24 ~all"]
            },
            "neutral-domain.com": {
                "TXT": ["v=spf1 ip4:192.0.2.1 ?all"]
            },
            "loop1.com": {
                "TXT": ["v=spf1 include:loop2.com -all"]
            },
            "loop2.com": {
                "TXT": ["v=spf1 include:loop1.com -all"]
            }
        }
        self.validator = SPFValidator(self.dns)

    def test_direct_ip_match(self):
        # 198.51.100.25 is inside 198.51.100.0/24
        res = self.validator.evaluate("198.51.100.25", "example.com")
        self.assertEqual(res.status, "Pass")
        self.assertEqual(res.matched_mechanism, "ip4:198.51.100.0/24")

    def test_single_ip_match(self):
        res = self.validator.evaluate("203.0.113.10", "example.com")
        self.assertEqual(res.status, "Pass")
        self.assertEqual(res.matched_mechanism, "ip4:203.0.113.10")

    def test_include_mechanism_match(self):
        res = self.validator.evaluate("198.51.100.50", "example.com")
        self.assertEqual(res.status, "Pass")

    def test_hard_fail_unauthorized_ip(self):
        # 203.0.113.99 is not in example.com SPF
        res = self.validator.evaluate("203.0.113.99", "example.com")
        self.assertEqual(res.status, "Fail")
        self.assertEqual(res.matched_mechanism, "-all")

    def test_softfail_mechanism(self):
        res = self.validator.evaluate("10.0.0.1", "softfail-domain.com")
        self.assertEqual(res.status, "SoftFail")
        self.assertEqual(res.matched_mechanism, "~all")

    def test_neutral_mechanism(self):
        res = self.validator.evaluate("10.0.0.1", "neutral-domain.com")
        self.assertEqual(res.status, "Neutral")
        self.assertEqual(res.matched_mechanism, "?all")

    def test_loop_detection(self):
        res = self.validator.evaluate("1.2.3.4", "loop1.com")
        self.assertEqual(res.status, "PermError")
        self.assertIn("Loop detected", res.explanation)

    def test_missing_spf_record(self):
        res = self.validator.evaluate("1.2.3.4", "nonexistent-domain.xyz")
        self.assertEqual(res.status, "None")


if __name__ == "__main__":
    unittest.main()
