"""
Automated unit tests for RFC 7489 DMARC Evaluator and Identifier Alignment.
"""

import unittest
from gateway.dns_manager import DNSManager
from gateway.dmarc_evaluator import DMARCEvaluator, get_organizational_domain
from gateway.spf_validator import SPFResult
from gateway.dkim_signer_verifier import DKIMResult


class TestDMARCEvaluator(unittest.TestCase):

    def setUp(self):
        self.dns = DNSManager(storage_file=":memory:")
        self.dns.records = {
            "_dmarc.example.com": {
                "TXT": ["v=DMARC1; p=reject; pct=100; rua=mailto:dmarc@example.com; adkim=r; aspf=r;"]
            },
            "_dmarc.strict.com": {
                "TXT": ["v=DMARC1; p=reject; pct=100; adkim=s; aspf=s;"]
            },
            "_dmarc.monitoring.com": {
                "TXT": ["v=DMARC1; p=none; pct=100; rua=mailto:reports@monitoring.com;"]
            },
            "_dmarc.quarantine.com": {
                "TXT": ["v=DMARC1; p=quarantine; pct=100;"]
            }
        }
        self.evaluator = DMARCEvaluator(self.dns)

    def test_organizational_domain_extraction(self):
        self.assertEqual(get_organizational_domain("mail.sub.example.com"), "example.com")
        self.assertEqual(get_organizational_domain("example.com"), "example.com")
        self.assertEqual(get_organizational_domain("server.portal.bank.co.uk"), "bank.co.uk")

    def test_dmarc_pass_both_aligned(self):
        spf_res = SPFResult(status="Pass", domain="example.com", client_ip="1.2.3.4")
        dkim_res = DKIMResult(status="Pass", domain="example.com", selector="s1")

        res = self.evaluator.evaluate(
            header_from="Alice <alice@example.com>",
            spf_result=spf_res,
            dkim_result=dkim_res
        )
        self.assertEqual(res.status, "Pass")
        self.assertEqual(res.disposition, "none")
        self.assertTrue(res.spf_aligned)
        self.assertTrue(res.dkim_aligned)

    def test_dmarc_pass_relaxed_subdomain_alignment(self):
        # Header From: example.com, Envelope From: mail.example.com
        # In relaxed mode (aspf=r), mail.example.com aligns with example.com
        spf_res = SPFResult(status="Pass", domain="mail.example.com", client_ip="1.2.3.4")
        dkim_res = DKIMResult(status="None")

        res = self.evaluator.evaluate(
            header_from="support@example.com",
            spf_result=spf_res,
            dkim_result=dkim_res,
            envelope_from="mailer@mail.example.com"
        )
        self.assertEqual(res.status, "Pass")
        self.assertTrue(res.spf_aligned)

    def test_dmarc_strict_alignment_failure(self):
        # Under strict mode (aspf=s), mail.strict.com does NOT align with strict.com
        spf_res = SPFResult(status="Pass", domain="mail.strict.com", client_ip="1.2.3.4")
        dkim_res = DKIMResult(status="None")

        res = self.evaluator.evaluate(
            header_from="admin@strict.com",
            spf_result=spf_res,
            dkim_result=dkim_res,
            envelope_from="bounces@mail.strict.com"
        )
        self.assertEqual(res.status, "Fail")
        self.assertFalse(res.spf_aligned)
        self.assertEqual(res.disposition, "reject")

    def test_dmarc_policy_quarantine(self):
        spf_res = SPFResult(status="Fail", domain="unrelated.com", client_ip="9.9.9.9")
        dkim_res = DKIMResult(status="None")

        res = self.evaluator.evaluate(
            header_from="user@quarantine.com",
            spf_result=spf_res,
            dkim_result=dkim_res,
            envelope_from="user@unrelated.com"
        )
        self.assertEqual(res.status, "Fail")
        self.assertEqual(res.disposition, "quarantine")

    def test_dmarc_policy_monitoring_none(self):
        spf_res = SPFResult(status="Fail", domain="bad.com", client_ip="8.8.8.8")
        dkim_res = DKIMResult(status="None")

        res = self.evaluator.evaluate(
            header_from="hello@monitoring.com",
            spf_result=spf_res,
            dkim_result=dkim_res,
            envelope_from="hello@bad.com"
        )
        self.assertEqual(res.status, "Fail")
        # In monitoring mode, disposition is 'none' (allow deliver + report)
        self.assertEqual(res.disposition, "none")
        self.assertEqual(res.published_policy, "none")


if __name__ == "__main__":
    unittest.main()
