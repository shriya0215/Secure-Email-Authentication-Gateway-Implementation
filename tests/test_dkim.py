"""
Automated unit tests for RFC 6376 DKIM Signer & Verifier.
"""

import unittest
from gateway.crypto_utils import generate_rsa_key
from gateway.dns_manager import DNSManager
from gateway.dkim_signer_verifier import (
    DKIMSigner,
    DKIMVerifier,
    canonicalize_body_relaxed,
    canonicalize_body_simple,
    canonicalize_header_relaxed,
    canonicalize_header_simple,
)


class TestDKIMSignerVerifier(unittest.TestCase):

    def setUp(self):
        self.dns = DNSManager(storage_file=":memory:")
        self.key = generate_rsa_key(1024)
        self.selector = "s1"
        self.domain = "company.org"

        # Publish public key to DNS
        self.dns.records = {
            f"{self.selector}._domainkey.{self.domain}": {
                "TXT": [self.key.to_dkim_dns_value()]
            }
        }
        self.signer = DKIMSigner(selector=self.selector, domain=self.domain, private_key=self.key)
        self.verifier = DKIMVerifier(self.dns)

    def test_canonicalization_header(self):
        # Relaxed lowercase, unfolded whitespace
        header_name = "Subject"
        header_val = "  Quarterly   Update\r\n\tReport  "
        canon = canonicalize_header_relaxed(header_name, header_val)
        self.assertEqual(canon, "subject:Quarterly Update Report")

        # Simple preserves casing
        canon_simple = canonicalize_header_simple("Subject", "  Important Notice\r\n")
        self.assertEqual(canon_simple, "Subject:  Important Notice")

    def test_canonicalization_body(self):
        body = "Line 1   with   spaces\r\nLine 2\r\n\r\n\r\n"
        canon = canonicalize_body_relaxed(body)
        self.assertEqual(canon, b"Line 1 with spaces\r\nLine 2\r\n")

    def test_sign_and_verify_roundtrip(self):
        raw_msg = (
            "From: Security Team <sec@company.org>\r\n"
            "To: Staff <staff@company.org>\r\n"
            "Subject: Mandatory Security Briefing\r\n"
            "Date: Fri, 07 Nov 2026 15:00:00 +0000\r\n"
            "Message-ID: <sec-2026-1@company.org>\r\n"
            "\r\n"
            "All personnel must attend the security review session.\r\n"
        )
        signed = self.signer.sign(raw_msg, canonicalization="relaxed/relaxed")
        self.assertIn("DKIM-Signature:", signed)

        res = self.verifier.verify(signed)
        self.assertEqual(res.status, "Pass")
        self.assertTrue(res.body_hash_match)
        self.assertTrue(res.signature_match)
        self.assertEqual(res.domain, "company.org")
        self.assertEqual(res.selector, "s1")

    def test_body_tampering_detection(self):
        raw_msg = (
            "From: Billing <billing@company.org>\r\n"
            "To: Client <client@client.com>\r\n"
            "Subject: Bank Account Details\r\n"
            "Date: Fri, 07 Nov 2026 15:00:00 +0000\r\n"
            "Message-ID: <pay-001@company.org>\r\n"
            "\r\n"
            "Please remit to Account #12345678.\r\n"
        )
        signed = self.signer.sign(raw_msg)
        # Attacker modifies body in transit
        tampered = signed.replace("Account #12345678", "Account #99999999 (ATTACKER)")

        res = self.verifier.verify(tampered)
        self.assertEqual(res.status, "Fail")
        self.assertFalse(res.body_hash_match)

    def test_header_tampering_detection(self):
        raw_msg = (
            "From: HR <hr@company.org>\r\n"
            "To: Staff <staff@company.org>\r\n"
            "Subject: Policy Update\r\n"
            "Date: Fri, 07 Nov 2026 15:00:00 +0000\r\n"
            "Message-ID: <hr-002@company.org>\r\n"
            "\r\n"
            "New policy is attached.\r\n"
        )
        signed = self.signer.sign(raw_msg)
        # Attacker tampers with signed header
        tampered = signed.replace("Subject: Policy Update", "Subject: URGENT ACTION REQUIRED")

        res = self.verifier.verify(tampered)
        self.assertEqual(res.status, "Fail")
        self.assertTrue(res.body_hash_match)
        self.assertFalse(res.signature_match)


if __name__ == "__main__":
    unittest.main()
