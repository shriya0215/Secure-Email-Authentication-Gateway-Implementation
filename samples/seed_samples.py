"""
Seed test keys, DNS records, and realistic sample emails for the gateway.
"""

import os
import sys

# Ensure local imports work
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from gateway.crypto_utils import generate_rsa_key
from gateway.dns_manager import dns_manager
from gateway.dkim_signer_verifier import DKIMSigner


def generate_samples():
    print("Generating RSA keys for sample domains...")
    # 1. Generate key for example.com
    key_example = generate_rsa_key(1024)
    dns_manager.set_record("default._domainkey.example.com", "TXT", [key_example.to_dkim_dns_value()])

    # Save private key for example.com to disk for CLI/signing tests
    priv_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "samples", "example_com_default.key")
    with open(priv_path, "w", encoding="utf-8", newline="\n") as f:
        f.write(key_example.to_private_pem())

    # 1. Legitimate Invoice EML
    raw_legit = (
        "Received: from mail.example.com ([198.51.100.25])\r\n"
        "    by mail-gw.antigravity.security with ESMTP id 98124\r\n"
        "    for <finance@clientcorp.com>; Fri, 07 Nov 2026 10:15:30 +0000\r\n"
        "Return-Path: <billing@example.com>\r\n"
        "From: Global Services Billing <billing@example.com>\r\n"
        "To: Accounts Payable <finance@clientcorp.com>\r\n"
        "Subject: Monthly Enterprise Invoice #INV-2026-8819\r\n"
        "Date: Fri, 07 Nov 2026 10:15:00 +0000\r\n"
        "Message-ID: <inv-2026-8819@example.com>\r\n"
        "MIME-Version: 1.0\r\n"
        "Content-Type: text/plain; charset=UTF-8\r\n"
        "\r\n"
        "Dear Client Team,\r\n\r\n"
        "Please find attached your service invoice for November 2026.\r\n"
        "Total Amount Due: $14,500.00 USD.\r\n"
        "Payment Terms: Net 30 days.\r\n\r\n"
        "Best regards,\r\n"
        "Accounts Department\r\n"
        "Global Services Inc.\r\n"
    )
    signer = DKIMSigner(selector="default", domain="example.com", private_key=key_example)
    signed_legit = signer.sign(raw_legit)

    legit_file = os.path.join(os.path.dirname(os.path.dirname(__file__)), "samples", "legitimate_invoice.eml")
    with open(legit_file, "wb") as f:
        f.write(signed_legit.encode("utf-8"))
    print(f"Created: {legit_file}")

    # 2. Spoofed CEO Fraud Phishing EML
    spoofed_email = (
        "Received: from evil-vps.attacker-net.org ([203.0.113.88])\r\n"
        "    by mail-gw.antigravity.security with ESMTP id 55431\r\n"
        "    for <treasury@clientcorp.com>; Fri, 07 Nov 2026 11:22:15 +0000\r\n"
        "Return-Path: <attacker@attacker-net.org>\r\n"
        "From: Executive Office <ceo@trustedbank.com>\r\n"
        "To: Corporate Treasury <treasury@clientcorp.com>\r\n"
        "Subject: URGENT: Wire Transfer Authorization Required Today\r\n"
        "Date: Fri, 07 Nov 2026 11:22:00 +0000\r\n"
        "Message-ID: <spoof-urgency-99@trustedbank.com>\r\n"
        "MIME-Version: 1.0\r\n"
        "Content-Type: text/plain; charset=UTF-8\r\n"
        "\r\n"
        "Team,\r\n\r\n"
        "I am currently in an executive meeting and cannot take calls.\r\n"
        "Please urgently execute an immediate international wire of $450,000.00\r\n"
        "to the offshore account details below by 2:00 PM today.\r\n\r\n"
        "Swift: EVILUS33\r\n"
        "IBAN: US9900000000123456789\r\n\r\n"
        "CEO - Trusted Bank Financial Group\r\n"
    )
    spoofed_file = os.path.join(os.path.dirname(os.path.dirname(__file__)), "samples", "spoofed_ceo_fraud.eml")
    with open(spoofed_file, "wb") as f:
        f.write(spoofed_email.encode("utf-8"))
    print(f"Created: {spoofed_file}")

    # 3. Tampered In-Transit EML (Man-In-The-Middle altered body and unauthorized relay)
    tampered_email = signed_legit.replace(
        "Received: from mail.example.com ([198.51.100.25])",
        "Received: from rogue-relay.intercept-net.org ([203.0.113.77])"
    ).replace(
        "$14,500.00 USD",
        "$98,750.00 USD (ROUTED TO NEW ATTACKER IBAN: GB29XAAA00000012345678)"
    )
    tampered_file = os.path.join(os.path.dirname(os.path.dirname(__file__)), "samples", "tampered_dkim_transfer.eml")
    with open(tampered_file, "wb") as f:
        f.write(tampered_email.encode("utf-8"))
    print(f"Created: {tampered_file}")

    # 4. Monitoring Mode Phase 1 EML (startup.io p=none)
    monitoring_email = (
        "Received: from bulk-relay.mailcloud.net ([198.51.100.99])\r\n"
        "    by mail-gw.antigravity.security with ESMTP id 12098\r\n"
        "    for <developer@somedomain.com>; Fri, 07 Nov 2026 09:00:00 +0000\r\n"
        "Return-Path: <marketing@unaligned-thirdparty.net>\r\n"
        "From: Startup Dev Weekly <newsletter@startup.io>\r\n"
        "To: Subscriber <developer@somedomain.com>\r\n"
        "Subject: Startup.io Weekly Digest #42 - Staging DMARC Deployment\r\n"
        "Date: Fri, 07 Nov 2026 09:00:00 +0000\r\n"
        "Message-ID: <weekly-42@startup.io>\r\n"
        "MIME-Version: 1.0\r\n"
        "Content-Type: text/plain; charset=UTF-8\r\n"
        "\r\n"
        "Welcome to our newsletter! We are currently transitioning our domain\r\n"
        "to strict DMARC enforcement using p=none monitoring mode.\r\n"
    )
    monitoring_file = os.path.join(os.path.dirname(os.path.dirname(__file__)), "samples", "dmarc_monitoring_marketing.eml")
    with open(monitoring_file, "wb") as f:
        f.write(monitoring_email.encode("utf-8"))
    print(f"Created: {monitoring_file}")

    # 5. Quarantine Mode EML (securecorp.org p=quarantine)
    quarantine_email = (
        "Received: from unknown-server.net ([203.0.113.19])\r\n"
        "    by mail-gw.antigravity.security with ESMTP id 77812\r\n"
        "    for <employee@securecorp.org>; Fri, 07 Nov 2026 12:30:00 +0000\r\n"
        "Return-Path: <unauthorized@unknown-server.net>\r\n"
        "From: HR Internal Portal <humanresources@securecorp.org>\r\n"
        "To: Employee <employee@securecorp.org>\r\n"
        "Subject: Notice: Annual Benefits Open Enrollment Form\r\n"
        "Date: Fri, 07 Nov 2026 12:30:00 +0000\r\n"
        "Message-ID: <hr-benefits-2026@securecorp.org>\r\n"
        "MIME-Version: 1.0\r\n"
        "Content-Type: text/plain; charset=UTF-8\r\n"
        "\r\n"
        "Please fill out your open enrollment form at the external portal link.\r\n"
    )
    quarantine_file = os.path.join(os.path.dirname(os.path.dirname(__file__)), "samples", "quarantine_hr_notice.eml")
    with open(quarantine_file, "wb") as f:
        f.write(quarantine_email.encode("utf-8"))
    print(f"Created: {quarantine_file}")

    dns_manager.save()
    print("All sample datasets & DNS records successfully seeded!")


if __name__ == "__main__":
    generate_samples()
