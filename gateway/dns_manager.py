"""
DNS Record Manager and Resolver.
Provides unified simulated (mock) and live DNS resolution for SPF, DKIM, and DMARC records.
"""

import json
import os
import re
import subprocess
from typing import Dict, List, Optional, Tuple


class DNSManager:
    """Manages DNS records for email authentication validation."""

    def __init__(self, storage_file: Optional[str] = None, enable_live_dns: bool = False):
        self.storage_file = storage_file or os.path.join(os.path.dirname(__file__), "dns_zone.json")
        self.enable_live_dns = enable_live_dns
        self.records: Dict[str, Dict[str, List[str]]] = {}
        self.load_or_init_defaults()

    def load_or_init_defaults(self):
        """Loads records from JSON file or initializes default security test domains."""
        if os.path.exists(self.storage_file):
            try:
                with open(self.storage_file, "r", encoding="utf-8") as f:
                    self.records = json.load(f)
                    return
            except Exception:
                pass

        self.reset_to_defaults()

    def reset_to_defaults(self):
        """Resets the DNS zone to comprehensive test records covering monitoring, quarantine, and reject policies."""
        self.records = {
            # Fully protected enterprise domain with p=reject
            "example.com": {
                "TXT": [
                    "v=spf1 ip4:198.51.100.0/24 ip4:203.0.113.10 include:_spf.example.com -all"
                ],
                "A": ["198.51.100.1"],
                "MX": ["mail.example.com"]
            },
            "_spf.example.com": {
                "TXT": [
                    "v=spf1 ip4:198.51.100.50 ip4:198.51.100.51 -all"
                ]
            },
            "_dmarc.example.com": {
                "TXT": [
                    "v=DMARC1; p=reject; pct=100; rua=mailto:dmarc-rua@example.com; ruf=mailto:dmarc-ruf@example.com; adkim=r; aspf=r"
                ]
            },
            "mail.example.com": {
                "A": ["198.51.100.10"]
            },

            # Phishing target domain (Banking) enforcing strict rejection
            "trustedbank.com": {
                "TXT": [
                    "v=spf1 ip4:198.51.100.200 -all"
                ],
                "MX": ["smtp.trustedbank.com"]
            },
            "_dmarc.trustedbank.com": {
                "TXT": [
                    "v=DMARC1; p=reject; pct=100; rua=mailto:security@trustedbank.com; aspf=s; adkim=s"
                ]
            },

            # Startup in Phase 1: Monitoring Mode (p=none)
            "startup.io": {
                "TXT": [
                    "v=spf1 ip4:192.0.2.0/24 ~all"
                ]
            },
            "_dmarc.startup.io": {
                "TXT": [
                    "v=DMARC1; p=none; pct=100; rua=mailto:dmarc-reports@startup.io"
                ]
            },

            # Medium enterprise in Phase 2: Quarantine Mode (p=quarantine)
            "securecorp.org": {
                "TXT": [
                    "v=spf1 ip4:192.0.2.80/28 -all"
                ]
            },
            "_dmarc.securecorp.org": {
                "TXT": [
                    "v=DMARC1; p=quarantine; pct=100; rua=mailto:aggregate@securecorp.org; ruf=mailto:forensics@securecorp.org"
                ]
            },

            # Subdomain test case
            "corp.example.com": {
                "TXT": [
                    "v=spf1 ip4:198.51.100.25 -all"
                ]
            }
        }
        self.save()

    def save(self):
        """Persists records to disk."""
        try:
            with open(self.storage_file, "w", encoding="utf-8") as f:
                json.dump(self.records, f, indent=2)
        except Exception:
            pass

    def add_record(self, domain: str, rtype: str, value: str):
        """Adds a DNS record."""
        domain = domain.lower().strip().rstrip(".")
        rtype = rtype.upper().strip()
        if domain not in self.records:
            self.records[domain] = {}
        if rtype not in self.records[domain]:
            self.records[domain][rtype] = []
        if value not in self.records[domain][rtype]:
            self.records[domain][rtype].append(value)
        self.save()

    def set_record(self, domain: str, rtype: str, values: List[str]):
        """Sets the exact list of values for a record type."""
        domain = domain.lower().strip().rstrip(".")
        rtype = rtype.upper().strip()
        if domain not in self.records:
            self.records[domain] = {}
        self.records[domain][rtype] = values
        self.save()

    def delete_domain(self, domain: str):
        """Deletes all records for a domain."""
        domain = domain.lower().strip().rstrip(".")
        if domain in self.records:
            del self.records[domain]
            self.save()

    def query(self, domain: str, rtype: str) -> List[str]:
        """Queries mock DNS records first; optionally falls back to live DNS query."""
        domain = domain.lower().strip().rstrip(".")
        rtype = rtype.upper().strip()

        if domain in self.records and rtype in self.records[domain]:
            return list(self.records[domain][rtype])

        # Attempt live lookup fallback if explicitly enabled
        if self.enable_live_dns:
            live_res = self._live_lookup(domain, rtype)
            if live_res:
                return live_res

        return []

    def get_spf_record(self, domain: str) -> Optional[str]:
        """Retrieves SPF TXT record (v=spf1...) for a domain."""
        records = self.query(domain, "TXT")
        for rec in records:
            clean = rec.strip().strip('"')
            if clean.startswith("v=spf1 ") or clean == "v=spf1":
                return clean
        return None

    def get_dkim_record(self, selector: str, domain: str) -> Optional[str]:
        """Retrieves DKIM record at <selector>._domainkey.<domain>."""
        qname = f"{selector}._domainkey.{domain}".lower().strip().rstrip(".")
        records = self.query(qname, "TXT")
        for rec in records:
            clean = rec.strip().strip('"')
            if "v=DKIM1" in clean or "p=" in clean:
                return clean
        return None

    def get_dmarc_record(self, domain: str) -> Tuple[Optional[str], Optional[str]]:
        """
        Retrieves DMARC record.
        RFC 7489 Section 6.6.3:
        Query _dmarc.<domain>. If not found, query _dmarc.<org_domain>.
        Returns (record_str, matched_domain).
        """
        domain = domain.lower().strip().rstrip(".")
        qname = f"_dmarc.{domain}"
        records = self.query(qname, "TXT")
        for rec in records:
            clean = rec.strip().strip('"')
            if clean.startswith("v=DMARC1"):
                return clean, domain

        # Fallback to organizational domain if domain has subdomains
        parts = domain.split(".")
        if len(parts) > 2:
            org_domain = ".".join(parts[-2:])
            org_qname = f"_dmarc.{org_domain}"
            org_records = self.query(org_qname, "TXT")
            for rec in org_records:
                clean = rec.strip().strip('"')
                if clean.startswith("v=DMARC1"):
                    return clean, org_domain

        return None, None

    def _live_lookup(self, domain: str, rtype: str) -> List[str]:
        """Attempts live DNS lookup using Windows nslookup."""
        try:
            cmd = ["nslookup", f"-type={rtype}", domain]
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=1.5)
            if res.returncode != 0:
                return []
            lines = res.stdout.splitlines()
            results = []
            if rtype == "TXT":
                for line in lines:
                    match = re.search(r'text\s*=\s*"([^"]+)"', line, re.IGNORECASE)
                    if match:
                        results.append(match.group(1))
            elif rtype == "A":
                capture = False
                for line in lines:
                    if "Name:" in line:
                        capture = True
                        continue
                    if capture and "Address:" in line:
                        parts = line.split("Address:")
                        if len(parts) > 1:
                            results.append(parts[1].strip())
            return results
        except Exception:
            return []


# Global default instance
dns_manager = DNSManager()
