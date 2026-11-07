"""
RFC 7208 Sender Policy Framework (SPF) Validator.
Evaluates authorization of sending IP addresses against SPF DNS records.
"""

from dataclasses import dataclass, field
import ipaddress
import re
from typing import List, Optional, Tuple
from gateway.dns_manager import DNSManager, dns_manager


@dataclass
class SPFResult:
    status: str  # 'Pass', 'Fail', 'SoftFail', 'Neutral', 'None', 'PermError', 'TempError'
    domain: str
    client_ip: str
    record: Optional[str] = None
    matched_mechanism: Optional[str] = None
    explanation: str = ""
    dns_lookups_count: int = 0
    details: List[str] = field(default_factory=list)

    def to_dict(self):
        return {
            "status": self.status,
            "domain": self.domain,
            "client_ip": self.client_ip,
            "record": self.record,
            "matched_mechanism": self.matched_mechanism,
            "explanation": self.explanation,
            "dns_lookups_count": self.dns_lookups_count,
            "details": self.details,
        }


class SPFValidator:
    """Evaluates client IP addresses against domain SPF records."""

    MAX_DNS_LOOKUPS = 10

    def __init__(self, dns_mgr: Optional[DNSManager] = None):
        self.dns = dns_mgr or dns_manager

    def evaluate(self, client_ip: str, sender_domain: str, recursion_depth: int = 0, seen_domains: Optional[set] = None) -> SPFResult:
        """
        Evaluates SPF for a given client IP and sender domain.
        Handles IPv4/IPv6 CIDRs, include:, a, mx, and all mechanisms.
        """
        seen_domains = seen_domains or set()
        domain = sender_domain.lower().strip().rstrip(".")
        details: List[str] = []

        # Validate IP address format
        try:
            ip_obj = ipaddress.ip_address(client_ip.strip())
        except ValueError:
            return SPFResult(
                status="PermError",
                domain=domain,
                client_ip=client_ip,
                explanation=f"Invalid IP address format: '{client_ip}'",
                details=["IP validation error"]
            )

        if domain in seen_domains:
            return SPFResult(
                status="PermError",
                domain=domain,
                client_ip=client_ip,
                explanation=f"Loop detected in SPF include for domain '{domain}'",
                details=details
            )
        seen_domains.add(domain)

        spf_record = self.dns.get_spf_record(domain)
        if not spf_record:
            return SPFResult(
                status="None",
                domain=domain,
                client_ip=client_ip,
                explanation=f"No SPF record published for domain '{domain}'",
                details=[f"DNS query for TXT at {domain} returned no v=spf1 record"]
            )

        details.append(f"Retrieved SPF record for '{domain}': {spf_record}")

        # Parse terms
        terms = spf_record.split()
        if not terms or terms[0].lower() != "v=spf1":
            return SPFResult(
                status="PermError",
                domain=domain,
                client_ip=client_ip,
                record=spf_record,
                explanation="SPF record does not start with 'v=spf1'",
                details=details
            )

        lookups_used = 1
        qualifier_map = {
            "+": "Pass",
            "-": "Fail",
            "~": "SoftFail",
            "?": "Neutral"
        }

        # Iterate through mechanisms
        for term in terms[1:]:
            term = term.strip()
            if not term:
                continue

            # Check for redirect modifier
            if term.lower().startswith("redirect="):
                redir_domain = term.split("=", 1)[1].strip()
                details.append(f"Following redirect to '{redir_domain}'")
                sub_res = self.evaluate(client_ip, redir_domain, recursion_depth + 1, seen_domains)
                sub_res.details = details + sub_res.details
                return sub_res

            # Determine qualifier (+, -, ~, ?)
            qualifier = "+"
            raw_term = term
            if term[0] in "+-~?":
                qualifier = term[0]
                term = term[1:]

            result_for_match = qualifier_map[qualifier]

            # 1. Mechanism: ip4:<network>
            if term.lower().startswith("ip4:"):
                cidr = term[4:].strip()
                try:
                    net = ipaddress.ip_network(cidr, strict=False)
                    if ip_obj.version == 4 and ip_obj in net:
                        details.append(f"Client IP {client_ip} matched {raw_term}")
                        return SPFResult(
                            status=result_for_match,
                            domain=domain,
                            client_ip=client_ip,
                            record=spf_record,
                            matched_mechanism=raw_term,
                            explanation=f"Client IP {client_ip} matched {raw_term} -> {result_for_match}",
                            dns_lookups_count=lookups_used,
                            details=details
                        )
                except ValueError:
                    return SPFResult(
                        status="PermError",
                        domain=domain,
                        client_ip=client_ip,
                        record=spf_record,
                        matched_mechanism=raw_term,
                        explanation=f"Malformed IPv4 CIDR: {cidr}",
                        details=details
                    )

            # 2. Mechanism: ip6:<network>
            elif term.lower().startswith("ip6:"):
                cidr = term[4:].strip()
                try:
                    net = ipaddress.ip_network(cidr, strict=False)
                    if ip_obj.version == 6 and ip_obj in net:
                        details.append(f"Client IP {client_ip} matched {raw_term}")
                        return SPFResult(
                            status=result_for_match,
                            domain=domain,
                            client_ip=client_ip,
                            record=spf_record,
                            matched_mechanism=raw_term,
                            explanation=f"Client IP {client_ip} matched {raw_term} -> {result_for_match}",
                            dns_lookups_count=lookups_used,
                            details=details
                        )
                except ValueError:
                    return SPFResult(
                        status="PermError",
                        domain=domain,
                        client_ip=client_ip,
                        record=spf_record,
                        matched_mechanism=raw_term,
                        explanation=f"Malformed IPv6 CIDR: {cidr}",
                        details=details
                    )

            # 3. Mechanism: a or a:<domain>
            elif term.lower() == "a" or term.lower().startswith("a:"):
                target_domain = domain if term.lower() == "a" else term[2:].strip()
                lookups_used += 1
                details.append(f"Evaluating 'a' mechanism for '{target_domain}'")
                a_records = self.dns.query(target_domain, "A")
                for a_ip in a_records:
                    try:
                        if ip_obj == ipaddress.ip_address(a_ip):
                            details.append(f"Client IP matched A record of {target_domain} ({a_ip})")
                            return SPFResult(
                                status=result_for_match,
                                domain=domain,
                                client_ip=client_ip,
                                record=spf_record,
                                matched_mechanism=raw_term,
                                explanation=f"Client IP {client_ip} matched A record of {target_domain} -> {result_for_match}",
                                dns_lookups_count=lookups_used,
                                details=details
                            )
                    except ValueError:
                        continue

            # 4. Mechanism: mx or mx:<domain>
            elif term.lower() == "mx" or term.lower().startswith("mx:"):
                target_domain = domain if term.lower() == "mx" else term[3:].strip()
                lookups_used += 1
                details.append(f"Evaluating 'mx' mechanism for '{target_domain}'")
                mx_hosts = self.dns.query(target_domain, "MX")
                for mx_host in mx_hosts:
                    lookups_used += 1
                    a_records = self.dns.query(mx_host, "A")
                    for a_ip in a_records:
                        try:
                            if ip_obj == ipaddress.ip_address(a_ip):
                                details.append(f"Client IP matched MX host {mx_host} IP ({a_ip})")
                                return SPFResult(
                                    status=result_for_match,
                                    domain=domain,
                                    client_ip=client_ip,
                                    record=spf_record,
                                    matched_mechanism=raw_term,
                                    explanation=f"Client IP {client_ip} matched MX host {mx_host} -> {result_for_match}",
                                    dns_lookups_count=lookups_used,
                                    details=details
                                )
                        except ValueError:
                            continue

            # 5. Mechanism: include:<domain>
            elif term.lower().startswith("include:"):
                inc_domain = term[8:].strip()
                lookups_used += 1
                details.append(f"Evaluating include '{inc_domain}'")
                if lookups_used > self.MAX_DNS_LOOKUPS:
                    return SPFResult(
                        status="PermError",
                        domain=domain,
                        client_ip=client_ip,
                        record=spf_record,
                        matched_mechanism=raw_term,
                        explanation=f"Exceeded max SPF DNS lookups ({self.MAX_DNS_LOOKUPS})",
                        details=details
                    )

                sub_res = self.evaluate(client_ip, inc_domain, recursion_depth + 1, seen_domains.copy())
                lookups_used += sub_res.dns_lookups_count
                if sub_res.status == "Pass":
                    details.append(f"Include {inc_domain} returned Pass")
                    return SPFResult(
                        status=result_for_match,
                        domain=domain,
                        client_ip=client_ip,
                        record=spf_record,
                        matched_mechanism=raw_term,
                        explanation=f"Matched included SPF policy '{inc_domain}' -> {result_for_match}",
                        dns_lookups_count=lookups_used,
                        details=details
                    )
                elif sub_res.status in ("PermError", "TempError"):
                    return sub_res

            # 6. Mechanism: all
            elif term.lower() == "all":
                details.append(f"Reached '{raw_term}' mechanism")
                return SPFResult(
                    status=result_for_match,
                    domain=domain,
                    client_ip=client_ip,
                    record=spf_record,
                    matched_mechanism=raw_term,
                    explanation=f"Matched catch-all mechanism '{raw_term}' -> {result_for_match}",
                    dns_lookups_count=lookups_used,
                    details=details
                )

        # Default if no mechanism matched: Neutral
        return SPFResult(
            status="Neutral",
            domain=domain,
            client_ip=client_ip,
            record=spf_record,
            matched_mechanism=None,
            explanation="No SPF mechanism matched and no 'all' mechanism defined",
            dns_lookups_count=lookups_used,
            details=details
        )
