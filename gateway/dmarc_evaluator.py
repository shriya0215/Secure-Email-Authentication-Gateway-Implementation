"""
RFC 7489 Domain-based Message Authentication, Reporting, and Conformance (DMARC) Evaluator.
Evaluates SPF and DKIM identifier alignment against published DMARC policies.
Generates RFC 7489 compliant RUA XML aggregate reports.
"""

from dataclasses import dataclass, field
import datetime
import re
from typing import Dict, List, Optional, Tuple
from gateway.dns_manager import DNSManager, dns_manager
from gateway.spf_validator import SPFResult
from gateway.dkim_signer_verifier import DKIMResult


def extract_domain_from_email(email_str: str) -> str:
    """Extracts lowercase domain from an email address or address field."""
    # Handle angle bracket formats: "John Doe <john@example.com>"
    match = re.search(r'<([^>]+)>', email_str)
    addr = match.group(1) if match else email_str
    if '@' in addr:
        return addr.split('@', 1)[1].strip().lower().rstrip('>')
    return addr.strip().lower()


def get_organizational_domain(domain: str) -> str:
    """
    Extracts the organizational domain (e.g. 'sub.corp.example.com' -> 'example.com').
    Covers common multi-part TLDs (co.uk, com.au, etc.).
    """
    parts = domain.lower().strip().rstrip('.').split('.')
    if len(parts) <= 2:
        return domain

    # Common two-part TLDs
    two_part_tlds = {
        "co.uk", "org.uk", "gov.uk", "ac.uk",
        "com.au", "net.au", "org.au",
        "co.in", "net.in", "org.in", "gen.in",
        "co.jp", "ne.jp",
        "com.br", "org.br",
    }
    candidate_tld = f"{parts[-2]}.{parts[-1]}"
    if candidate_tld in two_part_tlds:
        if len(parts) >= 3:
            return f"{parts[-3]}.{candidate_tld}"
        return candidate_tld

    return f"{parts[-2]}.{parts[-1]}"


@dataclass
class DMARCResult:
    status: str  # 'Pass' or 'Fail'
    header_from_domain: str
    dmarc_record: Optional[str] = None
    policy_domain: Optional[str] = None
    published_policy: str = "none"  # 'none', 'quarantine', 'reject'
    subdomain_policy: Optional[str] = None
    disposition: str = "none"       # 'none' (deliver), 'quarantine' (spam), 'reject' (block)
    percentage: int = 100
    spf_aligned: bool = False
    dkim_aligned: bool = False
    spf_status: str = "None"
    dkim_status: str = "None"
    adkim: str = "r"  # 'r' (relaxed) or 's' (strict)
    aspf: str = "r"   # 'r' (relaxed) or 's' (strict)
    rua: Optional[str] = None
    ruf: Optional[str] = None
    explanation: str = ""
    details: List[str] = field(default_factory=list)

    def to_dict(self):
        return {
            "status": self.status,
            "header_from_domain": self.header_from_domain,
            "dmarc_record": self.dmarc_record,
            "policy_domain": self.policy_domain,
            "published_policy": self.published_policy,
            "subdomain_policy": self.subdomain_policy,
            "disposition": self.disposition,
            "percentage": self.percentage,
            "spf_aligned": self.spf_aligned,
            "dkim_aligned": self.dkim_aligned,
            "spf_status": self.spf_status,
            "dkim_status": self.dkim_status,
            "adkim": self.adkim,
            "aspf": self.aspf,
            "rua": self.rua,
            "ruf": self.ruf,
            "explanation": self.explanation,
            "details": self.details,
        }


class DMARCEvaluator:
    """Evaluates DMARC compliance according to RFC 7489."""

    def __init__(self, dns_mgr: Optional[DNSManager] = None):
        self.dns = dns_mgr or dns_manager

    def evaluate(
        self,
        header_from: str,
        spf_result: SPFResult,
        dkim_result: DKIMResult,
        envelope_from: Optional[str] = None
    ) -> DMARCResult:
        """
        Evaluates DMARC given the RFC 5322 From header, SPF result, and DKIM result.
        """
        details: List[str] = []
        from_domain = extract_domain_from_email(header_from)
        details.append(f"RFC 5322 Header From Domain: '{from_domain}'")

        # Discover DMARC Record
        record_str, policy_domain = self.dns.get_dmarc_record(from_domain)
        if not record_str:
            details.append(f"No DMARC record found for '{from_domain}' or its organizational domain")
            return DMARCResult(
                status="Fail",
                header_from_domain=from_domain,
                published_policy="none",
                disposition="none",
                explanation=f"No DMARC policy published for domain '{from_domain}'",
                details=details
            )

        details.append(f"Retrieved DMARC record for '{policy_domain}': {record_str}")

        # Parse DMARC tags
        tags = self._parse_tags(record_str)
        policy = tags.get("p", "none").lower()
        sub_policy = tags.get("sp", policy).lower()
        adkim = tags.get("adkim", "r").lower()
        aspf = tags.get("aspf", "r").lower()
        rua = tags.get("rua")
        ruf = tags.get("ruf")

        try:
            pct = int(tags.get("pct", "100"))
        except ValueError:
            pct = 100

        # Determine effective policy (subdomain vs main domain)
        effective_policy = policy
        is_subdomain = (from_domain != policy_domain)
        if is_subdomain:
            effective_policy = sub_policy
            details.append(f"Domain is subdomain of '{policy_domain}', applying subdomain policy 'sp={effective_policy}'")
        else:
            details.append(f"Applying main domain policy 'p={effective_policy}'")

        # 1. Evaluate SPF Alignment
        # Envelope domain comes from envelope_from or SPF result domain
        env_domain = extract_domain_from_email(envelope_from) if envelope_from else spf_result.domain
        spf_aligned = self._check_alignment(from_domain, env_domain, aspf)
        details.append(
            f"SPF Alignment check: Header From='{from_domain}' vs Envelope='{env_domain}' (mode={aspf}) -> {'ALIGNED' if spf_aligned else 'NOT ALIGNED'}"
        )

        # 2. Evaluate DKIM Alignment
        dkim_aligned = False
        if dkim_result.domain:
            dkim_aligned = self._check_alignment(from_domain, dkim_result.domain, adkim)
            details.append(
                f"DKIM Alignment check: Header From='{from_domain}' vs DKIM d='{dkim_result.domain}' (mode={adkim}) -> {'ALIGNED' if dkim_aligned else 'NOT ALIGNED'}"
            )
        else:
            details.append("DKIM Alignment check: No DKIM signing domain present -> NOT ALIGNED")

        # DMARC PASS Condition:
        # (SPF is Pass AND SPF is aligned) OR (DKIM is Pass AND DKIM is aligned)
        spf_dmarc_pass = (spf_result.status == "Pass" and spf_aligned)
        dkim_dmarc_pass = (dkim_result.status == "Pass" and dkim_aligned)

        dmarc_pass = spf_dmarc_pass or dkim_dmarc_pass

        if dmarc_pass:
            status = "Pass"
            disposition = "none"  # Accept and deliver
            reasons = []
            if spf_dmarc_pass:
                reasons.append("SPF authenticated and aligned")
            if dkim_dmarc_pass:
                reasons.append("DKIM authenticated and aligned")
            explanation = f"DMARC Pass: {', '.join(reasons)}"
        else:
            status = "Fail"
            disposition = effective_policy  # 'none', 'quarantine', or 'reject'
            fail_reasons = []
            if not spf_aligned:
                fail_reasons.append(f"SPF unaligned (Envelope: {env_domain})")
            elif spf_result.status != "Pass":
                fail_reasons.append(f"SPF {spf_result.status}")

            if not dkim_aligned:
                fail_reasons.append(f"DKIM unaligned (d={dkim_result.domain or 'none'})")
            elif dkim_result.status != "Pass":
                fail_reasons.append(f"DKIM {dkim_result.status}")

            action_desc = {
                "none": "Monitoring mode: Deliver email and report violation",
                "quarantine": "Enforce quarantine: Divert email to spam/junk quarantine",
                "reject": "Enforce rejection: Block/reject email at gateway"
            }.get(disposition, disposition)

            explanation = f"DMARC Fail: {'; '.join(fail_reasons)}. Action: [{disposition.upper()}] - {action_desc}"

        return DMARCResult(
            status=status,
            header_from_domain=from_domain,
            dmarc_record=record_str,
            policy_domain=policy_domain,
            published_policy=policy,
            subdomain_policy=sub_policy if sub_policy != policy else None,
            disposition=disposition,
            percentage=pct,
            spf_aligned=spf_aligned,
            dkim_aligned=dkim_aligned,
            spf_status=spf_result.status,
            dkim_status=dkim_result.status,
            adkim=adkim,
            aspf=aspf,
            rua=rua,
            ruf=ruf,
            explanation=explanation,
            details=details
        )

    def _check_alignment(self, from_domain: str, candidate_domain: str, mode: str) -> bool:
        """
        Checks strict ('s') or relaxed ('r') alignment between from_domain and candidate_domain.
        """
        f = from_domain.lower().strip().rstrip('.')
        c = candidate_domain.lower().strip().rstrip('.')

        if mode == "s":
            # Strict: Exact match required
            return f == c
        else:
            # Relaxed: Organizational domains must match
            return get_organizational_domain(f) == get_organizational_domain(c)

    def _parse_tags(self, record_str: str) -> Dict[str, str]:
        """Parses DMARC record tag-value pairs."""
        tags = {}
        for part in record_str.split(';'):
            part = part.strip()
            if not part or '=' not in part:
                continue
            k, v = part.split('=', 1)
            tags[k.strip().lower()] = v.strip()
        return tags

    def generate_rua_report_xml(
        self,
        gateway_org: str,
        dmarc_res: DMARCResult,
        client_ip: str,
        msg_count: int = 1
    ) -> str:
        """
        Generates an RFC 7489 aggregate XML report (RUA) for the evaluated message.
        """
        now = datetime.datetime.now(datetime.timezone.utc)
        start_ts = int((now - datetime.timedelta(days=1)).timestamp())
        end_ts = int(now.timestamp())
        report_id = f"{dmarc_res.header_from_domain}.{end_ts}.rua"

        xml = f"""<?xml version="1.0" encoding="UTF-8" ?>
<feedback xmlns="urn:ietf:params:xml:ns:dmarc-2.0">
  <report_metadata>
    <org_name>{gateway_org}</org_name>
    <email>dmarc-admin@{gateway_org.lower().replace(' ', '')}.com</email>
    <report_id>{report_id}</report_id>
    <date_range>
      <begin>{start_ts}</begin>
      <end>{end_ts}</end>
    </date_range>
  </report_metadata>
  <policy_published>
    <domain>{dmarc_res.policy_domain}</domain>
    <adkim>{dmarc_res.adkim}</adkim>
    <aspf>{dmarc_res.aspf}</aspf>
    <p>{dmarc_res.published_policy}</p>
    <sp>{dmarc_res.subdomain_policy or dmarc_res.published_policy}</sp>
    <pct>{dmarc_res.percentage}</pct>
  </policy_published>
  <record>
    <row>
      <source_ip>{client_ip}</source_ip>
      <count>{msg_count}</count>
      <policy_evaluated>
        <disposition>{dmarc_res.disposition}</disposition>
        <dkim>{'pass' if dmarc_res.dkim_status == 'Pass' and dmarc_res.dkim_aligned else 'fail'}</dkim>
        <spf>{'pass' if dmarc_res.spf_status == 'Pass' and dmarc_res.spf_aligned else 'fail'}</spf>
      </policy_evaluated>
    </row>
    <identifiers>
      <header_from>{dmarc_res.header_from_domain}</header_from>
    </identifiers>
    <auth_results>
      <spf>
        <domain>{dmarc_res.header_from_domain}</domain>
        <result>{dmarc_res.spf_status.lower()}</result>
      </spf>
      <dkim>
        <domain>{dmarc_res.header_from_domain}</domain>
        <result>{dmarc_res.dkim_status.lower()}</result>
      </dkim>
    </auth_results>
  </record>
</feedback>"""
        return xml.strip()
