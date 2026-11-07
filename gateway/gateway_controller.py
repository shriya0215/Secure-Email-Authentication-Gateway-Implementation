"""
Secure Email Authentication Gateway Controller.
Orchestrates the entire SPF, DKIM, and DMARC verification pipeline,
evaluates threat levels, and outputs structured security analyses.
"""

from dataclasses import dataclass, field
import datetime
from typing import Any, Dict, List, Optional
from gateway.dns_manager import DNSManager, dns_manager
from gateway.email_parser import EmailParser, ParsedEmailHeaders, generate_authentication_results_header
from gateway.spf_validator import SPFValidator, SPFResult
from gateway.dkim_signer_verifier import DKIMVerifier, DKIMResult
from gateway.dmarc_evaluator import DMARCEvaluator, DMARCResult, extract_domain_from_email


@dataclass
class GatewayInspectionResult:
    timestamp: str
    security_verdict: str       # 'PASS', 'REJECT', 'QUARANTINE', 'MONITOR', 'UNAUTHENTICATED'
    threat_level: str           # 'CLEAN', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'
    threat_summary: str
    recommended_action: str
    parsed_headers: Dict[str, Any]
    spf: Dict[str, Any]
    dkim: Dict[str, Any]
    dmarc: Dict[str, Any]
    auth_results_header: str
    rua_xml: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "timestamp": self.timestamp,
            "security_verdict": self.security_verdict,
            "threat_level": self.threat_level,
            "threat_summary": self.threat_summary,
            "recommended_action": self.recommended_action,
            "parsed_headers": self.parsed_headers,
            "spf": self.spf,
            "dkim": self.dkim,
            "dmarc": self.dmarc,
            "auth_results_header": self.auth_results_header,
            "rua_xml": self.rua_xml,
        }


class EmailGateway:
    """Security Gateway implementing SPF, DKIM, and DMARC verification."""

    def __init__(self, dns_mgr: Optional[DNSManager] = None, gateway_hostname: str = "mail-gw.antigravity.security"):
        self.dns = dns_mgr or dns_manager
        self.gateway_hostname = gateway_hostname
        self.spf_validator = SPFValidator(self.dns)
        self.dkim_verifier = DKIMVerifier(self.dns)
        self.dmarc_evaluator = DMARCEvaluator(self.dns)

    def inspect(
        self,
        raw_email: str,
        client_ip: Optional[str] = None,
        envelope_from: Optional[str] = None
    ) -> GatewayInspectionResult:
        """
        Executes complete verification pipeline:
        1. Parse RFC 5322 email and headers
        2. Resolve client IP and envelope from
        3. Evaluate SPF
        4. Evaluate DKIM
        5. Evaluate DMARC alignment and policy
        6. Determine overall security verdict and threat level
        7. Generate standard Authentication-Results and RUA report XML
        """
        parsed = EmailParser.parse(raw_email)

        # 1. Resolve client IP (argument overrides, otherwise extract from Received headers, fallback to 127.0.0.1)
        effective_ip = (client_ip or parsed.extracted_client_ip or "127.0.0.1").strip()

        # 2. Resolve envelope from (argument overrides, otherwise Return-Path, otherwise From)
        effective_env_from = (envelope_from or parsed.return_path or parsed.header_from).strip()
        spf_domain = extract_domain_from_email(effective_env_from) or "unknown.domain"

        # 3. Evaluate SPF
        spf_res: SPFResult = self.spf_validator.evaluate(effective_ip, spf_domain)

        # 4. Evaluate DKIM
        dkim_res: DKIMResult = self.dkim_verifier.verify(raw_email)

        # 5. Evaluate DMARC
        dmarc_res: DMARCResult = self.dmarc_evaluator.evaluate(
            header_from=parsed.header_from,
            spf_result=spf_res,
            dkim_result=dkim_res,
            envelope_from=effective_env_from
        )

        # 6. Determine Threat Level & Action
        verdict, threat_level, summary, action = self._assess_threat(spf_res, dkim_res, dmarc_res)

        # 7. Synthesize Authentication-Results header
        from_domain = extract_domain_from_email(parsed.header_from) or "unknown.domain"
        auth_header = generate_authentication_results_header(
            auth_serv_id=self.gateway_hostname,
            spf_status=spf_res.status,
            spf_domain=spf_domain,
            client_ip=effective_ip,
            dkim_status=dkim_res.status,
            dkim_domain=dkim_res.domain,
            dkim_selector=dkim_res.selector,
            dmarc_status=dmarc_res.status,
            dmarc_policy=dmarc_res.published_policy,
            dmarc_disposition=dmarc_res.disposition,
            from_domain=from_domain
        )

        # 8. Generate RUA XML
        rua_xml = self.dmarc_evaluator.generate_rua_report_xml(
            gateway_org="SecureGateway Defense Corp",
            dmarc_res=dmarc_res,
            client_ip=effective_ip
        )

        now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()

        return GatewayInspectionResult(
            timestamp=now_iso,
            security_verdict=verdict,
            threat_level=threat_level,
            threat_summary=summary,
            recommended_action=action,
            parsed_headers={
                "from": parsed.header_from,
                "return_path": parsed.return_path,
                "to": parsed.to,
                "subject": parsed.subject,
                "date": parsed.date,
                "message_id": parsed.message_id,
                "extracted_client_ip": parsed.extracted_client_ip,
                "effective_client_ip": effective_ip,
                "effective_envelope_from": effective_env_from,
                "all_headers_count": len(parsed.all_headers)
            },
            spf=spf_res.to_dict(),
            dkim=dkim_res.to_dict(),
            dmarc=dmarc_res.to_dict(),
            auth_results_header=auth_header,
            rua_xml=rua_xml
        )

    def _assess_threat(
        self,
        spf: SPFResult,
        dkim: DKIMResult,
        dmarc: DMARCResult
    ) -> Tuple[str, str, str, str]:
        """Calculates security verdict, threat severity, and actionable remediation."""
        # Check for active DKIM tampering detection
        if dkim.status == "Fail" and not dkim.body_hash_match:
            if dmarc.disposition == "reject":
                return (
                    "REJECT",
                    "CRITICAL",
                    "Tampered in-transit! DKIM cryptographic body hash failed (content altered after signing), and domain policy requires rejection.",
                    "Block message immediately; payload has been modified by unauthorized intermediary."
                )
            elif dmarc.status == "Pass":
                return (
                    "SUSPICIOUS",
                    "HIGH",
                    "Warning: SPF passed but DKIM body hash verification failed. The message body appears to have been modified in transit.",
                    "Flag message as modified in transit and append security warning banner."
                )

        if dmarc.status == "Pass":
            return (
                "PASS",
                "CLEAN",
                "Legitimate email: Sender successfully authenticated via SPF and/or DKIM with identifier alignment.",
                "Deliver immediately to user inbox without friction."
            )

        # DMARC Failed
        if dmarc.disposition == "reject":
            return (
                "REJECT",
                "CRITICAL",
                f"High-confidence spoofing / phishing attempt detected! Sender failed DMARC authentication and alignment against strict reject policy ({dmarc.published_policy}).",
                "Block / reject message at SMTP gateway; drop connection and dispatch security telemetry."
            )
        elif dmarc.disposition == "quarantine":
            return (
                "QUARANTINE",
                "HIGH",
                f"Suspicious unauthenticated message. Domain policy requires quarantine ({dmarc.published_policy}).",
                "Divert to Spam/Junk folder or hold in administrator quarantine queue for human review."
            )
        elif dmarc.published_policy == "none":
            return (
                "MONITOR",
                "MEDIUM",
                "DMARC authentication failed, but domain is operating in monitoring mode (p=none).",
                "Deliver message with warning banner attached; record telemetry in RUA aggregate report."
            )
        else:
            return (
                "UNAUTHENTICATED",
                "MEDIUM",
                "No protective DMARC policy found for this domain. Email failed standard authentication checks.",
                "Flag message with external untrusted sender warning."
            )
