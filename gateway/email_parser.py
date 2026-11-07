"""
Email Header Parser and RFC 7601 / RFC 8601 Authentication-Results Generator.
"""

from dataclasses import dataclass, field
import email
from email import policy
import re
from typing import Dict, List, Optional, Tuple


@dataclass
class ParsedEmailHeaders:
    header_from: str = ""
    return_path: str = ""
    to: str = ""
    subject: str = ""
    date: str = ""
    message_id: str = ""
    has_dkim: bool = False
    dkim_signatures: List[str] = field(default_factory=list)
    received_hops: List[str] = field(default_factory=list)
    extracted_client_ip: Optional[str] = None
    all_headers: List[Tuple[str, str]] = field(default_factory=list)
    raw_header_text: str = ""
    body: str = ""


class EmailParser:
    """Parses raw email messages and headers."""

    IPV4_PATTERN = r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'

    @classmethod
    def parse(cls, raw_content: str) -> ParsedEmailHeaders:
        """
        Parses raw email message or header block into structured fields.
        """
        # Clean potential double-CR issues from Windows text file writes
        cleaned = raw_content.replace('\r\r\n', '\r\n').replace('\r\n', '\n').replace('\r', '\n')
        if '\n\n' in cleaned:
            header_text, body = cleaned.split('\n\n', 1)
        else:
            header_text, body = cleaned, ""

        parsed = ParsedEmailHeaders(raw_header_text=header_text, body=body)

        # Parse with standard email parser using standard newline format
        msg = email.message_from_string(cleaned, policy=policy.compat32)

        parsed.header_from = (msg.get("From") or "").strip()
        parsed.return_path = (msg.get("Return-Path") or "").strip()
        parsed.to = (msg.get("To") or "").strip()
        parsed.subject = (msg.get("Subject") or "").strip()
        parsed.date = (msg.get("Date") or "").strip()
        parsed.message_id = (msg.get("Message-ID") or "").strip()

        # Collect all headers
        for k, v in msg.items():
            parsed.all_headers.append((k, v))
            if k.lower() == "dkim-signature":
                parsed.has_dkim = True
                parsed.dkim_signatures.append(v)
            elif k.lower() == "received":
                parsed.received_hops.append(v)

        # Extract client IP from Received headers
        parsed.extracted_client_ip = cls._extract_client_ip(parsed.received_hops)

        return parsed

    @classmethod
    def _extract_client_ip(cls, received_hops: List[str]) -> Optional[str]:
        """
        Extracts origin sending client IP from Received headers.
        Searches backwards from the earliest hop towards the latest hop.
        """
        for hop in reversed(received_hops):
            # Look for IP in brackets [1.2.3.4] or parenthesis (1.2.3.4)
            bracket_match = re.search(r'\[(' + cls.IPV4_PATTERN + r')\]', hop)
            if bracket_match:
                ip = bracket_match.group(1)
                if not ip.startswith("127."):
                    return ip

            paren_match = re.search(r'\(([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})\)', hop)
            if paren_match:
                ip = paren_match.group(1)
                if not ip.startswith("127."):
                    return ip

            ip_match = re.search(cls.IPV4_PATTERN, hop)
            if ip_match:
                ip = ip_match.group(0)
                if not ip.startswith("127."):
                    return ip

        return None


def generate_authentication_results_header(
    auth_serv_id: str,
    spf_status: str,
    spf_domain: str,
    client_ip: str,
    dkim_status: str,
    dkim_domain: Optional[str],
    dkim_selector: Optional[str],
    dmarc_status: str,
    dmarc_policy: str,
    dmarc_disposition: str,
    from_domain: str,
) -> str:
    """
    Generates standard RFC 7601 / RFC 8601 Authentication-Results header.
    """
    lines = [f"Authentication-Results: {auth_serv_id};"]

    # SPF clause
    spf_clause = f"    spf={spf_status.lower()} (sender IP {client_ip}) smtp.mailfrom={spf_domain};"
    lines.append(spf_clause)

    # DKIM clause
    if dkim_domain and dkim_selector:
        dkim_clause = f"    dkim={dkim_status.lower()} header.d={dkim_domain} header.s={dkim_selector};"
    else:
        dkim_clause = f"    dkim={dkim_status.lower()} (no signature found);"
    lines.append(dkim_clause)

    # DMARC clause
    dmarc_clause = (
        f"    dmarc={dmarc_status.lower()} (p={dmarc_policy} dis={dmarc_disposition}) "
        f"header.from={from_domain}"
    )
    lines.append(dmarc_clause)

    return "\r\n".join(lines)
