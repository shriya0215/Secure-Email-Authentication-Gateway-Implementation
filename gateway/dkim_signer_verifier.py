"""
RFC 6376 DomainKeys Identified Mail (DKIM) Signer and Verifier.
Implements header and body canonicalization, SHA-256 body hashing, and RSA signature verification.
"""

import base64
from dataclasses import dataclass, field
import hashlib
import re
import time
from typing import Dict, List, Optional, Tuple
from gateway.crypto_utils import (
    RSAKey,
    import_public_key_der_or_b64,
    rsa_sign_sha256,
    rsa_verify_sha256,
)
from gateway.dns_manager import DNSManager, dns_manager


@dataclass
class DKIMResult:
    status: str  # 'Pass', 'Fail', 'None', 'PermError', 'TempError'
    domain: Optional[str] = None
    selector: Optional[str] = None
    canonicalization: Optional[str] = None
    signed_headers: List[str] = field(default_factory=list)
    body_hash_match: bool = False
    signature_match: bool = False
    explanation: str = ""
    dns_record: Optional[str] = None
    details: List[str] = field(default_factory=list)

    def to_dict(self):
        return {
            "status": self.status,
            "domain": self.domain,
            "selector": self.selector,
            "canonicalization": self.canonicalization,
            "signed_headers": self.signed_headers,
            "body_hash_match": self.body_hash_match,
            "signature_match": self.signature_match,
            "explanation": self.explanation,
            "dns_record": self.dns_record,
            "details": self.details,
        }


# ---------------- Canonicalization Functions ----------------

def canonicalize_header_relaxed(name: str, value: str) -> str:
    """
    RFC 6376 Section 3.4.2: Relaxed Header Canonicalization.
    - Lowercase header field name.
    - Unfold whitespace (replace CRLF followed by WSP with single space).
    - Convert multiple WSP to single space.
    - Strip leading/trailing WSP.
    """
    clean_name = name.strip().lower()
    clean_val = re.sub(r'\r?\n[ \t]+', ' ', value)
    clean_val = re.sub(r'[ \t]+', ' ', clean_val).strip()
    return f"{clean_name}:{clean_val}"


def canonicalize_header_simple(name: str, value: str) -> str:
    """RFC 6376 Section 3.4.1: Simple Header Canonicalization."""
    return f"{name}:{value.strip('\r\n')}"


def canonicalize_body_relaxed(body_text: str) -> bytes:
    """
    RFC 6376 Section 3.4.4: Relaxed Body Canonicalization.
    - Reduce all sequences of WSP within a line to a single space.
    - Ignore all WSP at the end of lines.
    - Ignore all empty lines at the end of the body.
    - End with CRLF if not empty.
    """
    lines = body_text.replace('\r\n', '\n').replace('\r', '\n').split('\n')
    processed_lines = []
    for line in lines:
        cleaned = re.sub(r'[ \t]+', ' ', line).rstrip(' \t')
        processed_lines.append(cleaned)

    # Trim trailing empty lines
    while processed_lines and processed_lines[-1] == "":
        processed_lines.pop()

    if not processed_lines:
        return b""

    return ("\r\n".join(processed_lines) + "\r\n").encode("utf-8")


def canonicalize_body_simple(body_text: str) -> bytes:
    """
    RFC 6376 Section 3.4.3: Simple Body Canonicalization.
    - Ignore trailing empty lines.
    - Ensure ending CRLF.
    """
    lines = body_text.replace('\r\n', '\n').replace('\r', '\n').split('\n')
    while lines and lines[-1] == "":
        lines.pop()
    if not lines:
        return b"\r\n"
    return ("\r\n".join(lines) + "\r\n").encode("utf-8")


# ---------------- Parsing Raw RFC 5322 Headers ----------------

def parse_raw_headers_and_body(raw_email: str) -> Tuple[List[Tuple[str, str]], str]:
    """
    Splits raw email into list of (HeaderName, HeaderValue) tuples preserving order and original case,
    and returns the body text.
    """
    # Normalize line endings to avoid \r\r\n issues on Windows
    normalized = raw_email.replace('\r\r\n', '\r\n').replace('\r\n', '\n').replace('\r', '\n')
    parts = normalized.split('\n\n', 1)
    header_block = parts[0]
    body = parts[1] if len(parts) > 1 else ""

    headers: List[Tuple[str, str]] = []
    current_name = None
    current_val: List[str] = []

    for line in header_block.split('\n'):
        if not line:
            continue
        if line[0] in ' \t':
            # Folded header line
            if current_name:
                current_val.append(line)
        else:
            if current_name:
                headers.append((current_name, '\n'.join(current_val)))
            if ':' in line:
                name, val = line.split(':', 1)
                current_name = name.strip()
                current_val = [val.lstrip()]
            else:
                current_name = None
                current_val = []

    if current_name:
        headers.append((current_name, '\n'.join(current_val)))

    return headers, body


def parse_dkim_tags(sig_header_val: str) -> Dict[str, str]:
    """Parses DKIM-Signature header tag-value pairs."""
    tags = {}
    # Clean whitespace and split on semicolons
    cleaned = re.sub(r'\r?\n[ \t]*', '', sig_header_val)
    parts = cleaned.split(';')
    for part in parts:
        part = part.strip()
        if not part or '=' not in part:
            continue
        k, v = part.split('=', 1)
        tags[k.strip()] = v.strip()
    return tags


# ---------------- DKIM Signer ----------------

class DKIMSigner:
    """Signs outgoing email messages per RFC 6376."""

    DEFAULT_HEADERS_TO_SIGN = [
        "From", "To", "Subject", "Date", "Message-ID", "Cc", "Content-Type", "MIME-Version"
    ]

    def __init__(self, selector: str, domain: str, private_key: RSAKey):
        self.selector = selector
        self.domain = domain.lower().strip()
        self.private_key = private_key

    def sign(
        self,
        raw_email: str,
        headers_to_sign: Optional[List[str]] = None,
        canonicalization: str = "relaxed/relaxed"
    ) -> str:
        """
        Signs a raw RFC 5322 email string and prepends the new DKIM-Signature header.
        """
        headers, body = parse_raw_headers_and_body(raw_email)
        c_header, c_body = canonicalization.split('/')

        # 1. Body Canonicalization & Hash
        if c_body == "relaxed":
            canon_body = canonicalize_body_relaxed(body)
        else:
            canon_body = canonicalize_body_simple(body)

        body_hash = hashlib.sha256(canon_body).digest()
        bh_b64 = base64.b64encode(body_hash).decode('ascii')

        # 2. Select headers to sign
        sign_header_names = headers_to_sign or self.DEFAULT_HEADERS_TO_SIGN
        headers_dict = {}
        for name, val in headers:
            headers_dict[name.lower()] = (name, val)

        actual_signed_names = []
        canonicalized_header_lines = []

        for req_name in sign_header_names:
            low_name = req_name.lower()
            if low_name in headers_dict:
                orig_name, val = headers_dict[low_name]
                actual_signed_names.append(orig_name)
                if c_header == "relaxed":
                    line = canonicalize_header_relaxed(orig_name, val)
                else:
                    line = canonicalize_header_simple(orig_name, val)
                canonicalized_header_lines.append(line)

        # 3. Construct DKIM-Signature header template with empty b=
        h_str = ":".join(actual_signed_names)
        timestamp = int(time.time())
        dkim_sig_val = (
            f"v=1; a=rsa-sha256; c={canonicalization}; d={self.domain}; s={self.selector}; "
            f"t={timestamp}; h={h_str}; bh={bh_b64}; b="
        )

        # 4. Canonicalize DKIM-Signature header itself
        if c_header == "relaxed":
            dkim_canon = canonicalize_header_relaxed("DKIM-Signature", dkim_sig_val)
        else:
            dkim_canon = canonicalize_header_simple("DKIM-Signature", dkim_sig_val)

        canonicalized_header_lines.append(dkim_canon)
        sign_payload = "\r\n".join(canonicalized_header_lines).encode("utf-8")

        # 5. Compute RSA signature
        sig_bytes = rsa_sign_sha256(sign_payload, self.private_key)
        b_b64 = base64.b64encode(sig_bytes).decode('ascii')

        # 6. Prepend completed DKIM-Signature header
        final_sig_header = f"DKIM-Signature: {dkim_sig_val}{b_b64}\r\n"
        return final_sig_header + raw_email


# ---------------- DKIM Verifier ----------------

class DKIMVerifier:
    """Verifies DKIM-Signature headers per RFC 6376."""

    def __init__(self, dns_mgr: Optional[DNSManager] = None):
        self.dns = dns_mgr or dns_manager

    def verify(self, raw_email: str) -> DKIMResult:
        """Parses and cryptographically verifies DKIM signatures in raw email."""
        details: List[str] = []
        headers, body = parse_raw_headers_and_body(raw_email)

        # Find DKIM-Signature header
        dkim_header_val = None
        dkim_header_orig_name = None
        for name, val in headers:
            if name.lower() == "dkim-signature":
                dkim_header_val = val
                dkim_header_orig_name = name
                break

        if not dkim_header_val:
            return DKIMResult(
                status="None",
                explanation="No DKIM-Signature header found in email",
                details=["Email does not contain DKIM-Signature"]
            )

        details.append("Found DKIM-Signature header")
        tags = parse_dkim_tags(dkim_header_val)

        # Check required tags: v, a, d, s, c, h, bh, b
        domain = tags.get("d")
        selector = tags.get("s")
        algorithm = tags.get("a", "rsa-sha256").lower()
        canon_setting = tags.get("c", "simple/simple").lower()
        h_tag = tags.get("h", "")
        bh_tag = tags.get("bh", "")
        b_tag = tags.get("b", "")

        if not domain or not selector or not bh_tag or not b_tag:
            return DKIMResult(
                status="PermError",
                domain=domain,
                selector=selector,
                explanation="Missing required DKIM tags (d, s, bh, or b)",
                details=details
            )

        if algorithm != "rsa-sha256":
            return DKIMResult(
                status="PermError",
                domain=domain,
                selector=selector,
                explanation=f"Unsupported DKIM algorithm: '{algorithm}' (only rsa-sha256 supported)",
                details=details
            )

        # Parse canonicalization (header/body)
        if "/" in canon_setting:
            c_header, c_body = canon_setting.split("/", 1)
        else:
            c_header, c_body = canon_setting, "simple"

        details.append(f"DKIM Selector: {selector}, Domain: {domain}, Canonicalization: {canon_setting}")

        # 1. Verify Body Hash (bh=)
        if c_body == "relaxed":
            canon_body = canonicalize_body_relaxed(body)
        else:
            canon_body = canonicalize_body_simple(body)

        computed_bh = base64.b64encode(hashlib.sha256(canon_body).digest()).decode('ascii')
        clean_expected_bh = re.sub(r'\s+', '', bh_tag)

        body_hash_match = (computed_bh == clean_expected_bh)
        if not body_hash_match:
            details.append(f"Body hash mismatch! Computed: {computed_bh}, Expected: {clean_expected_bh}")
            return DKIMResult(
                status="Fail",
                domain=domain,
                selector=selector,
                canonicalization=canon_setting,
                signed_headers=h_tag.split(":"),
                body_hash_match=False,
                signature_match=False,
                explanation="DKIM body hash does not match computed body content (possible tampering)",
                details=details
            )

        details.append("DKIM Body hash verification: PASSED")

        # 2. Fetch Public Key from DNS
        dns_record = self.dns.get_dkim_record(selector, domain)
        if not dns_record:
            details.append(f"DNS lookup failed for {selector}._domainkey.{domain}")
            return DKIMResult(
                status="PermError",
                domain=domain,
                selector=selector,
                canonicalization=canon_setting,
                signed_headers=h_tag.split(":"),
                body_hash_match=True,
                signature_match=False,
                explanation=f"No public key record found at DNS: {selector}._domainkey.{domain}",
                details=details
            )

        details.append(f"Retrieved DKIM DNS record: {dns_record}")
        dns_tags = parse_dkim_tags(dns_record)
        p_val = dns_tags.get("p")
        if not p_val:
            return DKIMResult(
                status="PermError",
                domain=domain,
                selector=selector,
                canonicalization=canon_setting,
                dns_record=dns_record,
                explanation="DKIM DNS record missing 'p=' public key tag (revoked or invalid)",
                details=details
            )

        try:
            pub_key = import_public_key_der_or_b64(p_val)
        except Exception as e:
            return DKIMResult(
                status="PermError",
                domain=domain,
                selector=selector,
                dns_record=dns_record,
                explanation=f"Failed to parse public key from DNS: {e}",
                details=details
            )

        # 3. Canonicalize signed headers
        signed_header_names = [h.strip() for h in h_tag.split(":") if h.strip()]
        headers_by_name: Dict[str, List[str]] = {}
        for name, val in headers:
            headers_by_name.setdefault(name.lower(), []).append((name, val))

        canonicalized_lines = []
        for h_name in signed_header_names:
            list_for_name = headers_by_name.get(h_name.lower())
            if list_for_name:
                orig_name, val = list_for_name.pop()  # RFC: take bottom-up if multiple
                if c_header == "relaxed":
                    canonicalized_lines.append(canonicalize_header_relaxed(orig_name, val))
                else:
                    canonicalized_lines.append(canonicalize_header_simple(orig_name, val))

        # Reconstruct DKIM-Signature header with empty b=
        # Strip the b= value from original header
        cleaned_dkim_val = re.sub(r'b=[a-zA-Z0-9+/=\s]+', 'b=', dkim_header_val)
        if c_header == "relaxed":
            canonicalized_lines.append(canonicalize_header_relaxed(dkim_header_orig_name, cleaned_dkim_val))
        else:
            canonicalized_lines.append(canonicalize_header_simple(dkim_header_orig_name, cleaned_dkim_val))

        verify_payload = "\r\n".join(canonicalized_lines).encode("utf-8")

        # 4. Verify RSA Signature
        clean_sig_b64 = re.sub(r'\s+', '', b_tag)
        try:
            sig_bytes = base64.b64decode(clean_sig_b64)
            sig_valid = rsa_verify_sha256(verify_payload, sig_bytes, pub_key)
        except Exception as e:
            details.append(f"Signature decoding error: {e}")
            sig_valid = False

        if not sig_valid:
            details.append("RSA signature verification failed against header payload")
            return DKIMResult(
                status="Fail",
                domain=domain,
                selector=selector,
                canonicalization=canon_setting,
                signed_headers=signed_header_names,
                body_hash_match=True,
                signature_match=False,
                dns_record=dns_record,
                explanation="DKIM RSA digital signature verification failed (header tampering or key mismatch)",
                details=details
            )

        details.append("DKIM RSA digital signature verification: PASSED")
        return DKIMResult(
            status="Pass",
            domain=domain,
            selector=selector,
            canonicalization=canon_setting,
            signed_headers=signed_header_names,
            body_hash_match=True,
            signature_match=True,
            dns_record=dns_record,
            explanation=f"Valid DKIM signature from domain '{domain}' using selector '{selector}'",
            details=details
        )
