#!/usr/bin/env python3
"""
Secure Email Authentication Gateway CLI.
Inspects email headers/messages, generates DKIM cryptographic keys, signs outgoing mail,
and configures SPF, DKIM, and DMARC staging policies.
"""

import argparse
import json
import os
import sys

# Ensure local imports work
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from gateway.crypto_utils import generate_rsa_key, import_private_key_pem
from gateway.dns_manager import dns_manager
from gateway.gateway_controller import EmailGateway
from gateway.dkim_signer_verifier import DKIMSigner


# ANSI Color formatting
class Colors:
    RESET = "\033[0m"
    BOLD = "\033[1m"
    GREEN = "\033[92m"
    RED = "\033[91m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    CYAN = "\033[96m"
    GRAY = "\033[90m"
    BG_RED = "\033[41m\033[97m"
    BG_GREEN = "\033[42m\033[97m"
    BG_YELLOW = "\033[43m\033[30m"


def print_banner():
    banner = f"""{Colors.CYAN}{Colors.BOLD}
========================================================================
    SECURE EMAIL AUTHENTICATION GATEWAY (SPF | DKIM | DMARC)
========================================================================{Colors.RESET}"""
    print(banner)


def format_status(status: str) -> str:
    s = status.upper()
    if s in ("PASS", "CLEAN"):
        return f"{Colors.GREEN}{Colors.BOLD}[PASS]{Colors.RESET}"
    elif s in ("FAIL", "REJECT", "CRITICAL"):
        return f"{Colors.RED}{Colors.BOLD}[{s}]{Colors.RESET}"
    elif s in ("QUARANTINE", "HIGH"):
        return f"{Colors.YELLOW}{Colors.BOLD}[{s}]{Colors.RESET}"
    elif s in ("SOFTFAIL", "NEUTRAL", "MONITOR", "MEDIUM"):
        return f"{Colors.YELLOW}{s}{Colors.RESET}"
    else:
        return f"{Colors.GRAY}{s}{Colors.RESET}"


def display_inspection(res_dict: dict, format_json: bool = False):
    if format_json:
        print(json.dumps(res_dict, indent=2))
        return

    print_banner()

    verdict = res_dict["security_verdict"]
    threat = res_dict["threat_level"]
    verdict_badge = (
        f"{Colors.BG_GREEN} VERDICT: {verdict} {Colors.RESET}"
        if verdict == "PASS"
        else f"{Colors.BG_RED} VERDICT: {verdict} {Colors.RESET}"
        if verdict == "REJECT"
        else f"{Colors.BG_YELLOW} VERDICT: {verdict} {Colors.RESET}"
    )

    print(f"\n{verdict_badge}  Threat Level: {format_status(threat)}")
    print(f"{Colors.BOLD}Summary:{Colors.RESET} {res_dict['threat_summary']}")
    print(f"{Colors.BOLD}Recommended Action:{Colors.RESET} {res_dict['recommended_action']}\n")

    # Message Headers Section
    hdr = res_dict["parsed_headers"]
    print(f"{Colors.CYAN}{Colors.BOLD}[1] PARSED MESSAGE HEADERS:{Colors.RESET}")
    print(f"  * From:             {hdr.get('from', '')}")
    print(f"  * Return-Path:      {hdr.get('return_path') or '(none)'}")
    print(f"  * Subject:          {hdr.get('subject', '')}")
    print(f"  * Client IP:        {hdr.get('effective_client_ip', '')} (Origin: {'Header Extracted' if hdr.get('extracted_client_ip') else 'Manual / Default'})")
    print(f"  * Message ID:       {hdr.get('message_id', '')}")

    # SPF Section
    spf = res_dict["spf"]
    print(f"\n{Colors.CYAN}{Colors.BOLD}[2] SENDER POLICY FRAMEWORK (SPF) - RFC 7208:{Colors.RESET}")
    print(f"  * Status:           {format_status(spf.get('status', ''))}")
    print(f"  * Evaluated Domain: {spf.get('domain', '')}")
    print(f"  * Client IP Tested: {spf.get('client_ip', '')}")
    print(f"  * Matched Rule:     {spf.get('matched_mechanism') or 'None'}")
    print(f"  * SPF DNS Record:   {spf.get('record') or '(No record found)'}")
    print(f"  * Explanation:      {spf.get('explanation', '')}")

    # DKIM Section
    dkim = res_dict["dkim"]
    print(f"\n{Colors.CYAN}{Colors.BOLD}[3] DOMAINKEYS IDENTIFIED MAIL (DKIM) - RFC 6376:{Colors.RESET}")
    print(f"  * Status:           {format_status(dkim.get('status', ''))}")
    print(f"  * Signing Domain:   {dkim.get('domain') or '(none)'}")
    print(f"  * Key Selector:     {dkim.get('selector') or '(none)'}")
    print(f"  * Canonicalization: {dkim.get('canonicalization') or 'N/A'}")
    print(f"  * Body Hash Match:  {'YES (Integrity Valid)' if dkim.get('body_hash_match') else 'NO / MISMATCH'}")
    print(f"  * RSA Sig Valid:    {'YES (Cryptographically Valid)' if dkim.get('signature_match') else 'NO / INVALID'}")
    print(f"  * Explanation:      {dkim.get('explanation', '')}")

    # DMARC Section
    dmarc = res_dict["dmarc"]
    print(f"\n{Colors.CYAN}{Colors.BOLD}[4] DMARC POLICY & ALIGNMENT - RFC 7489:{Colors.RESET}")
    print(f"  * Status:           {format_status(dmarc.get('status', ''))}")
    print(f"  * Published Policy: {dmarc.get('published_policy', '').upper()} (Enforced Disposition: {dmarc.get('disposition', '').upper()})")
    print(f"  * SPF Alignment:    {'ALIGNED (Pass)' if dmarc.get('spf_aligned') else 'UNALIGNED (Fail)'} [aspf={dmarc.get('aspf', 'r')}]")
    print(f"  * DKIM Alignment:   {'ALIGNED (Pass)' if dmarc.get('dkim_aligned') else 'UNALIGNED (Fail)'} [adkim={dmarc.get('adkim', 'r')}]")
    print(f"  * Reporting (RUA):  {dmarc.get('rua') or '(none)'}")
    print(f"  * Explanation:      {dmarc.get('explanation', '')}")

    # Authentication-Results Header
    print(f"\n{Colors.CYAN}{Colors.BOLD}[5] GENERATED RFC 7601 / RFC 8601 HEADER:{Colors.RESET}")
    print(f"{Colors.GRAY}{res_dict['auth_results_header']}{Colors.RESET}")
    print("=" * 72 + "\n")


def cmd_inspect_file(args):
    if not os.path.exists(args.file):
        print(f"{Colors.RED}Error: File '{args.file}' not found.{Colors.RESET}")
        sys.exit(1)

    with open(args.file, "r", encoding="utf-8", errors="replace") as f:
        content = f.read()

    gw = EmailGateway()
    res = gw.inspect(content, client_ip=args.ip, envelope_from=args.mail_from)
    display_inspection(res.to_dict(), format_json=args.json)


def cmd_inspect_header(args):
    if args.header:
        content = args.header
    else:
        print("Reading raw email/header from standard input (Ctrl+D / Ctrl+Z to finish):")
        content = sys.stdin.read()

    gw = EmailGateway()
    res = gw.inspect(content, client_ip=args.ip, envelope_from=args.mail_from)
    display_inspection(res.to_dict(), format_json=args.json)


def cmd_keygen(args):
    print_banner()
    print(f"{Colors.BOLD}Generating {args.bits}-bit RSA DKIM Keypair for domain '{args.domain}' (selector: '{args.selector}')...{Colors.RESET}")
    key = generate_rsa_key(args.bits)

    priv_file = args.out or f"{args.selector}_{args.domain.replace('.', '_')}.key"
    pub_file = f"{args.selector}_{args.domain.replace('.', '_')}.pub"

    with open(priv_file, "w", encoding="utf-8") as f:
        f.write(key.to_private_pem())

    with open(pub_file, "w", encoding="utf-8") as f:
        f.write(key.to_public_pem())

    dns_val = key.to_dkim_dns_value()
    dns_rr_name = f"{args.selector}._domainkey.{args.domain}"

    # Auto-publish in mock DNS store
    dns_manager.add_record(dns_rr_name, "TXT", dns_val)

    print(f"{Colors.GREEN}Successfully generated RSA keypair!{Colors.RESET}")
    print(f"  • Private Key saved to:  {priv_file}")
    print(f"  • Public Key saved to:   {pub_file}")
    print(f"\n{Colors.CYAN}{Colors.BOLD}DNS TXT Resource Record to Publish:{Colors.RESET}")
    print(f"  {Colors.BOLD}Host / Name:{Colors.RESET}   {dns_rr_name}.")
    print(f"  {Colors.BOLD}Record Type:{Colors.RESET}   TXT")
    print(f"  {Colors.BOLD}Record Value:{Colors.RESET}  \"{dns_val}\"")
    print(f"\n{Colors.GRAY}(This record has also been loaded into the gateway DNS resolver){Colors.RESET}\n")


def cmd_sign(args):
    if not os.path.exists(args.email):
        print(f"{Colors.RED}Error: Email file '{args.email}' not found.{Colors.RESET}")
        sys.exit(1)
    if not os.path.exists(args.key):
        print(f"{Colors.RED}Error: Private key file '{args.key}' not found.{Colors.RESET}")
        sys.exit(1)

    with open(args.email, "r", encoding="utf-8") as f:
        raw_msg = f.read()

    with open(args.key, "r", encoding="utf-8") as f:
        priv_pem = f.read()

    key = import_private_key_pem(priv_pem)
    signer = DKIMSigner(selector=args.selector, domain=args.domain, private_key=key)
    signed_email = signer.sign(raw_msg, canonicalization=args.canon)

    out_path = args.out or (args.email + ".signed.eml")
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(signed_email)

    print(f"{Colors.GREEN}Email signed successfully! Saved to: {out_path}{Colors.RESET}")


def cmd_dns_setup(args):
    print_banner()
    domain = args.domain.lower().strip()
    ips = [ip.strip() for ip in args.ips.split(",") if ip.strip()]

    # 1. SPF Record
    ip_terms = " ".join([f"ip4:{ip}" for ip in ips])
    spf_rec = f"v=spf1 {ip_terms} -all"

    # 2. DMARC Staging Records
    rua = f"mailto:dmarc-rua@{domain}"
    ruf = f"mailto:dmarc-ruf@{domain}"

    dmarc_none = f"v=DMARC1; p=none; sp=none; pct=100; rua={rua}; ruf={ruf}; adkim=r; aspf=r"
    dmarc_quar = f"v=DMARC1; p=quarantine; sp=quarantine; pct=100; rua={rua}; ruf={ruf}; adkim=r; aspf=r"
    dmarc_reject = f"v=DMARC1; p=reject; sp=reject; pct=100; rua={rua}; ruf={ruf}; adkim=r; aspf=r"

    selected_dmarc = {
        "none": dmarc_none,
        "quarantine": dmarc_quar,
        "reject": dmarc_reject
    }.get(args.policy.lower(), dmarc_none)

    # Save to DNS manager
    dns_manager.set_record(domain, "TXT", [spf_rec])
    dns_manager.set_record(f"_dmarc.{domain}", "TXT", [selected_dmarc])

    print(f"{Colors.CYAN}{Colors.BOLD}RECOMMENDED DNS RECORDS FOR '{domain}':{Colors.RESET}\n")

    print(f"{Colors.BOLD}1. SPF Record (Authorized Sending IPs):{Colors.RESET}")
    print(f"   Name:   {domain}.")
    print(f"   Type:   TXT")
    print(f"   Value:  \"{spf_rec}\"\n")

    print(f"{Colors.BOLD}2. DMARC Phased Deployment Sequence:{Colors.RESET}")
    print(f"   Name:   _dmarc.{domain}.")
    print(f"   Type:   TXT")
    print(f"   {Colors.YELLOW}Phase 1 (Monitoring - Active Now):{Colors.RESET}")
    print(f"     \"{dmarc_none}\"")
    print(f"   {Colors.YELLOW}Phase 2 (Quarantine):{Colors.RESET}")
    print(f"     \"{dmarc_quar}\"")
    print(f"   {Colors.GREEN}Phase 3 (Full Rejection / Enforcement):{Colors.RESET}")
    print(f"     \"{dmarc_reject}\"\n")

    print(f"{Colors.GREEN}Active DNS configured in Gateway with policy: {args.policy.upper()}{Colors.RESET}\n")


def cmd_test_suite(args):
    print_banner()
    print(f"{Colors.BOLD}Executing Comprehensive Authentication Gateway Test Suite...{Colors.RESET}\n")
    samples_dir = os.path.join(os.path.dirname(__file__), "samples")

    tests = [
        ("Legitimate Corporate Invoice (SPF + DKIM + DMARC Pass)", "legitimate_invoice.eml", "PASS"),
        ("Spoofed CEO Wire Fraud (Attacker IP, DMARC Reject)", "spoofed_ceo_fraud.eml", "REJECT"),
        ("Tampered In-Transit Wire Transfer (Body Altered)", "tampered_dkim_transfer.eml", "REJECT"),
        ("Monitoring Phase Newsletter (startup.io p=none)", "dmarc_monitoring_marketing.eml", "MONITOR"),
        ("Quarantine HR Notice (securecorp.org p=quarantine)", "quarantine_hr_notice.eml", "QUARANTINE"),
    ]

    gw = EmailGateway()
    passed = 0

    for name, filename, expected_verdict in tests:
        filepath = os.path.join(samples_dir, filename)
        if not os.path.exists(filepath):
            print(f"  {Colors.RED}File not found: {filename}{Colors.RESET}")
            continue

        with open(filepath, "r", encoding="utf-8") as f:
            content = f.read()

        res = gw.inspect(content)
        verdict = res.security_verdict
        match = (verdict == expected_verdict)
        if match:
            passed += 1
            status_tag = f"{Colors.GREEN}[PASS]{Colors.RESET}"
        else:
            status_tag = f"{Colors.RED}[FAIL - Got {verdict}, expected {expected_verdict}]{Colors.RESET}"

        print(f"  {status_tag} {name}")
        print(f"         SPF: {res.spf['status']} | DKIM: {res.dkim['status']} | DMARC: {res.dmarc['status']} -> {verdict}")

    print(f"\n{Colors.BOLD}Results:{Colors.RESET} {passed}/{len(tests)} scenarios passed successfully!\n")


def main():
    parser = argparse.ArgumentParser(
        description="Secure Email Authentication Gateway (SPF, DKIM, DMARC)",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    subparsers = parser.add_subparsers(dest="command", help="Gateway Subcommand")

    # Command: inspect-file
    p_file = subparsers.add_parser("inspect-file", help="Inspect raw .eml message or header file")
    p_file.add_argument("file", help="Path to raw email or header file")
    p_file.add_argument("--ip", help="Client IP address override")
    p_file.add_argument("--mail-from", help="Envelope Return-Path / Mail-From override")
    p_file.add_argument("--json", action="store_true", help="Output raw JSON results")

    # Command: inspect-header
    p_hdr = subparsers.add_parser("inspect-header", help="Inspect raw header text directly")
    p_hdr.add_argument("--header", help="Raw header text string (or read from stdin)")
    p_hdr.add_argument("--ip", help="Client IP address")
    p_hdr.add_argument("--mail-from", help="Envelope Return-Path / Mail-From")
    p_hdr.add_argument("--json", action="store_true", help="Output raw JSON results")

    # Command: keygen
    p_key = subparsers.add_parser("keygen", help="Generate RSA DKIM keypair and DNS TXT record")
    p_key.add_argument("--domain", required=True, help="Domain name (e.g. example.com)")
    p_key.add_argument("--selector", default="default", help="DKIM selector (default: default)")
    p_key.add_argument("--bits", type=int, default=2048, choices=[1024, 2048], help="Key bit size (1024 or 2048)")
    p_key.add_argument("--out", help="Path to save private key file")

    # Command: sign
    p_sign = subparsers.add_parser("sign", help="Sign outgoing email with DKIM private key")
    p_sign.add_argument("--email", required=True, help="Path to raw email file to sign")
    p_sign.add_argument("--domain", required=True, help="Signing domain (d=)")
    p_sign.add_argument("--selector", required=True, help="DKIM selector (s=)")
    p_sign.add_argument("--key", required=True, help="Path to RSA private key PEM file")
    p_sign.add_argument("--canon", default="relaxed/relaxed", help="Canonicalization (relaxed/relaxed, simple/simple)")
    p_sign.add_argument("--out", help="Path to save signed email")

    # Command: dns-setup
    p_dns = subparsers.add_parser("dns-setup", help="Generate SPF, DKIM, and DMARC DNS records")
    p_dns.add_argument("--domain", required=True, help="Domain name")
    p_dns.add_argument("--ips", required=True, help="Comma-separated authorized IPv4 addresses")
    p_dns.add_argument("--policy", default="none", choices=["none", "quarantine", "reject"], help="DMARC policy")

    # Command: test-suite
    subparsers.add_parser("test-suite", help="Run automated test suite across all sample attack/legit scenarios")

    args = parser.parse_args()
    if not args.command:
        parser.print_help()
        sys.exit(0)

    if args.command == "inspect-file":
        cmd_inspect_file(args)
    elif args.command == "inspect-header":
        cmd_inspect_header(args)
    elif args.command == "keygen":
        cmd_keygen(args)
    elif args.command == "sign":
        cmd_sign(args)
    elif args.command == "dns-setup":
        cmd_dns_setup(args)
    elif args.command == "test-suite":
        cmd_test_suite(args)


if __name__ == "__main__":
    main()
