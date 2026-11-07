# Secure Email Authentication Gateway (SPF, DKIM, and DMARC)

A complete, production-grade security gateway implementation for email authentication, header analysis, cryptographic key management, and anti-spoofing defense.

Compliant with:
- **RFC 7208**: Sender Policy Framework (SPF)
- **RFC 6376**: DomainKeys Identified Mail (DKIM)
- **RFC 7489**: Domain-based Message Authentication, Reporting, and Conformance (DMARC)
- **RFC 7601 / RFC 8601**: Enhanced Email Authentication-Results Headers

---

## Architecture Overview

```
                                      Incoming Email Message
                                                │
                                                ▼
                                    ┌───────────────────────┐
                                    │     Email Parser      │
                                    │ (RFC 5322 Extractor)  │
                                    └───────────┬───────────┘
                                                │
                    ┌───────────────────────────┼───────────────────────────┐
                    ▼                           ▼                           ▼
        ┌───────────────────────┐   ┌───────────────────────┐   ┌───────────────────────┐
        │     SPF Validator     │   │     DKIM Verifier     │   │      DNS Resolver     │
        │      (RFC 7208)       │   │      (RFC 6376)       │   │  (Mock Zone & Live)   │
        └───────────┬───────────┘   └───────────┬───────────┘   └───────────┬───────────┘
                    │                           │                           │
                    │   Client IP vs CIDR       │   RSA SHA-256 Sig Check   │   TXT / A / MX Records
                    │   + Mechanism Match       │   + Body Hash (bh=) Match │   _dmarc.<domain>
                    │                           │                           │
                    └───────────────────────────┼───────────────────────────┘
                                                │
                                                ▼
                                    ┌───────────────────────┐
                                    │    DMARC Evaluator    │
                                    │      (RFC 7489)       │
                                    └───────────┬───────────┘
                                                │
                     Identifier Alignment Check │ (Header From vs SPF / DKIM Domain)
                     Evaluate Published Policy  │ (p=none | quarantine | reject)
                                                │
                                                ▼
                                    ┌───────────────────────┐
                                    │  Gateway Decision &   │
                                    │   Threat Assessment   │
                                    └───────────┬───────────┘
                                                │
                    ┌───────────────────────────┴───────────────────────────┐
                    ▼                                                       ▼
        ┌───────────────────────┐                               ┌───────────────────────┐
        │ Authentication-Header │                               │  Aggregate XML Report │
        │ (RFC 7601 / RFC 8601) │                               │      (RFC 7489 RUA)   │
        └───────────────────────┘                               └───────────────────────┘
```

---

## Features

1. **SPF Engine (RFC 7208)**:
   - Validates client IP against authorized CIDR ranges (`ip4:`, `ip6:`).
   - Evaluates `a`, `mx`, `include:`, `redirect=`, and `all` mechanisms.
   - Enforces qualifiers: `+` (Pass), `-` (Fail), `~` (SoftFail), `?` (Neutral).
   - Recursive include evaluation with loop detection and max lookup limits.

2. **DKIM Cryptographic Studio (RFC 6376)**:
   - Pure-Python RSA PKCS#1 v1.5 with SHA-256 signing and verification (zero external dependencies).
   - Generates 1024-bit and 2048-bit keypairs with PEM and DNS TXT export.
   - Header canonicalization: `relaxed` and `simple`.
   - Body canonicalization: `relaxed` and `simple`.
   - SHA-256 body hash calculation (`bh=`) with tamper detection.
   - Signs outgoing emails and prepends valid `DKIM-Signature:` header.

3. **DMARC Evaluator & Alignment Engine (RFC 7489)**:
   - Evaluates SPF alignment (strict `aspf=s` vs relaxed `aspf=r`).
   - Evaluates DKIM alignment (strict `adkim=s` vs relaxed `adkim=r`).
   - Supports 3-phase policy staging: `p=none` (Monitoring), `p=quarantine`, and `p=reject`.
   - Organizational domain extraction for subdomains.
   - Synthesizes RFC 7489 XML Aggregate Feedback Reports (RUA).

4. **Web-Based Security Dashboard**:
   - Modern cyber-security visual interface (Tailwind CSS).
   - Interactive header/message inspector with instant test scenario presets.
   - Real-time verdict banners, threat severity scoring, and actionable remediation steps.
   - DKIM Key Studio: generate keys, sign emails, and test them with one click.
   - Policy Staging Wizard and live DNS Zone Table editor.

5. **Command-Line Interface (`email_gateway_cli.py`)**:
   - Colorized terminal output with clear visual status flags.
   - Batch and single file verification, stdin support, keygen, and DNS record setup.

---

## Project Structure

```text
ed4/
├── gateway/
│   ├── crypto_utils.py          # Pure Python RSA keygen, DER/PEM encoder, PKCS#1 v1.5 SHA-256
│   ├── dns_manager.py           # DNS resolver & zone manager (simulated and live query)
│   ├── spf_validator.py         # RFC 7208 SPF syntax parser and IP authorization
│   ├── dkim_signer_verifier.py  # RFC 6376 DKIM canonicalization, body hash & RSA verification
│   ├── dmarc_evaluator.py       # RFC 7489 DMARC alignment, policy enforcement & XML RUA
│   ├── email_parser.py          # RFC 5322 header extractor & RFC 7601 header generator
│   └── gateway_controller.py    # Master inspection pipeline & threat assessment
├── web/
│   ├── app.py                   # Flask Web Server & REST API endpoints
│   └── templates/
│       └── index.html           # Modern single-page web dashboard
├── samples/
│   ├── legitimate_invoice.eml   # SPF Pass + DKIM Pass + DMARC Pass (example.com)
│   ├── spoofed_ceo_fraud.eml    # Attacker IP spoofing trustedbank.com (DMARC Reject)
│   ├── tampered_dkim_transfer.eml # MITM altered body wire fraud (DKIM Body Hash Fail)
│   ├── dmarc_monitoring_marketing.eml # startup.io in Phase 1 (p=none)
│   ├── quarantine_hr_notice.eml # securecorp.org in Phase 2 (p=quarantine)
│   └── seed_samples.py          # Generator script for test keys and samples
├── tests/
│   ├── test_spf.py              # Unit tests for SPF mechanisms & CIDR
│   ├── test_dkim.py             # Unit tests for canonicalization, hashing & signatures
│   ├── test_dmarc.py            # Unit tests for identifier alignment & policies
│   └── test_gateway.py          # Integration tests for end-to-end inspection
├── email_gateway_cli.py         # CLI tool for verification, keygen, signing & DNS setup
├── run_gateway_web.py           # Launcher for Flask web dashboard
├── launch_web.bat               # Windows batch launcher for web dashboard
├── run_tests.bat                # Windows batch launcher for test suite
└── DNS_CONFIGURATION_GUIDE.md   # Production DNS deployment manual
```

---

## Quick Start & Usage

### 1. Launch the Web Dashboard
```bash
python run_gateway_web.py
```
Open **`http://127.0.0.1:5000`** in your browser.
- Select test scenarios to observe real-time detection of legitimate emails, spoofed emails, and tampered messages.
- Use the **DKIM Key Studio** to generate keys and sign outgoing emails.
- View and edit active records in the **DNS Zone** tab.

### 2. Command-Line Interface (CLI)

#### Run Automated Test Suite
```bash
python email_gateway_cli.py test-suite
```

#### Inspect an Email File
```bash
python email_gateway_cli.py inspect-file samples/legitimate_invoice.eml
python email_gateway_cli.py inspect-file samples/spoofed_ceo_fraud.eml
```

#### Inspect Raw Header Text from CLI
```bash
python email_gateway_cli.py inspect-header --header "From: ceo@trustedbank.com\r\nSubject: Wire\r\n" --ip 203.0.113.88
```

#### Generate a New 2048-bit RSA DKIM Keypair & DNS Record
```bash
python email_gateway_cli.py keygen --domain mydomain.com --selector mail2026 --bits 2048
```

#### Sign an Outgoing Email with DKIM
```bash
python email_gateway_cli.py sign --email draft.eml --domain mydomain.com --selector mail2026 --key mail2026_mydomain_com.key
```

#### Generate DNS Staging Records for a Domain
```bash
python email_gateway_cli.py dns-setup --domain mycorp.com --ips 198.51.100.10,198.51.100.11 --policy reject
```

### 3. Run Automated Unit & Integration Tests
```bash
pytest -v tests/
```
All 24 test cases covering SPF, DKIM, DMARC, alignment, and full gateway workflows execute and pass in under 1 second.
