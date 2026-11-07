# DNS Configuration Guide: SPF, DKIM, and DMARC Deployment

This guide provides practical instructions for configuring SPF, DKIM, and DMARC DNS records in production nameservers (Cloudflare, AWS Route 53, Google Cloud DNS, BIND9, etc.).

---

## 1. Sender Policy Framework (SPF) — RFC 7208

### Objective
Specify which IP addresses, networks, and mail exchangers are authorized to send email on behalf of your domain (`MAIL FROM` / envelope sender).

### Syntax & Mechanism Reference
| Mechanism | Description | Example |
| :--- | :--- | :--- |
| `v=spf1` | Required SPF version identifier | Must be at the start of the record |
| `ip4:<ip/cidr>` | Authorizes specific IPv4 address or CIDR range | `ip4:198.51.100.25` or `ip4:198.51.100.0/24` |
| `ip6:<ip/cidr>` | Authorizes IPv6 address or CIDR range | `ip6:2001:db8::/32` |
| `include:<domain>` | Recursively evaluates authorized SPF for third-party services | `include:_spf.google.com` |
| `mx` | Authorizes the IP addresses of the domain's MX servers | `mx` |
| `a` | Authorizes the domain's A record IP | `a` |
| `~all` | **SoftFail**: Transition qualifier; unlisted IPs are marked as suspicious | Used during testing / onboarding |
| `-all` | **Fail**: Strict qualifier; unlisted IPs are explicitly unauthorized | Recommended for full production enforcement |

### Production DNS Record Example
* **Host / Name**: `@` or `example.com.`
* **Type**: `TXT`
* **TTL**: `3600`
* **Value**:
  ```text
  v=spf1 ip4:198.51.100.0/24 include:_spf.google.com -all
  ```

---

## 2. DomainKeys Identified Mail (DKIM) — RFC 6376

### Objective
Provide cryptographic proof that the message originated from the claiming domain and that its body and critical headers were not tampered with in transit.

### Step 1: Generate RSA 2048-bit Keypair
Using the built-in Gateway CLI:
```bash
python email_gateway_cli.py keygen --domain example.com --selector default --bits 2048
```
Or using OpenSSL:
```bash
# 1. Generate private key
openssl genrsa -out dkim_default.key 2048

# 2. Extract public key in SubjectPublicKeyInfo DER format
openssl rsa -in dkim_default.key -pubout -outform DER | openssl base64 -A > dkim_default.pub.b64
```

### Step 2: Publish Public Key in DNS
* **Host / Name**: `<selector>._domainkey.<domain>.` (e.g., `default._domainkey.example.com.`)
* **Type**: `TXT`
* **TTL**: `3600`
* **Value**:
  ```text
  v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA...IDAQAB
  ```

### Step 3: Outgoing Email Signing
The outgoing Mail Transfer Agent (MTA) hashes the canonicalized body (`bh=`) and computes an RSA PKCS#1 v1.5 SHA-256 digital signature (`b=`) across selected headers (`From`, `To`, `Subject`, `Date`, `Message-ID`).

---

## 3. Domain-based Message Authentication, Reporting, and Conformance (DMARC) — RFC 7489

### Objective
Link SPF and DKIM authentication to the visible RFC 5322 `From:` header, enforce domain owner policies on unauthenticated emails, and collect XML aggregate feedback reports (RUA).

### DMARC Identifier Alignment
DMARC requires that either SPF or DKIM passes **and** aligns with the `From:` header:
1. **SPF Alignment**: The RFC 5321 `MAIL FROM` (envelope Return-Path) domain must match the `From:` domain.
   - `aspf=r` (Relaxed, default): Organizational domains must match (e.g., `bounce.example.com` aligns with `example.com`).
   - `aspf=s` (Strict): FQDNs must match exactly.
2. **DKIM Alignment**: The DKIM signature's `d=` tag must match the `From:` domain.
   - `adkim=r` (Relaxed, default): Organizational domains must match.
   - `adkim=s` (Strict): FQDNs must match exactly.

---

## 4. Recommended 3-Stage DMARC Deployment Strategy

To prevent accidental disruption of legitimate corporate email, organizations should deploy DMARC in three progressive phases:

### Phase 1: Monitoring & Discovery (`p=none`)
```text
Host:  _dmarc.example.com.
Type:  TXT
Value: v=DMARC1; p=none; sp=none; pct=100; rua=mailto:dmarc-rua@example.com; ruf=mailto:dmarc-ruf@example.com; adkim=r; aspf=r;
```
* **Duration**: 2 to 4 weeks.
* **Behavior**: No emails are blocked. Receiving gateways parse headers and send daily XML aggregate reports (`rua=`) detailing all sending IPs.
* **Action**: Identify legitimate third-party services (marketing, CRM, payroll) and update SPF includes and DKIM keys.

### Phase 2: Quarantine & Soft Enforcement (`p=quarantine`)
```text
Host:  _dmarc.example.com.
Type:  TXT
Value: v=DMARC1; p=quarantine; sp=quarantine; pct=100; rua=mailto:dmarc-rua@example.com; ruf=mailto:dmarc-ruf@example.com; adkim=r; aspf=r;
```
* **Duration**: 2 to 3 weeks.
* **Behavior**: Emails failing DMARC authentication and alignment are redirected to Spam/Junk folders or held in quarantine.
* **Action**: Verify that zero legitimate business emails are quarantined.

### Phase 3: Full Rejection & Anti-Spoofing Immunity (`p=reject`)
```text
Host:  _dmarc.example.com.
Type:  TXT
Value: v=DMARC1; p=reject; sp=reject; pct=100; rua=mailto:dmarc-rua@example.com; ruf=mailto:dmarc-ruf@example.com; adkim=r; aspf=r;
```
* **Duration**: Permanent production policy.
* **Behavior**: Receiving MTAs reject unauthorized spoofed emails directly at the SMTP handshake before user delivery.
* **Result**: Complete domain brand protection and cryptographic defense against phishing.
