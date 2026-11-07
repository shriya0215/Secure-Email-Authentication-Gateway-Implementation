"""
Flask Web Application for the Secure Email Authentication Gateway.
Provides interactive UI and REST API for email header analysis, DKIM key generation,
outgoing email signing, and SPF/DKIM/DMARC policy management.
"""

import json
import os
import sys

# Ensure local imports work
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from flask import Flask, jsonify, render_template, request
from gateway.crypto_utils import generate_rsa_key, import_private_key_pem
from gateway.dkim_signer_verifier import DKIMSigner
from gateway.dns_manager import dns_manager
from gateway.gateway_controller import EmailGateway

app = Flask(__name__, template_folder="templates", static_folder="static")
gateway = EmailGateway(dns_manager)

SAMPLES_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "samples")


def load_sample(filename: str) -> str:
    path = os.path.join(SAMPLES_DIR, filename)
    if os.path.exists(path):
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            return f.read()
    return ""


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/inspect", methods=["POST"])
def api_inspect():
    data = request.get_json(force=True) or {}
    raw_email = data.get("raw_email", "")
    client_ip = data.get("client_ip") or None
    envelope_from = data.get("envelope_from") or None

    if not raw_email.strip():
        return jsonify({"error": "Raw email content or headers required"}), 400

    result = gateway.inspect(raw_email, client_ip=client_ip, envelope_from=envelope_from)
    return jsonify(result.to_dict())


@app.route("/api/scenarios", methods=["GET"])
def api_scenarios():
    scenarios = [
        {
            "id": "legit",
            "name": "1. Legitimate Corporate Invoice (Clean Pass)",
            "description": "Authentic email from example.com with valid SPF authorized IP, cryptographically valid DKIM signature, and full DMARC alignment.",
            "expected_verdict": "PASS",
            "threat_level": "CLEAN",
            "raw_email": load_sample("legitimate_invoice.eml")
        },
        {
            "id": "spoof_ceo",
            "name": "2. Spoofed CEO Wire Fraud (Attacker Spoofing trustedbank.com)",
            "description": "Phishing attack forging Header From ceo@trustedbank.com originating from malicious server 203.0.113.88. DMARC policy enforces immediate rejection.",
            "expected_verdict": "REJECT",
            "threat_level": "CRITICAL",
            "raw_email": load_sample("spoofed_ceo_fraud.eml")
        },
        {
            "id": "tampered",
            "name": "3. Tampered Wire Transfer (In-Transit Body Modification)",
            "description": "Valid DKIM signature originally applied, but wire transfer bank details were modified in-transit. Body hash check fails.",
            "expected_verdict": "REJECT",
            "threat_level": "CRITICAL",
            "raw_email": load_sample("tampered_dkim_transfer.eml")
        },
        {
            "id": "monitoring",
            "name": "4. DMARC Monitoring Phase 1 (startup.io p=none)",
            "description": "Marketing newsletter sent via unaligned relay while organization is in DMARC monitoring mode (p=none). Delivered with telemetry logging.",
            "expected_verdict": "MONITOR",
            "threat_level": "MEDIUM",
            "raw_email": load_sample("dmarc_monitoring_marketing.eml")
        },
        {
            "id": "quarantine",
            "name": "5. DMARC Quarantine Phase 2 (securecorp.org p=quarantine)",
            "description": "Unauthenticated email sent to employee. Domain policy specifies p=quarantine, diverting message to spam folder.",
            "expected_verdict": "QUARANTINE",
            "threat_level": "HIGH",
            "raw_email": load_sample("quarantine_hr_notice.eml")
        }
    ]
    return jsonify(scenarios)


@app.route("/api/keygen", methods=["POST"])
def api_keygen():
    data = request.get_json(force=True) or {}
    domain = data.get("domain", "example.com").strip().lower()
    selector = data.get("selector", "default").strip()
    bits = int(data.get("bits", 2048))

    key = generate_rsa_key(bits)
    priv_pem = key.to_private_pem()
    pub_pem = key.to_public_pem()
    dns_val = key.to_dkim_dns_value()
    dns_rr_name = f"{selector}._domainkey.{domain}"

    # Auto-publish in mock DNS zone
    dns_manager.set_record(dns_rr_name, "TXT", [dns_val])

    return jsonify({
        "domain": domain,
        "selector": selector,
        "bits": bits,
        "private_key_pem": priv_pem,
        "public_key_pem": pub_pem,
        "dns_record_name": dns_rr_name,
        "dns_record_type": "TXT",
        "dns_record_value": dns_val
    })


@app.route("/api/sign", methods=["POST"])
def api_sign():
    data = request.get_json(force=True) or {}
    raw_email = data.get("raw_email", "")
    domain = data.get("domain", "example.com").strip().lower()
    selector = data.get("selector", "default").strip()
    priv_key_pem = data.get("private_key_pem", "")
    canon = data.get("canonicalization", "relaxed/relaxed")

    if not raw_email:
        return jsonify({"error": "Raw email content required"}), 400
    if not priv_key_pem:
        return jsonify({"error": "Private key PEM required"}), 400

    try:
        key = import_private_key_pem(priv_key_pem)
        signer = DKIMSigner(selector=selector, domain=domain, private_key=key)
        signed = signer.sign(raw_email, canonicalization=canon)
        return jsonify({"signed_email": signed})
    except Exception as e:
        return jsonify({"error": f"Signing failed: {str(e)}"}), 500


@app.route("/api/dns", methods=["GET", "POST"])
def api_dns():
    if request.method == "GET":
        return jsonify(dns_manager.records)

    data = request.get_json(force=True) or {}
    domain = data.get("domain", "").strip().lower()
    rtype = data.get("type", "TXT").strip().upper()
    value = data.get("value", "").strip()

    if not domain or not value:
        return jsonify({"error": "domain and value required"}), 400

    dns_manager.add_record(domain, rtype, value)
    return jsonify({"success": True, "records": dns_manager.records})


@app.route("/api/dns/reset", methods=["POST"])
def api_dns_reset():
    dns_manager.reset_to_defaults()
    return jsonify({"success": True, "records": dns_manager.records})


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
