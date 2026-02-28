#!/usr/bin/env python3
"""
ClydeCodeBot Alert System — Sign & Publish

Run on your local machine to create a signed alert.
Requires: alert_key.pem and alert_config.json (from alert_keygen.py)

Usage:
    python3 sign_alert.py

Interactive — prompts for severity, message, version range, and TOTP code.
Outputs alerts.json ready to git push.
"""

import base64
import hashlib
import hmac
import json
import math
import os
import struct
import sys
import time

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding, PrivateFormat, PublicFormat, NoEncryption, load_pem_private_key
)


def hotp(secret_bytes, counter):
    """Generate HOTP code (RFC 4226)."""
    msg = struct.pack(">Q", counter)
    h = hmac.new(secret_bytes, msg, hashlib.sha1).digest()
    offset = h[-1] & 0x0F
    code = struct.unpack(">I", h[offset:offset + 4])[0] & 0x7FFFFFFF
    return str(code % 10**6).zfill(6)


def totp(secret_b32, time_step=30):
    """Generate current TOTP code (RFC 6238)."""
    # Re-pad base32
    padded = secret_b32 + "=" * (-len(secret_b32) % 8)
    secret_bytes = base64.b32decode(padded, casefold=True)
    counter = int(time.time()) // time_step
    return hotp(secret_bytes, counter)


def verify_totp(secret_b32, code, window=1):
    """Verify TOTP code with time window."""
    padded = secret_b32 + "=" * (-len(secret_b32) % 8)
    secret_bytes = base64.b32decode(padded, casefold=True)
    now = int(time.time()) // 30
    for offset in range(-window, window + 1):
        if hotp(secret_bytes, now + offset) == code:
            return True
    return False


def load_existing_alerts():
    """Load existing alerts.json if present."""
    if os.path.exists("alerts.json"):
        with open("alerts.json") as f:
            data = json.load(f)
            return data.get("alerts", [])
    return []


def main():
    print()
    print("═══════════════════════════════════════════")
    print("  ✍️  ClydeCodeBot Alert Signer")
    print("═══════════════════════════════════════════")
    print()

    # Load signing key
    if not os.path.exists("alert_key.pem"):
        print("  ❌ alert_key.pem not found")
        print("  Run alert_keygen.py first")
        sys.exit(1)

    if not os.path.exists("alert_config.json"):
        print("  ❌ alert_config.json not found")
        print("  Run alert_keygen.py first")
        sys.exit(1)

    with open("alert_key.pem", "rb") as f:
        private_key = load_pem_private_key(f.read(), password=None)

    with open("alert_config.json") as f:
        config = json.load(f)

    totp_secret = config["totp_secret"]

    # Collect alert info
    print("  Severity levels:")
    print("    1) info     — shown on /status")
    print("    2) warning  — notification on next startup")
    print("    3) critical — immediate push to all users")
    print()

    severity_map = {"1": "info", "2": "warning", "3": "critical"}
    sev_input = input("  Severity (1-3): ").strip()
    severity = severity_map.get(sev_input, "info")
    print(f"  → {severity}")

    print()
    message = input("  Alert message: ").strip()
    if not message:
        print("  ❌ Message required")
        sys.exit(1)

    print()
    print("  Version range (which versions are affected):")
    min_ver = input("  Min version [0.0.0]: ").strip() or "0.0.0"
    max_ver = input("  Max version [999.999.999]: ").strip() or "999.999.999"

    # Generate alert ID
    alert_id = time.strftime("%Y%m%d-%H%M%S")

    # Require TOTP
    print()
    print("  ┌──────────────────────────────────────┐")
    print("  │  Open your authenticator app now.     │")
    print("  │  Enter the 6-digit code for           │")
    print("  │  'ClydeCodeBot Alerts'                  │")
    print("  └──────────────────────────────────────┘")
    print()
    totp_code = input("  TOTP code: ").strip()

    if not verify_totp(totp_secret, totp_code):
        print()
        print("  ❌ Invalid TOTP code. Aborting.")
        print("  Make sure your phone clock is synced.")
        sys.exit(1)

    print("  ✓ TOTP verified")

    # Build alert
    alert = {
        "id": alert_id,
        "severity": severity,
        "message": message,
        "min_version": min_ver,
        "max_version": max_ver,
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "totp_hash": hashlib.sha256(totp_code.encode()).hexdigest()[:16],
    }

    # Load existing alerts, append new one
    existing = load_existing_alerts()
    existing.append(alert)

    # Build payload (alerts without signature)
    payload = {
        "version": "1",
        "alerts": existing,
    }

    # Sign the payload
    payload_bytes = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    signature = private_key.sign(payload_bytes)
    sig_b64 = base64.b64encode(signature).decode()

    # Final file
    output = {
        "version": "1",
        "alerts": existing,
        "signature": sig_b64,
    }

    with open("alerts.json", "w") as f:
        json.dump(output, f, indent=2)

    # Summary
    print()
    print("═══════════════════════════════════════════")
    print("  ✅ Alert signed and saved")
    print("═══════════════════════════════════════════")
    print()
    print(f"  ID:       {alert_id}")
    print(f"  Severity: {severity}")
    print(f"  Message:  {message}")
    print(f"  Versions: {min_ver} → {max_ver}")
    print(f"  File:     alerts.json")
    print()
    print("  To publish:")
    print("    git add alerts.json")
    print("    git commit -m 'alert: {}'".format(message[:50]))
    print("    git push")
    print()
    print("  All ClydeCodeBot instances will pick it up")
    print("  within 24 hours (or on next restart).")
    print()


if __name__ == "__main__":
    main()
