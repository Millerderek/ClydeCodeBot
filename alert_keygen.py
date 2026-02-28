#!/usr/bin/env python3
"""
ClydeCodeBot Alert System — Key Generator

Run ONCE on your local machine (not the VPS).
Generates:
  1. Ed25519 signing key (private) → alert_key.pem (KEEP SECRET)
  2. Ed25519 public key → hardcode in clydecodebot.py
  3. TOTP secret → scan QR code with Microsoft Authenticator
  4. Signing script config → alert_config.json

Usage:
    python3 alert_keygen.py

Then scan the QR code with your authenticator app.
"""

import hashlib
import hmac
import json
import os
import struct
import sys
import time
import base64

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding, PrivateFormat, PublicFormat, NoEncryption
)


def generate_totp_secret(length=20):
    """Generate a random TOTP secret (base32 encoded)."""
    random_bytes = os.urandom(length)
    # Base32 encode without padding
    return base64.b32encode(random_bytes).decode("ascii").rstrip("=")


def totp_uri(secret, issuer="ClydeCodeBot", account="alerts"):
    """Generate otpauth:// URI for authenticator apps."""
    return f"otpauth://totp/{issuer}:{account}?secret={secret}&issuer={issuer}&digits=6&period=30"


def generate_qr_ascii(data):
    """Generate a simple text representation of the TOTP URI for manual entry."""
    return data


def main():
    print()
    print("═══════════════════════════════════════════")
    print("  🔑 ClydeCodeBot Alert Key Generator")
    print("═══════════════════════════════════════════")
    print()

    # Check for existing keys
    if os.path.exists("alert_key.pem"):
        print("⚠️  alert_key.pem already exists!")
        resp = input("  Overwrite? (yes/no): ").strip().lower()
        if resp != "yes":
            print("  Aborted.")
            sys.exit(0)

    # 1. Generate Ed25519 keypair
    print("  Generating Ed25519 keypair...")
    private_key = Ed25519PrivateKey.generate()

    # Save private key
    pem_bytes = private_key.private_bytes(
        Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()
    )
    with open("alert_key.pem", "wb") as f:
        f.write(pem_bytes)
    os.chmod("alert_key.pem", 0o600)
    print("  ✓ Private key saved: alert_key.pem")

    # Get public key hex
    pub_bytes = private_key.public_key().public_bytes(
        Encoding.Raw, PublicFormat.Raw
    )
    pub_hex = pub_bytes.hex()
    print(f"  ✓ Public key: {pub_hex}")

    # 2. Generate TOTP secret
    print()
    print("  Generating TOTP secret...")
    totp_secret = generate_totp_secret()
    uri = totp_uri(totp_secret)
    print(f"  ✓ TOTP secret: {totp_secret}")
    print()

    # 3. Save config
    config = {
        "public_key_hex": pub_hex,
        "totp_secret": totp_secret,
        "created": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }
    with open("alert_config.json", "w") as f:
        json.dump(config, f, indent=2)
    os.chmod("alert_config.json", 0o600)
    print("  ✓ Config saved: alert_config.json")

    # 4. Output instructions
    print()
    print("═══════════════════════════════════════════")
    print("  📱 AUTHENTICATOR SETUP")
    print("═══════════════════════════════════════════")
    print()
    print("  Open Microsoft Authenticator (or any TOTP app):")
    print("    1. Tap + → Other account")
    print("    2. Tap 'Enter code manually'")
    print(f"    3. Account name: ClydeCodeBot Alerts")
    print(f"    4. Secret key:   {totp_secret}")
    print("    5. Tap Finish")
    print()
    print("  Or scan this URI as a QR code:")
    print(f"    {uri}")
    print()
    print("  (Use any online QR generator with this URI,")
    print("   or install 'qrcode' package: pip install qrcode)")
    print()
    print("═══════════════════════════════════════════")
    print("  📋 ADD TO clydecodebot.py")
    print("═══════════════════════════════════════════")
    print()
    print("  Paste this near the top of clydecodebot.py:")
    print()
    print(f'    ALERT_PUBLIC_KEY = "{pub_hex}"')
    print()
    print("═══════════════════════════════════════════")
    print("  🔒 SECURITY CHECKLIST")
    print("═══════════════════════════════════════════")
    print()
    print("  ✅ alert_key.pem      → Keep on local machine ONLY")
    print("  ✅ alert_config.json   → Keep on local machine ONLY")
    print("  ✅ TOTP secret         → In your authenticator app ONLY")
    print("  ✅ Public key          → Hardcoded in clydecodebot.py (safe to share)")
    print("  ❌ NEVER put alert_key.pem on the VPS or in git")
    print()
    print("  To sign an alert:")
    print("    python3 sign_alert.py")
    print()


if __name__ == "__main__":
    main()
