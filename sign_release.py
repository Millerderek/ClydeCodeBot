#!/usr/bin/env python3
"""
ClydeCodeBot Release Signer

Signs releases with Ed25519 + TOTP. Produces:
  - release.json    (normal updates, bot checks every 3 days)
  - urgent_fix.json (critical fixes, bot checks every 6 hours)

Both include SHA256 checksums of all tracked files.

Usage:
    python3 sign_release.py                  # interactive
    python3 sign_release.py --type normal    # normal release
    python3 sign_release.py --type critical  # critical/urgent fix

Requires: alert_key.pem and alert_config.json from alert_keygen.py
"""

import base64
import hashlib
import hmac
import json
import os
import struct
import subprocess
import sys
import time

from cryptography.hazmat.primitives.serialization import load_pem_private_key


CHECKSUMMED_FILES = ["clydecodebot.py", "install.sh", "requirements.txt"]


def hotp(secret_bytes, counter):
    msg = struct.pack(">Q", counter)
    h = hmac.new(secret_bytes, msg, hashlib.sha1).digest()
    offset = h[-1] & 0x0F
    code = struct.unpack(">I", h[offset:offset + 4])[0] & 0x7FFFFFFF
    return str(code % 10**6).zfill(6)


def verify_totp(secret_b32, code, window=1):
    padded = secret_b32 + "=" * (-len(secret_b32) % 8)
    secret_bytes = base64.b32decode(padded, casefold=True)
    now = int(time.time()) // 30
    for offset in range(-window, window + 1):
        if hotp(secret_bytes, now + offset) == code:
            return True
    return False


def sha256_file(filepath):
    h = hashlib.sha256()
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def get_git_info():
    """Get current git commit and diff summary."""
    info = {}
    try:
        result = subprocess.run(["git", "rev-parse", "HEAD"],
                                capture_output=True, text=True, timeout=5)
        info["commit"] = result.stdout.strip()
    except Exception:
        info["commit"] = ""

    try:
        result = subprocess.run(["git", "log", "--oneline", "-5"],
                                capture_output=True, text=True, timeout=5)
        info["recent_commits"] = result.stdout.strip()
    except Exception:
        info["recent_commits"] = ""

    try:
        result = subprocess.run(["git", "diff", "HEAD~1", "--stat"],
                                capture_output=True, text=True, timeout=5)
        info["diff_stat"] = result.stdout.strip()
    except Exception:
        info["diff_stat"] = ""

    try:
        result = subprocess.run(["git", "diff", "HEAD~1", "--", "clydecodebot.py"],
                                capture_output=True, text=True, timeout=10)
        diff = result.stdout.strip()
        # Truncate to summary — first 3000 chars
        info["diff_summary"] = diff[:3000] if diff else "No diff available"
    except Exception:
        info["diff_summary"] = ""

    return info


def compute_checksums():
    """Compute SHA256 for all tracked files."""
    checksums = {}
    for fname in CHECKSUMMED_FILES:
        if os.path.exists(fname):
            checksums[fname] = sha256_file(fname)
            print(f"  ✓ {fname}: {checksums[fname][:16]}...")
        else:
            print(f"  ⚠ {fname}: not found (skipped)")
    return checksums


def main():
    print()
    print("═══════════════════════════════════════════")
    print("  📦 ClydeCodeBot Release Signer")
    print("═══════════════════════════════════════════")
    print()

    # Load keys
    if not os.path.exists("alert_key.pem"):
        print("  ❌ alert_key.pem not found — run alert_keygen.py first")
        sys.exit(1)
    if not os.path.exists("alert_config.json"):
        print("  ❌ alert_config.json not found — run alert_keygen.py first")
        sys.exit(1)

    with open("alert_key.pem", "rb") as f:
        private_key = load_pem_private_key(f.read(), password=None)
    with open("alert_config.json") as f:
        config = json.load(f)
    totp_secret = config["totp_secret"]

    # Release type
    if "--type" in sys.argv:
        idx = sys.argv.index("--type")
        release_type = sys.argv[idx + 1] if idx + 1 < len(sys.argv) else "normal"
    else:
        print("  Release type:")
        print("    1) Normal update  (release.json, checked every 3 days)")
        print("    2) Critical fix   (urgent_fix.json, checked every 6 hours)")
        print()
        choice = input("  Type (1 or 2): ").strip()
        release_type = "critical" if choice == "2" else "normal"

    print(f"  → {release_type}")

    # Version
    print()
    # Try to read current version from clydecodebot.py
    current_ver = "unknown"
    if os.path.exists("clydecodebot.py"):
        with open("clydecodebot.py") as f:
            for line in f:
                if line.startswith("VERSION"):
                    current_ver = line.split('"')[1]
                    break
    version = input(f"  Version [{current_ver}]: ").strip() or current_ver

    # Changelog
    print()
    changelog = input("  Changelog: ").strip()
    if not changelog:
        print("  ❌ Changelog required")
        sys.exit(1)

    # For critical: version range
    min_version = "0.0.0"
    max_version = "999.999.999"
    if release_type == "critical":
        print()
        min_version = input("  Affected min version [0.0.0]: ").strip() or "0.0.0"
        max_version = input(f"  Affected max version [{version}]: ").strip() or version

    # Checksums
    print()
    print("  Computing checksums...")
    checksums = compute_checksums()
    if not checksums:
        print("  ❌ No files to checksum")
        sys.exit(1)

    # Git info
    print()
    print("  Reading git info...")
    git = get_git_info()
    if not git["commit"]:
        print("  ⚠ Could not read git commit — enter manually:")
        git["commit"] = input("  Commit SHA: ").strip()

    print(f"  ✓ Commit: {git['commit'][:12]}")

    # TOTP
    print()
    print("  ┌──────────────────────────────────────┐")
    print("  │  Open your authenticator app now.     │")
    print("  │  Enter the 6-digit code for           │")
    print("  │  'ClydeCodeBot Alerts'                │")
    print("  └──────────────────────────────────────┘")
    print()
    totp_code = input("  TOTP code: ").strip()

    if not verify_totp(totp_secret, totp_code):
        print()
        print("  ❌ Invalid TOTP code. Aborting.")
        sys.exit(1)
    print("  ✓ TOTP verified")

    # Build TOTP HMAC — proves TOTP was valid at signing time
    # HMAC(totp_code, checksums_json) — baked into payload, covered by Ed25519
    checksums_json = json.dumps(checksums, sort_keys=True)
    totp_hmac = hmac.new(
        totp_code.encode(), checksums_json.encode(), hashlib.sha256
    ).hexdigest()

    # Build payload
    payload = {
        "version": version,
        "release_type": release_type,
        "changelog": changelog,
        "commit": git["commit"],
        "checksums": checksums,
        "diff_summary": git.get("diff_summary", ""),
        "totp_hmac": totp_hmac,
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }

    if release_type == "critical":
        payload["id"] = f"fix-{time.strftime('%Y%m%d-%H%M%S')}"
        payload["message"] = changelog
        payload["min_version"] = min_version
        payload["max_version"] = max_version

    # Sign — Ed25519 only for critical releases
    if release_type == "critical":
        payload_bytes = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
        signature = private_key.sign(payload_bytes)
        sig_b64 = base64.b64encode(signature).decode()
        payload["signature"] = sig_b64

    # Write output
    if release_type == "critical":
        outfile = "urgent_fix.json"
    else:
        outfile = "release.json"

    with open(outfile, "w") as f:
        json.dump(payload, f, indent=2)

    # Summary
    print()
    print("═══════════════════════════════════════════")
    print("  ✅ Release signed")
    print("═══════════════════════════════════════════")
    print()
    print(f"  Type:      {release_type}")
    print(f"  Version:   {version}")
    print(f"  Commit:    {git['commit'][:12]}")
    print(f"  Changelog: {changelog}")
    print(f"  Files:     {len(checksums)} checksummed")
    print(f"  TOTP:      HMAC embedded")
    if release_type == "critical":
        print(f"  Signature: Ed25519 ✅")
    else:
        print(f"  Signature: None (TOTP + checksums only)")
    print(f"  Output:    {outfile}")
    print()
    print("  To publish:")
    print(f"    git add {outfile}")
    print(f"    git commit -m 'release: v{version} — {changelog[:40]}'")
    print(f"    git push")
    print()
    if release_type == "normal":
        print("  Bots will detect this within 3 days (or on restart).")
    else:
        print("  🚨 Bots will detect this within 6 hours (or on restart).")
    print()


if __name__ == "__main__":
    main()
