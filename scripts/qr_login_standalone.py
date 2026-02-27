#!/usr/bin/env python3
"""
Standalone QR login script with file-based event output.

Designed for agent/automation use:
  - Writes QR image to a file for sending via messaging
  - Writes PIN to a file the instant it's generated (for fast relay)
  - Writes final status to a file

Usage:
    # 1. Start HMAC signer first:
    cd /path/to/line-client && node src/hmac/signer.js serve &

    # 2. Run this script:
    python3 scripts/qr_login_standalone.py

    # 3. Monitor output files:
    #    - QR image:  /data/workspace/line_qr.png  (send to user)
    #    - PIN:       /data/workspace/line_pin.txt  (relay FAST — 60s window!)
    #    - Status:    /data/workspace/line_status.txt
    #    - Done:      /data/workspace/line_done.txt  (OK:<mid> or FAILED)

    # 4. Token saved to: ~/.line-client/tokens.json

Environment variables:
    LINE_QR_PATH     - QR image output path (default: /data/workspace/line_qr.png)
    LINE_PIN_PATH    - PIN output path (default: /data/workspace/line_pin.txt)
    LINE_STATUS_PATH - Status output path (default: /data/workspace/line_status.txt)
    LINE_DONE_PATH   - Done flag output path (default: /data/workspace/line_done.txt)

Notes:
    - Clears cached certificate to ensure PIN is always requested
    - PIN must reach the user within ~60 seconds of generation
    - Token expires in ~7 days; re-run QR login when expired (APIError 10051)
"""

import json
import os
import sys
import time
from pathlib import Path

# Add repo root to path
REPO_DIR = Path(__file__).parent.parent
sys.path.insert(0, str(REPO_DIR))

import qrcode
from src.hmac import HmacSigner
from src.auth.qr_login import QRLogin

# Output file paths (configurable via env vars)
QR_PATH = os.environ.get("LINE_QR_PATH", "/data/workspace/line_qr.png")
PIN_PATH = os.environ.get("LINE_PIN_PATH", "/data/workspace/line_pin.txt")
STATUS_PATH = os.environ.get("LINE_STATUS_PATH", "/data/workspace/line_status.txt")
DONE_PATH = os.environ.get("LINE_DONE_PATH", "/data/workspace/line_done.txt")


def clean():
    """Remove old output files."""
    for f in [QR_PATH, PIN_PATH, STATUS_PATH, DONE_PATH]:
        Path(f).unlink(missing_ok=True)


def write_status(msg: str):
    """Write status to file and stdout."""
    Path(STATUS_PATH).write_text(msg)
    print(msg, flush=True)


def main():
    clean()

    # Clear cached certificate so PIN is always requested
    cert_path = Path.home() / ".line-client" / "sqr_cert"
    cert_path.unlink(missing_ok=True)

    write_status("STARTING")
    signer = HmacSigner(mode="server")

    def on_qr(url: str):
        img = qrcode.make(url)
        img.save(QR_PATH)
        write_status("QR_READY")

    def on_pin(pin: str):
        # Write PIN to file IMMEDIATELY — speed is critical
        Path(PIN_PATH).write_text(pin)
        write_status(f"PIN|{pin}")

    def on_status(msg: str):
        print(f"STATUS: {msg}", flush=True)

    login = QRLogin(signer)
    result = login.run(on_qr=on_qr, on_pin=on_pin, on_status=on_status)

    if result:
        # Token is auto-saved by QRLogin, but let's ensure it
        token_dir = Path.home() / ".line-client"
        token_dir.mkdir(parents=True, exist_ok=True)
        tokens = {
            "auth_token": result.auth_token,
            "mid": result.mid,
            "refresh_token": result.refresh_token,
            "certificate": result.certificate,
            "timestamp": int(time.time()),
        }
        (token_dir / "tokens.json").write_text(json.dumps(tokens, indent=2))

        done_msg = f"OK:{result.mid}"
        Path(DONE_PATH).write_text(done_msg)
        write_status(f"DONE|{result.mid}")
        print(f"\n✅ Login successful! MID: {result.mid}", flush=True)
        print(f"Token saved to: {token_dir / 'tokens.json'}", flush=True)
    else:
        Path(DONE_PATH).write_text("FAILED")
        write_status("FAILED")
        print("\n❌ Login failed", flush=True)
        sys.exit(1)


if __name__ == "__main__":
    main()
