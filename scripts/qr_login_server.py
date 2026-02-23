#!/usr/bin/env python3
"""
Server-side QR login — generates QR, saves to file, outputs PIN.
Designed to be called by an agent that sends QR/PIN via messaging.

Exit codes:
  0 = success (token saved)
  1 = failure

Output format (JSON lines):
  {"event": "qr", "path": "/path/to/qr.png", "url": "https://..."}
  {"event": "status", "message": "..."}
  {"event": "pin", "pin": "123456"}
  {"event": "done", "mid": "U...", "token_path": "~/.line-client/tokens.json"}
  {"event": "error", "message": "..."}
"""

import json
import sys
import os
from pathlib import Path

# Add repo root to path
REPO_DIR = Path(__file__).parent.parent
sys.path.insert(0, str(REPO_DIR))

import qrcode
from src.hmac import HmacSigner
from src.auth.qr_login import QRLogin


def emit(event, **kwargs):
    print(json.dumps({"event": event, **kwargs}), flush=True)


def main():
    qr_path = sys.argv[1] if len(sys.argv) > 1 else "/tmp/line_qr.png"

    signer = HmacSigner(mode="server")

    def on_qr(url):
        img = qrcode.make(url)
        img.save(qr_path)
        emit("qr", path=qr_path, url=url)

    def on_pin(pin):
        emit("pin", pin=pin)

    def on_status(msg):
        emit("status", message=msg)

    login = QRLogin(signer)
    result = login.run(on_qr=on_qr, on_pin=on_pin, on_status=on_status)

    if result:
        emit("done", mid=result.mid, token_path=str(Path.home() / ".line-client" / "tokens.json"))
    else:
        emit("error", message="Login failed")
        sys.exit(1)


if __name__ == "__main__":
    main()
