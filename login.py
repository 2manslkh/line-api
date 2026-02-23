#!/usr/bin/env python3
"""
LINE QR Login — run locally on your machine.

Usage:
    cd line-api
    pip install requests qrcode pillow PyNaCl
    python login.py

Displays QR code in terminal. Scan with LINE app.
Saves token to ~/.line-client/tokens.json
"""

import json
import os
import sys
import struct
import base64
import urllib.parse
import time
import requests
from pathlib import Path
from nacl.public import PrivateKey

BASE = "https://line-chrome-gw.line-apps.com"
CACHE_DIR = Path.home() / ".line-client"

HEADERS = {
    "accept": "application/json, text/plain, */*",
    "content-type": "application/json",
    "origin": "chrome-extension://ophjlpahpchlmihnnnihgmmeilfjmjjc",
    "x-lal": "en_US",
    "x-line-chrome-version": "3.7.1",
    "user-agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/145.0.0.0 Safari/537.36",
}

REPO_DIR = Path(__file__).parent
sys.path.insert(0, str(REPO_DIR))


def get_signer():
    from src.hmac import HmacSigner
    try:
        s = HmacSigner(mode="server")
        s.sign("test", "/test", "")
        return s
    except Exception:
        return HmacSigner(mode="subprocess")


def post_json(signer, path, data, token="", extra_headers=None, timeout=10, no_origin=False):
    body = json.dumps(data)
    headers = {**HEADERS, "X-Hmac": signer.sign(token, path, body)}
    if no_origin:
        headers.pop("origin", None)
    if token:
        headers["x-line-access"] = token
    if extra_headers:
        headers.update(extra_headers)
    return requests.post(BASE + path, data=body, headers=headers, timeout=timeout)


def display_qr(url):
    try:
        import qrcode
        qr = qrcode.QRCode(box_size=1, border=1)
        qr.add_data(url)
        qr.make(fit=True)
        qr.print_ascii(invert=True)
    except ImportError:
        print(f"\nQR URL: {url}")
        print("(pip install qrcode for terminal QR display)\n")


SQR_BASE = "/api/talk/thrift/LoginQrCode/SecondaryQrCodeLoginService"
SQR_POLL = "/api/talk/thrift/LoginQrCode/SecondaryQrCodeLoginPermitNoticeService"


def main():
    print("LINE QR Login")
    print("=" * 50)

    signer = get_signer()
    print("✓ HMAC signer ready\n")

    scanned = False
    session_id = None

    for attempt in range(3):
        # E2EE keypair
        private_key = PrivateKey.generate()
        public_key_b64 = base64.b64encode(bytes(private_key.public_key)).decode()

        # Create session
        r = post_json(signer, f"{SQR_BASE}/createSession", [{}])
        resp = r.json()
        if resp.get("code") != 0:
            print(f"✗ createSession failed: {resp}")
            sys.exit(1)
        session_id = resp["data"]["authSessionId"]

        # Create QR code
        r = post_json(signer, f"{SQR_BASE}/createQrCode", [{"authSessionId": session_id}])
        resp = r.json()
        if resp.get("code") != 0:
            print(f"✗ createQrCode failed: {resp}")
            sys.exit(1)
        callback_url = resp["data"]["callbackUrl"]
        qr_url = f"{callback_url}?secret={urllib.parse.quote(public_key_b64)}&e2eeVersion=1"

        print(f"\n{'=' * 50}")
        print(f"  Scan with LINE app (attempt {attempt + 1}/3)")
        print(f"{'=' * 50}\n")
        display_qr(qr_url)
        print(f"\n{'=' * 50}")
        print("Waiting for scan...\n")

        # Poll for scan (Chrome GW, no origin header)
        for i in range(30):
            try:
                t0 = time.time()
                r = post_json(signer, f"{SQR_POLL}/checkQrCodeVerified",
                              [{"authSessionId": session_id}],
                              extra_headers={"X-LST": "150000", "X-Line-Session-ID": session_id, "Referer": ""},
                              timeout=160, no_origin=True)
                elapsed = time.time() - t0
                resp = r.json()

                if resp.get("code") == 0 and elapsed > 1:
                    scanned = True
                    break
                elif resp.get("code") == 0:
                    time.sleep(2)
                elif resp.get("code") == 10051:
                    break  # expired
                elif resp.get("code") == 10052:
                    continue  # backend timeout
            except requests.exceptions.ReadTimeout:
                continue
            except Exception as e:
                print(f"  Poll error: {e}")
                time.sleep(1)

        if scanned:
            break
        print("\n⚠ QR expired. Generating a new one...\n")

    if not scanned:
        print("\n✗ Failed after 3 attempts.")
        sys.exit(1)

    print("✓ QR code scanned!")

    # verifyCertificate (REQUIRED state transition, even if it fails)
    cert_file = CACHE_DIR / "sqr_cert"
    cert = cert_file.read_text().strip() if cert_file.exists() else "dummy"

    r = post_json(signer, f"{SQR_BASE}/verifyCertificate",
                  [{"authSessionId": session_id, "certificate": cert}])
    resp = r.json()
    need_pin = resp.get("code") != 0

    if need_pin:
        # createPinCode
        r = post_json(signer, f"{SQR_BASE}/createPinCode", [{"authSessionId": session_id}])
        resp = r.json()
        pin = resp.get("data", {}).get("pinCode")

        if pin:
            print(f"\n{'=' * 50}")
            print(f"  Enter this PIN on your phone:  {pin}")
            print(f"{'=' * 50}\n")

            # Wait for PIN entry
            for i in range(10):
                try:
                    r = post_json(signer, f"{SQR_POLL}/checkPinCodeVerified",
                                  [{"authSessionId": session_id}],
                                  extra_headers={"X-LST": "110000", "X-Line-Session-ID": session_id, "Referer": ""},
                                  timeout=120, no_origin=True)
                    if r.json().get("code") == 0:
                        print("✓ PIN verified!")
                        break
                except requests.exceptions.ReadTimeout:
                    continue
        else:
            print(f"✗ createPinCode failed: {json.dumps(resp)[:200]}")
            sys.exit(1)
    else:
        print("✓ Certificate verified (no PIN needed)")

    # Login
    print("Logging in...")
    r = post_json(signer, f"{SQR_BASE}/qrCodeLoginV2",
                  [{"authSessionId": session_id, "systemName": "CHROMEOS",
                    "modelName": "CHROME", "autoLoginIsRequired": False}])

    data = r.json().get("data", {})
    token_v3 = data.get("tokenV3IssueResult", {})
    auth_token = token_v3.get("accessToken")
    refresh_token = token_v3.get("refreshToken")
    mid = data.get("mid")
    cert_new = data.get("certificate")

    if cert_new:
        CACHE_DIR.mkdir(parents=True, exist_ok=True)
        (CACHE_DIR / "sqr_cert").write_text(cert_new)

    if auth_token:
        CACHE_DIR.mkdir(parents=True, exist_ok=True)
        (CACHE_DIR / "tokens.json").write_text(json.dumps({
            "auth_token": auth_token,
            "refresh_token": refresh_token,
            "mid": mid,
            "saved_at": int(time.time()),
        }, indent=2))

        print(f"\n{'=' * 50}")
        print(f"  ✅ Logged in!")
        print(f"  MID: {mid}")
        print(f"  Token saved to: {CACHE_DIR / 'tokens.json'}")
        print(f"{'=' * 50}")
    else:
        print(f"\n✗ Login failed: {json.dumps(data)[:200]}")
        sys.exit(1)


if __name__ == "__main__":
    main()
