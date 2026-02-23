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

# Auto-detect if running from repo
REPO_DIR = Path(__file__).parent
sys.path.insert(0, str(REPO_DIR))

BASE = "https://line-chrome-gw.line-apps.com"
THRIFT_HOST = "https://ga2.line.naver.jp"
CACHE_DIR = Path.home() / ".line-client"

HEADERS = {
    "accept": "application/json, text/plain, */*",
    "content-type": "application/json",
    "origin": "chrome-extension://ophjlpahpchlmihnnnihgmmeilfjmjjc",
    "x-lal": "en_US",
    "x-line-chrome-version": "3.7.1",
    "user-agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/145.0.0.0 Safari/537.36",
}


def get_signer():
    from src.hmac import HmacSigner
    return HmacSigner(mode="server")


def post_json(signer, path, data, token=""):
    body = json.dumps(data)
    headers = {**HEADERS, "X-Hmac": signer.sign(token, path, body)}
    if token:
        headers["x-line-access"] = token
    return requests.post(BASE + path, data=body, headers=headers, timeout=10)


def make_thrift(method, session_id):
    buf = bytearray(b"\x80\x01\x00\x01")
    name = method.encode()
    buf += struct.pack(">i", len(name)) + name
    buf += struct.pack(">i", 0)
    buf += struct.pack(">bh", 12, 1)
    buf += struct.pack(">bh", 11, 1)
    sid = session_id.encode()
    buf += struct.pack(">i", len(sid)) + sid
    buf += b"\x00\x00"
    return bytes(buf)


def thrift_long_poll(method, session_id, timeout=15):
    headers = {
        "content-type": "application/x-thrift; protocol=TBINARY",
        "accept": "application/x-thrift",
        "x-line-application": "CHROMEOS\t3.7.1\tChrome OS\t1",
        "x-line-access": session_id,
        "x-lst": "150000",
        "user-agent": "Mozilla/5.0",
    }
    return requests.post(
        f"{THRIFT_HOST}/acct/lp/lgn/sq/v1",
        data=make_thrift(method, session_id),
        headers=headers,
        timeout=timeout,
    )


def display_qr(url):
    """Display QR code in terminal."""
    try:
        import qrcode

        qr = qrcode.QRCode(box_size=1, border=1)
        qr.add_data(url)
        qr.make(fit=True)
        qr.print_ascii(invert=True)
    except ImportError:
        print(f"\nQR URL: {url}")
        print("(pip install qrcode for terminal QR display)\n")


def main():
    print("LINE QR Login")
    print("=" * 50)

    signer = get_signer()
    print("✓ HMAC signer ready")

    # Generate E2EE keypair
    private_key = PrivateKey.generate()
    public_key_b64 = base64.b64encode(bytes(private_key.public_key)).decode()

    # Create session
    r = post_json(signer, "/api/talk/thrift/LoginQrCode/SecondaryQrCodeLoginService/createSession", [])
    session_id = r.json()["data"]["authSessionId"]
    print(f"✓ Session created")

    # Create QR code
    r = post_json(signer, "/api/talk/thrift/LoginQrCode/SecondaryQrCodeLoginService/createQrCode",
                  [{"authSessionId": session_id}])
    callback_url = r.json()["data"]["callbackUrl"]
    qr_url = f"{callback_url}?secret={urllib.parse.quote(public_key_b64)}&e2eeVersion=1"

    print(f"\n{'=' * 50}")
    print("Scan this QR code with LINE app:")
    print(f"{'=' * 50}\n")
    display_qr(qr_url)
    print(f"\n{'=' * 50}")
    print("Waiting for scan...\n")

    # Poll for scan
    scanned = False
    for i in range(20):  # ~5 min
        try:
            r = thrift_long_poll("checkQrCodeVerified", session_id, timeout=15)
            if r.status_code == 200:
                scanned = True
                break
        except requests.exceptions.ReadTimeout:
            sys.stdout.write(".")
            sys.stdout.flush()
            continue
        except Exception as e:
            print(f"\nPoll error: {e}")
            time.sleep(1)

    if not scanned:
        print("\n✗ Timed out waiting for scan. Try again.")
        sys.exit(1)

    print("\n✓ QR code scanned!")

    # Check for saved certificate (skips PIN on repeat logins)
    cert = None
    cert_file = CACHE_DIR / "sqr_cert"
    if cert_file.exists():
        cert = cert_file.read_text().strip()

    need_pin = True
    if cert:
        try:
            post_json(signer, "/api/talk/thrift/LoginQrCode/SecondaryQrCodeLoginService/verifyCertificate",
                      [{"authSessionId": session_id, "certificate": cert}])
            need_pin = False
            print("✓ Certificate verified (no PIN needed)")
        except Exception:
            pass

    if need_pin:
        r = post_json(signer, "/api/talk/thrift/LoginQrCode/SecondaryQrCodeLoginService/createPinCode",
                      [{"authSessionId": session_id}])
        pin = r.json().get("data", {}).get("pinCode")

        print(f"\n{'=' * 50}")
        print(f"  Enter this PIN on your phone:  {pin}")
        print(f"{'=' * 50}\n")

        # Wait for PIN verification
        for i in range(30):
            try:
                r = thrift_long_poll("checkPinCodeVerified", session_id, timeout=15)
                if r.status_code == 200:
                    break
            except requests.exceptions.ReadTimeout:
                sys.stdout.write(".")
                sys.stdout.flush()
                continue

        print("\n✓ PIN verified!")

    # Final login
    print("Logging in...")
    r = post_json(signer, "/api/talk/thrift/LoginQrCode/SecondaryQrCodeLoginService/qrCodeLoginV2",
                  [{"authSessionId": session_id, "systemName": "LINE for Chrome",
                    "deviceType": "CHROMEOS", "autoLoginIsRequired": True}])

    data = r.json().get("data", {})
    token_v3 = data.get("tokenV3IssueResult", {})
    auth_token = token_v3.get("accessToken")
    refresh_token = token_v3.get("refreshToken")
    mid = data.get("mid")
    cert_new = data.get("certificate")

    # Save certificate
    if cert_new:
        CACHE_DIR.mkdir(parents=True, exist_ok=True)
        (CACHE_DIR / "sqr_cert").write_text(cert_new)

    # Save tokens
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
        print(f"\n✗ Login failed: {json.dumps(data)[:500]}")
        sys.exit(1)


if __name__ == "__main__":
    main()
