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
    try:
        s = HmacSigner(mode="server")
        # Quick test
        result = s.sign("test", "/test", "")
        print(f"  HMAC test: {result[:20]}...")
        return s
    except Exception as e:
        print(f"  ⚠ Server mode failed ({e}), falling back to subprocess")
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
    print("✓ HMAC signer ready\n")

    scanned = False
    session_id = None
    private_key = None

    for attempt in range(3):  # Up to 3 QR codes
        # Generate E2EE keypair
        private_key = PrivateKey.generate()
        public_key_b64 = base64.b64encode(bytes(private_key.public_key)).decode()

        # Create session
        r = post_json(signer, "/api/talk/thrift/LoginQrCode/SecondaryQrCodeLoginService/createSession", [{}])
        resp = r.json()
        if resp.get("code") != 0:
            print(f"  ✗ createSession failed: {resp}")
            sys.exit(1)
        session_id = resp["data"]["authSessionId"]
        print(f"  Session: {session_id[:30]}...")

        # Create QR code
        r = post_json(signer, "/api/talk/thrift/LoginQrCode/SecondaryQrCodeLoginService/createQrCode",
                      [{"authSessionId": session_id}])
        resp = r.json()
        if resp.get("code") != 0:
            print(f"  ✗ createQrCode failed: {resp}")
            sys.exit(1)
        callback_url = resp["data"]["callbackUrl"]
        print(f"  URL: {callback_url[:60]}...")
        qr_url = f"{callback_url}?secret={urllib.parse.quote(public_key_b64)}&e2eeVersion=1"

        print(f"{'=' * 50}")
        print(f"  Scan NOW with LINE app (attempt {attempt + 1}/3)")
        print(f"{'=' * 50}\n")
        display_qr(qr_url)
        print(f"\n{'=' * 50}")
        print("Waiting for scan (2 min timeout)...\n")

        # Poll for scan via Chrome GW (same as extension does)
        poll_path = "/api/talk/thrift/LoginQrCode/SecondaryQrCodeLoginPermitNoticeService/checkQrCodeVerified"
        for i in range(60):  # poll for up to ~2 min
            try:
                t0 = time.time()
                r = post_json(signer, poll_path,
                              [{"authSessionId": session_id}],
                              extra_headers={
                                  "X-LST": "150000",
                                  "X-Line-Session-ID": session_id,
                                  "Referer": "",
                              },
                              timeout=160,
                              no_origin=True)
                elapsed = time.time() - t0
                resp = r.json()
                print(f"\n  Poll [{i+1}] ({elapsed:.1f}s): {json.dumps(resp)[:200]}")
                
                if resp.get("code") == 0 and elapsed > 1:
                    # Real long-poll returned = actually scanned
                    scanned = True
                    break
                elif resp.get("code") == 0 and elapsed < 1:
                    # Returned too fast — not a real scan, keep polling
                    print("  (instant return, not scanned yet)")
                    time.sleep(2)
                    continue
                elif resp.get("code") == 10052:
                    # Backend timeout, retry
                    continue
                elif resp.get("code") == 10051:
                    # Session expired
                    print("  Session expired")
                    break
                else:
                    print(f"  Unexpected code: {resp.get('code')}")
                    time.sleep(2)
            except requests.exceptions.ReadTimeout:
                sys.stdout.write(".")
                sys.stdout.flush()
                continue
            except Exception as e:
                print(f"\nPoll error: {e}")
                time.sleep(1)

        if scanned:
            break
        print("\n\n⚠ QR expired. Generating a new one...\n")

    if not scanned:
        print("\n✗ Failed after 3 attempts. Try again.")
        sys.exit(1)

    print("\n✓ QR code scanned!")

    # After scan: try verifyCertificate, then createPinCode if needed
    cert_file = CACHE_DIR / "sqr_cert"
    cert = cert_file.read_text().strip() if cert_file.exists() else None

    need_pin = True
    if cert:
        print(f"Trying verifyCertificate with saved cert...")
        r = post_json(signer, "/api/talk/thrift/LoginQrCode/SecondaryQrCodeLoginService/verifyCertificate",
                      [{"authSessionId": session_id, "certificate": cert}])
        resp = r.json()
        print(f"  verifyCertificate: {json.dumps(resp)[:200]}")
        if resp.get("code") == 0:
            need_pin = False
            print("✓ Certificate verified!")

    if need_pin:
        print("Creating PIN...")
        r = post_json(signer, "/api/talk/thrift/LoginQrCode/SecondaryQrCodeLoginService/createPinCode",
                      [{"authSessionId": session_id}])
        resp = r.json()
        print(f"  createPinCode: {json.dumps(resp)}")
        pin = resp.get("data", {}).get("pinCode")
        if pin:
            print(f"\n{'=' * 50}")
            print(f"  Enter this PIN on your phone:  {pin}")
            print(f"{'=' * 50}\n")
            # Wait for PIN verification (no origin, like Chrome ext)
            pin_poll = "/api/talk/thrift/LoginQrCode/SecondaryQrCodeLoginPermitNoticeService/checkPinCodeVerified"
            for i in range(10):
                try:
                    r = post_json(signer, pin_poll,
                                  [{"authSessionId": session_id}],
                                  extra_headers={"X-LST":"110000","X-Line-Session-ID":session_id,"Referer":""},
                                  timeout=120,
                                  no_origin=True)
                    resp = r.json()
                    print(f"\n  PIN poll: {json.dumps(resp)[:200]}")
                    if resp.get("code") == 0:
                        print("✓ PIN verified!")
                        break
                except requests.exceptions.ReadTimeout:
                    sys.stdout.write(".")
                    sys.stdout.flush()
        else:
            print(f"  ⚠ createPinCode failed — session may have expired")

    # Final login
    print("Logging in...")
    r = post_json(signer, "/api/talk/thrift/LoginQrCode/SecondaryQrCodeLoginService/qrCodeLoginV2",
                  [{"authSessionId": session_id, "systemName": "CHROMEOS",
                    "modelName": "CHROME", "autoLoginIsRequired": False}])

    full_resp = r.json()
    print(f"  Login response: {json.dumps(full_resp)}")
    data = full_resp.get("data", {})
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
