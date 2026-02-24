"""
LINE QR Login via Chrome Gateway.

Complete flow:
  createSession → createQrCode → checkQrCodeVerified →
  verifyCertificate → createPinCode → checkPinCodeVerified →
  qrCodeLoginV2 → token

Usage:
    from src.auth.qr_login import QRLogin
    
    login = QRLogin(signer)
    result = login.run(on_qr=callback, on_pin=callback)
"""

import json
import os
import stat
import time
import base64
import urllib.parse
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
    "user-agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
}

SQR = "/api/talk/thrift/LoginQrCode/SecondaryQrCodeLoginService"
POLL = "/api/talk/thrift/LoginQrCode/SecondaryQrCodeLoginPermitNoticeService"


class QRLoginResult:
    def __init__(self, auth_token, refresh_token, mid, certificate=None, metadata=None):
        self.auth_token = auth_token
        self.refresh_token = refresh_token
        self.mid = mid
        self.certificate = certificate
        self.metadata = metadata


class QRLogin:
    def __init__(self, signer):
        self.signer = signer

    def _post(self, path, data, extra_headers=None, timeout=10, no_origin=False):
        body = json.dumps(data)
        headers = {**HEADERS, "X-Hmac": self.signer.sign("", path, body)}
        if no_origin:
            headers.pop("origin", None)
        if extra_headers:
            headers.update(extra_headers)
        return requests.post(BASE + path, data=body, headers=headers, timeout=timeout)

    def run(self, on_qr=None, on_pin=None, on_status=None, max_attempts=3):
        """
        Run the QR login flow.

        Args:
            on_qr: callback(qr_url: str) — called with the QR URL to display/send
            on_pin: callback(pin: str) — called with the PIN code to show user
            on_status: callback(msg: str) — called with status updates
            max_attempts: number of QR regeneration attempts

        Returns:
            QRLoginResult on success, None on failure
        """
        def status(msg):
            if on_status:
                on_status(msg)

        for attempt in range(max_attempts):
            # E2EE keypair
            private_key = PrivateKey.generate()
            public_key_b64 = base64.b64encode(bytes(private_key.public_key)).decode()

            # Create session
            r = self._post(f"{SQR}/createSession", [{}])
            resp = r.json()
            if resp.get("code") != 0:
                status(f"createSession failed: {resp}")
                continue
            session_id = resp["data"]["authSessionId"]

            # Create QR
            r = self._post(f"{SQR}/createQrCode", [{"authSessionId": session_id}])
            resp = r.json()
            if resp.get("code") != 0:
                status(f"createQrCode failed: {resp}")
                continue
            callback_url = resp["data"]["callbackUrl"]
            qr_url = f"{callback_url}?secret={urllib.parse.quote(public_key_b64)}&e2eeVersion=1"

            # Deliver QR
            if on_qr:
                on_qr(qr_url)
            status(f"QR ready (attempt {attempt + 1}/{max_attempts})")

            # Poll for scan
            scanned = False
            for i in range(30):
                try:
                    t0 = time.time()
                    r = self._post(
                        f"{POLL}/checkQrCodeVerified",
                        [{"authSessionId": session_id}],
                        extra_headers={"X-LST": "150000", "X-Line-Session-ID": session_id, "Referer": ""},
                        timeout=160, no_origin=True,
                    )
                    elapsed = time.time() - t0
                    resp = r.json()

                    if resp.get("code") == 0 and elapsed > 1:
                        scanned = True
                        break
                    elif resp.get("code") == 0:
                        time.sleep(2)
                    elif resp.get("code") == 10051:
                        break
                except requests.exceptions.ReadTimeout:
                    continue

            if scanned:
                break
            status("QR expired, regenerating...")

        if not scanned:
            status("Failed after all attempts")
            return None

        status("QR scanned!")

        # verifyCertificate (REQUIRED state transition)
        cert_file = CACHE_DIR / "sqr_cert"
        cert = cert_file.read_text().strip() if cert_file.exists() else "dummy"
        r = self._post(f"{SQR}/verifyCertificate",
                       [{"authSessionId": session_id, "certificate": cert}])
        resp = r.json()
        need_pin = resp.get("code") != 0

        if need_pin:
            # createPinCode
            r = self._post(f"{SQR}/createPinCode", [{"authSessionId": session_id}])
            resp = r.json()
            pin = resp.get("data", {}).get("pinCode")

            if not pin:
                status(f"createPinCode failed: {resp}")
                return None

            # Deliver PIN immediately
            if on_pin:
                on_pin(pin)
            status(f"PIN: {pin}")

            # Wait for PIN verification
            for i in range(10):
                try:
                    r = self._post(
                        f"{POLL}/checkPinCodeVerified",
                        [{"authSessionId": session_id}],
                        extra_headers={"X-LST": "110000", "X-Line-Session-ID": session_id, "Referer": ""},
                        timeout=120, no_origin=True,
                    )
                    if r.json().get("code") == 0:
                        status("PIN verified!")
                        break
                except requests.exceptions.ReadTimeout:
                    continue
        else:
            status("Certificate verified (no PIN needed)")

        # Login
        r = self._post(f"{SQR}/qrCodeLoginV2",
                       [{"authSessionId": session_id, "systemName": "CHROMEOS",
                         "modelName": "CHROME", "autoLoginIsRequired": False}])
        data = r.json().get("data", {})
        token_v3 = data.get("tokenV3IssueResult", {})
        auth_token = token_v3.get("accessToken")

        if not auth_token:
            status(f"Login failed: {json.dumps(data)[:200]}")
            return None

        # Save certificate
        cert_new = data.get("certificate")
        CACHE_DIR.mkdir(parents=True, exist_ok=True)
        os.chmod(CACHE_DIR, stat.S_IRWXU)  # 0700

        if cert_new:
            cert_path = CACHE_DIR / "sqr_cert"
            cert_path.write_text(cert_new)
            os.chmod(cert_path, stat.S_IRUSR | stat.S_IWUSR)  # 0600

        # Save tokens
        result = QRLoginResult(
            auth_token=auth_token,
            refresh_token=token_v3.get("refreshToken"),
            mid=data.get("mid"),
            certificate=cert_new,
            metadata=data.get("metaData"),
        )

        token_path = CACHE_DIR / "tokens.json"
        token_path.write_text(json.dumps({
            "auth_token": result.auth_token,
            "refresh_token": result.refresh_token,
            "mid": result.mid,
            "saved_at": int(time.time()),
        }, indent=2))
        os.chmod(token_path, stat.S_IRUSR | stat.S_IWUSR)  # 0600

        status(f"Logged in! MID: {result.mid}")
        return result
