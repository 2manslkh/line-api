"""
QR Code login for LINE Chrome Gateway.

Flow:
1. POST /api/talk/thrift/LoginQrCode/SecondaryQrCodeLoginService/createSession → session ID
2. POST .../createQrCode → QR URL
3. User scans QR with LINE mobile app
4. Long-poll .../checkQrCodeVerified
5. .../verifyCertificate (or createPinCode if no cert)
6. .../qrCodeLoginV2 → JWT access token + refresh token

Usage:
    auth = QRChromeLogin()
    for status in auth.login():
        if status["status"] == "qr_code":
            print(f"Scan this QR: {status['url']}")
        elif status["status"] == "pin_required":
            print(f"Enter PIN on phone: {status['pin']}")
        elif status["status"] == "logged_in":
            token = status["auth_token"]
"""

import json
import time
import base64
import os
import requests
from pathlib import Path


BASE_URL = "https://line-chrome-gw.line-apps.com"
SQR_BASE = f"{BASE_URL}/api/talk/thrift/LoginQrCode/SecondaryQrCodeLoginService"
SQR_POLL_BASE = f"{BASE_URL}/api/talk/thrift/LoginQrCode/SecondaryQrCodeLoginPermitNoticeService"

CACHE_DIR = Path.home() / ".line-client"
CERT_FILE = CACHE_DIR / "sqr_cert"
TOKEN_FILE = CACHE_DIR / "tokens.json"

HEADERS = {
    "accept": "application/json, text/plain, */*",
    "content-type": "application/json",
    "origin": "chrome-extension://ophjlpahpchlmihnnnihgmmeilfjmjjc",
    "x-lal": "en_US",
    "x-line-chrome-version": "3.7.1",
    "user-agent": (
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
        "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/145.0.0.0 Safari/537.36"
    ),
}


class QRChromeLogin:
    """QR code login via the Chrome gateway JSON API."""

    def __init__(self, hmac_signer=None):
        from ..hmac import HmacSigner
        self._session = requests.Session()
        self._hmac = hmac_signer or HmacSigner(mode="server")

    def _post(self, url: str, data=None, timeout: int = 30, access_token: str = None) -> dict:
        """Make a signed POST request."""
        headers = {**HEADERS}
        if access_token:
            headers["x-line-access"] = access_token

        body = json.dumps(data) if data is not None else "[]"

        # Always sign — use empty string token for unauthenticated requests
        from urllib.parse import urlparse
        path = urlparse(url).path
        token_for_hmac = access_token or ""
        headers["X-Hmac"] = self._hmac.sign(token_for_hmac, path, body)

        resp = self._session.post(url, data=body, headers=headers, timeout=timeout)
        resp.raise_for_status()
        return resp.json()

    def login(self):
        """
        Generator yielding status dicts during QR login flow.
        Final yield has status="logged_in" with auth_token.
        """
        # 1. Create session
        resp = self._post(f"{SQR_BASE}/createSession", [])
        data = resp.get("data", resp) if isinstance(resp, dict) else resp
        session_id = None
        if isinstance(data, dict):
            session_id = data.get("authSessionId") or data.get("sessionId") or data.get("1")
        elif isinstance(data, str):
            session_id = data
        
        if not session_id:
            raise RuntimeError(f"Failed to create session: {resp}")

        yield {"status": "session_created", "session_id": session_id}

        # 2. Create QR code
        resp = self._post(f"{SQR_BASE}/createQrCode", [{"authSessionId": session_id}])
        data = resp.get("data", resp) if isinstance(resp, dict) else resp
        qr_url = data.get("callbackUrl") if isinstance(data, dict) else None

        if not qr_url:
            raise RuntimeError(f"Failed to create QR code: {resp}")

        yield {"status": "qr_code", "url": qr_url}

        # 3. Wait for scan (long-poll)
        yield {"status": "waiting_for_scan", "message": "Scan the QR code with your LINE app"}
        
        scanned = False
        for attempt in range(60):  # ~5 min timeout
            try:
                resp = self._post(
                    f"{SQR_POLL_BASE}/checkQrCodeVerified",
                    [{"authSessionId": session_id}],
                    timeout=10,
                    access_token=session_id,
                )
                scanned = True
                break
            except requests.exceptions.Timeout:
                continue
            except requests.exceptions.HTTPError as e:
                if e.response and e.response.status_code == 410:
                    raise RuntimeError("QR code expired. Please try again.")
                # May return error while waiting — retry
                time.sleep(1)
                continue

        if not scanned:
            raise RuntimeError("QR code verification timed out")

        yield {"status": "scanned"}

        # 4. Certificate or PIN
        cert = self._load_cert()
        need_pin = True

        if cert:
            try:
                self._post(
                    f"{SQR_BASE}/verifyCertificate",
                    [{"authSessionId": session_id, "certificate": cert}],
                )
                need_pin = False
                yield {"status": "certificate_verified"}
            except Exception:
                pass  # Fall through to PIN

        if need_pin:
            resp = self._post(f"{SQR_BASE}/createPinCode", [{"authSessionId": session_id}])
            pin = self._extract(resp, "pinCode") or self._extract(resp, 1)
            if not pin and isinstance(resp, dict) and resp.get("data"):
                d = resp["data"]
                pin = d if isinstance(d, str) else d.get("pinCode") or d.get("1")

            yield {"status": "pin_required", "pin": pin}

            # Wait for PIN verification
            for attempt in range(60):
                try:
                    self._post(
                        f"{SQR_POLL_BASE}/checkPinCodeVerified",
                        [{"authSessionId": session_id}],
                        timeout=10,
                        access_token=session_id,
                    )
                    break
                except requests.exceptions.Timeout:
                    continue
                except requests.exceptions.HTTPError:
                    time.sleep(1)
                    continue

            yield {"status": "pin_verified"}

        # 5. Final login
        resp = self._post(f"{SQR_BASE}/qrCodeLoginV2", [{
            "authSessionId": session_id,
            "systemName": "LINE for Chrome",
            "deviceType": "CHROMEOS",
            "autoLoginIsRequired": True,
        }])

        data = resp.get("data", resp) if isinstance(resp, dict) else resp

        # Extract tokens
        auth_token = None
        refresh_token = None
        cert_new = None
        mid = None

        if isinstance(data, dict):
            # Try v3 token format
            token_v3 = data.get("tokenV3IssueResult") or data.get("3")
            if token_v3:
                auth_token = token_v3.get("accessToken") or token_v3.get("1")
                refresh_token = token_v3.get("refreshToken") or token_v3.get("2")
            else:
                auth_token = data.get("accessToken") or data.get("2")

            cert_new = data.get("certificate") or data.get("1")
            mid = data.get("mid") or data.get("4")

        # Save cert for future logins (skips PIN)
        if cert_new:
            self._save_cert(cert_new)

        # Save tokens
        if auth_token and refresh_token:
            self._save_tokens(auth_token, refresh_token)

        yield {
            "status": "logged_in",
            "auth_token": auth_token,
            "refresh_token": refresh_token,
            "mid": mid,
        }

    def _extract(self, resp, key):
        """Try to extract a value from various response formats."""
        if isinstance(resp, dict):
            if key in resp:
                return resp[key]
            if "data" in resp and isinstance(resp["data"], dict):
                return resp["data"].get(key)
        return None

    def _load_cert(self) -> str | None:
        if CERT_FILE.exists():
            return CERT_FILE.read_text().strip()
        return None

    def _save_cert(self, cert: str):
        CACHE_DIR.mkdir(parents=True, exist_ok=True)
        CERT_FILE.write_text(cert)

    def _save_tokens(self, auth_token: str, refresh_token: str):
        CACHE_DIR.mkdir(parents=True, exist_ok=True)
        tokens = {}
        if TOKEN_FILE.exists():
            tokens = json.loads(TOKEN_FILE.read_text())
        tokens["auth_token"] = auth_token
        tokens["refresh_token"] = refresh_token
        tokens["saved_at"] = int(time.time())
        TOKEN_FILE.write_text(json.dumps(tokens, indent=2))


def qr_login_cli():
    """Interactive CLI for QR login. Prints QR code to terminal."""
    try:
        import qrcode
        has_qrcode = True
    except ImportError:
        has_qrcode = False

    auth = QRChromeLogin()
    token = None

    for status in auth.login():
        s = status["status"]

        if s == "session_created":
            print(f"Session created: {status['session_id'][:20]}...")

        elif s == "qr_code":
            url = status["url"]
            print(f"\n{'='*50}")
            print("Scan this QR code with your LINE app:")
            print(f"{'='*50}")
            if has_qrcode:
                qr = qrcode.QRCode(box_size=1, border=1)
                qr.add_data(url)
                qr.make(fit=True)
                qr.print_ascii(invert=True)
            else:
                print(f"\nURL: {url}")
                print("(pip install qrcode for terminal QR display)")
            print(f"{'='*50}\n")

        elif s == "waiting_for_scan":
            print("Waiting for scan...")

        elif s == "scanned":
            print("✓ QR code scanned!")

        elif s == "certificate_verified":
            print("✓ Certificate verified (no PIN needed)")

        elif s == "pin_required":
            print(f"\n{'='*50}")
            print(f"  Enter this PIN on your phone: {status['pin']}")
            print(f"{'='*50}\n")

        elif s == "pin_verified":
            print("✓ PIN verified!")

        elif s == "logged_in":
            token = status["auth_token"]
            print(f"\n✅ Logged in!")
            print(f"MID: {status.get('mid')}")
            print(f"Token saved to ~/.line-client/tokens.json")

    return token


if __name__ == "__main__":
    token = qr_login_cli()
    if token:
        print(f"\nAccess token:\n{token}")
