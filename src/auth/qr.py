"""
QR Code login (SQR) for LINE personal accounts.

Flow:
1. createSession() → session ID
2. createQrCode(session) → QR code URL
3. Display QR code, user scans with LINE app
4. checkQrCodeVerified(session) — long-poll until scanned
5. verifyCertificate(session, cert) — or createPinCode if no cert
6. qrCodeLoginV2(session) → auth token + refresh token
"""

import base64
import os
import json
from pathlib import Path
from ..transport.http import LineTransport
from ..config import LineConfig
from ..e2ee.crypto import E2EECrypto


CACHE_DIR = Path.home() / ".line-client"


class QRLogin:
    def __init__(self, transport: LineTransport, config: LineConfig):
        self.transport = transport
        self.config = config
        self.e2ee = E2EECrypto()

    def login(self):
        """
        Generator that yields status messages during QR login.
        Final yield is the auth token.
        """
        # 1. Create session
        resp = self.transport.call(
            "createSession", [],
            endpoint=self.config.SQR_ENDPOINT,
            protocol="binary",
        )
        session_id = resp.get(1)
        if not session_id:
            raise RuntimeError(f"Failed to create session: {resp}")
        yield {"status": "session_created", "session_id": session_id}

        # 2. Create QR code
        resp = self.transport.call(
            "createQrCode",
            [[12, 1, [[11, 1, session_id]]]],
            endpoint=self.config.SQR_ENDPOINT,
            protocol="binary",
        )
        qr_url = resp.get(1)
        if not qr_url:
            raise RuntimeError(f"Failed to create QR code: {resp}")

        # Append E2EE secret to URL
        secret, secret_pk = self.e2ee.create_sqr_secret()
        qr_url_with_secret = qr_url + "?secret=" + base64.urlsafe_b64encode(secret_pk).decode().rstrip("=")
        yield {"status": "qr_code", "url": qr_url_with_secret, "raw_url": qr_url}

        # 3. Wait for scan (long-poll)
        yield {"status": "waiting_for_scan"}
        verified = self._check_qr_verified(session_id)
        if not verified:
            raise RuntimeError("QR code verification failed or timed out")
        yield {"status": "scanned"}

        # 4. Verify certificate or PIN
        cert = self._load_cert()
        try:
            if cert:
                self.transport.call(
                    "verifyCertificate",
                    [[12, 1, [[11, 1, session_id], [11, 2, cert]]]],
                    endpoint=self.config.SQR_ENDPOINT,
                    protocol="binary",
                )
                yield {"status": "certificate_verified"}
            else:
                raise Exception("No cert")
        except Exception:
            # Need PIN code
            resp = self.transport.call(
                "createPinCode",
                [[12, 1, [[11, 1, session_id]]]],
                endpoint=self.config.SQR_ENDPOINT,
                protocol="binary",
            )
            pin = resp.get(1)
            yield {"status": "pin_required", "pin": pin}

            # Wait for PIN verification
            self._check_pin_verified(session_id)
            yield {"status": "pin_verified"}

        # 5. Login
        resp = self.transport.call(
            "qrCodeLoginV2",
            [[12, 1, [
                [11, 1, session_id],
                [11, 2, self.config.SYSTEM_NAME],
                [11, 3, self.config.DEVICE_TYPE],
                [2, 4, True],  # autoLoginIsRequired
            ]]],
            endpoint=self.config.SQR_ENDPOINT,
            protocol="binary",
        )

        # Extract results
        cert_new = resp.get(1)
        if cert_new:
            self._save_cert(cert_new)

        token_v3 = resp.get(3)
        mid = resp.get(4)
        metadata = resp.get(10)

        if token_v3:
            auth_token = token_v3.get(1) if isinstance(token_v3, dict) else None
            refresh_token = token_v3.get(2) if isinstance(token_v3, dict) else None
        else:
            # Fallback to v1 response
            auth_token = resp.get(2)
            refresh_token = None

        if metadata and secret:
            try:
                self.e2ee.decode_e2ee_key(metadata, secret, mid)
            except Exception as e:
                yield {"status": "e2ee_warning", "message": str(e)}

        if refresh_token:
            self._save_refresh_token(auth_token, refresh_token)

        yield {
            "status": "logged_in",
            "auth_token": auth_token,
            "refresh_token": refresh_token,
            "mid": mid,
        }

    def _check_qr_verified(self, session_id: str) -> bool:
        try:
            self.transport.long_poll(
                "checkQrCodeVerified",
                [[12, 1, [[11, 1, session_id]]]],
                endpoint=self.config.SQR_POLL_ENDPOINT,
                access_token=session_id,
            )
            return True
        except Exception as e:
            print(f"[checkQrCodeVerified] {e}")
            return False

    def _check_pin_verified(self, session_id: str) -> bool:
        try:
            self.transport.long_poll(
                "checkPinCodeVerified",
                [[12, 1, [[11, 1, session_id]]]],
                endpoint=self.config.SQR_POLL_ENDPOINT,
                access_token=session_id,
            )
            return True
        except Exception as e:
            print(f"[checkPinCodeVerified] {e}")
            return False

    def _load_cert(self) -> str | None:
        cert_path = CACHE_DIR / "sqr_cert"
        if cert_path.exists():
            return cert_path.read_text().strip()
        return None

    def _save_cert(self, cert: str):
        CACHE_DIR.mkdir(parents=True, exist_ok=True)
        (CACHE_DIR / "sqr_cert").write_text(cert)

    def _save_refresh_token(self, auth_token: str, refresh_token: str):
        CACHE_DIR.mkdir(parents=True, exist_ok=True)
        tokens_path = CACHE_DIR / "tokens.json"
        tokens = {}
        if tokens_path.exists():
            tokens = json.loads(tokens_path.read_text())
        tokens[auth_token] = refresh_token
        tokens_path.write_text(json.dumps(tokens))
