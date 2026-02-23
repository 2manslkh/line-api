"""
Email/password login for LINE.

Flow:
1. getRSAKeyInfo() → RSA public key + session key
2. Encrypt (sessionKey + email + password) with RSA
3. loginV2() with encrypted data + E2EE secret
4. If PIN required: wait for PIN verification
5. confirmE2EELogin() → auth token
"""

import rsa
import binascii
import base64
from ..transport.http import LineTransport
from ..config import LineConfig
from ..e2ee.crypto import E2EECrypto


class EmailLogin:
    def __init__(self, transport: LineTransport, config: LineConfig):
        self.transport = transport
        self.config = config
        self.e2ee = E2EECrypto()

    def login(self, email: str, password: str):
        """
        Generator that yields status messages during email login.
        Final yield contains the auth token.
        """
        # 1. Get RSA key
        resp = self.transport.call(
            "getRSAKeyInfo",
            [[8, 2, 1]],  # provider=LINE
            endpoint=self.config.RSA_KEY_ENDPOINT,
            protocol="binary",
        )
        keynm = resp.get(1)
        nvalue = resp.get(2)
        evalue = resp.get(3)
        session_key = resp.get(4)

        yield {"status": "rsa_key_received"}

        # 2. Encrypt credentials
        message = (
            chr(len(session_key)) + session_key +
            chr(len(email)) + email +
            chr(len(password)) + password
        ).encode("utf-8")
        pub_key = rsa.PublicKey(int(nvalue, 16), int(evalue, 16))
        encrypted = binascii.hexlify(rsa.encrypt(message, pub_key)).decode()

        # 3. Create E2EE secret
        secret, secret_pk = self.e2ee.create_sqr_secret()
        pincode = b"202202"
        e2ee_secret = self.e2ee.encrypt_aes_ecb(
            self.e2ee.sha256(pincode),
            base64.b64decode(secret_pk) if isinstance(secret_pk, (str, bytes)) else secret_pk,
        )

        yield {"status": "credentials_encrypted"}

        # 4. Login
        cert = self._load_email_cert(email)
        params = [[12, 2, [
            [8, 1, 2],       # loginType: 2 = with secret
            [8, 2, 1],       # provider: LINE
            [11, 3, keynm],
            [11, 4, encrypted],
            [2, 5, False],
            [11, 6, ""],
            [11, 7, self.config.SYSTEM_NAME],
            [11, 8, cert],
            [11, 9, None],   # verifier
            [11, 10, e2ee_secret],
            [8, 11, 1],
            [11, 12, "System Product Name"],
        ]]]

        try:
            resp = self.transport.call(
                "loginV2", params,
                endpoint=self.config.AUTH_ENDPOINT,
                protocol="binary",
            )
        except Exception as e:
            # Code 89 = E2EE not supported, retry without
            yield {"status": "login_error", "error": str(e)}
            return

        # Check if we got token directly
        if resp.get(9):
            # TokenV3 response
            token_info = resp[9]
            auth_token = token_info.get(1)
            refresh_token = token_info.get(2)
            yield {
                "status": "logged_in",
                "auth_token": auth_token,
                "refresh_token": refresh_token,
            }
            return

        if resp.get(1):
            # Direct token
            auth_token = resp[1]
            self._save_email_cert(email, resp.get(2))
            yield {"status": "logged_in", "auth_token": auth_token}
            return

        # PIN verification needed
        verifier = resp.get(3)
        yield {"status": "pin_required", "pin": pincode.decode()}

        # Wait for PIN verification (e2ee)
        from ..thrift.protocol import ThriftException
        try:
            verify_resp = self.transport.long_poll(
                "", [],
                endpoint=self.config.SECONDARY_LOGIN_VERIFY_E2EE,
                access_token=verifier,
            )
            # Process E2EE info from verification
            e2ee_info = verify_resp.get("metadata", {})
            if e2ee_info:
                self.e2ee.decode_e2ee_key(e2ee_info, secret)
                device_secret = self.e2ee.encrypt_device_secret(
                    base64.b64decode(e2ee_info["publicKey"]),
                    secret,
                    base64.b64decode(e2ee_info["encryptedKeyChain"]),
                )
                e2ee_login = self._confirm_e2ee_login(verifier, device_secret)
            else:
                e2ee_login = verify_resp.get("verifier")
        except Exception as e:
            yield {"status": "verification_error", "error": str(e)}
            return

        # Final login with verifier
        params[0][2][0] = [8, 1, 1]   # loginType: 1 = with verifier
        params[0][2][8] = [11, 9, e2ee_login]  # set verifier
        resp = self.transport.call(
            "loginV2", params,
            endpoint=self.config.AUTH_ENDPOINT,
            protocol="binary",
        )

        auth_token = resp.get(1)
        self._save_email_cert(email, resp.get(2))
        yield {"status": "logged_in", "auth_token": auth_token}

    def _confirm_e2ee_login(self, verifier: str, device_secret: bytes) -> str:
        resp = self.transport.call(
            "confirmE2EELogin",
            [
                [11, 1, verifier],
                [11, 2, base64.b64encode(device_secret).decode()],
            ],
            endpoint=self.config.AUTH_ENDPOINT,
            protocol="binary",
        )
        return resp.get(1)

    def _load_email_cert(self, email: str) -> str | None:
        from .qr import CACHE_DIR
        cert_path = CACHE_DIR / f"email_cert_{email}"
        if cert_path.exists():
            return cert_path.read_text().strip()
        return None

    def _save_email_cert(self, email: str, cert: str | None):
        if not cert:
            return
        from .qr import CACHE_DIR
        CACHE_DIR.mkdir(parents=True, exist_ok=True)
        (CACHE_DIR / f"email_cert_{email}").write_text(cert)
