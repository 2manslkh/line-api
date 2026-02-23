"""
HTTP/2 transport layer for LINE API communication.

LINE supports two transport modes:
- encType=0: Direct POST to gwz.line.naver.jp (no body encryption)
- encType=1: Encrypted POST to gf.line.naver.jp/enc (AES-CBC body, RSA key in x-lcs)
"""

import os
import base64
import httpx
import requests
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

from ..config import LineConfig
from ..thrift.protocol import TCompactProtocol, TBinaryProtocol


# LINE's public key for encrypting the AES session key
LINE_PUBLIC_KEY = """-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0LRokSkGDo8G5ObFfyKi
IdPAU5iOpj+UT+A3AcDxLuePyDt8IVp9HpOsJlf8uVk3Wr9fs+8y7cnF3WiY6Ro
526hy3fbWR4HiD0FaIRCOTbgRlsoGNC2rthp2uxYad5up78krSDXNKBab8t1PteCm
Oq84TpDCRmainaZQN9QxzaSvYWUICVv27Kk97y2j3LS3H64NCqjS88XacAieivEL
fMr6rT2GutRshKeNSZOUR3YROV4THa77USBQwRI7ZZTe6GUFazpocTN58QY8jFYO
Dzfhdyoiym6rXJNNnUKatiSC/hmzdpX8/h4Y98KaGAZaatLAgPMRCe582q4JwHg7
rwIDAQAB
-----END PUBLIC KEY-----"""

# Fixed IV used by LINE
LINE_IV = bytes([78, 9, 72, 62, 56, 245, 255, 114, 128, 18, 123, 158, 251, 92, 45, 51])


class LineTransport:
    """Handles HTTP communication with LINE servers."""

    def __init__(self, config: LineConfig, enc_type: int = 1):
        self.config = config
        self.enc_type = enc_type
        self.auth_token: str | None = None

        # HTTP/2 for direct mode (encType=0)
        self._h2 = httpx.Client(http2=True, timeout=300)
        # HTTP/1.1 for encrypted mode (encType=1) and long-polling
        self._h1 = requests.Session()

        # Encryption setup (encType=1)
        self._aes_key = os.urandom(16)
        self._rsa_key = RSA.import_key(LINE_PUBLIC_KEY)
        self._enc_key_header = self._encrypt_aes_key()

        # x-le value: controls encryption features
        # 18 = default for CHROMEOS (binary: 10010 → bit4=hmac, bit1=base)
        self.le = "18"

    def _encrypt_aes_key(self) -> str:
        """RSA-encrypt the AES key and format as x-lcs header value."""
        cipher = PKCS1_OAEP.new(self._rsa_key)
        encrypted = cipher.encrypt(self._aes_key)
        return "0005" + base64.b64encode(encrypted).decode()

    def _aes_encrypt(self, data: bytes) -> bytes:
        """AES-CBC encrypt request data."""
        cipher = AES.new(self._aes_key, AES.MODE_CBC, iv=LINE_IV)
        return cipher.encrypt(pad(data, AES.block_size))

    def _aes_decrypt(self, data: bytes) -> bytes:
        """AES-CBC decrypt response data."""
        cipher = AES.new(self._aes_key, AES.MODE_CBC, iv=LINE_IV)
        return unpad(cipher.decrypt(data), AES.block_size)

    def _encode_enc_headers(self, headers: dict) -> bytes:
        """Encode extra headers for encrypted transport (x-lt, x-lpqs)."""
        # Format: repeated [key_len(2B) + key + value_len(2B) + value]
        result = bytearray()
        for k, v in headers.items():
            k_bytes = k.encode('utf-8')
            v_bytes = v.encode('utf-8')
            result += len(k_bytes).to_bytes(2, 'big')
            result += k_bytes
            result += len(v_bytes).to_bytes(2, 'big')
            result += v_bytes
        # Prepend total count
        header_count = len(headers).to_bytes(2, 'big')
        return bytes(header_count) + bytes(result)

    @property
    def base_headers(self) -> dict:
        headers = {
            "x-line-application": self.config.app_name,
            "x-lal": self.config.LANGUAGE,
            "x-lpv": "1",
            "x-lhm": "POST",
            "User-Agent": self.config.user_agent,
            "content-type": "application/x-thrift; protocol=TBINARY",
            "accept": "application/x-thrift",
        }
        if self.enc_type == 1:
            headers["x-le"] = self.le
            headers["x-lcs"] = self._enc_key_header
            # ChromeOS origin
            headers["origin"] = "chrome-extension://CHRLINE-custom"
        return headers

    def call(
        self,
        method: str,
        params: list,
        endpoint: str | None = None,
        protocol: str = "compact",
        extra_headers: dict | None = None,
        use_h1: bool = False,
        access_token: str | None = None,
        enc_type: int | None = None,
    ) -> dict:
        """
        Make a Thrift RPC call.
        """
        if enc_type is None:
            enc_type = self.enc_type

        # Serialize thrift
        if protocol == "compact":
            ptype = "TCOMPACT"
            thrift_data = TCompactProtocol.write_request(method, params)
            endpoint = endpoint or self.config.TALK_ENDPOINT
        else:
            ptype = "TBINARY"
            thrift_data = TBinaryProtocol.write_request(method, params)
            endpoint = endpoint or self.config.TALK_BINARY_ENDPOINT

        headers = self.base_headers.copy()
        headers["content-type"] = f"application/x-thrift; protocol={ptype}"

        token = access_token or self.auth_token
        if extra_headers:
            headers.update(extra_headers)

        if enc_type == 0:
            # ── Direct mode ──
            if "x-le" in headers:
                del headers["x-le"]
            if "x-lcs" in headers:
                del headers["x-lcs"]
            if token:
                headers["X-Line-Access"] = token

            url = self.config.GW_HOST + endpoint
            if use_h1:
                resp = self._h1.post(url, data=thrift_data, headers=headers)
            else:
                resp = self._h2.post(url, content=thrift_data, headers=headers)

            body = resp.content

        elif enc_type == 1:
            # ── Encrypted mode ──
            enc_headers = {}
            if token:
                enc_headers["x-lt"] = token
            enc_headers["x-lpqs"] = endpoint

            header_bytes = self._encode_enc_headers(enc_headers)
            payload = header_bytes + thrift_data

            # Prepend LE byte if bit 2 is set
            le_val = int(self.le)
            if (le_val & 4) == 4:
                payload = bytes([le_val]) + payload

            encrypted = self._aes_encrypt(payload)

            # Add HMAC if bit 1 is set (le & 2)
            if (le_val & 2) == 2:
                import hmac
                import hashlib
                h = hmac.new(self._aes_key, encrypted, hashlib.sha256).digest()
                encrypted = encrypted + h

            headers["accept-encoding"] = "gzip, deflate"
            url = self.config.GF_HOST + self.config.ENCRYPTION_ENDPOINT

            if use_h1:
                resp = self._h1.post(url, data=encrypted, headers=headers)
            else:
                # Use h1 for encrypted mode (like CHRLINE does)
                resp = self._h1.post(url, data=encrypted, headers=headers)

            if resp.content:
                body = self._aes_decrypt(resp.content)
                # Strip LE byte if we prepended one
                if (le_val & 4) == 4:
                    body = body[1:]
            else:
                body = b""
        else:
            raise ValueError(f"Unknown enc_type: {enc_type}")

        if resp.status_code != 200:
            raise ConnectionError(
                f"HTTP {resp.status_code} on {endpoint}: {body[:200] if body else 'empty'}"
            )

        if not body:
            return {}

        if protocol == "compact":
            return TCompactProtocol.read_response(body)
        else:
            return TBinaryProtocol.read_response(body)

    def call_binary(self, method: str, params: list, endpoint: str | None = None, **kwargs) -> dict:
        return self.call(method, params, endpoint=endpoint, protocol="binary", **kwargs)

    def long_poll(
        self,
        method: str,
        params: list,
        endpoint: str,
        timeout_ms: int = 150000,
        access_token: str | None = None,
    ) -> dict:
        return self.call(
            method, params,
            endpoint=endpoint,
            protocol="binary",
            extra_headers={"x-lst": str(timeout_ms)},
            use_h1=True,
            access_token=access_token,
        )

    def close(self):
        self._h2.close()
        self._h1.close()
