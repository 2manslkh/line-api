"""
E2EE crypto operations for LINE.

LINE uses Curve25519 for key exchange and AES-GCM for message encryption.
"""

import os
import hashlib
import base64
import json
from pathlib import Path

try:
    import axolotl_curve25519 as Curve25519
    HAS_CURVE25519 = True
except ImportError:
    HAS_CURVE25519 = False

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    HAS_AESGCM = True
except ImportError:
    HAS_AESGCM = False

try:
    from Crypto.Cipher import AES
    from Crypto.Util.Padding import pad, unpad
    HAS_PYCRYPTO = True
except ImportError:
    HAS_PYCRYPTO = False


CACHE_DIR = Path.home() / ".line-client"
E2EE_KEYS_DIR = CACHE_DIR / "e2ee_keys"


class E2EECrypto:
    """Handles E2EE key exchange and message encryption/decryption."""

    def __init__(self):
        self._key_store = {}  # mid -> {keyId, pubKey, privKey}
        self._load_keys()

    def create_sqr_secret(self) -> tuple[bytes, bytes]:
        """
        Generate Curve25519 keypair for SQR login.
        Returns (private_key, public_key).
        """
        if not HAS_CURVE25519:
            # Fallback: generate random bytes (won't work for actual E2EE)
            private = os.urandom(32)
            return private, private  # placeholder

        private = os.urandom(32)
        # Curve25519 key clamping
        private = bytearray(private)
        private[0] &= 248
        private[31] &= 127
        private[31] |= 64
        private = bytes(private)

        public = Curve25519.generatePublicKey(private)
        return private, public

    def generate_shared_secret(self, private_key: bytes, public_key: bytes) -> bytes:
        """Compute Curve25519 shared secret."""
        if not HAS_CURVE25519:
            raise RuntimeError("axolotl_curve25519 not installed")
        if isinstance(public_key, str):
            public_key = base64.b64decode(public_key)
        return Curve25519.calculateAgreement(private_key, public_key)

    @staticmethod
    def sha256(data: bytes, suffix: bytes = b"") -> bytes:
        h = hashlib.sha256()
        h.update(data)
        if suffix:
            h.update(suffix)
        return h.digest()

    @staticmethod
    def encrypt_aes_ecb(key: bytes, data: bytes) -> str:
        """AES-ECB encrypt and return base64."""
        if not HAS_PYCRYPTO:
            raise RuntimeError("pycryptodome not installed")
        cipher = AES.new(key[:16], AES.MODE_ECB)
        padded = pad(data, AES.block_size)
        encrypted = cipher.encrypt(padded)
        return base64.b64encode(encrypted).decode()

    def encrypt_aes_gcm(self, key: bytes, plaintext: bytes, aad: bytes = b"") -> tuple[bytes, bytes, bytes]:
        """AES-GCM encrypt. Returns (nonce, ciphertext, tag)."""
        if not HAS_AESGCM:
            raise RuntimeError("cryptography not installed")
        nonce = os.urandom(12)
        aesgcm = AESGCM(key)
        ct = aesgcm.encrypt(nonce, plaintext, aad)
        # ct includes tag at the end (last 16 bytes)
        return nonce, ct[:-16], ct[-16:]

    def decrypt_aes_gcm(self, key: bytes, nonce: bytes, ciphertext: bytes, tag: bytes, aad: bytes = b"") -> bytes:
        """AES-GCM decrypt."""
        if not HAS_AESGCM:
            raise RuntimeError("cryptography not installed")
        aesgcm = AESGCM(key)
        return aesgcm.decrypt(nonce, ciphertext + tag, aad)

    def decode_e2ee_key(self, metadata: dict, secret: bytes, mid: str | None = None):
        """
        Decode E2EE key from login metadata and store it.
        """
        if isinstance(metadata, str):
            metadata = json.loads(metadata)

        public_key = metadata.get("publicKey")
        encrypted_key_chain = metadata.get("encryptedKeyChain")
        key_id = metadata.get("keyId") or metadata.get("specVersion")

        if public_key and secret:
            try:
                shared = self.generate_shared_secret(secret, base64.b64decode(public_key))
                aes_key = self.sha256(shared, b"Key")
                # Store the derived key
                if mid:
                    self._key_store[mid] = {
                        "keyId": key_id,
                        "pubKey": public_key,
                        "sharedKey": base64.b64encode(aes_key).decode(),
                    }
                    self._save_keys()
            except Exception as e:
                print(f"[E2EE] Failed to decode key: {e}")

    def encrypt_device_secret(self, public_key: bytes, secret: bytes, encrypted_key_chain: bytes) -> bytes:
        """Encrypt device secret for E2EE login confirmation."""
        shared = self.generate_shared_secret(secret, public_key)
        aes_key = self.sha256(shared, b"Key")
        aes_iv = self._xor(self.sha256(shared, b"IV"))

        if not HAS_PYCRYPTO:
            raise RuntimeError("pycryptodome not installed")

        cipher = AES.new(aes_key, AES.MODE_CBC, aes_iv)
        return cipher.encrypt(pad(encrypted_key_chain, AES.block_size))

    @staticmethod
    def _xor(data: bytes) -> bytes:
        """XOR first 16 bytes with last 16 bytes of 32-byte input."""
        return bytes(a ^ b for a, b in zip(data[:16], data[16:]))

    def _load_keys(self):
        keys_file = E2EE_KEYS_DIR / "keys.json"
        if keys_file.exists():
            try:
                self._key_store = json.loads(keys_file.read_text())
            except Exception:
                self._key_store = {}

    def _save_keys(self):
        E2EE_KEYS_DIR.mkdir(parents=True, exist_ok=True)
        (E2EE_KEYS_DIR / "keys.json").write_text(json.dumps(self._key_store, indent=2))
