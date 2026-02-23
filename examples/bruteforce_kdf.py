#!/usr/bin/env python3
"""
Brute-force the LINE HMAC KDF algorithm.

Capture a real request from the LINE Chrome extension (via Network tab):
  - X-Hmac header value
  - accessToken (from Authorization header, strip "Bearer ")
  - Request path (e.g. /api/v4/something)
  - Request body (JSON string, or empty string if GET)

Then run:
  python bruteforce_kdf.py --token YOUR_ACCESS_TOKEN --path /api/v4/... --body '{"key":"val"}' --hmac CAPTURED_XHMAC

It tries every reasonable KDF combo to find what produces a matching HMAC.
"""

import argparse
import hashlib
import hmac
import base64
import struct

# Static secrets from the extension
TOKENS = {
    "chrome": "YOUR_CHROME_TOKEN_HERE",
    "edge": "GS-30Ed0WxiXR50y9hED4O1qmJ2QaBK0dFpc_w9ZaBSisb2rlnKvPUkMK_93GS30",
}
VERSION = "3.7.1"


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def hmac_sha256(key: bytes, msg: bytes) -> bytes:
    return hmac.new(key, msg, hashlib.sha256).digest()


def hkdf_extract(salt: bytes, ikm: bytes) -> bytes:
    """HKDF-Extract: PRK = HMAC-SHA256(salt, IKM)"""
    return hmac_sha256(salt, ikm)


def hkdf_expand(prk: bytes, info: bytes, length: int = 32) -> bytes:
    """HKDF-Expand"""
    n = (length + 31) // 32
    okm = b""
    prev = b""
    for i in range(1, n + 1):
        prev = hmac_sha256(prk, prev + info + bytes([i]))
        okm += prev
    return okm[:length]


def b64url_decode(s: str) -> bytes:
    """Decode base64url (no padding)."""
    s = s.replace("-", "+").replace("_", "/")
    pad = 4 - len(s) % 4
    if pad != 4:
        s += "=" * pad
    return base64.b64decode(s)


def try_kdf(name: str, secret_bytes: bytes, version_hash: bytes, token_hash: bytes) -> bytes:
    """Try a KDF variant and return the derived key."""
    
    if name == "hkdf(salt=ver, ikm=secret, info=token)":
        prk = hkdf_extract(version_hash, secret_bytes)
        return hkdf_expand(prk, token_hash)
    
    elif name == "hkdf(salt=secret, ikm=ver, info=token)":
        prk = hkdf_extract(secret_bytes, version_hash)
        return hkdf_expand(prk, token_hash)
    
    elif name == "hkdf(salt=ver, ikm=token_hash, info=secret)":
        prk = hkdf_extract(version_hash, token_hash)
        return hkdf_expand(prk, secret_bytes)
    
    elif name == "hkdf(salt=token, ikm=secret, info=ver)":
        prk = hkdf_extract(token_hash, secret_bytes)
        return hkdf_expand(prk, version_hash)
    
    elif name == "hmac(secret, ver+token)":
        return hmac_sha256(secret_bytes, version_hash + token_hash)
    
    elif name == "hmac(secret, token+ver)":
        return hmac_sha256(secret_bytes, token_hash + version_hash)
    
    elif name == "hmac(ver, secret+token)":
        return hmac_sha256(version_hash, secret_bytes + token_hash)
    
    elif name == "hmac(ver, token+secret)":
        return hmac_sha256(version_hash, token_hash + secret_bytes)
    
    elif name == "hmac(token, ver+secret)":
        return hmac_sha256(token_hash, version_hash + secret_bytes)
    
    elif name == "hmac(token, secret+ver)":
        return hmac_sha256(token_hash, secret_bytes + version_hash)
    
    elif name == "hmac(hmac(ver,secret), token)":
        k = hmac_sha256(version_hash, secret_bytes)
        return hmac_sha256(k, token_hash)
    
    elif name == "hmac(hmac(secret,ver), token)":
        k = hmac_sha256(secret_bytes, version_hash)
        return hmac_sha256(k, token_hash)
    
    elif name == "hmac(hmac(ver,token), secret)":
        k = hmac_sha256(version_hash, token_hash)
        return hmac_sha256(k, secret_bytes)
    
    elif name == "sha256(secret+ver+token)":
        return sha256(secret_bytes + version_hash + token_hash)
    
    elif name == "sha256(ver+token+secret)":
        return sha256(version_hash + token_hash + secret_bytes)
    
    # deriveKey(lS, sha256(accessToken)) — lS is first arg, token_hash is second
    # Maybe it's just HMAC with the loadToken result as key
    elif name == "hmac(loadToken(secret), ver_hash XOR token_hash)":
        xored = bytes(a ^ b for a, b in zip(version_hash, token_hash))
        return hmac_sha256(secret_bytes, xored)
    
    elif name == "direct: hmac(secret, token)":
        return hmac_sha256(secret_bytes, token_hash)
    
    elif name == "direct: hmac(ver, token)":
        return hmac_sha256(version_hash, token_hash)
    
    elif name == "hkdf(salt=ver, ikm=secret+token)":
        prk = hkdf_extract(version_hash, secret_bytes + token_hash)
        return hkdf_expand(prk, b"")
    
    elif name == "hkdf_no_info(salt=ver, ikm=secret)_expand(token)":
        prk = hkdf_extract(version_hash, secret_bytes)
        return hkdf_expand(prk, token_hash)
    
    return b""


def main():
    parser = argparse.ArgumentParser(description="Brute-force LINE HMAC KDF")
    parser.add_argument("--token", required=True, help="accessToken from Authorization header")
    parser.add_argument("--path", required=True, help="Request path (e.g. /api/v4/...)")
    parser.add_argument("--body", default="", help="Request body (JSON string)")
    parser.add_argument("--hmac", required=True, help="Captured X-Hmac header value")
    parser.add_argument("--origin", default="chrome", choices=["chrome", "edge"])
    args = parser.parse_args()

    static_token = TOKENS[args.origin]
    version_hash = sha256(VERSION.encode())
    token_hash = sha256(args.token.encode())
    message = (args.path + args.body).encode()
    target_hmac = args.hmac

    # Try both raw and base64url-decoded secret
    secret_variants = {
        "raw_utf8": static_token.encode(),
        "b64url_decoded": b64url_decode(static_token),
    }

    kdf_names = [
        "hkdf(salt=ver, ikm=secret, info=token)",
        "hkdf(salt=secret, ikm=ver, info=token)",
        "hkdf(salt=ver, ikm=token_hash, info=secret)",
        "hkdf(salt=token, ikm=secret, info=ver)",
        "hmac(secret, ver+token)",
        "hmac(secret, token+ver)",
        "hmac(ver, secret+token)",
        "hmac(ver, token+secret)",
        "hmac(token, ver+secret)",
        "hmac(token, secret+ver)",
        "hmac(hmac(ver,secret), token)",
        "hmac(hmac(secret,ver), token)",
        "hmac(hmac(ver,token), secret)",
        "sha256(secret+ver+token)",
        "sha256(ver+token+secret)",
        "hmac(loadToken(secret), ver_hash XOR token_hash)",
        "direct: hmac(secret, token)",
        "direct: hmac(ver, token)",
        "hkdf(salt=ver, ikm=secret+token)",
        "hkdf_no_info(salt=ver, ikm=secret)_expand(token)",
    ]

    print(f"Version hash: {version_hash.hex()}")
    print(f"Token hash:   {token_hash.hex()[:32]}...")
    print(f"Message:      {args.path + args.body[:50]}...")
    print(f"Target HMAC:  {target_hmac}")
    print(f"\nTrying {len(kdf_names) * len(secret_variants)} combinations...\n")

    for sec_name, secret_bytes in secret_variants.items():
        for kdf_name in kdf_names:
            try:
                derived_key = try_kdf(kdf_name, secret_bytes, version_hash, token_hash)
                if not derived_key:
                    continue

                # Try HMAC-SHA256 with the derived key
                sig = hmac_sha256(derived_key, message)

                # Try different encodings of the signature
                candidates = {
                    "base64": base64.b64encode(sig).decode(),
                    "base64url": base64.urlsafe_b64encode(sig).decode().rstrip("="),
                    "hex": sig.hex(),
                }

                for enc_name, candidate in candidates.items():
                    if candidate == target_hmac:
                        print(f"{'='*60}")
                        print(f"  MATCH FOUND!")
                        print(f"  Secret:   {sec_name}")
                        print(f"  KDF:      {kdf_name}")
                        print(f"  Encoding: {enc_name}")
                        print(f"  Key:      {derived_key.hex()}")
                        print(f"  HMAC:     {candidate}")
                        print(f"{'='*60}")
                        return
            except Exception as e:
                pass

    print("No match found. The KDF might be more exotic (custom WASM logic).")
    print("Consider decompiling the .wasm binary next.")


if __name__ == "__main__":
    main()
