#!/usr/bin/env python3
"""
Brute-force LINE HMAC KDF v2 — tries more path/body variants and KDF combos.
"""

import hashlib
import hmac
import base64
import itertools

# Static secrets
CHROME_TOKEN = "wODdrvWqmdP4Zliay-iF3cz3KZcK0ekrial868apg06TXeCo7A1hIQO0ESElHg6D"
VERSION = "3.7.1"

ACCESS_TOKEN = "***REDACTED_TOKEN***"

TARGET_HMAC = "***REDACTED_HMAC***"

BODY_RAW = '[2027297402,{"from":"***REDACTED_MID***","to":"***REDACTED_MID_2***","toType":0,"id":"local-2027297402","createdTime":"1771850938000","sessionId":0,"text":"hello","contentType":0,"contentMetadata":{},"hasContent":false}]'

def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()

def hmac_sha256(key: bytes, msg: bytes) -> bytes:
    return hmac.new(key, msg, hashlib.sha256).digest()

def hkdf_extract(salt: bytes, ikm: bytes) -> bytes:
    return hmac_sha256(salt, ikm)

def hkdf_expand(prk: bytes, info: bytes, length: int = 32) -> bytes:
    n = (length + 31) // 32
    okm = b""
    prev = b""
    for i in range(1, n + 1):
        prev = hmac_sha256(prk, prev + info + bytes([i]))
        okm += prev
    return okm[:length]

def b64url_decode(s: str) -> bytes:
    s = s.replace("-", "+").replace("_", "/")
    pad = 4 - len(s) % 4
    if pad != 4:
        s += "=" * pad
    return base64.b64decode(s)

def check(derived_key: bytes, message: bytes, label: str):
    sig = hmac_sha256(derived_key, message)
    b64 = base64.b64encode(sig).decode()
    b64url = base64.urlsafe_b64encode(sig).decode().rstrip("=")
    
    if b64 == TARGET_HMAC or b64url == TARGET_HMAC:
        print(f"\n{'='*60}")
        print(f"  MATCH! {label}")
        print(f"  Key: {derived_key.hex()}")
        print(f"  Sig: {b64}")
        print(f"  Msg: {message[:100]}")
        print(f"{'='*60}")
        return True
    return False

def main():
    ver_hash = sha256(VERSION.encode())
    tok_hash = sha256(ACCESS_TOKEN.encode())
    secret_raw = CHROME_TOKEN.encode()
    secret_b64 = b64url_decode(CHROME_TOKEN)

    # Different path interpretations
    paths = [
        "/api/talk/thrift/Talk/TalkService/sendMessage",
        "/talk/thrift/Talk/TalkService/sendMessage",
        "/S4",
        "/TalkService/sendMessage",
        "api/talk/thrift/Talk/TalkService/sendMessage",
        "https://line-chrome-gw.line-apps.com/api/talk/thrift/Talk/TalkService/sendMessage",
    ]
    
    # Different body interpretations
    bodies = [
        BODY_RAW,
        "",  # maybe body is excluded
        "null",
    ]

    secrets = {"raw": secret_raw, "b64dec": secret_b64}
    
    # KDF variants
    def kdfs(sec):
        return {
            # HKDF variants
            "hkdf(s=ver,i=sec,info=tok)": hkdf_expand(hkdf_extract(ver_hash, sec), tok_hash),
            "hkdf(s=sec,i=ver,info=tok)": hkdf_expand(hkdf_extract(sec, ver_hash), tok_hash),
            "hkdf(s=ver,i=tok,info=sec)": hkdf_expand(hkdf_extract(ver_hash, tok_hash), sec[:32] if len(sec)>32 else sec),
            "hkdf(s=tok,i=sec,info=ver)": hkdf_expand(hkdf_extract(tok_hash, sec), ver_hash),
            "hkdf(s=sec,i=tok,info=ver)": hkdf_expand(hkdf_extract(sec, tok_hash), ver_hash),
            # HMAC chains
            "hmac(sec, ver+tok)": hmac_sha256(sec, ver_hash + tok_hash),
            "hmac(sec, tok+ver)": hmac_sha256(sec, tok_hash + ver_hash),
            "hmac(ver, sec+tok)": hmac_sha256(ver_hash, sec + tok_hash),
            "hmac(ver, tok+sec)": hmac_sha256(ver_hash, tok_hash + sec),
            "hmac(tok, ver+sec)": hmac_sha256(tok_hash, ver_hash + sec),
            "hmac(tok, sec+ver)": hmac_sha256(tok_hash, sec + ver_hash),
            "hmac(hmac(ver,sec),tok)": hmac_sha256(hmac_sha256(ver_hash, sec), tok_hash),
            "hmac(hmac(sec,ver),tok)": hmac_sha256(hmac_sha256(sec, ver_hash), tok_hash),
            "hmac(hmac(ver,tok),sec)": hmac_sha256(hmac_sha256(ver_hash, tok_hash), sec),
            "hmac(hmac(tok,ver),sec)": hmac_sha256(hmac_sha256(tok_hash, ver_hash), sec),
            "hmac(hmac(sec,tok),ver)": hmac_sha256(hmac_sha256(sec, tok_hash), ver_hash),
            "hmac(hmac(tok,sec),ver)": hmac_sha256(hmac_sha256(tok_hash, sec), ver_hash),
            # Direct
            "hmac(sec, tok)": hmac_sha256(sec, tok_hash),
            "hmac(tok, sec)": hmac_sha256(tok_hash, sec),
            "hmac(ver, tok)": hmac_sha256(ver_hash, tok_hash),
            "hmac(tok, ver)": hmac_sha256(tok_hash, ver_hash),
            # XOR
            "hmac(sec, ver^tok)": hmac_sha256(sec, bytes(a^b for a,b in zip(ver_hash, tok_hash))),
            # Just the secret as key directly
            "just_sec": sec[:32] if len(sec)>=32 else sec + b'\x00'*(32-len(sec)),
            "just_ver": ver_hash,
            "just_tok": tok_hash,
            # sha256 combos
            "sha256(sec+ver+tok)": sha256(sec + ver_hash + tok_hash),
            "sha256(ver+sec+tok)": sha256(ver_hash + sec + tok_hash),
            "sha256(ver+tok+sec)": sha256(ver_hash + tok_hash + sec),
        }

    total = 0
    found = False
    
    for sec_name, sec in secrets.items():
        for kdf_name, derived_key in kdfs(sec).items():
            for path in paths:
                for body in bodies:
                    msg = (path + body).encode()
                    label = f"secret={sec_name} kdf={kdf_name} path={path[:40]} body={'empty' if not body else body[:20]+'...'}"
                    total += 1
                    if check(derived_key, msg, label):
                        found = True
                        # Keep going to see if multiple match

    if not found:
        print(f"\nNo match in {total} attempts.")
        print("Next step: decompile the .wasm binary.")

if __name__ == "__main__":
    main()
