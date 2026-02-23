#!/usr/bin/env python3
"""
LINE QR Login via direct Thrift (no Chrome GW needed).
Based on CHRLINE reference implementation.

Usage:
    pip install requests qrcode pillow PyNaCl
    python login_thrift.py
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

LINE_HOST = "https://ga2.line.naver.jp"
LINE_LP_HOST = "https://ga2.line.naver.jp"  # long-poll same host
CACHE_DIR = Path.home() / ".line-client"

APP_NAME = "CHROMEOS\t3.7.1\tChrome OS\t1"

HEADERS = {
    "x-line-application": APP_NAME,
    "x-lap": "5",
    "x-lpv": "1",
    "x-lal": "en_US",
    "x-lhm": "POST",
    "content-type": "application/x-thrift; protocol=TBINARY",
    "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/145.0.0.0 Safari/537.36",
}


def write_thrift_string(buf, s):
    """Write a Thrift BINARY string (type 11)."""
    encoded = s.encode() if isinstance(s, str) else s
    buf += struct.pack(">i", len(encoded))
    buf += encoded


def make_thrift_call(method, params=None):
    """
    Build a TBinary Thrift call.
    params is a list of [type, field_id, value] or [type, field_id, [sub_fields]]
    """
    buf = bytearray()
    # Version + CALL type
    buf += b"\x80\x01\x00\x01"
    # Method name
    name = method.encode()
    buf += struct.pack(">i", len(name)) + name
    # Sequence ID
    buf += struct.pack(">i", 0)
    # Fields
    if params:
        for p in params:
            write_thrift_field(buf, p)
    # STOP
    buf += b"\x00"
    return bytes(buf)


def write_thrift_field(buf, field):
    """Write a Thrift field. field = [type, id, value]"""
    ftype, fid, value = field
    buf += struct.pack(">bh", ftype, fid)
    if ftype == 11:  # STRING
        write_thrift_string(buf, value)
    elif ftype == 2:  # BOOL
        buf += struct.pack(">b", 1 if value else 0)
    elif ftype == 8:  # I32
        buf += struct.pack(">i", value)
    elif ftype == 12:  # STRUCT
        for sub in value:
            write_thrift_field(buf, sub)
        buf += b"\x00"  # STOP


def parse_thrift_response(data):
    """Simple Thrift binary response parser — extracts string fields."""
    result = {}
    pos = 0
    
    # Skip version header (4 bytes)
    pos = 4
    
    # Read method name
    name_len = struct.unpack(">i", data[pos:pos+4])[0]
    pos += 4
    method = data[pos:pos+name_len].decode()
    pos += name_len
    result["_method"] = method
    
    # Skip seqid
    pos += 4
    
    # Parse fields recursively
    def read_fields(pos, depth=0):
        fields = {}
        while pos < len(data):
            if data[pos] == 0:  # STOP
                pos += 1
                break
            ftype = data[pos]
            fid = struct.unpack(">h", data[pos+1:pos+3])[0]
            pos += 3
            
            if ftype == 11:  # STRING
                slen = struct.unpack(">i", data[pos:pos+4])[0]
                pos += 4
                fields[fid] = data[pos:pos+slen]
                try:
                    fields[f"{fid}_str"] = data[pos:pos+slen].decode()
                except:
                    pass
                pos += slen
            elif ftype == 8:  # I32
                fields[fid] = struct.unpack(">i", data[pos:pos+4])[0]
                pos += 4
            elif ftype == 10:  # I64
                fields[fid] = struct.unpack(">q", data[pos:pos+8])[0]
                pos += 8
            elif ftype == 2:  # BOOL
                fields[fid] = data[pos] != 0
                pos += 1
            elif ftype == 12:  # STRUCT
                sub, pos = read_fields(pos, depth+1)
                fields[fid] = sub
            elif ftype == 15:  # LIST
                elem_type = data[pos]
                count = struct.unpack(">i", data[pos+1:pos+5])[0]
                pos += 5
                items = []
                for _ in range(count):
                    if elem_type == 11:
                        slen = struct.unpack(">i", data[pos:pos+4])[0]
                        pos += 4
                        items.append(data[pos:pos+slen])
                        pos += slen
                    elif elem_type == 12:
                        sub, pos = read_fields(pos, depth+1)
                        items.append(sub)
                    else:
                        break
                fields[fid] = items
            elif ftype == 13:  # MAP
                ktype = data[pos]
                vtype = data[pos+1]
                count = struct.unpack(">i", data[pos+2:pos+6])[0]
                pos += 6
                m = {}
                for _ in range(count):
                    if ktype == 11:
                        klen = struct.unpack(">i", data[pos:pos+4])[0]
                        pos += 4
                        k = data[pos:pos+klen].decode()
                        pos += klen
                    else:
                        k = str(_)
                    if vtype == 11:
                        vlen = struct.unpack(">i", data[pos:pos+4])[0]
                        pos += 4
                        v = data[pos:pos+vlen]
                        try: v = v.decode()
                        except: pass
                        pos += vlen
                    else:
                        v = None
                    m[k] = v
                fields[fid] = m
            else:
                # Unknown type, try to skip
                break
        return fields, pos
    
    fields, _ = read_fields(pos)
    result["fields"] = fields
    return result


def thrift_post(path, data, headers=None, timeout=10):
    """POST Thrift binary to LINE server."""
    h = {**HEADERS}
    if headers:
        h.update(headers)
    r = requests.post(LINE_HOST + path, data=data, headers=h, timeout=timeout)
    return r


def create_session():
    data = make_thrift_call("createSession")
    r = thrift_post("/acct/lgn/sq/v1", data)
    if r.status_code != 200:
        print(f"createSession failed: {r.status_code}")
        print(f"Body: {r.content[:200]}")
        sys.exit(1)
    parsed = parse_thrift_response(r.content)
    # Session ID is in field 1 of the result struct (field 0)
    result = parsed["fields"]
    # Navigate: field 0 (success result) -> field 1 (authSessionId)
    if 0 in result and isinstance(result[0], dict):
        session_id = result[0].get(1, result[0].get("1_str", ""))
        if isinstance(session_id, bytes):
            session_id = session_id.decode()
    elif 1 in result:
        session_id = result[1] if isinstance(result[1], str) else result.get("1_str", result[1].decode())
    else:
        print(f"Unexpected createSession response: {result}")
        sys.exit(1)
    return session_id


def create_qr_code(session_id):
    params = [
        [12, 1, [
            [11, 1, session_id],
        ]]
    ]
    data = make_thrift_call("createQrCode", params)
    r = thrift_post("/acct/lgn/sq/v1", data)
    if r.status_code != 200:
        print(f"createQrCode failed: {r.status_code}")
        print(f"Body: {r.content[:200]}")
        sys.exit(1)
    parsed = parse_thrift_response(r.content)
    result = parsed["fields"]
    # Field 0 (success) -> field 1 (callbackUrl)
    if 0 in result and isinstance(result[0], dict):
        url = result[0].get("1_str", "")
    else:
        print(f"Unexpected createQrCode response: {result}")
        sys.exit(1)
    return url


def check_qr_verified(session_id, timeout=15):
    params = [
        [12, 1, [
            [11, 1, session_id],
        ]]
    ]
    data = make_thrift_call("checkQrCodeVerified", params)
    headers = {
        "x-line-access": session_id,
        "x-lst": "150000",
    }
    try:
        r = requests.post(
            LINE_LP_HOST + "/acct/lp/lgn/sq/v1",
            data=data,
            headers={**HEADERS, **headers},
            timeout=timeout,
        )
        return r.status_code == 200
    except requests.exceptions.ReadTimeout:
        return False


def create_pin_code(session_id):
    params = [
        [12, 1, [
            [11, 1, session_id],
        ]]
    ]
    data = make_thrift_call("createPinCode", params)
    r = thrift_post("/acct/lgn/sq/v1", data)
    parsed = parse_thrift_response(r.content)
    result = parsed["fields"]
    if 0 in result and isinstance(result[0], dict):
        pin = result[0].get("1_str", "")
    else:
        pin = "???"
    return pin


def check_pin_verified(session_id, timeout=15):
    params = [
        [12, 1, [
            [11, 1, session_id],
        ]]
    ]
    data = make_thrift_call("checkPinCodeVerified", params)
    headers = {
        "x-line-access": session_id,
        "x-lst": "150000",
    }
    try:
        r = requests.post(
            LINE_LP_HOST + "/acct/lp/lgn/sq/v1",
            data=data,
            headers={**HEADERS, **headers},
            timeout=timeout,
        )
        return r.status_code == 200
    except requests.exceptions.ReadTimeout:
        return False


def verify_certificate(session_id, cert):
    params = [
        [12, 1, [
            [11, 1, session_id],
            [11, 2, cert],
        ]]
    ]
    data = make_thrift_call("verifyCertificate", params)
    r = thrift_post("/acct/lgn/sq/v1", data)
    return r.status_code == 200


def qr_code_login(session_id):
    params = [
        [12, 1, [
            [11, 1, session_id],
            [11, 2, "LINE for Chrome"],
            [2, 4, True],  # autoLoginIsRequired
        ]]
    ]
    data = make_thrift_call("qrCodeLoginV2", params)
    r = thrift_post("/acct/lgn/sq/v1", data)
    if r.status_code != 200:
        print(f"qrCodeLoginV2 failed: {r.status_code}")
        return None
    parsed = parse_thrift_response(r.content)
    return parsed["fields"]


def display_qr(url):
    try:
        import qrcode
        qr = qrcode.QRCode(box_size=1, border=1)
        qr.add_data(url)
        qr.make(fit=True)
        qr.print_ascii(invert=True)
    except ImportError:
        print(f"\nQR URL: {url}")
        print("(pip install qrcode for terminal QR)\n")


def main():
    print("LINE QR Login (Direct Thrift)")
    print("=" * 50)

    scanned = False
    session_id = None
    private_key = None

    for attempt in range(3):
        # E2EE keypair
        private_key = PrivateKey.generate()
        public_key_b64 = base64.b64encode(bytes(private_key.public_key)).decode()

        # Create session via direct Thrift
        print(f"\nCreating session (attempt {attempt + 1}/3)...")
        session_id = create_session()
        print(f"  Session: {session_id[:40]}...")

        # Create QR code
        callback_url = create_qr_code(session_id)
        qr_url = f"{callback_url}?secret={urllib.parse.quote(public_key_b64)}&e2eeVersion=1"
        print(f"  URL: {callback_url[:60]}...")

        print(f"\n{'=' * 50}")
        print(f"  SCAN NOW with LINE QR scanner!")
        print(f"{'=' * 50}\n")
        display_qr(qr_url)
        print(f"\n{'=' * 50}")
        print("Waiting for scan...\n")

        for i in range(8):
            if check_qr_verified(session_id, timeout=15):
                scanned = True
                break
            sys.stdout.write(".")
            sys.stdout.flush()

        if scanned:
            break
        print("\n\n⚠ QR expired. Regenerating...\n")

    if not scanned:
        print("\n✗ Failed after 3 attempts.")
        sys.exit(1)

    print("\n✓ QR code scanned!")

    # Certificate check
    need_pin = True
    cert_file = CACHE_DIR / "sqr_cert"
    if cert_file.exists():
        cert = cert_file.read_text().strip()
        if verify_certificate(session_id, cert):
            need_pin = False
            print("✓ Certificate verified (no PIN needed)")

    if need_pin:
        pin = create_pin_code(session_id)
        print(f"\n{'=' * 50}")
        print(f"  Enter this PIN on your phone:  {pin}")
        print(f"{'=' * 50}\n")

        for i in range(30):
            if check_pin_verified(session_id, timeout=15):
                break
            sys.stdout.write(".")
            sys.stdout.flush()
        print("\n✓ PIN verified!")

    # Login
    print("Logging in...")
    result = qr_code_login(session_id)
    if not result:
        print("✗ Login failed")
        sys.exit(1)

    # Extract from nested Thrift response
    # Field 0 is the success struct
    success = result.get(0, result)
    
    # Try to find token info
    # tokenV3IssueResult is typically field 3
    token_info = success.get(3, {}) if isinstance(success, dict) else {}
    auth_token = token_info.get("1_str", "") if isinstance(token_info, dict) else ""
    refresh_token = token_info.get("2_str", "") if isinstance(token_info, dict) else ""
    
    # mid is field 4
    mid = success.get("4_str", "") if isinstance(success, dict) else ""
    
    # certificate is field 1
    cert_new = success.get("1_str", "") if isinstance(success, dict) else ""
    
    # metadata is field 10
    metadata = success.get(10, {}) if isinstance(success, dict) else {}

    if cert_new:
        CACHE_DIR.mkdir(parents=True, exist_ok=True)
        (CACHE_DIR / "sqr_cert").write_text(cert_new)

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
        print(f"\nRaw response for debug:")
        print(json.dumps({k: str(v)[:100] for k, v in result.items()}, indent=2))
        print("\n✗ Could not extract token. Check response above.")
        sys.exit(1)


if __name__ == "__main__":
    main()
