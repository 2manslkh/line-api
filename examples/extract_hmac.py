#!/usr/bin/env python3
"""
Extract HMAC implementation from LINE Chrome extension source.

Run from the extension directory:
    cd "/Users/kenk/Library/Application Support/BraveSoftware/Brave-Browser/Profile 24/Extensions/ophjlpahpchlmihnnnihgmmeilfjmjjc/3.7.1_0"
    python3 ~/path/to/extract_hmac.py
"""

import re
import os

JS_FILES = [
    "static/js/main.js",
    "static/js/ltsmSandbox.js",
    "static/js/cropperSandbox.js",
]


def extract_around(content, pattern, before=300, after=800, max_matches=5):
    results = []
    for m in re.finditer(pattern, content):
        start = max(0, m.start() - before)
        end = min(len(content), m.end() + after)
        results.append((m.start(), content[start:end]))
        if len(results) >= max_matches:
            break
    return results


def main():
    for js_file in JS_FILES:
        if not os.path.exists(js_file):
            continue

        print(f"\n{'='*60}")
        print(f"FILE: {js_file}")
        print(f"{'='*60}")

        content = open(js_file).read()

        # 1. Find getHmac implementation
        print(f"\n--- getHmac implementation ---")
        for offset, text in extract_around(content, r'getHmac', before=300, after=500, max_matches=3):
            print(f"\n[offset {offset}]")
            print(text)
            print()

        # 2. Find HKDF key derivation
        print(f"\n--- HKDF derivation ---")
        for offset, text in extract_around(content, r'HKDF', before=100, after=800, max_matches=3):
            print(f"\n[offset {offset}]")
            print(text)
            print()

        # 3. Find the async key derivation functions (vL, ME, or similar)
        print(f"\n--- async key derivation (deriveBits) ---")
        for offset, text in extract_around(content, r'deriveBits', before=200, after=400, max_matches=3):
            print(f"\n[offset {offset}]")
            print(text)
            print()

        # 4. Find HMAC-SHA256 signing
        print(f"\n--- crypto.subtle.sign ---")
        for offset, text in extract_around(content, r'crypto\.subtle\.sign\b', before=200, after=400, max_matches=3):
            print(f"\n[offset {offset}]")
            print(text)
            print()

        # 5. Find where X-Hmac header is set (the interceptor)
        print(f"\n--- X-Hmac header assignment ---")
        for offset, text in extract_around(content, r'X-Hmac', before=500, after=200, max_matches=3):
            print(f"\n[offset {offset}]")
            print(text)
            print()

        # Only process main.js (most complete)
        break


if __name__ == "__main__":
    main()
