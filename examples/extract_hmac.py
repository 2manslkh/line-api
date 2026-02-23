#!/usr/bin/env python3
"""
Extract HMAC implementation from LINE Chrome extension.
Run from the extension directory.
"""

import re
import os

def extract(content, pattern, before=300, after=800, max_matches=5):
    results = []
    for m in re.finditer(pattern, content):
        start = max(0, m.start() - before)
        end = min(len(content), m.end() + after)
        results.append((m.start(), content[start:end]))
        if len(results) >= max_matches:
            break
    return results

def main():
    target = "static/js/ltsmSandbox.js"
    if not os.path.exists(target):
        print(f"File not found: {target}")
        print(f"Current dir: {os.getcwd()}")
        return

    content = open(target, encoding='utf-8', errors='ignore').read()
    print(f"File size: {len(content)} bytes\n")

    searches = [
        ("GET_HMAC handler", r'GET_HMAC'),
        ("HMAC command enum", r'GET_HMAC|HMAC["\s:,]'),
        ("hmac compute/sign in sandbox", r'async.*hmac|computeHmac|calcHmac|generateHmac'),
        ("HMAC SHA256 sign", r'HMAC.*SHA-256|SHA-256.*HMAC'),
        ("importKey.*HMAC", r'importKey\([^)]*"HMAC"'),  
        ("crypto.subtle.sign HMAC", r'subtle\.sign\("HMAC"'),
        ("command handler switch", r'case.*HMAC|GET_HMAC'),
        ("onmessage handler", r'onmessage|addEventListener.*message'),
        ("accessToken.*path.*body together", r'accessToken.*path.*body|path.*body.*accessToken'),
    ]

    for label, pattern in searches:
        results = extract(content, pattern, before=300, after=800, max_matches=3)
        if results:
            for offset, text in results:
                print(f"{'='*60}")
                print(f"[{label}] offset {offset}")
                print(f"{'='*60}")
                print(text)
                print()

if __name__ == "__main__":
    main()
