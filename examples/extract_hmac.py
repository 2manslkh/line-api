#!/usr/bin/env python3
"""
Extract HMAC implementation from LINE Chrome extension.
Run from the extension directory.

Output is kept compact: 150 chars before match, 400 after, 2 matches max per pattern.
Deduplicates overlapping regions. Total output typically <50KB.
"""

import re
import os
import sys

BEFORE = 80
AFTER = 200
MAX_PER_PATTERN = 2

SEARCHES = [
    ("GET_HMAC handler",        r'GET_HMAC'),
    ("importKey HMAC",          r'importKey\([^)]*"HMAC"'),
    ("subtle.sign",             r'subtle\.sign\('),
    ("onmessage handler",       r'onmessage\s*=|addEventListener\(\s*["\']message'),
    ("token+path+body",         r'accessToken.{0,80}path.{0,80}body|path.{0,80}body.{0,80}accessToken'),
    # cS/lS initialization & deriveKey
    ("cS assignment",           r'cS\s*=\s*[^,;]{5,80}'),
    ("lS assignment",           r'lS\s*=\s*[^,;]{5,80}'),
    ("deriveKey def/call",      r'deriveKey\s*[\(=]'),
    ("fS constructor",          r'fS\s*[\(=]'),
    ("LTSM_NOT_READY",         r'LTSM_NOT_READY'),
    ("tm function (SHA)",       r'(?:function\s+tm|tm\s*=\s*async|const\s+tm)'),
    ("yw error class",          r'class\s+yw|yw\s*=\s*'),
    # SecureKey / WASM tracing
    ("SecureKey class/ref",     r'SecureKey'),
    ("loadToken def/call",      r'loadToken\s*[\(=]'),
    ("uS assignment",           r'uS\s*=\s*[^,;]{5,80}'),
    (".wasm reference",         r'\.wasm'),
    ("WebAssembly",             r'WebAssembly\.(?:instantiate|compile|Module)'),
    ("origin token map",        r'chrome-extension://[^"]{20,60}"\s*:\s*"[^"]+'),
]


def main():
    target = sys.argv[1] if len(sys.argv) > 1 else "static/js/ltsmSandbox.js"
    if not os.path.exists(target):
        print(f"File not found: {target}\nCwd: {os.getcwd()}")
        return

    content = open(target, encoding='utf-8', errors='ignore').read()
    print(f"# {target} — {len(content):,} bytes\n")

    seen = set()  # (start, end) ranges already printed

    for label, pattern in SEARCHES:
        matches = list(re.finditer(pattern, content))[:MAX_PER_PATTERN]
        if not matches:
            continue
        print(f"\n## {label} ({len(matches)} hit{'s' if len(matches)>1 else ''})\n")
        for m in matches:
            start = max(0, m.start() - BEFORE)
            end = min(len(content), m.end() + AFTER)
            # skip if this region largely overlaps a previous one
            if any(s <= start and end <= e for s, e in seen):
                continue
            seen.add((start, end))
            snippet = content[start:end].replace('\r', '')
            print(f"--- offset {m.start()} ---")
            print(snippet)
            print()


if __name__ == "__main__":
    main()
