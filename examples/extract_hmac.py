#!/usr/bin/env python3
"""
Extract HMAC implementation from LINE Chrome extension source.

Usage:
    cd "/Users/kenk/Library/Application Support/BraveSoftware/Brave-Browser/Profile 24/Extensions/ophjlpahpchlmihnnnihgmmeilfjmjjc/3.7.1_0"
    python3 ~/line-api/examples/extract_hmac.py
"""

import re
import os
import glob

def search_file(filepath, patterns):
    try:
        content = open(filepath, encoding='utf-8', errors='ignore').read()
    except:
        return
    
    fname = os.path.basename(filepath)
    for label, pattern in patterns:
        for m in re.finditer(pattern, content):
            start = max(0, m.start() - 300)
            end = min(len(content), m.end() + 600)
            snippet = content[start:end]
            print(f"\n{'='*60}")
            print(f"[{fname} @ {m.start()}] {label}")
            print(f"{'='*60}")
            print(snippet)
            print()

def main():
    patterns = [
        ("HMAC header set", r'X-Hmac'),
        ("getHmac function", r'getHmac\s*[\(\{]'),
        ("getHmac definition", r'getHmac\s*:'),
        ("HKDF import", r'"HKDF"'),
        ("sign function", r'crypto\.subtle\.sign\('),
        ("importKey HMAC", r'importKey\([^)]*HMAC'),
        ("hmac key derive", r'macKey'),
    ]
    
    # Find all JS files
    js_files = glob.glob("static/js/*.js") + glob.glob("*.js") + glob.glob("js/*.js")
    
    if not js_files:
        print("No JS files found! Make sure you're in the extension directory.")
        print(f"Current dir: {os.getcwd()}")
        print(f"Files here: {os.listdir('.')[:20]}")
        return
    
    print(f"Scanning {len(js_files)} files...")
    
    for f in sorted(js_files):
        search_file(f, patterns)

if __name__ == "__main__":
    main()
