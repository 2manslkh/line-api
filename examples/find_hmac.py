#!/usr/bin/env python3
"""
Helper script to find the HMAC key in the LINE Chrome extension.

Run this on your Mac to search the extension source for HMAC logic.
"""

import os
import glob
import re
import sys


def find_extension_dir():
    """Find the LINE Chrome extension directory across all browser profiles."""
    browser_roots = [
        os.path.expanduser("~/Library/Application Support/Google/Chrome"),
        os.path.expanduser("~/Library/Application Support/BraveSoftware/Brave-Browser"),
        os.path.expanduser("~/.config/google-chrome"),
        os.path.expanduser("~/.config/BraveSoftware/Brave-Browser"),
    ]

    ext_id = "ophjlpahpchlmihnnnihgmmeilfjmjjc"

    for root in browser_roots:
        if not os.path.isdir(root):
            continue
        # Search Default and all Profile * directories
        for entry in os.listdir(root):
            if entry == "Default" or entry.startswith("Profile"):
                ext_path = os.path.join(root, entry, "Extensions", ext_id)
                if os.path.exists(ext_path):
                    versions = sorted(os.listdir(ext_path))
                    if versions:
                        return os.path.join(ext_path, versions[-1])

    return None


def search_for_hmac(ext_dir):
    """Search JS files for HMAC-related code."""
    patterns = [
        r'hmac',
        r'x-hmac',
        r'HMAC',
        r'createHmac',
        r'crypto\.subtle',
        r'importKey',
        r'sign\(',
    ]
    
    js_files = glob.glob(os.path.join(ext_dir, "**", "*.js"), recursive=True)
    
    print(f"Searching {len(js_files)} JS files in {ext_dir}\n")
    
    for js_file in js_files:
        try:
            content = open(js_file).read()
            for pattern in patterns:
                matches = list(re.finditer(pattern, content, re.IGNORECASE))
                if matches:
                    rel_path = os.path.relpath(js_file, ext_dir)
                    for match in matches[:3]:
                        start = max(0, match.start() - 100)
                        end = min(len(content), match.end() + 100)
                        context = content[start:end].replace('\n', ' ')
                        print(f"📁 {rel_path} (offset {match.start()}):")
                        print(f"   ...{context}...")
                        print()
        except Exception:
            pass


def main():
    ext_dir = find_extension_dir()
    
    if not ext_dir:
        print("❌ LINE Chrome extension not found!")
        print("\nSearched paths:")
        print("  - Chrome: ~/Library/Application Support/Google/Chrome/Default/Extensions/")
        print("  - Brave:  ~/Library/Application Support/BraveSoftware/Brave-Browser/Default/Extensions/")
        print(f"\nLooking for extension ID: ophjlpahpchlmihnnnihgmmeilfjmjjc")
        
        if len(sys.argv) > 1:
            ext_dir = sys.argv[1]
            print(f"\nUsing provided path: {ext_dir}")
        else:
            print("\nYou can also pass the path directly:")
            print("  python find_hmac.py /path/to/extension/dir")
            sys.exit(1)
    
    print(f"✅ Found extension at: {ext_dir}\n")
    search_for_hmac(ext_dir)


if __name__ == "__main__":
    main()
