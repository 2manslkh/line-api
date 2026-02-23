#!/usr/bin/env python3
"""
Basic LINE Chrome client example.

Usage:
    python chrome_basic.py <auth_token>
    
    # Or set env var:
    export LINE_TOKEN="your_jwt_token"
    python chrome_basic.py
"""

import sys
import os
import json

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from src.chrome_client import LineChromeClient


def main():
    token = sys.argv[1] if len(sys.argv) > 1 else os.environ.get("LINE_TOKEN")
    if not token:
        print("Usage: python chrome_basic.py <auth_token>")
        print("  or: export LINE_TOKEN=... && python chrome_basic.py")
        sys.exit(1)

    client = LineChromeClient(token)

    if not client.mid:
        print("Login failed!")
        sys.exit(1)

    print(f"\nProfile: {json.dumps(client.profile, indent=2, ensure_ascii=False)[:500]}")

    # Poll for messages
    print("\n--- Listening for messages (Ctrl+C to stop) ---\n")

    def on_message(msg, cl):
        from_id = msg.get("_from") or msg.get("from")
        to_id = msg.get("to")
        text = msg.get("text")
        ct = msg.get("contentType", 0)
        print(f"[{from_id} → {to_id}] (type={ct}): {text}")

    try:
        thread = client.on_message(on_message)
        thread.join()
    except KeyboardInterrupt:
        print("\nStopping...")
        client.stop()


if __name__ == "__main__":
    main()
