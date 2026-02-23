#!/usr/bin/env python3
"""Basic LINE client usage example."""

import sys
sys.path.insert(0, "..")

from src.client import LineClient
from src.chat.poll import OpType


def main():
    # Try saved token, fall back to QR login
    client = LineClient(auto_login=False)
    
    saved = client.token_manager.load_token()
    if saved and client.token_manager.validate_token(saved["auth_token"]):
        client._login_with_token(saved["auth_token"])
    else:
        print("Starting QR login...")
        for step in client.login_qr():
            if step["status"] == "logged_in":
                break

    if not client.is_logged_in:
        print("Login failed!")
        return

    print(f"\nProfile: {client.profile}")
    print(f"MID: {client.mid}")

    # Get contacts
    try:
        contact_ids = client.contacts.get_all_contact_ids()
        print(f"\nContacts: {contact_ids}")
    except Exception as e:
        print(f"Failed to get contacts: {e}")

    # Get groups
    try:
        chats = client.talk.get_all_chat_mids()
        print(f"\nChats: {chats}")
    except Exception as e:
        print(f"Failed to get chats: {e}")

    # Poll for messages
    print("\n--- Listening for messages (Ctrl+C to stop) ---\n")

    def on_message(message, cl):
        from_mid = message.get(1)  # _from
        to_mid = message.get(2)    # to
        text = message.get(10)     # text
        print(f"[{from_mid} → {to_mid}]: {text}")

        # Echo bot: reply with same text
        if text and from_mid != cl.mid:
            cl.send(to_mid if to_mid != cl.mid else from_mid, f"Echo: {text}")

    try:
        thread = client.on_message(on_message)
        thread.join()
    except KeyboardInterrupt:
        print("\nStopping...")
        client.close()


if __name__ == "__main__":
    main()
