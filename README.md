# line-client

Unofficial LINE Messenger client using the Chrome extension gateway API.

## Architecture

LINE's Chrome extension uses a **JSON REST API** at `line-chrome-gw.line-apps.com` — no Thrift binary, no AES encryption. Just HTTPS + JSON + JWT auth.

```
src/
├── chrome_client.py    # ⭐ Main client (Chrome gateway, JSON API)
├── client.py           # Legacy Thrift client (reference)
├── config.py           # Endpoints, app identity
├── transport/           # HTTP transport (Thrift path)
├── thrift/              # Thrift protocol implementation
├── auth/                # QR/email login flows
├── chat/                # TalkService, polling, contacts
└── e2ee/                # Curve25519 + AES-GCM crypto
```

## Quick Start

```bash
pip install requests
```

```python
from src.chrome_client import LineChromeClient

# Use auth token from LINE Chrome extension
client = LineChromeClient(auth_token="your_jwt_token")

# Get profile
print(client.profile)

# Send message
client.send_message("recipient_mid", "Hello!")

# Get recent messages
messages = client.get_recent_messages("chat_mid", count=20)

# Poll for new messages
def on_msg(msg, client):
    print(f"[{msg.get('_from')}]: {msg.get('text')}")

client.on_message(on_msg)
```

## Getting Your Auth Token

1. Install the [LINE Chrome extension](https://chromewebstore.google.com/detail/line/ophjlpahpchlmihnnnihgmmeilfjmjjc)
2. Log in with QR code
3. Open DevTools → Network tab
4. Look for any request to `line-chrome-gw.line-apps.com`
5. Copy the `x-line-access` header value — that's your JWT token

Token is valid for ~7 days. The `lct` cookie contains the same value.

## API Endpoints

All endpoints follow the pattern:
```
POST https://line-chrome-gw.line-apps.com/api/talk/thrift/Talk/TalkService/{method}
```

Request body is JSON (array of method parameters).
Response: `{"code": 0, "message": "OK", "data": ...}`

### Known Endpoints
- `getProfile` — Get your profile
- `getContact` — Get a contact by MID
- `sendMessage` — Send a message
- `getRecentMessagesV2` — Get recent messages in a chat
- `getMessageReadRange` — Get read receipts
- `getAllChatMids` — Get all chat IDs
- `fetchOps` — Long-poll for new events
- `acquireEncryptedAccessToken` — Refresh token

### HMAC Signing

Most endpoints require an `x-hmac` header. The HMAC computation needs to be reverse-engineered from the Chrome extension source.

**TODO:** Extract HMAC key derivation from extension JS.

To find it:
```bash
# macOS Chrome extension path:
~/Library/Application Support/Google/Chrome/Default/Extensions/ophjlpahpchlmihnnnihgmmeilfjmjjc/

# Search for HMAC logic:
grep -r "hmac\|x-hmac\|HMAC" . --include="*.js"
```

## Project Status

- ✅ Chrome gateway discovery
- ✅ JSON API client
- ✅ Profile, send/receive messages
- ✅ Chat management, reactions
- ✅ Long-polling for events
- ⬜ HMAC signing (need to extract from extension)
- ⬜ QR code login flow
- ⬜ Token refresh
- ⬜ E2EE message decryption

## Reference

Protocol knowledge from studying [CHRLINE](https://github.com/DeachSword/CHRLINE) (archived 2023).
