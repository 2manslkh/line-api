"""Token management — storage, refresh, validation."""

import json
from pathlib import Path
from ..transport.http import LineTransport
from ..config import LineConfig

CACHE_DIR = Path.home() / ".line-client"


class TokenManager:
    def __init__(self, transport: LineTransport, config: LineConfig):
        self.transport = transport
        self.config = config

    def save_token(self, auth_token: str, refresh_token: str | None = None):
        CACHE_DIR.mkdir(parents=True, exist_ok=True)
        data = {"auth_token": auth_token}
        if refresh_token:
            data["refresh_token"] = refresh_token
        (CACHE_DIR / "session.json").write_text(json.dumps(data))

    def load_token(self) -> dict | None:
        path = CACHE_DIR / "session.json"
        if path.exists():
            return json.loads(path.read_text())
        return None

    def validate_token(self, auth_token: str) -> bool:
        """Test if token is still valid by calling getProfile."""
        self.transport.auth_token = auth_token
        try:
            resp = self.transport.call("getProfile", [], protocol="compact")
            return resp.get(1) is not None  # mid field
        except Exception:
            return False

    def refresh(self, auth_token: str, refresh_token: str) -> dict | None:
        """Attempt to refresh an expired auth token."""
        try:
            resp = self.transport.call(
                "refreshAccessToken",
                [[11, 1, refresh_token]],
                endpoint="/EXT/auth/tokenrefresh/v1",
                protocol="compact",
            )
            new_token = resp.get(1)
            new_refresh = resp.get(2)
            if new_token:
                self.save_token(new_token, new_refresh)
                return {"auth_token": new_token, "refresh_token": new_refresh}
        except Exception as e:
            print(f"[refresh] Failed: {e}")
        return None
