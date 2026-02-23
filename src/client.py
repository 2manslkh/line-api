"""
LINE Client — main entry point.

Usage:
    # QR code login
    client = LineClient()
    
    # Auth token login
    client = LineClient(auth_token="...")
    
    # Email login
    client = LineClient(email="...", password="...")
"""

from .config import LineConfig
from .transport.http import LineTransport
from .auth.qr import QRLogin
from .auth.email import EmailLogin
from .auth.token import TokenManager
from .chat.talk import TalkService
from .chat.poll import Poller, OpType
from .chat.contacts import ContactService


class LineClient:
    """
    Unofficial LINE Messenger client.
    
    Connects to LINE's Thrift API as a ChromeOS device.
    """

    def __init__(
        self,
        auth_token: str | None = None,
        email: str | None = None,
        password: str | None = None,
        device: str = "CHROMEOS",
        version: str | None = None,
        auto_login: bool = True,
    ):
        self.config = LineConfig()
        if version:
            self.config.APP_VERSION = version
        
        self.transport = LineTransport(self.config)
        self.token_manager = TokenManager(self.transport, self.config)
        
        # Services
        self.talk = TalkService(self.transport, self.config)
        self.contacts = ContactService(self.transport, self.config)
        self.poller = Poller(self.transport, self.config)
        
        # State
        self.mid: str | None = None
        self.profile: dict | None = None
        self.is_logged_in = False

        if not auto_login:
            return

        # Auth flow
        if auth_token:
            self._login_with_token(auth_token)
        elif email and password:
            self._login_with_email(email, password)
        else:
            # Try saved token first
            saved = self.token_manager.load_token()
            if saved and self.token_manager.validate_token(saved["auth_token"]):
                self._login_with_token(saved["auth_token"])
            else:
                print("No valid session found. Use login_qr() or login_email().")

    def _login_with_token(self, token: str):
        self.transport.auth_token = token
        self._init_profile()

    def _login_with_email(self, email: str, password: str):
        login = EmailLogin(self.transport, self.config)
        for step in login.login(email, password):
            status = step.get("status")
            if status == "pin_required":
                print(f"Enter PIN on your phone: {step['pin']}")
            elif status == "logged_in":
                self.transport.auth_token = step["auth_token"]
                self.token_manager.save_token(
                    step["auth_token"],
                    step.get("refresh_token"),
                )
                self._init_profile()
            elif status == "login_error":
                raise RuntimeError(f"Login failed: {step['error']}")
            else:
                print(f"[login] {status}")

    def login_qr(self):
        """
        Interactive QR code login.
        Returns generator yielding status dicts.
        """
        login = QRLogin(self.transport, self.config)
        for step in login.login():
            status = step.get("status")
            if status == "qr_code":
                print(f"\n{'='*50}")
                print(f"Scan this QR code with LINE app:")
                print(f"{step['url']}")
                print(f"{'='*50}\n")
            elif status == "pin_required":
                print(f"\nEnter PIN on your phone: {step['pin']}\n")
            elif status == "logged_in":
                self.transport.auth_token = step["auth_token"]
                self.token_manager.save_token(
                    step["auth_token"],
                    step.get("refresh_token"),
                )
                self._init_profile()
                print(f"Logged in as: {self.profile.get(20, 'Unknown')}")
            else:
                print(f"[login] {status}")
            yield step

    def _init_profile(self):
        """Load profile after auth."""
        try:
            self.profile = self.contacts.get_profile()
            self.mid = self.profile.get(1)  # mid field
            display_name = self.profile.get(20)
            if self.mid:
                self.is_logged_in = True
                print(f"✓ Logged in as {display_name} ({self.mid})")

                # Get initial revision for polling
                try:
                    rev_resp = self.transport.call("getLastOpRevision", [])
                    if isinstance(rev_resp, dict):
                        self.poller.revision = rev_resp.get(0, 0)
                    elif isinstance(rev_resp, int):
                        self.poller.revision = rev_resp
                except Exception:
                    pass
            else:
                print("⚠ Login may have failed — no MID in profile")
        except Exception as e:
            print(f"⚠ Failed to get profile: {e}")

    # ── Convenience methods ──

    def send(self, to: str, text: str, **kwargs) -> dict:
        """Send a text message."""
        return self.talk.send_message(to, text, **kwargs)

    def reply(self, to: str, text: str, reply_to: str) -> dict:
        """Reply to a message."""
        return self.talk.send_message(to, text, reply_to=reply_to)

    def poll(self):
        """Generator that yields incoming operations."""
        return self.poller.poll(lambda op: None)

    def on_message(self, handler):
        """
        Register a message handler and start polling.
        
        handler receives (message_dict, client) on each new message.
        """
        def _op_handler(op):
            op_type = op.get(3)
            if op_type == OpType.RECEIVE_MESSAGE:
                message = op.get(20)  # message field
                if message:
                    handler(message, self)

        return self.poller.poll_threaded(_op_handler)

    def close(self):
        self.poller.stop()
        self.transport.close()
