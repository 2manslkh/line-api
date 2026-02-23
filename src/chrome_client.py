"""
LINE Chrome Gateway Client — JSON API.

The LINE Chrome extension uses a JSON-based REST API at line-chrome-gw.line-apps.com,
NOT the Thrift binary protocol. This is dramatically simpler.

Usage:
    client = LineChromeClient(auth_token="your_jwt_token")
    profile = client.get_profile()
    client.send_message("recipient_mid", "Hello!")
    
    for event in client.poll():
        print(event)
"""

import json
import time
import threading
import requests
from typing import Callable


BASE_URL = "https://line-chrome-gw.line-apps.com"
TALK_BASE = f"{BASE_URL}/api/talk/thrift/Talk/TalkService"
POLL_BASE = f"{BASE_URL}/api/talk/thrift/Talk"


class LineChromeClient:
    """LINE client using the Chrome extension gateway (JSON API)."""

    def __init__(self, auth_token: str):
        self.auth_token = auth_token
        self._msg_seq = int(time.time())
        self._session = requests.Session()
        self._running = False
        self.revision = 0
        self.mid: str | None = None
        self.profile: dict | None = None

        # Init
        self._init_profile()

    @property
    def _headers(self) -> dict:
        return {
            "accept": "application/json, text/plain, */*",
            "content-type": "application/json",
            "origin": "chrome-extension://ophjlpahpchlmihnnnihgmmeilfjmjjc",
            "x-lal": "en_US",
            "x-line-access": self.auth_token,
            "x-line-chrome-version": "3.7.1",
            "user-agent": (
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
                "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/145.0.0.0 Safari/537.36"
            ),
        }

    def _next_seq(self) -> int:
        self._msg_seq += 1
        return self._msg_seq

    def _call(self, endpoint: str, params: list | dict = None, timeout: int = 30) -> dict:
        """Make a JSON API call to the Chrome gateway."""
        if params is None:
            params = []
        url = f"{TALK_BASE}/{endpoint}"
        resp = self._session.post(url, json=params, headers=self._headers, timeout=timeout)
        resp.raise_for_status()
        data = resp.json()
        if data.get("code") != 0:
            raise APIError(data.get("code"), data.get("message"), data.get("data"))
        return data.get("data")

    def _call_raw(self, url: str, params: list | dict = None, timeout: int = 30) -> dict:
        """Call an arbitrary endpoint."""
        if params is None:
            params = []
        resp = self._session.post(url, json=params, headers=self._headers, timeout=timeout)
        resp.raise_for_status()
        return resp.json()

    # ── Profile & Contacts ──

    def _init_profile(self):
        try:
            self.profile = self.get_profile()
            self.mid = self.profile.get("mid")
            name = self.profile.get("displayName")
            region = self.profile.get("regionCode")
            print(f"✓ Logged in as {name} ({self.mid}) [{region}]")
        except Exception as e:
            print(f"⚠ Failed to get profile: {e}")

    def get_profile(self) -> dict:
        return self._call("getProfile")

    def get_contact(self, mid: str) -> dict:
        return self._call("getContact", [mid])

    def get_contacts(self, mids: list[str]) -> list:
        return self._call("getContacts", [mids])

    def get_all_contact_ids(self) -> list:
        return self._call("getAllContactIds")

    # ── Messaging ──

    def send_message(
        self,
        to: str,
        text: str,
        content_type: int = 0,
        content_metadata: dict | None = None,
        reply_to: str | None = None,
    ) -> dict:
        """Send a text message."""
        seq = self._next_seq()
        message = {
            "from": self.mid,
            "to": to,
            "toType": self._get_to_type(to),
            "id": f"local-{seq}",
            "createdTime": str(int(time.time() * 1000)),
            "sessionId": 0,
            "text": text,
            "contentType": content_type,
            "contentMetadata": content_metadata or {},
            "hasContent": False,
        }
        if reply_to:
            message["relatedMessageId"] = reply_to
            message["messageRelationType"] = 3  # REPLY
            message["relatedMessageServiceCode"] = 1
        return self._call("sendMessage", [seq, message])

    def unsend_message(self, message_id: str) -> dict:
        return self._call("unsendMessage", [self._next_seq(), message_id])

    def get_recent_messages(self, chat_id: str, count: int = 50) -> list:
        return self._call("getRecentMessagesV2", [chat_id, count])

    def get_message_read_range(self, chat_ids: list[str]) -> dict:
        return self._call("getMessageReadRange", [chat_ids])

    def send_chat_checked(self, chat_id: str, last_message_id: str) -> dict:
        """Mark messages as read."""
        return self._call("sendChatChecked", [self._next_seq(), chat_id, last_message_id])

    # ── Chats & Groups ──

    def get_chats(self, chat_ids: list[str], with_members: bool = True, with_invitees: bool = True) -> dict:
        return self._call("getChats", [{"chatMids": chat_ids, "withMembers": with_members, "withInvitees": with_invitees}])

    def get_all_chat_mids(self) -> dict:
        return self._call("getAllChatMids", [{"withMemberChats": True, "withInvitedChats": True}, 0])

    def accept_chat_invitation(self, chat_id: str) -> dict:
        return self._call("acceptChatInvitation", [self._next_seq(), chat_id])

    def create_chat(self, name: str, target_mids: list[str]) -> dict:
        return self._call("createChat", [self._next_seq(), {"type": 0, "name": name, "targetUserMids": target_mids}])

    def leave_chat(self, chat_id: str) -> dict:
        return self._call("deleteSelfFromChat", [self._next_seq(), chat_id])

    # ── Reactions ──

    def react(self, message_id: str, reaction_type: int) -> dict:
        """React to a message. Types: 2=like, 3=love, 4=laugh, 5=surprised, 6=sad, 7=angry"""
        return self._call("react", [self._next_seq(), {"messageId": int(message_id), "reactionType": {"type": reaction_type}}])

    # ── Polling ──

    def get_last_op_revision(self) -> int:
        return self._call("getLastOpRevision")

    def fetch_ops(self, count: int = 50) -> list:
        """Fetch pending operations. May block (long-poll)."""
        params = [self.revision, count, 0, 0]
        result = self._call("fetchOps", params, timeout=60)
        if isinstance(result, list):
            for op in result:
                rev = op.get("revision")
                if rev and rev > self.revision:
                    self.revision = rev
            return result
        return []

    def poll(self):
        """Generator yielding operations as they arrive."""
        if self.revision == 0:
            self.revision = self.get_last_op_revision()
        while True:
            try:
                ops = self.fetch_ops()
                for op in ops:
                    yield op
            except Exception as e:
                print(f"[poll] {e}")
                time.sleep(2)

    def on_message(self, handler: Callable):
        """
        Start polling and call handler(message, client) on each new message.
        Returns the polling thread.
        """
        self._running = True
        if self.revision == 0:
            self.revision = self.get_last_op_revision()

        def _run():
            while self._running:
                try:
                    ops = self.fetch_ops()
                    for op in ops:
                        op_type = op.get("type")
                        if op_type == 26:  # SEND_MESSAGE
                            msg = op.get("message")
                            if msg:
                                handler(msg, self)
                        elif op_type == 27:  # RECEIVE_MESSAGE
                            msg = op.get("message")
                            if msg:
                                handler(msg, self)
                except Exception as e:
                    print(f"[poll] {e}")
                    time.sleep(2)

        t = threading.Thread(target=_run, daemon=True)
        t.start()
        return t

    def stop(self):
        self._running = False

    # ── Helpers ──

    @staticmethod
    def _get_to_type(mid: str) -> int:
        """Guess to_type from MID format."""
        if mid.startswith("u") or mid.startswith("U"):
            return 0  # USER
        elif mid.startswith("c") or mid.startswith("C"):
            return 2  # GROUP
        elif mid.startswith("r") or mid.startswith("R"):
            return 1  # ROOM
        return 0


class APIError(Exception):
    def __init__(self, code: int, message: str, data: dict = None):
        self.code = code
        self.api_message = message
        self.data = data
        super().__init__(f"APIError({code}): {message} {data or ''}")
