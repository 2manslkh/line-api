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
from .hmac import HmacSigner


BASE_URL = "https://line-chrome-gw.line-apps.com"
TALK_BASE = f"{BASE_URL}/api/talk/thrift/Talk/TalkService"
POLL_BASE = f"{BASE_URL}/api/talk/thrift/Talk"


class LineChromeClient:
    """LINE client using the Chrome extension gateway (JSON API)."""

    def __init__(self, auth_token: str, hmac_mode: str = "server"):
        self.auth_token = auth_token
        self._msg_seq = int(time.time())
        self._session = requests.Session()
        self._running = False
        self.revision = 0
        self.mid: str | None = None
        self.profile: dict | None = None
        self._hmac = HmacSigner(mode=hmac_mode)

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

    def _sign_request(self, path: str, body: str) -> str:
        """Compute X-Hmac for a request."""
        return self._hmac.sign(self.auth_token, path, body)

    def _call(self, endpoint: str, params: list | dict = None, timeout: int = 30) -> dict:
        """Make a JSON API call to the Chrome gateway."""
        if params is None:
            params = []
        path = f"/api/talk/thrift/Talk/TalkService/{endpoint}"
        url = BASE_URL + path
        body = json.dumps(params)
        headers = {**self._headers, "X-Hmac": self._sign_request(path, body)}
        resp = self._session.post(url, data=body, headers=headers, timeout=timeout)
        resp.raise_for_status()
        data = resp.json()
        if data.get("code") != 0:
            raise APIError(data.get("code"), data.get("message"), data.get("data"))
        return data.get("data")

    def _call_raw(self, url: str, params: list | dict = None, timeout: int = 30) -> dict:
        """Call an arbitrary endpoint."""
        if params is None:
            params = []
        # Extract path from URL for HMAC
        from urllib.parse import urlparse
        path = urlparse(url).path
        body = json.dumps(params)
        headers = {**self._headers, "X-Hmac": self._sign_request(path, body)}
        resp = self._session.post(url, data=body, headers=headers, timeout=timeout)
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

    def find_contact_by_userid(self, userid: str) -> dict:
        """Search for a contact by LINE ID."""
        return self._call("findContactByUserid", [userid])

    def find_and_add_contact_by_mid(self, mid: str) -> dict:
        """Add a friend by MID."""
        return self._call("findAndAddContactsByMid", [self._next_seq(), mid, 0, ""])

    def find_contacts_by_phone(self, phones: list[str]) -> dict:
        """Search contacts by phone numbers."""
        return self._call("findContactsByPhone", [phones])

    def get_blocked_contact_ids(self) -> list:
        return self._call("getBlockedContactIds")

    def get_blocked_recommendation_ids(self) -> list:
        return self._call("getBlockedRecommendationIds")

    def block_contact(self, mid: str) -> dict:
        return self._call("blockContact", [self._next_seq(), mid])

    def unblock_contact(self, mid: str) -> dict:
        return self._call("unblockContact", [self._next_seq(), mid])

    def block_recommendation(self, mid: str) -> dict:
        return self._call("blockRecommendation", [self._next_seq(), mid])

    def update_contact_setting(self, mid: str, flag: int, value: str) -> dict:
        """Update contact setting. flag: 1=CONTACT_SETTING_NOTIFICATION_DISABLE, etc."""
        return self._call("updateContactSetting", [self._next_seq(), mid, flag, value])

    def get_favorite_mids(self) -> list:
        return self._call("getFavoriteMids")

    def get_recommendation_ids(self) -> list:
        return self._call("getRecommendationIds")

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

    def get_previous_messages(self, chat_id: str, end_seq: int, count: int = 50) -> list:
        """Get paginated message history before a given sequence number."""
        return self._call("getPreviousMessagesV2WithRequest", [
            {"chatId": chat_id, "endSeq": end_seq, "limit": count, "withReadCount": True}
        ])

    def get_messages_by_ids(self, message_ids: list[str]) -> list:
        """Fetch specific messages by their IDs."""
        return self._call("getMessagesByIds", [message_ids])

    def get_message_boxes(self, count: int = 50) -> list:
        """Get chat list with last message preview (inbox)."""
        return self._call("getMessageBoxes", ["", count, 0])

    def get_message_boxes_by_ids(self, chat_ids: list[str]) -> list:
        """Get specific chats with last message preview."""
        return self._call("getMessageBoxesByIds", [chat_ids])

    def get_message_read_range(self, chat_ids: list[str]) -> dict:
        return self._call("getMessageReadRange", [chat_ids])

    def send_chat_checked(self, chat_id: str, last_message_id: str) -> dict:
        """Mark messages as read."""
        return self._call("sendChatChecked", [self._next_seq(), chat_id, last_message_id])

    def send_chat_removed(self, chat_id: str, last_message_id: str) -> dict:
        """Remove/delete a chat from inbox."""
        return self._call("sendChatRemoved", [self._next_seq(), chat_id, last_message_id])

    def send_postback(self, to: str, postback_data: str) -> dict:
        """Send postback content (for bot interactions)."""
        return self._call("sendPostback", [self._next_seq(), to, postback_data])

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

    def invite_into_chat(self, chat_id: str, mids: list[str]) -> dict:
        """Invite users into a group chat."""
        return self._call("inviteIntoChat", [self._next_seq(), chat_id, {"targetUserMids": mids}])

    def cancel_chat_invitation(self, chat_id: str, mids: list[str]) -> dict:
        """Cancel pending invitations."""
        return self._call("cancelChatInvitation", [self._next_seq(), chat_id, {"targetUserMids": mids}])

    def reject_chat_invitation(self, chat_id: str) -> dict:
        """Reject a group chat invitation."""
        return self._call("rejectChatInvitation", [self._next_seq(), chat_id])

    def delete_other_from_chat(self, chat_id: str, mids: list[str]) -> dict:
        """Kick members from a group chat."""
        return self._call("deleteOtherFromChat", [self._next_seq(), chat_id, {"targetUserMids": mids}])

    def update_chat(self, chat_id: str, updates: dict) -> dict:
        """Update chat settings. updates can include: name, picturePath, extra.groupExtra.preventedJoinByTicket, etc."""
        return self._call("updateChat", [self._next_seq(), {"chatMid": chat_id, **updates}, 0])

    def set_chat_hidden_status(self, chat_id: str, hidden: bool) -> dict:
        """Archive/unarchive a chat."""
        return self._call("setChatHiddenStatus", [self._next_seq(), chat_id, hidden])

    def get_rooms(self, room_ids: list[str]) -> dict:
        """Get legacy room info."""
        return self._call("getRoomsV2", [room_ids])

    def invite_into_room(self, room_id: str, mids: list[str]) -> dict:
        """Invite users into a legacy room."""
        return self._call("inviteIntoRoom", [self._next_seq(), room_id, mids])

    def leave_room(self, room_id: str) -> dict:
        return self._call("leaveRoom", [self._next_seq(), room_id])

    # ── Reactions ──

    def react(self, message_id: str, reaction_type: int) -> dict:
        """React to a message. Types: 2=like, 3=love, 4=laugh, 5=surprised, 6=sad, 7=angry"""
        return self._call("react", [self._next_seq(), {"messageId": int(message_id), "reactionType": {"type": reaction_type}}])

    def cancel_reaction(self, message_id: str) -> dict:
        """Remove a reaction from a message."""
        return self._call("cancelReaction", [self._next_seq(), {"messageId": int(message_id), "reactionType": {"type": 0}}])

    # ── Profile & Settings ──

    def update_profile_attributes(self, attr: int, value: str, meta: dict = None) -> dict:
        """
        Update a profile attribute.

        Attribute IDs:
            2  = DISPLAY_NAME
            16 = STATUS_MESSAGE
            4  = PICTURE_STATUS (profile picture path)

        Example: client.update_profile_attributes(16, "Hello world!")
        """
        return self._call("updateProfileAttributes", [
            self._next_seq(),
            {"profileAttributes": {str(attr): {"value": value, "meta": meta or {}}}}
        ])

    def update_status_message(self, message: str) -> dict:
        """Shortcut to update status message."""
        return self.update_profile_attributes(16, message)

    def update_display_name(self, name: str) -> dict:
        """Shortcut to update display name."""
        return self.update_profile_attributes(2, name)

    def get_settings(self) -> dict:
        return self._call("getSettings")

    def get_settings_attributes(self, attr_bitset: int) -> dict:
        return self._call("getSettingsAttributes2", [attr_bitset])

    def update_settings_attributes(self, attr_bitset: int, settings: dict) -> dict:
        return self._call("updateSettingsAttributes2", [self._next_seq(), attr_bitset, settings])

    # ── Other Services ──

    def get_server_time(self) -> int:
        return self._call("getServerTime")

    def get_configurations(self) -> dict:
        return self._call("getConfigurations")

    def get_rsa_key_info(self) -> dict:
        return self._call("getRSAKeyInfo", [0])

    def report_abuse(self, mid: str, category: int = 0, reason: str = "") -> dict:
        return self._call("reportAbuseEx", [self._next_seq(), {"reportee": mid, "category": category, "reason": reason}])

    def issue_channel_token(self, channel_id: str) -> dict:
        """Issue a channel token (for LINE Login/LIFF)."""
        path = "/api/talk/thrift/Talk/ChannelService/issueChannelToken"
        url = BASE_URL + path
        body = json.dumps([channel_id])
        headers = {**self._headers, "X-Hmac": self._sign_request(path, body)}
        resp = self._session.post(url, data=body, headers=headers, timeout=30)
        resp.raise_for_status()
        return resp.json().get("data")

    def get_buddy_detail(self, mid: str) -> dict:
        """Get official account / buddy detail."""
        path = "/api/talk/thrift/Talk/BuddyService/getBuddyDetail"
        url = BASE_URL + path
        body = json.dumps([mid])
        headers = {**self._headers, "X-Hmac": self._sign_request(path, body)}
        resp = self._session.post(url, data=body, headers=headers, timeout=30)
        resp.raise_for_status()
        return resp.json().get("data")

    def add_friend_by_mid(self, mid: str) -> dict:
        """Add friend via RelationService."""
        path = "/api/talk/thrift/Talk/RelationService/addFriendByMid"
        url = BASE_URL + path
        body = json.dumps([self._next_seq(), mid])
        headers = {**self._headers, "X-Hmac": self._sign_request(path, body)}
        resp = self._session.post(url, data=body, headers=headers, timeout=30)
        resp.raise_for_status()
        return resp.json().get("data")

    def logout(self) -> dict:
        """Logout and invalidate the current token."""
        path = "/api/talk/thrift/Talk/AuthService/logoutV2"
        url = BASE_URL + path
        body = json.dumps([])
        headers = {**self._headers, "X-Hmac": self._sign_request(path, body)}
        resp = self._session.post(url, data=body, headers=headers, timeout=30)
        resp.raise_for_status()
        return resp.json().get("data")

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
