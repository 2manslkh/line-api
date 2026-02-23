"""
TalkService — core messaging operations.
"""

from ..transport.http import LineTransport
from ..config import LineConfig


class TalkService:
    """Send and receive messages via LINE TalkService."""

    _msg_seq = 0

    def __init__(self, transport: LineTransport, config: LineConfig):
        self.transport = transport
        self.config = config

    def _next_seq(self) -> int:
        self._msg_seq += 1
        return self._msg_seq

    def send_message(
        self,
        to: str,
        text: str | None = None,
        content_type: int = 0,
        content_metadata: dict | None = None,
        reply_to: str | None = None,
        location: dict | None = None,
    ) -> dict:
        """
        Send a message.

        Args:
            to: Recipient MID (user, group, or room)
            text: Message text
            content_type: 0=text, 1=image, 2=video, etc.
            content_metadata: Extra metadata dict
            reply_to: Message ID to reply to
            location: Location dict {1: title, 3: lat, 4: lon}
        """
        if content_metadata is None:
            content_metadata = {}

        message = [
            [11, 2, to],
            [10, 5, 0],    # createdTime
            [10, 6, 0],    # deliveredTime
            [2, 14, False], # hasContent
            [8, 15, content_type],
            [13, 18, [11, 11, content_metadata]],
            [3, 19, 0],    # sessionId
        ]

        if text is not None:
            message.append([11, 10, text])

        if location is not None:
            loc_obj = [
                [11, 1, location.get(1, "")],
                [11, 2, location.get(2, "")],
                [4, 3, location.get(3, 0.0)],
                [4, 4, location.get(4, 0.0)],
            ]
            message.append([12, 11, loc_obj])

        if reply_to is not None:
            message.append([11, 21, reply_to])
            message.append([8, 22, 3])   # REPLY relation type
            message.append([8, 24, 1])   # relatedMessageServiceCode

        params = [
            [8, 1, self._next_seq()],
            [12, 2, message],
        ]

        return self.transport.call("sendMessage", params)

    def unsend_message(self, message_id: str) -> dict:
        """Unsend (delete) a message."""
        params = [[8, 1, self._next_seq()], [11, 2, message_id]]
        return self.transport.call("unsendMessage", params)

    def get_recent_messages(self, chat_id: str, count: int = 50) -> dict:
        """Get recent messages from a chat."""
        params = [
            [12, 1, [
                [11, 1, chat_id],
            ]],
            [8, 2, count],
        ]
        return self.transport.call("getRecentMessagesV2", params)

    def get_previous_messages(self, chat_id: str, end_seq: int, count: int = 50) -> dict:
        """Get older messages before a sequence number."""
        params = [
            [11, 1, chat_id],
            [12, 2, [[10, 1, end_seq]]],
            [8, 3, count],
        ]
        return self.transport.call("getPreviousMessagesV2WithRequest", params)

    def send_chat_checked(self, chat_id: str, last_message_id: str) -> dict:
        """Mark messages as read."""
        params = [
            [8, 1, self._next_seq()],
            [11, 2, chat_id],
            [11, 3, last_message_id],
        ]
        return self.transport.call("sendChatChecked", params)

    def get_chats(self, chat_ids: list[str]) -> dict:
        """Get chat info for given IDs."""
        params = [
            [12, 1, [
                [15, 1, [11, chat_ids]],
                [2, 2, True],  # withMembers
                [2, 3, True],  # withInvitees
            ]],
        ]
        return self.transport.call("getChats", params)

    def get_all_chat_mids(self) -> dict:
        """Get all chat MIDs the user belongs to."""
        params = [
            [12, 1, [
                [2, 1, True],   # withMemberChats
                [2, 2, True],   # withInvitedChats
            ]],
            [8, 2, 0],  # syncReason
        ]
        return self.transport.call("getAllChatMids", params)

    def react(self, message_id: str, reaction_type: int) -> dict:
        """
        React to a message.
        reaction_type: 2=like, 3=love, 4=laugh, 5=surprised, 6=sad, 7=angry
        """
        params = [
            [8, 1, self._next_seq()],
            [12, 2, [
                [10, 1, int(message_id)],
                [12, 2, [
                    [8, 1, reaction_type],
                ]],
            ]],
        ]
        return self.transport.call("react", params)
