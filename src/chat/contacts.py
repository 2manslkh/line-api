"""
Contact and group management.
"""

from ..transport.http import LineTransport
from ..config import LineConfig


class ContactService:
    """Manage contacts and groups."""

    def __init__(self, transport: LineTransport, config: LineConfig):
        self.transport = transport
        self.config = config

    def get_profile(self) -> dict:
        """Get the logged-in user's profile."""
        return self.transport.call("getProfile", [])

    def get_contact(self, mid: str) -> dict:
        """Get a single contact by MID."""
        params = [[11, 2, mid]]
        return self.transport.call("getContact", params)

    def get_contacts(self, mids: list[str]) -> dict:
        """Get multiple contacts."""
        params = [[15, 2, [11, mids]]]
        return self.transport.call("getContacts", params)

    def get_all_contact_ids(self) -> dict:
        """Get all contact MIDs."""
        return self.transport.call("getAllContactIds", [])

    def get_blocked_contact_ids(self) -> dict:
        """Get blocked contact MIDs."""
        return self.transport.call("getBlockedContactIds", [])

    def block_contact(self, mid: str) -> dict:
        """Block a contact."""
        params = [
            [8, 1, 0],  # reqSeq
            [11, 2, mid],
        ]
        return self.transport.call("blockContact", params)

    def unblock_contact(self, mid: str) -> dict:
        """Unblock a contact."""
        params = [
            [8, 1, 0],
            [11, 2, mid],
        ]
        return self.transport.call("unblockContact", params)

    def get_group(self, group_id: str) -> dict:
        """Get group info."""
        params = [[11, 2, group_id]]
        return self.transport.call("getGroup", params)

    def get_groups(self, group_ids: list[str]) -> dict:
        """Get multiple groups."""
        params = [[15, 2, [11, group_ids]]]
        return self.transport.call("getGroups", params)

    def get_group_ids_joined(self) -> dict:
        """Get IDs of groups the user has joined."""
        return self.transport.call("getGroupIdsJoined", [])

    def get_group_ids_invited(self) -> dict:
        """Get IDs of groups the user is invited to."""
        return self.transport.call("getGroupIdsInvited", [])

    def accept_group_invitation(self, group_id: str) -> dict:
        """Accept a group invitation."""
        params = [
            [8, 1, 0],
            [11, 2, group_id],
        ]
        return self.transport.call("acceptChatInvitation", params)

    def create_chat(self, name: str, target_mids: list[str]) -> dict:
        """Create a new group chat."""
        params = [
            [8, 1, 0],
            [12, 2, [
                [8, 1, 0],   # type: GROUP
                [11, 2, name],
                [15, 3, [11, target_mids]],
            ]],
        ]
        return self.transport.call("createChat", params)

    def invite_into_chat(self, chat_id: str, target_mids: list[str]) -> dict:
        """Invite users into a chat."""
        params = [
            [8, 1, 0],
            [11, 2, chat_id],
            [15, 3, [11, target_mids]],
        ]
        return self.transport.call("inviteIntoChat", params)

    def leave_chat(self, chat_id: str) -> dict:
        """Leave a chat."""
        params = [
            [8, 1, 0],
            [11, 2, chat_id],
        ]
        return self.transport.call("deleteSelfFromChat", params)

    def find_and_add_contact(self, mid: str) -> dict:
        """Find and add a contact by MID."""
        params = [
            [8, 1, 0],
            [11, 2, mid],
        ]
        return self.transport.call("findAndAddContactsByMid", params)
