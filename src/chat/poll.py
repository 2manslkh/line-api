"""
Long-polling for real-time events (new messages, etc).

LINE uses revision-based long-polling: you send your current revision,
the server holds the connection until new ops arrive, then returns them.
"""

import threading
import traceback
from typing import Callable
from ..transport.http import LineTransport
from ..config import LineConfig


# Operation types (from LINE protocol)
class OpType:
    END_OF_OPERATION = 0
    UPDATE_PROFILE = 1
    NOTIFIED_UPDATE_PROFILE = 2
    REGISTER_USERID = 3
    ADD_CONTACT = 4
    NOTIFIED_ADD_CONTACT = 5
    BLOCK_CONTACT = 6
    UNBLOCK_CONTACT = 7
    NOTIFIED_RECOMMEND_CONTACT = 8
    CREATE_GROUP = 9
    UPDATE_GROUP = 10
    NOTIFIED_UPDATE_GROUP = 11
    INVITE_INTO_GROUP = 12
    NOTIFIED_INVITE_INTO_GROUP = 13
    LEAVE_GROUP = 15
    NOTIFIED_LEAVE_GROUP = 16
    ACCEPT_GROUP_INVITATION = 17
    NOTIFIED_ACCEPT_GROUP_INVITATION = 18
    KICKOUT_FROM_GROUP = 19
    NOTIFIED_KICKOUT_FROM_GROUP = 20
    CREATE_ROOM = 21
    INVITE_INTO_ROOM = 22
    NOTIFIED_INVITE_INTO_ROOM = 23
    LEAVE_ROOM = 24
    NOTIFIED_LEAVE_ROOM = 25
    SEND_MESSAGE = 26
    RECEIVE_MESSAGE = 27
    SEND_MESSAGE_RECEIPT = 28
    RECEIVE_MESSAGE_RECEIPT = 29
    SEND_CONTENT_RECEIPT = 30
    RECEIVE_ANNOUNCEMENT = 31
    CANCEL_INVITATION_GROUP = 32
    NOTIFIED_CANCEL_INVITATION_GROUP = 33
    NOTIFIED_UNREGISTER_USER = 34
    REJECT_GROUP_INVITATION = 35
    NOTIFIED_REJECT_GROUP_INVITATION = 36
    UPDATE_SETTINGS = 47
    NOTIFIED_REGISTER_USER = 48
    INVITE_VIA_EMAIL = 49
    NOTIFIED_REQUEST_RECOVERY = 50
    SEND_CHAT_CHECKED = 52
    SEND_CHAT_REMOVED = 53
    NOTIFIED_FORCE_SYNC_MESSAGE = 54
    SEND_CONTENT = 55
    NOTIFIED_UPDATE_CONTENT_PREVIEW = 57
    NOTIFIED_PROFILE_CONTENT = 58
    NOTIFIED_READ_MESSAGE = 74


class Poller:
    """Long-poll for LINE operations."""

    def __init__(self, transport: LineTransport, config: LineConfig):
        self.transport = transport
        self.config = config
        self.revision = 0
        self._running = False

    def set_revision(self, revision: int):
        if revision is not None:
            self.revision = max(revision, self.revision)

    def fetch_ops(self, count: int = 100) -> list[dict]:
        """
        Fetch pending operations since current revision.
        Blocks until ops are available (long-poll).
        """
        params = [
            [10, 2, self.revision],
            [8, 3, count],
            [10, 4, 0],      # globalRev
            [10, 5, 0],      # individualRev
        ]
        resp = self.transport.call(
            "fetchOps", params,
            extra_headers={"x-lst": "60000"},  # 60s timeout
        )

        # Response is a list of operations
        ops = []
        if isinstance(resp, dict):
            # Single op or error
            if "error" in resp:
                raise RuntimeError(resp["error"])
            ops = [resp]
        elif isinstance(resp, list):
            ops = resp

        for op in ops:
            if isinstance(op, dict):
                op_type = op.get(3, -1)
                if op_type != -1:
                    revision = op.get(1)
                    if revision:
                        self.set_revision(revision)

        return ops

    def poll(self, handler: Callable[[dict], None]):
        """
        Generator that yields operations as they arrive.
        """
        while True:
            try:
                ops = self.fetch_ops()
                for op in ops:
                    yield op
            except Exception as e:
                print(f"[poll] Error: {e}")
                import time
                time.sleep(2)

    def poll_threaded(self, handler: Callable[[dict], None]):
        """Start polling in a background thread."""
        self._running = True

        def _run():
            while self._running:
                try:
                    for op in self.poll(handler):
                        if not self._running:
                            break
                        try:
                            handler(op)
                        except Exception:
                            traceback.print_exc()
                except Exception:
                    traceback.print_exc()
                    import time
                    time.sleep(5)

        t = threading.Thread(target=_run, daemon=True)
        t.start()
        return t

    def stop(self):
        self._running = False
