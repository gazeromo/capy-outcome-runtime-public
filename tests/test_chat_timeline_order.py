from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from capy_outcome_runtime.chat import ChatStore

class ChatTimelineOrder(unittest.TestCase):
    def test_equal_timestamp_messages_keep_durable_insertion_order(self):
        with tempfile.TemporaryDirectory() as root:
            store = ChatStore(Path(root) / "chat.sqlite3")
            conversation = store.create_conversation("owner")
            with patch("capy_outcome_runtime.chat.utc_now", return_value="2026-09-05T00:00:00.000Z"):
                ids = [store.append_message("owner", conversation, "owner" if i == 0 else "assistant", str(i)) for i in range(8)]
            for current in (store, ChatStore(Path(root) / "chat.sqlite3")):
                self.assertEqual(ids, [m["id"] for m in current.timeline("owner", conversation)["messages"]])
