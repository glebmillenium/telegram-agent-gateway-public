"""Deterministic in-memory fixtures. Never connects to Telegram."""

from .core import Message

FAKE_CHAT_ID = 100000001


class FakeBackend:
    def __init__(self) -> None:
        self.messages = [
            Message(3, FAKE_CHAT_ID, "2026-10-21T08:03:00+00:00", FAKE_CHAT_ID,
                    "MOCK: второй тест чтения MCP", False, False),
            Message(2, FAKE_CHAT_ID, "2026-10-21T08:02:00+00:00", FAKE_CHAT_ID,
                    "MOCK: согласуем план рабочего пилота", False, False),
            Message(1, FAKE_CHAT_ID, "2026-10-21T08:01:00+00:00", FAKE_CHAT_ID,
                    "MOCK: первое тестовое сообщение", False, False),
            Message(99, 100000002, "2026-10-21T08:00:00+00:00", 100000002,
                    "MOCK: this foreign chat must never be returned", False, False),
        ]

    async def read_messages(self, chat_id: int, limit: int, before_id: int | None) -> list[Message]:
        return [m for m in self.messages if m.chat_id == chat_id
                and (before_id is None or m.id < before_id)][:limit]

    async def search_messages(self, chat_id: int, query: str, limit: int, before_id: int | None) -> list[Message]:
        return [m for m in self.messages if m.chat_id == chat_id
                and (before_id is None or m.id < before_id)
                and query.casefold() in m.text.casefold()][:limit]

    async def close(self) -> None:
        pass
