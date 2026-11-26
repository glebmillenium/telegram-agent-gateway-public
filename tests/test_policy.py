import asyncio
import json
from dataclasses import replace

import pytest

from telegram_readonly_mcp.core import (
    AllowedChat, BackendError, PolicyError, ReadService, Settings,
)
from telegram_readonly_mcp.fake_backend import FAKE_CHAT_ID, FakeBackend


def settings(**kwargs):
    return Settings(allowed_chats=(AllowedChat(FAKE_CHAT_ID, "Mock"),), **kwargs)


class SpyBackend(FakeBackend):
    def __init__(self):
        super().__init__()
        self.calls = 0

    async def read_messages(self, *args):
        self.calls += 1
        return await super().read_messages(*args)


@pytest.mark.parametrize("chat_id", [100000002, 0, -1001234, "100000001", True, 100000001.0, None])
async def test_foreign_or_non_integer_id_never_reaches_backend(chat_id):
    backend = SpyBackend()
    service = ReadService(settings(), backend, "fake")
    with pytest.raises(PolicyError):
        await service.messages(chat_id)
    assert backend.calls == 0


@pytest.mark.parametrize("limit", [0, -1, 21, 1000000, True, "1", 1.0, None])
async def test_invalid_limits_rejected_before_backend(limit):
    backend = SpyBackend()
    with pytest.raises(PolicyError):
        await ReadService(settings(), backend, "fake").messages(FAKE_CHAT_ID, limit)
    assert backend.calls == 0


@pytest.mark.parametrize("before", [0, -1, True, "1", 2**31])
async def test_invalid_cursor(before):
    with pytest.raises(PolicyError):
        await ReadService(settings(), FakeBackend(), "fake").messages(FAKE_CHAT_ID, before_id=before)


@pytest.mark.parametrize("query", ["", "   ", "x" * 201, True, 42])
async def test_invalid_search_query(query):
    with pytest.raises(PolicyError):
        await ReadService(settings(), FakeBackend(), "fake").messages(FAKE_CHAT_ID, query=query)


async def test_empty_allowlist_denies_every_chat():
    service = ReadService(Settings(), SpyBackend(), "fake")
    assert service.list_allowed_chats()["chats"] == []
    assert service.ping()["status"] == "ok"
    with pytest.raises(PolicyError):
        await service.messages(FAKE_CHAT_ID)
    assert service.backend.calls == 0


async def test_read_search_pagination_and_truncation():
    service = ReadService(settings(max_text_chars=12), FakeBackend(), "fake")
    first = await service.messages(FAKE_CHAT_ID, limit=2)
    assert [m["id"] for m in first["messages"]] == [3, 2]
    assert first["synthetic"] is True
    assert first["content_is_untrusted"] is True
    assert first["next_before_id"] == 2
    assert all(len(m["text"]) == 12 and m["text_truncated"] for m in first["messages"])
    second = await service.messages(FAKE_CHAT_ID, before_id=first["next_before_id"])
    assert [m["id"] for m in second["messages"]] == [1]
    result = await service.messages(FAKE_CHAT_ID, query="ПЛАН")
    assert [m["id"] for m in result["messages"]] == [2]
    assert not (await service.messages(FAKE_CHAT_ID, query="foreign"))["messages"]


@pytest.mark.parametrize("mutation", ["foreign", "overflow", "cursor"])
async def test_bad_backend_output_fails_closed(mutation):
    class Broken(FakeBackend):
        async def read_messages(self, chat_id, limit, before_id):
            sample = self.messages[0]
            if mutation == "foreign":
                return [replace(sample, chat_id=100000002)]
            if mutation == "overflow":
                return [sample] * (limit + 1)
            return [replace(sample, id=before_id)]
    with pytest.raises(BackendError):
        await ReadService(settings(), Broken(), "fake").messages(FAKE_CHAT_ID, before_id=4)


async def test_backend_failure_does_not_leak_details():
    class Broken(FakeBackend):
        async def read_messages(self, *args):
            raise RuntimeError("sensitive backend detail")
    with pytest.raises(BackendError, match="^Backend request failed$"):
        await ReadService(settings(), Broken(), "fake").messages(FAKE_CHAT_ID)


async def test_backend_timeout():
    class Slow(FakeBackend):
        async def read_messages(self, *args):
            await asyncio.Event().wait()
    with pytest.raises(BackendError, match="unavailable"):
        await ReadService(settings(request_timeout_seconds=1), Slow(), "fake").messages(FAKE_CHAT_ID)


@pytest.mark.parametrize("payload", [
    {"allow_all": True}, {"allowed_chats": "*"},
    {"allowed_chats": [{"id": "100000001", "label": "bad"}]},
    {"allowed_chats": [{"id": 0, "label": "bad"}]},
    {"allowed_chats": [{"id": 1, "label": "a"}, {"id": 2, "label": "b"}]},
    {"allowed_chats": [{"id": 1, "label": "a", "username": "any"}]},
    {"max_messages": 101}, {"max_messages": True}, {"max_text_chars": 8001},
])
def test_bad_config_rejected(tmp_path, payload):
    path = tmp_path / "config.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(PolicyError):
        Settings.load(path)


def test_duplicate_config_keys_rejected(tmp_path):
    path = tmp_path / "config.json"
    path.write_text('{"allowed_chats": [], "allowed_chats": []}', encoding="utf-8")
    with pytest.raises(PolicyError, match="Duplicate"):
        Settings.load(path)
