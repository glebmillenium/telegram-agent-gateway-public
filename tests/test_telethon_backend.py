from argparse import Namespace
import asyncio
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest
from telethon.tl import functions, types

from telegram_readonly_mcp.core import BackendError
from telegram_readonly_mcp import telethon_backend as module
from telegram_readonly_mcp.login import login


CHAT_ID = 123456789


def settings():
    return SimpleNamespace(
        allowed_chats=(SimpleNamespace(id=CHAT_ID, label="Synthetic allowed peer"),),
        max_messages=5, max_text_chars=30, request_timeout_seconds=1,
    )


class FakeSession:
    def __init__(self):
        self.auth_key = object()
        self.save_entities = True
        self.peer = types.InputPeerUser(CHAT_ID, 777)
        self.closed = False
        self.lookups = []

    def get_input_entity(self, chat_id):
        self.lookups.append(chat_id)
        if self.peer is None:
            raise ValueError("must not leak")
        return self.peer

    def close(self):
        self.closed = True


class FakeClient:
    def __init__(self):
        self.session = FakeSession()
        self.connected = 0
        self.disconnected = 0
        self.calls = []
        self.messages = [SimpleNamespace(
            id=4, peer_id=types.PeerUser(CHAT_ID),
            date=datetime(2026, 10, 21, tzinfo=timezone.utc),
            from_id=types.PeerUser(CHAT_ID), message="Synthetic message " * 4,
            out=False, media=None,
        )]
        self.failure = None

    async def connect(self):
        self.connected += 1

    async def disconnect(self):
        self.disconnected += 1

    async def __call__(self, request):
        assert type(request) in (functions.messages.GetHistoryRequest, functions.messages.SearchRequest)
        self.calls.append(request)
        if self.failure is not None:
            raise self.failure
        return SimpleNamespace(messages=self.messages)


@pytest.fixture
def stub(monkeypatch, tmp_path):
    client = FakeClient()
    constructions = []

    def create(*args, **kwargs):
        constructions.append((args, kwargs))
        return client

    monkeypatch.setattr(module, "RuntimeTelegramClient", create)
    # No existing session is read or created, even in this mocked test suite.
    monkeypatch.setattr(module, "validated_session_path", lambda path, **kwargs: tmp_path / "not-opened.session")
    backend = module.TelethonBackend(settings(), tmp_path / "not-opened.session", 1234, "synthetic-not-secret")
    return backend, client, constructions


async def test_lazy_start_and_only_scoped_history_rpc(stub):
    backend, client, constructions = stub
    assert constructions == []
    messages = await backend.read_messages(CHAT_ID, 2, 9)
    assert len(constructions) == 1
    options = constructions[0][1]
    assert options["receive_updates"] is False
    assert options["catch_up"] is False
    assert options["request_retries"] == 0
    assert options["connection_retries"] == 0
    assert options["auto_reconnect"] is False
    assert options["flood_sleep_threshold"] == 0
    assert client.session.save_entities is False
    assert client.session.lookups == [CHAT_ID]
    assert type(client.calls[0]) is functions.messages.GetHistoryRequest
    assert client.calls[0].peer.user_id == CHAT_ID
    assert client.calls[0].limit == 2
    assert client.calls[0].offset_id == 9
    assert messages[0].chat_id == CHAT_ID
    assert messages[0].text == "Synthetic message " * 4  # core owns truncation metadata
    assert messages[0].outgoing is False
    assert messages[0].has_media is False
    await backend.close()
    assert client.disconnected == 1


async def test_search_is_single_peer_scoped(stub):
    backend, client, _ = stub
    await backend.search_messages(CHAT_ID, "Synthetic", 3)
    request = client.calls[0]
    assert type(request) is functions.messages.SearchRequest
    assert request.peer.user_id == CHAT_ID
    assert request.q == "Synthetic"
    assert request.limit == 3


@pytest.mark.parametrize("chat_id", [CHAT_ID + 1, "123456789", True, None, "@example_peer"])
async def test_foreign_and_non_numeric_peer_denied_before_session_access(stub, chat_id):
    backend, client, constructions = stub
    with pytest.raises(BackendError, match="allowlisted"):
        await backend.read_messages(chat_id, 1)
    assert constructions == []
    assert client.calls == []


@pytest.mark.parametrize("limit", [0, -1, 6, 999999, True, "2", None])
async def test_invalid_limit_denied_before_session_access(stub, limit):
    backend, _, constructions = stub
    with pytest.raises(BackendError, match="limit"):
        await backend.read_messages(CHAT_ID, limit)
    assert constructions == []


@pytest.mark.parametrize("before_id", [0, -1, True, "4", 2**31])
async def test_invalid_offset_denied_before_session_access(stub, before_id):
    backend, _, constructions = stub
    with pytest.raises(BackendError, match="before_id"):
        await backend.read_messages(CHAT_ID, 1, before_id)
    assert constructions == []


@pytest.mark.parametrize("query", ["", " ", "a" * 201, 123])
async def test_invalid_query_denied_before_session_access(stub, query):
    backend, _, constructions = stub
    with pytest.raises(BackendError, match="Search requires"):
        await backend.search_messages(CHAT_ID, query, 1)
    assert constructions == []


async def test_unknown_peer_does_not_trigger_dialog_lookup(stub):
    backend, client, _ = stub
    client.session.peer = None
    with pytest.raises(BackendError, match="cache"):
        await backend.read_messages(CHAT_ID, 1)
    assert client.calls == []
    assert client.session.lookups == [CHAT_ID]


async def test_wrong_cached_peer_denied_before_rpc(stub):
    backend, client, _ = stub
    client.session.peer = types.InputPeerUser(CHAT_ID + 1, 777)
    with pytest.raises(BackendError, match="does not match"):
        await backend.read_messages(CHAT_ID, 1)
    assert client.calls == []


async def test_missing_auth_key_never_connects_or_authorizes(stub):
    backend, client, _ = stub
    client.session.auth_key = None
    with pytest.raises(BackendError, match="authorization key"):
        await backend.read_messages(CHAT_ID, 1)
    assert client.connected == 0
    assert client.calls == []
    assert client.session.closed


async def test_empty_auth_key_never_connects_or_generates_key(stub):
    from telethon.crypto import AuthKey
    backend, client, _ = stub
    client.session.auth_key = AuthKey(data=b"")
    with pytest.raises(BackendError, match="authorization key"):
        await backend.read_messages(CHAT_ID, 1)
    assert client.connected == 0
    assert client.calls == []
    assert client.session.closed


async def test_foreign_response_is_rejected(stub):
    backend, client, _ = stub
    client.messages[0].peer_id = types.PeerUser(CHAT_ID + 1)
    with pytest.raises(BackendError, match="different chat"):
        await backend.read_messages(CHAT_ID, 1)


async def test_rpc_errors_are_sanitized(stub):
    backend, client, _ = stub
    client.failure = RuntimeError("PRIVATE_CONTENT_OR_SECRET")
    with pytest.raises(BackendError) as error:
        await backend.read_messages(CHAT_ID, 1)
    assert "PRIVATE_CONTENT_OR_SECRET" not in str(error.value)
    assert client.disconnected == 1


async def test_external_cancellation_disconnects(stub, monkeypatch):
    backend, client, _ = stub
    request_started = asyncio.Event()

    async def blocked_call(self, request):
        request_started.set()
        await asyncio.Event().wait()

    monkeypatch.setattr(FakeClient, "__call__", blocked_call)
    task = asyncio.create_task(backend.read_messages(CHAT_ID, 1))
    await request_started.wait()
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert client.disconnected == 1
    assert backend._client is None


async def test_backend_rejects_upstream_overflow(stub):
    backend, client, _ = stub
    client.messages *= 20
    with pytest.raises(BackendError, match="more messages"):
        await backend.read_messages(CHAT_ID, 2)


async def test_read_only_interface_has_no_generic_rpc_or_write_method(stub):
    backend, _, _ = stub
    assert {name for name in dir(backend) if not name.startswith("_")} == {"read_messages", "search_messages", "close"}


def test_session_path_rejects_project_path_without_opening_it():
    project = Path(module.__file__).resolve().parents[2]
    with pytest.raises(BackendError, match="outside"):
        module.validated_session_path(project / "forbidden.session", must_exist=False)


def test_session_path_rejects_relative_path():
    with pytest.raises(BackendError, match="absolute"):
        module.validated_session_path(Path("relative.session"), must_exist=False)


async def test_login_requires_explicit_acknowledgment_before_touching_session():
    args = Namespace(accept_full_account_session_risk=False, session=Path("never-opened.session"), peer_username=None)
    with pytest.raises(BackendError, match="acknowledgment"):
        await login(args)


async def test_login_refuses_noninteractive_agent_execution(monkeypatch):
    import sys
    monkeypatch.setattr(sys.stdin, "isatty", lambda: False)
    args = Namespace(accept_full_account_session_risk=True, session=Path("never-opened.session"), peer_username=None)
    with pytest.raises(BackendError, match="interactive terminal"):
        await login(args)
