"""Exercise pinned Telethon lifecycle code without a network or session file.

Unlike the adapter's fake-client tests, these call real connect/sign_in methods.
Only the MTProto sender is fake; a guard makes any actual transport connection a
test failure. Test account/application values are inert, synthetic constants.
"""

import asyncio
from datetime import datetime, timezone

import pytest
from telethon import errors
from telethon.network.connection.tcpfull import ConnectionTcpFull
from telethon.sessions import MemorySession
from telethon.tl import functions, types

from telegram_readonly_mcp.core import BackendError
from telegram_readonly_mcp.telethon_backend import (
    NoUpdatesTelegramClient,
    RuntimeTelegramClient,
    UserLoginTelegramClient,
)


def unwrap(request):
    while type(request) in (
        functions.InvokeWithLayerRequest,
        functions.InvokeWithoutUpdatesRequest,
        functions.InitConnectionRequest,
    ):
        request = request.query
    return request


class MemoryOnlySender:
    """No sockets, encrypted transport, key generation or account access."""

    def __init__(self):
        self.auth_key = object()
        self.requests = []
        self.connections = 0
        self.failure = None
        self.user = types.User(id=42, access_hash=23, first_name="Synthetic", bot=False)

    async def connect(self, connection):
        self.connections += 1
        # The actual Telethon connection object is intentionally never started.
        return True

    async def send(self, request, ordered=False):
        self.requests.append(request)
        leaf = unwrap(request)
        if self.failure is not None:
            raise self.failure
        if type(leaf) is functions.help.GetConfigRequest:
            return None
        if type(leaf) is functions.auth.SignInRequest:
            return types.auth.Authorization(user=self.user)
        if type(leaf) in (functions.messages.GetHistoryRequest, functions.messages.SearchRequest):
            return types.messages.Messages(messages=[], topics=[], chats=[], users=[])
        if type(leaf) is functions.contacts.ResolveUsernameRequest:
            return types.contacts.ResolvedPeer(peer=types.PeerUser(42), chats=[], users=[self.user])
        raise AssertionError(f"Unexpected request: {type(leaf).__name__}")

    def is_connected(self):
        # Causes the real keepalive task to finish without scheduling any work.
        return False


@pytest.fixture(autouse=True)
def no_real_transport(monkeypatch):
    async def forbidden_connection(*args, **kwargs):
        raise AssertionError("A lifecycle test attempted a real Telegram connection")

    monkeypatch.setattr(ConnectionTcpFull, "connect", forbidden_connection)


def build_client(client_type=NoUpdatesTelegramClient, **kwargs):
    options = dict(
        receive_updates=False, catch_up=False, request_retries=0,
        connection_retries=0, auto_reconnect=False, flood_sleep_threshold=0,
    )
    options.update(kwargs)
    client = client_type(MemorySession(), 1234, "synthetic-application-value", **options)
    sender = MemoryOnlySender()
    client._sender = sender
    return client, sender


async def finish_background_tasks(client):
    # connect creates these using real Telethon code. Neither should poll.
    await asyncio.wait_for(asyncio.gather(client._updates_handle, client._keepalive_handle), timeout=1)


async def test_real_connect_only_sends_protocol_configuration():
    client, sender = build_client()
    await client.connect()
    await finish_background_tasks(client)
    assert sender.connections == 1
    assert len(sender.requests) == 1
    assert type(sender.requests[0]) is functions.InvokeWithLayerRequest
    assert type(sender.requests[0].query) is functions.InvokeWithoutUpdatesRequest
    assert type(unwrap(sender.requests[0])) is functions.help.GetConfigRequest
    assert await client.get_me() is None
    assert await client.is_user_authorized() is False
    assert len(sender.requests) == 1


async def test_real_sign_in_does_not_fetch_account_wide_updates():
    client, sender = build_client(UserLoginTelegramClient, peer_username=None)
    await client.connect()
    await finish_background_tasks(client)
    sender.requests.clear()

    # Real sign_in builds/resolves the request and invokes the real _on_login.
    # The fake sender supplies a synthetic response, without authorizing anyone.
    result = await client.sign_in(
        phone="+10000000000", code="00000", phone_code_hash="synthetic-code-hash",
    )
    assert result.id == 42
    assert await client.is_user_authorized() is True
    assert [type(unwrap(request)) for request in sender.requests] == [functions.auth.SignInRequest]
    assert client._mb_entity_cache.self_id == 42


async def test_runtime_real_call_allows_only_exact_scoped_reads():
    client, sender = build_client(RuntimeTelegramClient, allowed_chat_ids=frozenset({123}), max_messages=5)
    await client.connect()
    await finish_background_tasks(client)
    sender.requests.clear()
    request = functions.messages.GetHistoryRequest(
        peer=types.InputPeerUser(123, 777), offset_id=0, offset_date=None,
        add_offset=0, limit=2, max_id=0, min_id=0, hash=0,
    )
    result = await client(request)
    assert result.messages == []
    assert [type(unwrap(item)) for item in sender.requests] == [functions.messages.GetHistoryRequest]

    sender.requests.clear()
    foreign = functions.messages.GetHistoryRequest(
        peer=types.InputPeerUser(124, 777), offset_id=0, offset_date=None,
        add_offset=0, limit=2, max_id=0, min_id=0, hash=0,
    )
    for forbidden in (foreign, functions.updates.GetStateRequest(), functions.updates.GetDifferenceRequest(
        pts=1, date=datetime(2026, 10, 21, tzinfo=timezone.utc), qts=0,
    ), functions.messages.SendMessageRequest(
        peer=types.InputPeerUser(123, 777), message="Never sent", random_id=999,
    ), functions.messages.ReadHistoryRequest(
        peer=types.InputPeerUser(123, 777), max_id=4,
    ), functions.messages.GetDialogsRequest(
        offset_date=None, offset_id=0, offset_peer=types.InputPeerEmpty(), limit=1, hash=0,
    ), [request]):
        with pytest.raises(BackendError):
            await client(forbidden)
    assert sender.requests == []


async def test_runtime_dc_migration_fails_without_connecting():
    client, sender = build_client(RuntimeTelegramClient, allowed_chat_ids=frozenset({123}), max_messages=5)
    with pytest.raises(BackendError):
        await client._switch_dc(2)
    assert sender.connections == 0
    assert sender.requests == []


async def test_real_sdk_migration_path_does_not_generate_another_key():
    client, sender = build_client(RuntimeTelegramClient, allowed_chat_ids=frozenset({123}), max_messages=5)
    await client.connect()
    await finish_background_tasks(client)
    sender.requests.clear()
    original_key = client.session.auth_key
    request = functions.messages.GetHistoryRequest(
        peer=types.InputPeerUser(123, 777), offset_id=0, offset_date=None,
        add_offset=0, limit=2, max_id=0, min_id=0, hash=0,
    )
    sender.failure = errors.PhoneMigrateError(request=request, capture=4)
    with pytest.raises(BackendError):
        await client(request)
    assert sender.connections == 1
    assert client.session.auth_key is original_key
    assert [type(unwrap(item)) for item in sender.requests] == [functions.messages.GetHistoryRequest]


async def test_user_login_cannot_read_messages_or_resolve_other_peers():
    client, sender = build_client(UserLoginTelegramClient, peer_username="selected_peer")
    await client.connect()
    await finish_background_tasks(client)
    sender.requests.clear()
    for request in (
        functions.updates.GetStateRequest(),
        functions.contacts.ResolveUsernameRequest(username="other_peer"),
        functions.messages.GetHistoryRequest(
            peer=types.InputPeerUser(123, 777), offset_id=0, offset_date=None,
            add_offset=0, limit=2, max_id=0, min_id=0, hash=0,
        ),
    ):
        with pytest.raises(BackendError):
            await client(request)
    assert sender.requests == []

    result = await client(functions.contacts.ResolveUsernameRequest(username="selected_peer"))
    assert result.peer.user_id == 42
    assert [type(unwrap(item)) for item in sender.requests] == [functions.contacts.ResolveUsernameRequest]
    with pytest.raises(BackendError):
        await client(functions.contacts.ResolveUsernameRequest(username="selected_peer"))
    assert len(sender.requests) == 1


async def test_update_loop_never_checks_account_state_even_while_connected(monkeypatch):
    client, sender = build_client()
    monkeypatch.setattr(sender, "is_connected", lambda: True)

    def forbidden_state_access(*args, **kwargs):
        raise AssertionError("The update loop attempted account-wide state access")

    monkeypatch.setattr(type(client._message_box), "get_difference", forbidden_state_access)
    monkeypatch.setattr(type(client._message_box), "check_deadlines", forbidden_state_access)
    await asyncio.wait_for(client._update_loop(), timeout=0.25)
    assert sender.requests == []
    assert sender.connections == 0


async def test_user_login_retries_send_code_once_after_dc_migration(monkeypatch):
    client, sender = build_client(UserLoginTelegramClient, peer_username=None, request_retries=1)
    await client.connect()
    await finish_background_tasks(client)
    sender.requests.clear()
    migrations = []

    async def fake_switch_dc(new_dc):
        # Exercise Telethon retry control flow without touching any transport,
        # session key, or real datacenter connection.
        migrations.append(new_dc)

    async def migrate_then_success(request, ordered=False):
        sender.requests.append(request)
        leaf = unwrap(request)
        assert type(leaf) is functions.auth.SendCodeRequest
        if len(sender.requests) == 1:
            raise errors.PhoneMigrateError(request=leaf, capture=4)
        return types.auth.SentCode(
            type=types.auth.SentCodeTypeApp(length=5), phone_code_hash="synthetic-code-hash",
        )

    monkeypatch.setattr(client, "_switch_dc", fake_switch_dc)
    monkeypatch.setattr(sender, "send", migrate_then_success)
    result = await client(functions.auth.SendCodeRequest(
        phone_number="+10000000000", api_id=1234,
        api_hash="synthetic-application-value", settings=types.CodeSettings(),
    ))
    assert result.phone_code_hash == "synthetic-code-hash"
    assert migrations == [4]
    assert sender.connections == 1
    assert [type(unwrap(item)) for item in sender.requests] == [functions.auth.SendCodeRequest] * 2
