import asyncio
import json
import socket
import sys
from pathlib import Path

import httpx
import pytest
import uvicorn
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from mcp.client.streamable_http import streamable_http_client

from telegram_readonly_mcp.core import AllowedChat, PolicyError, ReadService, Settings
from telegram_readonly_mcp.fake_backend import FAKE_CHAT_ID, FakeBackend
from telegram_readonly_mcp.server import ConfiguredTelegramBackend, TOOL_NAMES, create_http_app

ROOT = Path(__file__).resolve().parents[1]


async def verify_session(session):
    initialized = await session.initialize()
    assert initialized.capabilities.resources is None
    assert initialized.capabilities.prompts is None
    assert initialized.capabilities.logging is None
    tools = (await session.list_tools()).tools
    assert {t.name for t in tools} == TOOL_NAMES
    assert all(t.annotations.readOnlyHint and not t.annotations.destructiveHint for t in tools)
    assert all(t.inputSchema["additionalProperties"] is False for t in tools)
    ping = await session.call_tool("ping", {})
    assert not ping.isError
    assert ping.structuredContent["telegram_connection_checked"] is False
    chats = await session.call_tool("list_allowed_chats", {})
    assert [c["id"] for c in chats.structuredContent["chats"]] == [FAKE_CHAT_ID]
    result = await session.call_tool("read_messages", {"chat_id": FAKE_CHAT_ID, "limit": 2})
    assert not result.isError
    assert len(result.structuredContent["messages"]) == 2
    found = await session.call_tool("search_messages", {"chat_id": FAKE_CHAT_ID, "query": "план", "limit": 1})
    assert not found.isError
    assert found.structuredContent["messages"][0]["id"] == 2
    denied_calls = [
        ("read_messages", {"chat_id": 100000002}),
        ("read_messages", {"chat_id": str(FAKE_CHAT_ID)}),
        ("read_messages", {"chat_id": FAKE_CHAT_ID, "limit": 21}),
        ("read_messages", {"chat_id": FAKE_CHAT_ID, "limit": True}),
        ("read_messages", {"chat_id": FAKE_CHAT_ID, "method": "send_message"}),
        ("search_messages", {"query": "all chats"}),
        ("search_messages", {"chat_id": FAKE_CHAT_ID, "query": "   "}),
        ("search_messages", {"chat_id": FAKE_CHAT_ID, "query": "x" * 201}),
        ("ping", {"token": "must-not-be-reflected"}),
    ] + [(name, {}) for name in ["send_message", "edit_message", "delete_messages", "forward_messages", "mark_read", "rpc", "get_dialogs", "global_search"]]
    for name, args in denied_calls:
        result = await session.call_tool(name, args)
        assert result.isError, (name, args)
        assert "must-not-be-reflected" not in result.model_dump_json()


async def test_real_stdio_mcp_roundtrip():
    params = StdioServerParameters(command=sys.executable, args=[
        "-m", "telegram_readonly_mcp.server", "--config", str(ROOT / "config.fake.json")])
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            await verify_session(session)


async def test_real_loopback_http_roundtrip_and_host_protection():
    service = ReadService(Settings(allowed_chats=(AllowedChat(FAKE_CHAT_ID, "Mock"),)), FakeBackend(), "fake")
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    server = uvicorn.Server(uvicorn.Config(create_http_app(service), log_level="critical", access_log=False))
    task = asyncio.create_task(server.serve(sockets=[sock]))
    try:
        async with asyncio.timeout(10):
            while not server.started:
                if task.done():
                    await task
                await asyncio.sleep(0.01)
        url = f"http://127.0.0.1:{port}/mcp"
        async with streamable_http_client(url) as (read, write, _):
            async with ClientSession(read, write) as session:
                await verify_session(session)
        async with httpx.AsyncClient() as client:
            result = await client.post(url, headers={"host": "attacker.invalid"}, json={})
            assert result.status_code == 421
            result = await client.post(url, headers={"origin": "https://attacker.invalid"}, json={})
            assert result.status_code == 403
            result = await client.post(url, content=b"x" * 16_385, headers={"content-type": "application/json"})
            assert result.status_code == 413
    finally:
        server.should_exit = True
        await asyncio.wait_for(task, 10)
        sock.close()


def test_telegram_http_refused():
    with pytest.raises(PolicyError):
        create_http_app(ReadService(Settings(), FakeBackend(), "telegram"))


async def test_ping_allowlist_never_load_telegram_credentials_or_session(monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError("No credential or session access is permitted")
    monkeypatch.setattr(ConfiguredTelegramBackend, "_get", forbidden)
    backend = ConfiguredTelegramBackend(Settings(), Path("not-opened.session"))
    service = ReadService(Settings(), backend, "telegram")
    assert service.ping()["status"] == "ok"
    assert service.list_allowed_chats()["chats"] == []
    await backend.close()
