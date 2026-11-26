import asyncio
import hashlib
import json
from pathlib import Path

import httpx
import pytest

from telegram_gateway.bot_api import FakeBotTransport
from telegram_gateway.demo import message
from telegram_gateway.http_server import create_app
from telegram_gateway.protocol import VERSION_KEY, CAPABILITIES_KEY
from telegram_gateway.runtime import Runtime, RuntimeBlocked, configuration_status, verify_bot_identity
from telegram_gateway.runtime_config import RuntimeConfig
from telegram_gateway.service import ConsumerBusy


def config(tmp_path, mode="fake", **changes):
    data = {"version": 1, "mode": mode, "state_dir": str(tmp_path / "state"),
            "bind": {"host": "127.0.0.1", "port": 8765},
            "policy": {"principals": {
                "zeta": [{"chat_id": -1001, "permissions": ["history", "events", "draft", "send"]}],
                "support": [{"chat_id": -1002, "topic_id": 7, "permissions": ["history", "events"]}]}},
            "auth": {"mode": "fake", "credentials": {"fixture-zeta": "zeta", "fixture-support": "support"}},
            "public_base_url": "http://127.0.0.1:8765", "outbound_enabled": True,
            "approval": {"owner_ids": [99], "review_scope": {"chat_id": -1001}},
            "bot": {"approved_groups": [{"chat_id": -1001, "type": "supergroup", "title": "FAKE zeta"},
                                         {"chat_id": -1002, "type": "supergroup", "title": "FAKE SUPPORT"}]},
            "allowed_callbacks": {"zeta": ["https://events.example.test/zeta"], "support": ["https://events.example.test/support"]}}
    if mode == "live":
        (tmp_path / "secrets").mkdir(exist_ok=True)
        data.update(network_enabled=True, secrets_dir=str(tmp_path / "secrets"),
                    agent_bindings={"zeta": "runtime_fixture_bot", "support": "runtime_fixture_bot"},
                    auth={"mode": "static", "token_digests": {hashlib.sha256(b"synthetic-test-credential-32-characters").hexdigest(): "zeta"}},
                    bot={"reference": "runtime_fixture_bot", "token_ref": {"env": "GATEWAY_TEST_UNUSED_TOKEN"}, "expected_bot_id": 70000,
                         "approved_groups": [{"chat_id": -1001, "type": "supergroup", "title": "FAKE zeta"},
                                             {"chat_id": -1002, "type": "supergroup", "title": "FAKE SUPPORT"}]})
    data.update(changes)
    return RuntimeConfig.from_dict(data)


class FakeLive(FakeBotTransport):
    def __init__(self):
        super().__init__()
        self.override = {}
    async def get_me(self):
        return {"ok": True, "result": self.override.get("me", {"id": 70000, "is_bot": True, "username": "runtime_fixture_bot"})}
    async def get_webhook_info(self):
        return {"ok": True, "result": self.override.get("webhook", {"url": ""})}
    async def get_chat(self, chat_id):
        return {"ok": True, "result": self.override.get("chat", {"id": chat_id, "type": "supergroup", "title": "FAKE zeta" if chat_id == -1001 else "FAKE SUPPORT"})}
    async def get_chat_member(self, chat_id, user_id):
        return {"ok": True, "result": self.override.get("member", {"user": {"id": user_id, "is_bot": user_id == 70000}, "status": "member"})}


@pytest.mark.asyncio
async def test_runtime_http_event_restart_end_to_end(tmp_path):
    cfg = config(tmp_path)
    transport = FakeBotTransport([message(1, -1001, "zeta only"), message(2, -1002, "SUPPORT only", topic=7), message(3, -1999, "Forbidden")])
    runtime = Runtime(cfg, transport=transport)
    await runtime.start()
    try:
        app = create_app(runtime.protocol, runtime.auth, resource_metadata=None,
                         metadata_url=cfg.public_base_url + "/.well-known/oauth-protected-resource/mcp",
                         allowed_hosts={"127.0.0.1:8765"}, allowed_origins=set())
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url=cfg.public_base_url) as client:
            async def rpc(method, params, who="zeta"):
                params = dict(params, _meta={VERSION_KEY: "2026-07-28", CAPABILITIES_KEY: {}})
                headers = {"Authorization": "Bearer fixture-" + who, "Accept": "application/json, text/event-stream",
                           "MCP-Protocol-Version": "2026-07-28", "Mcp-Method": method}
                if method == "tools/call":
                    headers["Mcp-Name"] = params["name"]
                return await client.post("/mcp", headers=headers, json={"jsonrpc": "2.0", "id": "e2e", "method": method, "params": params})
            discover = await rpc("server/discover", {})
            assert discover.status_code == 200
            assert discover.json()["result"]["resultType"] == "complete"
            for tool in ("ping", "status"):
                check = await rpc("tools/call", {"name": tool, "arguments": {}})
                assert check.status_code == 200 and "error" not in check.json(), check.text
                assert not check.json()["result"].get("isError"), check.text
            for who, chat, topic in (("zeta", -1001, None), ("support", -1002, 7)):
                subscribe = await rpc("events/subscribe", {"name": "telegram.message.created", "arguments": {"chat_id": chat, "topic_id": topic},
                    "delivery": {"mode": "webhook", "url": "https://events.example.test/" + who, "secret": "whsec_" + "YWFh" * 8}}, who)
                assert subscribe.status_code == 200, subscribe.text
            await runtime.gateway.poll_once()
            for principal in runtime.principals:
                runtime.gateway.export_events(principal, runtime.hub)
            await runtime.hub.deliver_due()
            assert len(runtime.fake_callbacks) == 2
            assert "Forbidden" not in json.dumps(runtime.fake_callbacks)
            response = await rpc("tools/call", {"name": "read_history", "arguments": {"chat_id": -1002, "topic_id": 7}})
            assert response.json().get("error") or response.json()["result"].get("isError") is True
    finally:
        await runtime.close()
    restarted = Runtime(cfg, transport=transport)
    await restarted.start()
    try:
        await restarted.gateway.poll_once()
        assert restarted.store.db.execute("SELECT COUNT(*) FROM gw_messages").fetchone()[0] == 2
        assert restarted.hub.status(restarted.principals[0])["active_subscriptions"] == 1
    finally:
        await restarted.close()


@pytest.mark.asyncio
async def test_foreground_serve_without_public_base_closes(tmp_path, monkeypatch):
    from telegram_gateway.runtime import serve
    data = {"version": 1, "mode": "fake", "state_dir": str(tmp_path / "state"),
            "policy": {"principals": {"zeta": []}},
            "auth": {"mode": "fake", "credentials": {"fixture-zeta": "zeta"}}}
    cfg = RuntimeConfig.from_dict(data)
    class FakeServer:
        def __init__(self, config):
            self.config = config
        async def serve(self):
            async with self.config.app.router.lifespan_context(self.config.app):
                await asyncio.sleep(.01)
    monkeypatch.setattr("uvicorn.Server", FakeServer)
    await serve(cfg)
    assert json.loads((cfg.state_dir / "runtime-status.json").read_text())["state"] == "stopped"


@pytest.mark.asyncio
async def test_operator_prompt_command_persists_without_approval_bypass(tmp_path):
    from telegram_gateway.runtime import approval_command
    cfg = config(tmp_path)
    runtime = Runtime(cfg)
    await runtime.start()
    principal = runtime.auth.authenticate("Bearer fixture-zeta")
    draft = runtime.gateway.create_draft(principal, -1001, "FAKE prompt command")
    draft_id = draft["draft"]["draft_id"]
    await runtime.close()
    with pytest.raises(RuntimeBlocked):
        await approval_command(cfg, "zeta", draft_id)
    result = await approval_command(cfg, "zeta", draft_id, confirm_send=True)
    assert result["status"] == "bound"
    check = Runtime(cfg)
    await check.start()
    try:
        assert check.store.db.execute("SELECT status FROM gw_drafts WHERE id=?", (draft_id,)).fetchone()[0] == "pending"
    finally:
        await check.close()


@pytest.mark.asyncio
async def test_exclusive_lifecycle_and_workers(tmp_path):
    cfg = config(tmp_path)
    runtime = Runtime(cfg)
    await runtime.start()
    other = Runtime(cfg)
    with pytest.raises(ConsumerBusy):
        await other.start()
    runtime.start_workers()
    await asyncio.sleep(.02)
    await runtime.close()
    assert json.loads((cfg.state_dir / "runtime-status.json").read_text())["state"] == "stopped"
    await other.start()
    await other.close()


@pytest.mark.parametrize("allow,network", [(False, False), (False, True), (True, False)])
def test_live_needs_both_gates(tmp_path, allow, network):
    cfg = config(tmp_path, "live", network_enabled=network)
    with pytest.raises(RuntimeBlocked):
        Runtime(cfg, allow_live=allow)


@pytest.mark.asyncio
async def test_fake_state_cannot_become_live(tmp_path):
    fake = Runtime(config(tmp_path))
    await fake.start()
    await fake.close()
    live = Runtime(config(tmp_path, "live"), allow_live=True, transport=FakeLive())
    with pytest.raises(RuntimeBlocked, match="another backend"):
        await live.start()


@pytest.mark.asyncio
@pytest.mark.parametrize("key,value", [
    ("me", {"id": 70001, "is_bot": True}),
    ("me", {"id": 70000, "is_bot": False}),
    ("webhook", {"url": "https://other.example/hook"}),
    ("chat", {"id": -1001, "type": "supergroup", "title": "Wrong"}),
    ("chat", {"id": -1001, "type": "supergroup", "title": "FAKE zeta", "username": "public"}),
    ("member", {"user": {"id": 70000, "is_bot": True}, "status": "left"}),
])
async def test_live_preflight_no_writes(tmp_path, key, value):
    transport = FakeLive()
    transport.override[key] = value
    with pytest.raises(RuntimeBlocked):
        await verify_bot_identity(config(tmp_path, "live"), transport)
    assert not transport.calls and not transport.sent


@pytest.mark.asyncio
async def test_readiness_and_disabled_send(tmp_path):
    cfg = config(tmp_path, outbound_enabled=False)
    status = configuration_status(cfg)
    assert status["secrets_read"] is False and status["telegram_checked"] is False
    runtime = Runtime(cfg)
    await runtime.start()
    try:
        with pytest.raises(ValueError, match="disabled"):
            await runtime.gateway.send_draft(runtime.principals[0], "0" * 32)
        assert runtime.gateway.ping(runtime.principals[0])["telegram_connected"] is False
    finally:
        await runtime.close()


@pytest.mark.asyncio
async def test_complete_runtime_over_ephemeral_loopback(tmp_path, monkeypatch):
    import socket
    import uvicorn
    from telegram_gateway.runtime import serve
    with socket.socket() as reservation:
        reservation.bind(("127.0.0.1", 0))
        port = reservation.getsockname()[1]
    cfg = config(tmp_path, bind={"host": "127.0.0.1", "port": port}, public_base_url=f"http://127.0.0.1:{port}")
    servers = []
    original = uvicorn.Server
    class ObservedServer(original):
        def __init__(self, cfg):
            super().__init__(cfg)
            servers.append(self)
    monkeypatch.setattr(uvicorn, "Server", ObservedServer)
    task = asyncio.create_task(serve(cfg))
    try:
        for _ in range(300):
            if servers and servers[0].started:
                break
            if task.done():
                await task
            await asyncio.sleep(.01)
        assert servers and servers[0].started
        async with httpx.AsyncClient(base_url=cfg.public_base_url, trust_env=False) as client:
            unauthorized = await client.post("/mcp", json={})
            assert unauthorized.status_code == 401
            response = await client.post("/mcp", headers={"Authorization": "Bearer fixture-zeta",
                "Accept": "application/json, text/event-stream", "MCP-Protocol-Version": "2026-07-28",
                "Mcp-Method": "tools/call", "Mcp-Name": "ping"}, json={"jsonrpc": "2.0", "id": "socket-ping",
                "method": "tools/call", "params": {"name": "ping", "arguments": {}, "_meta": {
                    VERSION_KEY: "2026-07-28", CAPABILITIES_KEY: {}}}})
            assert response.status_code == 200
            body = response.json()["result"]["structuredContent"]
            assert body["mode"] == "fake" and body["telegram_connected"] is False
    finally:
        if servers:
            servers[0].should_exit = True
        try:
            await asyncio.wait_for(task, timeout=10)
        except BaseException:
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)
            raise
    assert json.loads((cfg.state_dir / "runtime-status.json").read_text())["state"] == "stopped"
