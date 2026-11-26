"""Actual loopback HTTP for two synthetic bots; not an agent/dot integration."""
import asyncio
from contextlib import asynccontextmanager, suppress
import socket

import httpx
import pytest
import uvicorn

from telegram_gateway.bot_api import FakeBotTransport
from telegram_gateway.demo import message
from telegram_gateway.http_server import VERSION, create_app
from telegram_gateway.protocol import CAPABILITIES_KEY, VERSION_KEY
from telegram_gateway.runtime import make_runtime
from telegram_gateway.runtime_config import RuntimeConfig
from telegram_gateway.service import ProcessLock


def _request(name, arguments=None):
    return {"jsonrpc": "2.0", "id": "multi-http-fixture", "method": "tools/call", "params": {
        "name": name, "arguments": arguments or {},
        "_meta": {VERSION_KEY: VERSION, CAPABILITIES_KEY: {}},
    }}


def _headers(name, credential=None):
    headers = {"Content-Type": "application/json", "Accept": "application/json, text/event-stream",
               "MCP-Protocol-Version": VERSION, "Mcp-Method": "tools/call", "Mcp-Name": name}
    if credential is not None:
        headers["Authorization"] = "Bearer " + credential
    return headers


@pytest.mark.asyncio
async def test_two_fake_bots_over_loopback_mcp2_and_cancelled_shutdown(tmp_path):
    """One real HTTP listener routes only by verified Bearer principal."""
    fixtures = (
        ("zeta", "example_zeta_bot", -11001, "fixture-http-zeta", "ZETA SYNTHETIC ONLY"),
        ("agent_beta", "example_agent_beta_bot", -11002, "fixture-http-agent_beta", "AGENT_BETA SYNTHETIC ONLY"),
    )
    profiles = [{
        "id": principal, "name": principal, "purpose": "Synthetic HTTP test", "prompt": "Inert metadata",
        "enabled": True, "telegram_username": reference, "auth_principal": principal,
        "chats": [{"chat_id": chat, "type": "supergroup", "title": "Synthetic " + principal,
                   "topic_id": 7, "actions": ["history", "events"]}],
    } for principal, reference, chat, _, _ in fixtures]
    cfg = RuntimeConfig.from_dict({
        "version": 1, "mode": "fake", "state_dir": str(tmp_path / "state"),
        "network_enabled": False, "outbound_enabled": False, "poll_interval_seconds": 300,
        "auth": {"mode": "fake", "credentials": {credential: principal for principal, _, _, credential, _ in fixtures}},
        "agents": profiles,
    }, project_root=tmp_path / "synthetic-code")
    # Identical Telegram update/message IDs are deliberately reused per bot.
    transports = {reference: FakeBotTransport([message(1, chat, text, topic=7)])
                  for _, reference, chat, _, text in fixtures}
    runtime = make_runtime(cfg, transports=transports)
    children, workers = [], []

    @asynccontextmanager
    async def lifecycle(app):
        await runtime.start()
        try:
            assert len(runtime.children) == 2
            children.extend(runtime.children.values())
            assert all(child.auth is runtime.auth for child in children)
            await asyncio.gather(*(child.gateway.poll_once() for child in children))
            runtime.start_workers()
            workers.extend(task for child in children for task in child.tasks)
            yield
        finally:
            await runtime.close()

    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0))
    listener.listen(5)
    listener.setblocking(False)
    port = listener.getsockname()[1]
    base = f"http://127.0.0.1:{port}"
    app = create_app(runtime.protocol, runtime.auth, resource_metadata=None,
                     metadata_url=base + "/.well-known/oauth-protected-resource",
                     allowed_hosts={f"127.0.0.1:{port}"}, allowed_origins=set(), lifecycle=lifecycle)
    server = uvicorn.Server(uvicorn.Config(app, log_config=None, access_log=False,
                                          log_level="critical", lifespan="on"))
    server_task = asyncio.create_task(server.serve(sockets=[listener]))
    try:
        async with asyncio.timeout(10):
            while not server.started and not server_task.done():
                await asyncio.sleep(0.01)
        assert server.started and not server_task.done()
        async with httpx.AsyncClient(base_url=base, trust_env=False, timeout=3) as client:
            unauthorized = await client.post("/mcp", json=_request("ping"), headers=_headers("ping"))
            assert unauthorized.status_code == 401
            assert unauthorized.headers["www-authenticate"] == "Bearer"
            pings = await asyncio.gather(*(
                client.post("/mcp", json=_request("ping"), headers=_headers("ping", credential))
                for _, _, _, credential, _ in fixtures))
            for response, (_, reference, _, _, _) in zip(pings, fixtures):
                assert response.status_code == 200
                result = response.json()["result"]["structuredContent"]
                assert result["status"] == "ok" and result["bot_reference"] == reference
                assert result["backend"] == "fake" and result["telegram_connected"] is False
                assert result["cloud_delivery_confirmed"] is None
                assert result["cloud_delivery_status"] == "not_evaluated"
                assert "mcp-session-id" not in response.headers

            statuses = await asyncio.gather(*(
                client.post("/mcp", json=_request("status"), headers=_headers("status", credential))
                for _, _, _, credential, _ in fixtures))
            for response in statuses:
                assert response.status_code == 200
                result = response.json()["result"]["structuredContent"]
                assert result["cloud_delivery_confirmed"] is None
                assert result["cloud_delivery_status"] == "not_evaluated"

            histories = await asyncio.gather(*(
                client.post("/mcp", json=_request("read_history", {"chat_id": chat, "topic_id": 7}),
                            headers=_headers("read_history", credential))
                for _, _, chat, credential, _ in fixtures))
            for index, (response, (_, reference, chat, credential, text)) in enumerate(zip(histories, fixtures)):
                assert response.status_code == 200
                rows = response.json()["result"]["structuredContent"]["messages"]
                assert [row["text"] for row in rows] == [text]
                assert rows[0]["bot_reference"] == reference
                _, other_bot, other_chat, _, other_text = fixtures[1 - index]
                assert other_text not in response.text and other_bot not in response.text
                forbidden = await client.post("/mcp", json=_request("read_history", {"chat_id": other_chat, "topic_id": 7}),
                                              headers=_headers("read_history", credential))
                assert forbidden.status_code == 403 and forbidden.json()["error"]["code"] == -33001
                assert other_text not in forbidden.text
                for field in ("bot_reference", "bot", "agent_id", "principal"):
                    selector = await client.post("/mcp", json=_request("read_history", {
                        "chat_id": chat, "topic_id": 7, field: other_bot,
                    }), headers=_headers("read_history", credential))
                    if field in ("agent_id", "principal"):
                        assert selector.status_code == 400 and selector.json()["error"]["code"] == -32602
                    else:
                        assert selector.status_code == 200
                        rejected = selector.json()["result"]
                        assert rejected["isError"] is True and "structuredContent" not in rejected
                    assert text not in selector.text and other_text not in selector.text
            assert all(transport.sent == [] for transport in transports.values())

        # Cancellation of the shutdown caller must still finish both children,
        # poll/delivery task cancellation, SQLite closes and lock release.
        closing = asyncio.create_task(runtime.close())
        await asyncio.sleep(0)
        assert closing.cancel()
        with pytest.raises(asyncio.CancelledError):
            await closing
        assert len(workers) == 4 and all(task.done() and task.cancelled() for task in workers)
        assert not runtime.started and runtime.lock is None and runtime.children == {}
        assert all(child.store is None and child.hub is None and child.secrets is None
                   and child.lock is None and child.tasks == [] for child in children)
        for state_dir in (cfg.state_dir, *(child.cfg.state_dir for child in children)):
            with ProcessLock(state_dir / "runtime.lock"):
                pass
    finally:
        server.should_exit = True
        try:
            await asyncio.wait_for(asyncio.shield(server_task), timeout=5)
        except asyncio.TimeoutError:
            server.force_exit = True
            server_task.cancel()
            with suppress(asyncio.CancelledError):
                await server_task
        finally:
            listener.close()
            await runtime.close()
    assert server_task.done() and listener.fileno() == -1
