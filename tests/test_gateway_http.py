"""Real ASGI binding plus one ephemeral loopback exchange; synthetic data only."""
import asyncio
import base64
from contextlib import asynccontextmanager
import json
import socket
import threading
import time

import httpx
import pytest
import uvicorn

from telegram_gateway.auth import FakeAuthenticator, OwnerApprovalVerifier, VerifiedPrincipal
from telegram_gateway.bot_api import BotApiAdapter, FakeBotTransport
from telegram_gateway.events import EventHub, MemorySecretStore
from telegram_gateway.http_server import create_app, VERSION
from telegram_gateway.policy import Policy, Scope, GatewayDenied
from telegram_gateway.protocol import Protocol, VERSION_KEY, CAPABILITIES_KEY
from telegram_gateway.runtime_auth import protected_resource_metadata
from telegram_gateway.service import Gateway, StateStore

BASE = "http://127.0.0.1"
META_URL = BASE + "/.well-known/oauth-protected-resource"
METADATA = protected_resource_metadata(BASE + "/mcp", "https://issuer.example", required_scope="mcp:gateway")
AUTH = "Bearer fixture-zeta"


def payload(method="server/discover", params=None, *, version=VERSION, request_id="http-test"):
    values = dict(params or {})
    values["_meta"] = {VERSION_KEY: version, CAPABILITIES_KEY: {}}
    return {"jsonrpc": "2.0", "id": request_id, "method": method, "params": values}


def headers(method="server/discover", *, version=VERSION, auth=AUTH, name=None):
    result = {"Content-Type": "application/json", "Accept": "application/json, text/event-stream",
              "MCP-Protocol-Version": version, "Mcp-Method": method}
    if auth is not None:
        result["Authorization"] = auth
    if name is not None:
        result["Mcp-Name"] = name
    return result


@pytest.fixture
def setup(tmp_path):
    policy = Policy.from_dict({"principals": {
        "zeta": [{"chat_id": -1001, "permissions": ["history", "events", "draft", "send"]}],
        "support": [{"chat_id": -1002, "topic_id": 7, "permissions": ["history", "events"]}]}})
    auth = FakeAuthenticator({"fixture-zeta": "zeta", "fixture-support": "support"})
    principals = [auth.authenticate("Bearer fixture-" + name) for name in ("zeta", "support")]
    store = StateStore(tmp_path / "gateway.sqlite")
    adapter = BotApiAdapter(FakeBotTransport(), allowed_scopes={(-1001, None), (-1002, 7)})
    gateway = Gateway(store, policy, principals, adapter, owner_verifier=OwnerApprovalVerifier([99], [Scope(-1001)]))
    async def no_network(*args, **kwargs):
        raise AssertionError("HTTP transport tests must not send callbacks")
    def authorize(principal, name, args):
        policy.require(principal, "events", Scope(args["chat_id"], args.get("topic_id")))
    hub = EventHub(tmp_path / "events.sqlite", authorize, sender=no_network,
                   resolver=lambda _: ["93.184.216.34"], secret_store=MemorySecretStore(),
                   catalog_authorizer=lambda p: bool(policy.allowed_scopes(p, "events")),
                   callback_authorizer=lambda p, u: (_ for _ in ()).throw(GatewayDenied("Unavailable")))
    protocol = Protocol(auth, gateway, hub)
    def make(**extra):
        kwargs = dict(resource_metadata=METADATA, metadata_url=META_URL,
                      allowed_hosts={"127.0.0.1"}, allowed_origins=set())
        kwargs.update(extra)
        return create_app(protocol, auth, **kwargs)
    yield make, protocol, auth
    hub.close()
    store.close()


@pytest.mark.asyncio
async def test_unauthorized_metadata_then_real_strict_discovery(setup):
    make, _, _ = setup
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=make()), base_url=BASE) as client:
        unauthorized = await client.post("/mcp", content=b"not parsed", headers=headers(auth=None))
        assert unauthorized.status_code == 401
        assert unauthorized.headers["www-authenticate"] == 'Bearer resource_metadata="' + META_URL + '", scope="mcp:gateway"'
        assert "fixture-zeta" not in unauthorized.text
        for path in ("/.well-known/oauth-protected-resource", "/.well-known/oauth-protected-resource/mcp"):
            meta = await client.get(path)
            assert meta.status_code == 200 and meta.json() == METADATA
            assert meta.headers["cache-control"] == "no-store"
        result = await client.post("/mcp", json=payload(), headers=headers())
        assert result.status_code == 200
        assert result.json()["result"]["supportedVersions"] == [VERSION]
        assert result.json()["result"]["resultType"] == "complete"
        assert result.json()["result"]["_meta"]["io.modelcontextprotocol/serverInfo"]["name"] == "telegram-agent-gateway"
        assert "mcp-session-id" not in result.headers


@pytest.mark.asyncio
@pytest.mark.parametrize("auth", [None, "Bearer wrong", "fixture-zeta", "Basic fixture-zeta"])
async def test_authentication_cannot_come_from_body_cookie_or_query(setup, auth):
    make, _, _ = setup
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=make()), base_url=BASE) as client:
        value = payload()
        value["agent_id"] = "zeta"
        h = headers(auth=auth)
        h["Cookie"] = "Authorization=" + AUTH
        result = await client.post("/mcp?agent_id=zeta&authorization=fixture-zeta", json=value, headers=h)
        assert result.status_code == 401 and "fixture-zeta" not in result.text


@pytest.mark.asyncio
async def test_duplicate_authorization_is_rejected(setup):
    make, _, _ = setup
    h = list(headers().items()) + [("authorization", "Bearer fixture-support")]
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=make()), base_url=BASE) as client:
        result = await client.post("/mcp", json=payload(), headers=h)
        assert result.status_code == 401


@pytest.mark.asyncio
@pytest.mark.parametrize("removed", ["MCP-Protocol-Version", "Mcp-Method"])
async def test_required_mirror_headers(setup, removed):
    make, _, _ = setup
    h = headers()
    del h[removed]
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=make()), base_url=BASE) as client:
        result = await client.post("/mcp", json=payload(), headers=h)
        assert result.status_code == 400 and result.json()["error"]["code"] == -32020


@pytest.mark.asyncio
async def test_version_negotiation_and_header_body_mismatch(setup):
    make, _, _ = setup
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=make()), base_url=BASE) as client:
        result = await client.post("/mcp", json=payload(version="2025-11-25"), headers=headers(version="2025-11-25"))
        assert result.status_code == 400 and result.json()["error"]["code"] == -32022
        assert result.json()["error"]["data"] == {"supported": [VERSION], "requested": "2025-11-25"}
        mismatch = await client.post("/mcp", json=payload(), headers=headers(version="2025-11-25"))
        assert mismatch.status_code == 400 and mismatch.json()["error"]["code"] == -32020
        method = await client.post("/mcp", json=payload(), headers=headers(method="tools/list"))
        assert method.status_code == 400 and method.json()["error"]["code"] == -32020


@pytest.mark.asyncio
async def test_mcp_name_plain_base64_and_mismatch(setup):
    make, _, _ = setup
    body = payload("tools/call", {"name": "ping", "arguments": {}})
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=make()), base_url=BASE) as client:
        for name in ("ping", "=?base64?" + base64.b64encode(b"ping").decode() + "?="):
            result = await client.post("/mcp", json=body, headers=headers("tools/call", name=name))
            assert result.status_code == 200 and result.json()["result"]["isError"] is False
        for name in (None, "status", "=?base64?!!!!?="):
            result = await client.post("/mcp", json=body, headers=headers("tools/call", name=name))
            assert result.status_code == 400 and result.json()["error"]["code"] == -32020


@pytest.mark.asyncio
async def test_unknown_method_404_and_legacy_handshake_not_supported(setup):
    make, _, _ = setup
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=make()), base_url=BASE) as client:
        for method in ("not/a-method", "initialize"):
            result = await client.post("/mcp", json=payload(method), headers=headers(method))
            assert result.status_code == 404 and result.json()["error"]["code"] == -32601
        for method in ("GET", "DELETE", "PUT"):
            result = await client.request(method, "/mcp", headers={"Authorization": AUTH})
            assert result.status_code == 405 and result.headers["allow"] == "POST"


@pytest.mark.asyncio
@pytest.mark.parametrize("body,code", [(b"{bad", -32700), (b'[{"jsonrpc":"2.0"}]', -32600),
    (b'{"jsonrpc":"2.0","jsonrpc":"2.0"}', -32700), (b'NaN', -32700), (b'"secret-text"', -32600),
    (b'{}', -32600), (b'{"jsonrpc":"1.0","id":1,"method":"server/discover"}', -32600),
    (b'{"jsonrpc":"2.0","id":null,"method":"server/discover"}', -32600)])
async def test_malformed_json_is_sanitized(setup, body, code):
    make, _, _ = setup
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=make()), base_url=BASE) as client:
        result = await client.post("/mcp", content=body, headers=headers())
        assert result.status_code == 400 and result.json()["error"]["code"] == code
        assert "secret-text" not in result.text


@pytest.mark.asyncio
async def test_notifications_never_invoke_handlers(setup):
    make, protocol, _ = setup
    called = []
    original = protocol.request_authenticated
    async def wrapped(*args):
        called.append(True)
        return await original(*args)
    protocol.request_authenticated = wrapped
    body = payload("tools/call", {"name": "execute_draft", "arguments": {"draft_id": "fake"}})
    del body["id"]
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=make()), base_url=BASE) as client:
        result = await client.post("/mcp", json=body, headers=headers("tools/call", name="execute_draft"))
        assert result.status_code == 400 and result.content == b"" and not called


@pytest.mark.asyncio
async def test_cross_scope_and_body_principal_cannot_change_authenticated_identity(setup):
    make, _, _ = setup
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=make()), base_url=BASE) as client:
        body = payload("tools/call", {"name": "read_history", "arguments": {"chat_id": -1002, "topic_id": 7}})
        denied = await client.post("/mcp", json=body, headers=headers("tools/call", name="read_history"))
        assert denied.status_code == 403 and denied.json()["error"]["code"] == -33001
        assert "www-authenticate" not in denied.headers
        body["params"]["arguments"]["agent_id"] = "support"
        spoof = await client.post("/mcp", json=body, headers=headers("tools/call", name="read_history"))
        assert spoof.status_code == 400 and spoof.json()["error"]["code"] == -32602


@pytest.mark.asyncio
@pytest.mark.parametrize("change,status", [({"Content-Type": "text/plain"}, 415),
    ({"Content-Type": "application/json; charset=utf-16"}, 415), ({"Accept": "application/json"}, 406),
    ({"Accept": "application/json, text/event-stream;q=0"}, 406), ({"Content-Encoding": "gzip"}, 415)])
async def test_media_headers(setup, change, status):
    make, _, _ = setup
    h = {**headers(), **change}
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=make()), base_url=BASE) as client:
        result = await client.post("/mcp", json=payload(), headers=h)
        assert result.status_code == status


@pytest.mark.asyncio
async def test_body_cap_for_declared_and_chunked_requests(setup):
    make, _, _ = setup
    async def chunks():
        for _ in range(65):
            yield b"x" * 1024
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=make()), base_url=BASE) as client:
        declared = await client.post("/mcp", content=b"x" * 65537, headers=headers())
        assert declared.status_code == 413
        chunked = await client.post("/mcp", content=chunks(), headers=headers())
        assert chunked.status_code == 413


@pytest.mark.asyncio
async def test_host_origin_protection_and_scoped_cors(setup):
    make, _, _ = setup
    app = make(allowed_origins={"http://localhost:4321"})
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url=BASE) as client:
        for extra in ({"Host": "attacker.example"}, {"Host": "127.0.0.1.attacker.example"}, {"Origin": "null"}, {"Origin": "https://attacker.example"}):
            result = await client.post("/mcp", json=payload(), headers={**headers(), **extra})
            assert result.status_code == 403
        allowed = await client.post("/mcp", json=payload(), headers={**headers(), "Origin": "http://localhost:4321"})
        assert allowed.status_code == 200
        assert allowed.headers["access-control-allow-origin"] == "http://localhost:4321"
        preflight = await client.options("/mcp", headers={"Origin": "http://localhost:4321", "Access-Control-Request-Method": "POST", "Access-Control-Request-Headers": "authorization,mcp-method"})
        assert preflight.status_code == 204
        assert preflight.headers["access-control-allow-methods"] == "POST"
        bad = await client.options("/mcp", headers={"Origin": "http://localhost:4321", "Access-Control-Request-Method": "DELETE"})
        assert bad.status_code == 403


@pytest.mark.asyncio
async def test_static_mode_does_not_advertise_oauth_metadata(setup):
    make, _, _ = setup
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=make(resource_metadata=None)), base_url=BASE) as client:
        result = await client.post("/mcp", content=b"", headers=headers(auth=None))
        assert result.status_code == 401 and result.headers["www-authenticate"] == "Bearer"
        assert (await client.get("/.well-known/oauth-protected-resource")).status_code == 404


def test_boundary_configuration_does_not_accept_wildcards(setup):
    make, _, _ = setup
    for kwargs in ({"allowed_hosts": set()}, {"allowed_hosts": {"*"}}, {"allowed_origins": {"*"}},
                   {"metadata_url": 'https://issuer.example/"\r\nBad: data'}):
        with pytest.raises(ValueError):
            make(**kwargs)


@pytest.mark.asyncio
async def test_missing_metadata_is_not_filled_by_legacy_fixture_adapter(setup):
    make, _, _ = setup
    body = {"jsonrpc": "2.0", "id": 1, "method": "server/discover", "params": {}}
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=make()), base_url=BASE) as client:
        result = await client.post("/mcp", json=body, headers=headers())
        assert result.status_code == 400 and result.json()["error"]["code"] == -32020


@pytest.mark.asyncio
async def test_forged_authentication_result_and_handler_exception_are_sanitized(setup):
    make, protocol, auth = setup
    original_auth = auth.authenticate
    auth.authenticate = lambda _: VerifiedPrincipal("zeta")
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=make()), base_url=BASE) as client:
        denied = await client.post("/mcp", json=payload(), headers=headers())
        assert denied.status_code == 401
    auth.authenticate = original_auth
    async def bad_handler(*args):
        raise RuntimeError("SECRET CALLBACK TOKEN SHOULD NEVER APPEAR")
    protocol.request_authenticated = bad_handler
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=make()), base_url=BASE) as client:
        failed = await client.post("/mcp", json=payload(), headers=headers())
        assert failed.status_code == 500 and failed.json()["error"]["code"] == -32603
        assert "SECRET" not in failed.text


@pytest.mark.asyncio
async def test_lifecycle_is_owned_by_explicit_server_lifespan(setup):
    make, _, _ = setup
    transitions = []
    @asynccontextmanager
    async def lifespan(app):
        transitions.append("start")
        yield
        transitions.append("stop")
    app = make(lifecycle=lifespan)
    assert transitions == []
    async with app.router.lifespan_context(app):
        assert transitions == ["start"]
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url=BASE) as client:
            assert (await client.post("/mcp", json=payload(), headers=headers())).status_code == 200
    assert transitions == ["start", "stop"]


def test_ephemeral_localhost_http_exchange_and_cleanup(setup):
    """Actual TCP/HTTP. It proves HTTP transport, not a ChatGPT/dot call."""
    make, _, _ = setup
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0))
    listener.listen(5)
    port = listener.getsockname()[1]
    app = make(allowed_hosts={f"127.0.0.1:{port}"})
    server = uvicorn.Server(uvicorn.Config(app, log_config=None, access_log=False, log_level="critical", lifespan="off"))
    thread = threading.Thread(target=server.run, kwargs={"sockets": [listener]}, daemon=True)
    thread.start()
    try:
        deadline = time.monotonic() + 10
        while not server.started and thread.is_alive() and time.monotonic() < deadline:
            time.sleep(0.01)
        assert server.started
        with httpx.Client(base_url=f"http://127.0.0.1:{port}", trust_env=False, timeout=3) as client:
            denied = client.post("/mcp", json=payload(), headers=headers(auth=None))
            assert denied.status_code == 401
            accepted = client.post("/mcp", json=payload(), headers=headers())
            assert accepted.status_code == 200 and accepted.json()["result"]["supportedVersions"] == [VERSION]
            assert "mcp-session-id" not in accepted.headers
    finally:
        server.should_exit = True
        thread.join(5)
        listener.close()
        if thread.is_alive():
            server.force_exit = True
            thread.join(2)
        assert not thread.is_alive()
