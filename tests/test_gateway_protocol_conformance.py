"""MCP 2026-07-28 wire-format checks using synthetic data and no sockets.

Reference: modelcontextprotocol.io/specification/2026-07-28/schema and
developers.openai.com/plugins/build/mcp-events. HTTP binding has its own suite.
"""
import base64
import asyncio
import json
import ssl
import threading
from datetime import datetime
from types import SimpleNamespace

import pytest

from telegram_gateway.auth import FakeAuthenticator, VerifiedPrincipal
from telegram_gateway.bot_api import BotApiAdapter, FakeBotTransport
from telegram_gateway.events import EventHub, MemorySecretStore, WebhookResponse, EVENT_NAME
from telegram_gateway.policy import Policy, Scope
from telegram_gateway.protocol import (
    Protocol, ProtocolError, parse_jsonrpc, error_response,
    VERSION_KEY, CAPABILITIES_KEY, CLIENT_KEY, SERVER_KEY,
)
from telegram_gateway.service import Gateway, StateStore

SECRET = "whsec_" + base64.b64encode(b"synthetic-only-conformance-fixture").decode()
CALLBACK = "https://receiver.example/events"


def payload(method="server/discover", params=None, request_id="official-example"):
    return {"jsonrpc": "2.0", "id": request_id, "method": method, "params": {
        "_meta": {VERSION_KEY: "2026-07-28", CAPABILITIES_KEY: {}, CLIENT_KEY: {"name": "ExampleClient", "version": "1.0.0"}},
        **(params or {}),
    }}


def subscription(**extra):
    return {"name": EVENT_NAME, "arguments": {"chat_id": -1001},
            "delivery": {"mode": "webhook", "url": CALLBACK, "secret": SECRET}, "cursor": None, **extra}


@pytest.fixture
def env(tmp_path):
    auth = FakeAuthenticator({"fixture-zeta": "zeta", "fixture-support": "support"})
    principal = auth.authenticate("Bearer fixture-zeta")
    support = auth.authenticate("Bearer fixture-support")
    policy = Policy.from_dict({"principals": {
        "zeta": [{"chat_id": -1001, "permissions": ["history", "events", "draft", "send", "forward"]}],
        "support": [{"chat_id": -1002, "permissions": ["history", "events"]}],
    }})
    clock = [1_800_000_000.0]
    state = StateStore((tmp_path / "state" / "gateway.sqlite").resolve())
    wire = FakeBotTransport()
    gateway = Gateway(state, policy, [principal, support], BotApiAdapter(wire, allowed_scopes={(-1001, None), (-1002, None)}), clock=lambda: clock[0])
    calls = []

    async def receiver(target, body, headers):
        calls.append((target, body, headers))
        challenge = json.loads(body).get("challenge")
        return WebhookResponse(200, json.dumps({"challenge": challenge}).encode())

    def authorize(p, name, args):
        policy.require(p, "events", Scope(**args))

    def callback_authorize(p, url):
        if url != CALLBACK:
            raise ValueError("Not registered")

    hub = EventHub(tmp_path / "events.sqlite", authorize, sender=receiver, resolver=lambda _: ["8.8.8.8"],
                   secret_store=MemorySecretStore(), clock=lambda: clock[0], callback_authorizer=callback_authorize,
                   catalog_authorizer=lambda p: bool(policy.allowed_scopes(p, "events")))
    yield SimpleNamespace(protocol=Protocol(auth, gateway, hub), principal=principal, support=support, auth=auth,
                          gateway=gateway, hub=hub, clock=clock, calls=calls, wire=wire)
    hub.close()
    state.close()


async def exchange(env, request, principal=None):
    # Exercise both actual wire encodings, not only Python object dispatch.
    decoded = parse_jsonrpc(json.dumps(request, ensure_ascii=False, allow_nan=False).encode())
    response = await env.protocol.request_authenticated(decoded, principal or env.principal)
    return json.loads(json.dumps(response, ensure_ascii=False, allow_nan=False))


@pytest.mark.asyncio
@pytest.mark.parametrize("request_id", ["official-example", "", 0, -2, 2**40])
async def test_request_ids_and_complete_discovery(env, request_id):
    response = await exchange(env, payload(request_id=request_id))
    assert response["id"] == request_id
    result = response["result"]
    assert result["resultType"] == "complete"
    assert result["supportedVersions"] == ["2026-07-28"]
    assert result["capabilities"] == {"tools": {}, "events": {}}
    assert "untrusted" in result["instructions"]
    assert result["_meta"][SERVER_KEY]["name"] == "telegram-agent-gateway"
    assert "task" not in json.dumps(result["capabilities"])


@pytest.mark.asyncio
@pytest.mark.parametrize("request_id", [None, True, 1.5, {}, []])
async def test_invalid_ids_use_invalid_request_without_id(env, request_id):
    response = await exchange(env, payload(request_id=request_id))
    assert response["error"]["code"] == -32600
    assert "id" not in response


@pytest.mark.parametrize("raw", [b"{", b"\xff", b'{"id":1,"id":2}', b'{"number":NaN}', "null trailing"])
def test_parse_errors_never_reflect_body(raw):
    with pytest.raises(ProtocolError) as caught:
        parse_jsonrpc(raw)
    assert error_response(caught.value) == {"jsonrpc": "2.0", "error": {"code": -32700, "message": "Parse error"}}


@pytest.mark.asyncio
@pytest.mark.parametrize("message", [[], None, 17, {"jsonrpc": "1.0", "id": 3, "method": "server/discover"}, {"jsonrpc": "2.0", "id": 3, "result": {}}])
async def test_batches_responses_and_malformed_envelopes_rejected(env, message):
    assert (await exchange(env, message))["error"]["code"] == -32600


@pytest.mark.asyncio
async def test_strict_metadata_and_explicit_fixture_adapter(env):
    old = {"jsonrpc": "2.0", "id": 1, "method": "server/discover", "params": {}}
    assert (await exchange(env, old))["error"]["code"] == -32602
    compatible = await env.protocol.request(old, authorization="Bearer fixture-zeta")
    assert compatible["result"]["resultType"] == "complete"
    assert old["params"] == {}  # Adapter does not mutate caller-owned input.


@pytest.mark.asyncio
async def test_optional_client_info_extensions_and_progress_are_not_identity(env):
    request = payload("tools/call", {"name": "ping"})
    meta = request["params"]["_meta"]
    del meta[CLIENT_KEY]
    meta["progressToken"] = "progress-one"
    meta["com.example/principal"] = "support"
    meta[CAPABILITIES_KEY] = {"com.example/extensions": {}}
    response = await exchange(env, request)
    assert response["result"]["isError"] is False
    assert "support" not in json.dumps(response)


@pytest.mark.asyncio
@pytest.mark.parametrize("patch", [{VERSION_KEY: None}, {CAPABILITIES_KEY: []}, {CLIENT_KEY: {}}, {"progressToken": False}, {"bad/meta/key": 1}])
async def test_invalid_metadata(env, patch):
    request = payload()
    request["params"]["_meta"].update(patch)
    assert (await exchange(env, request))["error"]["code"] == -32602


@pytest.mark.asyncio
async def test_unsupported_version_has_typed_negotiation_error(env):
    request = payload()
    request["params"]["_meta"][VERSION_KEY] = "2025-11-25"
    error = (await exchange(env, request))["error"]
    assert error == {"code": -32022, "message": "Unsupported protocol version",
                     "data": {"supported": ["2026-07-28"], "requested": "2025-11-25"}}


@pytest.mark.asyncio
@pytest.mark.parametrize("method", ["initialize", "tasks/get", "notifications/initialized", "events/stream", "arbitrary/rpc"])
async def test_unimplemented_method_is_method_not_found(env, method):
    assert (await exchange(env, payload(method)))["error"]["code"] == -32601


@pytest.mark.asyncio
async def test_notifications_never_invoke_request_handlers(env):
    request = payload("tools/call", {"name": "create_draft", "arguments": {"chat_id": -1001, "text": "must not create"}})
    del request["id"]
    assert await exchange(env, request) is None
    assert env.gateway.store.db.execute("SELECT COUNT(*) FROM gw_drafts").fetchone()[0] == 0


@pytest.mark.asyncio
@pytest.mark.parametrize("principal", [None, VerifiedPrincipal("zeta"), {"id": "zeta"}])
async def test_dispatch_requires_verified_principal(env, principal):
    response = await env.protocol.request_authenticated(payload(), principal)
    assert response["error"]["code"] == -33001


@pytest.mark.asyncio
async def test_catalog_actual_schemas_and_single_page(env):
    result = (await exchange(env, payload("tools/list")))["result"]
    names = [tool["name"] for tool in result["tools"]]
    assert names == sorted(names)
    assert "nextCursor" not in result
    tools = {tool["name"]: tool for tool in result["tools"]}
    assert tools["read_history"]["inputSchema"]["properties"]["limit"]["maximum"] == 100
    assert tools["create_draft"]["inputSchema"]["properties"]["attachments"]["items"]["additionalProperties"] is False
    assert tools["send_draft"]["annotations"]["openWorldHint"] is True
    for method in ("tools/list", "events/list"):
        for cursor in ("foreign-cursor", 3, None):
            assert (await exchange(env, payload(method, {"cursor": cursor})))["error"]["code"] == -32602


@pytest.mark.asyncio
@pytest.mark.parametrize("params", [
    {"name": "unknown"}, {"name": "ping", "arguments": None},
    {"name": "ping", "arguments": {"agent_id": "support"}},
    {"name": "ping", "task": {"ttl": 60000}},
    {"name": "ping", "requestState": "not-issued"}, {"name": "ping", "inputResponses": {"forged": {}}},
])
async def test_call_structure_errors_are_protocol_errors(env, params):
    response = await exchange(env, payload("tools/call", params))
    assert response["error"]["code"] == -32602
    assert env.wire.calls == []


@pytest.mark.asyncio
@pytest.mark.parametrize("args", [{"chat_id": -1001, "limit": 0}, {"chat_id": -1001, "limit": True}, {"chat_id": "-1001"}, {"chat_id": -1001, "surprise": 1}, {}])
async def test_tool_schema_validation_is_actionable_execution_error(env, args):
    result = (await exchange(env, payload("tools/call", {"name": "read_history", "arguments": args})))["result"]
    assert result["resultType"] == "complete" and result["isError"] is True
    assert "input schema" in result["content"][0]["text"]


@pytest.mark.asyncio
async def test_scope_denial_is_distinct_from_tool_state_failure(env):
    denied = await exchange(env, payload("tools/call", {"name": "read_history", "arguments": {"chat_id": -1002}}))
    assert denied["error"]["code"] == -33001
    unavailable = await exchange(env, payload("tools/call", {"name": "send_draft", "arguments": {"draft_id": "a" * 32}}))
    assert unavailable["result"]["isError"] is True
    assert env.wire.sent == []


@pytest.mark.asyncio
async def test_optional_arguments_empty_input_responses_and_integral_numbers(env):
    response = await exchange(env, payload("tools/call", {"name": "ping", "inputResponses": {}}))
    assert response["result"]["isError"] is False
    response = await exchange(env, payload("tools/call", {"name": "read_history", "arguments": {"chat_id": -1001.0, "limit": 1.0}}))
    assert response["result"]["structuredContent"]["messages"] == []


@pytest.mark.asyncio
async def test_unexpected_server_failure_is_internal_and_does_not_leak(env, monkeypatch):
    def failure(p):
        raise RuntimeError("private-secret-marker")
    monkeypatch.setattr(env.gateway, "ping", failure)
    response = await exchange(env, payload("tools/call", {"name": "ping"}))
    assert response["error"]["code"] == -32603
    assert "private-secret-marker" not in json.dumps(response)


@pytest.mark.asyncio
@pytest.mark.parametrize("extra,lifetime", [({}, 3600), ({"ttlMs": None}, 3600), ({"ttlMs": -10}, 1), ({"ttlMs": 0}, 1), ({"ttlMs": 10}, 1), ({"ttlMs": 2000}, 2), ({"ttlMs": 10**30}, 86400)])
async def test_event_ttl_integer_negotiation_not_a_rejection_path(env, extra, lifetime):
    response = await exchange(env, payload("events/subscribe", subscription(**extra)))
    result = response["result"]
    assert result["resultType"] == "complete" and result["cursor"] is None and result["truncated"] is False
    assert datetime.fromisoformat(result["refreshBefore"]).timestamp() - env.clock[0] == lifetime


@pytest.mark.asyncio
@pytest.mark.parametrize("ttl", [True, "1000", 1.5, {}, []])
async def test_event_invalid_ttl_type_is_invalid_params(env, ttl):
    assert (await exchange(env, payload("events/subscribe", subscription(ttlMs=ttl))))["error"]["code"] == -32602
    assert env.calls == []


@pytest.mark.asyncio
async def test_event_emit_only_max_age_and_complete_unsubscribe(env):
    request = subscription(maxAgeMs=300000)
    result = (await exchange(env, payload("events/subscribe", request)))["result"]
    assert result["cursor"] is None
    stop = {"name": request["name"], "arguments": request["arguments"], "delivery": {"mode": "webhook", "url": CALLBACK}}
    response = (await exchange(env, payload("events/unsubscribe", stop)))["result"]
    assert response["resultType"] == "complete"


@pytest.mark.asyncio
@pytest.mark.parametrize("failure,reason", [(TimeoutError(), "timeout"), (ssl.SSLError(), "tls_error"), (ConnectionRefusedError(), "connection_refused"), (WebhookResponse(403), "http_4xx"), (WebhookResponse(503), "http_5xx"), (WebhookResponse(200, b'{}'), "challenge_failed")])
async def test_callback_errors_keep_openai_code_and_categorized_reason(env, failure, reason):
    async def fail(*_):
        if isinstance(failure, Exception):
            raise failure
        return failure
    env.hub.sender = fail
    error = (await exchange(env, payload("events/subscribe", subscription())))["error"]
    assert error["code"] == -32015 and error["data"] == {"reason": reason}
    assert SECRET not in json.dumps(error) and CALLBACK not in json.dumps(error)
    assert env.hub.status(env.principal)["active_subscriptions"] == 0


@pytest.mark.asyncio
async def test_callback_verification_cache_scoped_bounded_expiring_and_revoked(env):
    first = (await exchange(env, payload("events/subscribe", subscription())))["result"]
    second = (await exchange(env, payload("events/subscribe", subscription())))["result"]
    assert first["id"] == second["id"] and len(env.calls) == 1
    other = subscription()
    other["arguments"]["chat_id"] = -1002
    await exchange(env, payload("events/subscribe", other), env.support)
    assert len(env.calls) == 2
    env.clock[0] += 301
    await exchange(env, payload("events/subscribe", subscription()))
    assert len(env.calls) == 3
    env.hub.revoke_owner(env.principal)
    await exchange(env, payload("events/subscribe", subscription()))
    assert len(env.calls) == 4


@pytest.mark.asyncio
async def test_cached_callback_never_waives_current_binding(env):
    await exchange(env, payload("events/subscribe", subscription()))
    env.hub.callback_authorizer = lambda *_: False
    response = await exchange(env, payload("events/subscribe", subscription()))
    assert "error" in response and len(env.calls) == 1


@pytest.mark.asyncio
async def test_callback_cache_capacity_is_bounded(env):
    env.hub._verified_callbacks = {("fixture-owner", str(index)): env.clock[0] + 100 for index in range(1024)}
    await exchange(env, payload("events/subscribe", subscription()))
    assert len(env.hub._verified_callbacks) == 1024
    assert ("zeta", CALLBACK) in env.hub._verified_callbacks


@pytest.mark.asyncio
async def test_nonfinite_and_nonunicode_values_are_request_errors(env):
    for bad in (float("inf"), "\ud800", {"\ud800": 1}):
        message = payload("tools/call", {"name": "ping", "arguments": {"bad": bad}})
        response = await env.protocol.request_authenticated(message, env.principal)
        assert response["error"]["code"] == -32600


@pytest.mark.asyncio
async def test_stalled_callback_dns_has_one_deadline_and_never_starts_http(env, monkeypatch):
    import telegram_gateway.events as events_module
    started, released, finished = threading.Event(), threading.Event(), threading.Event()

    def stalled_dns(_):
        started.set()
        released.wait(2)
        finished.set()
        return ["8.8.8.8"]

    env.hub.resolver = stalled_dns
    monkeypatch.setattr(events_module, "WEBHOOK_ATTEMPT_TIMEOUT", 0.05)
    try:
        task = asyncio.create_task(exchange(env, payload("events/subscribe", subscription())))
        for _ in range(20):
            if started.is_set():
                break
            await asyncio.sleep(0.005)
        assert started.is_set()
        assert not task.done()  # Event loop remained responsive during DNS.
        response = await asyncio.wait_for(task, timeout=1)
        assert response["error"]["code"] == -32015
        assert response["error"]["data"] == {"reason": "timeout"}
        assert env.calls == []
        released.set()
        for _ in range(20):
            if finished.is_set():
                break
            await asyncio.sleep(0.005)
        assert finished.is_set()
        await asyncio.sleep(0.01)
        assert env.calls == []  # A late DNS result cannot start HTTP.
    finally:
        released.set()
