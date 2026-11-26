"""Synthetic all-topic runtime integration; no real catalog or secret reads."""
from dataclasses import replace

import pytest

from telegram_gateway.bot_api import FakeBotTransport
from telegram_gateway.demo import message
from telegram_gateway.policy import GatewayDenied, Scope
from telegram_gateway.runtime import Runtime, RuntimeBlocked, make_runtime
from telegram_gateway.runtime_config import RuntimeConfig

CHAT = -1001
ALPHA, BETA = "alpha_topics_bot", "beta_topics_bot"


def config(tmp_path, *, alpha_whole=True, beta_whole=True):
    profiles = []
    for principal, reference, whole in (("alpha", ALPHA, alpha_whole), ("beta", BETA, beta_whole)):
        chat = {"chat_id": CHAT, "type": "supergroup", "title": "Synthetic group", "actions": ["history", "events"]}
        if whole:
            chat["all_topics"] = True
        profiles.append({"id": principal, "name": "Synthetic " + principal, "purpose": "test",
                         "prompt": "inert metadata", "enabled": True, "telegram_username": reference,
                         "auth_principal": principal, "chats": [chat]})
    return RuntimeConfig.from_dict({"version": 1, "mode": "fake", "state_dir": str(tmp_path / "state"),
        "agents": profiles, "auth": {"mode": "fake", "credentials": {"fixture-alpha": "alpha", "fixture-beta": "beta"}},
        "allowed_callbacks": {"alpha": ["https://events.example.test/alpha"], "beta": ["https://events.example.test/beta"]}})


def transports():
    return {reference: FakeBotTransport([message(1, CHAT, principal + " general"),
        message(2, CHAT, principal + " seven", topic=7), message(3, CHAT, principal + " eight", topic=8),
        message(4, -1999, "must not capture", topic=7)])
        for principal, reference in (("alpha", ALPHA), ("beta", BETA))}


@pytest.mark.asyncio
async def test_whole_chat_aggregate_isolated_between_bots_and_null_stays_exact(tmp_path):
    runtime = make_runtime(config(tmp_path), transports=transports())
    await runtime.start()
    try:
        assert len(runtime.children) == 2
        for child in runtime.children.values():
            await child.gateway.poll_once()
        for principal, reference in (("alpha", ALPHA), ("beta", BETA)):
            p = runtime.auth.authenticate("Bearer fixture-" + principal)
            rows = runtime.gateway.read_history(p, CHAT, all_topics=True)["messages"]
            assert {row["text"] for row in rows} == {principal + " general", principal + " seven", principal + " eight"}
            assert {row["bot_reference"] for row in rows} == {reference}
            assert {row["topic_id"] for row in rows} == {None, 7, 8}
            exact_null = runtime.gateway.read_history(p, CHAT)["messages"]
            assert [row["text"] for row in exact_null] == [principal + " general"]
            assert [row["text"] for row in runtime.gateway.read_history(p, CHAT, 7)["messages"]] == [principal + " seven"]
            assert len(runtime.gateway.search_history(p, CHAT, principal, all_topics=True)["messages"]) == 3
            assert len(runtime.gateway.search_history(p, CHAT, principal)["messages"]) == 1
            events = runtime.gateway.next_events(p, CHAT, all_topics=True)["events"]
            assert {row["data"]["topic_id"] for row in events} == {None, 7, 8}
            assert {row["data"]["bot_reference"] for row in events} == {reference}
            with pytest.raises(GatewayDenied):
                runtime.gateway.read_history(p, -1999, all_topics=True)
    finally:
        await runtime.close()


@pytest.mark.asyncio
async def test_exact_null_grant_does_not_capture_or_authorize_other_topics(tmp_path):
    runtime = make_runtime(config(tmp_path, alpha_whole=False), transports=transports())
    await runtime.start()
    try:
        for child in runtime.children.values():
            await child.gateway.poll_once()
        alpha = runtime.auth.authenticate("Bearer fixture-alpha")
        assert [row["text"] for row in runtime.gateway.read_history(alpha, CHAT)["messages"]] == ["alpha general"]
        assert runtime.children[ALPHA].store.db.execute("SELECT COUNT(*) FROM gw_messages").fetchone()[0] == 1
        assert runtime.children[BETA].store.db.execute("SELECT COUNT(*) FROM gw_messages").fetchone()[0] == 3
        for method, args in ((runtime.gateway.read_history, (alpha, CHAT)),
                             (runtime.gateway.search_history, (alpha, CHAT, "alpha")),
                             (runtime.gateway.next_events, (alpha, CHAT))):
            with pytest.raises(GatewayDenied):
                method(*args, all_topics=True)
        with pytest.raises(GatewayDenied):
            runtime.gateway.read_history(alpha, CHAT, 7)
        assert len(runtime.gateway.next_events(alpha, CHAT)["events"]) == 1
    finally:
        await runtime.close()


@pytest.mark.asyncio
async def test_event_authorization_and_callbacks_remain_principal_scoped(tmp_path):
    runtime = make_runtime(config(tmp_path, beta_whole=False))
    await runtime.start()
    try:
        alpha, beta = [runtime.auth.authenticate("Bearer fixture-" + name) for name in ("alpha", "beta")]
        a, b = runtime.children[ALPHA], runtime.children[BETA]
        a._event_authorize(alpha, "telegram.message.created", {"chat_id": CHAT, "all_topics": True})
        a._event_authorize(alpha, "telegram.message.created", {"chat_id": CHAT, "topic_id": 77})
        b._event_authorize(beta, "telegram.message.created", {"chat_id": CHAT, "topic_id": None})
        for args in ({"chat_id": CHAT, "all_topics": True}, {"chat_id": CHAT, "topic_id": 77}):
            with pytest.raises(GatewayDenied):
                b._event_authorize(beta, "telegram.message.created", args)
        with pytest.raises(GatewayDenied):
            a._event_authorize(beta, "telegram.message.created", {"chat_id": CHAT, "all_topics": True})
        a._callback_authorize(alpha, "https://events.example.test/alpha")
        with pytest.raises(GatewayDenied):
            a._callback_authorize(alpha, "https://events.example.test/beta")
        with pytest.raises(GatewayDenied):
            a._event_authorize(alpha, "telegram.message.created", {"chat_id": CHAT, "topic_id": 7, "all_topics": True})
    finally:
        await runtime.close()


@pytest.mark.asyncio
@pytest.mark.parametrize("value", [1, "true", None, [], {}])
async def test_runtime_routes_reject_nonboolean_all_topics(tmp_path, value):
    runtime = make_runtime(config(tmp_path))
    await runtime.start()
    try:
        alpha = runtime.auth.authenticate("Bearer fixture-alpha")
        with pytest.raises(GatewayDenied):
            runtime.gateway.read_history(alpha, CHAT, all_topics=value)
        with pytest.raises(GatewayDenied):
            runtime.children[ALPHA]._event_authorize(alpha, "telegram.message.created", {"chat_id": CHAT, "all_topics": value})
    finally:
        await runtime.close()


def test_approval_review_scope_must_remain_exact_before_authentication(tmp_path, monkeypatch):
    cfg = replace(config(tmp_path).bot_configs[ALPHA], review_scope=Scope(CHAT, all_topics=True), owner_ids=(99,))
    monkeypatch.setattr("telegram_gateway.runtime.make_authenticator", lambda *_: pytest.fail("Do not open auth resources"))
    with pytest.raises(RuntimeBlocked, match="exact"):
        Runtime(cfg)


async def rpc(runtime, method, params, *, who="alpha"):
    return await runtime.protocol.request({"jsonrpc": "2.0", "id": 1, "method": method, "params": params},
                                          authorization="Bearer fixture-" + who)


@pytest.mark.asyncio
async def test_protocol_flag_schema_read_aggregate_and_false_compatibility(tmp_path):
    runtime = make_runtime(config(tmp_path), transports=transports())
    await runtime.start()
    try:
        for child in runtime.children.values():
            await child.gateway.poll_once()
        catalog = await rpc(runtime, "tools/list", {})
        tools = {tool["name"]: tool for tool in catalog["result"]["tools"]}
        for name in ("read_history", "search_history", "next_events"):
            assert tools[name]["inputSchema"]["properties"]["all_topics"] == {"type": "boolean", "default": False}
        for args, expected in (({"chat_id": CHAT}, 1), ({"chat_id": CHAT, "all_topics": False}, 1),
                               ({"chat_id": CHAT, "all_topics": True}, 3)):
            result = await rpc(runtime, "tools/call", {"name": "read_history", "arguments": args})
            assert result["result"]["isError"] is False
            assert len(result["result"]["structuredContent"]["messages"]) == expected
        for invalid in ("true", 1, None):
            result = await rpc(runtime, "tools/call", {"name": "read_history", "arguments": {"chat_id": CHAT, "all_topics": invalid}})
            assert result["result"]["isError"] is True
        result = await rpc(runtime, "tools/call", {"name": "read_history", "arguments": {"chat_id": CHAT, "all_topics": True, "bot_reference": BETA}})
        assert result["result"]["isError"] is True
    finally:
        await runtime.close()


@pytest.mark.asyncio
async def test_protocol_whole_chat_subscription_requires_explicit_grant(tmp_path):
    runtime = make_runtime(config(tmp_path, beta_whole=False))
    await runtime.start()
    try:
        for who in ("alpha", "beta"):
            params = {"name": "telegram.message.created", "arguments": {"chat_id": CHAT, "all_topics": True},
                      "delivery": {"mode": "webhook", "url": "https://events.example.test/" + who, "secret": "whsec_" + "YWFh" * 8}}
            result = await rpc(runtime, "events/subscribe", params, who=who)
            assert ("error" not in result) is (who == "alpha")
        invalid = {"name": "telegram.message.created", "arguments": {"chat_id": CHAT, "all_topics": "true"},
                   "delivery": {"mode": "webhook", "url": "https://events.example.test/alpha", "secret": "whsec_" + "YWFh" * 8}}
        assert "error" in await rpc(runtime, "events/subscribe", invalid)
    finally:
        await runtime.close()
