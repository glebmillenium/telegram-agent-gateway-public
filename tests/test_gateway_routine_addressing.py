"""Recipient selection only: synthetic Bot API, callbacks and identifiers."""
from dataclasses import replace
import hashlib
import json
import time

import pytest

from telegram_gateway.demo import message
from telegram_gateway.grok_routine import GrokRoutineError, Route
from telegram_gateway.runtime import make_runtime
from test_gateway_grok_runtime import ALPHA, BETA, CHAT, config, dependencies, principal


def test_route_addressing_is_exact_and_part_of_fingerprint():
    route = Route("test_route", "agent-alpha", ALPHA, "https://hooks.example/test", "fixture_ref")
    assert route.addressing == "mentions_or_replies"
    fields = [route.route_id, route.principal_id, route.bot_reference, route.url,
              ["fixture_reference", "fixture_ref"]]
    legacy = hashlib.sha256(json.dumps(fields, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    assert route.fingerprint() != legacy
    for invalid in (None, False, "all", "mention", ""):
        with pytest.raises(GrokRoutineError):
            replace(route, addressing=invalid)


@pytest.mark.asyncio
@pytest.mark.parametrize("topic", [None, 1, 7])
async def test_only_exact_addressed_human_or_bot_events_wake(tmp_path, topic):
    deps, sent, loaded = dependencies(updates=False)
    runtime = make_runtime(config(tmp_path), **deps)
    await runtime.start()
    try:
        child = runtime.children[ALPHA]
        child.cfg = replace(child.cfg, expected_bot_id=777)
        texts = ["@ALPHA_TEST_BOT hello", "/probe@alpha_test_bot hello", "@beta_test_bot hello",
                 "@alpha_test_bot_extra hello", "mail@alpha_test_bot", "mail.name@alpha_test_bot",
                 "mail+@alpha_test_bot", "@alpha_test_bot.example", "Unaddressed human message",
                 "@alpha_test_bot self", "@alpha_test_bot forwarded", "@alpha_test_bot anonymous",
                 "@alpha_test_bot via bot", "@alpha_test_bot other bot", "@alpha_test_bot absent sender",
                 "https://example.test/probe@alpha_test_bot", "Hello,@alpha_test_bot!",
                 "not/probe@alpha_test_bot", "é@alpha_test_bot"]
        updates = [message(i, CHAT, text, topic=topic) for i, text in enumerate(texts, 1)]
        updates[9]["message"]["from"]["id"] = 777
        updates[10]["message"]["forward_origin"] = {"type": "user"}
        updates[11]["message"]["sender_chat"] = {"id": CHAT}
        updates[12]["message"]["via_bot"] = {"id": 888}
        updates[13]["message"]["from"]["is_bot"] = True
        del updates[14]["message"]["from"]
        updates.append(message(20, -1002, "@alpha_test_bot foreign", topic=topic))
        deps["transports"][ALPHA].updates.extend(updates)
        await child.gateway.poll_once()
        assert child.export_routine_events("alpha_routine") == {"exported": 4}
        assert child.store.db.execute("SELECT cursor FROM gw_routine_exports").fetchone()[0] == 19
        for _ in range(4):
            assert (await child.routine_once("alpha_routine"))["status"] == "accepted"
        assert (await child.routine_once("alpha_routine"))["status"] == "idle"
        assert [event["data"]["message_id"] for event in sent[ALPHA]] == [1, 2, 14, 17]
        assert all(event["data"]["topic_id"] == topic for event in sent[ALPHA])
        assert len(loaded[ALPHA]) == 4 and sent[BETA] == []
        assert child.store.db.execute("SELECT COUNT(*) FROM gw_messages WHERE chat=-1002").fetchone()[0] == 0
    finally:
        await runtime.close()


def add_link(child, *, mid, owner="agent-alpha", chat=CHAT, topic=None):
    child.store.db.execute("INSERT INTO gw_outbound_links VALUES(?,?,?,?,?,?,?)",
                           (owner, chat, -1 if topic is None else topic, mid, "fixture-task", 0, time.time()))


@pytest.mark.asyncio
@pytest.mark.parametrize("topic", [None, 1, 7])
async def test_reply_requires_own_principal_chat_and_topic_but_not_mention(tmp_path, topic):
    deps, sent, _ = dependencies(updates=False)
    runtime = make_runtime(config(tmp_path), **deps)
    await runtime.start()
    try:
        child = runtime.children[ALPHA]
        child.cfg = replace(child.cfg, expected_bot_id=777)
        add_link(child, mid=800, topic=topic)
        add_link(child, mid=801, chat=-1002, topic=topic)
        add_link(child, mid=802, topic=7 if topic is None else None)
        add_link(child, mid=803, owner="agent-beta", topic=topic)
        updates = [message(1, CHAT, "Unmentioned own reply", topic=topic, reply=800),
                   message(2, CHAT, "@beta_test_bot still a reply to own message", topic=topic, reply=800),
                   message(3, CHAT, "Foreign chat link", topic=topic, reply=801),
                   message(4, CHAT, "Foreign topic link", topic=topic, reply=802),
                   message(5, CHAT, "Foreign principal link", topic=topic, reply=803),
                   message(6, CHAT, "Unknown link", topic=topic, reply=804),
                   message(7, CHAT, "Own echo", topic=topic, reply=800, sender=777),
                   message(8, CHAT, "Forwarded reply", topic=topic, reply=800)]
        updates[-1]["message"]["forward_origin"] = {"type": "user"}
        deps["transports"][ALPHA].updates.extend(updates)
        await child.gateway.poll_once()
        assert child.export_routine_events("alpha_routine") == {"exported": 2}
        for _ in range(2):
            assert (await child.routine_once("alpha_routine"))["status"] == "accepted"
        assert [event["data"]["message_id"] for event in sent[ALPHA]] == [1, 2]
        assert sent[BETA] == []
    finally:
        await runtime.close()


@pytest.mark.asyncio
async def test_reply_filter_is_rechecked_before_dispatch_and_secret_loading(tmp_path):
    deps, sent, loaded = dependencies(updates=False)
    runtime = make_runtime(config(tmp_path), **deps)
    await runtime.start()
    try:
        child = runtime.children[ALPHA]
        add_link(child, mid=800, topic=7)
        deps["transports"][ALPHA].updates.append(message(1, CHAT, "Own reply", topic=7, reply=800))
        await child.gateway.poll_once()
        assert child.export_routine_events("alpha_routine") == {"exported": 1}
        child.store.db.execute("DELETE FROM gw_outbound_links WHERE mid=800")
        assert (await child.routine_once("alpha_routine"))["status"] == "revoked"
        assert sent[ALPHA] == loaded[ALPHA] == []
    finally:
        await runtime.close()


@pytest.mark.asyncio
@pytest.mark.parametrize("phase", ["dns", "secret"])
async def test_filter_is_rechecked_after_dns_and_secret_load(tmp_path, phase):
    deps, sent, loaded = dependencies()
    runtime = make_runtime(config(tmp_path), **deps)
    await runtime.start()
    try:
        child = runtime.children[ALPHA]
        await child.gateway.poll_once()
        child.export_routine_events("alpha_routine")
        sink = child.routine_sinks["alpha_routine"]
        enabled = [True]
        original = sink.event_filter
        sink.event_filter = lambda data: enabled[0] and original(data)
        if phase == "dns":
            def resolve(_):
                enabled[0] = False
                return ["8.8.8.8"]
            sink.resolver = resolve
        else:
            loader = sink.secret_loader
            def load(reference):
                enabled[0] = False
                return loader(reference)
            sink.secret_loader = load
        assert (await child.routine_once("alpha_routine"))["status"] == "revoked"
        assert sent[ALPHA] == []
        assert len(loaded[ALPHA]) == (1 if phase == "secret" else 0)
    finally:
        await runtime.close()
