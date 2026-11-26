"""Explicit all-topic grants, fake transport only, no personal files or live I/O."""
import inspect
import json

import pytest

from telegram_gateway.auth import FakeAuthenticator, OwnerApprovalVerifier
from telegram_gateway.bot_api import BotApiAdapter, BotRejected, FakeBotTransport
from telegram_gateway.policy import GatewayDenied, Policy, Scope
from telegram_gateway.service import Gateway, StateStore

A, B, C = -100001, -100002, -100003
PERMISSIONS = ["history", "events", "draft", "send", "forward"]


def update(number, *, chat=A, topic=None, text="match fake", reply=None, sender=41):
    message = {"message_id": number, "date": 1700000000, "chat": {"id": chat, "type": "supergroup"},
               "from": {"id": sender, "is_bot": False}, "text": text}
    if topic is not None:
        message["message_thread_id"] = topic
    if reply is not None:
        message["reply_to_message"] = {"message_id": reply}
    return {"update_id": number, "message": message}


@pytest.fixture
def setup(tmp_path):
    policy = Policy.from_dict({"principals": {
        "zeta": [{"chat_id": A, "all_topics": True, "permissions": PERMISSIONS}],
        "reader": [{"chat_id": A, "all_topics": True, "permissions": ["history", "events"]}],
        "exact": [{"chat_id": A, "permissions": ["history", "events"]},
                  {"chat_id": A, "topic_id": 2, "permissions": ["history", "events"]},
                  {"chat_id": A, "topic_id": 3, "permissions": ["history", "events"]}],
        "foreign": [{"chat_id": B, "topic_id": 7, "permissions": ["history", "events"]}]}})
    auth = FakeAuthenticator({f"fake-{name}": name for name in ("zeta", "reader", "exact", "foreign")})
    principals = {name: auth.authenticate(f"Bearer fake-{name}") for name in ("zeta", "reader", "exact", "foreign")}
    wire = FakeBotTransport([update(1, text="match unthreaded"), update(2, topic=2, text="match second"),
                             update(3, topic=3, text="match third"), update(4, chat=B, topic=7, text="foreign private"),
                             update(5, chat=C, topic=8, text=object())])
    bot = BotApiAdapter(wire, allowed_scopes={(B, 7)}, allowed_all_topic_chats={A})
    store = StateStore((tmp_path / "state" / "gateway.sqlite").resolve())
    owner = OwnerApprovalVerifier([99], [Scope(A)], clock=lambda: 1000.0)
    g = Gateway(store, policy, principals.values(), bot, owner_verifier=owner, clock=lambda: 1000.0,
                bot_reference="all_topics_test_bot")
    yield g, wire, principals
    store.close()


async def capture_with_future_topic(setup):
    g, wire, _ = setup
    await g.poll_once()
    wire.updates.append(update(6, topic=999, text="match future"))
    await g.poll_once()


async def test_adapter_all_topics_includes_unthreaded_two_topics_and_future_topic():
    wire = FakeBotTransport([update(1), update(2, topic=2), update(3, topic=3),
                             update(4, chat=B, topic=8, text=object())])
    adapter = BotApiAdapter(wire, allowed_all_topic_chats={A})
    batch = await adapter.poll()
    assert [m.topic_id for m in batch.messages] == [None, 2, 3]
    assert batch.next_offset == 5
    wire.updates.append(update(5, topic=999))
    future = await adapter.poll(batch.next_offset)
    assert [m.topic_id for m in future.messages] == [999]
    assert all(m.chat_id == A for m in batch.messages + future.messages)


async def test_adapter_exact_none_and_exact_topics_preserve_old_semantics():
    wire = FakeBotTransport([update(1), update(2, topic=2), update(3, topic=3), update(4, topic=999)])
    unthreaded = await BotApiAdapter(wire, allowed_scopes={(A, None)}).poll()
    assert [m.topic_id for m in unthreaded.messages] == [None]
    exact = await BotApiAdapter(wire, allowed_scopes={(A, 2), (A, 3)}).poll()
    assert [m.topic_id for m in exact.messages] == [2, 3]


async def test_adapter_wildcard_one_chat_and_exact_other_chat_are_separate():
    wire = FakeBotTransport([update(1, topic=999), update(2, chat=B, topic=7),
                             update(3, chat=B), update(4, chat=B, topic=8), update(5, chat=C)])
    batch = await BotApiAdapter(wire, allowed_all_topic_chats={A}, allowed_scopes={(B, 7)}).poll()
    assert [(m.chat_id, m.topic_id) for m in batch.messages] == [(A, 999), (B, 7)]


@pytest.mark.parametrize("value", [None, True, [], [A], (A,), str(A), {True}, {0}, {1}, {"-100001"}, {-(2**52)}])
def test_adapter_all_topic_allowlist_requires_explicit_valid_negative_group_set(value):
    with pytest.raises(BotRejected):
        BotApiAdapter(allowed_all_topic_chats=value)


@pytest.mark.parametrize("topic", [None, 2, 999])
async def test_adapter_wildcard_outbound_still_sends_once_to_one_exact_destination(topic):
    wire = FakeBotTransport()
    adapter = BotApiAdapter(wire, allowed_all_topic_chats=frozenset({A}))
    receipt = await adapter.send_message(chat_id=A, topic_id=topic, text="fake reviewed", operation_id="fake-operation")
    assert len(wire.sent) == 1 and receipt.topic_id == topic
    assert wire.sent[0]["params"].get("message_thread_id") == topic
    with pytest.raises(BotRejected):
        await adapter.send_message(chat_id=B, topic_id=topic, text="forbidden", operation_id="foreign")
    assert len(wire.sent) == 1


@pytest.mark.parametrize("topic", [True, False, 0, -1, "all", "*", [], 2**31])
async def test_adapter_wildcard_does_not_bypass_destination_validation(topic):
    wire = FakeBotTransport()
    adapter = BotApiAdapter(wire, allowed_all_topic_chats={A})
    with pytest.raises(BotRejected):
        await adapter.send_message(chat_id=A, topic_id=topic, text="fake", operation_id="fake-operation")
    assert wire.sent == []


async def test_history_and_search_aggregate_return_actual_topics_with_global_limit(setup):
    g, _, ps = setup
    await capture_with_future_topic(setup)
    p = ps["zeta"]
    records = g.read_history(p, A, all_topics=True)["messages"]
    assert [r["topic_id"] for r in records] == [999, 3, 2, None]
    assert all(r["chat_id"] == A for r in records)
    assert [r["message_id"] for r in g.read_history(p, A, all_topics=True, limit=2)["messages"]] == [6, 3]
    assert [r["message_id"] for r in g.read_history(p, A, all_topics=True, before_id=3)["messages"]] == [2, 1]
    found = g.search_history(p, A, "MATCH", all_topics=True, limit=2)["messages"]
    assert [r["topic_id"] for r in found] == [999, 3]
    assert g.search_history(p, A, "foreign", all_topics=True)["messages"] == []


async def test_false_default_queries_remain_unthreaded_even_with_wildcard_grant(setup):
    g, _, ps = setup
    await capture_with_future_topic(setup)
    p = ps["zeta"]
    assert [m["topic_id"] for m in g.read_history(p, A)["messages"]] == [None]
    assert [m["topic_id"] for m in g.search_history(p, A, "match")["messages"]] == [None]
    assert [e["data"]["topic_id"] for e in g.next_events(p, A)["events"]] == [None]
    assert [m["topic_id"] for m in g.read_history(p, A, topic_id=2)["messages"]] == [2]


async def test_aggregate_events_retain_owner_chat_and_actual_topics_then_ack(setup):
    g, _, ps = setup
    await capture_with_future_topic(setup)
    events = g.next_events(ps["zeta"], A, all_topics=True)["events"]
    assert [e["data"]["topic_id"] for e in events] == [None, 2, 3, 999]
    assert all(e["data"]["chat_id"] == A for e in events)
    for event in events:
        with pytest.raises(GatewayDenied):
            g.ack_event(ps["exact"], event["event_id"])
        assert g.ack_event(ps["zeta"], event["event_id"]) == {"acknowledged": True}
    assert g.next_events(ps["zeta"], A, all_topics=True)["events"] == []
    assert len(g.next_events(ps["reader"], A, all_topics=True)["events"]) == 4


def call(g, method, p, chat=A, **kwargs):
    if method == "search_history":
        return g.search_history(p, chat, "match", **kwargs)
    return getattr(g, method)(p, chat, **kwargs)


@pytest.mark.parametrize("method", ["read_history", "search_history", "next_events"])
@pytest.mark.parametrize("flag", [0, 1, None, "true", [], {}])
def test_service_all_topics_is_strict_boolean(setup, method, flag):
    g, _, ps = setup
    with pytest.raises(GatewayDenied):
        call(g, method, ps["zeta"], all_topics=flag)


@pytest.mark.parametrize("method", ["read_history", "search_history", "next_events"])
async def test_aggregate_requires_explicit_wildcard_grant_not_union_of_exact_grants(setup, method):
    g, _, ps = setup
    await capture_with_future_topic(setup)
    with pytest.raises(GatewayDenied):
        call(g, method, ps["exact"], all_topics=True)
    with pytest.raises(GatewayDenied):
        call(g, method, ps["zeta"], topic_id=2, all_topics=True)
    with pytest.raises(GatewayDenied):
        call(g, method, ps["zeta"], chat=B, all_topics=True)
    with pytest.raises(GatewayDenied):
        call(g, method, ps["zeta"], chat=C, all_topics=True)


@pytest.mark.parametrize("method", ["read_history", "search_history", "next_events"])
@pytest.mark.parametrize("limit", [0, 101, True])
def test_aggregate_keeps_existing_limits(setup, method, limit):
    g, _, ps = setup
    with pytest.raises(GatewayDenied):
        call(g, method, ps["zeta"], all_topics=True, limit=limit)


async def test_revoking_wildcard_blocks_stored_topic_history_events_and_export(setup):
    g, _, ps = setup
    await capture_with_future_topic(setup)
    # A migrated legacy null-only grant remains exact; stored rows confer no rights.
    g.policy = Policy.from_dict({"principals": {"zeta": [{"chat_id": A, "topic_id": None,
                                                      "permissions": ["history", "events"]}]}})
    for method in ("read_history", "search_history", "next_events"):
        with pytest.raises(GatewayDenied):
            call(g, method, ps["zeta"], all_topics=True)
        with pytest.raises(GatewayDenied):
            call(g, method, ps["zeta"], topic_id=999)
    assert [e["data"]["topic_id"] for e in g.next_events(ps["zeta"], A)["events"]] == [None]
    class Collector:
        def __init__(self):
            self.items = []
        def enqueue(self, p, name, args, body, event_id, *, occurred_at):
            self.items.append((args, body, event_id))
    hub = Collector()
    assert g.export_events(ps["zeta"], hub) == {"exported": 1}
    assert hub.items[0][0] == {"chat_id": A, "topic_id": None}
    assert hub.items[0][1]["topic_id"] is None


async def test_export_under_wildcard_grant_keeps_actual_topic_arguments(setup):
    g, _, ps = setup
    await capture_with_future_topic(setup)
    class Collector:
        def __init__(self):
            self.items = []
        def enqueue(self, p, name, args, body, event_id, *, occurred_at):
            self.items.append((args, body, event_id))
    hub = Collector()
    assert g.export_events(ps["zeta"], hub) == {"exported": 4}
    assert {args["topic_id"] for args, _, _ in hub.items} == {None, 2, 3, 999}
    for args, body, _ in hub.items:
        assert args == {"chat_id": A, "topic_id": body["topic_id"]}
        assert "all_topics" not in args and "all_topics" not in body


async def test_event_only_wildcard_does_not_grant_history(setup):
    g, _, ps = setup
    g.policy = Policy.from_dict({"principals": {"zeta": [{"chat_id": A, "all_topics": True, "permissions": ["events"]}]}})
    g.principals = (ps["zeta"],)
    await g.poll_once()
    assert len(g.next_events(ps["zeta"], A, all_topics=True)["events"]) == 3
    for method in ("read_history", "search_history"):
        with pytest.raises(GatewayDenied):
            call(g, method, ps["zeta"], all_topics=True)


def test_scope_listing_emits_true_but_omits_false_for_legacy_clients(setup):
    g, _, ps = setup
    wildcard = g.list_allowed_scopes(ps["zeta"])
    assert wildcard["history"] == [{"chat_id": A, "topic_id": None, "all_topics": True}]
    exact = g.list_allowed_scopes(ps["exact"])
    assert exact["history"] == [{"chat_id": A, "topic_id": None}, {"chat_id": A, "topic_id": 2}, {"chat_id": A, "topic_id": 3}]
    assert "all_topics" not in json.dumps(exact)


async def test_outbound_from_wildcard_policy_remains_one_reviewed_exact_destination(setup):
    g, wire, ps = setup
    await capture_with_future_topic(setup)
    with pytest.raises(GatewayDenied):
        g.create_draft(ps["reader"], A, "no outbound grant", topic_id=999)
    d = g.create_forward_draft(ps["zeta"], A, 2, A, source_topic_id=2, topic_id=999)
    assert d["draft"]["topic_id"] == 999 and d["draft"]["source"]["topic_id"] == 2
    did = d["draft"]["draft_id"]
    challenge = g.bind_owner_challenge(ps["zeta"], did, A, 800)
    wire.updates.append(update(10, reply=800, sender=99, text=challenge["approval_text"]))
    await g.poll_once()
    assert (await g.send_draft(ps["zeta"], did))["status"] == "sent"
    assert len(wire.sent) == 1 and wire.sent[0]["params"]["message_thread_id"] == 999
    for method in (g.create_draft, g.create_forward_draft, g.send_draft,
                   g.bind_owner_challenge, g.bot.send_message, g.bot.forward_message):
        assert "all_topics" not in inspect.signature(method).parameters


def test_legacy_policy_grant_does_not_silently_become_wildcard():
    old = Policy.from_dict({"principals": {"legacy": [{"chat_id": A, "topic_id": None, "permissions": ["history"]}]}})
    p = FakeAuthenticator({"fake-legacy": "legacy"}).authenticate("Bearer fake-legacy")
    old.require(p, "history", Scope(A))
    with pytest.raises(GatewayDenied):
        old.require(p, "history", Scope(A, 2))
    with pytest.raises(GatewayDenied):
        old.require(p, "history", Scope(A, all_topics=True))
