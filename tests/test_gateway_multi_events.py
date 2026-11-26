"""Two synthetic bot runtimes: protocol routing, queues and callback isolation.

All credentials/signing keys below are inert fixtures generated from constants.
No personal configuration, real secrets, listeners or network are accessed.
"""
import base64
import json
from types import SimpleNamespace

import pytest
import pytest_asyncio

from telegram_gateway.auth import VerifiedPrincipal
from telegram_gateway.bot_api import FakeBotTransport
from telegram_gateway.demo import message
from telegram_gateway.events import EVENT_NAME, EventError, WebhookResponse, verify_signature
from telegram_gateway.protocol import CAPABILITIES_KEY, VERSION_KEY
from telegram_gateway.runtime import make_runtime
from telegram_gateway.runtime_config import RuntimeConfig

BOT = {"alpha": "alpha_test_bot", "beta": "beta_test_bot"}
CALLBACK = {who: f"https://receiver.example/{who}" for who in BOT}
SHARED_CALLBACK = "https://receiver.example/shared"
SECRET = {who: "whsec_" + base64.b64encode(("synthetic-multi-event-key-" + who).encode()).decode() for who in BOT}
ROTATED = "whsec_" + base64.b64encode(b"synthetic-multi-event-key-alpha-rotated").decode()
CHAT, TOPIC = -1001, 7


class Receiver:
    def __init__(self):
        self.calls = []
        self.fail_events = False

    async def __call__(self, target, body, headers):
        self.calls.append((target, body, dict(headers)))
        envelope = json.loads(body)
        if envelope.get("type") == "verification":
            return WebhookResponse(200, json.dumps({"challenge": envelope["challenge"]}).encode())
        if self.fail_events:
            raise ConnectionError("synthetic callback failure")
        return WebhookResponse(200)

    @property
    def events(self):
        return [call for call in self.calls if json.loads(call[1]).get("type") != "verification"]


def config_data(tmp_path, *, beta_events=True):
    profiles = []
    for index, who in enumerate(BOT):
        profiles.append({"id": who, "name": f"Synthetic {who}", "purpose": "Isolation test only",
                         "prompt": "Metadata only", "enabled": True, "telegram_username": BOT[who],
                         "auth_principal": "agent-" + who, "expected_bot_id": 5001 + index,
                         "chats": [{"chat_id": CHAT, "topic_id": TOPIC, "type": "supergroup", "title": "Shared synthetic group",
                                    "actions": ["history", "events"] if who == "alpha" or beta_events else ["history"]}]})
    return {"version": 1, "mode": "fake", "state_dir": str(tmp_path / "state"),
            "network_enabled": False, "outbound_enabled": False,
            "auth": {"mode": "fake", "credentials": {"fixture-" + who: "agent-" + who for who in BOT}},
            "agents": profiles,
            "allowed_callbacks": {"agent-" + who: [CALLBACK[who], SHARED_CALLBACK] for who in BOT}}


async def open_environment(tmp_path, *, beta_events=True):
    cfg = RuntimeConfig.from_dict(config_data(tmp_path, beta_events=beta_events), project_root=tmp_path / "code")
    receivers = {who: Receiver() for who in BOT}
    transports = {who: FakeBotTransport([message(1, CHAT, who + "-only synthetic message", topic=TOPIC)]) for who in BOT}
    runtime = make_runtime(cfg, transports={BOT[who]: wire for who, wire in transports.items()},
                           senders={BOT[who]: receiver for who, receiver in receivers.items()},
                           resolvers={ref: lambda _: ["8.8.8.8"] for ref in BOT.values()})
    await runtime.start()
    principals = {who: runtime.auth.authenticate("Bearer fixture-" + who) for who in BOT}
    return SimpleNamespace(runtime=runtime, cfg=cfg, principals=principals, receivers=receivers, transports=transports)


@pytest_asyncio.fixture
async def env(tmp_path):
    item = await open_environment(tmp_path)
    try:
        yield item
    finally:
        await item.runtime.close()


def params(who, *, callback=None, secret=None):
    return {"name": EVENT_NAME, "arguments": {"chat_id": CHAT, "topic_id": TOPIC},
            "delivery": {"mode": "webhook", "url": callback or CALLBACK[who], "secret": secret or SECRET[who]}, "cursor": None}


async def rpc(env, who, method, args=None):
    request = {"jsonrpc": "2.0", "id": "multi-event-test", "method": method,
               "params": {"_meta": {VERSION_KEY: "2026-07-28", CAPABILITIES_KEY: {}}, **(args or {})}}
    # Pass a JSON round-trip and only the independently verified principal.
    response = await env.runtime.protocol.request_authenticated(json.loads(json.dumps(request)), env.principals[who])
    return json.loads(json.dumps(response))


async def subscribe(env, who, **kwargs):
    response = await rpc(env, who, "events/subscribe", params(who, **kwargs))
    assert "result" in response, response
    return response["result"]


async def capture(env, who):
    child = env.runtime.children[BOT[who]]
    await child.gateway.poll_once()
    result = child.gateway.export_events(env.principals[who], child.hub)
    return result


def row(env, who):
    return env.runtime.children[BOT[who]].hub.db.execute("SELECT * FROM evt_subscriptions WHERE active=1").fetchone()


@pytest.mark.asyncio
async def test_identical_telegram_ids_are_namespaced_at_export_and_delivered_independently(env):
    subscriptions = {who: await subscribe(env, who) for who in BOT}
    assert subscriptions["alpha"]["id"] != subscriptions["beta"]["id"]
    children = env.runtime.children
    assert children[BOT["alpha"]].hub.path != children[BOT["beta"]].hub.path
    assert children[BOT["alpha"]].secrets.path != children[BOT["beta"]].secrets.path
    ids, task_ids = [], []
    for who in BOT:
        child = children[BOT[who]]
        assert (await capture(env, who))["exported"] == 1
        assert (await capture(env, who))["exported"] == 0
        assert (await child.hub.deliver_due())["delivered"] == 1
        assert (await child.hub.deliver_due())["delivered"] == 0
        assert len(env.receivers[who].events) == 1
        _, body, headers = env.receivers[who].events[0]
        envelope = json.loads(body)
        assert envelope["data"]["chat_id"] == CHAT and envelope["data"]["message_id"] == 1
        assert envelope["data"]["text"] == who + "-only synthetic message"
        assert envelope["data"]["content_is_untrusted"] is True
        assert "bot_ref" not in envelope["data"] and "bot_reference" not in envelope["data"]
        assert envelope["eventId"] == headers["webhook-id"]
        ids.append(envelope["eventId"])
        task_ids.append(envelope["data"]["task_id"])
        verify_signature(SECRET[who], body, headers, now=int(headers["webhook-timestamp"]), replay_ids=set())
        other = "beta" if who == "alpha" else "alpha"
        with pytest.raises(EventError):
            verify_signature(SECRET[other], body, headers, now=int(headers["webhook-timestamp"]), replay_ids=set())
    assert ids[0] != ids[1]  # Receiver-side dedup must not discard the other bot.
    assert task_ids[0] != task_ids[1]  # Reply/task correlation must retain origin.


@pytest.mark.asyncio
async def test_same_local_outbox_event_id_dedup_does_not_cross_databases(env):
    for who in BOT:
        await subscribe(env, who)
        child = env.runtime.children[BOT[who]]
        data = {"chat_id": CHAT, "topic_id": TOPIC, "message_id": 1, "text": who}
        assert child.hub.enqueue(env.principals[who], EVENT_NAME, {"chat_id": CHAT, "topic_id": TOPIC}, data, "same-local-id") == 1
        assert child.hub.enqueue(env.principals[who], EVENT_NAME, {"chat_id": CHAT, "topic_id": TOPIC}, data, "same-local-id") == 0
        assert child.hub.db.execute("SELECT COUNT(*) FROM evt_deliveries").fetchone()[0] == 1


@pytest.mark.asyncio
async def test_shared_callback_subscriptions_have_distinct_owner_secret_references(env):
    for who in BOT:
        await subscribe(env, who, callback=SHARED_CALLBACK)
    alpha, beta = row(env, "alpha"), row(env, "beta")
    assert alpha["id"] != beta["id"] and alpha["secret_ref"] != beta["secret_ref"]
    assert len(env.receivers["alpha"].calls) == len(env.receivers["beta"].calls) == 1
    for who, own, other in (("alpha", alpha, beta), ("beta", beta, alpha)):
        store = env.runtime.children[BOT[who]].secrets
        assert store.get(own["secret_ref"]) == SECRET[who]
        with pytest.raises(EventError):
            store.get(other["secret_ref"])


@pytest.mark.asyncio
async def test_callback_binding_rejects_other_bot_receiver_before_any_callback(env):
    response = await rpc(env, "alpha", "events/subscribe", params("alpha", callback=CALLBACK["beta"]))
    assert response["error"]["code"] == -33001
    assert env.receivers["alpha"].calls == env.receivers["beta"].calls == []
    assert env.runtime.children[BOT["beta"]].hub.status(env.principals["beta"])["active_subscriptions"] == 0


@pytest.mark.asyncio
@pytest.mark.parametrize("field", ["bot", "bot_ref", "bot_reference", "agent_id", "principal"])
async def test_event_request_cannot_override_authenticated_bot_route(env, field):
    request = params("alpha")
    request[field] = BOT["beta"]
    response = await rpc(env, "alpha", "events/subscribe", request)
    assert response["error"]["code"] == -32602
    request = params("alpha")
    request["arguments"][field] = BOT["beta"]
    assert (await rpc(env, "alpha", "events/subscribe", request))["error"]["code"] == -32602
    assert env.receivers["alpha"].calls == env.receivers["beta"].calls == []


@pytest.mark.asyncio
async def test_history_tools_and_catalog_route_by_principal_even_same_chat(env):
    for who in BOT:
        await capture(env, who)
        catalog = (await rpc(env, who, "events/list"))["result"]
        assert [item["name"] for item in catalog["events"]] == [EVENT_NAME]
        assert "bot_reference" not in catalog["events"][0]["inputSchema"]["properties"]
        history = await rpc(env, who, "tools/call", {"name": "read_history", "arguments": {"chat_id": CHAT, "topic_id": TOPIC}})
        assert history["result"]["structuredContent"]["messages"][0]["text"] == who + "-only synthetic message"
    forged = await rpc(env, "alpha", "tools/call", {"name": "read_history", "arguments": {"chat_id": CHAT, "topic_id": TOPIC, "bot_reference": BOT["beta"]}})
    assert "error" in forged or forged["result"].get("isError") is True
    metadata_claim = {"jsonrpc": "2.0", "id": "untrusted-route-hint", "method": "tools/call", "params": {
        "_meta": {VERSION_KEY: "2026-07-28", CAPABILITIES_KEY: {}, "com.example/bot_reference": BOT["beta"]},
        "name": "read_history", "arguments": {"chat_id": CHAT, "topic_id": TOPIC}}}
    response = await env.runtime.protocol.request_authenticated(metadata_claim, env.principals["alpha"])
    assert response["result"]["structuredContent"]["messages"][0]["text"] == "alpha-only synthetic message"


@pytest.mark.asyncio
async def test_catalog_permission_does_not_bleed_between_bots(tmp_path):
    item = await open_environment(tmp_path, beta_events=False)
    try:
        assert (await rpc(item, "alpha", "events/list"))["result"]["events"]
        assert (await rpc(item, "beta", "events/list"))["result"]["events"] == []
        assert (await rpc(item, "beta", "events/subscribe", params("beta")))["error"]["code"] == -33001
        assert item.receivers["beta"].calls == []
    finally:
        await item.runtime.close()


@pytest.mark.asyncio
async def test_unverified_identity_cannot_pick_any_child(env):
    for principal in (VerifiedPrincipal("agent-alpha"), {"id": "agent-alpha"}, None):
        request = {"jsonrpc": "2.0", "id": 1, "method": "events/list", "params": {"_meta": {VERSION_KEY: "2026-07-28", CAPABILITIES_KEY: {}}}}
        response = await env.runtime.protocol.request_authenticated(request, principal)
        assert response["error"]["code"] == -33001


@pytest.mark.asyncio
async def test_unsubscribe_rotation_and_revocation_touch_only_own_bot(env):
    for who in BOT:
        await subscribe(env, who, callback=SHARED_CALLBACK)
        await capture(env, who)
    old_beta_ref = row(env, "beta")["secret_ref"]
    await subscribe(env, "alpha", callback=SHARED_CALLBACK, secret=ROTATED)
    assert row(env, "beta")["secret_ref"] == old_beta_ref
    alpha = env.runtime.children[BOT["alpha"]]
    beta = env.runtime.children[BOT["beta"]]
    assert beta.secrets.get(old_beta_ref) == SECRET["beta"]
    request = {"name": EVENT_NAME, "arguments": {"chat_id": CHAT, "topic_id": TOPIC}, "delivery": {"mode": "webhook", "url": SHARED_CALLBACK}}
    assert "result" in await rpc(env, "alpha", "events/unsubscribe", request)
    assert alpha.hub.status(env.principals["alpha"])["active_subscriptions"] == 0
    assert beta.hub.status(env.principals["beta"])["active_subscriptions"] == 1
    assert (await alpha.hub.deliver_due())["delivered"] == 0
    assert (await beta.hub.deliver_due())["delivered"] == 1
    assert not env.receivers["alpha"].events and len(env.receivers["beta"].events) == 1


@pytest.mark.asyncio
async def test_transient_failure_and_retry_state_are_independent(env):
    for who in BOT:
        await subscribe(env, who)
        await capture(env, who)
    env.receivers["alpha"].fail_events = True
    result_a = await env.runtime.children[BOT["alpha"]].hub.deliver_due()
    result_b = await env.runtime.children[BOT["beta"]].hub.deliver_due()
    assert result_a["retried"] == 1 and result_a["delivered"] == 0
    assert result_b["delivered"] == 1 and result_b["retried"] == 0
    a = env.runtime.children[BOT["alpha"]].hub.db.execute("SELECT status,attempts FROM evt_deliveries").fetchone()
    b = env.runtime.children[BOT["beta"]].hub.db.execute("SELECT status,attempts FROM evt_deliveries").fetchone()
    assert a["status"] == "pending" and a["attempts"] == 1
    assert b["status"] == "delivered" and b["attempts"] == 1


@pytest.mark.asyncio
async def test_restart_one_bot_preserves_its_pending_subscription_without_touching_other(env):
    subscriptions = {who: await subscribe(env, who) for who in BOT}
    for who in BOT:
        await capture(env, who)
    original_beta = env.runtime.children[BOT["beta"]]
    alpha_id = row(env, "alpha")["id"]
    assert await env.runtime.restart_bot(BOT["alpha"]) is True
    assert env.runtime.children[BOT["beta"]] is original_beta
    assert row(env, "alpha")["id"] == alpha_id == subscriptions["alpha"]["id"]
    for who in BOT:
        child = env.runtime.children[BOT[who]]
        assert (await child.hub.deliver_due())["delivered"] == 1
        assert (await capture(env, who))["exported"] == 0
        assert len(env.receivers[who].events) == 1


@pytest.mark.asyncio
async def test_foreign_principal_cannot_enqueue_into_other_bot_hub(env):
    await subscribe(env, "beta")
    beta = env.runtime.children[BOT["beta"]]
    with pytest.raises(EventError):
        beta.hub.enqueue(env.principals["alpha"], EVENT_NAME, {"chat_id": CHAT, "topic_id": TOPIC},
                         {"chat_id": CHAT, "topic_id": TOPIC, "message_id": 1, "text": "cross-bot attempt"}, "same-local-id")
    assert beta.hub.db.execute("SELECT COUNT(*) FROM evt_deliveries").fetchone()[0] == 0


@pytest.mark.asyncio
async def test_queued_event_policy_revocation_affects_only_one_bot(env):
    for who in BOT:
        await subscribe(env, who)
        await capture(env, who)
    alpha, beta = (env.runtime.children[BOT[who]] for who in BOT)

    def revoke(*_):
        raise ValueError("Synthetic permission revoked")

    alpha.hub.authorizer = revoke
    assert (await alpha.hub.deliver_due())["revoked"] == 1
    assert (await beta.hub.deliver_due())["delivered"] == 1
    assert not env.receivers["alpha"].events
    assert len(env.receivers["beta"].events) == 1
