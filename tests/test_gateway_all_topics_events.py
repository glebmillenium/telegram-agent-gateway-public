"""Explicit whole-chat Events subscriptions, entirely offline synthetic state."""
import asyncio
import base64
import hashlib
import json
import threading

import pytest

from telegram_gateway.auth import PrincipalAuthority
from telegram_gateway.events import EVENT_NAME, EventError, EventHub, MemorySecretStore, WebhookResponse
from telegram_gateway.policy import Policy, Scope

CHAT, FOREIGN = -1001, -1002
SECRET = "whsec_" + base64.b64encode(b"synthetic-all-topics-event-fixture").decode()


class Setup:
    def __init__(self, tmp_path):
        self.now = 1_800_000_000.0
        self.principals = {name: PrincipalAuthority().restore(name) for name in ("wide", "exact", "other")}
        self.grants = {
            "wide": [{"chat_id": CHAT, "all_topics": True, "permissions": ["events"]}],
            "exact": [{"chat_id": CHAT, "topic_id": topic, "permissions": ["events"]} for topic in (None, 7, 9)],
            "other": [{"chat_id": FOREIGN, "all_topics": True, "permissions": ["events"]}],
        }
        self.calls = []
        self.statuses = []
        self.denied_actual_topics = set()
        self.authorizations = []
        self.secrets = MemorySecretStore()
        self.path = tmp_path / "events.sqlite"
        self.hub = self.open()

    def authorize(self, principal, name, arguments):
        self.authorizations.append((principal.id, dict(arguments)))
        if name != EVENT_NAME:
            raise ValueError()
        if not arguments.get("all_topics", False) and arguments["topic_id"] in self.denied_actual_topics:
            raise ValueError()
        Policy.from_dict({"principals": self.grants}).require(principal, "events", Scope(**arguments))

    def callback_authorize(self, principal, callback):
        if callback != self.callback(principal.id):
            raise ValueError()

    @staticmethod
    def callback(owner):
        return "https://receiver.example/" + owner

    async def receiver(self, target, body, headers):
        self.calls.append((target, body, dict(headers)))
        envelope = json.loads(body)
        if envelope.get("type") == "verification":
            return WebhookResponse(200, json.dumps({"challenge": envelope["challenge"]}).encode())
        return WebhookResponse(self.statuses.pop(0) if self.statuses else 200)

    def open(self):
        return EventHub(self.path, self.authorize, sender=self.receiver, resolver=lambda _: ["8.8.8.8"],
                        secret_store=self.secrets, clock=lambda: self.now,
                        principal_factory=PrincipalAuthority().restore, catalog_authorizer=lambda p: bool(self.grants.get(p.id)),
                        callback_authorizer=self.callback_authorize)

    def params(self, owner="wide", *, topic=None, all_topics=None, chat=CHAT, explicit_false=False):
        arguments = {"chat_id": chat, "topic_id": topic}
        if all_topics is not None or explicit_false:
            arguments["all_topics"] = all_topics if not explicit_false else False
        return {"name": EVENT_NAME, "arguments": arguments,
                "delivery": {"mode": "webhook", "url": self.callback(owner), "secret": SECRET}}

    def enqueue(self, topic, *, owner="wide", chat=CHAT, event_id=None):
        return self.hub.enqueue(self.principals[owner], EVENT_NAME, {"chat_id": chat, "topic_id": topic},
                                {"chat_id": chat, "topic_id": topic, "message_id": 1, "text": "synthetic topic"},
                                event_id or "topic-" + str(topic))

    @property
    def deliveries(self):
        return [json.loads(body) for _, body, _ in self.calls if json.loads(body).get("type") != "verification"]


@pytest.fixture
def setup(tmp_path):
    item = Setup(tmp_path)
    yield item
    item.hub.close()


@pytest.mark.asyncio
async def test_catalog_has_explicit_filter_but_payload_is_actual_scope(setup):
    catalog = await setup.hub.handle("events/list", {}, setup.principals["wide"])
    descriptor = catalog["events"][0]
    assert descriptor["inputSchema"]["properties"]["all_topics"]["type"] == "boolean"
    assert descriptor["inputSchema"]["properties"]["all_topics"]["default"] is False
    assert "all_topics" not in descriptor["payloadSchema"]["properties"]


@pytest.mark.asyncio
async def test_explicit_whole_chat_subscription_includes_current_and_new_topics(setup):
    await setup.hub.subscribe(setup.principals["wide"], setup.params(all_topics=True))
    for topic in (None, 7, 9, 987654):
        assert setup.enqueue(topic) == 1
    assert (await setup.hub.deliver_due())["delivered"] == 4
    assert {event["data"]["topic_id"] for event in setup.deliveries} == {None, 7, 9, 987654}
    assert all("all_topics" not in event["data"] for event in setup.deliveries)
    assert all(event["data"]["content_is_untrusted"] is True for event in setup.deliveries)


@pytest.mark.asyncio
async def test_omitted_or_false_flag_with_null_topic_stays_unthreaded(setup):
    old = await setup.hub.subscribe(setup.principals["wide"], setup.params())
    refreshed = await setup.hub.subscribe(setup.principals["wide"], setup.params(explicit_false=True))
    assert old["id"] == refreshed["id"]
    assert setup.enqueue(7) == 0
    assert setup.enqueue(None) == 1
    assert (await setup.hub.deliver_due())["delivered"] == 1
    assert setup.deliveries[0]["data"]["topic_id"] is None


@pytest.mark.asyncio
async def test_exact_and_whole_chat_filters_are_distinct_and_match_only_their_scope(setup):
    broad = await setup.hub.subscribe(setup.principals["wide"], setup.params(all_topics=True))
    exact = await setup.hub.subscribe(setup.principals["wide"], setup.params(topic=7))
    assert broad["id"] != exact["id"]
    assert setup.enqueue(7) == 2
    assert setup.enqueue(9) == 1
    assert setup.enqueue(7) == 0  # Dedup remains per subscription/event ID.


@pytest.mark.asyncio
async def test_union_of_exact_grants_never_authorizes_whole_chat(setup):
    with pytest.raises(EventError):
        await setup.hub.subscribe(setup.principals["exact"], setup.params("exact", all_topics=True))
    assert setup.calls == []
    # Exact subscriptions remain valid, including an explicitly false flag.
    await setup.hub.subscribe(setup.principals["exact"], setup.params("exact", topic=7, explicit_false=True))


@pytest.mark.asyncio
@pytest.mark.parametrize("arguments", [
    {"chat_id": CHAT, "all_topics": 1}, {"chat_id": CHAT, "all_topics": 0},
    {"chat_id": CHAT, "all_topics": "true"}, {"chat_id": CHAT, "all_topics": None},
    {"chat_id": CHAT, "all_topics": []}, {"chat_id": CHAT, "all_topics": True, "topic_id": 7},
    {"chat_id": 1001, "all_topics": True}, {"all_topics": True},
])
async def test_invalid_all_topics_filters_fail_before_verification(setup, arguments):
    request = setup.params()
    request["arguments"] = arguments
    with pytest.raises(EventError):
        await setup.hub.subscribe(setup.principals["wide"], request)
    assert setup.calls == []


@pytest.mark.asyncio
async def test_whole_chat_filter_never_matches_other_chat_or_owner(setup):
    await setup.hub.subscribe(setup.principals["wide"], setup.params(all_topics=True))
    await setup.hub.subscribe(setup.principals["other"], setup.params("other", chat=FOREIGN, all_topics=True))
    with pytest.raises(EventError):
        await setup.hub.subscribe(setup.principals["wide"], setup.params(chat=FOREIGN, all_topics=True))
    with pytest.raises(EventError):
        setup.enqueue(7, chat=FOREIGN)
    assert setup.enqueue(7) == 1
    assert setup.enqueue(7, owner="other", chat=FOREIGN) == 1
    assert (await setup.hub.deliver_due(setup.principals["wide"]))["delivered"] == 1
    assert {event["data"]["chat_id"] for event in setup.deliveries} == {CHAT}


@pytest.mark.asyncio
async def test_legacy_subscription_identity_and_persisted_filter_are_not_migrated(setup):
    sub = await setup.hub.subscribe(setup.principals["wide"], setup.params())
    legacy_args = {"chat_id": CHAT, "topic_id": None}
    identity = json.dumps(["wide", EVENT_NAME, legacy_args, setup.callback("wide")], ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    assert sub["id"] == "sub_" + hashlib.sha256(identity.encode()).hexdigest()
    stored = setup.hub.db.execute("SELECT arguments FROM evt_subscriptions").fetchone()[0]
    assert stored == json.dumps(legacy_args, sort_keys=True, separators=(",", ":"))
    setup.hub.close()
    setup.hub = setup.open()
    renewed = await setup.hub.subscribe(setup.principals["wide"], setup.params(explicit_false=True))
    assert renewed["id"] == sub["id"]
    assert setup.hub.db.execute("SELECT arguments FROM evt_subscriptions").fetchone()[0] == stored
    assert setup.enqueue(7) == 0
    request = setup.params(explicit_false=True)
    request["delivery"].pop("secret")
    setup.hub.unsubscribe(setup.principals["wide"], request)
    assert setup.hub.status(setup.principals["wide"])["active_subscriptions"] == 0


@pytest.mark.asyncio
async def test_downgraded_whole_chat_grant_does_not_become_exact_subscription(setup):
    await setup.hub.subscribe(setup.principals["wide"], setup.params(all_topics=True))
    setup.enqueue(7)
    setup.grants["wide"] = [{"chat_id": CHAT, "topic_id": 7, "permissions": ["events"]}]
    assert setup.enqueue(7, event_id="after-downgrade") == 0
    assert (await setup.hub.deliver_due())["revoked"] == 1
    assert setup.deliveries == []
    assert setup.hub.status(setup.principals["wide"])["active_subscriptions"] == 0


@pytest.mark.asyncio
async def test_actual_topic_permission_is_rechecked_in_addition_to_subscription(setup):
    await setup.hub.subscribe(setup.principals["wide"], setup.params(all_topics=True))
    setup.enqueue(7)
    setup.authorizations.clear()
    setup.denied_actual_topics.add(7)
    assert (await setup.hub.deliver_due())["revoked"] == 1
    assert ("wide", {"chat_id": CHAT, "topic_id": None, "all_topics": True}) in setup.authorizations
    assert ("wide", {"chat_id": CHAT, "topic_id": 7}) in setup.authorizations
    assert setup.deliveries == []


@pytest.mark.asyncio
async def test_retry_restart_preserves_actual_topic_and_owner(setup):
    sub = await setup.hub.subscribe(setup.principals["wide"], setup.params(all_topics=True))
    setup.enqueue(7, event_id="bot:fixture:message-1")
    setup.statuses = [503]
    assert (await setup.hub.deliver_due())["retried"] == 1
    first = setup.deliveries[0]
    setup.now += 4
    setup.hub.close()
    setup.hub = setup.open()
    assert setup.hub.db.execute("SELECT id FROM evt_subscriptions").fetchone()[0] == sub["id"]
    assert (await setup.hub.deliver_due(setup.principals["other"]))["delivered"] == 0
    assert (await setup.hub.deliver_due(setup.principals["wide"]))["delivered"] == 1
    assert setup.deliveries == [first, first]
    assert first["data"]["topic_id"] == 7
    assert setup.enqueue(999999, event_id="bot:fixture:message-2") == 1


@pytest.mark.asyncio
async def test_emitted_message_must_have_actual_scope_and_no_wildcard_payload(setup):
    await setup.hub.subscribe(setup.principals["wide"], setup.params(all_topics=True))
    data = {"chat_id": CHAT, "topic_id": 7, "message_id": 1, "text": "fixture"}
    with pytest.raises(EventError):
        setup.hub.enqueue(setup.principals["wide"], EVENT_NAME, {"chat_id": CHAT, "all_topics": True}, data, "bad-scope")
    with pytest.raises(EventError):
        setup.hub.enqueue(setup.principals["wide"], EVENT_NAME, {"chat_id": CHAT, "topic_id": 7}, {**data, "all_topics": True}, "bad-body")


@pytest.mark.asyncio
async def test_delivery_rejects_queued_body_outside_saved_filter(setup):
    await setup.hub.subscribe(setup.principals["wide"], setup.params(all_topics=True))
    setup.enqueue(7)
    body = json.loads(setup.hub.db.execute("SELECT body FROM evt_deliveries").fetchone()[0])
    body["data"]["chat_id"] = FOREIGN
    setup.hub.db.execute("UPDATE evt_deliveries SET body=?", (json.dumps(body).encode(),))
    assert (await setup.hub.deliver_due())["revoked"] == 1
    assert setup.deliveries == []


@pytest.mark.asyncio
async def test_whole_chat_revocation_during_dns_prevents_http_delivery(setup):
    await setup.hub.subscribe(setup.principals["wide"], setup.params(all_topics=True))
    setup.enqueue(7)
    entered, release = threading.Event(), threading.Event()

    def delayed_dns(_):
        entered.set()
        release.wait(2)
        return ["8.8.8.8"]

    setup.hub.resolver = delayed_dns
    task = asyncio.create_task(setup.hub.deliver_due())
    try:
        for _ in range(100):
            if entered.is_set():
                break
            await asyncio.sleep(0.005)
        assert entered.is_set()
        setup.grants["wide"] = [{"chat_id": CHAT, "topic_id": 7, "permissions": ["events"]}]
        release.set()
        assert (await asyncio.wait_for(task, timeout=2))["revoked"] == 1
        assert setup.deliveries == []
    finally:
        release.set()
        if not task.done():
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)
