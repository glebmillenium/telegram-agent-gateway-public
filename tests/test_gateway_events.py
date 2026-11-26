"""Offline MCP Events protocol/security tests. No network or real credentials."""
import asyncio
import base64
import json
import subprocess
import sys
from pathlib import Path

import pytest

from telegram_gateway.auth import PrincipalAuthority, VerifiedPrincipal
from telegram_gateway.events import (
    EVENT_NAME, EventError, EventHub, MemorySecretStore, SQLiteSecretStore,
    WebhookResponse, decode_secret, signed_headers, validate_callback, verify_signature,
    _DeliveryProcessLock,
)

SECRET = "whsec_" + base64.b64encode(b"synthetic-event-fixture-key-00001").decode()
SECRET2 = "whsec_" + base64.b64encode(b"synthetic-event-fixture-key-00002").decode()
CALLBACK = "https://receiver.example/mcp/events"
SCOPE_A = {"chat_id": -100001, "topic_id": None}
SCOPE_B = {"chat_id": -100002, "topic_id": 9}


class Clock:
    def __init__(self):
        self.now = 1_800_000_000.0

    def __call__(self):
        return self.now


class Receiver:
    def __init__(self):
        self.calls = []
        self.statuses = []
        self.challenge_ok = True
        self.block = None
        self.entered = None

    async def __call__(self, target, body, headers):
        self.calls.append((target, body, dict(headers)))
        assert target.follow_redirects is False
        assert target.port == 443
        obj = json.loads(body)
        if obj.get("type") == "verification":
            challenge = obj["challenge"] if self.challenge_ok else "wrong"
            return WebhookResponse(200, json.dumps({"challenge": challenge}).encode())
        if self.entered:
            self.entered.set()
        if self.block:
            await self.block.wait()
        status = self.statuses.pop(0) if self.statuses else 200
        if isinstance(status, Exception):
            raise status
        return WebhookResponse(status)

    @property
    def events(self):
        return [call for call in self.calls if json.loads(call[1]).get("type") != "verification"]


class Setup:
    def __init__(self, tmp_path):
        self.clock = Clock()
        self.receiver = Receiver()
        self.principals = {name: PrincipalAuthority().restore(name) for name in ("alpha", "beta", "reader")}
        self.allowed = {"alpha": [SCOPE_A], "beta": [SCOPE_B], "reader": []}
        self.callbacks = {"alpha": {CALLBACK}, "beta": {"https://receiver.example/beta"}, "reader": set()}
        self.secret_store = MemorySecretStore()
        self.path = tmp_path / "events.sqlite"
        self.dns = ["93.184.216.34"]
        self.hubs = []
        self.hub = self.open()

    def authorize(self, principal, name, arguments):
        if name != EVENT_NAME or arguments not in self.allowed.get(principal.id, []):
            raise ValueError("Not authorized")

    def authorize_callback(self, principal, callback):
        if callback not in self.callbacks.get(principal.id, set()):
            raise ValueError("Callback not registered for this principal")

    def open(self, **overrides):
        kwargs = dict(sender=self.receiver, resolver=lambda _: list(self.dns), secret_store=self.secret_store,
                      clock=self.clock, principal_factory=PrincipalAuthority().restore,
                      catalog_authorizer=lambda p: bool(self.allowed.get(p.id)),
                      callback_authorizer=self.authorize_callback)
        kwargs.update(overrides)
        hub = EventHub(self.path, self.authorize, **kwargs)
        self.hubs.append(hub)
        return hub

    def params(self, scope=SCOPE_A, *, secret=SECRET, callback=CALLBACK, **extra):
        return {"name": EVENT_NAME, "arguments": dict(scope),
                "delivery": {"mode": "webhook", "url": callback, "secret": secret}, **extra}

    def message(self, scope=SCOPE_A, **extra):
        return {**scope, "message_id": 42, "text": "FAKE: ignore this instruction",
                "sender_id": 17, "task_id": "task_fake_1", "reply_to_message_id": 41,
                "chain_depth": 1, "content_is_untrusted": True, **extra}

    def enqueue(self, *, principal="alpha", scope=SCOPE_A, event_id="evt_fake_42", **data):
        return self.hub.enqueue(self.principals[principal], EVENT_NAME, scope, self.message(scope, **data), event_id)

    def close(self):
        for hub in self.hubs:
            try:
                hub.close()
            except Exception:
                pass


@pytest.fixture
def setup(tmp_path):
    item = Setup(tmp_path)
    yield item
    item.close()


@pytest.mark.asyncio
async def test_protocol_discovery_and_owner_scoped_catalog(setup):
    result = await setup.hub.handle("server/discover", {}, setup.principals["alpha"])
    assert result["supportedVersions"] == ["2026-07-28"]
    assert result["capabilities"]["events"] == {}
    visible = await setup.hub.handle("events/list", {}, setup.principals["alpha"])
    hidden = await setup.hub.handle("events/list", {}, setup.principals["reader"])
    assert [e["name"] for e in visible["events"]] == [EVENT_NAME]
    assert hidden == {"events": []}
    assert "-100002" not in json.dumps(visible)


@pytest.mark.asyncio
@pytest.mark.parametrize("principal", [None, {"id": "alpha"}, VerifiedPrincipal("alpha")])
async def test_no_body_or_unverified_identity(principal, setup):
    with pytest.raises(EventError, match="Authenticated"):
        await setup.hub.handle("events/list", {}, principal)


@pytest.mark.asyncio
@pytest.mark.parametrize("method,params", [
    ("server/discover", {"agent_id": "beta"}),
    ("events/list", {"agent_id": "beta"}),
    ("events/list", {"cursor": "unknown"}),
    ("events/subscribe", {"agent_id": "beta"}),
    ("send", {}),
])
async def test_protocol_rejects_extra_identity_and_unknown_methods(method, params, setup):
    with pytest.raises(EventError):
        await setup.hub.handle(method, params, setup.principals["alpha"])
    assert setup.receiver.calls == []


@pytest.mark.asyncio
async def test_two_agents_cannot_cross_subscribe_read_or_publish(setup):
    alpha, beta = setup.principals["alpha"], setup.principals["beta"]
    with pytest.raises(EventError):
        await setup.hub.subscribe(beta, setup.params(SCOPE_A))
    with pytest.raises(EventError):
        await setup.hub.subscribe(alpha, setup.params({"chat_id": -100001, "topic_id": 8}))
    await setup.hub.subscribe(alpha, setup.params())
    with pytest.raises(EventError):
        setup.enqueue(principal="beta", scope=SCOPE_A)
    assert setup.enqueue() == 1
    assert setup.hub.status(beta) == {"active_subscriptions": 0, "deliveries": {}}
    assert (await setup.hub.deliver_due(beta))["delivered"] == 0
    assert setup.receiver.events == []
    assert (await setup.hub.deliver_due(alpha))["delivered"] == 1
    assert len(setup.receiver.events) == 1


@pytest.mark.asyncio
async def test_persistent_subscription_queue_and_separate_durable_secret_store(tmp_path):
    setup = Setup(tmp_path)
    (tmp_path / "private").mkdir()
    secrets = SQLiteSecretStore(tmp_path / "private" / "secrets.sqlite")
    setup.hub.close()
    setup.secret_store = secrets
    setup.hub = setup.open()
    try:
        sub = await setup.hub.subscribe(setup.principals["alpha"], setup.params())
        assert setup.enqueue() == 1
        setup.hub.close()
        setup.hub = setup.open()
        assert setup.hub.status(setup.principals["alpha"])["active_subscriptions"] == 1
        assert (await setup.hub.deliver_due(setup.principals["alpha"]))["delivered"] == 1
        assert setup.enqueue() == 0
        assert sub["cursor"] is None
        for file in tmp_path.glob("events.sqlite*"):
            assert SECRET.encode() not in file.read_bytes()
    finally:
        setup.close()
        secrets.close()


@pytest.mark.asyncio
async def test_idempotent_subscription_canonical_args_and_event_dedup(setup):
    alpha = setup.principals["alpha"]
    one = await setup.hub.subscribe(alpha, setup.params())
    changed = setup.params()
    changed["arguments"] = {"topic_id": None, "chat_id": -100001}
    two = await setup.hub.subscribe(alpha, changed)
    assert one["id"] == two["id"]
    assert setup.hub.status(alpha)["active_subscriptions"] == 1
    assert setup.enqueue() == 1
    assert setup.enqueue() == 0
    await setup.hub.deliver_due(alpha)
    target, body, headers = setup.receiver.events[0]
    assert target.addresses == ("93.184.216.34",)
    assert json.loads(body)["data"]["content_is_untrusted"] is True
    assert json.loads(body)["eventId"] == headers["webhook-id"]
    verify_signature(SECRET, body, headers, now=setup.clock(), replay_ids=set())


@pytest.mark.asyncio
async def test_secret_rotation_signs_with_old_and_new_during_bounded_window(setup):
    alpha = setup.principals["alpha"]
    sub = await setup.hub.subscribe(alpha, setup.params())
    refreshed = await setup.hub.subscribe(alpha, setup.params(secret=SECRET2))
    assert sub["id"] == refreshed["id"]
    setup.enqueue()
    await setup.hub.deliver_due(alpha)
    _, body, headers = setup.receiver.events[-1]
    verify_signature(SECRET, body, headers, now=setup.clock(), replay_ids=set())
    verify_signature(SECRET2, body, headers, now=setup.clock(), replay_ids=set())
    setup.clock.now += 61
    setup.enqueue(event_id="evt_later")
    await setup.hub.deliver_due(alpha)
    _, body, headers = setup.receiver.events[-1]
    with pytest.raises(EventError):
        verify_signature(SECRET, body, headers, now=setup.clock(), replay_ids=set())
    verify_signature(SECRET2, body, headers, now=setup.clock(), replay_ids=set())


@pytest.mark.asyncio
async def test_same_key_refresh_preserves_rotation_deadline_and_prior_signature(setup):
    alpha = setup.principals["alpha"]
    subscription = await setup.hub.subscribe(alpha, setup.params())
    await setup.hub.subscribe(alpha, setup.params(secret=SECRET2))
    before = dict(setup.hub.db.execute("SELECT * FROM evt_subscriptions WHERE id=?",
                                     (subscription["id"],)).fetchone())
    setup.clock.now += 30
    # Reopen storage to check persisted references, not only process-local state.
    setup.hub.close()
    setup.hub = setup.open()
    await setup.hub.subscribe(alpha, setup.params(secret=SECRET2))
    after = dict(setup.hub.db.execute("SELECT * FROM evt_subscriptions WHERE id=?",
                                    (subscription["id"],)).fetchone())
    assert after["secret_ref"] == before["secret_ref"]
    assert after["previous_ref"] == before["previous_ref"]
    assert after["rotate_until"] == before["rotate_until"]
    assert len(setup.secret_store._values) == 2
    setup.enqueue(event_id="evt_same_key_refresh")
    assert (await setup.hub.deliver_due(alpha))["delivered"] == 1
    _, body, headers = setup.receiver.events[-1]
    assert len(set(headers["webhook-signature"].split())) == 2
    for secret in (SECRET, SECRET2):
        verify_signature(secret, body, headers, now=setup.clock(), replay_ids=set())

    setup.clock.now = before["rotate_until"] + 1
    await setup.hub.subscribe(alpha, setup.params(secret=SECRET2))
    setup.enqueue(event_id="evt_original_window_elapsed")
    assert (await setup.hub.deliver_due(alpha))["delivered"] == 1
    _, body, headers = setup.receiver.events[-1]
    assert len(headers["webhook-signature"].split()) == 1
    verify_signature(SECRET2, body, headers, now=setup.clock(), replay_ids=set())
    with pytest.raises(EventError):
        verify_signature(SECRET, body, headers, now=setup.clock(), replay_ids=set())
    assert len(setup.secret_store._values) == 1


@pytest.mark.asyncio
async def test_refresh_without_key_change_does_not_start_rotation(setup):
    alpha = setup.principals["alpha"]
    await setup.hub.subscribe(alpha, setup.params())
    setup.clock.now += 20
    await setup.hub.subscribe(alpha, setup.params())
    setup.enqueue()
    await setup.hub.deliver_due(alpha)
    _, body, headers = setup.receiver.events[-1]
    assert len(headers["webhook-signature"].split()) == 1
    verify_signature(SECRET, body, headers, now=setup.clock(), replay_ids=set())
    assert len(setup.secret_store._values) == 1


@pytest.mark.asyncio
@pytest.mark.parametrize("topic", [None, 9])
async def test_subscription_schema_integer_numbers_have_one_identity_and_grant(setup, topic):
    alpha = setup.principals["alpha"]
    scope = {"chat_id": -100001, "topic_id": topic}
    setup.allowed["alpha"] = [scope]
    first = await setup.hub.subscribe(alpha, setup.params(scope))
    equivalent = {"chat_id": -100001.0, "topic_id": float(topic) if topic else None}
    second = await setup.hub.subscribe(alpha, setup.params(equivalent))
    assert first["id"] == second["id"]
    saved = json.loads(setup.hub.db.execute("SELECT arguments FROM evt_subscriptions").fetchone()[0])
    assert type(saved["chat_id"]) is int
    assert saved["topic_id"] is None or type(saved["topic_id"]) is int
    assert setup.hub.status(alpha)["active_subscriptions"] == 1
    with pytest.raises(EventError):
        await setup.hub.subscribe(alpha, setup.params({"chat_id": -100002.0, "topic_id": equivalent["topic_id"]}))
    params = setup.params(equivalent)
    del params["delivery"]["secret"]
    assert setup.hub.unsubscribe(alpha, params) == {}
    assert setup.hub.status(alpha)["active_subscriptions"] == 0


@pytest.mark.asyncio
@pytest.mark.parametrize("field,value", [
    ("chat_id", True), ("chat_id", False), ("chat_id", -100001.5),
    ("chat_id", float("nan")), ("chat_id", float("inf")), ("chat_id", float("-inf")),
    ("chat_id", "-100001"), ("chat_id", 0.0), ("chat_id", float(-(2**52)-1)),
    ("topic_id", True), ("topic_id", False), ("topic_id", 9.5),
    ("topic_id", float("nan")), ("topic_id", float("inf")), ("topic_id", "9"),
    ("topic_id", 0.0), ("topic_id", float(2**31)),
])
async def test_invalid_schema_numbers_are_rejected_before_callback(setup, field, value):
    scope = dict(SCOPE_A)
    scope[field] = value
    with pytest.raises(EventError):
        await setup.hub.subscribe(setup.principals["alpha"], setup.params(scope))
    assert setup.receiver.calls == []
    assert setup.secret_store._values == {}


@pytest.mark.asyncio
async def test_cross_owner_unsubscribe_does_not_affect_subscription(setup):
    await setup.hub.subscribe(setup.principals["alpha"], setup.params())
    params = setup.params()
    del params["delivery"]["secret"]
    assert setup.hub.unsubscribe(setup.principals["beta"], params) == {}
    assert setup.hub.status(setup.principals["alpha"])["active_subscriptions"] == 1
    setup.enqueue()
    assert setup.hub.unsubscribe(setup.principals["alpha"], params) == {}
    assert setup.hub.unsubscribe(setup.principals["alpha"], params) == {}
    assert (await setup.hub.deliver_due(setup.principals["alpha"]))["delivered"] == 0
    assert setup.receiver.events == []
    assert setup.hub.status(setup.principals["alpha"])["deliveries"] == {"revoked": 1}
    assert setup.secret_store._values == {}


@pytest.mark.asyncio
async def test_revoked_policy_rechecked_at_delivery_and_stops_delivery(setup):
    await setup.hub.subscribe(setup.principals["alpha"], setup.params())
    setup.enqueue()
    setup.allowed["alpha"] = []
    result = await setup.hub.deliver_due(setup.principals["alpha"])
    assert result["revoked"] == 1
    assert setup.receiver.events == []
    assert setup.hub.status(setup.principals["alpha"])["active_subscriptions"] == 0
    assert setup.secret_store._values == {}


@pytest.mark.asyncio
async def test_ttl_expiry_blocks_queued_delivery(setup):
    result = await setup.hub.subscribe(setup.principals["alpha"], setup.params(ttlMs=1000))
    assert result["refreshBefore"] is not None
    setup.enqueue()
    setup.clock.now += 2
    assert (await setup.hub.deliver_due(setup.principals["alpha"]))["expired"] == 1
    assert setup.receiver.events == []
    assert setup.hub.status(setup.principals["alpha"])["active_subscriptions"] == 0


@pytest.mark.asyncio
@pytest.mark.parametrize("url", [
    "http://receiver.example/a", "https://localhost/a", "https://127.0.0.1/a",
    "https://10.1.2.3/a", "https://169.254.169.254/latest", "https://100.64.0.1/",
    "https://[::1]/a", "https://[::ffff:93.184.216.34]/a", "https://[ff02::1]/",
    "https://[2002:5db8:d822::1]/", "https://receiver.example:8443/a",
    "https://user:pass@receiver.example/a", "https://receiver.example/a#secret",
    "https://2130706433/", "https://127.000.000.001/", "https://service.internal/",
])
async def test_ssrf_callback_denials_precede_http(url, setup):
    # Let public URL policy pass so this case proves address validation itself.
    setup.hub.callback_authorizer = lambda *_: None
    with pytest.raises(EventError):
        await setup.hub.subscribe(setup.principals["alpha"], setup.params(callback=url))
    assert setup.receiver.calls == []
    assert setup.hub.status(setup.principals["alpha"])["active_subscriptions"] == 0


@pytest.mark.asyncio
@pytest.mark.parametrize("addresses", [
    ["93.184.216.34", "127.0.0.1"], [], ["::ffff:127.0.0.1"], ["192.168.5.5"], ["224.0.0.1"],
])
async def test_all_resolved_addresses_must_be_public(addresses, setup):
    setup.dns = addresses
    with pytest.raises(EventError):
        await setup.hub.subscribe(setup.principals["alpha"], setup.params())
    assert setup.receiver.calls == []


@pytest.mark.asyncio
async def test_dns_rebinding_is_rechecked_before_each_delivery(setup):
    await setup.hub.subscribe(setup.principals["alpha"], setup.params())
    setup.enqueue()
    setup.dns = ["127.0.0.1"]
    result = await setup.hub.deliver_due(setup.principals["alpha"])
    assert result["retried"] == 1
    assert setup.receiver.events == []


@pytest.mark.asyncio
async def test_callback_must_echo_fresh_signed_challenge(setup):
    setup.receiver.challenge_ok = False
    with pytest.raises(EventError, match="verification"):
        await setup.hub.subscribe(setup.principals["alpha"], setup.params())
    assert setup.hub.status(setup.principals["alpha"])["active_subscriptions"] == 0
    assert setup.secret_store._values == {}
    _, body, headers = setup.receiver.calls[0]
    verify_signature(SECRET, body, headers, now=setup.clock(), replay_ids=set())


@pytest.mark.asyncio
async def test_no_owner_callback_binding_fails_closed_before_network(setup):
    other = setup.open(callback_authorizer=None)
    with pytest.raises(EventError, match="Callback not authorized"):
        await other.subscribe(setup.principals["alpha"], setup.params())
    assert setup.receiver.calls == []


@pytest.mark.asyncio
@pytest.mark.parametrize("callback", [False, True, "awaitable"])
@pytest.mark.parametrize("boundary", ["authorizer", "callback_authorizer"])
async def test_authorization_hooks_must_synchronously_return_none_or_raise(callback, boundary, setup):
    async def not_an_authorization(*_):
        return None
    setattr(setup.hub, boundary, not_an_authorization if callback == "awaitable" else lambda *_: callback)
    with pytest.raises(EventError):
        await setup.hub.subscribe(setup.principals["alpha"], setup.params())
    assert setup.receiver.calls == []


@pytest.mark.asyncio
async def test_agent_cannot_redirect_events_to_other_agents_callback(setup):
    with pytest.raises(EventError, match="Callback not authorized"):
        await setup.hub.subscribe(setup.principals["alpha"], setup.params(callback="https://receiver.example/beta"))
    assert setup.receiver.calls == []
    await setup.hub.subscribe(setup.principals["beta"], setup.params(SCOPE_B, callback="https://receiver.example/beta"))
    assert setup.hub.status(setup.principals["beta"])["active_subscriptions"] == 1


@pytest.mark.asyncio
async def test_callback_binding_revocation_prevents_pending_delivery(setup):
    await setup.hub.subscribe(setup.principals["alpha"], setup.params())
    setup.enqueue()
    setup.callbacks["alpha"].clear()
    result = await setup.hub.deliver_due(setup.principals["alpha"])
    assert result["revoked"] == 1
    assert setup.receiver.events == []


@pytest.mark.asyncio
async def test_subscription_capacity_is_bounded_before_http(setup):
    setup.hub.callback_authorizer = lambda *_: None
    for i in range(32):
        await setup.hub.subscribe(setup.principals["alpha"], setup.params(callback=f"https://receiver.example/{i}"))
    calls = len(setup.receiver.calls)
    with pytest.raises(EventError, match="capacity"):
        await setup.hub.subscribe(setup.principals["alpha"], setup.params(callback="https://receiver.example/overflow"))
    assert len(setup.receiver.calls) == calls


@pytest.mark.asyncio
async def test_recovered_final_attempt_does_not_exceed_retry_limit(setup):
    await setup.hub.subscribe(setup.principals["alpha"], setup.params())
    setup.enqueue()
    setup.hub.db.execute("UPDATE evt_deliveries SET status='sending',attempts=5,lease_until=0")
    result = await setup.hub.deliver_due(setup.principals["alpha"])
    assert result["failed"] == 1
    assert setup.receiver.events == []


@pytest.mark.asyncio
@pytest.mark.parametrize("secret", [
    "plain-secret", "whsec_!!!", "whsec_" + base64.b64encode(b"x" * 23).decode(),
    "whsec_" + base64.b64encode(b"x" * 65).decode(),
])
async def test_invalid_secret_never_causes_callback(secret, setup):
    with pytest.raises(EventError):
        await setup.hub.subscribe(setup.principals["alpha"], setup.params(secret=secret))
    assert setup.receiver.calls == []


def test_signature_tampering_and_replay_are_rejected():
    body = b'{"eventId":"evt1","data":{"text":"fake"}}'
    headers = signed_headers(SECRET, "evt1", body, 1000, "sub_test")
    replay = set()
    verify_signature(SECRET, body, headers, now=1001, replay_ids=replay)
    with pytest.raises(EventError):
        verify_signature(SECRET, body, headers, now=1001, replay_ids=replay)
    with pytest.raises(EventError):
        verify_signature(SECRET, body + b" ", headers, now=1001, replay_ids=set())
    with pytest.raises(EventError):
        verify_signature(SECRET, body, headers, now=1400, replay_ids=set())
    with pytest.raises(EventError):
        verify_signature(SECRET, body, headers, now=600, replay_ids=set())
    with pytest.raises(EventError):
        verify_signature(SECRET2, body, headers, now=1001, replay_ids=set())


@pytest.mark.asyncio
async def test_unknown_webhook_outcome_retries_same_event_and_body_with_fresh_signature(setup):
    await setup.hub.subscribe(setup.principals["alpha"], setup.params())
    setup.enqueue()
    setup.receiver.statuses = [TimeoutError("may have been accepted"), 200]
    first = await setup.hub.deliver_due(setup.principals["alpha"])
    assert first["retried"] == 1
    assert (await setup.hub.deliver_due(setup.principals["alpha"]))["delivered"] == 0
    setup.clock.now += 3
    second = await setup.hub.deliver_due(setup.principals["alpha"])
    assert second["delivered"] == 1
    _, old_body, old_headers = setup.receiver.events[0]
    _, new_body, new_headers = setup.receiver.events[1]
    assert old_body == new_body
    assert old_headers["webhook-id"] == new_headers["webhook-id"]
    assert old_headers["webhook-signature"] != new_headers["webhook-signature"]
    assert old_headers["webhook-timestamp"] != new_headers["webhook-timestamp"]


@pytest.mark.asyncio
@pytest.mark.parametrize("status", [301, 302, 400, 401, 403, 410, 413])
async def test_permanent_http_failure_or_redirect_is_not_retried(status, setup):
    await setup.hub.subscribe(setup.principals["alpha"], setup.params())
    setup.enqueue()
    setup.receiver.statuses = [status]
    assert (await setup.hub.deliver_due(setup.principals["alpha"]))["failed"] == 1
    setup.clock.now += 500
    assert (await setup.hub.deliver_due(setup.principals["alpha"]))["delivered"] == 0
    assert len(setup.receiver.events) == 1


@pytest.mark.asyncio
async def test_transient_retries_have_bounded_attempts(setup):
    await setup.hub.subscribe(setup.principals["alpha"], setup.params())
    setup.enqueue()
    setup.receiver.statuses = [500] * 10
    for _ in range(5):
        await setup.hub.deliver_due(setup.principals["alpha"])
        setup.clock.now += 100
    assert len(setup.receiver.events) == 5
    assert setup.hub.status(setup.principals["alpha"])["deliveries"] == {"failed": 1}


@pytest.mark.asyncio
async def test_one_active_consumer_across_two_hubs(setup):
    await setup.hub.subscribe(setup.principals["alpha"], setup.params())
    setup.enqueue()
    setup.receiver.entered = asyncio.Event()
    setup.receiver.block = asyncio.Event()
    other = setup.open()
    first = asyncio.create_task(setup.hub.deliver_due(setup.principals["alpha"]))
    await asyncio.wait_for(setup.receiver.entered.wait(), timeout=1)
    try:
        # A paused worker still owns the OS lock after BOTH SQL lease deadlines.
        setup.clock.now += 60
        assert (await other.deliver_due(setup.principals["alpha"]))["busy"] == 1
    finally:
        setup.receiver.block.set()
    assert (await first)["delivered"] == 1
    assert len(setup.receiver.events) == 1


def test_delivery_process_lock_excludes_a_separate_process_and_releases(tmp_path):
    path = tmp_path / "consumer.lock"
    child = (
        "from pathlib import Path\n"
        "import sys\n"
        "from telegram_gateway.events import _DeliveryProcessLock\n"
        "with _DeliveryProcessLock(Path(sys.argv[1])) as acquired:\n"
        "    print('acquired' if acquired else 'busy')\n"
    )
    def probe():
        result = subprocess.run([sys.executable, "-c", child, str(path)], capture_output=True,
                                text=True, timeout=10, check=True)
        return result.stdout.strip()
    with _DeliveryProcessLock(path) as acquired:
        assert acquired is True
        assert probe() == "busy"
    assert probe() == "acquired"
    assert path.exists()


@pytest.mark.asyncio
async def test_unsubscribe_while_delivery_inflight_does_not_resurrect_pending(setup):
    await setup.hub.subscribe(setup.principals["alpha"], setup.params())
    setup.enqueue()
    setup.receiver.entered = asyncio.Event()
    setup.receiver.block = asyncio.Event()
    first = asyncio.create_task(setup.hub.deliver_due(setup.principals["alpha"]))
    await asyncio.wait_for(setup.receiver.entered.wait(), timeout=1)
    try:
        params = setup.params()
        del params["delivery"]["secret"]
        setup.hub.unsubscribe(setup.principals["alpha"], params)
    finally:
        setup.receiver.block.set()
    result = await first
    assert result["revoked"] == 1
    assert setup.hub.status(setup.principals["alpha"])["deliveries"] == {"revoked": 1}


@pytest.mark.asyncio
async def test_background_requires_trusted_principal_factory(setup):
    other = setup.open(principal_factory=None)
    with pytest.raises(EventError, match="principal resolver"):
        await other.deliver_due()


@pytest.mark.asyncio
async def test_missing_production_transport_fails_closed(setup):
    other = setup.open(sender=None)
    with pytest.raises(EventError, match="not configured"):
        await other.subscribe(setup.principals["alpha"], setup.params())
    assert setup.receiver.calls == []
    assert other.status(setup.principals["alpha"])["active_subscriptions"] == 0


@pytest.mark.asyncio
@pytest.mark.parametrize("data", [
    {"chat_id": -100002}, {"topic_id": 12}, {"message_id": True},
    {"text": "x" * 4001}, {"chain_depth": 9}, {"chain_depth": -1},
    {"content_is_untrusted": False}, {"agent_id": "beta"}, {"task_id": "../secret"},
])
async def test_event_scope_payload_and_chain_limits(data, setup):
    await setup.hub.subscribe(setup.principals["alpha"], setup.params())
    with pytest.raises(EventError):
        setup.enqueue(**data)
    assert setup.hub.status(setup.principals["alpha"])["deliveries"] == {}


@pytest.mark.asyncio
async def test_no_replay_cursor_claim_for_uncaptured_history(setup):
    with pytest.raises(EventError, match="historical replay"):
        await setup.hub.subscribe(setup.principals["alpha"], setup.params(cursor="old-event"))
    assert setup.receiver.calls == []


def test_paths_do_not_allow_project_state_or_combined_secret_state(tmp_path):
    project = Path(__file__).resolve().parents[1]
    with pytest.raises(EventError, match="outside"):
        EventHub(project / "must-not-create.sqlite", lambda *_: None)
    secrets = SQLiteSecretStore(tmp_path / "combined.sqlite")
    try:
        with pytest.raises(EventError, match="separate"):
            EventHub(tmp_path / "combined.sqlite", lambda *_: None, secret_store=secrets)
    finally:
        secrets.close()
