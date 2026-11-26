"""Grok Routine adapter tests: synthetic callbacks/secrets; no network access."""
import asyncio
from dataclasses import FrozenInstanceError
import json
import threading
from types import SimpleNamespace

import pytest

from telegram_gateway.auth import PrincipalAuthority, VerifiedPrincipal
from telegram_gateway.events import CallbackTarget, WebhookResponse
from telegram_gateway.grok_routine import (
    GrokRoutineError, GrokRoutineSink, PinnedGrokRoutineSender, Route, bearer_headers,
)
from telegram_gateway.policy import Policy, Scope
from telegram_gateway.runtime_config import SecretRef

BOT = "fixture_alpha_bot"
URL = "https://routine.example/hooks/fixture?sample=synthetic"
KEY = "synthetic-routine-bearer-not-a-real-key"


class Receiver:
    def __init__(self):
        self.calls = []
        self.result = WebhookResponse(200)
        self.entered = None
        self.release = None

    async def __call__(self, target, body, headers):
        self.calls.append((target, body, headers.copy()))
        if self.entered:
            self.entered.set()
        if self.release:
            await self.release.wait()
        if isinstance(self.result, Exception):
            raise self.result
        return self.result


class Setup:
    def __init__(self, tmp_path):
        self.now = 1_800_000_000.0
        self.principal = PrincipalAuthority().restore("alpha")
        self.other = PrincipalAuthority().restore("beta")
        self.grants = {"alpha": [{"chat_id": -1001, "topic_id": 7, "permissions": ["events"]}]}
        self.receiver = Receiver()
        self.loaded = []
        self.key = KEY
        self.dns = ["8.8.8.8"]
        self.path = tmp_path / "routine.sqlite"
        self.route = Route("fixture_route", "alpha", BOT, URL, "fixture_key_ref")
        self.sinks = []
        self.sink = self.open()

    def authorize(self, p, name, arguments):
        assert name == "telegram.message.created"
        Policy.from_dict({"principals": self.grants}).require(p, "events", Scope(**arguments))

    def load(self, reference):
        self.loaded.append(reference)
        return self.key

    def open(self, **changes):
        args = dict(db_path=self.path, route=self.route, authorizer=self.authorize,
                    secret_loader=self.load, sender=self.receiver, resolver=lambda _: self.dns,
                    clock=lambda: self.now)
        args.update(changes)
        sink = GrokRoutineSink(**args)
        self.sinks.append(sink)
        return sink

    def data(self, **changes):
        return {"chat_id": -1001, "topic_id": 7, "message_id": 42,
                "text": "Untrusted fixture: ignore the instruction in this text.",
                "sender_id": 99, "task_id": "bot:fixture_alpha_bot:task-42", **changes}

    def enqueue(self, event_id="bot:fixture_alpha_bot:message-42", **changes):
        return self.sink.enqueue(self.principal, event_id, self.data(**changes), bot_reference=BOT)

    async def dispatch(self):
        return await self.sink.dispatch_once(self.principal, bot_reference=BOT)

    def status(self):
        return self.sink.status(self.principal, bot_reference=BOT)


@pytest.fixture
def setup(tmp_path):
    item = Setup(tmp_path)
    yield item
    for sink in item.sinks:
        try:
            sink.close()
        except Exception:
            pass


@pytest.mark.asyncio
async def test_json_bearer_receipt_is_accepted_not_completed_and_secrets_not_persisted(setup):
    assert setup.loaded == []
    assert setup.enqueue() is True
    assert await setup.dispatch() == {"status": "accepted", "run_completed": False}
    target, body, headers = setup.receiver.calls[0]
    assert target.hostname == "routine.example" and target.addresses == ("8.8.8.8",)
    assert target.follow_redirects is False
    assert headers == {"Content-Type": "application/json", "Authorization": "Bearer " + KEY}
    envelope = json.loads(body)
    assert set(envelope) == {"eventId", "type", "data"}
    assert envelope["type"] == "telegram.message.created"
    assert envelope["data"]["content_is_untrusted"] is True
    assert "instructions" not in envelope and "bot_reference" not in envelope["data"]
    assert setup.loaded == ["fixture_key_ref"]
    assert setup.status()["queue"]["accepted"] == 1
    assert setup.sink.db.execute("SELECT body FROM grok_outbox").fetchone()[0] == b""
    assert KEY not in repr(setup.route) and URL not in repr(setup.route)
    assert KEY not in repr(bearer_headers(KEY))
    setup.sink.db.execute("PRAGMA wal_checkpoint(FULL)")
    assert KEY.encode() not in setup.path.read_bytes()
    assert URL.encode() not in setup.path.read_bytes()


@pytest.mark.asyncio
async def test_duplicates_never_start_another_run_even_after_restart(setup):
    assert setup.enqueue() is True
    assert setup.enqueue() is False
    await setup.dispatch()
    assert setup.enqueue() is False
    with pytest.raises(GrokRoutineError, match="another payload"):
        setup.enqueue(text="changed")
    setup.sink.close()
    setup.sink = setup.open()
    assert setup.enqueue() is False
    assert (await setup.dispatch())["status"] == "idle"
    assert len(setup.receiver.calls) == 1


@pytest.mark.asyncio
@pytest.mark.parametrize("status,expected", [(201, "rejected"), (202, "rejected"), (204, "rejected"), (302, "rejected"), (400, "rejected"), (401, "rejected"), (429, "rejected"), (500, "unknown"), (503, "unknown")])
async def test_non200_is_terminal_and_never_retried(setup, status, expected):
    setup.receiver.result = WebhookResponse(status, b"private endpoint response")
    setup.enqueue()
    result = await setup.dispatch()
    assert result == {"status": expected, "run_completed": False}
    assert (await setup.dispatch())["status"] == "idle"
    assert len(setup.receiver.calls) == 1
    assert "private" not in json.dumps(result)


@pytest.mark.asyncio
@pytest.mark.parametrize("failure", [TimeoutError("secret"), ConnectionError(URL), RuntimeError(KEY)])
async def test_possible_send_failure_is_unknown_without_error_details_or_retry(setup, failure):
    setup.receiver.result = failure
    setup.enqueue()
    result = await setup.dispatch()
    assert result["status"] == "unknown"
    assert (await setup.dispatch())["status"] == "idle"
    assert KEY not in json.dumps(result) and URL not in json.dumps(result)
    assert len(setup.receiver.calls) == 1


@pytest.mark.asyncio
async def test_crash_after_durable_claim_recovers_as_unknown(setup):
    setup.enqueue()
    setup.sink.db.execute("UPDATE grok_outbox SET status='sending',claimed=?", (setup.now,))
    setup.sink.close()
    setup.sink = setup.open()
    assert setup.status()["queue"]["unknown"] == 1
    assert (await setup.dispatch())["status"] == "idle"
    assert setup.receiver.calls == setup.loaded == []


@pytest.mark.asyncio
async def test_cancel_after_io_claim_is_terminal_unknown(setup):
    setup.receiver.entered, setup.receiver.release = asyncio.Event(), asyncio.Event()
    setup.enqueue()
    task = asyncio.create_task(setup.dispatch())
    await asyncio.wait_for(setup.receiver.entered.wait(), timeout=1)
    with pytest.raises(GrokRoutineError, match="stop before closing"):
        setup.sink.close()
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert setup.status()["queue"]["unknown"] == 1
    assert (await setup.dispatch())["status"] == "idle"
    assert len(setup.receiver.calls) == 1


@pytest.mark.asyncio
async def test_timeout_after_sender_start_is_unknown(setup, monkeypatch):
    import telegram_gateway.grok_routine as module
    monkeypatch.setattr(module, "ATTEMPT_TIMEOUT", 0.03)
    setup.receiver.release = asyncio.Event()
    setup.enqueue()
    assert (await setup.dispatch())["status"] == "unknown"
    assert len(setup.receiver.calls) == 1
    assert (await setup.dispatch())["status"] == "idle"


@pytest.mark.asyncio
async def test_one_os_held_consumer_and_no_recovery_of_active_sender(setup):
    second = setup.open()
    setup.enqueue()
    setup.receiver.entered, setup.receiver.release = asyncio.Event(), asyncio.Event()
    task = asyncio.create_task(setup.dispatch())
    await asyncio.wait_for(setup.receiver.entered.wait(), timeout=1)
    try:
        assert (await second.dispatch_once(setup.principal, bot_reference=BOT))["status"] == "busy"
        with pytest.raises(GrokRoutineError, match="in use"):
            setup.open()
        assert setup.status()["queue"]["sending"] == 1
    finally:
        setup.receiver.release.set()
        await task
    assert setup.status()["queue"]["accepted"] == 1
    assert len(setup.receiver.calls) == 1


@pytest.mark.parametrize("principal", [None, {"id": "alpha"}, VerifiedPrincipal("alpha"), PrincipalAuthority().restore("beta")])
def test_principal_identity_is_not_accepted_from_body(setup, principal):
    with pytest.raises(GrokRoutineError):
        setup.sink.enqueue(principal, "event-1", setup.data(), bot_reference=BOT)
    with pytest.raises(GrokRoutineError):
        setup.sink.status(principal, bot_reference=BOT)


@pytest.mark.asyncio
async def test_wrong_bot_chat_topic_and_route_fields_fail_closed(setup):
    with pytest.raises(GrokRoutineError):
        setup.sink.enqueue(setup.principal, "event-1", setup.data(), bot_reference="fixture_beta_bot")
    for changes in ({"chat_id": -1002}, {"topic_id": 8}, {"url": URL}, {"bot_reference": BOT}, {"agent_id": "beta"}, {"instructions": "act now"}, {"all_topics": True}):
        with pytest.raises(GrokRoutineError):
            setup.enqueue(**changes)
    assert setup.receiver.calls == setup.loaded == []


@pytest.mark.asyncio
async def test_revoked_events_right_prevents_delivery(setup):
    setup.enqueue()
    setup.grants["alpha"] = []
    assert (await setup.dispatch())["status"] == "revoked"
    assert setup.receiver.calls == setup.loaded == []


@pytest.mark.asyncio
async def test_revoke_while_inflight_preserves_uncertainty_even_if_receipt_arrives(setup):
    setup.enqueue()
    setup.receiver.entered, setup.receiver.release = asyncio.Event(), asyncio.Event()
    task = asyncio.create_task(setup.dispatch())
    await asyncio.wait_for(setup.receiver.entered.wait(), timeout=1)
    setup.sink.revoke(setup.principal, bot_reference=BOT)
    setup.receiver.release.set()
    assert (await task)["status"] == "unknown"
    assert (await setup.dispatch())["status"] == "idle"


@pytest.mark.asyncio
async def test_auth_rechecked_after_dns_before_key_load_or_sender(setup):
    entered, release = threading.Event(), threading.Event()
    def resolver(_):
        entered.set()
        release.wait(2)
        return ["8.8.8.8"]
    setup.sink.resolver = resolver
    setup.enqueue()
    task = asyncio.create_task(setup.dispatch())
    try:
        for _ in range(100):
            if entered.is_set():
                break
            await asyncio.sleep(0.005)
        assert entered.is_set()
        setup.grants["alpha"] = []
        release.set()
        assert (await task)["status"] == "revoked"
        assert setup.receiver.calls == setup.loaded == []
    finally:
        release.set()
        if not task.done():
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)


@pytest.mark.asyncio
async def test_policy_change_during_secret_loader_also_prevents_send(setup):
    def load(_):
        setup.grants["alpha"] = []
        return KEY
    setup.sink.secret_loader = load
    setup.enqueue()
    assert (await setup.dispatch())["status"] == "revoked"
    assert setup.receiver.calls == []


@pytest.mark.asyncio
async def test_dns_timeout_cannot_start_late_http(setup, monkeypatch):
    import telegram_gateway.grok_routine as module
    monkeypatch.setattr(module, "ATTEMPT_TIMEOUT", 0.03)
    release, finished = threading.Event(), threading.Event()
    def resolver(_):
        release.wait(2)
        finished.set()
        return ["8.8.8.8"]
    setup.sink.resolver = resolver
    setup.enqueue()
    try:
        assert (await setup.dispatch())["status"] == "rejected"
        release.set()
        for _ in range(100):
            if finished.is_set():
                break
            await asyncio.sleep(0.005)
        assert finished.is_set()
        await asyncio.sleep(0.01)
        assert setup.receiver.calls == setup.loaded == []
    finally:
        release.set()


@pytest.mark.asyncio
@pytest.mark.parametrize("addresses", [["127.0.0.1"], ["10.0.0.1"], ["169.254.169.254"], ["::1"], ["::ffff:8.8.8.8"], ["8.8.8.8", "192.168.1.1"]])
async def test_ssrf_targets_are_rejected_without_credentials_or_http(setup, addresses):
    setup.dns = addresses
    setup.enqueue()
    assert (await setup.dispatch())["status"] == "rejected"
    assert setup.receiver.calls == setup.loaded == []


@pytest.mark.asyncio
async def test_dns_is_checked_again_for_each_new_event(setup):
    setup.enqueue("event-1")
    assert (await setup.dispatch())["status"] == "accepted"
    setup.dns = ["127.0.0.1"]
    setup.enqueue("event-2")
    assert (await setup.dispatch())["status"] == "rejected"
    assert len(setup.receiver.calls) == len(setup.loaded) == 1


@pytest.mark.asyncio
@pytest.mark.parametrize("key", ["", "bearer with spaces", "secret\r\nX-Host: bad", "\u0441\u0435\u043a\u0440\u0435\u0442", "x" * 4097, None])
async def test_bearer_validation_rejects_injection_before_sender(setup, key):
    setup.key = key
    setup.enqueue()
    assert (await setup.dispatch())["status"] == "rejected"
    assert setup.receiver.calls == []


def test_route_immutable_redacted_typed_reference_and_no_telegram_token_reference(setup):
    with pytest.raises(FrozenInstanceError):
        setup.route.url = "https://evil.example/"
    reference = SecretRef("env", "FAKE_GROK_ROUTINE_TOKEN")
    route = Route("other_route", "alpha", BOT, URL, reference)
    assert route.bearer_ref is reference and "FAKE_GROK" not in repr(route)
    with pytest.raises(GrokRoutineError):
        Route("wrong_route", "alpha", BOT, URL, SecretRef("local_bot", BOT))


@pytest.mark.parametrize("url", ["http://routine.example/hook", "https://user:pass@routine.example/hook", "https://routine.example:8443/hook", "https://localhost/hook", "https://routine.example/hook#fragment"])
def test_route_url_rejected_without_resolution_or_secret_access(setup, url):
    with pytest.raises(GrokRoutineError):
        Route("bad_route", "alpha", BOT, url)
    assert setup.loaded == setup.receiver.calls == []


def test_existing_route_cannot_retarget_queued_payload_to_different_receiver(setup):
    setup.enqueue()
    with pytest.raises(GrokRoutineError, match="another route"):
        setup.open(route=Route("fixture_route", "alpha", BOT, "https://another.example/hooks/fixture", "fixture_key_ref"))


@pytest.mark.asyncio
async def test_same_event_id_two_routes_have_separate_state_and_destinations(setup):
    other = setup.open(route=Route("other_route", "beta", "fixture_beta_bot", "https://routine.example/beta", "fixture_beta_ref"))
    setup.grants["beta"] = [{"chat_id": -1001, "topic_id": 7, "permissions": ["events"]}]
    setup.enqueue("same-event-id")
    assert other.enqueue(setup.other, "same-event-id", setup.data(text="beta-only"), bot_reference="fixture_beta_bot")
    assert (await setup.dispatch())["status"] == "accepted"
    assert other.status(setup.other, bot_reference="fixture_beta_bot")["queue"]["queued"] == 1
    assert (await other.dispatch_once(setup.other, bot_reference="fixture_beta_bot"))["status"] == "accepted"
    assert len(setup.receiver.calls) == 2
    assert setup.receiver.calls[0][0].url != setup.receiver.calls[1][0].url


@pytest.mark.parametrize("age", [0, 59, 3601, True, 60.0])
def test_max_age_limit_is_strict(setup, age):
    with pytest.raises(GrokRoutineError):
        setup.open(max_age_seconds=age)


@pytest.mark.asyncio
async def test_expiry_erases_body_and_duplicate_never_renews_it(setup):
    setup.sink.max_age_seconds = 60
    setup.enqueue()
    setup.now += 61
    assert (await setup.dispatch())["status"] == "expired"
    assert setup.enqueue() is False
    assert (await setup.dispatch())["status"] == "idle"
    assert setup.sink.db.execute("SELECT body FROM grok_outbox").fetchone()[0] == b""
    assert setup.loaded == setup.receiver.calls == []


def test_queue_limit_1000_and_payload_limits(setup):
    for index in range(1000):
        setup.enqueue("event-" + str(index))
    with pytest.raises(GrokRoutineError, match="capacity"):
        setup.enqueue("event-overflow")
    assert setup.status()["queue"]["queued"] == 1000
    with pytest.raises(GrokRoutineError):
        setup.enqueue("bad-text", text="x" * 4001)


@pytest.mark.asyncio
async def test_tampered_queued_payload_fails_closed(setup):
    setup.enqueue()
    body = json.loads(setup.sink.db.execute("SELECT body FROM grok_outbox").fetchone()[0])
    body["data"]["chat_id"] = -1002
    setup.sink.db.execute("UPDATE grok_outbox SET body=?", (json.dumps(body).encode(),))
    assert (await setup.dispatch())["status"] == "revoked"
    assert setup.loaded == setup.receiver.calls == []


@pytest.mark.parametrize("result", [False, True])
def test_authorizer_must_raise_or_return_none(setup, result):
    setup.sink.authorizer = lambda *_: result
    with pytest.raises(GrokRoutineError):
        setup.enqueue()


def test_async_authorizer_is_not_silently_accepted(setup):
    async def authority(*_):
        return None
    setup.sink.authorizer = authority
    with pytest.raises(GrokRoutineError):
        setup.enqueue()


@pytest.mark.asyncio
async def test_no_default_sender_or_implicit_activation(setup):
    setup.sink.sender = None
    setup.enqueue()
    assert (await setup.dispatch())["status"] == "unavailable"
    assert setup.status()["queue"]["queued"] == 1
    assert setup.loaded == []


@pytest.mark.asyncio
async def test_concrete_sender_uses_separate_bearer_contract_and_no_redirects(monkeypatch):
    sender = PinnedGrokRoutineSender()
    captured = []
    def exchange(target, body, headers, deadline):
        captured.append((target, body, headers))
        return WebhookResponse(302)
    monkeypatch.setattr(sender, "_exchange", exchange)
    monkeypatch.setenv("HTTPS_PROXY", "http://never-used.example:8080")
    target = CallbackTarget(URL, "routine.example", 443, ("8.8.8.8",))
    response = await sender(target, b'{}', bearer_headers(KEY))
    assert response.status == 302 and len(captured) == 1
    assert captured[0][2]["Host"] == "routine.example"
    assert captured[0][2]["Authorization"] == "Bearer " + KEY
    assert "Proxy-Authorization" not in captured[0][2]
    assert KEY not in repr(captured[0][2])


@pytest.mark.asyncio
@pytest.mark.parametrize("target", [
    CallbackTarget(URL, "routine.example", 443, ("127.0.0.1",)),
    CallbackTarget(URL, "wrong.example", 443, ("8.8.8.8",)),
    CallbackTarget(URL, "routine.example", 443, ("8.8.8.8",), True),
])
async def test_sender_rejects_forged_target_before_exchange(monkeypatch, target):
    sender = PinnedGrokRoutineSender()
    def forbidden(*_):
        raise AssertionError("HTTP must not start")
    monkeypatch.setattr(sender, "_exchange", forbidden)
    with pytest.raises(GrokRoutineError, match="HTTPS delivery failed"):
        await sender(target, b'{}', bearer_headers(KEY))


def test_sender_connection_uses_literal_ip_and_original_tls_hostname(monkeypatch):
    import telegram_gateway.network as network
    calls = []
    monkeypatch.setattr(network, "_PinnedHTTPSConnection", lambda *args, **kwargs: calls.append((args, kwargs)))
    sender = PinnedGrokRoutineSender()
    sender._connection(CallbackTarget(URL, "routine.example", 443, ("8.8.8.8", "1.1.1.1")), 123.0)
    assert calls[0][0] == ("routine.example", 443, "8.8.8.8")
    assert calls[0][1]["deadline"] == 123.0
