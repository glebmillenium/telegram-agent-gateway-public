"""Count-only polling diagnostics; all wire responses and credentials are synthetic."""
from dataclasses import FrozenInstanceError, asdict
import json
import socket

import pytest

from telegram_gateway.bot_api import (
    BotApiAdapter, BotRejected, BotUnavailable, DeliveryUncertain, FakeBotTransport, PollBatch,
)
from telegram_gateway.network import BotHTTPTransport


TOKEN = "123456:" + "PUBLIC_SYNTHETIC_FIXTURE_123456"
PRIVATE_MARKER = "SYNTHETIC_MUST_NOT_APPEAR"
CHAT = -100001
REASONS = ("non_message_update", "other_namespace", "non_group_chat", "outside_scope")


@pytest.fixture(autouse=True)
def no_real_network(monkeypatch):
    def denied(*args, **kwargs):
        raise AssertionError("Fake diagnostics tests must not access the network")
    monkeypatch.setattr(socket, "getaddrinfo", denied)
    monkeypatch.setattr(socket, "create_connection", denied)


class IntSubclass(int):
    pass


@pytest.mark.parametrize("code", [400, 409, 429, 599])
def test_rejection_accepts_only_safe_numeric_api_code(code):
    error = BotRejected(api_error_code=code, retry_after=120)
    assert error.api_error_code == code and error.retry_after == 120
    assert str(error) == "Bot API request rejected"


@pytest.mark.parametrize("code", [None, True, False, 399, 600, "409", 409.0, [],
                                 {"secret": PRIVATE_MARKER}, IntSubclass(409)])
def test_invalid_api_code_is_discarded_without_secret_echo(code):
    error = BotRejected(api_error_code=code)
    assert error.api_error_code is None
    assert PRIVATE_MARKER not in repr(error) + repr(vars(error))


def test_original_rejection_and_poll_batch_constructors_remain_compatible():
    error = BotRejected("Fixed local diagnostic", retry_after=7)
    assert str(error) == "Fixed local diagnostic" and error.api_error_code is None
    batch = PollBatch((), 10, 0)
    assert batch.updates == () and batch.next_offset == 10
    assert batch.discard_counts == tuple((reason, 0) for reason in REASONS)
    with pytest.raises(FrozenInstanceError):
        batch.discard_counts = ()


class RejectedTransport:
    def __init__(self, code, retry):
        self.error = BotRejected(PRIVATE_MARKER, api_error_code=code, retry_after=retry)

    async def request(self, method, params):
        raise self.error


@pytest.mark.asyncio
@pytest.mark.parametrize("code,retry,expected_retry", [(409, None, None), (429, 120, 120),
                                                      (429, True, None), (429, "120", None)])
async def test_poll_preserves_safe_code_and_retry_but_not_transport_description(code, retry, expected_retry):
    adapter = BotApiAdapter(RejectedTransport(code, retry), allowed_scopes={(CHAT, None)})
    with pytest.raises(BotRejected) as caught:
        await adapter.poll()
    assert caught.value.api_error_code == code
    assert caught.value.retry_after == expected_retry
    assert str(caught.value) == "Bot polling rejected; cursor unchanged"
    assert PRIVATE_MARKER not in repr(caught.value)
    assert caught.value.__suppress_context__ is True


@pytest.mark.asyncio
async def test_poll_revalidates_modified_error_code():
    transport = RejectedTransport(409, None)
    transport.error.api_error_code = PRIVATE_MARKER
    with pytest.raises(BotRejected) as caught:
        await BotApiAdapter(transport).poll()
    assert caught.value.api_error_code is None
    assert PRIVATE_MARKER not in repr(caught.value) + repr(vars(caught.value))


@pytest.mark.parametrize("code,expected", [(409, 409), (429, 429), (True, None),
                                         ("409", None), (599, 599), (600, None)])
@pytest.mark.parametrize("sending", [False, True])
def test_raw_api_rejection_keeps_only_safe_error_code(code, expected, sending):
    response = {"ok": False, "error_code": code, "description": PRIVATE_MARKER,
                "parameters": {"retry_after": 120}}
    with pytest.raises(BotRejected) as caught:
        BotApiAdapter._result(response, sending=sending)
    assert caught.value.api_error_code == expected and caught.value.retry_after == 120
    assert PRIVATE_MARKER not in repr(caught.value) + repr(vars(caught.value))


class FakeWire(BotHTTPTransport):
    def __init__(self, status, response):
        super().__init__(TOKEN)
        self.status, self.response, self.exchange_count = status, response, 0

    async def _resolve_target(self, deadline):
        return None  # The fake exchange does not dial, resolve, or inspect a target.

    def _exchange(self, target, path, body, deadline):
        self.exchange_count += 1
        return self.status, json.dumps(self.response).encode("utf-8")


@pytest.mark.asyncio
@pytest.mark.parametrize("status,body_code,expected", [
    (400, 409, 409), (429, 429, 429), (400, 599, 599),
    (429, None, 429), (429, True, 429), (429, "429", 429),
    (409, 600, 409), (400, PRIVATE_MARKER, 400), (200, None, None),
    (200, False, None), (200, 399, None), (200, 429, 429),
])
async def test_wire_rejection_code_priority_fallback_and_sanitization(status, body_code, expected):
    transport = FakeWire(status, {"ok": False, "error_code": body_code,
                                 "description": PRIVATE_MARKER,
                                 "parameters": {"retry_after": 120}})
    with pytest.raises(BotRejected) as caught:
        await BotApiAdapter(transport).poll()
    assert caught.value.api_error_code == expected and caught.value.retry_after == 120
    assert PRIVATE_MARKER not in repr(caught.value) + repr(vars(caught.value))
    assert TOKEN not in repr(caught.value) + repr(transport)
    assert transport.exchange_count == 1


@pytest.mark.asyncio
async def test_wire_missing_error_code_falls_back_to_http_status():
    transport = FakeWire(409, {"ok": False, "description": PRIVATE_MARKER})
    with pytest.raises(BotRejected) as caught:
        await transport.request("getUpdates", {"offset": 0, "limit": 100, "timeout": 1,
                                                "allowed_updates": ["message"]})
    assert caught.value.api_error_code == 409 and caught.value.retry_after is None
    assert transport.exchange_count == 1


@pytest.mark.asyncio
@pytest.mark.parametrize("retry", [True, "120", 0, 86401, {"secret": PRIVATE_MARKER}])
async def test_wire_invalid_retry_after_is_not_retained(retry):
    transport = FakeWire(429, {"ok": False, "error_code": 429,
                              "parameters": {"retry_after": retry}, "description": PRIVATE_MARKER})
    with pytest.raises(BotRejected) as caught:
        await BotApiAdapter(transport).poll()
    assert caught.value.retry_after is None and caught.value.api_error_code == 429
    assert PRIVATE_MARKER not in repr(caught.value) + repr(vars(caught.value))


@pytest.mark.asyncio
@pytest.mark.parametrize("sending", [False, True])
async def test_http_500_keeps_existing_read_unavailable_send_uncertain_classification(sending):
    transport = FakeWire(500, {"ok": False, "error_code": 500, "description": PRIVATE_MARKER})
    method = "sendMessage" if sending else "getMe"
    params = {"chat_id": CHAT, "text": "Synthetic approved text", "protect_content": True,
              "link_preview_options": {"is_disabled": True}} if sending else {}
    with pytest.raises(DeliveryUncertain if sending else BotUnavailable) as caught:
        await transport.request(method, params)
    assert PRIVATE_MARKER not in repr(caught.value) and transport.exchange_count == 1


def message(update_id, *, chat=CHAT, topic=None, text="Synthetic permitted message"):
    body = {"message_id": update_id + 10, "date": 1700000000,
            "chat": {"id": chat, "type": "supergroup"}, "text": text}
    if topic is not None:
        body["message_thread_id"] = topic
    return {"update_id": update_id, "message": body}


@pytest.mark.asyncio
async def test_fixed_discard_counts_cover_all_branches_without_foreign_content():
    updates = [
        {"update_id": 1, "edited_message": {"text": PRIVATE_MARKER}},
        {"update_id": 2, "message": {"business_connection_id": PRIVATE_MARKER, "chat": None}},
        {"update_id": 3, "message": {"guest_query_id": PRIVATE_MARKER, "chat": None}},
        {"update_id": 4, "message": {"chat": {"id": 123, "type": "private"}, "text": PRIVATE_MARKER}},
        {"update_id": 5, "message": {"chat": {"id": -999, "type": "channel"}, "text": PRIVATE_MARKER}},
        message(6, chat=-100002, text={"never_serialize": PRIVATE_MARKER}),
        message(7, topic=123, text={"never_serialize": PRIVATE_MARKER}),
        message(8),
    ]
    batch = await BotApiAdapter(FakeBotTransport(updates), allowed_scopes={(CHAT, None)}).poll()
    assert batch.discard_counts == (("non_message_update", 1), ("other_namespace", 2),
                                    ("non_group_chat", 2), ("outside_scope", 2))
    assert batch.next_offset == 9 and batch.received_count == 8 and len(batch.messages) == 1
    assert sum(dict(batch.discard_counts).values()) + len(batch.messages) == batch.received_count
    assert PRIVATE_MARKER not in repr(batch) + json.dumps(asdict(batch))


@pytest.mark.asyncio
async def test_discarded_content_is_not_serialized_and_scope_policy_is_unchanged(monkeypatch):
    def forbidden(value):
        raise AssertionError("Discarded message content was serialized")
    monkeypatch.setattr("telegram_gateway.bot_api._json_snapshot", forbidden)
    updates = [message(2, chat=-100002, text=object()), message(5, topic=7, text=object())]
    batch = await BotApiAdapter(FakeBotTransport(updates), allowed_scopes={(CHAT, None)}).poll()
    assert batch.messages == () and dict(batch.discard_counts)["outside_scope"] == 2
    assert batch.next_offset == 6 and batch.received_count == 2


@pytest.mark.asyncio
async def test_all_topics_grant_still_accepts_exact_group_and_only_counts_foreign_group():
    updates = [message(1), message(2, topic=7), message(3, chat=-100002, topic=7)]
    batch = await BotApiAdapter(FakeBotTransport(updates), allowed_all_topic_chats={CHAT}).poll()
    assert len(batch.messages) == 2 and dict(batch.discard_counts)["outside_scope"] == 1
    assert sum(dict(batch.discard_counts).values()) == 1


@pytest.mark.asyncio
async def test_empty_batch_has_all_zero_counts_and_unchanged_offset():
    batch = await BotApiAdapter(FakeBotTransport()).poll(offset=9)
    assert batch == PollBatch((), 9, 0)


@pytest.mark.asyncio
@pytest.mark.parametrize("updates", [
    [{"update_id": True}], [{"update_id": 1}, {"update_id": 1}],
    [dict(message(1), edited_message={"text": PRIVATE_MARKER})],
])
async def test_malformed_or_ambiguous_update_remains_rejected_not_counted(updates):
    with pytest.raises(BotRejected):
        await BotApiAdapter(FakeBotTransport(updates), allowed_scopes={(CHAT, None)}).poll()
