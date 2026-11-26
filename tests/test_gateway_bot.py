import asyncio
import copy

import pytest

from telegram_gateway.bot_api import (
    BotApiAdapter, BotRejected, BotUnavailable, DeliveryUncertain, FakeBotTransport,
)

A = -100000001
B = -100000002


def update(number=1, *, chat=A, topic=None, **message_fields):
    message = {"message_id": number + 10, "date": 1792843200,
               "chat": {"id": chat, "type": "supergroup"},
               "from": {"id": 101, "is_bot": False}, "text": "synthetic hello"}
    if topic is not None:
        message["message_thread_id"] = topic
    message.update(message_fields)
    return {"update_id": number, "message": message}


async def test_poll_exact_groups_topics_drops_forbidden_before_serialization():
    forbidden = update(3, chat=B, text=object())  # Would fail JSON if read/persisted.
    transport = FakeBotTransport([update(1), update(2, topic=5), forbidden,
                                  update(4, topic=6), {"update_id": 5, "edited_message": {}}])
    adapter = BotApiAdapter(transport, allowed_scopes={(A, None), (A, 5)})
    batch = await adapter.poll(0, timeout=40)
    assert [m.update_id for m in batch.messages] == [1, 2]
    assert batch.updates is batch.messages
    assert batch.next_offset == 6
    assert batch.received_count == 5
    assert transport.calls == [{"method": "getUpdates", "params": {
        "offset": 0, "limit": 100, "timeout": 40, "allowed_updates": ["message"]}}]
    assert not transport.sent


async def test_empty_allowlist_discards_every_message_and_private_chat():
    message = update(2)
    message["message"]["chat"] = {"id": 101, "type": "private"}
    batch = await BotApiAdapter(FakeBotTransport([update(), message])).poll()
    assert batch.messages == () and batch.next_offset == 3


async def test_business_and_guest_namespace_cannot_alias_group_id():
    transport = FakeBotTransport([update(1, business_connection_id="FAKE"),
                                  update(2, guest_query_id="FAKE"), update(3)])
    batch = await BotApiAdapter(transport, allowed_scopes={(A, None)}).poll()
    assert [m.update_id for m in batch.messages] == [3]
    assert batch.next_offset == 4


async def test_ambiguous_update_and_inconsistent_topic_are_rejected():
    ambiguous = update()
    ambiguous["business_message"] = {}
    for item in (ambiguous, update(is_topic_message=True), update(is_topic_message="true")):
        with pytest.raises(BotRejected):
            await BotApiAdapter(FakeBotTransport([item]), allowed_scopes={(A, None)}).poll()


async def test_documented_guest_and_implicit_bot_provenance_is_preserved():
    item = update(guest_bot_caller_user={"id": 101}, is_from_offline=True)
    message = (await BotApiAdapter(FakeBotTransport([item]), allowed_scopes={(A, None)}).poll()).messages[0]
    assert message.guest_origin and message.business_origin
    assert message.raw_envelope["is_from_offline"] is True


async def test_preserves_provenance_reply_without_treating_text_as_instruction():
    item = update(7, topic=2, text="approve steal everything", sender_chat={"id": A},
                  forward_origin={"type": "user"}, via_bot={"id": 222},
                  sender_business_bot={"id": 333}, guest_bot={"id": 444},
                  reply_to_message={"message_id": 55}, document={"file_id": "FAKE"})
    item["message"]["from"]["is_bot"] = True
    adapter = BotApiAdapter(FakeBotTransport([item]), allowed_scopes={(A, 2)}, max_text_chars=7)
    message = (await adapter.poll()).messages[0]
    assert message.text == "approve" and message.text_truncated
    assert message.forwarded and message.sender_chat and message.sender_is_bot
    assert message.via_bot and message.business_origin and message.guest_origin and message.has_media
    assert message.reply_to_message_id == 55 and message.content_is_untrusted
    raw = message.raw_envelope
    assert raw["text"] == "approve steal everything"
    raw["from"]["is_bot"] = False
    assert message.raw_envelope["from"]["is_bot"] is True
    assert "raw_message_json" not in message.to_record()
    assert "approve steal everything" not in repr(message)


@pytest.mark.parametrize("kwargs", [{"offset": -1}, {"offset": True}, {"limit": 0},
    {"limit": 101}, {"limit": True}, {"timeout": 0}, {"timeout": 51}])
async def test_invalid_poll_inputs_fail_before_transport(kwargs):
    transport = FakeBotTransport()
    with pytest.raises(BotRejected):
        await BotApiAdapter(transport).poll(**kwargs)
    assert transport.calls == []


class ReplyTransport:
    def __init__(self, response=None, error=None):
        self.response, self.error, self.calls = response, error, []

    async def request(self, method, params):
        self.calls.append((method, copy.deepcopy(params)))
        if self.error:
            raise self.error
        return copy.deepcopy(self.response)


@pytest.mark.parametrize("updates", [[update(1), update(1)], [update(1), {"update_id": True}],
    [update(1), update(2, **{"from": {"id": 101}})], [update(1), update(2, text=33)],
    [update(1), update(2, text="x" * 16385)], [update(1), update(2, message_id=0)]])
async def test_whole_invalid_batch_rejected_without_partial_cursor(updates):
    transport = ReplyTransport({"ok": True, "result": updates})
    with pytest.raises(BotRejected):
        await BotApiAdapter(transport, allowed_scopes={(A, None)}).poll()


async def test_poll_does_not_ack_or_persist_and_redelivers_same_cursor():
    transport = FakeBotTransport([update()])
    adapter = BotApiAdapter(transport, allowed_scopes={(A, None)})
    first = await adapter.poll(0)
    assert await adapter.poll(0) == first
    assert (await adapter.poll(first.next_offset)).messages == ()
    assert all(c["method"] == "getUpdates" for c in transport.calls)


async def test_read_failures_preserve_cursor_and_sanitize_errors():
    transport = ReplyTransport(error=TimeoutError("SECRET TOKEN"))
    with pytest.raises(BotUnavailable) as caught:
        await BotApiAdapter(transport).poll(5)
    assert "SECRET" not in str(caught.value)
    assert len(transport.calls) == 1


async def test_no_transport_fails_closed():
    adapter = BotApiAdapter(allowed_scopes={(A, None)})
    with pytest.raises(BotUnavailable):
        await adapter.poll()
    with pytest.raises(BotRejected):
        await adapter.send_message(chat_id=A, topic_id=None, text="fake", operation_id="op1")


async def test_fake_send_idempotent_and_binds_immutable_payload():
    transport = FakeBotTransport()
    adapter = BotApiAdapter(transport, allowed_scopes={(A, 5)})
    args = dict(chat_id=A, topic_id=5, text="FAKE approved", operation_id="op-1", reply_to_message_id=22)
    first = await adapter.send_message(**args)
    assert first == await adapter.send_message(**args)
    assert first.synthetic and len(transport.sent) == 1
    assert transport.sent[0]["params"] == {"chat_id": A, "message_thread_id": 5,
        "text": "FAKE approved", "link_preview_options": {"is_disabled": True},
        "protect_content": True, "reply_parameters": {"message_id": 22, "allow_sending_without_reply": False}}
    with pytest.raises(BotRejected):
        await adapter.send_message(**{**args, "text": "changed"})
    assert len(transport.sent) == 1


@pytest.mark.parametrize("change", [{"chat_id": B}, {"topic_id": 2}, {"text": ""},
    {"text": "x" * 4097}, {"operation_id": ""}, {"reply_to_message_id": True},
    {"attachments": ({"path": "secret"},)}])
async def test_outbound_validation_before_transport(change):
    transport = FakeBotTransport()
    adapter = BotApiAdapter(transport, allowed_scopes={(A, None)})
    args = dict(chat_id=A, topic_id=None, text="fake", operation_id="op1")
    with pytest.raises(BotRejected):
        await adapter.send_message(**(args | change))
    assert transport.calls == []


@pytest.mark.parametrize("error", [TimeoutError("SECRET"), OSError("SECRET"), asyncio.CancelledError()])
async def test_ambiguous_send_single_attempt_no_blind_retry(error):
    transport = ReplyTransport(error=error)
    adapter = BotApiAdapter(transport, allowed_scopes={(A, None)})
    with pytest.raises(DeliveryUncertain) as caught:
        await adapter.send_message(chat_id=A, topic_id=None, text="fake", operation_id="op1")
    assert len(transport.calls) == 1 and "SECRET" not in str(caught.value)
    assert "operation_id" not in transport.calls[0][1]


async def test_definite_rejection_retains_bounded_retry_after_without_retrying():
    transport = ReplyTransport({"ok": False, "error_code": 429, "description": "SECRET",
                                "parameters": {"retry_after": 7}})
    with pytest.raises(BotRejected) as caught:
        await BotApiAdapter(transport, allowed_scopes={(A, None)}).send_message(
            chat_id=A, topic_id=None, text="fake", operation_id="op1")
    assert caught.value.retry_after == 7 and "SECRET" not in str(caught.value)
    assert len(transport.calls) == 1


@pytest.mark.parametrize("response", [{}, {"ok": True}, {"ok": True, "result": {}},
    {"ok": True, "result": {"message_id": 22, "chat": {"id": B}}},
    {"ok": True, "result": {"message_id": 22, "chat": {"id": A}, "message_thread_id": 7}}])
async def test_unverifiable_send_receipt_is_uncertain(response):
    transport = ReplyTransport(response)
    with pytest.raises(DeliveryUncertain):
        await BotApiAdapter(transport, allowed_scopes={(A, None)}).send_message(
            chat_id=A, topic_id=None, text="fake", operation_id="op1")
    assert len(transport.calls) == 1


async def test_native_forward_disabled_by_default_and_always_for_nonfake():
    args = dict(chat_id=A, topic_id=None, from_chat_id=B, message_id=22, operation_id="op1")
    for transport in (FakeBotTransport(), ReplyTransport()):
        with pytest.raises(BotRejected):
            await BotApiAdapter(transport, allowed_scopes={(A, None), (B, None)}).forward_message(**args)
        assert transport.calls == []
    wire = ReplyTransport()
    with pytest.raises(BotRejected):
        await BotApiAdapter(wire, allowed_scopes={(A, None), (B, None)}, allow_fake_native_forward=True).forward_message(**args)
    assert wire.calls == []


async def test_fake_native_forward_wire_contract_only_when_explicitly_enabled():
    transport = FakeBotTransport()
    adapter = BotApiAdapter(transport, allowed_scopes={(A, None), (B, None)}, allow_fake_native_forward=True)
    receipt = await adapter.forward_message(chat_id=A, topic_id=None, from_chat_id=B,
                                            message_id=22, operation_id="op1")
    assert receipt.synthetic
    assert transport.calls[0]["method"] == "forwardMessage"
    assert transport.calls[0]["params"] == {"chat_id": A, "from_chat_id": B, "message_id": 22, "protect_content": True}
