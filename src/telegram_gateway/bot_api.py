"""Bounded Bot API wire adapter; no network, token loader, or user session.

Only an explicitly injected transport can make requests. getUpdates is Telegram
long polling, not a chat-scoped Telegram endpoint; unwanted scopes are discarded
before returning data. The caller persists a batch and its cursor atomically and
owns the single-consumer lease. Telegram retains updates for at most 24 hours.
History is the gateway's captured history, never a fabricated Bot API method.
"""
from __future__ import annotations

import asyncio
import copy
import json
import re
from dataclasses import asdict, dataclass, field
from typing import Any, Mapping, Protocol

MAX_ID = 2**52 - 1
MAX_UPDATE_ID = 2**63 - 2
MAX_ENVELOPE_BYTES = 128 * 1024
_OPERATION = re.compile(r"[A-Za-z0-9_.:-]{1,128}\Z")


class BotRejected(RuntimeError):
    """Definite validation/API rejection; no successful send is being claimed."""

    def __init__(self, message: str = "Bot API request rejected", *, retry_after: int | None = None,
                 api_error_code: int | None = None):
        super().__init__(message)
        self.retry_after = retry_after
        self.api_error_code = api_error_code if type(api_error_code) is int and 400 <= api_error_code <= 599 else None


class BotUnavailable(RuntimeError):
    """A read failed; the durable cursor must remain unchanged."""


class DeliveryUncertain(RuntimeError):
    """A send might have happened. Never blindly retry it."""


class BotTransport(Protocol):
    async def request(self, method: str, params: Mapping[str, Any]) -> Mapping[str, Any]: ...


def _integer(value: Any, low: int, high: int, label: str) -> int:
    if type(value) is not int or not low <= value <= high:
        raise BotRejected(f"Invalid {label}")
    return value


def _scope(chat_id: Any, topic_id: Any) -> tuple[int, int | None]:
    # This adapter is intentionally for group/supergroup IDs, not private peers.
    _integer(chat_id, -MAX_ID, -1, "group ID")
    if topic_id is not None:
        _integer(topic_id, 1, 2**31 - 1, "topic ID")
    return chat_id, topic_id


def _object(value: Any, label: str) -> dict:
    if type(value) is not dict:
        raise BotRejected(f"Invalid {label}")
    return value


def _json_snapshot(value: dict) -> str:
    try:
        result = json.dumps(value, ensure_ascii=False, separators=(",", ":"), allow_nan=False)
        if len(result.encode("utf-8")) > MAX_ENVELOPE_BYTES:
            raise ValueError
        return result
    except (TypeError, ValueError, UnicodeError, RecursionError):
        raise BotRejected("Invalid or oversized Telegram message") from None


@dataclass(frozen=True)
class InboundMessage:
    update_id: int
    chat_id: int
    topic_id: int | None
    message_id: int
    date: int
    text: str
    sender_id: int | None
    sender_is_bot: bool
    reply_to_message_id: int | None
    forwarded: bool
    sender_chat: bool
    via_bot: bool
    business_origin: bool
    guest_origin: bool
    text_truncated: bool
    has_media: bool
    raw_message_json: str = field(repr=False, compare=False)
    content_is_untrusted: bool = True

    @property
    def raw_envelope(self) -> dict:
        """Fresh copy from the trusted transport, only for the owner verifier.

        The original envelope preserves every provenance field. Never expose it
        to an agent tool or treat text/quoted instructions as owner authority.
        """
        return json.loads(self.raw_message_json)

    def to_record(self) -> dict:
        record = asdict(self)
        del record["raw_message_json"]
        return record


@dataclass(frozen=True)
class PollBatch:
    messages: tuple[InboundMessage, ...]
    next_offset: int
    received_count: int
    discard_counts: tuple[tuple[str, int], ...] = (
        ("non_message_update", 0), ("other_namespace", 0),
        ("non_group_chat", 0), ("outside_scope", 0),
    )

    @property
    def updates(self) -> tuple[InboundMessage, ...]:
        return self.messages


@dataclass(frozen=True)
class SendReceipt:
    message_id: int
    chat_id: int
    topic_id: int | None
    operation_id: str
    synthetic: bool


class BotApiAdapter:
    """Wire-level adapter. Service authorization MUST run before outbound calls.

    allowed_scopes is a second boundary, using exact (chat_id, topic_id) pairs.
    None means the unthreaded scope, not every topic. The separate explicit
    allowed_all_topic_chats set includes current/future topics and unthreaded
    messages in those exact groups. Every outbound call still has one concrete
    destination. No login, webhook management, or arbitrary-method API.
    """

    def __init__(self, transport: BotTransport | None = None, *,
                 allowed_scopes: set[tuple[int, int | None]] | frozenset[tuple[int, int | None]] = frozenset(),
                 max_text_chars: int = 4000, allow_fake_native_forward: bool = False,
                 allowed_all_topic_chats: set[int] | frozenset[int] = frozenset()):
        _integer(max_text_chars, 1, 4096, "text limit")
        self.allowed_scopes = frozenset(_scope(*scope) for scope in allowed_scopes)
        if type(allowed_all_topic_chats) not in (set, frozenset):
            raise BotRejected("Explicit all-topic group set required")
        self.allowed_all_topic_chats = frozenset(_scope(chat, None)[0] for chat in allowed_all_topic_chats)
        self.transport = transport
        self.max_text_chars = max_text_chars
        self.allow_fake_native_forward = allow_fake_native_forward

    def _require_scope(self, chat_id: int, topic_id: int | None) -> None:
        scope = _scope(chat_id, topic_id)
        if scope not in self.allowed_scopes and scope[0] not in self.allowed_all_topic_chats:
            raise BotRejected("Group/topic is not allowlisted")

    async def poll(self, offset: int = 0, *, limit: int = 100, timeout: int = 25) -> PollBatch:
        _integer(offset, 0, MAX_UPDATE_ID + 1, "update offset")
        _integer(limit, 1, 100, "poll limit")
        _integer(timeout, 1, 50, "long-poll timeout")
        if self.transport is None:
            raise BotUnavailable("Bot transport is not configured")
        try:
            response = await self.transport.request("getUpdates", {
                "offset": offset, "limit": limit, "timeout": timeout,
                "allowed_updates": ["message"],
            })
        except asyncio.CancelledError:
            raise
        except BotRejected as error:
            retry_after = error.retry_after
            if type(retry_after) is not int or not 1 <= retry_after <= 86400:
                retry_after = None
            raise BotRejected("Bot polling rejected; cursor unchanged", retry_after=retry_after,
                              api_error_code=error.api_error_code) from None
        except Exception:
            raise BotUnavailable("Bot polling unavailable; cursor unchanged") from None
        result = self._result(response, sending=False)
        if type(result) is not list or len(result) > limit:
            raise BotRejected("Invalid Telegram update batch")
        messages = []
        discarded = {reason: 0 for reason, _ in PollBatch.discard_counts}
        next_offset = offset
        seen = set()
        for update in result:
            update = _object(update, "Telegram update")
            update_id = _integer(update.get("update_id"), 0, MAX_UPDATE_ID, "update ID")
            if update_id < offset or update_id in seen:
                raise BotRejected("Unexpected or duplicate update ID")
            seen.add(update_id)
            next_offset = max(next_offset, update_id + 1)
            # Previous bot subscriptions can briefly yield other update types.
            # Those are acknowledged only after the caller persists this batch.
            if "message" not in update:
                discarded["non_message_update"] += 1
                continue
            if set(update) != {"update_id", "message"}:
                raise BotRejected("Ambiguous Telegram update envelope")
            message = _object(update["message"], "Telegram message")
            # Telegram documents these as independent chat namespaces even
            # when their numeric chat IDs collide with ordinary bot chats.
            if "business_connection_id" in message or "guest_query_id" in message:
                discarded["other_namespace"] += 1
                continue
            chat = _object(message.get("chat"), "Telegram chat")
            chat_id, topic_id = chat.get("id"), message.get("message_thread_id")
            if chat.get("type") not in {"group", "supergroup"}:
                discarded["non_group_chat"] += 1
                continue
            scope = _scope(chat_id, topic_id)
            if scope not in self.allowed_scopes and scope[0] not in self.allowed_all_topic_chats:
                discarded["outside_scope"] += 1
                continue  # Do not serialize, retain, or return forbidden text.
            if "is_topic_message" in message and (
                    type(message["is_topic_message"]) is not bool
                    or (message["is_topic_message"] and topic_id is None)):
                raise BotRejected("Inconsistent topic identity")
            snapshot = _json_snapshot(message)
            message_id = _integer(message.get("message_id"), 1, 2**31 - 1, "message ID")
            date = _integer(message.get("date"), 1, MAX_UPDATE_ID, "message date")
            text = message.get("text", message.get("caption", ""))
            if type(text) is not str or len(text) > 16384:
                raise BotRejected("Invalid Telegram message text")
            sender = message.get("from")
            sender_id, sender_is_bot = None, True  # Missing sender never approves.
            if sender is not None:
                sender = _object(sender, "Telegram sender")
                sender_id = _integer(sender.get("id"), 1, MAX_ID, "sender ID")
                if type(sender.get("is_bot")) is not bool:
                    raise BotRejected("Invalid sender identity")
                sender_is_bot = sender["is_bot"]
            reply_id = None
            if "reply_to_message" in message:
                reply = _object(message["reply_to_message"], "reply reference")
                reply_id = _integer(reply.get("message_id"), 1, 2**31 - 1, "reply ID")
            forwarded = any(k in message for k in (
                "forward_origin", "forward_from", "forward_from_chat", "forward_sender_name",
                "forward_date", "forward_signature", "forward_from_message_id", "is_automatic_forward"))
            messages.append(InboundMessage(
                update_id, chat_id, topic_id, message_id, date, text[:self.max_text_chars],
                sender_id, sender_is_bot, reply_id, forwarded,
                "sender_chat" in message, "via_bot" in message,
                any(k in message for k in ("business_connection_id", "sender_business_bot", "via_business_bot", "is_from_offline")),
                any(k in message for k in ("guest_query_id", "guest_bot_caller_user", "guest_bot_caller_chat", "guest_bot", "sender_guest_bot", "via_guest_bot")),
                len(text) > self.max_text_chars,
                any(k in message for k in ("photo", "document", "video", "audio", "voice", "animation", "sticker", "video_note", "paid_media", "rich_message")),
                snapshot,
            ))
        # No cursor persistence occurs here. Caller commits messages/dedup/cursor
        # in one transaction under its fenced single-consumer lease.
        return PollBatch(tuple(messages), next_offset, len(result), tuple(discarded.items()))

    @staticmethod
    def _result(response: Any, *, sending: bool) -> Any:
        if type(response) is not dict or type(response.get("ok")) is not bool:
            error = DeliveryUncertain if sending else BotRejected
            raise error("Invalid Bot API response")
        if response["ok"] is False:
            retry = response.get("parameters", {})
            retry_after = retry.get("retry_after") if type(retry) is dict else None
            if type(retry_after) is not int or not 1 <= retry_after <= 86400:
                retry_after = None
            raise BotRejected("Bot API explicitly rejected request", retry_after=retry_after,
                              api_error_code=response.get("error_code"))
        if "result" not in response:
            error = DeliveryUncertain if sending else BotRejected
            raise error("Incomplete Bot API response")
        return response["result"]

    async def send_message(self, *, chat_id: int, topic_id: int | None, text: str,
                           operation_id: str, reply_to_message_id: int | None = None,
                           attachments: tuple = ()) -> SendReceipt:
        self._require_scope(chat_id, topic_id)
        if type(text) is not str or not text or len(text) > 4096:
            raise BotRejected("Invalid outbound text")
        if type(attachments) not in (tuple, list) or attachments:
            raise BotRejected("Attachment sending is not implemented")
        params: dict[str, Any] = {"chat_id": chat_id, "text": text,
                                 "link_preview_options": {"is_disabled": True}, "protect_content": True}
        if topic_id is not None:
            params["message_thread_id"] = topic_id
        if reply_to_message_id is not None:
            _integer(reply_to_message_id, 1, 2**31 - 1, "reply ID")
            params["reply_parameters"] = {"message_id": reply_to_message_id,
                                          "allow_sending_without_reply": False}
        return await self._send("sendMessage", params, operation_id, chat_id, topic_id)

    async def forward_message(self, *, chat_id: int, topic_id: int | None,
                              from_chat_id: int, message_id: int,
                              operation_id: str) -> SendReceipt:
        # Telegram source messages can change after approval. Production MVP
        # forwards only an approved immutable snapshot via send_message.
        if not self.allow_fake_native_forward or not isinstance(self.transport, FakeBotTransport):
            raise BotRejected("Native forwarding is disabled; use an approved immutable snapshot")
        self._require_scope(chat_id, topic_id)
        _scope(from_chat_id, None)
        if not any(scope[0] == from_chat_id for scope in self.allowed_scopes):
            raise BotRejected("Forward source is not allowlisted")
        _integer(message_id, 1, 2**31 - 1, "source message ID")
        params = {"chat_id": chat_id, "from_chat_id": from_chat_id, "message_id": message_id,
                  "protect_content": True}
        if topic_id is not None:
            params["message_thread_id"] = topic_id
        return await self._send("forwardMessage", params, operation_id, chat_id, topic_id)

    async def _send(self, method: str, params: dict, operation_id: str,
                    chat_id: int, topic_id: int | None) -> SendReceipt:
        if type(operation_id) is not str or not _OPERATION.fullmatch(operation_id):
            raise BotRejected("Invalid operation ID")
        if self.transport is None:
            raise BotRejected("Bot transport is not configured")
        try:
            if isinstance(self.transport, FakeBotTransport):
                response = await self.transport.execute_once(method, params, operation_id)
            else:
                # Bot API has no idempotency-key parameter. Do not invent one.
                response = await self.transport.request(method, params)
        except BotRejected:
            raise
        except (Exception, asyncio.CancelledError):
            raise DeliveryUncertain("Send outcome is unknown; do not retry automatically") from None
        result = self._result(response, sending=True)
        try:
            result = _object(result, "sent message")
            message_id = _integer(result.get("message_id"), 1, 2**31 - 1, "sent message ID")
            returned_chat = _object(result.get("chat"), "sent chat")
            returned_scope = _scope(returned_chat.get("id"), result.get("message_thread_id"))
            if returned_scope != (chat_id, topic_id):
                raise BotRejected("Unexpected destination")
        except BotRejected:
            raise DeliveryUncertain("Send receipt could not be verified; do not retry automatically") from None
        return SendReceipt(message_id, chat_id, topic_id, operation_id, isinstance(self.transport, FakeBotTransport))


class FakeBotTransport:
    """In-memory synthetic transport. This class never accesses the network.

    Fake-only operation IDs model idempotency for tests. Real Bot API has no
    such guarantee; production outbox state must handle ambiguous sends.
    """
    def __init__(self, updates: list[dict] | tuple[dict, ...] = ()):
        self.updates = copy.deepcopy(list(updates))
        self.calls: list[dict] = []
        self.sent: list[dict] = []
        self._results: dict[str, tuple[str, str, dict]] = {}
        self._lock = asyncio.Lock()

    async def request(self, method: str, params: Mapping[str, Any]) -> dict:
        if method not in {"getUpdates", "sendMessage", "forwardMessage"}:
            raise BotRejected("Unknown fake Bot API method")
        params = copy.deepcopy(dict(params))
        self.calls.append({"method": method, "params": params})
        if method == "getUpdates":
            updates = [u for u in self.updates if u.get("update_id", -1) >= params["offset"]]
            return {"ok": True, "result": copy.deepcopy(updates[:params["limit"]])}
        message = {"message_id": 1000 + len(self.sent), "chat": {"id": params["chat_id"], "type": "supergroup"}}
        if "message_thread_id" in params:
            message["message_thread_id"] = params["message_thread_id"]
        if method == "sendMessage":
            message["text"] = params["text"]
        self.sent.append({"method": method, "params": params, "message": copy.deepcopy(message)})
        return {"ok": True, "result": message}

    async def execute_once(self, method: str, params: dict, operation_id: str) -> dict:
        canonical = json.dumps(params, sort_keys=True, separators=(",", ":"), allow_nan=False)
        async with self._lock:
            if operation_id in self._results:
                old_method, old_params, result = self._results[operation_id]
                if (old_method, old_params) != (method, canonical):
                    raise BotRejected("Fake operation ID reused with changed payload")
                return copy.deepcopy(result)
            result = await self.request(method, params)
            self._results[operation_id] = (method, canonical, copy.deepcopy(result))
            return result
