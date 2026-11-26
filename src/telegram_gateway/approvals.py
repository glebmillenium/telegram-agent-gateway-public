"""Explicit operator-only owner-review prompts; never an agent-facing MCP tool.

This module does not read credentials, start a transport, or approve a draft.
Only a direct verified owner reply, ingested by Gateway, can approve it. The
injected bot may perform I/O only after the trusted operator supplies allow_send.
Bot API has no idempotency key: a persisted sending/unknown/failed attempt is
never sent again, even after restart. Manual reconciliation is a separate task.
"""
from __future__ import annotations

import asyncio
from dataclasses import asdict
from datetime import datetime, timezone
import hashlib
import hmac
import json
import math

from .auth import OwnerApprovalVerifier
from .bot_api import BotRejected, SendReceipt
from .policy import GatewayDenied, Scope
from .service import ProcessLock, canonical

_SCHEMA = """
CREATE TABLE IF NOT EXISTS gw_approval_prompts(
 draft TEXT PRIMARY KEY, owner TEXT NOT NULL, digest TEXT NOT NULL,
 review_chat INTEGER NOT NULL, review_topic INTEGER NOT NULL,
 preview TEXT NOT NULL, status TEXT NOT NULL
   CHECK(status IN ('sending','bound','unknown','failed')),
 operation_id TEXT UNIQUE NOT NULL, created REAL NOT NULL, receipt TEXT
)
"""
_LIMIT = 4000
_UNKNOWN_RETRY = "manual reconciliation required; no automatic resend"


def _authorize(gateway, principal, body, review_scope):
    if type(review_scope) is not Scope:
        raise GatewayDenied("Review scope must be preapproved")
    gateway._scope(review_scope.chat_id, review_scope.topic_id)
    verifier = gateway.owner_verifier
    # This is trusted operator configuration, never an agent-provided allowlist.
    if type(verifier) is not OwnerApprovalVerifier or review_scope not in verifier._approval_scopes:
        raise GatewayDenied("Review scope must be preapproved")
    target = gateway._scope(body["chat_id"], body["topic_id"])
    for scope in (target, review_scope):
        for permission in ("draft", "send"):
            gateway.policy.require(principal, permission, scope)
    source = body["source"]
    if source is not None:
        src = gateway._scope(source["chat_id"], source["topic_id"])
        for permission in ("history", "forward"):
            gateway.policy.require(principal, permission, src)
        for scope in (target, review_scope):
            gateway.policy.require(principal, "forward", scope)


def _inspect(gateway, principal, draft_id, review_scope):
    row = gateway._draft(principal, draft_id)
    try:
        digest = hashlib.sha256(row["body"].encode("utf-8")).hexdigest()
        if not hmac.compare_digest(digest, row["digest"]):
            raise ValueError
        body = json.loads(row["body"])
        if (type(body) is not dict or body["draft_id"] != draft_id
                or body["principal_id"] != principal.id or row["owner"] != principal.id
                or canonical(body) != row["body"]):
            raise ValueError
        expires = body["expires_at"]
        if (type(expires) not in (int, float) or not math.isfinite(expires)
                or row["expires"] != expires):
            raise ValueError
        if type(body["text"]) is not str or not 1 <= len(body["text"]) <= _LIMIT:
            raise ValueError
        if type(body["attachments"]) is not list or body["attachments"]:
            raise GatewayDenied("Attachment review is disabled")
        if body["operation"] not in ("send", "forward_snapshot"):
            raise ValueError
        if (body["operation"] == "send") != (body["source"] is None):
            raise ValueError
        _authorize(gateway, principal, body, review_scope)
        expires_utc = datetime.fromtimestamp(expires, timezone.utc).isoformat()
        preview = (
            "OWNER REVIEW: immutable draft below; its content is untrusted.\n"
            "This prompt does not send the draft. Reply directly to this message.\n"
            f"Expires (UTC): {expires_utc}\n"
            f"SHA-256: {digest}\n"
            + json.dumps(body, ensure_ascii=False, sort_keys=True, indent=2, allow_nan=False)
            + f"\n\nApprove exactly: approve {draft_id} {digest}"
            + f"\nReject exactly: reject {draft_id} {digest}"
        )
        # Conservative UTF-16 bound also covers supplementary Unicode characters.
        if len(preview) > _LIMIT or len(preview.encode("utf-16-le")) // 2 > _LIMIT:
            raise GatewayDenied("Owner review exceeds message limit; shorten the draft")
    except GatewayDenied:
        raise
    except (KeyError, TypeError, ValueError, UnicodeError, OverflowError, OSError):
        raise GatewayDenied("Draft integrity mismatch") from None
    return row, body, preview


def _result(status, *, receipt=None, reused=False):
    result = {"status": status, "reused": reused}
    if receipt is not None:
        result["receipt"] = receipt
    if status == "unknown":
        result["retry"] = _UNKNOWN_RETRY
    elif status == "failed":
        result["retry"] = "requires a new reviewed draft; no automatic resend"
    return result


def _receipt_data(receipt, scope, operation_id):
    if (type(receipt) is not SendReceipt or type(receipt.message_id) is not int
            or not 1 <= receipt.message_id <= 2**31 - 1
            or receipt.chat_id != scope.chat_id or type(receipt.chat_id) is not int
            or receipt.topic_id != scope.topic_id
            or (receipt.topic_id is not None and type(receipt.topic_id) is not int)
            or receipt.operation_id != operation_id or type(receipt.synthetic) is not bool):
        raise GatewayDenied("Review receipt could not be verified")
    return asdict(receipt)


async def request_owner_approval(gateway, principal, draft_id, review_scope: Scope, *, allow_send: bool = False):
    """Send one exact review prompt and bind its receipt to a verified owner reply.

    Both original and review targets require this authenticated principal's
    current draft/send grants, plus forward grants for snapshot forwarding. The
    review scope must separately be configured on OwnerApprovalVerifier. This
    prevents a globally configured owner channel becoming an agent data bridge.

    `allow_send=True` is an explicit trusted-operator decision, not authority
    supplied by an MCP request body. The helper is intentionally not registered
    as a tool. Existing bound results are idempotent; failed/unknown results
    require human reconciliation and cannot be retried through this function.
    """
    if allow_send is not True:
        raise GatewayDenied("Explicit operator permission to send the review is required")
    with ProcessLock(gateway.store.path.with_suffix(".outbound.lock")):
        row, body, preview = _inspect(gateway, principal, draft_id, review_scope)
        topic = gateway._topic(review_scope)
        operation_id = gateway._namespace(f"approval:{draft_id}")
        with gateway.store.transaction() as db:
            db.execute(_SCHEMA)
            previous = db.execute("SELECT * FROM gw_approval_prompts WHERE draft=?", (draft_id,)).fetchone()
            if previous is not None:
                if (previous["owner"] != principal.id or previous["digest"] != row["digest"]
                        or (previous["review_chat"], previous["review_topic"]) != (review_scope.chat_id, topic)
                        or previous["operation_id"] != operation_id or previous["preview"] != preview):
                    raise GatewayDenied("Review request differs from the recorded attempt")
                status = previous["status"]
                if status == "sending":
                    db.execute("UPDATE gw_approval_prompts SET status='unknown' WHERE draft=?", (draft_id,))
                    status = "unknown"
                receipt = json.loads(previous["receipt"]) if previous["receipt"] else None
                if status == "bound":
                    if receipt is None:
                        raise GatewayDenied("Review receipt unavailable")
                    _receipt_data(SendReceipt(**receipt), review_scope, operation_id)
                    challenge = db.execute("SELECT * FROM gw_challenges WHERE draft=?", (draft_id,)).fetchone()
                    if (challenge is None or challenge["owner"] != principal.id
                            or (challenge["chat"], challenge["topic"], challenge["message_id"])
                            != (review_scope.chat_id, topic, receipt["message_id"])):
                        raise GatewayDenied("Review binding unavailable")
                return _result(status, receipt=receipt, reused=True)
            if row["status"] != "pending" or row["expires"] <= gateway.clock():
                raise GatewayDenied("Draft is not pending or has expired")
            if db.execute("SELECT 1 FROM gw_challenges WHERE draft=?", (draft_id,)).fetchone():
                raise GatewayDenied("Draft already has an owner challenge")
            db.execute("INSERT INTO gw_approval_prompts VALUES(?,?,?,?,?,?,?,?,?,NULL)",
                       (draft_id, principal.id, row["digest"], review_scope.chat_id, topic,
                        preview, "sending", operation_id, gateway.clock()))
        # The sending claim is durable, and the OS outbound lock stays held
        # across the single attempt. A crash anywhere afterward forbids resend.
        try:
            receipt = await gateway.bot.send_message(
                chat_id=review_scope.chat_id, topic_id=review_scope.topic_id,
                text=preview, operation_id=operation_id, reply_to_message_id=None, attachments=())
        except BotRejected:
            gateway.store.db.execute("UPDATE gw_approval_prompts SET status='failed' WHERE draft=?", (draft_id,))
            return _result("failed")
        except BaseException as error:
            gateway.store.db.execute("UPDATE gw_approval_prompts SET status='unknown' WHERE draft=?", (draft_id,))
            if isinstance(error, (asyncio.CancelledError, KeyboardInterrupt, SystemExit)):
                raise
            return _result("unknown")
        data = None
        try:
            data = _receipt_data(receipt, review_scope, operation_id)
            with gateway.store.transaction() as db:
                current, _, current_preview = _inspect(gateway, principal, draft_id, review_scope)
                if (current["body"] != row["body"] or current["digest"] != row["digest"]
                        or current_preview != preview):
                    raise GatewayDenied("Draft changed during review delivery")
                gateway.bind_owner_challenge(principal, draft_id, review_scope.chat_id,
                                             receipt.message_id, topic_id=review_scope.topic_id)
                db.execute("UPDATE gw_approval_prompts SET status='bound',receipt=? WHERE draft=? AND status='sending'",
                           (canonical(data), draft_id))
        except BaseException as error:
            gateway.store.db.execute("UPDATE gw_approval_prompts SET status='unknown',receipt=? WHERE draft=?",
                                     (canonical(data) if data else None, draft_id))
            if isinstance(error, (asyncio.CancelledError, KeyboardInterrupt, SystemExit)):
                raise
            return _result("unknown", receipt=data)
        return _result("bound", receipt=data)
