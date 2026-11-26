import asyncio
from dataclasses import replace
import hashlib
import json
import sqlite3

import pytest

from telegram_gateway.approvals import request_owner_approval
from telegram_gateway.auth import FakeAuthenticator, OwnerApprovalVerifier, VerifiedPrincipal
from telegram_gateway.bot_api import BotApiAdapter, BotRejected, DeliveryUncertain, FakeBotTransport, SendReceipt
from telegram_gateway.policy import GatewayDenied, Policy, Scope, TOOL_PERMISSIONS
from telegram_gateway.service import ConsumerBusy, Gateway, ProcessLock, StateStore, canonical


TARGET = Scope(-1001)
REVIEW = Scope(-1003, 5)
ALL = ["history", "events", "draft", "send", "forward"]


@pytest.fixture
def setup(tmp_path):
    now = [1700000000.0]
    policy = Policy.from_dict({"principals": {
        "zeta": [{"chat_id": TARGET.chat_id, "permissions": ALL},
                 {"chat_id": REVIEW.chat_id, "topic_id": REVIEW.topic_id, "permissions": ["draft", "send", "forward"]}],
        "support": [{"chat_id": -1002, "permissions": ALL}]}})
    auth = FakeAuthenticator({"fixture-zeta": "zeta", "fixture-support": "support"})
    a, b = auth.authenticate("Bearer fixture-zeta"), auth.authenticate("Bearer fixture-support")
    wire = FakeBotTransport()
    bot = BotApiAdapter(wire, allowed_scopes={(-1001, None), (-1002, None), (-1003, 5)})
    store = StateStore((tmp_path / "state" / "gateway.sqlite").resolve())
    verifier = OwnerApprovalVerifier([99], [REVIEW, TARGET], clock=lambda: now[0])
    g = Gateway(store, policy, [a, b], bot, owner_verifier=verifier, clock=lambda: now[0])
    yield g, wire, a, b, now
    g.store.close()


def draft(g, a, text='Точный текст\n"quoted" 🙂', **kwargs):
    return g.create_draft(a, TARGET.chat_id, text, **kwargs)


def prompt_row(g, draft_id):
    return g.store.db.execute("SELECT * FROM gw_approval_prompts WHERE draft=?", (draft_id,)).fetchone()


def no_prompt(g, wire):
    assert not wire.sent
    exists = g.store.db.execute("SELECT 1 FROM sqlite_master WHERE name='gw_approval_prompts'").fetchone()
    assert not exists or g.store.db.execute("SELECT COUNT(*) FROM gw_approval_prompts").fetchone()[0] == 0


def reply(update, challenge, text, *, sender=99, bot=False, topic=5, **extras):
    message = {"message_id": update, "date": 1700000001, "chat": {"id": -1003, "type": "supergroup"},
               "message_thread_id": topic, "from": {"id": sender, "is_bot": bot},
               "reply_to_message": {"message_id": challenge}, "text": text}
    message.update(extras)
    return {"update_id": update, "message": message}


@pytest.mark.parametrize("allow", [False, None, 0, 1, "true"])
async def test_default_deny_requires_literal_operator_true(setup, allow):
    g, w, a, _, _ = setup
    d = draft(g, a)
    with pytest.raises(GatewayDenied):
        await request_owner_approval(g, a, d["draft"]["draft_id"], REVIEW, allow_send=allow)
    no_prompt(g, w)


async def test_omitted_send_permission_denies(setup):
    g, w, a, _, _ = setup
    with pytest.raises(GatewayDenied):
        await request_owner_approval(g, a, draft(g, a)["draft"]["draft_id"], REVIEW)
    no_prompt(g, w)


async def test_exact_single_preview_durable_before_network_and_bound_atomically(setup, monkeypatch):
    g, w, a, _, _ = setup
    d = draft(g, a)
    did = d["draft"]["draft_id"]
    original = g.bot.send_message

    async def inspect_claim(**args):
        with sqlite3.connect(g.store.path) as other:
            status, preview = other.execute("SELECT status,preview FROM gw_approval_prompts WHERE draft=?", (did,)).fetchone()
        assert status == "sending" and preview == args["text"]
        with pytest.raises(ConsumerBusy):
            with ProcessLock(g.store.path.with_suffix(".outbound.lock")):
                pass
        assert args["operation_id"] == f"approval:{did}"
        return await original(**args)

    monkeypatch.setattr(g.bot, "send_message", inspect_claim)
    result = await request_owner_approval(g, a, did, REVIEW, allow_send=True)
    assert result["status"] == "bound" and result["reused"] is False
    assert len(w.sent) == 1
    params = w.sent[0]["params"]
    assert params["chat_id"] == REVIEW.chat_id and params["message_thread_id"] == REVIEW.topic_id
    assert params["protect_content"] is True and "parse_mode" not in params
    preview = params["text"]
    assert json.dumps(d["draft"], ensure_ascii=False, sort_keys=True, indent=2) in preview
    assert f'approve {did} {d["digest"]}' in preview
    assert f'reject {did} {d["digest"]}' in preview
    assert len(preview) <= 4000 and "Expires (UTC):" in preview
    assert prompt_row(g, did)["status"] == "bound"
    challenge = g.store.db.execute("SELECT * FROM gw_challenges WHERE draft=?", (did,)).fetchone()
    assert challenge["message_id"] == result["receipt"]["message_id"]
    assert g._draft(a, did)["status"] == "pending"
    assert "request_owner_approval" not in TOOL_PERMISSIONS and "bind_owner_challenge" not in TOOL_PERMISSIONS


async def test_bound_is_idempotent_across_restart_even_after_draft_consumed(setup):
    g, w, a, _, now = setup
    d = draft(g, a)
    did = d["draft"]["draft_id"]
    first = await request_owner_approval(g, a, did, REVIEW, allow_send=True)
    g.store.close()
    g.store = StateStore(g.store.path)
    g.store.db.execute("UPDATE gw_drafts SET status='sent' WHERE id=?", (did,))
    now[0] += 500
    again = await request_owner_approval(g, a, did, REVIEW, allow_send=True)
    assert again == {**first, "reused": True} and len(w.sent) == 1


@pytest.mark.parametrize("principal", ["support", "forged", "body"])
async def test_principal_isolation_and_forgery_denied(setup, principal):
    g, w, a, b, _ = setup
    d = draft(g, a)
    p = {"support": b, "forged": VerifiedPrincipal("zeta"), "body": {"agent_id": "zeta"}}[principal]
    with pytest.raises(GatewayDenied):
        await request_owner_approval(g, p, d["draft"]["draft_id"], REVIEW, allow_send=True)
    no_prompt(g, w)


@pytest.mark.parametrize("scope", [Scope(-9999), Scope(-1003), Scope(-1003, 6), {"chat_id": -1003, "topic_id": 5}])
async def test_review_must_match_preapproved_scope_exactly(setup, scope):
    g, w, a, _, _ = setup
    with pytest.raises(GatewayDenied):
        await request_owner_approval(g, a, draft(g, a)["draft"]["draft_id"], scope, allow_send=True)
    no_prompt(g, w)


async def test_owner_channel_not_configured_denies(setup):
    g, w, a, _, _ = setup
    d = draft(g, a)
    g.owner_verifier = None
    with pytest.raises(GatewayDenied):
        await request_owner_approval(g, a, d["draft"]["draft_id"], REVIEW, allow_send=True)
    no_prompt(g, w)


@pytest.mark.parametrize("which,permission", [("target", "draft"), ("target", "send"), ("review", "draft"), ("review", "send")])
async def test_current_policy_required_on_original_and_review_targets(setup, which, permission):
    g, w, a, _, _ = setup
    d = draft(g, a)
    grants = [{"chat_id": -1001, "permissions": list(ALL)},
              {"chat_id": -1003, "topic_id": 5, "permissions": list(ALL)}]
    grants[0 if which == "target" else 1]["permissions"].remove(permission)
    g.policy = Policy.from_dict({"principals": {"zeta": grants}})
    with pytest.raises(GatewayDenied):
        await request_owner_approval(g, a, d["draft"]["draft_id"], REVIEW, allow_send=True)
    no_prompt(g, w)


@pytest.mark.parametrize("status", ["approved", "rejected", "sending", "unknown", "failed", "sent"])
async def test_new_prompt_requires_pending_draft(setup, status):
    g, w, a, _, _ = setup
    did = draft(g, a)["draft"]["draft_id"]
    g.store.db.execute("UPDATE gw_drafts SET status=? WHERE id=?", (status, did))
    with pytest.raises(GatewayDenied):
        await request_owner_approval(g, a, did, REVIEW, allow_send=True)
    no_prompt(g, w)


async def test_expired_new_draft_denied(setup):
    g, w, a, _, now = setup
    did = draft(g, a, expires_in=1)["draft"]["draft_id"]
    now[0] += 1
    with pytest.raises(GatewayDenied):
        await request_owner_approval(g, a, did, REVIEW, allow_send=True)
    no_prompt(g, w)


@pytest.mark.parametrize("mutation", ["body", "digest", "expiry_column", "owner_in_body", "draft_in_body", "operation"])
async def test_integrity_mismatch_never_sends(setup, mutation):
    g, w, a, _, _ = setup
    d = draft(g, a)
    did = d["draft"]["draft_id"]
    body = d["draft"]
    if mutation == "digest":
        g.store.db.execute("UPDATE gw_drafts SET digest=? WHERE id=?", ("0" * 64, did))
    elif mutation == "expiry_column":
        g.store.db.execute("UPDATE gw_drafts SET expires=1 WHERE id=?", (did,))
    else:
        key, value = {"body": ("text", "changed"), "owner_in_body": ("principal_id", "support"),
                      "draft_in_body": ("draft_id", "x" * 32), "operation": ("operation", "delete")}[mutation]
        body[key] = value
        payload = canonical(body)
        digest_value = hashlib.sha256(payload.encode()).hexdigest() if mutation != "body" else d["digest"]
        g.store.db.execute("UPDATE gw_drafts SET body=?,digest=? WHERE id=?", (payload, digest_value, did))
    with pytest.raises(GatewayDenied):
        await request_owner_approval(g, a, did, REVIEW, allow_send=True)
    no_prompt(g, w)


async def test_attachments_not_silently_omitted(setup):
    g, w, a, _, _ = setup
    did = draft(g, a, attachments=[{"sha256": "a" * 64, "name": "review.txt"}])["draft"]["draft_id"]
    with pytest.raises(GatewayDenied, match="Attachment"):
        await request_owner_approval(g, a, did, REVIEW, allow_send=True)
    no_prompt(g, w)


@pytest.mark.parametrize("text", ["x" * 4000, "🙂" * 1800, "\n" * 2000])
async def test_oversized_preview_rejected_without_truncation(setup, text):
    g, w, a, _, _ = setup
    did = draft(g, a, text)["draft"]["draft_id"]
    with pytest.raises(GatewayDenied, match="limit"):
        await request_owner_approval(g, a, did, REVIEW, allow_send=True)
    no_prompt(g, w)


@pytest.mark.parametrize("error,status", [(BotRejected("synthetic rejection"), "failed"),
                                         (DeliveryUncertain("synthetic uncertain"), "unknown"),
                                         (TimeoutError("synthetic timeout"), "unknown"),
                                         (RuntimeError("synthetic unexpected"), "unknown")])
async def test_failure_states_are_durable_and_never_automatically_reused(setup, monkeypatch, error, status):
    g, w, a, _, _ = setup
    did = draft(g, a)["draft"]["draft_id"]
    calls = []

    async def fail(**args):
        calls.append(args)
        raise error

    monkeypatch.setattr(g.bot, "send_message", fail)
    first = await request_owner_approval(g, a, did, REVIEW, allow_send=True)
    assert first["status"] == status and first["reused"] is False
    assert prompt_row(g, did)["status"] == status
    g.store.close()
    g.store = StateStore(g.store.path)
    again = await request_owner_approval(g, a, did, REVIEW, allow_send=True)
    assert again["status"] == status and again["reused"] is True
    assert len(calls) == 1 and "no automatic resend" in again["retry"]
    assert g._draft(a, did)["status"] == "pending"
    assert not g.store.db.execute("SELECT * FROM gw_challenges").fetchall()


async def test_crashed_sending_claim_is_recovered_unknown_without_network(setup):
    g, w, a, _, _ = setup
    did = draft(g, a)["draft"]["draft_id"]
    await request_owner_approval(g, a, did, REVIEW, allow_send=True)
    g.store.db.execute("UPDATE gw_approval_prompts SET status='sending',receipt=NULL WHERE draft=?", (did,))
    g.store.db.execute("DELETE FROM gw_challenges WHERE draft=?", (did,))
    g.store.close()
    g.store = StateStore(g.store.path)
    result = await request_owner_approval(g, a, did, REVIEW, allow_send=True)
    assert result["status"] == "unknown" and prompt_row(g, did)["status"] == "unknown"
    assert len(w.sent) == 1


async def test_concurrent_requests_os_lock_and_cancellation(setup, monkeypatch):
    g, w, a, _, _ = setup
    did = draft(g, a)["draft"]["draft_id"]
    started = asyncio.Event()

    async def blocked(**args):
        started.set()
        await asyncio.Event().wait()

    monkeypatch.setattr(g.bot, "send_message", blocked)
    first = asyncio.create_task(request_owner_approval(g, a, did, REVIEW, allow_send=True))
    await asyncio.wait_for(started.wait(), timeout=1)
    with pytest.raises(ConsumerBusy):
        await request_owner_approval(g, a, did, REVIEW, allow_send=True)
    first.cancel()
    with pytest.raises(asyncio.CancelledError):
        await first
    assert prompt_row(g, did)["status"] == "unknown"
    assert (await request_owner_approval(g, a, did, REVIEW, allow_send=True))["status"] == "unknown"


@pytest.mark.parametrize("change", ["expiry", "permission", "body", "binding_failure"])
async def test_delivery_then_binding_failure_is_unknown_and_not_retried(setup, monkeypatch, change):
    g, w, a, _, now = setup
    d = draft(g, a)
    did = d["draft"]["draft_id"]
    original = g.bot.send_message

    async def mutate(**args):
        receipt = await original(**args)
        if change == "expiry":
            now[0] += 500
        elif change == "permission":
            g.policy = Policy.from_dict({"principals": {"zeta": []}})
        elif change == "body":
            g.store.db.execute("UPDATE gw_drafts SET body='{}' WHERE id=?", (did,))
        return receipt

    monkeypatch.setattr(g.bot, "send_message", mutate)
    if change == "binding_failure":
        def fail(*args, **kwargs):
            raise RuntimeError("synthetic binding failure")
        monkeypatch.setattr(g, "bind_owner_challenge", fail)
    result = await request_owner_approval(g, a, did, REVIEW, allow_send=True)
    assert result["status"] == "unknown" and result["receipt"]["synthetic"] is True
    assert prompt_row(g, did)["status"] == "unknown" and len(w.sent) == 1
    assert not g.store.db.execute("SELECT * FROM gw_challenges").fetchall()


@pytest.mark.parametrize("change", [{"chat_id": -1002}, {"topic_id": None}, {"operation_id": "wrong"},
                                   {"message_id": True}, {"message_id": 0}])
async def test_unverifiable_receipt_never_binds(setup, monkeypatch, change):
    g, w, a, _, _ = setup
    did = draft(g, a)["draft"]["draft_id"]

    async def bad_receipt(**args):
        return replace(SendReceipt(88, REVIEW.chat_id, REVIEW.topic_id, args["operation_id"], True), **change)

    monkeypatch.setattr(g.bot, "send_message", bad_receipt)
    result = await request_owner_approval(g, a, did, REVIEW, allow_send=True)
    assert result["status"] == "unknown"
    assert not g.store.db.execute("SELECT * FROM gw_challenges").fetchall()


async def test_existing_bound_challenge_cannot_be_replaced(setup):
    g, w, a, _, _ = setup
    did = draft(g, a)["draft"]["draft_id"]
    g.bind_owner_challenge(a, did, REVIEW.chat_id, 777, REVIEW.topic_id)
    with pytest.raises(GatewayDenied):
        await request_owner_approval(g, a, did, REVIEW, allow_send=True)
    no_prompt(g, w)


async def test_bound_prompt_cannot_be_retargeted(setup):
    g, w, a, _, _ = setup
    did = draft(g, a)["draft"]["draft_id"]
    await request_owner_approval(g, a, did, REVIEW, allow_send=True)
    with pytest.raises(GatewayDenied):
        await request_owner_approval(g, a, did, TARGET, allow_send=True)
    assert len(w.sent) == 1


async def test_real_service_owner_reply_verification_then_single_fake_send(setup):
    g, w, a, _, _ = setup
    d = draft(g, a)
    did = d["draft"]["draft_id"]
    result = await request_owner_approval(g, a, did, REVIEW, allow_send=True)
    challenge = result["receipt"]["message_id"]
    approve = f'approve {did} {d["digest"]}'
    w.updates = [reply(2001, challenge, approve, sender=7),
                 reply(2002, challenge, approve, bot=True),
                 reply(2003, challenge, approve, forward_origin={"type": "user"}),
                 reply(2004, challenge, approve, sender_chat={"id": -1003}),
                 reply(2005, challenge, approve, via_bot={"id": 7}),
                 reply(2006, challenge + 9, approve),
                 reply(2007, challenge, approve + "\nextra")]
    await g.poll_once()
    assert g._draft(a, did)["status"] == "pending"
    with pytest.raises(GatewayDenied):
        await g.send_draft(a, did)
    w.updates.append(reply(2008, challenge, approve))
    await g.poll_once()
    assert g._draft(a, did)["status"] == "approved"
    sent = await g.send_draft(a, did)
    assert sent["status"] == "sent" and len(w.sent) == 2
    assert w.sent[1]["params"]["chat_id"] == TARGET.chat_id
    assert w.sent[1]["params"]["text"] == d["draft"]["text"]
    assert (await g.send_draft(a, did))["reused"] is True
    assert len(w.sent) == 2


async def test_snapshot_forward_permissions_rechecked_before_prompt(setup):
    g, w, a, _, _ = setup
    w.updates = [{"update_id": 1, "message": {"message_id": 1, "date": 1700000000,
                 "chat": {"id": -1001, "type": "supergroup"}, "from": {"id": 44, "is_bot": False},
                 "text": "immutable source"}}]
    await g.poll_once()
    d = g.create_forward_draft(a, -1001, 1, -1001)
    g.policy = Policy.from_dict({"principals": {"zeta": [
        {"chat_id": -1001, "permissions": ["history", "draft", "send"]},
        {"chat_id": -1003, "topic_id": 5, "permissions": ALL}]}})
    with pytest.raises(GatewayDenied):
        await request_owner_approval(g, a, d["draft"]["draft_id"], REVIEW, allow_send=True)
    no_prompt(g, w)
