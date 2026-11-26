"""Simultaneous synthetic bots only: no credentials, network, or live startup."""
import asyncio
import inspect
import json
import uuid
from dataclasses import replace

import pytest

from telegram_gateway.auth import VerifiedPrincipal, PrincipalAuthority
from telegram_gateway.bot_api import FakeBotTransport, BotRejected
from telegram_gateway.demo import message
from telegram_gateway.multi_runtime import MultiRuntime, GatewayRouter
from telegram_gateway.policy import GatewayDenied
from telegram_gateway.runtime import Runtime, RuntimeBlocked, make_runtime, approval_command, serve, verify_bot_identity
from telegram_gateway.runtime_config import RuntimeConfig
from telegram_gateway.service import ConsumerBusy, Gateway

ALPHA, BETA = "alpha_test_bot", "beta_test_bot"
CHAT, TOPIC = -1001, 7


def config(tmp_path, *, outbound=True):
    profiles = []
    for name, reference, owner in (("alpha", ALPHA, 99), ("beta", BETA, 199)):
        profiles.append({"id": name, "name": "Synthetic " + name, "purpose": "fake isolation test",
                         "prompt": "Inert fixture metadata", "enabled": True,
                         "telegram_username": reference, "auth_principal": name,
                         "chats": [{"chat_id": CHAT, "topic_id": TOPIC, "type": "supergroup",
                                    "title": "Synthetic same group", "actions": ["history", "events", "draft", "send", "forward"]}],
                         "approval": {"owner_ids": [owner], "review_scope": {"chat_id": CHAT, "topic_id": TOPIC}}})
    return RuntimeConfig.from_dict({"version": 1, "mode": "fake", "state_dir": str(tmp_path / "state"),
            "agents": profiles, "auth": {"mode": "fake", "credentials": {"fixture-alpha": "alpha", "fixture-beta": "beta"}},
            "outbound_enabled": outbound, "poll_interval_seconds": 0.1})


def principals(runtime):
    return tuple(runtime.auth.authenticate("Bearer fixture-" + name) for name in ("alpha", "beta"))


async def wait_for(predicate):
    async with asyncio.timeout(2):
        while not predicate():
            await asyncio.sleep(.01)


async def approve(runtime, principal, reference, text="Synthetic reviewed message", *, update=50):
    draft = runtime.gateway.create_draft(principal, CHAT, text, topic_id=TOPIC)
    child = runtime.children[reference]
    challenge = child.gateway.bind_owner_challenge(principal, draft["draft"]["draft_id"], CHAT, update + 100, TOPIC)
    child.transport.updates.append(message(update, CHAT, challenge["approval_text"], topic=TOPIC,
                                            sender=child.cfg.owner_ids[0], reply=update + 100))
    await child.gateway.poll_once()
    return draft


def test_router_signatures_publish_no_bot_selector():
    for method in ("ping", "status", "list_allowed_scopes", "read_history", "search_history", "next_events",
                   "ack_event", "create_draft", "create_forward_draft", "send_draft"):
        assert inspect.signature(getattr(GatewayRouter, method)) == inspect.signature(getattr(Gateway, method))


@pytest.mark.asyncio
async def test_two_bots_simultaneous_identical_ids_are_isolated(tmp_path):
    transports = {ALPHA: FakeBotTransport([message(1, CHAT, "alpha private", topic=TOPIC)]),
                  BETA: FakeBotTransport([message(1, CHAT, "beta private", topic=TOPIC)])}
    runtime = make_runtime(config(tmp_path), transports=transports)
    assert isinstance(runtime, MultiRuntime)
    await runtime.start()
    try:
        alpha, beta = principals(runtime)
        assert len(runtime.children) == 2
        assert all(child.auth is runtime.auth for child in runtime.children.values())
        runtime.start_workers()
        await wait_for(lambda: all(child.gateway.poll_state == "ok" for child in runtime.children.values()))
        for principal, reference, text, foreign in ((alpha, ALPHA, "alpha private", "beta private"), (beta, BETA, "beta private", "alpha private")):
            history = runtime.gateway.read_history(principal, CHAT, TOPIC)
            assert [row["text"] for row in history["messages"]] == [text]
            assert foreign not in json.dumps(history)
            assert history["messages"][0]["bot_reference"] == reference
            assert not runtime.gateway.search_history(principal, CHAT, foreign, TOPIC)["messages"]
            assert runtime.gateway.ping(principal)["bot_reference"] == reference
            status = json.dumps(runtime.gateway.status(principal))
            assert (BETA if reference == ALPHA else ALPHA) not in status
            assert runtime.children[reference].store.db.execute("SELECT COUNT(*) FROM gw_seen").fetchone()[0] == 1
    finally:
        children = list(runtime.children.values())
        await runtime.close()
    assert all(child.store is None and not child.tasks and child.lock is None for child in children)
    assert json.loads((runtime.cfg.state_dir / "runtime-status.json").read_text())["state"] == "stopped"


@pytest.mark.asyncio
async def test_forged_identity_and_body_routing_denied(tmp_path):
    runtime = make_runtime(config(tmp_path))
    await runtime.start()
    try:
        for p in (VerifiedPrincipal("alpha"), PrincipalAuthority().restore("unconfigured"), {"id": "alpha"}):
            with pytest.raises(GatewayDenied):
                runtime.gateway.status(p)
        for field, value in (("bot_reference", BETA), ("agent_id", "beta"), ("principal", "beta"), ("bot", BETA)):
            result = await runtime.protocol.request({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                "params": {"name": "read_history", "arguments": {"chat_id": CHAT, "topic_id": TOPIC, field: value}}},
                authorization="Bearer fixture-alpha")
            assert "error" in result or result["result"].get("isError")
        alpha, _ = principals(runtime)
        with pytest.raises(GatewayDenied):
            runtime.gateway.read_history(alpha, -1002, TOPIC)
        with pytest.raises(GatewayDenied):
            runtime.gateway.read_history(alpha, CHAT, 8)
    finally:
        await runtime.close()


@pytest.mark.asyncio
async def test_start_failure_does_not_stop_other_bot_and_operator_restart(tmp_path):
    fail = {ALPHA: True}
    class SometimesFails(Runtime):
        async def start(self):
            if fail.get(self.cfg.bot_reference):
                raise RuntimeBlocked("private diagnostic must never leak")
            await super().start()
    transports = {ALPHA: FakeBotTransport(), BETA: FakeBotTransport([message(1, CHAT, "healthy beta", topic=TOPIC)])}
    runtime = make_runtime(config(tmp_path), runtime_factory=SometimesFails, transports=transports)
    await runtime.start()
    try:
        alpha, beta = principals(runtime)
        healthy = runtime.children[BETA]
        assert runtime.bot_status[ALPHA] == "unavailable"
        assert runtime.gateway.ping(alpha)["status"] == "unavailable"
        assert "private diagnostic" not in json.dumps(runtime.gateway.status(alpha))
        with pytest.raises(GatewayDenied):
            runtime.gateway.read_history(alpha, CHAT, TOPIC)
        runtime.start_workers()
        await wait_for(lambda: healthy.gateway.poll_state == "ok")
        assert runtime.gateway.read_history(beta, CHAT, TOPIC)["messages"][0]["text"] == "healthy beta"
        fail[ALPHA] = False
        assert await runtime.restart_bot(ALPHA)
        assert runtime.children[BETA] is healthy and len(healthy.tasks) == 2
        assert len(runtime.children[ALPHA].tasks) == 2
        assert runtime.gateway.ping(alpha)["status"] == "ok"
        with pytest.raises(RuntimeBlocked):
            await runtime.restart_bot("foreign_bot")
    finally:
        await runtime.close()


@pytest.mark.asyncio
async def test_root_and_child_process_locks_preserved(tmp_path):
    cfg = config(tmp_path)
    standalone = Runtime(cfg.bot_configs[ALPHA])
    await standalone.start()
    runtime = make_runtime(cfg)
    await runtime.start()
    try:
        assert runtime.bot_status[ALPHA] == "unavailable" and BETA in runtime.children
        assert json.loads((standalone.cfg.state_dir / "runtime-status.json").read_text())["state"] == "running"
        other = make_runtime(cfg)
        with pytest.raises(ConsumerBusy):
            await other.start()
    finally:
        await runtime.close()
        await standalone.close()
    replacement = make_runtime(cfg)
    await replacement.start()
    assert len(replacement.children) == 2
    await replacement.close()


@pytest.mark.asyncio
async def test_owner_approvals_and_uncertain_send_do_not_cross_bot(tmp_path, monkeypatch):
    class AmbiguousFake(FakeBotTransport):
        async def request(self, method, params):
            result = await super().request(method, params)
            if method == "sendMessage":
                raise TimeoutError("synthetic ambiguous send")
            return result
    transports = {ALPHA: AmbiguousFake(), BETA: FakeBotTransport()}
    runtime = make_runtime(config(tmp_path), transports=transports)
    await runtime.start()
    try:
        alpha, beta = principals(runtime)
        monkeypatch.setattr("telegram_gateway.service.uuid.uuid4", lambda: uuid.UUID(int=42))
        a = runtime.gateway.create_draft(alpha, CHAT, "same text", topic_id=TOPIC)
        b = runtime.gateway.create_draft(beta, CHAT, "same text", topic_id=TOPIC)
        did = a["draft"]["draft_id"]
        assert did == b["draft"]["draft_id"] and a["digest"] != b["digest"]
        challenges = [runtime.children[ref].gateway.bind_owner_challenge(p, did, CHAT, 800, TOPIC)
                      for p, ref in ((alpha, ALPHA), (beta, BETA))]
        same = message(1, CHAT, challenges[0]["approval_text"], topic=TOPIC, sender=99, reply=800)
        transports[ALPHA].updates.append(same)
        transports[BETA].updates.append(same)
        for child in runtime.children.values():
            await child.gateway.poll_once()
        assert runtime.children[ALPHA].gateway._draft(alpha, did)["status"] == "approved"
        assert runtime.children[BETA].gateway._draft(beta, did)["status"] == "pending"
        transports[BETA].updates.append(message(2, CHAT, challenges[1]["approval_text"], topic=TOPIC, sender=199, reply=800))
        await runtime.children[BETA].gateway.poll_once()
        unknown = await runtime.gateway.send_draft(alpha, did)
        assert unknown["status"] == "unknown" and len(transports[ALPHA].sent) == 1
        assert await runtime.restart_bot(ALPHA)
        with pytest.raises(GatewayDenied):
            await runtime.gateway.send_draft(alpha, did)
        delivered = await runtime.gateway.send_draft(beta, did)
        assert delivered["status"] == "sent" and delivered["receipt"]["bot_reference"] == BETA
        assert delivered["receipt"]["operation_id"].startswith("bot:" + BETA + ":")
        assert (await runtime.gateway.send_draft(beta, did))["reused"] is True
        assert len(transports[ALPHA].sent) == len(transports[BETA].sent) == 1
    finally:
        await runtime.close()


@pytest.mark.asyncio
async def test_per_bot_rate_limits_and_backoff_are_independent(tmp_path):
    class Throttled(FakeBotTransport):
        async def request(self, method, params):
            if method == "getUpdates":
                raise BotRejected("Synthetic retry", retry_after=30)
            return await super().request(method, params)
    runtime = make_runtime(config(tmp_path), transports={ALPHA: Throttled(), BETA: FakeBotTransport([message(1, CHAT, "not delayed", topic=TOPIC)])})
    await runtime.start()
    try:
        runtime.start_workers()
        await wait_for(lambda: runtime.children[ALPHA].gateway.poll_state == "retrying" and runtime.children[BETA].gateway.poll_state == "ok")
        _, beta = principals(runtime)
        assert runtime.gateway.read_history(beta, CHAT, TOPIC)["messages"][0]["text"] == "not delayed"
    finally:
        await runtime.close()


@pytest.mark.asyncio
async def test_per_bot_send_budget_does_not_consume_other_bot_budget(tmp_path):
    runtime = make_runtime(config(tmp_path))
    await runtime.start()
    try:
        alpha, beta = principals(runtime)
        for child in runtime.children.values():
            child.gateway.max_sends_per_minute = 1
        first = await approve(runtime, alpha, ALPHA, update=1)
        second = await approve(runtime, alpha, ALPHA, update=2)
        other = await approve(runtime, beta, BETA, update=1)
        assert (await runtime.gateway.send_draft(alpha, first["draft"]["draft_id"]))["status"] == "sent"
        with pytest.raises(GatewayDenied, match="rate"):
            await runtime.gateway.send_draft(alpha, second["draft"]["draft_id"])
        assert (await runtime.gateway.send_draft(beta, other["draft"]["draft_id"]))["status"] == "sent"
    finally:
        await runtime.close()


@pytest.mark.asyncio
async def test_shutdown_idempotent_and_cancels_all_worker_tasks(tmp_path):
    closed = {}
    class CountClose(Runtime):
        async def close(self):
            closed[self.cfg.bot_reference] = closed.get(self.cfg.bot_reference, 0) + 1
            await super().close()
    runtime = make_runtime(config(tmp_path), runtime_factory=CountClose)
    await runtime.start()
    children = list(runtime.children.values())
    runtime.start_workers()
    await asyncio.sleep(.01)
    await asyncio.gather(runtime.close(), runtime.close())
    assert closed == {ALPHA: 1, BETA: 1}
    assert all(not child.tasks and child.lock is None and child.store is None for child in children)
    assert not runtime.children and runtime.lock is None


@pytest.mark.asyncio
async def test_cancelled_restart_drains_inflight_call_and_releases_child(tmp_path):
    runtime = make_runtime(config(tmp_path))
    await runtime.start()
    original = runtime.children[ALPHA]
    alpha, _ = principals(runtime)
    entered, cancelling, release = asyncio.Event(), asyncio.Event(), asyncio.Event()
    async def blocked(child):
        entered.set()
        try:
            await asyncio.Event().wait()
        except asyncio.CancelledError:
            cancelling.set()
            await release.wait()
            raise
    active = asyncio.create_task(runtime.call_for(alpha, blocked))
    await entered.wait()
    restart = asyncio.create_task(runtime.restart_bot(ALPHA))
    await cancelling.wait()
    restart.cancel()
    await asyncio.sleep(.01)
    assert not restart.done()
    release.set()
    with pytest.raises(asyncio.CancelledError):
        await restart
    assert original.store is None and original.lock is None and not original.tasks
    assert active.done()
    assert await runtime.restart_bot(ALPHA)
    await runtime.close()


@pytest.mark.asyncio
async def test_operator_approval_routes_child_scope_and_namespaces_prompt(tmp_path):
    cfg = config(tmp_path)
    runtime = make_runtime(cfg)
    await runtime.start()
    alpha, beta = principals(runtime)
    drafts = [runtime.gateway.create_draft(p, CHAT, "Review synthetic text", topic_id=TOPIC) for p in (alpha, beta)]
    await runtime.close()
    with pytest.raises(RuntimeBlocked):
        await approval_command(cfg, "alpha", drafts[0]["draft"]["draft_id"])
    for principal, reference, draft in zip(("alpha", "beta"), (ALPHA, BETA), drafts):
        result = await approval_command(cfg, principal, draft["draft"]["draft_id"], confirm_send=True)
        assert result["status"] == "bound"
        assert result["receipt"]["topic_id"] == TOPIC
        assert result["receipt"]["operation_id"].startswith(f"bot:{reference}:approval:")


@pytest.mark.asyncio
async def test_catalog_serve_uses_factory_and_closes_without_listener(tmp_path, monkeypatch):
    cfg = config(tmp_path)
    class FakeServer:
        def __init__(self, config):
            self.config = config
        async def serve(self):
            async with self.config.app.router.lifespan_context(self.config.app):
                await asyncio.sleep(.01)
    monkeypatch.setattr("uvicorn.Server", FakeServer)
    await serve(cfg)
    assert json.loads((cfg.state_dir / "runtime-status.json").read_text())["state"] == "stopped"


def test_same_transport_injection_rejected(tmp_path):
    same = FakeBotTransport()
    with pytest.raises(RuntimeBlocked):
        make_runtime(config(tmp_path), transports={ALPHA: same, BETA: same})


@pytest.mark.asyncio
@pytest.mark.parametrize("username", [None, 123, "other_test_bot", "invalid/name"])
async def test_named_bot_identity_requires_matching_username(tmp_path, username):
    cfg = replace(config(tmp_path).bot_configs[ALPHA], expected_bot_id=70001)
    class FakeIdentity:
        async def get_me(self):
            return {"ok": True, "result": {"id": 70001, "is_bot": True, "username": username}}
        async def get_webhook_info(self):
            pytest.fail("Identity mismatch must stop before other preflight calls")
    with pytest.raises(RuntimeBlocked, match="identity"):
        await verify_bot_identity(cfg, FakeIdentity())


@pytest.mark.asyncio
async def test_named_bot_identity_accepts_canonical_username(tmp_path):
    cfg = replace(config(tmp_path).bot_configs[ALPHA], expected_bot_id=70001)
    class FakeIdentity:
        async def get_me(self):
            return {"ok": True, "result": {"id": 70001, "is_bot": True, "username": "Alpha_Test_Bot"}}
        async def get_webhook_info(self):
            return {"ok": True, "result": {"url": ""}}
        async def get_chat(self, chat_id):
            return {"ok": True, "result": {"id": chat_id, "type": "supergroup", "title": "Synthetic same group"}}
        async def get_chat_member(self, chat_id, user_id):
            return {"ok": True, "result": {"user": {"id": user_id, "is_bot": user_id == 70001}, "status": "member"}}
    await verify_bot_identity(cfg, FakeIdentity())


@pytest.mark.asyncio
@pytest.mark.parametrize("bad", ["me", "bot_member", "owner_member"])
async def test_identity_preflight_rejects_bool_as_numeric_one(tmp_path, bad):
    cfg = replace(config(tmp_path).bot_configs[ALPHA], expected_bot_id=70001 if bad == "owner_member" else 1,
                  owner_ids=(1,) if bad == "owner_member" else (99,))
    class FakeIdentity:
        async def get_me(self):
            return {"ok": True, "result": {"id": True if bad == "me" else cfg.expected_bot_id,
                                            "is_bot": True, "username": ALPHA}}
        async def get_webhook_info(self):
            return {"ok": True, "result": {"url": ""}}
        async def get_chat(self, chat_id):
            return {"ok": True, "result": {"id": chat_id, "type": "supergroup", "title": "Synthetic same group"}}
        async def get_chat_member(self, chat_id, user_id):
            fake_id = True if user_id == 1 else user_id
            return {"ok": True, "result": {"user": {"id": fake_id, "is_bot": user_id == cfg.expected_bot_id}, "status": "member"}}
    with pytest.raises(RuntimeBlocked):
        await verify_bot_identity(cfg, FakeIdentity())
