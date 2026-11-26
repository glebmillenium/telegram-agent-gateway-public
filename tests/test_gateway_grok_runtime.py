"""Grok runtime integration uses only synthetic config, callbacks and credentials."""
import asyncio
from dataclasses import replace
import json
import sqlite3

import pytest

from telegram_gateway.bot_api import FakeBotTransport
from telegram_gateway.demo import message
from telegram_gateway.events import WebhookResponse
from telegram_gateway.policy import Policy
from telegram_gateway.runtime import make_runtime
from telegram_gateway.runtime_config import RuntimeConfig

ALPHA, BETA = "alpha_test_bot", "beta_test_bot"
CHAT = -1001


def addressed_message(update, chat, text, *, bot=ALPHA, **kwargs):
    return message(update, chat, "@" + bot + " " + text, **kwargs)


def config(tmp_path, *, routes=True):
    data = {"version": 1, "mode": "fake", "state_dir": str(tmp_path / "state"),
            "agents": [], "routine_routes": {}, "auth": {"mode": "fake", "credentials": {}},
            "poll_interval_seconds": .1}
    for name in ("alpha", "beta"):
        data["agents"].append({"id": name, "name": "Synthetic " + name, "purpose": "test", "prompt": "inert metadata",
            "enabled": True, "telegram_username": name + "_test_bot", "auth_principal": "agent-" + name,
            "chats": [{"chat_id": CHAT, "type": "supergroup", "title": "Synthetic group", "all_topics": True,
                       "actions": ["history", "events"]}],
            "integration": {"platform": "grok_bot", "enabled": routes,
                            "inbound": {"mode": "webhook", "ref": name + "_routine"},
                            "outbound": {"mode": "local_commands", "ref": name + "_local"}}})
        data["auth"]["credentials"]["fixture-" + name] = "agent-" + name
        if routes:
            data["routine_routes"][name + "_routine"] = {"principal_id": "agent-" + name,
                "bot_reference": name + "_test_bot", "url": "https://hooks.example/" + name,
                "bearer_ref": {"env": "SYNTHETIC_ROUTINE_" + name.upper()}}
    return RuntimeConfig.from_dict(data, project_root=tmp_path / "code")


def dependencies(*, updates=True, outcomes=None):
    sent, loaded = {ALPHA: [], BETA: []}, {ALPHA: [], BETA: []}
    transports, senders, loaders, resolvers = {}, {}, {}, {}
    for name, reference in (("alpha", ALPHA), ("beta", BETA)):
        transports[reference] = FakeBotTransport([addressed_message(1, CHAT, name + " synthetic event", bot=reference, topic=7)] if updates else [])
        async def sender(target, body, headers, ref=reference):
            assert headers["Authorization"] == "Bearer PUBLIC_SYNTHETIC_FIXTURE"
            sent[ref].append(json.loads(body))
            outcome = (outcomes or {}).get(ref, 200)
            if isinstance(outcome, Exception):
                raise outcome
            return WebhookResponse(outcome)
        def loader(secret_ref, ref=reference):
            loaded[ref].append(secret_ref)
            return "PUBLIC_SYNTHETIC_FIXTURE"
        senders[reference], loaders[reference], resolvers[reference] = sender, loader, lambda _: ["8.8.8.8"]
    return {"transports": transports, "routine_senders": senders, "routine_resolvers": resolvers,
            "routine_secret_loaders": loaders}, sent, loaded


def principal(runtime, name):
    return runtime.auth.authenticate("Bearer fixture-" + name)


async def poll_all(runtime):
    for child in runtime.children.values():
        await child.gateway.poll_once()


@pytest.mark.asyncio
async def test_per_bot_route_isolation_and_mcp_export_independence(tmp_path):
    deps, sent, loaded = dependencies()
    runtime = make_runtime(config(tmp_path), **deps)
    await runtime.start()
    try:
        await poll_all(runtime)
        a, b = runtime.children[ALPHA], runtime.children[BETA]
        a.gateway.export_events(principal(runtime, "alpha"), a.hub)
        assert a.store.db.execute("SELECT exported FROM gw_event_exports").fetchone()[0] == 1
        assert a.export_routine_events("alpha_routine") == {"exported": 1}
        assert b.export_routine_events("beta_routine") == {"exported": 1}
        assert b.store.db.execute("SELECT exported FROM gw_event_exports").fetchone()[0] == 0
        b.gateway.export_events(principal(runtime, "beta"), b.hub)
        assert b.store.db.execute("SELECT exported FROM gw_event_exports").fetchone()[0] == 1
        for child, route in ((a, "alpha_routine"), (b, "beta_routine")):
            result = await child.routine_once(route)
            assert result == {"status": "accepted", "run_completed": False}
        assert sent[ALPHA][0]["data"]["text"] == "@alpha_test_bot alpha synthetic event"
        assert sent[BETA][0]["data"]["text"] == "@beta_test_bot beta synthetic event"
        assert sent[ALPHA][0]["eventId"] != sent[BETA][0]["eventId"]
        assert loaded[ALPHA][0].value == "SYNTHETIC_ROUTINE_ALPHA"
        assert loaded[BETA][0].value == "SYNTHETIC_ROUTINE_BETA"
        assert a.routine_sinks["alpha_routine"].path != b.routine_sinks["beta_routine"].path
    finally:
        await runtime.close()


@pytest.mark.asyncio
async def test_cursor_crash_gap_dedup_and_restart_no_duplicate(tmp_path):
    deps, sent, _ = dependencies()
    cfg = config(tmp_path)
    runtime = make_runtime(cfg, **deps)
    await runtime.start()
    await poll_all(runtime)
    a = runtime.children[ALPHA]
    a.export_routine_events("alpha_routine")
    a.store.db.execute("UPDATE gw_routine_exports SET cursor=0 WHERE route_id='alpha_routine'")
    a.export_routine_events("alpha_routine")
    assert a.routine_sinks["alpha_routine"].db.execute("SELECT COUNT(*) FROM grok_outbox").fetchone()[0] == 1
    await runtime.close()
    restarted = make_runtime(cfg, **deps)
    await restarted.start()
    try:
        a = restarted.children[ALPHA]
        assert (await a.routine_once("alpha_routine"))["status"] == "accepted"
        assert (await a.routine_once("alpha_routine"))["status"] == "idle"
        assert len(sent[ALPHA]) == 1
    finally:
        await restarted.close()


@pytest.mark.asyncio
async def test_new_route_is_future_only_and_removed_route_never_replays(tmp_path):
    deps, sent, _ = dependencies()
    old = make_runtime(config(tmp_path, routes=False), **deps)
    await old.start()
    await poll_all(old)
    await old.close()
    enabled = make_runtime(config(tmp_path), **deps)
    await enabled.start()
    assert (await enabled.children[ALPHA].routine_once("alpha_routine"))["status"] == "idle"
    deps["transports"][ALPHA].updates.append(addressed_message(2, CHAT, "queued before revoke", topic=7))
    await enabled.children[ALPHA].gateway.poll_once()
    enabled.children[ALPHA].export_routine_events("alpha_routine")
    old_path = enabled.children[ALPHA].routine_sinks["alpha_routine"].path
    await enabled.close()
    removed = make_runtime(config(tmp_path, routes=False), **deps)
    await removed.start()
    deps["transports"][ALPHA].updates.append(addressed_message(3, CHAT, "while route disabled", topic=7))
    await removed.children[ALPHA].gateway.poll_once()
    await removed.close()
    with sqlite3.connect(old_path) as db:
        assert db.execute("SELECT status FROM grok_outbox").fetchone()[0] == "revoked"
    again = make_runtime(config(tmp_path), **deps)
    await again.start()
    try:
        assert (await again.children[ALPHA].routine_once("alpha_routine"))["status"] == "idle"
        deps["transports"][ALPHA].updates.append(addressed_message(4, CHAT, "future enabled event", topic=7))
        await again.children[ALPHA].gateway.poll_once()
        assert (await again.children[ALPHA].routine_once("alpha_routine"))["status"] == "accepted"
        assert [v["data"]["text"] for v in sent[ALPHA]] == ["@alpha_test_bot future enabled event"]
    finally:
        await again.close()


@pytest.mark.asyncio
async def test_route_fingerprint_change_revokes_queue_and_starts_new_future_stream(tmp_path):
    deps, sent, _ = dependencies()
    cfg = config(tmp_path)
    runtime = make_runtime(cfg, **deps)
    await runtime.start()
    await poll_all(runtime)
    a = runtime.children[ALPHA]
    a.export_routine_events("alpha_routine")
    old_path = a.routine_sinks["alpha_routine"].path
    await runtime.close()
    fields = dict(cfg.bot_configs[ALPHA].routine_routes["alpha_routine"], url="https://hooks.example/rotated")
    child_cfg = replace(cfg.bot_configs[ALPHA], routine_routes={"alpha_routine": fields})
    changed = replace(cfg, bot_configs={**cfg.bot_configs, ALPHA: child_cfg})
    runtime = make_runtime(changed, **deps)
    await runtime.start()
    try:
        assert runtime.children[ALPHA].routine_sinks["alpha_routine"].path != old_path
        with sqlite3.connect(old_path) as db:
            assert db.execute("SELECT status FROM grok_outbox").fetchone()[0] == "revoked"
        assert (await runtime.children[ALPHA].routine_once("alpha_routine"))["status"] == "idle"
        assert sent[ALPHA] == []
    finally:
        await runtime.close()


@pytest.mark.asyncio
@pytest.mark.parametrize("outcome,expected", [(200, "accepted"), (201, "rejected"), (500, "unknown"), (TimeoutError("synthetic timeout"), "unknown")])
async def test_only_200_accepted_unknown_never_retried_after_restart(tmp_path, outcome, expected):
    deps, sent, _ = dependencies(outcomes={ALPHA: outcome})
    cfg = config(tmp_path)
    runtime = make_runtime(cfg, **deps)
    await runtime.start()
    await poll_all(runtime)
    assert (await runtime.children[ALPHA].routine_once("alpha_routine"))["status"] == expected
    assert (await runtime.children[BETA].routine_once("beta_routine"))["status"] == "accepted"
    await runtime.close()
    runtime = make_runtime(cfg, **deps)
    await runtime.start()
    try:
        assert (await runtime.children[ALPHA].routine_once("alpha_routine"))["status"] == "idle"
        assert len(sent[ALPHA]) == len(sent[BETA]) == 1
    finally:
        await runtime.close()


@pytest.mark.asyncio
async def test_revoke_and_current_grants_rechecked_before_secret_loading(tmp_path):
    deps, sent, loaded = dependencies()
    runtime = make_runtime(config(tmp_path), **deps)
    await runtime.start()
    try:
        await poll_all(runtime)
        a, b = runtime.children[ALPHA], runtime.children[BETA]
        a.export_routine_events("alpha_routine")
        b.export_routine_events("beta_routine")
        a.revoke_routine("alpha_routine")
        b.cfg = replace(b.cfg, policy=Policy.from_dict({"principals": {"agent-beta": []}}))
        await a.routine_once("alpha_routine")
        assert (await b.routine_once("beta_routine"))["status"] == "revoked"
        assert sent == {ALPHA: [], BETA: []} and loaded == {ALPHA: [], BETA: []}
    finally:
        await runtime.close()


@pytest.mark.asyncio
async def test_fake_incomplete_injections_never_fall_back_to_network_or_secrets(tmp_path, monkeypatch):
    deps, sent, loaded = dependencies()
    deps.pop("routine_resolvers")
    def forbidden(*args, **kwargs):
        pytest.fail("Fake mode attempted a real dependency")
    monkeypatch.setattr("socket.getaddrinfo", forbidden)
    monkeypatch.setattr("telegram_gateway.runtime.load_secret", forbidden)
    runtime = make_runtime(config(tmp_path), **deps)
    await runtime.start()
    try:
        await poll_all(runtime)
        for reference, route in ((ALPHA, "alpha_routine"), (BETA, "beta_routine")):
            assert (await runtime.children[reference].routine_once(route))["status"] == "unavailable"
        assert sent == {ALPHA: [], BETA: []} and loaded == {ALPHA: [], BETA: []}
    finally:
        await runtime.close()


@pytest.mark.asyncio
async def test_no_routes_preserve_workers_and_do_not_create_export_state(tmp_path):
    deps, sent, loaded = dependencies()
    runtime = make_runtime(config(tmp_path, routes=False), **deps)
    await runtime.start()
    try:
        runtime.start_workers()
        for child in runtime.children.values():
            assert len(child.tasks) == 2 and not child.routine_sinks
            assert child.store.db.execute("SELECT 1 FROM sqlite_master WHERE name='gw_routine_exports'").fetchone() is None
        assert sent == {ALPHA: [], BETA: []} and loaded == {ALPHA: [], BETA: []}
    finally:
        await runtime.close()


@pytest.mark.asyncio
async def test_slow_route_independent_and_shutdown_marks_inflight_unknown(tmp_path):
    deps, sent, _ = dependencies()
    entered = asyncio.Event()
    async def slow(target, body, headers):
        entered.set()
        await asyncio.Event().wait()
    deps["routine_senders"][ALPHA] = slow
    runtime = make_runtime(config(tmp_path), **deps)
    await runtime.start()
    a = runtime.children[ALPHA]
    path = a.routine_sinks["alpha_routine"].path
    runtime.start_workers()
    await asyncio.wait_for(entered.wait(), 3)
    async with asyncio.timeout(3):
        while not sent[BETA]:
            await asyncio.sleep(.01)
    await runtime.close()
    assert not a.tasks and not a.routine_sinks and a.lock is None
    with sqlite3.connect(path) as db:
        assert db.execute("SELECT status FROM grok_outbox").fetchone()[0] == "unknown"
