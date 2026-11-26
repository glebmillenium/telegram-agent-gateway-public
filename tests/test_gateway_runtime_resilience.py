"""Polling diagnostics and retry tests: fake transport and scratch state only."""
import asyncio
import json

import pytest

from telegram_gateway.bot_api import BotApiAdapter, BotRejected, BotUnavailable, FakeBotTransport
from telegram_gateway.demo import message
from telegram_gateway.runtime import Runtime
from telegram_gateway.runtime_config import RuntimeConfig


def config(tmp_path):
    return RuntimeConfig.from_dict({"version": 1, "mode": "fake", "state_dir": str(tmp_path / "state"),
        "policy": {"principals": {"reader": [{"chat_id": -1001, "permissions": ["history", "events"]}]}},
        "auth": {"mode": "fake", "credentials": {"fixture-reader": "reader"}},
        "bot": {"approved_groups": [{"chat_id": -1001, "type": "supergroup", "title": "Synthetic"}]},
        "poll_interval_seconds": .1})


@pytest.mark.asyncio
@pytest.mark.parametrize("delay,expected", [(1, 1), (120, 120), (86400, 86400), (None, None),
    (True, None), (0, None), (-1, None), (86401, None), (120.0, None), ("120", None), (float("inf"), None)])
async def test_poll_preserves_only_validated_retry_after_and_sanitizes_error(delay, expected):
    class Rejected:
        async def request(self, method, params):
            raise BotRejected("SYNTHETIC_PRIVATE_ERROR", retry_after=delay)
    adapter = BotApiAdapter(Rejected(), allowed_scopes={(-1001, None)})
    with pytest.raises(BotRejected) as caught:
        await adapter.poll(17)
    assert caught.value.retry_after == expected
    assert "SYNTHETIC_PRIVATE_ERROR" not in str(caught.value)
    assert caught.value.__suppress_context__ is True


@pytest.mark.asyncio
async def test_unknown_poll_error_remains_unavailable_without_raw_error():
    class Broken:
        async def request(self, method, params):
            raise OSError("SYNTHETIC_PRIVATE_ERROR")
    with pytest.raises(BotUnavailable) as caught:
        await BotApiAdapter(Broken(), allowed_scopes={(-1001, None)}).poll()
    assert "SYNTHETIC_PRIVATE_ERROR" not in str(caught.value)


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", ["exception", "response"])
async def test_runtime_respects_120_seconds_then_recovers_without_sleeping(tmp_path, monkeypatch, kind):
    class Throttled(FakeBotTransport):
        attempts = 0
        async def request(self, method, params):
            self.attempts += 1
            if self.attempts == 1:
                if kind == "exception":
                    raise BotRejected("SYNTHETIC_PRIVATE_ERROR", retry_after=120)
                return {"ok": False, "parameters": {"retry_after": 120}, "description": "SYNTHETIC_PRIVATE_ERROR"}
            return await super().request(method, params)
    transport = Throttled([message(1, -1001, "synthetic update")])
    runtime = Runtime(config(tmp_path), transport=transport)
    await runtime.start()
    delays, snapshots = [], []
    principal = runtime.auth.authenticate("Bearer fixture-reader")
    async def sleep(delay):
        delays.append(delay)
        snapshots.append(runtime.gateway.status(principal))
        if len(delays) == 1:
            assert runtime.store.db.execute("SELECT value FROM gw_meta WHERE key='cursor'").fetchone()[0] == "0"
        if len(delays) == 2:
            runtime.stopping = True
    monkeypatch.setattr("telegram_gateway.runtime.asyncio.sleep", sleep)
    try:
        await runtime.poll_loop()
        assert delays == [120, .1]
        assert snapshots[0]["health"] == "degraded" and snapshots[0]["poll_state"] == "retrying"
        assert snapshots[1]["health"] == "ok" and snapshots[1]["poll_state"] == "ok"
        assert "SYNTHETIC_PRIVATE_ERROR" not in json.dumps(snapshots)
        assert runtime.gateway.read_history(principal, -1001)["messages"][0]["text"] == "synthetic update"
    finally:
        await runtime.close()


@pytest.mark.asyncio
async def test_local_exponential_backoff_stays_capped_separately(tmp_path, monkeypatch):
    runtime = Runtime(config(tmp_path))
    await runtime.start()
    delays = []
    async def failed():
        raise RuntimeError("Synthetic failure")
    async def sleep(delay):
        delays.append(delay)
        if len(delays) == 7:
            runtime.stopping = True
    monkeypatch.setattr(runtime.gateway, "poll_once", failed)
    monkeypatch.setattr("telegram_gateway.runtime.asyncio.sleep", sleep)
    try:
        await runtime.poll_loop()
        assert delays == [2, 4, 8, 16, 32, 60, 60]
    finally:
        await runtime.close()


@pytest.mark.asyncio
async def test_transient_status_failure_does_not_kill_polling_and_health_recovers(tmp_path, monkeypatch):
    transport = FakeBotTransport([message(1, -1001, "first synthetic update")])
    runtime = Runtime(config(tmp_path), transport=transport)
    await runtime.start()
    original_write = runtime._write_status
    writes, states = [], []
    principal = runtime.auth.authenticate("Bearer fixture-reader")
    def flaky(state):
        writes.append(state)
        if len(writes) == 1:
            raise OSError("SYNTHETIC_PRIVATE_PATH_OR_TOKEN")
        original_write(state)
    async def sleep(delay):
        states.append(runtime.gateway.status(principal))
        if len(states) == 1:
            assert runtime.gateway.ping(principal)["health"] == "degraded"
            transport.updates.append(message(2, -1001, "second synthetic update"))
        else:
            runtime.stopping = True
    monkeypatch.setattr(runtime, "_write_status", flaky)
    monkeypatch.setattr("telegram_gateway.runtime.asyncio.sleep", sleep)
    try:
        await runtime.poll_loop()
        assert len(states) == 2
        assert states[0]["status_write_state"] == "degraded" and states[0]["health"] == "degraded"
        assert states[0]["poll_state"] == "ok"
        assert states[1]["status_write_state"] == "ok" and states[1]["health"] == "ok"
        assert len(runtime.gateway.read_history(principal, -1001)["messages"]) == 2
        disk_status = json.loads((runtime.cfg.state_dir / "runtime-status.json").read_text())
        assert disk_status["health"] == "ok" and disk_status["status_write_state"] == "ok"
        assert "SYNTHETIC_PRIVATE_PATH_OR_TOKEN" not in json.dumps(states) + json.dumps(disk_status)
    finally:
        await runtime.close()


@pytest.mark.asyncio
async def test_repeated_status_failures_keep_polling_and_health_degraded(tmp_path, monkeypatch):
    runtime = Runtime(config(tmp_path))
    await runtime.start()
    loops = []
    original_write = runtime._write_status
    def broken(state):
        raise PermissionError("SYNTHETIC_PRIVATE_DETAIL")
    async def sleep(delay):
        loops.append(runtime.gateway.status_write_state)
        if len(loops) == 3:
            runtime.stopping = True
    monkeypatch.setattr(runtime, "_write_status", broken)
    monkeypatch.setattr("telegram_gateway.runtime.asyncio.sleep", sleep)
    try:
        await runtime.poll_loop()
        assert loops == ["degraded"] * 3
        assert len(runtime.transport.calls) == 3
    finally:
        monkeypatch.setattr(runtime, "_write_status", original_write)
        await runtime.close()


def test_cli_status_includes_existing_bot_counts_and_only_safe_fields(tmp_path, monkeypatch, capsys):
    from telegram_gateway import runtime as module
    cfg = config(tmp_path)
    cfg.state_dir.mkdir()
    (cfg.state_dir / "runtime-status.json").write_text(json.dumps({"state": "running", "mode": "fake",
        "timestamp": 1700000000, "poll_state": "per_bot", "dot_wakeup_verified": False,
        "configured_bots": 2, "available_bots": 1, "health": "degraded", "status_write_state": "degraded",
        "ignored_private": "SYNTHETIC_PRIVATE_DETAIL"}))
    monkeypatch.setattr(module.RuntimeConfig, "load", lambda path: cfg)
    monkeypatch.setattr("sys.argv", ["gateway", "status", "--config", "synthetic-unused"])
    module.main()
    output = capsys.readouterr()
    data = json.loads(output.out)
    assert data["configured_bots"] == 2 and data["available_bots"] == 1
    assert data["health"] == "degraded"
    assert "ignored_private" not in data and "SYNTHETIC_PRIVATE_DETAIL" not in output.out + output.err
