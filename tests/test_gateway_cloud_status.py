"""Diagnostics report an unknown cloud outcome; synthetic dependencies only."""
import json
from types import SimpleNamespace

import pytest

from telegram_gateway.auth import FakeAuthenticator
from telegram_gateway.bot_api import BotApiAdapter, FakeBotTransport
from telegram_gateway.multi_runtime import GatewayRouter
from telegram_gateway.policy import Policy
from telegram_gateway.runtime import RuntimeGateway
from telegram_gateway.service import Gateway, StateStore


@pytest.mark.parametrize("kind", ["base", "fake", "live_shape"])
@pytest.mark.parametrize("method", ["ping", "status"])
def test_diagnostics_do_not_evaluate_cloud_delivery(tmp_path, kind, method):
    principal = FakeAuthenticator({"synthetic-fixture": "reader"}).authenticate("Bearer synthetic-fixture")
    policy = Policy.from_dict({"principals": {"reader": []}})
    wire = FakeBotTransport()
    store = StateStore((tmp_path / "gateway.sqlite").resolve())
    try:
        arguments = (store, policy, [principal], BotApiAdapter(wire))
        if kind == "base":
            gateway = Gateway(*arguments)
        else:
            gateway = RuntimeGateway(*arguments, mode="live" if kind == "live_shape" else "fake",
                                     outbound_enabled=False)
            # This is a state fixture, not a live connection or network probe.
            gateway.poll_state = "ok"
        result = getattr(gateway, method)(principal)
        assert result["cloud_delivery_confirmed"] is None
        assert result["cloud_delivery_status"] == "not_evaluated"
        assert json.loads(json.dumps(result))["cloud_delivery_confirmed"] is None
        if kind == "live_shape" and method == "ping":
            assert result["telegram_connected"] is True
        assert wire.calls == [] and wire.sent == []
    finally:
        store.close()


@pytest.mark.parametrize("method", ["ping", "status"])
def test_unavailable_child_does_not_report_a_cloud_delivery_failure(method):
    principal = FakeAuthenticator({"synthetic-fixture": "reader"}).authenticate("Bearer synthetic-fixture")
    runtime = SimpleNamespace(reference_for=lambda _: "status_fixture_bot", children={},
                              cfg=SimpleNamespace(policy=Policy.from_dict({"principals": {"reader": []}})))
    router = GatewayRouter(runtime)
    result = getattr(router, method)(principal)
    assert result["cloud_delivery_confirmed"] is None
    assert result["cloud_delivery_status"] == "not_evaluated"
    assert result["telegram_connected"] is False
