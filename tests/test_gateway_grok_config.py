"""Grok route configuration: only synthetic in-memory data, no I/O."""
import copy
from pathlib import Path
import socket

import pytest

from telegram_gateway.auth import FakeAuthenticator
from telegram_gateway.policy import GatewayDenied, Scope
from telegram_gateway.runtime_config import RuntimeConfig, RuntimeConfigError, SecretRef


def profile(name="alpha"):
    return {"id": name, "name": "Fixture " + name, "purpose": "test", "prompt": "inert",
            "enabled": True, "telegram_username": name + "_test_bot", "auth_principal": "agent-" + name,
            "expected_bot_id": 70001 if name == "alpha" else 70002,
            "chats": [{"chat_id": -1001 if name == "alpha" else -1002, "type": "supergroup",
                       "title": "Synthetic " + name, "actions": ["history", "events"]}],
            "integration": {"platform": "grok_bot", "enabled": True,
                            "inbound": {"mode": "webhook", "ref": name + "_routine"},
                            "outbound": {"mode": "local_commands", "ref": name + "_local"}}}


def route(name="alpha"):
    return {"principal_id": "agent-" + name, "bot_reference": name + "_test_bot",
            "url": "https://hooks.example/" + name,
            "bearer_ref": {"env": "SYNTHETIC_GROK_" + name.upper()}}


def config(tmp_path):
    return {"version": 1, "mode": "fake", "state_dir": str(tmp_path / "state"),
            "agents": [profile()], "routine_routes": {"alpha_routine": route()},
            "auth": {"mode": "fake", "credentials": {"fixture-alpha": "agent-alpha"}}}


def parse(data, tmp_path):
    return RuntimeConfig.from_dict(data, project_root=tmp_path / "code")


def test_catalog_route_is_bound_immutable_configured_and_never_verified(tmp_path):
    data = config(tmp_path)
    data["routine_routes"]["alpha_routine"]["bot_reference"] = "@ALPHA_TEST_BOT"
    data["routine_routes"]["alpha_routine"]["url"] = "https://HOOKS.EXAMPLE:443/alpha"
    cfg = parse(data, tmp_path)
    child = cfg.bot_configs["alpha_test_bot"]
    expected = {"route_id": "alpha_routine", "principal_id": "agent-alpha",
                "bot_reference": "alpha_test_bot", "url": "https://hooks.example/alpha",
                "bearer_ref": SecretRef("env", "SYNTHETIC_GROK_ALPHA"), "addressing": "mentions_or_replies"}
    assert cfg.routine_routes == child.routine_routes == {"alpha_routine": expected}
    metadata = cfg.agent_profiles[0]["integration"]
    assert metadata["enabled"] is True and metadata["status"] == "configured"
    assert metadata["reason"] == "delivery_not_verified"
    assert not cfg.network_enabled and not cfg.outbound_enabled
    assert cfg.allowed_callbacks == child.allowed_callbacks == {}
    principal = FakeAuthenticator({"fixture": "agent-alpha"}).authenticate("Bearer fixture")
    with pytest.raises(GatewayDenied):
        child.policy.require(principal, "send", Scope(-1001))
    data["routine_routes"]["alpha_routine"]["url"] = "https://changed.example/"
    assert cfg.routine_routes["alpha_routine"]["url"] == expected["url"]
    with pytest.raises(TypeError):
        cfg.routine_routes["new"] = expected
    with pytest.raises(TypeError):
        child.routine_routes["alpha_routine"]["principal_id"] = "foreign"
    assert "SYNTHETIC_GROK_ALPHA" not in repr(cfg)
    assert "hooks.example" not in repr(child)


def test_two_bot_routes_and_file_references_are_partitioned(tmp_path):
    data = config(tmp_path)
    data["agents"].append(profile("beta"))
    data["routine_routes"]["beta_routine"] = route("beta")
    data["auth"]["credentials"]["fixture-beta"] = "agent-beta"
    data["secrets_dir"] = str(tmp_path / "secrets")
    for name in ("alpha", "beta"):
        data["routine_routes"][name + "_routine"]["bearer_ref"] = {
            "file": str(tmp_path / "secrets" / "bots" / (name + "_test_bot") / "routine.secret")}
    cfg = parse(data, tmp_path)
    assert set(cfg.routine_routes) == {"alpha_routine", "beta_routine"}
    for name in ("alpha", "beta"):
        child = cfg.bot_configs[name + "_test_bot"]
        assert set(child.routine_routes) == {name + "_routine"}
        assert child.routine_routes[name + "_routine"]["principal_id"] == "agent-" + name
        assert Path(child.routine_routes[name + "_routine"]["bearer_ref"].value).parent == child.secrets_dir


def test_legacy_disabled_integration_has_empty_routes_and_unchanged_policy(tmp_path):
    data = config(tmp_path)
    data.pop("routine_routes")
    data["agents"][0]["integration"]["enabled"] = False
    cfg = parse(data, tmp_path)
    assert cfg.routine_routes == cfg.bot_configs["alpha_test_bot"].routine_routes == {}
    assert cfg.agent_profiles[0]["integration"]["reason"] == "adapter_not_connected"
    empty = RuntimeConfig.from_dict({"version": 1, "mode": "disabled"}, project_root=tmp_path / "code")
    assert empty.routine_routes == {}


@pytest.mark.parametrize("change", ["missing_route", "unused_route", "wrong_principal", "wrong_bot", "inactive_agent",
                                     "disabled_integration", "missing_integration", "unknown_route_ref", "route_without_agent"])
def test_dangling_unused_or_foreign_routes_fail_closed(tmp_path, change):
    data = config(tmp_path)
    if change == "missing_route":
        data.pop("routine_routes")
    elif change == "unused_route":
        data["routine_routes"]["unused"] = route()
    elif change == "wrong_principal":
        data["routine_routes"]["alpha_routine"]["principal_id"] = "foreign"
    elif change == "wrong_bot":
        data["routine_routes"]["alpha_routine"]["bot_reference"] = "foreign_test_bot"
    elif change == "inactive_agent":
        data["agents"][0]["enabled"] = False
    elif change == "disabled_integration":
        data["agents"][0]["integration"]["enabled"] = False
    elif change == "missing_integration":
        data["agents"][0].pop("integration")
    elif change == "unknown_route_ref":
        data["agents"][0]["integration"]["inbound"]["ref"] = "unknown"
    else:
        data["agents"] = []
    with pytest.raises(RuntimeConfigError):
        parse(data, tmp_path)


@pytest.mark.parametrize("change", ["platform", "inbound", "outbound", "missing_outbound_ref", "missing_inbound_ref", "verified"])
def test_only_supported_unverified_grok_combination_can_be_enabled(tmp_path, change):
    data = config(tmp_path)
    integration = data["agents"][0]["integration"]
    if change == "platform":
        integration["platform"] = "chatgpt_dots"
    elif change == "inbound":
        integration["inbound"]["mode"] = "mcp_events"
    elif change == "outbound":
        integration["outbound"]["mode"] = "remote_mcp"
    elif change.startswith("missing_"):
        integration[change.split("_")[1]].pop("ref")
    else:
        integration["status"] = "verified"
    with pytest.raises(RuntimeConfigError):
        parse(data, tmp_path)


@pytest.mark.parametrize("url", ["http://hooks.example/a", "https://user:password@hooks.example/a",
                                 "https://hooks.example/a#fragment", "https://127.0.0.1/a", "https://[::1]/a",
                                 "https://10.0.0.1/a", "https://localhost/a", "https://hooks.internal/a",
                                 "https://hooks.example:8443/a", "https://hooks.example/space here"])
def test_route_destination_is_public_https_syntax_only(tmp_path, url):
    data = config(tmp_path)
    data["routine_routes"]["alpha_routine"]["url"] = url
    with pytest.raises(RuntimeConfigError):
        parse(data, tmp_path)


@pytest.mark.parametrize("value", [None, [], "route", {"BAD-ID": route()}, {"alpha_routine": {**route(), "token": "SYNTHETIC_FORBIDDEN"}}])
def test_route_shape_and_unknown_fields_are_strict(tmp_path, value):
    data = config(tmp_path)
    data["routine_routes"] = copy.deepcopy(value)
    with pytest.raises(RuntimeConfigError):
        parse(data, tmp_path)


@pytest.mark.parametrize("ref", [{"local_bot": "alpha_test_bot"}, {"token": "SYNTHETIC_FORBIDDEN"}, "secret", {},
                                 {"env": "BAD ENV"}, {"env": "FIXTURE", "file": "not-allowed"}])
def test_bearer_requires_separate_valid_secret_reference(tmp_path, ref):
    data = config(tmp_path)
    data["routine_routes"]["alpha_routine"]["bearer_ref"] = ref
    with pytest.raises(RuntimeConfigError):
        parse(data, tmp_path)


@pytest.mark.parametrize("kind", ["file"])
def test_bearer_file_is_contained_in_own_child_secrets_directory_without_reads(tmp_path, kind):
    data = config(tmp_path)
    data["secrets_dir"] = str(tmp_path / "secrets")
    ref = data["routine_routes"]["alpha_routine"]
    ref["bearer_ref"] = {kind: str(tmp_path / "secrets" / "bots" / "alpha_test_bot" / "fixture.secret")}
    assert parse(data, tmp_path).routine_routes["alpha_routine"]["bearer_ref"].kind == kind
    for path in (tmp_path / "secrets" / "fixture.secret", tmp_path / "secrets" / "bots" / "beta_test_bot" / "fixture.secret"):
        ref["bearer_ref"] = {kind: str(path)}
        with pytest.raises(RuntimeConfigError):
            parse(data, tmp_path)


def test_lowlevel_config_cannot_bypass_profile_integration_binding(tmp_path):
    with pytest.raises(RuntimeConfigError):
        parse({"version": 1, "mode": "disabled", "routine_routes": {"alpha_routine": route()}}, tmp_path)


def test_parsing_never_reads_secrets_paths_environment_or_network(tmp_path, monkeypatch):
    from telegram_gateway import local_secrets, runtime_config
    data = config(tmp_path)
    def denied(*args, **kwargs):
        pytest.fail("Configuration parsing performed I/O")
    for method in ("open", "stat", "resolve"):
        monkeypatch.setattr(Path, method, denied)
    monkeypatch.setattr(runtime_config, "load_secret", denied)
    monkeypatch.setattr(runtime_config.os, "getenv", denied)
    monkeypatch.setattr(local_secrets, "load_bot_token", denied)
    monkeypatch.setattr(socket, "getaddrinfo", denied)
    monkeypatch.setattr(socket, "create_connection", denied)
    cfg = parse(data, tmp_path)
    assert cfg.routine_routes["alpha_routine"]["bearer_ref"].kind == "env"


def test_telegram_dpapi_store_cannot_be_used_as_a_grok_credential(tmp_path, monkeypatch):
    from telegram_gateway import dpapi_store
    data = config(tmp_path)
    data["secrets_dir"] = str(tmp_path / "secrets")
    data["routine_routes"]["alpha_routine"]["bearer_ref"] = {
        "dpapi_file": str(tmp_path / "secrets" / "bots" / "alpha_test_bot" / "synthetic.dpapi")}
    def forbidden(*args, **kwargs):
        pytest.fail("Rejected reference must not be read or decrypted")
    monkeypatch.setattr(dpapi_store, "load_token", forbidden)
    with pytest.raises(RuntimeConfigError, match="routine bearer reference"):
        parse(data, tmp_path)


def test_local_webhook_ref_is_route_bound_pure_and_fingerprint_compatible(tmp_path, monkeypatch):
    from telegram_gateway import local_secrets
    from telegram_gateway.grok_routine import Route
    data = config(tmp_path)
    data["routine_routes"]["alpha_routine"]["bearer_ref"] = {"local_webhook": "alpha_routine"}
    def forbidden(*args, **kwargs):
        pytest.fail("reference parse must not read any webhook secret")
    monkeypatch.setattr(local_secrets, "load_webhook", forbidden)
    cfg = parse(data, tmp_path)
    fields = cfg.routine_routes["alpha_routine"]
    assert fields["bearer_ref"].kind == "local_webhook"
    route = Route(**dict(fields))
    assert len(route.fingerprint()) == 64
    assert route.fingerprint() == Route(**dict(fields)).fingerprint()
    assert "alpha_routine" not in repr(fields["bearer_ref"])
    data["routine_routes"]["alpha_routine"]["bearer_ref"] = {"local_webhook": "foreign_routine"}
    with pytest.raises(RuntimeConfigError, match="routine bearer reference"):
        parse(data, tmp_path)


@pytest.mark.parametrize("value", ["all_messages", "broadcast", "", None, True, [], {}])
def test_route_addressing_cannot_enable_broadcast_or_unknown_modes(tmp_path, value):
    data = config(tmp_path)
    data["routine_routes"]["alpha_routine"]["addressing"] = value
    with pytest.raises(RuntimeConfigError):
        parse(data, tmp_path)


def test_explicit_addressed_mode_is_preserved(tmp_path):
    data = config(tmp_path)
    data["routine_routes"]["alpha_routine"]["addressing"] = "mentions_or_replies"
    cfg = parse(data, tmp_path)
    assert cfg.routine_routes["alpha_routine"]["addressing"] == "mentions_or_replies"
