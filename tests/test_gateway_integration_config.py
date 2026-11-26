"""Integration declarations are inert metadata; no real configuration is read."""
import copy
from pathlib import Path
import socket

import pytest

from telegram_gateway.agent_config import AgentConfigError, compile_agent_config
from telegram_gateway.auth import FakeAuthenticator
from telegram_gateway.policy import GatewayDenied, Scope
from telegram_gateway.runtime_config import RuntimeConfig, RuntimeConfigError


def profile(identity="zeta"):
    return {"id": identity, "name": identity, "purpose": "Fixture", "prompt": "Inert fixture",
            "enabled": False, "telegram_username": identity + "_test_bot",
            "auth_principal": identity, "chats": []}


def integration(platform="chatgpt_dots"):
    return {"platform": platform, "inbound": {"mode": "manual"}, "outbound": {"mode": "local_commands"}}


def config(entry):
    return {"version": 1, "mode": "disabled", "agents": [entry]}


def test_platform_is_explicit_and_not_inferred_from_agent_name(tmp_path):
    zeta, agent_beta = profile("zeta"), profile("agent_beta")
    zeta["integration"] = integration("grok_bot")
    agent_beta["integration"] = integration("chatgpt_dots")
    cfg = RuntimeConfig.from_dict({"version": 1, "mode": "disabled", "agents": [zeta, agent_beta]}, project_root=tmp_path / "code")
    assert [entry["integration"]["platform"] for entry in cfg.agent_profiles] == ["grok_bot", "chatgpt_dots"]
    assert cfg.bot_configs == {} and cfg.agent_bindings == {}


def test_legacy_profile_without_integration_has_no_inferred_default(tmp_path):
    cfg = RuntimeConfig.from_dict(config(profile()), project_root=tmp_path / "code")
    assert "integration" not in cfg.agent_profiles[0]


def test_disabled_declaration_does_not_change_telegram_grants_or_auth_and_has_no_io(tmp_path, monkeypatch):
    from telegram_gateway import local_secrets
    entry = profile()
    entry.update(enabled=True, chats=[{"chat_id": -1001, "type": "supergroup", "title": "Synthetic", "actions": ["history"]}])
    raw = {"version": 1, "mode": "fake", "state_dir": str(tmp_path / "state"), "agents": [entry],
           "auth": {"mode": "fake", "credentials": {"fixture-zeta": "zeta"}}}
    before = RuntimeConfig.from_dict(raw, project_root=tmp_path / "code")
    entry["integration"] = {"platform": "custom_backend", "enabled": False, "status": "configured",
                            "inbound": {"mode": "webhook", "ref": "fixture_webhook"},
                            "outbound": {"mode": "remote_mcp", "ref": "fixture_remote"}}
    def denied(*args, **kwargs):
        raise AssertionError("integration declarations must not perform I/O")
    for attribute in ("open", "stat", "resolve"):
        monkeypatch.setattr(Path, attribute, denied)
    monkeypatch.setattr(local_secrets, "load_bot_token", denied)
    monkeypatch.setattr(socket, "create_connection", denied)
    after = RuntimeConfig.from_dict(raw, project_root=tmp_path / "code")
    assert after.auth == before.auth and after.agent_bindings == before.agent_bindings
    assert after.bot_configs["zeta_test_bot"].bot_token_ref is None
    principal = FakeAuthenticator({"fixture-zeta": "zeta"}).authenticate("Bearer fixture-zeta")
    assert after.policy.allowed_scopes(principal, "history") == before.policy.allowed_scopes(principal, "history")
    with pytest.raises(GatewayDenied):
        after.policy.require(principal, "send", Scope(-1001))
    metadata = after.agent_profiles[0]["integration"]
    assert metadata["enabled"] is False and metadata["status"] == "configured"
    assert metadata["reason"] == "adapter_not_connected"


def test_status_is_computed_from_declaration_completeness_and_metadata_is_frozen(tmp_path):
    entry = profile()
    entry["integration"] = integration()
    entry["integration"]["status"] = "configured"
    cfg = RuntimeConfig.from_dict(config(entry), project_root=tmp_path / "code")
    metadata = cfg.agent_profiles[0]["integration"]
    assert metadata["status"] == "pending" and metadata["enabled"] is False
    entry["integration"]["inbound"]["ref"] = "fixture_inbound"
    entry["integration"]["outbound"]["ref"] = "fixture_outbound"
    entry["integration"]["status"] = "pending"
    populated = RuntimeConfig.from_dict(config(entry), project_root=tmp_path / "code").agent_profiles[0]["integration"]
    assert populated["status"] == "configured"
    assert "ref" not in metadata["inbound"]
    with pytest.raises(TypeError):
        populated["status"] = "verified"
    with pytest.raises(TypeError):
        populated["inbound"]["mode"] = "webhook"


@pytest.mark.parametrize("inbound", ["manual", "mcp_events", "webhook"])
def test_unimplemented_integration_cannot_be_enabled(inbound):
    entry = profile()
    entry["integration"] = integration()
    entry["integration"].update(enabled=True)
    entry["integration"]["inbound"]["mode"] = inbound
    with pytest.raises(AgentConfigError, match="^Integration adapter is not connected$"):
        compile_agent_config(config(entry))


def test_configuration_cannot_claim_verified_without_a_verifier(tmp_path):
    entry = profile()
    entry["integration"] = integration()
    entry["integration"]["status"] = "verified"
    with pytest.raises(AgentConfigError, match="^Integration verification is unavailable$"):
        compile_agent_config(config(entry))
    with pytest.raises(RuntimeConfigError):
        RuntimeConfig.from_dict(config(entry), project_root=tmp_path / "code")


@pytest.mark.parametrize("direction,mode", [("inbound", "push"), ("inbound", "remote_mcp"),
                                            ("outbound", "webhook"), ("outbound", "sendMessage"), ("inbound", None)])
def test_unknown_or_wrong_direction_modes_fail_closed(direction, mode):
    entry = profile()
    entry["integration"] = integration()
    entry["integration"][direction]["mode"] = mode
    with pytest.raises(AgentConfigError):
        compile_agent_config(config(entry))


@pytest.mark.parametrize("reference", [None, "", "https://example.invalid/callback", "Bearer TEST_TOKEN",
                                       "123456:telegram_token_shape", "sk-secret-shape", "jwt.part.signature", {}, "../path"])
def test_reference_is_only_a_nonsecret_identifier(reference):
    entry = profile()
    entry["integration"] = integration()
    entry["integration"]["inbound"]["ref"] = reference
    with pytest.raises(AgentConfigError):
        compile_agent_config(config(entry))


@pytest.mark.parametrize("change", [
    {"enabled": 1}, {"enabled": "false"}, {"status": "connected"}, {"platform": "https://example.invalid"},
    {"platform": None}, {"token": "SYNTHETIC_FORBIDDEN_VALUE"}, {"reason": "connected"},
    {"inbound": {"mode": "manual", "authorization": "FORBIDDEN"}},
])
def test_unknown_fields_wrong_types_and_credentials_are_rejected(change):
    entry = profile()
    entry["integration"] = integration()
    entry["integration"].update(copy.deepcopy(change))
    with pytest.raises(AgentConfigError):
        compile_agent_config(config(entry))
