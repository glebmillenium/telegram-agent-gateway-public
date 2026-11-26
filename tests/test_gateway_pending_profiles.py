"""Pending profile schema uses synthetic metadata, never private imports."""
from pathlib import Path

import pytest

from telegram_gateway.runtime_config import RuntimeConfig, RuntimeConfigError


def profile(identity="pending_alpha", **changes):
    value = {"id": identity, "name": "Synthetic pending profile", "purpose": "", "prompt": "",
             "enabled": False, "telegram_username": None, "auth_principal": None, "chats": [],
             "integration": {"platform": "grok_bot", "enabled": False,
                             "inbound": {"mode": "webhook"}, "outbound": {"mode": "local_commands"}}}
    value.update(changes)
    return value


def parse(entries, tmp_path):
    return RuntimeConfig.from_dict({"version": 1, "mode": "disabled", "agents": entries},
                                   project_root=tmp_path / "synthetic-code")


@pytest.mark.parametrize("username,principal", [(None, None), ("@EXAMPLE_TEST_BOT", None), (None, "agent-alpha")])
def test_pending_identity_is_preserved_without_invented_binding(tmp_path, username, principal):
    cfg = parse([profile(telegram_username=username, auth_principal=principal)], tmp_path)
    metadata = cfg.agent_profiles[0]
    assert metadata["telegram_username"] == ("example_test_bot" if username else None)
    assert metadata["auth_principal"] == principal
    assert metadata["chats"] == () and metadata["enabled"] is False
    assert cfg.principals == () and cfg.agent_bindings == {} and cfg.bot_configs == {}
    assert cfg.approved_groups == () and cfg.bot_token_ref is None and cfg.routine_routes == {}
    assert not metadata["integration"]["enabled"]


def test_several_unresolved_profiles_do_not_collide_on_null_identity(tmp_path):
    cfg = parse([profile("one"), profile("two"), profile("three")], tmp_path)
    assert [p["id"] for p in cfg.agent_profiles] == ["one", "two", "three"]
    assert all(p["telegram_username"] is None and p["auth_principal"] is None for p in cfg.agent_profiles)
    assert cfg.bot_configs == {}


@pytest.mark.parametrize("username,principal", [(None, None), ("example_test_bot", None), (None, "agent-alpha")])
def test_active_profile_cannot_have_missing_identity(tmp_path, username, principal):
    with pytest.raises(RuntimeConfigError):
        parse([profile(enabled=True, telegram_username=username, auth_principal=principal)], tmp_path)


@pytest.mark.parametrize("extra", [
    {"chats": [{"chat_id": -1001, "type": "supergroup", "title": "Synthetic", "actions": []}]},
    {"expected_bot_id": 9001}, {"expected_bot_id": None}, {"approval": {}}, {"approval": None},
    {"standing_send": None}, {"standing_send": {"purpose": "gateway_technical_test", "chat_id": -1001}},
    {"enabled": 0}, {"enabled": "false"}, {"chats": None},
])
def test_pending_profile_cannot_carry_authority_or_malformed_flags(tmp_path, extra):
    with pytest.raises(RuntimeConfigError):
        parse([profile(**extra)], tmp_path)


def test_pending_profile_cannot_enable_supported_integration(tmp_path):
    entry = profile()
    entry["integration"].update(enabled=True)
    entry["integration"]["inbound"]["ref"] = "fixture_routine"
    entry["integration"]["outbound"]["ref"] = "fixture_client"
    with pytest.raises(RuntimeConfigError):
        parse([entry], tmp_path)


@pytest.mark.parametrize("field,value,other", [
    ("telegram_username", "example_test_bot", "@EXAMPLE_TEST_BOT"),
    ("auth_principal", "agent-alpha", "agent-alpha"),
    ("id", "same_id", "same_id"),
])
def test_non_null_identity_and_operator_ids_still_enforce_uniqueness(tmp_path, field, value, other):
    first, second = profile("one"), profile("two")
    first[field], second[field] = value, other
    with pytest.raises(RuntimeConfigError):
        parse([first, second], tmp_path)


@pytest.mark.parametrize("field,value", [("telegram_username", ""), ("telegram_username", "missing"),
                                          ("auth_principal", ""), ("auth_principal", "bad principal")])
def test_pending_status_does_not_relax_non_null_identity_validation(tmp_path, field, value):
    if field == "telegram_username" and value == "missing":
        # A concrete valid username is metadata, not a magic missing sentinel.
        cfg = parse([profile(**{field: value})], tmp_path)
        assert cfg.agent_profiles[0][field] == value
    else:
        with pytest.raises(RuntimeConfigError):
            parse([profile(**{field: value})], tmp_path)


def test_concrete_disabled_profile_keeps_existing_chat_metadata_behavior(tmp_path):
    chats = [{"chat_id": -1001, "type": "group", "title": "Synthetic", "actions": ["history"]}]
    cfg = parse([profile(telegram_username="example_test_bot", auth_principal="agent-alpha", chats=chats)], tmp_path)
    assert cfg.agent_profiles[0]["chats"][0]["chat_id"] == -1001
    assert cfg.bot_configs == {} and cfg.principals == ()


def test_pending_compile_has_no_secret_file_or_network_access(tmp_path, monkeypatch):
    import socket
    from telegram_gateway import local_secrets
    def forbidden(*args, **kwargs):
        pytest.fail("Pending metadata must not perform I/O")
    for method in ("open", "resolve", "stat"):
        monkeypatch.setattr(Path, method, forbidden)
    monkeypatch.setattr(local_secrets, "load_bot_token", forbidden)
    monkeypatch.setattr(local_secrets, "load_webhook", forbidden)
    monkeypatch.setattr(socket, "getaddrinfo", forbidden)
    cfg = parse([profile()], tmp_path)
    assert cfg.auth_mode == "disabled" and cfg.routine_routes == {}
