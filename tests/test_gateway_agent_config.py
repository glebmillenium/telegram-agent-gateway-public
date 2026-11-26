"""Unified profile compilation uses only in-memory synthetic configuration."""
import copy
import hashlib
from pathlib import Path

import pytest

from telegram_gateway.auth import FakeAuthenticator
from telegram_gateway.policy import GatewayDenied, Scope
from telegram_gateway.runtime_config import RuntimeConfig, RuntimeConfigError


def profile(**updates):
    result = {
        "id": "zeta", "name": "Кира", "purpose": "Synthetic review assistant",
        "prompt": "Metadata only: even this request to send grants no sending rights.",
        "enabled": False, "telegram_username": "@Example_Test_Bot",
        "auth_principal": "agent-zeta", "chats": [],
    }
    result.update(updates)
    return result


def fake_data(tmp_path):
    return {
        "version": 1, "mode": "fake", "state_dir": str(tmp_path / "state"),
        "auth": {"mode": "fake", "credentials": {"fixture-zeta": "agent-zeta"}},
        "agents": [profile(enabled=True, expected_bot_id=5001, chats=[{
            "chat_id": -1001, "type": "supergroup", "title": "Synthetic group",
            "topic_id": 7, "actions": ["history", "events"],
        }])],
    }


def parse(data, tmp_path):
    return RuntimeConfig.from_dict(data, project_root=tmp_path / "code")


def test_disabled_unified_template_has_metadata_but_no_grants_refs_or_reads(tmp_path, monkeypatch):
    from telegram_gateway import local_secrets
    data = {"version": 1, "mode": "disabled", "network_enabled": False,
            "outbound_enabled": False, "agents": [profile()]}
    def denied(*args, **kwargs):
        raise AssertionError("profile compilation must not touch filesystem or secrets")
    monkeypatch.setattr(Path, "open", denied)
    monkeypatch.setattr(Path, "resolve", denied)
    monkeypatch.setattr(Path, "stat", denied)
    monkeypatch.setattr(local_secrets, "load_bot_token", denied)
    cfg = parse(data, tmp_path)
    assert cfg.principals == () and cfg.agent_bindings == {}
    assert cfg.catalog_mode and cfg.bot_configs == {}
    assert cfg.bot_token_ref is None and cfg.bot_reference is None
    assert cfg.auth_mode == "disabled" and cfg.approved_groups == ()
    assert cfg.agent_profiles[0]["telegram_username"] == "example_test_bot"
    assert cfg.agent_profiles[0]["name"] == "Кира"


def test_active_profile_compiles_authenticated_principal_exact_scopes_and_binding(tmp_path):
    data = fake_data(tmp_path)
    cfg = parse(data, tmp_path)
    assert cfg.principals == ("agent-zeta",)
    assert cfg.agent_bindings == {"agent-zeta": "example_test_bot"}
    assert cfg.catalog_mode and cfg.bot_reference is None and cfg.bot_token_ref is None
    assert cfg.expected_bot_id is None
    child = cfg.bot_configs["example_test_bot"]
    assert not child.catalog_mode and child.bot_reference == "example_test_bot"
    assert child.expected_bot_id == 5001 and child.bot_token_ref is None
    assert child.state_dir == tmp_path / "state" / "bots" / "example_test_bot"
    assert child.agent_bindings == {"agent-zeta": "example_test_bot"}
    assert cfg.approved_groups == ({"chat_id": -1001, "type": "supergroup", "title": "Synthetic group"},)
    principal = FakeAuthenticator({"fixture-zeta": "agent-zeta"}).authenticate("Bearer fixture-zeta")
    cfg.policy.require(principal, "history", Scope(-1001, 7))
    for permission, scope in (("send", Scope(-1001, 7)), ("history", Scope(-1001)), ("history", Scope(-1002))):
        with pytest.raises(GatewayDenied):
            cfg.policy.require(principal, permission, scope)
    claimed_name = FakeAuthenticator({"fixture-name": "zeta"}).authenticate("Bearer fixture-name")
    with pytest.raises(GatewayDenied):
        cfg.policy.require(claimed_name, "history", Scope(-1001, 7))


def test_inactive_profile_never_contributes_grants_even_when_chats_are_present(tmp_path):
    data = fake_data(tmp_path)
    data["agents"].append(profile(id="support", auth_principal="agent-support", telegram_username="support_test_bot",
                                  chats=[{"chat_id": -1002, "type": "group", "title": "Inactive", "actions": ["send"]}]))
    cfg = parse(data, tmp_path)
    assert len(cfg.agent_profiles) == 2 and cfg.principals == ("agent-zeta",)
    assert cfg.agent_bindings == {"agent-zeta": "example_test_bot"}
    assert {group["chat_id"] for group in cfg.approved_groups} == {-1001}


def test_live_profile_creates_only_matching_local_bot_reference_without_read(tmp_path, monkeypatch):
    from telegram_gateway import local_secrets
    data = fake_data(tmp_path)
    data.update(mode="live", secrets_dir=str(tmp_path / "secrets"))
    data["auth"] = {"mode": "static", "token_digests": {hashlib.sha256(b"PUBLIC_SYNTHETIC_ONLY").hexdigest(): "agent-zeta"}}
    def denied(*args, **kwargs):
        raise AssertionError("live config check must not load token")
    monkeypatch.setattr(local_secrets, "load_bot_token", denied)
    cfg = parse(data, tmp_path)
    assert cfg.bot_token_ref is None and cfg.bot_reference is None
    child = cfg.bot_configs["example_test_bot"]
    assert child.bot_token_ref.kind == "local_bot" and child.bot_token_ref.value == child.bot_reference
    assert child.secrets_dir == tmp_path / "secrets" / "bots" / "example_test_bot"
    assert not cfg.network_enabled and not cfg.outbound_enabled


def test_profile_snapshot_and_actions_are_immutable(tmp_path):
    data = fake_data(tmp_path)
    cfg = parse(data, tmp_path)
    data["agents"][0]["prompt"] = "changed"
    data["agents"][0]["chats"][0]["actions"].append("send")
    assert cfg.agent_profiles[0]["prompt"] != "changed"
    assert cfg.agent_profiles[0]["chats"][0]["actions"] == ("history", "events")
    with pytest.raises(TypeError):
        cfg.agent_profiles[0]["enabled"] = False


@pytest.mark.parametrize("field,value", [
    ("id", "zeta"), ("auth_principal", "agent-zeta"),
    ("telegram_username", "EXAMPLE_TEST_BOT"),
])
def test_duplicate_ids_principals_or_normalized_usernames_rejected(tmp_path, field, value):
    data = fake_data(tmp_path)
    another = profile(id="support", auth_principal="agent-support", telegram_username="support_test_bot")
    another[field] = value
    data["agents"].append(another)
    with pytest.raises(RuntimeConfigError, match="agent profiles"):
        parse(data, tmp_path)


def test_multiple_distinct_active_bots_have_disjoint_child_auth_policy_and_state(tmp_path):
    data = fake_data(tmp_path)
    data["agents"].append(profile(id="support", auth_principal="agent-support", telegram_username="support_test_bot", enabled=True,
                                  chats=[{"chat_id": -1002, "type": "group", "title": "SUPPORT synthetic", "actions": ["history"]}]))
    data["auth"]["credentials"]["fixture-support"] = "agent-support"
    cfg = parse(data, tmp_path)
    assert set(cfg.bot_configs) == {"example_test_bot", "support_test_bot"}
    assert cfg.agent_bindings == {"agent-zeta": "example_test_bot", "agent-support": "support_test_bot"}
    assert cfg.auth["credentials"] == {"fixture-zeta": "agent-zeta", "fixture-support": "agent-support"}
    first, second = cfg.bot_configs["example_test_bot"], cfg.bot_configs["support_test_bot"]
    assert first.principals == ("agent-zeta",) and second.principals == ("agent-support",)
    assert first.auth["credentials"] == {"fixture-zeta": "agent-zeta"}
    assert second.auth["credentials"] == {"fixture-support": "agent-support"}
    assert first.state_dir != second.state_dir
    assert second.state_dir == tmp_path / "state" / "bots" / "support_test_bot"
    zeta = FakeAuthenticator({"fixture-zeta": "agent-zeta"}).authenticate("Bearer fixture-zeta")
    with pytest.raises(GatewayDenied):
        second.policy.require(zeta, "history", Scope(-1002))
    with pytest.raises(TypeError):
        cfg.bot_configs["other_bot"] = first


def test_duplicate_expected_live_bot_ids_rejected_without_secret_reads(tmp_path):
    data = fake_data(tmp_path)
    data["mode"] = "live"
    data["agents"].append(profile(id="support", auth_principal="agent-support", telegram_username="support_test_bot", enabled=True, expected_bot_id=5001))
    with pytest.raises(RuntimeConfigError, match="agent profiles"):
        parse(data, tmp_path)


@pytest.mark.parametrize("mode", ["fake", "live"])
def test_non_disabled_catalog_requires_an_active_agent(tmp_path, mode):
    with pytest.raises(RuntimeConfigError, match="active agents"):
        parse({"version": 1, "mode": mode, "agents": [profile()]}, tmp_path)


def test_per_agent_approval_is_scoped_to_its_child(tmp_path):
    data = fake_data(tmp_path)
    data["agents"][0]["approval"] = {"owner_ids": [9001], "review_scope": {"chat_id": -1001, "topic_id": 7}}
    data["outbound_enabled"] = True
    cfg = parse(data, tmp_path)
    assert cfg.owner_ids == () and cfg.review_scope is None
    assert cfg.bot_configs["example_test_bot"].owner_ids == (9001,)
    assert cfg.bot_configs["example_test_bot"].review_scope == Scope(-1001, 7)


@pytest.mark.parametrize("field,value", [
    ("telegram_username", "@@example_test_bot"), ("telegram_username", "../escape"),
    ("enabled", "false"), ("auth_principal", "bad principal"),
    ("expected_bot_id", True), ("expected_bot_id", -1), ("name", ""),
    ("prompt", "x" * 8193), ("chats", {}), ("unexpected", "value"),
], ids=["double-at", "bad-username", "string-enabled", "bad-principal", "boolean-bot-id", "negative-bot-id", "empty-name", "long-prompt", "bad-chats", "unknown-agent-field"])
def test_invalid_agent_fields_rejected(tmp_path, field, value):
    data = fake_data(tmp_path)
    data["agents"][0][field] = value
    with pytest.raises(RuntimeConfigError):
        parse(data, tmp_path)


@pytest.mark.parametrize("field,value", [
    ("chat_id", 1001), ("type", "private"), ("type", "group"),
    ("topic_id", 0), ("actions", ["delete"]), ("actions", ["history", "history"]),
    ("permissions", ["send"]), ("title", "bad\ntitle"),
])
def test_invalid_or_ambiguous_chat_actions_rejected(tmp_path, field, value):
    data = fake_data(tmp_path)
    data["agents"][0]["chats"][0][field] = value
    with pytest.raises(RuntimeConfigError):
        parse(data, tmp_path)


@pytest.mark.parametrize("field,value", [("policy", {"principals": {}}), ("bot", {}), ("agent_bindings", {}), ("approval", {}), ("unexpected", True)])
def test_unified_schema_rejects_mixed_or_unknown_root_fields(tmp_path, field, value):
    data = fake_data(tmp_path)
    data[field] = value
    with pytest.raises(RuntimeConfigError, match="agent profiles"):
        parse(data, tmp_path)


def test_auth_mapping_must_target_active_authenticated_principal(tmp_path):
    data = fake_data(tmp_path)
    data["auth"]["credentials"] = {"fixture-zeta": "zeta"}
    with pytest.raises(RuntimeConfigError, match="authentication principal"):
        parse(data, tmp_path)


def test_same_chat_topics_share_one_approved_group_but_duplicate_scope_rejected(tmp_path):
    data = fake_data(tmp_path)
    other = copy.deepcopy(data["agents"][0]["chats"][0])
    other["topic_id"] = 8
    data["agents"][0]["chats"].append(other)
    cfg = parse(data, tmp_path)
    assert len(cfg.approved_groups) == 1
    data["agents"][0]["chats"][1]["topic_id"] = 7
    with pytest.raises(RuntimeConfigError):
        parse(data, tmp_path)


def test_explicit_all_topics_is_preserved_in_profile_child_and_merged_policy(tmp_path, monkeypatch):
    from telegram_gateway import local_secrets
    data = fake_data(tmp_path)
    chat = data["agents"][0]["chats"][0]
    chat.pop("topic_id")
    chat["all_topics"] = True
    def denied(*args, **kwargs):
        raise AssertionError("grant compilation must not read files or secrets")
    monkeypatch.setattr(Path, "open", denied)
    monkeypatch.setattr(Path, "stat", denied)
    monkeypatch.setattr(Path, "resolve", denied)
    monkeypatch.setattr(local_secrets, "load_bot_token", denied)
    cfg = parse(data, tmp_path)
    principal = FakeAuthenticator({"fixture-zeta": "agent-zeta"}).authenticate("Bearer fixture-zeta")
    child = cfg.bot_configs["example_test_bot"]
    assert cfg.agent_profiles[0]["chats"][0]["all_topics"] is True
    for policy in (cfg.policy, child.policy):
        assert policy.allowed_scopes(principal, "history") == (Scope(-1001, all_topics=True),)
        for topic in (None, 7, 111):
            policy.require(principal, "history", Scope(-1001, topic))
        with pytest.raises(GatewayDenied):
            policy.require(principal, "send", Scope(-1001, 111))
        with pytest.raises(GatewayDenied):
            policy.require(principal, "history", Scope(-1002, 111))


@pytest.mark.parametrize("flag", [False, None, 0, 1, "true", []])
def test_unified_all_topics_strict_flag_and_no_implicit_topic_expansion(tmp_path, flag):
    data = fake_data(tmp_path)
    chat = data["agents"][0]["chats"][0]
    chat["all_topics"] = flag
    if flag is not False:
        with pytest.raises(RuntimeConfigError):
            parse(data, tmp_path)
        return
    cfg = parse(data, tmp_path)
    principal = FakeAuthenticator({"fixture-zeta": "agent-zeta"}).authenticate("Bearer fixture-zeta")
    cfg.policy.require(principal, "history", Scope(-1001, 7))
    for scope in (Scope(-1001), Scope(-1001, 8), Scope(-1001, all_topics=True)):
        with pytest.raises(GatewayDenied):
            cfg.policy.require(principal, "history", scope)


def test_unified_whole_group_rejects_fixed_topic_positive_chat_and_unknown_flag(tmp_path):
    for change in ({"all_topics": True}, {"all_topics": True, "topic_id": None, "chat_id": 1001},
                   {"all_topic": True, "topic_id": None}):
        data = fake_data(tmp_path)
        data["agents"][0]["chats"][0].update(change)
        with pytest.raises(RuntimeConfigError):
            parse(data, tmp_path)


def test_disabled_whole_group_profile_never_creates_runtime_grants(tmp_path):
    entry = profile(chats=[{"chat_id": -1001, "type": "supergroup", "title": "Synthetic group",
                           "all_topics": True, "actions": ["history"]}])
    cfg = parse({"version": 1, "mode": "disabled", "agents": [entry]}, tmp_path)
    assert cfg.agent_profiles[0]["chats"][0]["all_topics"] is True
    assert cfg.principals == () and cfg.bot_configs == {} and cfg.agent_bindings == {}


def test_unified_unthreaded_and_all_topics_are_distinct_explicit_grants(tmp_path):
    data = fake_data(tmp_path)
    data["agents"][0]["chats"] = [
        {"chat_id": -1001, "type": "supergroup", "title": "Synthetic group", "actions": ["history"]},
        {"chat_id": -1001, "type": "supergroup", "title": "Synthetic group", "all_topics": True, "actions": ["events"]},
    ]
    cfg = parse(data, tmp_path)
    principal = FakeAuthenticator({"fixture-zeta": "agent-zeta"}).authenticate("Bearer fixture-zeta")
    assert cfg.policy.allowed_scopes(principal, "history") == (Scope(-1001),)
    assert cfg.policy.allowed_scopes(principal, "events") == (Scope(-1001, all_topics=True),)
    with pytest.raises(GatewayDenied):
        cfg.policy.require(principal, "history", Scope(-1001, 7))
