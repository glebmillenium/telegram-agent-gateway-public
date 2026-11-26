"""Standing send configuration is tested using in-memory synthetic profiles only."""
import copy
from pathlib import Path

import pytest

from telegram_gateway.auth import FakeAuthenticator
from telegram_gateway.policy import GatewayDenied, Scope
from telegram_gateway.runtime_config import RuntimeConfig, RuntimeConfigError


def profile(name="alpha", *, send=True):
    chats = [{"chat_id": -1001, "type": "supergroup", "title": "Synthetic group", "all_topics": True,
              "actions": ["history", "events", "draft"]}]
    if send:
        chats.append({"chat_id": -1001, "type": "supergroup", "title": "Synthetic group", "actions": ["send"]})
    return {"id": name, "name": "Synthetic " + name, "purpose": "test metadata", "prompt": "inert",
            "enabled": True, "telegram_username": name + "_test_bot", "auth_principal": "agent-" + name,
            "expected_bot_id": 70001 if name == "alpha" else 70002, "chats": chats}


def config(tmp_path):
    agent = profile()
    agent["standing_send"] = {"purpose": "gateway_technical_test", "chat_id": -1001, "topic_id": None}
    return {"version": 1, "mode": "fake", "state_dir": str(tmp_path / "state"),
            "outbound_enabled": True, "agents": [agent],
            "auth": {"mode": "fake", "credentials": {"fixture-alpha": "agent-alpha"}}}


def parse(data, tmp_path):
    return RuntimeConfig.from_dict(data, project_root=tmp_path / "code")


def test_standing_binding_inferred_immutable_and_does_not_widen_grants(tmp_path):
    data = config(tmp_path)
    cfg = parse(data, tmp_path)
    child = cfg.bot_configs["alpha_test_bot"]
    assert cfg.standing_send is None
    assert child.owner_ids == () and child.review_scope is None and child.outbound_enabled
    assert child.standing_send == {"purpose": "gateway_technical_test", "principal_id": "agent-alpha",
                                  "bot_reference": "alpha_test_bot", "expected_bot_id": 70001,
                                  "chat_id": -1001, "topic_id": None}
    data["agents"][0]["standing_send"]["chat_id"] = -1002
    assert child.standing_send["chat_id"] == -1001
    with pytest.raises(TypeError):
        child.standing_send["principal_id"] = "foreign"
    p = FakeAuthenticator({"fixture": "agent-alpha"}).authenticate("Bearer fixture")
    child.policy.require(p, "send", Scope(-1001))
    child.policy.require(p, "history", Scope(-1001, 77))
    child.policy.require(p, "draft", Scope(-1001, 77))
    for permission, scope in (("send", Scope(-1001, 77)), ("send", Scope(-1001, all_topics=True)),
                              ("forward", Scope(-1001)), ("send", Scope(-1002))):
        with pytest.raises(GatewayDenied):
            child.policy.require(p, permission, scope)


def test_absent_and_null_defaults_never_authorize_ownerless_outbound(tmp_path):
    for omitted in (False, True):
        data = config(tmp_path)
        if omitted:
            data["agents"][0].pop("standing_send")
        else:
            data["agents"][0]["standing_send"] = None
        with pytest.raises(RuntimeConfigError):
            parse(data, tmp_path)
        data["outbound_enabled"] = False
        cfg = parse(data, tmp_path)
        assert cfg.bot_configs["alpha_test_bot"].standing_send is None


@pytest.mark.parametrize("field,value", [
    ("purpose", "arbitrary_send"), ("purpose", None), ("chat_id", 1001), ("chat_id", True),
    ("topic_id", "general"), ("topic_id", 0), ("topic_id", True),
    ("all_topics", None), ("all_topics", 1), ("all_topics", "true"), ("principal_id", "foreign"),
    ("bot_reference", "foreign_bot"), ("expected_bot_id", 70002),
    ("max_messages", 999), ("max_text_chars", 9999), ("enabled", True),
])
def test_invalid_or_supplied_binding_fields_rejected(tmp_path, field, value):
    data = config(tmp_path)
    data["agents"][0]["standing_send"][field] = value
    with pytest.raises(RuntimeConfigError):
        parse(data, tmp_path)


@pytest.mark.parametrize("bad", [True, False, [], "enabled", {}, {"chat_id": -1001}])
def test_nonobject_or_incomplete_standing_declaration_rejected(tmp_path, bad):
    data = config(tmp_path)
    data["agents"][0]["standing_send"] = bad
    with pytest.raises(RuntimeConfigError):
        parse(data, tmp_path)


@pytest.mark.parametrize("change", ["wildcard_only", "wrong_topic", "wrong_chat", "no_send", "no_bot_id", "inactive"])
def test_exact_send_grant_and_active_bot_identity_required(tmp_path, change):
    data = config(tmp_path)
    agent = data["agents"][0]
    if change == "wildcard_only":
        agent["chats"][0]["actions"].append("send")
        agent["chats"].pop()
    elif change == "wrong_topic":
        agent["standing_send"]["topic_id"] = 7
    elif change == "wrong_chat":
        agent["standing_send"]["chat_id"] = -1002
    elif change == "no_send":
        agent["chats"].pop()
    elif change == "no_bot_id":
        agent.pop("expected_bot_id")
    elif change == "inactive":
        agent["enabled"] = False
    with pytest.raises(RuntimeConfigError):
        parse(data, tmp_path)


@pytest.mark.parametrize("change", ["wildcard_send", "foreign_topic_send", "foreign_chat_send", "exact_forward", "wildcard_forward"])
def test_ownerless_outbound_cannot_have_uncovered_send_or_forward(tmp_path, change):
    data = config(tmp_path)
    chats = data["agents"][0]["chats"]
    if change == "wildcard_send":
        chats[0]["actions"].append("send")
    elif change == "wildcard_forward":
        chats[0]["actions"].append("forward")
    elif change == "exact_forward":
        chats[1]["actions"].append("forward")
    else:
        extra = copy.deepcopy(chats[1])
        extra["topic_id"] = 8
        if change == "foreign_chat_send":
            extra["chat_id"] = -1002
        chats.append(extra)
    with pytest.raises(RuntimeConfigError, match="unreviewed"):
        parse(data, tmp_path)


def test_existing_owner_review_validation_not_weakened(tmp_path):
    data = config(tmp_path)
    data["agents"][0]["approval"] = {"owner_ids": [99]}
    with pytest.raises(RuntimeConfigError):
        parse(data, tmp_path)
    data["agents"][0]["approval"] = {"review_scope": {"chat_id": -1001}}
    with pytest.raises(RuntimeConfigError):
        parse(data, tmp_path)
    data["agents"][0]["approval"] = {"owner_ids": [99], "review_scope": {"chat_id": -1001}}
    data["agents"][0].pop("standing_send")
    child = parse(data, tmp_path).bot_configs["alpha_test_bot"]
    assert child.standing_send is None and child.owner_ids == (99,)


def test_two_profiles_receive_distinct_bindings_and_readonly_sibling_has_no_send_gate(tmp_path):
    data = config(tmp_path)
    data["agents"].append(profile("beta", send=False))
    data["auth"]["credentials"]["fixture-beta"] = "agent-beta"
    cfg = parse(data, tmp_path)
    assert cfg.outbound_enabled and cfg.bot_configs["alpha_test_bot"].outbound_enabled
    beta = cfg.bot_configs["beta_test_bot"]
    assert not beta.outbound_enabled and beta.standing_send is None
    data["agents"][1] = profile("beta")
    data["agents"][1]["standing_send"] = dict(data["agents"][0]["standing_send"])
    cfg = parse(data, tmp_path)
    assert cfg.bot_configs["beta_test_bot"].standing_send["principal_id"] == "agent-beta"
    assert cfg.bot_configs["beta_test_bot"].standing_send["expected_bot_id"] == 70002
    assert cfg.bot_configs["alpha_test_bot"].standing_send["principal_id"] == "agent-alpha"


def test_standing_cannot_be_shared_by_multiple_lowlevel_principals(tmp_path):
    data = {"version": 1, "mode": "fake", "state_dir": str(tmp_path / "state"), "outbound_enabled": True,
            "bot": {"reference": "alpha_test_bot", "expected_bot_id": 70001,
                    "approved_groups": [{"chat_id": -1001, "type": "supergroup", "title": "Synthetic group"}]},
            "agent_bindings": {"alpha": "alpha_test_bot", "beta": "alpha_test_bot"},
            "policy": {"principals": {name: [{"chat_id": -1001, "permissions": ["draft", "send"]}] for name in ("alpha", "beta")}},
            "auth": {"mode": "fake", "credentials": {"fixture-alpha": "alpha", "fixture-beta": "beta"}},
            "standing_send": {"purpose": "gateway_technical_test", "chat_id": -1001}}
    with pytest.raises(RuntimeConfigError, match="identity"):
        parse(data, tmp_path)


def test_parser_performs_no_filesystem_env_or_secret_reads(tmp_path, monkeypatch):
    data = config(tmp_path)
    def forbidden(*args, **kwargs):
        pytest.fail("Pure parser attempted filesystem or secret access")
    for method in ("open", "stat", "resolve"):
        monkeypatch.setattr(Path, method, forbidden)
    monkeypatch.setattr("telegram_gateway.runtime_config.os.getenv", forbidden)
    monkeypatch.setattr("telegram_gateway.runtime_config.load_secret", forbidden)
    cfg = parse(data, tmp_path)
    assert cfg.bot_configs["alpha_test_bot"].standing_send["purpose"] == "gateway_technical_test"


def all_topics_config(tmp_path):
    data = config(tmp_path)
    agent = data["agents"][0]
    agent["standing_send"]["all_topics"] = True
    agent["chats"][0]["actions"].append("send")
    return data


def test_all_topics_standing_covers_only_same_group_and_preserves_flag(tmp_path):
    data = all_topics_config(tmp_path)
    extra = copy.deepcopy(data["agents"][0]["chats"][1])
    extra["topic_id"] = 77
    data["agents"][0]["chats"].append(extra)
    cfg = parse(data, tmp_path)
    child = cfg.bot_configs["alpha_test_bot"]
    assert child.standing_send["all_topics"] is True
    assert cfg.agent_profiles[0]["standing_send"]["all_topics"] is True
    assert child.standing_send["chat_id"] == -1001 and child.standing_send["topic_id"] is None
    principal = FakeAuthenticator({"fixture": "agent-alpha"}).authenticate("Bearer fixture")
    for scope in (Scope(-1001), Scope(-1001, 77), Scope(-1001, all_topics=True)):
        child.policy.require(principal, "send", scope)
    with pytest.raises(GatewayDenied):
        child.policy.require(principal, "send", Scope(-1002, 77))


def test_explicit_false_keeps_legacy_exact_standing_rule(tmp_path):
    data = config(tmp_path)
    data["agents"][0]["standing_send"]["all_topics"] = False
    child = parse(data, tmp_path).bot_configs["alpha_test_bot"]
    assert "all_topics" not in child.standing_send


@pytest.mark.parametrize("change", ["missing_wildcard_grant", "fixed_topic", "foreign_chat", "forward"])
def test_all_topics_standing_cannot_infer_or_expand_authority(tmp_path, change):
    data = all_topics_config(tmp_path)
    agent = data["agents"][0]
    if change == "missing_wildcard_grant":
        agent["chats"][0]["actions"].remove("send")
    elif change == "fixed_topic":
        agent["standing_send"]["topic_id"] = 77
    elif change == "foreign_chat":
        extra = copy.deepcopy(agent["chats"][1])
        extra["chat_id"] = -1002
        agent["chats"].append(extra)
    else:
        agent["chats"][0]["actions"].append("forward")
    with pytest.raises(RuntimeConfigError):
        parse(data, tmp_path)


def test_lowlevel_all_topics_standing_requires_explicit_matching_wildcard_grant(tmp_path):
    from telegram_gateway.agent_config import compile_agent_config
    data = all_topics_config(tmp_path)
    _, children, _, _ = compile_agent_config(data)
    raw = children["alpha_test_bot"]
    child = parse(raw, tmp_path)
    assert child.standing_send["all_topics"] is True
    raw["policy"]["principals"]["agent-alpha"][0]["permissions"].remove("send")
    with pytest.raises(RuntimeConfigError, match="standing send exact grant"):
        parse(raw, tmp_path)
