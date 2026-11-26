"""Configuration checks use disposable synthetic paths and fixtures only."""
import copy
import hashlib
import json
import os
from pathlib import Path

import pytest

from telegram_gateway.policy import Scope
from telegram_gateway.runtime_config import RuntimeConfig, RuntimeConfigError, SecretRef, SecretUnavailable, load_secret


@pytest.fixture
def config_data(tmp_path):
    return {
        "version": 1, "mode": "fake", "state_dir": str(tmp_path / "state"),
        "policy": {"principals": {
            "zeta": [{"chat_id": -1001, "topic_id": 7, "permissions": ["history", "events", "draft", "send"]}],
            "support": [{"chat_id": -1002, "permissions": ["history", "events"]}],
        }},
        "auth": {"mode": "fake", "credentials": {"fixture-zeta": "zeta", "fixture-support": "support"}},
        "bot": {"approved_groups": [
            {"chat_id": -1001, "type": "supergroup", "title": "Fake zeta group"},
            {"chat_id": -1002, "type": "group", "title": "Fake SUPPORT group"},
        ]},
        "approval": {"owner_ids": [9001], "review_scope": {"chat_id": -1001, "topic_id": 7}},
    }


def parse(data, tmp_path):
    return RuntimeConfig.from_dict(data, project_root=tmp_path / "code")


def live_data(config_data, tmp_path):
    data = copy.deepcopy(config_data)
    data.update(mode="live", secrets_dir=str(tmp_path / "secrets"))
    data["auth"] = {"mode": "static", "token_digests": {hashlib.sha256(b"PUBLIC_FIXED_SYNTHETIC_TOKEN_FOR_TESTS").hexdigest(): "zeta"}}
    data["bot"].update(reference="example_test_bot", token_ref={"env": "SYNTHETIC_GATEWAY_BOT_TOKEN"}, expected_bot_id=5001)
    data["agent_bindings"] = {principal: "example_test_bot" for principal in data["policy"]["principals"]}
    return data


def oauth_data(config_data, tmp_path):
    data = live_data(config_data, tmp_path)
    data["public_base_url"] = "https://gateway.test.example"
    data["auth"] = {
        "mode": "oauth", "issuer": "https://issuer.test.example", "audience": "https://gateway.test.example/mcp",
        "jwks_file": str(tmp_path / "public-config" / "jwks.json"),
        "subjects": [{"issuer": "https://issuer.test.example", "sub": "subject-zeta", "principal": "zeta"}],
    }
    return data


def test_disabled_default_is_empty_and_inert(tmp_path):
    cfg = parse({"version": 1}, tmp_path)
    assert cfg.mode == "disabled" and cfg.principals == () and cfg.auth_mode == "disabled"
    assert cfg.state_dir is None and cfg.secrets_dir is None and cfg.bot_token_ref is None
    assert not cfg.network_enabled and not cfg.outbound_enabled and not cfg.allowed_callbacks
    assert cfg.bot_reference is None and cfg.agent_bindings == {}


def test_fake_normalized_contract(config_data, tmp_path):
    cfg = parse(config_data, tmp_path)
    assert cfg.principals == ("support", "zeta")
    assert cfg.bind_host == "127.0.0.1" and cfg.bind_port == 8765
    assert cfg.allowed_hosts == ("127.0.0.1:8765",) and cfg.allowed_origins == ()
    assert cfg.auth_mode == "fake" and cfg.auth["credentials"]["fixture-zeta"] == "zeta"
    assert cfg.review_scope == Scope(-1001, 7) and cfg.owner_ids == (9001,)
    assert cfg.state_dir == tmp_path / "state" and cfg.poll_interval_seconds == 1
    assert cfg.bot_reference is None and cfg.agent_bindings == {}
    config_data["bot"]["approved_groups"][0]["title"] = "changed after parse"
    assert cfg.approved_groups[0]["title"] == "Fake zeta group"


def test_live_without_network_flag_can_be_checked(config_data, tmp_path):
    cfg = parse(live_data(config_data, tmp_path), tmp_path)
    assert cfg.mode == "live" and cfg.network_enabled is False and cfg.outbound_enabled is False
    assert cfg.expected_bot_id == 5001 and cfg.bot_token_ref.kind == "env"
    assert cfg.bot_reference == "example_test_bot"
    assert cfg.agent_bindings == {"zeta": "example_test_bot", "support": "example_test_bot"}


@pytest.mark.parametrize("omitted", ["both", "bindings", "reference"])
def test_live_requires_explicit_complete_agent_bot_binding(config_data, tmp_path, omitted):
    data = live_data(config_data, tmp_path)
    if omitted in ("both", "bindings"):
        data.pop("agent_bindings")
    if omitted in ("both", "reference"):
        data["bot"].pop("reference")
    with pytest.raises(RuntimeConfigError, match="agent bot bindings"):
        parse(data, tmp_path)


@pytest.mark.parametrize("bindings", [
    {}, {"zeta": "example_test_bot"},
    {"zeta": "example_test_bot", "support": "example_test_bot", "outsider": "example_test_bot"},
    {"zeta": "example_test_bot", "support": "another_test_bot"},
    {"zeta": "example_test_bot", "support": None}, [], None,
])
def test_binding_rejects_foreign_principal_missing_principal_or_unknown_bot(config_data, tmp_path, bindings):
    data = live_data(config_data, tmp_path)
    data["agent_bindings"] = bindings
    with pytest.raises(RuntimeConfigError, match="agent bot bindings"):
        parse(data, tmp_path)


@pytest.mark.parametrize("reference", [None, 1, "@@example_test_bot", "../escape", ""])
def test_bot_reference_must_be_explicit_valid_name(config_data, tmp_path, reference):
    data = live_data(config_data, tmp_path)
    data["bot"]["reference"] = reference
    with pytest.raises(RuntimeConfigError, match="bot reference"):
        parse(data, tmp_path)


def test_binding_snapshot_is_immutable_and_does_not_expand_policy(config_data, tmp_path):
    config_data["bot"]["reference"] = "example_test_bot"
    config_data["agent_bindings"] = {"zeta": "example_test_bot", "support": "example_test_bot"}
    cfg = parse(config_data, tmp_path)
    config_data["agent_bindings"]["zeta"] = "changed_test_bot"
    assert cfg.agent_bindings["zeta"] == "example_test_bot"
    with pytest.raises(TypeError):
        cfg.agent_bindings["zeta"] = "another_test_bot"
    from telegram_gateway.auth import FakeAuthenticator
    principal = FakeAuthenticator({"fixture-support": "support"}).authenticate("Bearer fixture-support")
    assert cfg.policy.allowed_scopes(principal, "history") == (Scope(-1002),)
    assert cfg.policy.allowed_scopes(principal, "send") == ()


def test_local_bot_secret_must_match_adapter_reference(config_data, tmp_path):
    data = live_data(config_data, tmp_path)
    data["bot"]["token_ref"] = {"local_bot": "another_test_bot"}
    with pytest.raises(RuntimeConfigError, match="bot secret reference"):
        parse(data, tmp_path)
    data["bot"]["token_ref"] = {"local_bot": "example_test_bot"}
    assert parse(data, tmp_path).bot_token_ref.value == "example_test_bot"


def test_bot_reference_and_local_secret_use_shared_username_normalization(config_data, tmp_path):
    data = live_data(config_data, tmp_path)
    data["bot"]["reference"] = "@EXAMPLE_TEST_BOT"
    data["bot"]["token_ref"] = {"local_bot": "@Example_Test_Bot"}
    cfg = parse(data, tmp_path)
    assert cfg.bot_reference == "example_test_bot"
    assert cfg.bot_token_ref.value == "example_test_bot"


def test_disabled_binding_template_is_inert_without_auth_ids_directories_or_reads(tmp_path, monkeypatch):
    from telegram_gateway import local_secrets
    data = {
        "version": 1, "mode": "disabled",
        "policy": {"principals": {"zeta": []}},
        "agent_bindings": {"zeta": "coordinator_demo_bot"},
        "bot": {"reference": "coordinator_demo_bot", "token_ref": {"local_bot": "coordinator_demo_bot"}, "approved_groups": []},
    }
    def denied(*args, **kwargs):
        raise AssertionError("disabled binding template must not inspect secrets or filesystem")
    monkeypatch.setattr(Path, "open", denied)
    monkeypatch.setattr(Path, "resolve", denied)
    monkeypatch.setattr(Path, "stat", denied)
    monkeypatch.setattr(local_secrets, "load_bot_token", denied)
    cfg = parse(data, tmp_path)
    assert cfg.mode == "disabled" and cfg.principals == ("zeta",)
    assert cfg.bot_reference == "coordinator_demo_bot" and cfg.agent_bindings == {"zeta": "coordinator_demo_bot"}
    assert cfg.auth_mode == "disabled" and cfg.expected_bot_id is None and cfg.approved_groups == ()
    assert cfg.state_dir is None and cfg.secrets_dir is None
    assert not cfg.network_enabled and not cfg.outbound_enabled
    from telegram_gateway.auth import FakeAuthenticator
    principal = FakeAuthenticator({"fixture-zeta": "zeta"}).authenticate("Bearer fixture-zeta")
    assert cfg.policy.allowed_scopes(principal, "history") == ()


def test_oauth_normalized_without_jwks_read(config_data, tmp_path):
    cfg = parse(oauth_data(config_data, tmp_path), tmp_path)
    assert cfg.auth_mode == "oauth"
    assert cfg.auth["subject_principals"] == {("https://issuer.test.example", "subject-zeta"): "zeta"}
    assert cfg.auth["jwks_file"] == tmp_path / "public-config" / "jwks.json"
    assert cfg.auth["required_scope"] == "mcp:gateway"
    assert cfg.allowed_hosts == ("127.0.0.1:8765", "gateway.test.example")


@pytest.mark.parametrize("kind", ["file", "dpapi_file"])
def test_parser_does_not_touch_reference_files_environment_or_resolve(config_data, tmp_path, monkeypatch, kind):
    data = oauth_data(config_data, tmp_path)
    data["bot"]["token_ref"] = {kind: str(tmp_path / "secrets" / "not-created.token")}
    def denied(*args, **kwargs):
        raise AssertionError("config parsing must not inspect referenced filesystem/environment")
    monkeypatch.setattr(Path, "open", denied)
    monkeypatch.setattr(Path, "stat", denied)
    monkeypatch.setattr(Path, "resolve", denied)
    monkeypatch.setattr(os, "getenv", denied)
    cfg = parse(data, tmp_path)
    assert cfg.mode == "live" and cfg.bot_token_ref.kind == kind


@pytest.mark.parametrize("patch", [
    {"unknown": True}, {"version": True}, {"version": 2}, {"mode": "auto"},
    {"bind": {"host": "0.0.0.0"}}, {"bind": {"host": "localhost"}}, {"bind": {"port": True}},
    {"bind": {"port": 80}}, {"bind": {"port": 65536}}, {"bind": {"extra": "x"}},
    {"state_dir": "relative/state"}, {"network_enabled": "false"}, {"network_enabled": True},
    {"outbound_enabled": 1}, {"poll_interval_seconds": 0}, {"poll_interval_seconds": float("nan")},
    {"allowed_hosts": ["*"]}, {"allowed_hosts": ["*.example.com"]}, {"allowed_hosts": []},
    {"allowed_hosts": ["a.example", "a.example"]}, {"allowed_origins": ["https://example.com/path"]},
])
def test_invalid_root_fields_fail_closed(config_data, tmp_path, patch):
    config_data.update(patch)
    with pytest.raises(RuntimeConfigError):
        parse(config_data, tmp_path)


def test_paths_keep_code_state_secrets_separate(config_data, tmp_path):
    for state, secrets in [
        (tmp_path / "code" / "state", tmp_path / "secrets"),
        (tmp_path / "state", tmp_path / "code" / "secrets"),
        (tmp_path / "state", tmp_path / "state" / "secrets"),
        (tmp_path / "secrets" / "state", tmp_path / "secrets"),
        (tmp_path / "same", tmp_path / "same"),
    ]:
        data = live_data(config_data, tmp_path)
        data.update(state_dir=str(state), secrets_dir=str(secrets))
        with pytest.raises(RuntimeConfigError):
            parse(data, tmp_path)


@pytest.mark.parametrize("which", ["token_ref", "expected_bot_id", "approved_groups"])
def test_live_bot_prerequisites_required(config_data, tmp_path, which):
    data = live_data(config_data, tmp_path)
    data["bot"].pop(which)
    with pytest.raises(RuntimeConfigError):
        parse(data, tmp_path)


def test_fake_rejects_real_secret_reference(config_data, tmp_path):
    config_data["bot"]["token_ref"] = {"env": "SYNTHETIC_BOT_TOKEN"}
    with pytest.raises(RuntimeConfigError):
        parse(config_data, tmp_path)


def test_fake_auth_cannot_enter_live_or_disabled(config_data, tmp_path):
    data = live_data(config_data, tmp_path)
    data["auth"] = config_data["auth"]
    with pytest.raises(RuntimeConfigError):
        parse(data, tmp_path)
    config_data["mode"] = "disabled"
    with pytest.raises(RuntimeConfigError):
        parse(config_data, tmp_path)


@pytest.mark.parametrize("bad_group", [
    {"chat_id": 1001, "type": "group", "title": "fake"},
    {"chat_id": -1001, "type": "private", "title": "fake"},
    {"chat_id": -1001, "type": "group", "title": "fake", "username": "guess"},
    {"chat_id": -1001, "type": "supergroup"},
])
def test_only_explicit_group_metadata(config_data, tmp_path, bad_group):
    config_data["bot"]["approved_groups"][0] = bad_group
    with pytest.raises(RuntimeConfigError):
        parse(config_data, tmp_path)


def test_scope_must_belong_to_approved_group_and_topics_to_supergroup(config_data, tmp_path):
    data = copy.deepcopy(config_data)
    data["policy"]["principals"]["zeta"][0]["chat_id"] = -9999
    with pytest.raises(RuntimeConfigError):
        parse(data, tmp_path)
    config_data["bot"]["approved_groups"][0]["type"] = "group"
    with pytest.raises(RuntimeConfigError):
        parse(config_data, tmp_path)


def test_low_level_all_topics_grant_stays_with_explicit_approved_group(config_data, tmp_path):
    from telegram_gateway.auth import FakeAuthenticator
    from telegram_gateway.policy import GatewayDenied
    grant = config_data["policy"]["principals"]["zeta"][0]
    grant.pop("topic_id")
    grant.update(all_topics=True, permissions=["history", "events"])
    cfg = parse(config_data, tmp_path)
    principal = FakeAuthenticator({"fixture-zeta": "zeta"}).authenticate("Bearer fixture-zeta")
    cfg.policy.require(principal, "history", Scope(-1001, 123))
    cfg.policy.require(principal, "history", Scope(-1001, all_topics=True))
    with pytest.raises(GatewayDenied):
        cfg.policy.require(principal, "history", Scope(-1002, 123))
    grant["chat_id"] = -9999
    with pytest.raises(RuntimeConfigError):
        parse(config_data, tmp_path)


@pytest.mark.parametrize("changes", [
    {"all_topics": True}, {"all_topics": 1, "topic_id": None},
    {"all_topics": None, "topic_id": None}, {"all_topics": "true", "topic_id": None},
    {"all_topics": True, "topic_id": None, "chat_id": 1001},
    {"all_topic": True, "topic_id": None},
])
def test_low_level_malformed_all_topics_fails_closed(config_data, tmp_path, changes):
    config_data["policy"]["principals"]["zeta"][0].update(changes)
    with pytest.raises(RuntimeConfigError):
        parse(config_data, tmp_path)


def test_owner_review_scope_rejects_whole_group_flag(config_data, tmp_path):
    config_data["approval"]["review_scope"] = {"chat_id": -1001, "all_topics": True}
    with pytest.raises(RuntimeConfigError):
        parse(config_data, tmp_path)


def test_auth_cannot_map_unknown_principal(config_data, tmp_path):
    config_data["auth"]["credentials"]["fixture-unknown"] = "outsider"
    with pytest.raises(RuntimeConfigError):
        parse(config_data, tmp_path)


@pytest.mark.parametrize("update", [
    {"owner_ids": [9001, 9001]}, {"owner_ids": [True]}, {"owner_ids": []},
    {"review_scope": {"chat_id": -9000}}, {"review_scope": {"chat_id": -1001, "topic_id": 0}},
])
def test_owner_scope_is_explicit(config_data, tmp_path, update):
    config_data["approval"].update(update)
    with pytest.raises(RuntimeConfigError):
        parse(config_data, tmp_path)


def test_outbound_enabled_needs_owner_review(config_data, tmp_path):
    config_data.pop("approval")
    assert parse(config_data, tmp_path).review_scope is None
    config_data["outbound_enabled"] = True
    with pytest.raises(RuntimeConfigError):
        parse(config_data, tmp_path)


@pytest.mark.parametrize("url", [
    "http://callback.example/event", "https://127.0.0.1/event", "https://10.0.0.1/event",
    "https://localhost/event", "https://x.local/event", "https://user:pass@example.com/event",
    "https://example.com/event#fragment", "https://example.com/event\r\nx:1",
])
def test_callback_allowlist_is_exact_https_public_destination(config_data, tmp_path, url):
    config_data["allowed_callbacks"] = {"zeta": [url]}
    with pytest.raises(RuntimeConfigError):
        parse(config_data, tmp_path)


def test_callback_owners_and_sensitive_repr(config_data, tmp_path):
    callback = "https://callback.example/event/fixture-opaque-id"
    config_data["allowed_callbacks"] = {"zeta": [callback]}
    cfg = parse(config_data, tmp_path)
    assert cfg.allowed_callbacks["zeta"] == (callback,)
    assert callback not in repr(cfg) and "fixture-zeta" not in repr(cfg)
    config_data["allowed_callbacks"] = {"outsider": [callback]}
    with pytest.raises(RuntimeConfigError):
        parse(config_data, tmp_path)


@pytest.mark.parametrize("change", [
    {"audience": "https://other.example/mcp"}, {"issuer": "http://issuer.test.example"},
    {"subjects": [{"issuer": "https://other.example", "sub": "subject-zeta", "principal": "zeta"}]},
    {"subjects": [{"issuer": "https://issuer.test.example", "sub": "subject-zeta", "principal": "outsider"}]},
    {"subjects": []}, {"required_scope": "gateway scope"}, {"client_secret": "MUST_NOT_BE_ACCEPTED"},
])
def test_oauth_config_pinned_to_server_resource_and_known_subjects(config_data, tmp_path, change):
    data = oauth_data(config_data, tmp_path)
    data["auth"].update(change)
    with pytest.raises(RuntimeConfigError):
        parse(data, tmp_path)


def test_jwks_public_config_must_not_overlap_code_state_or_secrets(config_data, tmp_path):
    for directory in ("code", "state", "secrets"):
        data = oauth_data(config_data, tmp_path)
        data["auth"]["jwks_file"] = str(tmp_path / directory / "jwks.json")
        with pytest.raises(RuntimeConfigError):
            parse(data, tmp_path)


def test_duplicate_json_members_rejected(tmp_path):
    path = tmp_path / "duplicate-config.json"
    path.write_text('{"version":1,"mode":"disabled","mode":"live"}', encoding="utf-8")
    with pytest.raises(RuntimeConfigError):
        RuntimeConfig.load(path, project_root=tmp_path / "code")
    path.write_text('{"version":1,"bind":{"port":8765,"port":9000}}', encoding="utf-8")
    with pytest.raises(RuntimeConfigError):
        RuntimeConfig.load(path, project_root=tmp_path / "code")


def test_load_reads_only_selected_json(config_data, tmp_path):
    path = tmp_path / "fake-config.json"
    path.write_text(json.dumps(config_data), encoding="utf-8")
    assert RuntimeConfig.load(path, project_root=tmp_path / "code").mode == "fake"


@pytest.mark.parametrize("ref", [{}, {"env": "GOOD", "file": "x"}, {"value": "raw-secret"}, {"env": "BAD NAME"}, {"file": "relative"}, {"dpapi_file": "relative"}, {"dpapi_file": "x", "file": "x"}])
def test_secret_ref_is_definition_only_and_strict(tmp_path, ref):
    with pytest.raises(RuntimeConfigError):
        SecretRef.from_dict(ref, secrets_dir=tmp_path / "secrets")


@pytest.mark.parametrize("kind", ["file", "dpapi_file"])
def test_secret_ref_file_must_be_lexically_under_secrets(tmp_path, kind):
    with pytest.raises(RuntimeConfigError):
        SecretRef.from_dict({kind: str(tmp_path / "outside.token")}, secrets_dir=tmp_path / "secrets")
    with pytest.raises(RuntimeConfigError):
        SecretRef.from_dict({kind: str(tmp_path / "secrets")}, secrets_dir=tmp_path / "secrets")
    with pytest.raises(RuntimeConfigError):
        SecretRef.from_dict({kind: str(tmp_path / "secrets" / "fixture.token")}, secrets_dir=None)
    ref = SecretRef.from_dict({kind: str(tmp_path / "secrets" / "fixture.token")}, secrets_dir=tmp_path / "secrets")
    assert ref.kind == kind and "fixture.token" not in repr(ref)


def test_secret_loader_requires_explicit_live_and_reads_only_synthetic_env():
    ref = SecretRef("env", "SYNTHETIC_GATEWAY_TOKEN")
    with pytest.raises(SecretUnavailable):
        load_secret(ref, environ={"SYNTHETIC_GATEWAY_TOKEN": "PUBLIC_FAKE_ONLY"})
    assert load_secret(ref, live_mode=True, environ={"SYNTHETIC_GATEWAY_TOKEN": "PUBLIC_FAKE_ONLY"}) == "PUBLIC_FAKE_ONLY"
    with pytest.raises(SecretUnavailable, match="^Secret is unavailable$"):
        load_secret(ref, live_mode=True, environ={})


def test_secret_file_loader_only_synthetic_file_and_physical_containment(tmp_path):
    code, private = tmp_path / "code", tmp_path / "secrets"
    code.mkdir()
    private.mkdir()
    path = private / "fixture.token"
    path.write_text("PUBLIC_SYNTHETIC_TEST_VALUE\n", encoding="utf-8")
    ref = SecretRef("file", str(path))
    assert load_secret(ref, secrets_dir=private, project_root=code, live_mode=True) == "PUBLIC_SYNTHETIC_TEST_VALUE"
    with pytest.raises(SecretUnavailable):
        load_secret(SecretRef("file", str(tmp_path / "other.token")), secrets_dir=private, project_root=code, live_mode=True)


@pytest.mark.parametrize("kind", ["file", "dpapi_file"])
def test_secret_loader_rejects_resolved_escape_without_read(tmp_path, monkeypatch, kind):
    code, private = tmp_path / "code", tmp_path / "secrets"
    code.mkdir()
    private.mkdir()
    source = private / "link.token"
    outside = tmp_path / "outside.token"
    original_resolve = Path.resolve
    def resolve(path, strict=False):
        if path == source:
            return outside
        return original_resolve(path, strict=strict)
    def denied(*args, **kwargs):
        raise AssertionError("escaping secret must not be opened")
    monkeypatch.setattr(Path, "resolve", resolve)
    monkeypatch.setattr(Path, "open", denied)
    with pytest.raises(SecretUnavailable):
        load_secret(SecretRef(kind, str(source)), secrets_dir=private, project_root=code, live_mode=True)


def test_dpapi_reference_requires_live_gate_before_filesystem_or_decrypt(tmp_path, monkeypatch):
    ref = SecretRef("dpapi_file", str(tmp_path / "secrets" / "fixture.dpapi"))
    def denied(*args, **kwargs):
        raise AssertionError("a non-live call must not inspect any secret reference")
    monkeypatch.setattr(Path, "resolve", denied)
    monkeypatch.setattr(Path, "open", denied)
    with pytest.raises(SecretUnavailable, match="^Secret loading requires explicit live runtime$"):
        load_secret(ref, secrets_dir=tmp_path / "secrets")


def test_local_bot_reference_config_parse_never_reads(config_data, tmp_path, monkeypatch):
    from telegram_gateway import local_secrets
    data = live_data(config_data, tmp_path)
    data["bot"]["token_ref"] = {"local_bot": "example_test_bot"}
    def denied(*args, **kwargs):
        raise AssertionError("config parsing must not read any secret")
    monkeypatch.setattr(Path, "open", denied)
    monkeypatch.setattr(Path, "resolve", denied)
    monkeypatch.setattr(Path, "stat", denied)
    monkeypatch.setattr(local_secrets, "load_bot_token", denied)
    cfg = parse(data, tmp_path)
    assert cfg.bot_token_ref.kind == "local_bot"
    assert cfg.bot_token_ref.value == "example_test_bot"
    assert "example_test_bot" not in repr(cfg.bot_token_ref)


@pytest.mark.parametrize("value", ["@@example_bot", "../escape", "", None])
def test_local_bot_reference_rejects_invalid_names(value):
    with pytest.raises(RuntimeConfigError):
        SecretRef.from_dict({"local_bot": value}, secrets_dir=None)


def test_local_bot_runtime_only_reads_fixed_project_file_after_live_gate(tmp_path, monkeypatch):
    from telegram_gateway import local_secrets
    code = tmp_path / "fake-code"
    code.mkdir()
    path = code / "secrets.local.json"
    token = "12345:" + "A" * 35
    path.write_text(json.dumps({"version": 1, "bots": {"example_test_bot": {"token": token}}}), encoding="utf-8")
    ref = SecretRef.from_dict({"local_bot": "example_test_bot"}, secrets_dir=None)
    with pytest.raises(SecretUnavailable, match="^Secret loading requires explicit live runtime$"):
        load_secret(ref, project_root=code)
    assert load_secret(ref, project_root=code, live_mode=True) == token
    # The exception is not a general grant to read ordinary repository files.
    with pytest.raises(SecretUnavailable):
        load_secret(SecretRef("file", str(path)), secrets_dir=code, project_root=code, live_mode=True)


def test_local_bot_runtime_rejects_resolved_file_escape(tmp_path, monkeypatch):
    from telegram_gateway import local_secrets
    code = tmp_path / "fake-code"
    code.mkdir()
    source = code / "secrets.local.json"
    original_resolve = Path.resolve
    def resolve(path, strict=False):
        return tmp_path / "outside.json" if path == source else original_resolve(path, strict=strict)
    def denied(*args, **kwargs):
        raise AssertionError("escaped local bot file must not be read")
    monkeypatch.setattr(Path, "resolve", resolve)
    monkeypatch.setattr(local_secrets, "load_bot_token", denied)
    with pytest.raises(SecretUnavailable, match="^Secret is unavailable$"):
        load_secret(SecretRef("local_bot", "example_test_bot"), project_root=code, live_mode=True)


def test_dpapi_loader_receives_only_validated_synthetic_path(tmp_path, monkeypatch):
    from telegram_gateway import dpapi_store
    code, private = tmp_path / "code", tmp_path / "secrets"
    code.mkdir()
    private.mkdir()
    source = private / "fixture.dpapi"
    source.write_bytes(b"PUBLIC_SYNTHETIC_DPAPI_PLACEHOLDER")
    calls = []
    def fake_load(path):
        calls.append(path)
        return "PUBLIC_SYNTHETIC_TEST_VALUE"
    monkeypatch.setattr(dpapi_store, "load_token", fake_load)
    ref = SecretRef.from_dict({"dpapi_file": str(source)}, secrets_dir=private)
    assert load_secret(ref, secrets_dir=private, project_root=code, live_mode=True) == "PUBLIC_SYNTHETIC_TEST_VALUE"
    assert calls == [source.resolve(strict=True)]


def test_dpapi_failure_is_sanitized_without_plaintext_fallback(tmp_path, monkeypatch):
    from telegram_gateway import dpapi_store
    code, private = tmp_path / "code", tmp_path / "secrets"
    code.mkdir()
    private.mkdir()
    source = private / "fixture.dpapi"
    source.write_bytes(b"PUBLIC_PLAINTEXT_MUST_NOT_BE_RETURNED")
    def failure(path):
        raise ValueError("SYNTHETIC_EXCEPTION_DETAIL_MUST_NOT_ESCAPE")
    monkeypatch.setattr(dpapi_store, "load_token", failure)
    with pytest.raises(SecretUnavailable, match="^Secret is unavailable$") as error:
        load_secret(SecretRef("dpapi_file", str(source)), secrets_dir=private, project_root=code, live_mode=True)
    assert error.value.__suppress_context__


@pytest.mark.parametrize("invalid", [None, b"SYNTHETIC_BYTES", "", "contains spaces", "x" * 8193])
def test_dpapi_decoded_value_still_uses_runtime_secret_validation(tmp_path, monkeypatch, invalid):
    from telegram_gateway import dpapi_store
    code, private = tmp_path / "code", tmp_path / "secrets"
    code.mkdir()
    private.mkdir()
    source = private / "fixture.dpapi"
    source.write_bytes(b"PUBLIC_SYNTHETIC_DPAPI_PLACEHOLDER")
    monkeypatch.setattr(dpapi_store, "load_token", lambda path: invalid)
    with pytest.raises(SecretUnavailable, match="^Secret is unavailable$"):
        load_secret(SecretRef("dpapi_file", str(source)), secrets_dir=private, project_root=code, live_mode=True)


@pytest.mark.parametrize("field", ["state_dir", "secrets_dir"])
def test_runtime_directories_cannot_contain_the_checkout(config_data, tmp_path, field):
    data = live_data(config_data, tmp_path)
    data[field] = str(tmp_path)
    with pytest.raises(RuntimeConfigError):
        parse(data, tmp_path)


@pytest.mark.parametrize("given,expected", [
    ("https://Receiver.example", "https://receiver.example/"),
    ("https://Receiver.example.:443", "https://receiver.example/"),
    ("https://Receiver.example:443/callback?part=1", "https://receiver.example/callback?part=1"),
])
def test_callback_config_uses_same_canonical_identity_as_event_hub(config_data, tmp_path, given, expected):
    from telegram_gateway.events import _callback_url
    config_data["allowed_callbacks"] = {"zeta": [given]}
    cfg = parse(config_data, tmp_path)
    assert cfg.allowed_callbacks["zeta"] == (expected,)
    assert _callback_url(given)[0] in cfg.allowed_callbacks["zeta"]


def test_callback_config_rejects_non443_and_canonical_duplicates(config_data, tmp_path):
    for values in (["https://receiver.example:8443/event"], ["https://Receiver.example", "https://receiver.example:443/"]):
        config_data["allowed_callbacks"] = {"zeta": values}
        with pytest.raises(RuntimeConfigError):
            parse(config_data, tmp_path)


@pytest.mark.parametrize("live,expected", [(False, "https://hooks.example/test"), (True, None), (True, "http://hooks.example/test")])
def test_local_webhook_requires_live_gate_and_expected_https_before_read(live, expected, monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail("missing gate must prevent all filesystem access")
    monkeypatch.setattr(Path, "resolve", forbidden)
    monkeypatch.setattr(Path, "open", forbidden)
    ref = SecretRef.from_dict({"local_webhook": "example_routine"}, secrets_dir=None)
    with pytest.raises(SecretUnavailable):
        load_secret(ref, live_mode=live, expected_url=expected)


def test_local_webhook_key_is_bound_to_exact_canonical_url_and_fixed_project_file(tmp_path):
    project = tmp_path / "fake-project"
    project.mkdir()
    key = "CustomScheme PUBLIC_SYNTHETIC_GROK_KEY"
    (project / "secrets.local.json").write_text(json.dumps({"version": 1, "bots": {}, "webhooks": {
        "example_routine": {"url": "https://HOOKS.EXAMPLE:443/test", "authorization_header": key}}}), encoding="utf-8")
    ref = SecretRef.from_dict({"local_webhook": "example_routine"}, secrets_dir=None)
    assert load_secret(ref, live_mode=True, project_root=project, expected_url="https://hooks.example/test") == key
    with pytest.raises(SecretUnavailable, match="^Secret is unavailable$"):
        load_secret(ref, live_mode=True, project_root=project, expected_url="https://hooks.example/foreign")


def test_webhook_reference_cannot_be_a_telegram_bot_token(config_data, tmp_path):
    data = live_data(config_data, tmp_path)
    data["bot"]["token_ref"] = {"local_webhook": "example_routine"}
    with pytest.raises(RuntimeConfigError, match="bot secret reference"):
        parse(data, tmp_path)
