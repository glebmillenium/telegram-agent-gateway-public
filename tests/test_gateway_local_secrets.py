"""Only newly created fake paths; never read the project's actual secret file."""
import json
from pathlib import Path

import pytest

from telegram_gateway import local_secrets
from telegram_gateway.local_secrets import LocalSecretsError, load_bot_token, main, status, validate_bot_name

BOT = "example_test_bot"
TOKEN = "12345:" + "A" * 35  # Public fixed syntax fixture, never sent anywhere.


def write_fake(tmp_path, data=None):
    path = tmp_path / "fixture.local.json"
    if data is None:
        data = {"version": 1, "bots": {BOT: {"token": TOKEN}}}
    path.write_text(json.dumps(data), encoding="utf-8")
    return path


def test_explicit_fake_file_and_default_path_redirected_to_fake_project(tmp_path, monkeypatch):
    path = write_fake(tmp_path)
    assert load_bot_token(BOT, path=path) == TOKEN
    assert status(BOT, path=path) == {"valid": True, "bot_present": True, "token_configured": True}
    monkeypatch.setattr(local_secrets, "_PROJECT", tmp_path)
    (tmp_path / "secrets.local.json").write_bytes(path.read_bytes())
    assert load_bot_token(BOT) == TOKEN


def test_empty_placeholder_is_valid_but_not_loadable(tmp_path):
    path = write_fake(tmp_path, {"version": 1, "bots": {BOT: {"token": ""}}})
    assert status(BOT, path=path) == {"valid": True, "bot_present": True, "token_configured": False}
    with pytest.raises(LocalSecretsError, match="^Local bot secret is unavailable$"):
        load_bot_token(BOT, path=path)


def test_unknown_bot_and_missing_file_have_only_boolean_status(tmp_path):
    path = write_fake(tmp_path)
    assert status("another_test_bot", path=path) == {"valid": True, "bot_present": False, "token_configured": False}
    assert status(BOT, path=tmp_path / "missing.json") == {"valid": False, "bot_present": False, "token_configured": False}
    with pytest.raises(LocalSecretsError, match="^Local bot secret is unavailable$"):
        load_bot_token("another_test_bot", path=path)


@pytest.mark.parametrize("name", ["@@example_bot", "a", "1example_bot", "x" * 33, "../example_bot", "example bot", "бот_bot", None])
def test_invalid_bot_name_rejected_without_filesystem(name, monkeypatch):
    def denied(*args, **kwargs):
        raise AssertionError("invalid bot name must not cause a filesystem read")
    monkeypatch.setattr(Path, "open", denied)
    monkeypatch.setattr(Path, "resolve", denied)
    with pytest.raises(LocalSecretsError, match="^Local bot secret is unavailable$"):
        load_bot_token(name, path=Path("unused"))
    assert status(name, path=Path("unused")) == {"valid": False, "bot_present": False, "token_configured": False}


@pytest.mark.parametrize("data", [
    [], {}, {"version": True, "bots": {}}, {"version": 2, "bots": {}},
    {"version": 1, "bots": [], "extra": True}, {"version": 1, "bots": []},
    {"version": 1, "bots": {BOT: {"token": TOKEN, "extra": True}}},
    {"version": 1, "bots": {BOT: {"token": None}}},
    {"version": 1, "bots": {BOT: {"token": "not-a-token"}}},
    {"version": 1, "bots": {BOT: {"token": TOKEN + "\n"}}},
    {"version": 1, "bots": {"@@bad_bot": {"token": ""}}},
    {"version": 1, "bots": {BOT: {"token": ""}, BOT.upper(): {"token": ""}}},
])
def test_schema_failures_are_sanitized_and_status_is_false(tmp_path, data):
    path = write_fake(tmp_path, data)
    with pytest.raises(LocalSecretsError, match="^Local bot secret is unavailable$"):
        load_bot_token(BOT, path=path)
    assert status(BOT, path=path) == {"valid": False, "bot_present": False, "token_configured": False}


@pytest.mark.parametrize("raw", [
    b'{"version":1,"version":1,"bots":{}}',
    b'{"version":1,"bots":{"example_test_bot":{"token":"","token":""}}}',
    b'{"version":NaN,"bots":{}}', b"{bad json", b"\xff", b" " * 65537,
], ids=["duplicate-root", "duplicate-nested", "nan", "malformed", "invalid-utf8", "oversized"])
def test_bounded_strict_json_parser(tmp_path, raw):
    path = tmp_path / "fake-malformed.json"
    path.write_bytes(raw)
    with pytest.raises(LocalSecretsError, match="^Local bot secret is unavailable$"):
        load_bot_token(BOT, path=path)


def test_resolved_alias_rejected_before_read(tmp_path, monkeypatch):
    source = tmp_path / "fake-alias.json"
    original_resolve = Path.resolve
    def resolve(path, strict=False):
        return tmp_path / "other.json" if path == source else original_resolve(path, strict=strict)
    def denied(*args, **kwargs):
        raise AssertionError("aliased secret must not be opened")
    monkeypatch.setattr(Path, "resolve", resolve)
    monkeypatch.setattr(Path, "open", denied)
    with pytest.raises(LocalSecretsError):
        load_bot_token(BOT, path=source)


def test_status_cli_output_has_no_bot_token_or_path(tmp_path, capsys):
    path = write_fake(tmp_path)
    assert main(["check", "--bot", BOT, "--path", str(path)]) == 0
    captured = capsys.readouterr()
    assert json.loads(captured.out) == {"valid": True, "bot_present": True, "token_configured": True}
    assert captured.err == ""
    assert TOKEN not in captured.out and BOT not in captured.out and str(path) not in captured.out


def test_cli_invalid_arguments_never_echo_supplied_values(capsys):
    with pytest.raises(SystemExit) as error:
        main(["check", "--bot", BOT, "--unexpected", TOKEN])
    assert error.value.code == 2
    output = capsys.readouterr()
    assert output.out == "" and output.err == "Invalid local secrets command\n"


def test_token_syntax_matches_transport_acceptance(tmp_path):
    from telegram_gateway.network import _TOKEN as transport_pattern
    for token in (TOKEN, "12345:" + "_-" * 10, "9" * 20 + ":" + "x" * 128):
        assert transport_pattern.fullmatch(token)
        path = write_fake(tmp_path, {"version": 1, "bots": {BOT: {"token": token}}})
        assert load_bot_token(BOT, path=path) == token


@pytest.mark.parametrize("name,expected", [
    ("coordinator_demo_bot", "coordinator_demo_bot"), ("@Coordinator_Demo_Bot", "coordinator_demo_bot"),
    ("COORDINATOR_DEMO_BOT", "coordinator_demo_bot"), ("planner_demo_ai", "planner_demo_ai"),
    ("@PLANNER_DEMO_AI", "planner_demo_ai"), ("abcde", "abcde")])
def test_public_normalizer_without_secret_or_filesystem_reads(name, expected, monkeypatch):
    monkeypatch.setattr(Path, "open", lambda *a, **k: pytest.fail("unexpected file read"))
    monkeypatch.setattr(Path, "resolve", lambda *a, **k: pytest.fail("unexpected path resolution"))
    assert validate_bot_name(name) == expected


@pytest.mark.parametrize("stored", [BOT, BOT.upper(), "@" + BOT, "@" + BOT.upper()])
@pytest.mark.parametrize("requested", [BOT, BOT.upper(), "@" + BOT, "@" + BOT.upper()])
def test_file_keys_and_requested_bot_share_one_normalization(tmp_path, stored, requested):
    path = write_fake(tmp_path, {"version": 1, "bots": {stored: {"token": TOKEN}}})
    assert load_bot_token(requested, path=path) == TOKEN
    assert status(requested, path=path) == {"valid": True, "bot_present": True, "token_configured": True}
    assert set(local_secrets._read(path)) == {BOT}


@pytest.mark.parametrize("other", [BOT.upper(), "@" + BOT, "@" + BOT.upper()])
def test_normalized_duplicate_keys_fail_before_token_selection(tmp_path, other):
    path = write_fake(tmp_path, {"version": 1, "bots": {BOT: {"token": TOKEN}, other: {"token": ""}}})
    with pytest.raises(LocalSecretsError):
        load_bot_token(BOT, path=path)
    assert status(other, path=path) == {"valid": False, "bot_present": False, "token_configured": False}


@pytest.mark.parametrize("name", ["@@example_bot", " example_bot", "example_bot ", "@", "zeta", "@zeta", "İexample_bot", "еxample_bot"])
def test_no_double_strip_trimming_short_alias_or_unicode_normalization(name):
    with pytest.raises(LocalSecretsError):
        validate_bot_name(name)


@pytest.mark.parametrize("bad_entry", [{"token": "malformed"}, {"token": None}, {},
    {"token": TOKEN, "extra": True}, [], None, {"token": TOKEN + "\n"}])
def test_malformed_other_bot_does_not_disable_valid_selected_bot(tmp_path, bad_entry):
    path = write_fake(tmp_path, {"version": 1, "bots": {
        "@Inactive_Gateway_Ai": bad_entry, BOT: {"token": TOKEN}}})
    assert load_bot_token("@" + BOT.upper(), path=path) == TOKEN
    assert status(BOT, path=path) == {"valid": True, "bot_present": True, "token_configured": True}
    with pytest.raises(LocalSecretsError, match="^Local bot secret is unavailable$"):
        load_bot_token("inactive_gateway_ai", path=path)
    assert status("inactive_gateway_ai", path=path) == {"valid": False, "bot_present": False, "token_configured": False}


WEBHOOK_URL = "https://hooks.example/fixture"
WEBHOOK_KEY = "CustomScheme PUBLIC_SYNTHETIC_WEBHOOK_KEY"


def webhook_fake(tmp_path, *, entry=None):
    return write_fake(tmp_path, {"version": 1, "bots": {BOT: {"token": TOKEN}},
        "webhooks": {"example_routine": entry if entry is not None else {
            "url": WEBHOOK_URL, "authorization_header": WEBHOOK_KEY}}})


def test_optional_webhook_pair_is_explicit_immutable_and_redacted(tmp_path, monkeypatch):
    import dataclasses
    import socket
    path = webhook_fake(tmp_path, entry={"url": "https://HOOKS.EXAMPLE:443/fixture", "authorization_header": WEBHOOK_KEY})
    monkeypatch.setattr(socket, "getaddrinfo", lambda *a, **k: pytest.fail("unexpected DNS"))
    secret = local_secrets.load_webhook("example_routine", path=path)
    assert secret.url == WEBHOOK_URL and secret.authorization_header == WEBHOOK_KEY
    assert WEBHOOK_KEY not in repr(secret) and WEBHOOK_URL not in repr(secret)
    with pytest.raises(dataclasses.FrozenInstanceError):
        secret.authorization_header = "changed"
    assert load_bot_token(BOT, path=path) == TOKEN
    assert status(BOT, path=path)["token_configured"]
    with pytest.raises(LocalSecretsError, match="^Local webhook secret is unavailable$"):
        local_secrets.load_webhook("example_routine", path=write_fake(tmp_path))


@pytest.mark.parametrize("entry", [None, [], {}, {"url": WEBHOOK_URL}, {"url": WEBHOOK_URL, "authorization_header": WEBHOOK_KEY, "extra": True},
    {"url": "", "authorization_header": ""}, {"url": WEBHOOK_URL, "authorization_header": None},
    {"url": WEBHOOK_URL, "authorization_header": " " + WEBHOOK_KEY},
    {"url": WEBHOOK_URL, "authorization_header": WEBHOOK_KEY + " "},
    {"url": WEBHOOK_URL, "authorization_header": WEBHOOK_KEY + "\t"},
    {"url": WEBHOOK_URL, "authorization_header": WEBHOOK_KEY + "\n"},
    {"url": WEBHOOK_URL, "authorization_header": "x" * 4097}])
def test_selected_webhook_failures_never_disclose_data_or_break_other_bot(tmp_path, entry):
    path = write_fake(tmp_path, {"version": 1, "bots": {BOT: {"token": TOKEN}},
                               "webhooks": {"example_routine": entry}})
    with pytest.raises(LocalSecretsError, match="^Local webhook secret is unavailable$") as exc:
        local_secrets.load_webhook("example_routine", path=path)
    assert WEBHOOK_KEY not in str(exc.value) and str(path) not in str(exc.value)
    assert load_bot_token(BOT, path=path) == TOKEN


@pytest.mark.parametrize("url", ["http://hooks.example/", "https://user:key@hooks.example/", "https://hooks.example/#",
    "https://hooks.example/#fragment", "https://127.0.0.1/", "https://[::1]/", "https://localhost/", "https://hooks.internal/",
    "https://hooks.example:8443/", "https://hooks.example/path with space"])
def test_webhook_url_is_strict_public_https(tmp_path, url):
    path = webhook_fake(tmp_path, entry={"url": url, "authorization_header": WEBHOOK_KEY})
    with pytest.raises(LocalSecretsError, match="^Local webhook secret is unavailable$"):
        local_secrets.load_webhook("example_routine", path=path)


@pytest.mark.parametrize("ref", [None, 1, "", "../route", "UPPER", "route-name", "x" * 65])
def test_invalid_webhook_reference_fails_before_read(ref, monkeypatch):
    monkeypatch.setattr(Path, "open", lambda *a, **k: pytest.fail("unexpected read"))
    monkeypatch.setattr(Path, "resolve", lambda *a, **k: pytest.fail("unexpected resolve"))
    with pytest.raises(LocalSecretsError, match="^Local webhook secret is unavailable$"):
        local_secrets.load_webhook(ref)


def test_other_malformed_entries_are_isolated_for_webhook_selection(tmp_path):
    path = write_fake(tmp_path, {"version": 1, "bots": {BOT: {"token": "bad"}},
        "webhooks": {"other_routine": {"url": None},
                     "example_routine": {"url": WEBHOOK_URL, "authorization_header": WEBHOOK_KEY}}})
    assert local_secrets.load_webhook("example_routine", path=path).authorization_header == WEBHOOK_KEY


def test_default_webhook_path_redirected_only_to_disposable_test_project(tmp_path, monkeypatch):
    path = webhook_fake(tmp_path)
    (tmp_path / "secrets.local.json").write_bytes(path.read_bytes())
    monkeypatch.setattr(local_secrets, "_PROJECT", tmp_path)
    assert local_secrets.load_webhook("example_routine").url == WEBHOOK_URL


def test_webhook_duplicate_json_key_is_rejected(tmp_path):
    path = tmp_path / "duplicate-webhook.json"
    path.write_text('{"version":1,"bots":{},"webhooks":{"example_routine":{"url":"https://hooks.example/","authorization_header":"fixture","authorization_header":"other"}}}', encoding="utf-8")
    with pytest.raises(LocalSecretsError, match="^Local webhook secret is unavailable$"):
        local_secrets.load_webhook("example_routine", path=path)
