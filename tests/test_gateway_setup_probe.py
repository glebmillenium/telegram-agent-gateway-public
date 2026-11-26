import copy
import json
from pathlib import Path
import socket

import pytest

from telegram_gateway import setup_probe
from telegram_gateway.setup_probe import ProbeBlocked, ProbeConfig, main, run_probe
from telegram_gateway.auth import OwnerApprovalVerifier

TOKEN = "98765:synthetic_setup_test_credential_only"
TITLE = "PRIVATE_TEST_GROUP"
MARKER = "FAKE public setup marker"


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    def blocked(*args, **kwargs):
        raise AssertionError("No network is permitted in setup-probe tests")
    monkeypatch.setattr(socket, "create_connection", blocked)
    monkeypatch.setattr(socket, "getaddrinfo", blocked)


@pytest.fixture
def settings(tmp_path):
    secrets = tmp_path / "synthetic-secrets"
    secrets.mkdir()
    token_path = secrets / "fake-bot-token"
    token_path.write_text(TOKEN + "\n", encoding="utf-8")
    data = {"version": 1, "secrets_dir": str(secrets), "token_ref": {"file": str(token_path)},
            "target_title": TITLE, "marker_text": MARKER}
    config_path = tmp_path / "setup.json"
    config_path.write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")
    return data, config_path


def update(number=1, chat=-100001, sender=91, *, title=TITLE, text=MARKER, kind="supergroup", **extra):
    msg = {"message_id": number + 100, "date": 1700000000,
           "chat": {"id": chat, "type": kind, "title": title},
           "from": {"id": sender, "is_bot": False}, "text": text}
    msg.update(extra)
    return {"update_id": number, "message": msg}


class FakeProbeTransport:
    def __init__(self, updates=()):
        self.calls = []
        self.me = {"ok": True, "result": {"id": 98765, "is_bot": True, "username": "synthetic_setup_bot"}}
        self.webhook = {"ok": True, "result": {"url": ""}}
        self.updates = {"ok": True, "result": copy.deepcopy(list(updates))}

    async def get_me(self):
        self.calls.append(("getMe", {}))
        return copy.deepcopy(self.me)

    async def get_webhook_info(self):
        self.calls.append(("getWebhookInfo", {}))
        return copy.deepcopy(self.webhook)

    async def request(self, method, params):
        assert method == "getUpdates"
        assert params == {"offset": 0, "limit": 100, "timeout": 0}
        self.calls.append((method, copy.deepcopy(params)))
        return copy.deepcopy(self.updates)


def factory(wire):
    def construct(token):
        assert token == TOKEN
        return wire
    return construct


async def probe(settings, wire, **kwargs):
    cfg = ProbeConfig.load(settings[1])
    return await run_probe(cfg, allow_live_network=True, confirm_read_updates=True,
                           transport_factory=factory(wire), **kwargs)


@pytest.mark.parametrize("a,b", [(False, False), (True, False), (False, True), (1, True), (True, 1), (None, True), (True, "true")])
async def test_gates_precede_secret_read_and_transport(settings, monkeypatch, a, b):
    cfg = ProbeConfig.from_dict(settings[0])
    def forbidden(*args, **kwargs):
        pytest.fail("Secret/transport was accessed without both explicit gates")
    monkeypatch.setattr(setup_probe, "load_secret", forbidden)
    with pytest.raises(ProbeBlocked, match="confirmations"):
        await run_probe(cfg, allow_live_network=a, confirm_read_updates=b, transport_factory=forbidden)


async def test_omitted_gates_are_denied(settings, monkeypatch):
    monkeypatch.setattr(setup_probe, "load_secret", lambda *a, **k: pytest.fail("secret read"))
    with pytest.raises(ProbeBlocked):
        await run_probe(ProbeConfig.from_dict(settings[0]))


def test_configuration_parse_does_not_load_secrets(settings, monkeypatch):
    monkeypatch.setattr(setup_probe, "load_secret", lambda *a, **k: pytest.fail("secret read"))
    cfg = ProbeConfig.load(settings[1])
    assert cfg.target_title == TITLE
    assert cfg.marker_text == MARKER
    assert TOKEN not in repr(cfg) and MARKER not in repr(cfg)


async def test_only_exact_candidates_are_output_and_no_ack_or_mutation(settings):
    wire = FakeProbeTransport([update(), update(2, chat=-199999, title="Other chat", text="PRIVATE OTHER MESSAGE"),
                               update(3, text=MARKER + " extra"), update(4, title=TITLE + " suffix"),
                               update(5, kind="private"), update(6, kind="channel")])
    before = settings[1].read_bytes()
    result = await probe(settings, wire)
    assert [c[0] for c in wire.calls] == ["getMe", "getWebhookInfo", "getUpdates"]
    assert result["bot"] == {"id": 98765, "username": "synthetic_setup_bot"}
    assert result["status"] == "UNVERIFIED_NOT_GRANTED"
    assert result["selected"] is None and result["operator_review_required"] is True
    assert result["permissions_granted"] is False and result["updates_acknowledged"] is False
    assert result["candidates"] == [{"status": "UNVERIFIED_NOT_GRANTED",
            "chat": {"id": -100001, "type": "supergroup", "title": TITLE},
            "sender": {"id": 91}, "message_id": 101}]
    output = json.dumps(result)
    for secret in (TOKEN, MARKER, "PRIVATE OTHER MESSAGE", "-199999"):
        assert secret not in output
    assert settings[1].read_bytes() == before
    assert sorted(p.name for p in settings[1].parent.iterdir()) == ["setup.json", "synthetic-secrets"]


async def test_duplicate_titles_and_multiple_humans_never_auto_selected(settings):
    wire = FakeProbeTransport([update(), update(2, chat=-100002, sender=92, kind="group"),
                               update(3, sender=93, message_thread_id=7)])
    result = await probe(settings, wire)
    assert len(result["candidates"]) == 3 and result["selected"] is None
    assert result["candidates"][2]["message_thread_id"] == 7
    assert all(c["status"] == "UNVERIFIED_NOT_GRANTED" for c in result["candidates"])


async def test_repeat_probe_uses_same_zero_offset_without_acknowledging(settings):
    wire = FakeProbeTransport([update()])
    first = await probe(settings, wire)
    second = await probe(settings, wire)
    assert first == second
    reads = [params for method, params in wire.calls if method == "getUpdates"]
    assert len(reads) == 2 and all(params["offset"] == 0 for params in reads)
    assert wire.updates["result"] == [update()]


async def test_empty_batch_returns_bot_metadata_without_grants(settings):
    result = await probe(settings, FakeProbeTransport())
    assert result["candidates"] == [] and result["selected"] is None
    assert result["permissions_granted"] is False


@pytest.mark.parametrize("field", sorted(OwnerApprovalVerifier._FORBIDDEN))
async def test_forward_anonymous_bot_business_guest_provenance_rejected(settings, field):
    wire = FakeProbeTransport([update(**{field: None})])
    assert (await probe(settings, wire))["candidates"] == []


@pytest.mark.parametrize("sender", [None, {}, {"id": 91, "is_bot": True}, {"id": 91},
                                     {"id": True, "is_bot": False}, {"id": -1, "is_bot": False},
                                     {"id": 2**52, "is_bot": False}, {"id": 91, "is_bot": 0}])
async def test_only_direct_identified_humans(settings, sender):
    item = update()
    item["message"]["from"] = sender
    assert (await probe(settings, FakeProbeTransport([item])))["candidates"] == []


@pytest.mark.parametrize("chat_id", [1234567890, 0, True, "-100001", -(2**52)])
async def test_positive_locator_and_invalid_group_ids_are_not_candidates(settings, chat_id):
    result = await probe(settings, FakeProbeTransport([update(chat=chat_id)]))
    assert result["candidates"] == []


@pytest.mark.parametrize("value", [0, True, -1, 2**31, "1"])
async def test_invalid_message_or_topic_ids_rejected(settings, value):
    message_case = update(1, message_id=value)
    topic_case = update(2, message_thread_id=value)
    assert (await probe(settings, FakeProbeTransport([message_case, topic_case])))["candidates"] == []


async def test_caption_edited_business_guest_update_types_not_accepted(settings):
    caption = update()
    caption["message"].pop("text")
    caption["message"]["caption"] = MARKER
    items = [caption]
    for number, key in enumerate(("edited_message", "business_message", "guest_message", "channel_post"), 2):
        items.append({"update_id": number, key: update()["message"]})
    other_envelope = update(9)
    other_envelope["business_connection_id"] = "fake-business"
    items.append(other_envelope)
    assert (await probe(settings, FakeProbeTransport(items)))["candidates"] == []


async def test_existing_webhook_stops_before_updates_without_logging_url(settings):
    wire = FakeProbeTransport([update()])
    wire.webhook["result"]["url"] = "https://private.example/SECRET-HOOK"
    with pytest.raises(ProbeBlocked) as caught:
        await probe(settings, wire)
    assert "SECRET" not in str(caught.value) and "not changed" in str(caught.value)
    assert [method for method, _ in wire.calls] == ["getMe", "getWebhookInfo"]


@pytest.mark.parametrize("me", [{}, {"id": 98765, "is_bot": False, "username": "valid_bot"},
    {"id": True, "is_bot": True, "username": "valid_bot"}, {"id": 98765, "is_bot": True},
    {"id": 98765, "is_bot": True, "username": "bad\nusername"}])
async def test_malformed_bot_metadata_stops_before_updates(settings, me):
    wire = FakeProbeTransport()
    wire.me["result"] = me
    with pytest.raises(ProbeBlocked):
        await probe(settings, wire)
    assert len(wire.calls) == 1


@pytest.mark.parametrize("batch", [[{}], [update(1), update(1)], [{"update_id": True}],
                                      [{"update_id": -1}], {}, [update(i) for i in range(101)]])
async def test_invalid_or_oversized_batch_has_no_partial_output(settings, batch):
    wire = FakeProbeTransport()
    wire.updates["result"] = batch
    with pytest.raises(ProbeBlocked):
        await probe(settings, wire)


@pytest.mark.parametrize("key,value", [("version", True), ("version", 2), ("target_title", ""),
    ("target_title", "a" * 129), ("marker_text", ""), ("marker_text", "a" * 257),
    ("marker_text", "two\nlines"), ("secrets_dir", "relative"),
    ("token_ref", {"env": "BAD NAME"}), ("token_ref", {"env": "X", "file": "Y"}),
    ("chat_id", 1234567890), ("token", TOKEN)])
def test_config_strict_and_no_locator_guessing(settings, key, value):
    data = copy.deepcopy(settings[0])
    data[key] = value
    with pytest.raises(ProbeBlocked) as caught:
        ProbeConfig.from_dict(data)
    assert TOKEN not in str(caught.value)


def test_config_secret_reference_outside_directory_or_checkout_denied(settings):
    data = copy.deepcopy(settings[0])
    data["token_ref"] = {"file": str(settings[1])}
    with pytest.raises(ProbeBlocked):
        ProbeConfig.from_dict(data)
    data["secrets_dir"] = str(setup_probe._PROJECT / "secrets")
    data["token_ref"] = {"file": str(setup_probe._PROJECT / "secrets" / "bot-token")}
    with pytest.raises(ProbeBlocked):
        ProbeConfig.from_dict(data)


def test_external_config_load_rejects_checkout_and_relative_before_read(monkeypatch):
    def read_forbidden(*args, **kwargs):
        pytest.fail("Unapproved config file read")
    monkeypatch.setattr(Path, "open", read_forbidden)
    for path in ("setup.json", setup_probe._PROJECT / "setup.json"):
        with pytest.raises(ProbeBlocked):
            ProbeConfig.load(path)


@pytest.mark.parametrize("raw", ['{"version":1,"version":1}', '{"token_ref":{"env":"ONE","env":"TWO"}}',
                                 '{"version":NaN}', '{"version":Infinity}', '{', '[]', '"scalar"'])
def test_duplicate_keys_and_non_json_rejected(settings, raw):
    settings[1].write_text(raw, encoding="utf-8")
    with pytest.raises(ProbeBlocked):
        ProbeConfig.load(settings[1])


def test_bounded_config_read(settings):
    settings[1].write_bytes(b" " * 65537)
    with pytest.raises(ProbeBlocked):
        ProbeConfig.load(settings[1])


async def test_missing_secret_or_transport_error_is_sanitized(settings, monkeypatch):
    cfg = ProbeConfig.from_dict(settings[0])
    def error(*args, **kwargs):
        raise RuntimeError(f"fake secret failure {TOKEN}")
    monkeypatch.setattr(setup_probe, "load_secret", error)
    with pytest.raises(ProbeBlocked) as caught:
        await run_probe(cfg, allow_live_network=True, confirm_read_updates=True, transport_factory=error)
    assert TOKEN not in str(caught.value)


@pytest.mark.parametrize("flags", [[], ["--allow-live-network"], ["--confirm-read-updates"]])
def test_cli_requires_both_gates_before_any_config_read(settings, monkeypatch, capsys, flags):
    monkeypatch.setattr(ProbeConfig, "load", lambda *a: pytest.fail("config read before confirmation"))
    with pytest.raises(SystemExit) as caught:
        main(["--config", str(settings[1]), *flags])
    assert caught.value.code == 2 and capsys.readouterr().out == ""


def test_cli_fake_success_prints_only_sanitized_candidates(settings, monkeypatch, capsys):
    wire = FakeProbeTransport([update(), update(2, title="UNRELATED", text="UNRELATED SECRET")])
    monkeypatch.setattr(setup_probe, "BotHTTPTransport", factory(wire))
    assert main(["--config", str(settings[1]), "--allow-live-network", "--confirm-read-updates"]) == 0
    captured = capsys.readouterr()
    assert captured.err == ""
    data = json.loads(captured.out)
    assert len(data["candidates"]) == 1 and data["status"] == "UNVERIFIED_NOT_GRANTED"
    assert TOKEN not in captured.out and MARKER not in captured.out and "UNRELATED" not in captured.out


def test_cli_fake_failure_never_prints_raw_api_details(settings, monkeypatch, capsys):
    wire = FakeProbeTransport()
    wire.me = {"ok": False, "description": "PRIVATE " + TOKEN}
    monkeypatch.setattr(setup_probe, "BotHTTPTransport", factory(wire))
    with pytest.raises(SystemExit) as caught:
        main(["--config", str(settings[1]), "--allow-live-network", "--confirm-read-updates"])
    captured = capsys.readouterr()
    assert caught.value.code == 2 and captured.out == ""
    assert TOKEN not in captured.err and "PRIVATE" not in captured.err
