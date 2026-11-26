"""Read-only owned-draft diagnostics: synthetic SQLite state, no network."""
import json

import pytest

from telegram_gateway.auth import FakeAuthenticator
from telegram_gateway.bot_api import BotApiAdapter, FakeBotTransport
from telegram_gateway.policy import GatewayDenied, Policy
from telegram_gateway.protocol import Protocol
from telegram_gateway.runtime import make_runtime
from telegram_gateway.runtime_config import RuntimeConfig
from telegram_gateway.service import Gateway, StateStore


TEXT = "SYNTHETIC PRIVATE DRAFT TEXT MUST NOT BE RETURNED"
CHAT = -1101


def policy(grants=None):
    grants = grants if grants is not None else [{"chat_id": CHAT, "topic_id": 7, "permissions": ["draft", "send"]}]
    return Policy.from_dict({"principals": {"alpha": grants, "beta": grants}})


@pytest.fixture
def env(tmp_path):
    auth = FakeAuthenticator({"fixture-alpha": "alpha", "fixture-beta": "beta"})
    a, b = (auth.authenticate("Bearer fixture-" + name) for name in ("alpha", "beta"))
    clock = [1000.0]
    store = StateStore((tmp_path / "state.sqlite").resolve())
    wire = FakeBotTransport()
    gateway = Gateway(store, policy(), [a, b], BotApiAdapter(wire),
                      clock=lambda: clock[0], bot_reference="fixture_alpha_bot")
    draft = gateway.create_draft(a, CHAT, TEXT, topic_id=7, expires_in=60)["draft"]["draft_id"]
    yield gateway, store, wire, auth, a, b, draft, clock
    assert wire.calls == [] and wire.sent == []
    store.close()


@pytest.mark.parametrize("status,attempt", [("pending", False), ("approved", False), ("rejected", False),
    ("sending", True), ("sent", True), ("failed", True), ("unknown", True)])
def test_owned_status_projects_only_metadata_without_writes(env, status, attempt):
    gateway, store, _, _, a, _, draft, _ = env
    receipt = {"message_id": 31, "chat_id": CHAT, "topic_id": 7, "operation_id": gateway._namespace(draft),
               "synthetic": True, "bot_reference": "fixture_alpha_bot", "untrusted_extra": TEXT}
    failure = {"kind": "telegram_rejected", "api_error_code": 429, "retry_after_seconds": 12, "raw_error": TEXT}
    store.db.execute("UPDATE gw_drafts SET status=?,consumed=?,receipt=?,failure=? WHERE id=?",
        (status, 1001 if attempt else None, json.dumps(receipt) if status == "sent" else None,
         json.dumps(failure) if status == "failed" else None, draft))
    before = list(store.db.iterdump())
    result = gateway.get_draft_status(a, draft)
    assert set(result) == {"draft_id", "status", "expired", "attempt_started", "failure", "receipt"}
    assert result["draft_id"] == draft and result["status"] == status
    assert result["attempt_started"] is attempt and result["expired"] is False
    assert (result["receipt"] is not None) is (status == "sent")
    assert (result["failure"] is not None) is (status == "failed")
    assert TEXT not in json.dumps(result) and "raw_error" not in json.dumps(result)
    assert before == list(store.db.iterdump())


def test_expired_pending_draft_is_not_claimed_or_reclassified(env):
    gateway, store, _, _, a, _, draft, clock = env
    clock[0] += 61
    before = list(store.db.iterdump())
    result = gateway.get_draft_status(a, draft)
    assert result["status"] == "pending" and result["expired"] is True
    assert result["attempt_started"] is False
    assert before == list(store.db.iterdump())


@pytest.mark.parametrize("grants", [[], [{"chat_id": CHAT, "topic_id": 7, "permissions": ["draft"]}],
    [{"chat_id": CHAT, "topic_id": 7, "permissions": ["send"]}],
    [{"chat_id": -1102, "topic_id": 7, "permissions": ["draft", "send"]}],
    [{"chat_id": CHAT, "topic_id": 8, "permissions": ["draft", "send"]}]])
def test_current_exact_chat_topic_and_both_permissions_required(env, grants):
    gateway, store, _, _, a, _, draft, _ = env
    gateway.policy = policy(grants)
    before = list(store.db.iterdump())
    with pytest.raises(GatewayDenied):
        gateway.get_draft_status(a, draft)
    assert before == list(store.db.iterdump())


def test_other_owner_and_unknown_id_are_denied_even_with_same_grants(env):
    gateway, _, _, _, a, b, draft, _ = env
    for principal, identity in ((b, draft), (a, "0" * 32)):
        with pytest.raises(GatewayDenied):
            gateway.get_draft_status(principal, identity)


def test_cross_bot_row_cannot_be_read_as_same_principal(env, tmp_path):
    gateway, store, _, _, a, _, draft, _ = env
    other = StateStore((tmp_path / "other.sqlite").resolve())
    try:
        alien = Gateway(other, policy(), [a], BotApiAdapter(FakeBotTransport()), bot_reference="fixture_beta_bot")
        row = tuple(store.db.execute("SELECT * FROM gw_drafts WHERE id=?", (draft,)).fetchone())
        other.db.execute("INSERT INTO gw_drafts VALUES(" + ",".join("?" for _ in row) + ")", row)
        with pytest.raises(GatewayDenied):
            alien.get_draft_status(a, draft)
    finally:
        other.close()


@pytest.mark.parametrize("failure,expected", [
    (None, None), ({"kind": TEXT}, None), ({"kind": []}, None),
    ({"kind": "telegram_rejected", "api_error_code": True, "retry_after_seconds": TEXT},
     {"kind": "telegram_rejected", "api_error_code": None, "retry_after_seconds": None}),
    ({"kind": "delivery_uncertain", "stage": "transport", "error_category": "timeout", "raw_error": TEXT},
     {"kind": "delivery_uncertain", "stage": "transport", "error_category": "timeout"}),
    ({"kind": "delivery_uncertain", "stage": "receipt_persistence", "error_category": "sqlite"},
     {"kind": "delivery_uncertain", "stage": "receipt_persistence", "error_category": "sqlite"}),
    ({"kind": "delivery_uncertain", "stage": "transport", "error_category": "adapter_uncertain"},
     {"kind": "delivery_uncertain", "stage": "transport", "error_category": "adapter_uncertain"}),
    ({"kind": "delivery_uncertain", "stage": [], "error_category": TEXT}, None),
])
def test_failure_projection_never_returns_arbitrary_details(env, failure, expected):
    gateway, store, _, _, a, _, draft, _ = env
    store.db.execute("UPDATE gw_drafts SET status='unknown',consumed=1001,failure=? WHERE id=?",
                     (None if failure is None else json.dumps(failure), draft))
    result = gateway.get_draft_status(a, draft)
    assert result["failure"] == expected and result["attempt_started"] is True
    assert TEXT not in json.dumps(result)


def test_corrupt_receipt_scope_and_draft_integrity_fail_closed(env):
    gateway, store, _, _, a, _, draft, _ = env
    receipt = {"message_id": 31, "chat_id": -1102, "topic_id": 7, "operation_id": gateway._namespace(draft),
               "synthetic": True, "bot_reference": "fixture_alpha_bot"}
    store.db.execute("UPDATE gw_drafts SET receipt=? WHERE id=?", (json.dumps(receipt), draft))
    with pytest.raises(GatewayDenied):
        gateway.get_draft_status(a, draft)
    store.db.execute("UPDATE gw_drafts SET receipt=NULL,digest=? WHERE id=?", ("0" * 64, draft))
    with pytest.raises(GatewayDenied):
        gateway.get_draft_status(a, draft)


@pytest.mark.parametrize("draft_scope,send_scope,visible", [
    ({"chat_id": CHAT}, {"chat_id": -1102}, False),
    ({"chat_id": CHAT, "topic_id": 7}, {"chat_id": CHAT, "topic_id": 8}, False),
    ({"chat_id": CHAT, "all_topics": True}, {"chat_id": CHAT, "topic_id": 7}, True),
    ({"chat_id": CHAT, "topic_id": 7}, {"chat_id": CHAT, "all_topics": True}, True),
])
def test_tool_catalog_requires_overlapping_draft_and_send_grants(env, draft_scope, send_scope, visible):
    _, _, _, _, a, _, _, _ = env
    current = policy([{**draft_scope, "permissions": ["draft"]}, {**send_scope, "permissions": ["send"]}])
    assert ("get_draft_status" in current.tools_for(a)) is visible


@pytest.mark.asyncio
async def test_protocol_readonly_schema_and_foreign_draft_non_disclosure(env):
    gateway, _, _, auth, a, b, draft, _ = env
    protocol = Protocol(auth, gateway, None)
    catalog = await protocol.request({"jsonrpc": "2.0", "id": 1, "method": "tools/list"}, authorization="Bearer fixture-alpha")
    tool = next(t for t in catalog["result"]["tools"] if t["name"] == "get_draft_status")
    assert tool["annotations"]["readOnlyHint"] is True and tool["annotations"]["openWorldHint"] is False
    assert tool["inputSchema"]["properties"] == {"draft_id": {"type": "string", "pattern": "^[a-f0-9]{32}$"}}
    request = {"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {
        "name": "get_draft_status", "arguments": {"draft_id": draft}}}
    own = await protocol.request(request, authorization="Bearer fixture-alpha")
    assert own["result"]["structuredContent"]["status"] == "pending"
    denied = await protocol.request(request, authorization="Bearer fixture-beta")
    assert denied["result"]["isError"] is True and "structuredContent" not in denied["result"]
    assert TEXT not in json.dumps(own) + json.dumps(denied)


@pytest.mark.asyncio
async def test_multi_runtime_routes_status_only_to_authenticated_bot(tmp_path):
    profiles = [{"id": name, "name": name, "purpose": "fixture", "prompt": "fixture", "enabled": True,
                 "telegram_username": f"fixture_{name}_bot", "auth_principal": name,
                 "chats": [{"chat_id": CHAT, "type": "supergroup", "title": "Synthetic", "topic_id": 7,
                            "actions": ["draft", "send"]}]} for name in ("alpha", "beta")]
    cfg = RuntimeConfig.from_dict({"version": 1, "mode": "fake", "state_dir": str(tmp_path / "state"),
        "auth": {"mode": "fake", "credentials": {"fixture-alpha": "alpha", "fixture-beta": "beta"}},
        "network_enabled": False, "outbound_enabled": False, "agents": profiles}, project_root=tmp_path / "code")
    wires = {reference: FakeBotTransport() for reference in cfg.bot_configs}
    runtime = make_runtime(cfg, transports=wires)
    await runtime.start()
    try:
        a, b = (runtime.auth.authenticate("Bearer fixture-" + name) for name in ("alpha", "beta"))
        draft = runtime.gateway.create_draft(a, CHAT, TEXT, topic_id=7)["draft"]["draft_id"]
        assert runtime.gateway.get_draft_status(a, draft)["status"] == "pending"
        with pytest.raises(GatewayDenied):
            runtime.gateway.get_draft_status(b, draft)
        assert all(not wire.calls and not wire.sent for wire in wires.values())
    finally:
        await runtime.close()
