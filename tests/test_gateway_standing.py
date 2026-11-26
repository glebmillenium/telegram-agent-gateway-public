"""Pure standing-policy tests: synthetic identities/drafts, no I/O or grants."""
from dataclasses import FrozenInstanceError, replace
import copy
import hashlib
from pathlib import Path
import socket

import pytest

from telegram_gateway.auth import FakeAuthenticator, VerifiedPrincipal
from telegram_gateway.service import canonical
from telegram_gateway.standing import PURPOSE, StandingAuthorization, StandingDenied, StandingSendPolicy


@pytest.fixture
def policy():
    return StandingSendPolicy(purpose=PURPOSE, principal_id="agent_beta", bot_reference="agent_beta_test_bot",
                              expected_bot_id=5001, chat_id=-1001)


@pytest.fixture
def principal():
    return FakeAuthenticator({"fixture-agent_beta": "agent_beta"}).authenticate("Bearer fixture-agent_beta")


@pytest.fixture
def body():
    return {"draft_id": "a" * 32, "principal_id": "agent_beta", "bot_reference": "agent_beta_test_bot",
            "operation": "send", "chat_id": -1001, "topic_id": None,
            "text": "Тест шлюза: обычный текст.\nСтрока 2.", "attachments": [], "source": None,
            "task_id": "bot:agent_beta_test_bot:tg:-1001:-1:42", "reply_to_message_id": 42,
            "chain_depth": 1, "started": 1000.25, "expires_at": 1300.25}


def authorize(policy, principal, body, **identity):
    return policy.authorize(principal, bot_reference=identity.get("bot_reference", "agent_beta_test_bot"),
                            bot_id=identity.get("bot_id", 5001), body=body)


def test_exact_plaintext_authorized_and_hash_matches_gateway_canonical(policy, principal, body):
    decision = authorize(policy, principal, body)
    assert decision.authorized
    assert decision.policy_fingerprint == policy.fingerprint == policy.policy_fingerprint
    assert decision.payload_digest == hashlib.sha256(canonical(body).encode("utf-8")).hexdigest()
    assert body["text"] not in repr(decision)
    assert not StandingAuthorization(decision.policy_fingerprint, decision.payload_digest).authorized
    with pytest.raises(FrozenInstanceError):
        decision.payload_digest = "b" * 64
    with pytest.raises(FrozenInstanceError):
        policy.chat_id = -1002


def test_each_exact_identity_scope_and_limit_is_bound_in_fingerprint(policy):
    assert replace(policy, bot_reference="@AGENT_BETA_TEST_BOT").fingerprint == policy.fingerprint
    for change in ({"principal_id": "zeta"}, {"bot_reference": "zeta_test_bot"}, {"expected_bot_id": 5002},
                   {"chat_id": -1002}, {"topic_id": 7}, {"max_text_chars": 999}):
        assert replace(policy, **change).fingerprint != policy.fingerprint


@pytest.mark.parametrize("identity", [VerifiedPrincipal("agent_beta"), {"id": "agent_beta"}, "agent_beta", None])
def test_unsealed_or_body_identity_cannot_authorize(policy, body, identity):
    with pytest.raises(StandingDenied, match="^Standing send is not permitted$"):
        authorize(policy, identity, body)


def test_other_authenticated_principal_or_runtime_bot_cannot_use_grant(policy, body, principal):
    other = FakeAuthenticator({"fixture-zeta": "zeta"}).authenticate("Bearer fixture-zeta")
    with pytest.raises(StandingDenied):
        authorize(policy, other, body)
    for changed in ({"bot_reference": "zeta_test_bot"}, {"bot_id": 5002}, {"bot_id": True}, {"bot_id": "5001"}):
        with pytest.raises(StandingDenied):
            authorize(policy, principal, body, **changed)


@pytest.mark.parametrize("change", [
    {"principal_id": "zeta"}, {"bot_reference": "zeta_test_bot"}, {"chat_id": -1002},
    {"topic_id": 7}, {"topic_id": False}, {"chat_id": True},
    {"operation": "forward_snapshot"}, {"source": {}}, {"source": False},
    {"attachments": [{"name": "fixture.txt", "sha256": "b" * 64}]}, {"attachments": None},
    {"all_topics": True}, {"parse_mode": "HTML"}, {"agent_id": "agent_beta"},
    {"text": ""}, {"text": "x" * 4001}, {"text": "bad\x00text"},
    {"reply_to_message_id": True}, {"reply_to_message_id": 0}, {"chain_depth": -1},
    {"started": float("nan")}, {"expires_at": 999},
], ids=["body-principal", "body-bot", "foreign-chat", "foreign-topic", "boolean-topic", "boolean-chat",
        "forward", "source", "false-source", "attachment", "null-attachments", "wildcard", "markup-mode",
        "claimed-identity", "empty", "long", "control", "boolean-reply", "zero-reply", "negative-depth", "nan", "bad-expiry"])
def test_foreign_targets_nonplaintext_operations_and_malformed_drafts_denied(policy, principal, body, change):
    body.update(change)
    with pytest.raises(StandingDenied, match="^Standing send is not permitted$"):
        authorize(policy, principal, body)


def test_exact_topic_does_not_mean_general_or_any_topic(policy, principal, body):
    scoped = replace(policy, topic_id=7)
    with pytest.raises(StandingDenied):
        authorize(scoped, principal, body)
    body["topic_id"] = 7
    assert authorize(scoped, principal, body).authorized
    body["topic_id"] = 8
    with pytest.raises(StandingDenied):
        authorize(scoped, principal, body)


@pytest.mark.parametrize("change", [
    {"purpose": "general_send"}, {"principal_id": "*"}, {"bot_reference": "@@bad_bot"},
    {"expected_bot_id": True}, {"expected_bot_id": 0}, {"chat_id": 1001}, {"chat_id": 0},
    {"topic_id": True}, {"topic_id": "all"}, {"max_text_chars": True}, {"max_text_chars": 4001},
])
def test_policy_configuration_is_explicit_and_strict(policy, change):
    with pytest.raises(StandingDenied, match="^Standing send is not permitted$"):
        replace(policy, **change)


def test_authorization_is_snapshot_bound_for_all_immutable_draft_fields(policy, principal, body):
    initial = authorize(policy, principal, body)
    for change in ({"text": "Different plaintext"}, {"draft_id": "b" * 32}, {"reply_to_message_id": 43},
                   {"task_id": "bot:agent_beta_test_bot:draft:another"}, {"chain_depth": 2}, {"expires_at": 1200.25}):
        changed = {**body, **change}
        result = authorize(policy, principal, changed)
        assert result.payload_digest != initial.payload_digest
    body["text"] = "Changed after authorization"
    assert initial.payload_digest != hashlib.sha256(canonical(body).encode("utf-8")).hexdigest()


def test_no_reads_network_mutation_or_semantic_classifier(policy, principal, body, monkeypatch):
    def denied(*args, **kwargs):
        raise AssertionError("pure standing policy must not perform I/O")
    monkeypatch.setattr(Path, "open", denied)
    monkeypatch.setattr(Path, "read_text", denied)
    monkeypatch.setattr(socket, "create_connection", denied)
    body["text"] = "Literal plaintext without technical keywords; no semantic classifier is claimed."
    original = copy.deepcopy(body)
    assert authorize(policy, principal, body).authorized
    assert body == original
