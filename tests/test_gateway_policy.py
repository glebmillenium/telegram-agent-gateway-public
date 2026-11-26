import copy

import pytest

from telegram_gateway.auth import (
    ApprovalChallenge, AuthenticationDenied, FakeAuthenticator, OwnerApprovalVerifier,
    PrincipalAuthority, TrustedBotMessage, VerifiedPrincipal, trusted_bot_message_from_transport,
)
from telegram_gateway.policy import GatewayDenied, Policy, Scope


@pytest.fixture
def auth():
    return FakeAuthenticator({"fixture-zeta": "zeta", "fixture-support": "support", "fixture-outsider": "outsider"})


@pytest.fixture
def policy():
    return Policy.from_dict({"principals": {
        "zeta": [{"chat_id": -1001, "topic_id": 7, "permissions": ["history", "events", "draft", "send"]}],
        "support": [{"chat_id": -1002, "topic_id": None, "permissions": ["history", "events"]}],
    }})


def test_two_agents_have_disjoint_server_enforced_scopes(policy, auth):
    zeta, support = auth.authenticate("Bearer fixture-zeta"), auth.authenticate("Bearer fixture-support")
    policy.require(zeta, "history", Scope(-1001, 7))
    policy.require(support, "history", Scope(-1002))
    for principal, foreign in [(zeta, Scope(-1002)), (support, Scope(-1001, 7))]:
        with pytest.raises(GatewayDenied, match="Access denied"):
            policy.require(principal, "history", foreign)
    assert policy.allowed_scopes(zeta, "events") == (Scope(-1001, 7),)
    assert policy.allowed_scopes(support, "events") == (Scope(-1002),)


@pytest.mark.parametrize("scope", [Scope(-1001), Scope(-1001, 8)])
def test_topic_does_not_inherit_chat_or_other_topic(policy, auth, scope):
    with pytest.raises(GatewayDenied):
        policy.require(auth.authenticate("Bearer fixture-zeta"), "history", scope)


def test_read_and_send_never_imply_forward(policy, auth):
    zeta = auth.authenticate("Bearer fixture-zeta")
    for permission in ("history", "send"):
        policy.require(zeta, permission, Scope(-1001, 7))
    with pytest.raises(GatewayDenied):
        policy.require(zeta, "forward", Scope(-1001, 7))
    assert "create_forward_draft" not in policy.tools_for(zeta)
    assert "send_draft" not in policy.tools_for(auth.authenticate("Bearer fixture-support"))


@pytest.mark.parametrize("principal", [VerifiedPrincipal("zeta"), {"id": "zeta"}, {"agent_id": "zeta"}, "zeta", None])
def test_forged_request_identity_is_not_a_verified_principal(policy, principal):
    with pytest.raises(GatewayDenied):
        policy.require(principal, "history", Scope(-1001, 7))


def test_unknown_authenticated_principal_denied(policy, auth):
    with pytest.raises(GatewayDenied):
        policy.tools_for(auth.authenticate("Bearer fixture-outsider"))
    restored = PrincipalAuthority().restore("zeta")
    assert restored.authenticated
    policy.require(restored, "history", Scope(-1001, 7))


@pytest.mark.parametrize("header", [None, "", "zeta", "Bearer zeta", "Bearer fixture-zeta extra", "Basic fixture-zeta", {"agent_id": "zeta"}])
def test_fake_authentication_no_body_or_anonymous_fallback(auth, header):
    with pytest.raises(AuthenticationDenied):
        auth.authenticate(header)


@pytest.mark.parametrize("bad", [
    {}, {"principals": {}, "default": "allow"}, {"principals": {"*": []}},
    {"principals": {"zeta": [{"chat_id": -1001, "permissions": ["*"]}]}},
    {"principals": {"zeta": [{"chat_id": -1001, "permissions": ["history"], "agent_id": "support"}]}},
    {"principals": {"zeta": [{"chat_id": -1001, "permissions": ["history", "history"]}]}},
    {"principals": {"zeta": [{"chat_id": -1001, "permissions": []}, {"chat_id": -1001, "permissions": []}]}},
])
def test_policy_rejects_wildcards_duplicates_and_unknown_fields(bad):
    with pytest.raises(GatewayDenied):
        Policy.from_dict(bad)


@pytest.mark.parametrize("chat,topic", [(True, None), (0, None), (2**52, None), (-1001, True), (-1001, 0), (-1001, -1), (-1001, "7")])
def test_scope_is_strict(chat, topic):
    with pytest.raises(GatewayDenied):
        Scope(chat, topic)


def test_policy_snapshot_immutable(auth):
    config = {"principals": {"zeta": [{"chat_id": -1001, "permissions": ["history"]}]}}
    p = Policy.from_dict(config)
    config["principals"]["zeta"][0]["permissions"].append("forward")
    with pytest.raises(GatewayDenied):
        p.require(auth.authenticate("Bearer fixture-zeta"), "forward", Scope(-1001))


def test_whole_group_grant_covers_actual_topics_but_not_other_principal_chat_or_action(auth):
    policy = Policy.from_dict({"principals": {
        "zeta": [{"chat_id": -1001, "all_topics": True, "permissions": ["history", "events"]}],
        "support": [{"chat_id": -1001, "topic_id": 7, "permissions": ["history"]}],
    }})
    zeta, support = auth.authenticate("Bearer fixture-zeta"), auth.authenticate("Bearer fixture-support")
    for topic in (None, 1, 7, 12345, 2**31 - 1):
        for permission in ("history", "events"):
            policy.require(zeta, permission, Scope(-1001, topic))
        with pytest.raises(GatewayDenied):
            policy.require(zeta, "send", Scope(-1001, topic))
    policy.require(zeta, "history", Scope(-1001, all_topics=True))
    with pytest.raises(GatewayDenied):
        policy.require(zeta, "history", Scope(-1002, 7))
    with pytest.raises(GatewayDenied):
        policy.require(support, "history", Scope(-1001, 12345))
    with pytest.raises(GatewayDenied):
        policy.require(support, "history", Scope(-1001, all_topics=True))
    assert policy.allowed_scopes(zeta, "history") == (Scope(-1001, all_topics=True),)
    assert policy.allowed_scopes(zeta, "send") == ()


def test_finite_topic_grants_never_become_an_aggregate_or_unthreaded_grant(auth):
    policy = Policy.from_dict({"principals": {"zeta": [
        {"chat_id": -1001, "topic_id": topic, "permissions": ["history"]} for topic in (7, 8, 9)
    ]}})
    principal = auth.authenticate("Bearer fixture-zeta")
    for topic in (7, 8, 9):
        policy.require(principal, "history", Scope(-1001, topic))
    for scope in (Scope(-1001), Scope(-1001, all_topics=True), Scope(-1001, 10)):
        with pytest.raises(GatewayDenied):
            policy.require(principal, "history", scope)


def test_unthreaded_and_whole_group_grants_are_distinct_with_separate_permissions(auth):
    policy = Policy.from_dict({"principals": {"zeta": [
        {"chat_id": -1001, "topic_id": None, "permissions": ["send"]},
        {"chat_id": -1001, "all_topics": True, "permissions": ["history"]},
    ]}})
    principal = auth.authenticate("Bearer fixture-zeta")
    policy.require(principal, "send", Scope(-1001))
    policy.require(principal, "history", Scope(-1001, 42))
    for scope in (Scope(-1001, 42), Scope(-1001, all_topics=True)):
        with pytest.raises(GatewayDenied):
            policy.require(principal, "send", scope)
    assert Scope(-1001) != Scope(-1001, all_topics=True)
    assert len({Scope(-1001), Scope(-1001, all_topics=True)}) == 2


@pytest.mark.parametrize("flag", [None, 0, 1, "true", [], {}])
def test_all_topics_flag_is_strict_boolean_in_scope_and_policy(flag):
    with pytest.raises(GatewayDenied):
        Scope(-1001, all_topics=flag)
    with pytest.raises(GatewayDenied):
        Policy.from_dict({"principals": {"zeta": [{"chat_id": -1001, "all_topics": flag, "permissions": ["history"]}]}})


@pytest.mark.parametrize("chat,topic", [(1001, None), (-1001, 7), (-1001, False), (True, None)])
def test_whole_group_scope_requires_negative_chat_and_no_fixed_topic(chat, topic):
    with pytest.raises(GatewayDenied):
        Scope(chat, topic, all_topics=True)


def test_missing_and_false_all_topics_are_same_legacy_grant(auth):
    policy = Policy.from_dict({"principals": {"zeta": [
        {"chat_id": -1001, "all_topics": False, "permissions": ["history"]},
    ]}})
    principal = auth.authenticate("Bearer fixture-zeta")
    policy.require(principal, "history", Scope(-1001))
    for scope in (Scope(-1001, 7), Scope(-1001, all_topics=True)):
        with pytest.raises(GatewayDenied):
            policy.require(principal, "history", scope)
    with pytest.raises(GatewayDenied):
        Policy.from_dict({"principals": {"zeta": [
            {"chat_id": -1001, "permissions": ["history"]},
            {"chat_id": -1001, "all_topics": False, "permissions": ["history"]},
        ]}})


def test_approval_verifier_requires_exact_scope_even_when_called_directly():
    with pytest.raises(AuthenticationDenied):
        OwnerApprovalVerifier([9001], [Scope(-1001, all_topics=True)])
    with pytest.raises(AuthenticationDenied):
        OwnerApprovalVerifier([9001], [Scope(-1001, 7), Scope(-1001, all_topics=True)])


@pytest.fixture
def challenge():
    return ApprovalChallenge("zeta", "draft_1", "a" * 64, -1001, 7, 40, 200)


@pytest.fixture
def message(challenge):
    return {
        "message_id": 41, "chat": {"id": -1001, "type": "supergroup"},
        "message_thread_id": 7, "from": {"id": 9001, "is_bot": False},
        "reply_to_message": {"message_id": 40},
        "text": f"approve {challenge.draft_id} {challenge.digest}",
    }


@pytest.fixture
def verifier():
    return OwnerApprovalVerifier([9001], [Scope(-1001, 7)], clock=lambda: 100)


def test_direct_verified_owner_bound_reply_accepted(verifier, message, challenge):
    decision = verifier.verify(trusted_bot_message_from_transport(message), challenge)
    assert decision.verified and decision.approved and decision.owner_id == 9001
    assert (decision.principal_id, decision.draft_id, decision.digest) == ("zeta", "draft_1", "a" * 64)
    message["text"] = message["text"].replace("approve", "reject")
    assert not verifier.verify(trusted_bot_message_from_transport(message), challenge).approved


def test_untrusted_json_or_unsealed_message_cannot_approve(verifier, message, challenge):
    for forged in (message, TrustedBotMessage(message)):
        with pytest.raises(AuthenticationDenied):
            verifier.verify(forged, challenge)


@pytest.mark.parametrize("field", [
    "sender_chat", "forward_origin", "forward_from", "forward_from_chat", "forward_date",
    "forward_sender_name", "via_bot", "sender_business_bot", "business_connection_id",
    "guest_bot", "external_reply", "is_automatic_forward", "forward_from_message_id",
    "forward_signature", "via_business_connection", "paid_star_count", "is_paid_post",
    "guest_query_id", "guest_bot_caller_user", "guest_bot_caller_chat",
    "sender_guest_bot", "via_guest_bot", "via_business_bot", "is_from_offline",
])
def test_forward_anonymous_and_bot_provenance_rejected(verifier, message, challenge, field):
    message[field] = {"id": 9001}
    with pytest.raises(AuthenticationDenied):
        verifier.verify(trusted_bot_message_from_transport(message), challenge)


@pytest.mark.parametrize("change", [
    {"from": {"id": 9001, "is_bot": True}}, {"from": {"id": 9001}},
    {"from": {"id": 9002, "is_bot": False}}, {"from": {"id": True, "is_bot": False}},
    {"chat": {"id": -1002, "type": "supergroup"}},
    {"chat": {"id": -1001, "type": "private"}}, {"message_thread_id": 8},
    {"reply_to_message": {"message_id": 39}}, {"message_id": 40},
    {"text": "approve"}, {"text": "approve draft_1 " + "b" * 64},
    {"text": "approve draft_2 " + "a" * 64}, {"text": "APPROVE draft_1 " + "a" * 64},
])
def test_owner_identity_scope_reply_and_exact_payload_required(verifier, message, challenge, change):
    message.update(change)
    with pytest.raises(AuthenticationDenied):
        verifier.verify(trusted_bot_message_from_transport(message), challenge)


def test_expired_challenge_fails(verifier, message, challenge):
    expired = ApprovalChallenge("zeta", "draft_1", "a" * 64, -1001, 7, 40, 100)
    with pytest.raises(AuthenticationDenied):
        verifier.verify(trusted_bot_message_from_transport(message), expired)


def test_approval_transport_snapshot_cannot_be_mutated(verifier, message, challenge):
    sealed = trusted_bot_message_from_transport(message)
    message["from"]["id"] = 42
    message["text"] = "reject"
    assert verifier.verify(sealed, challenge).approved
    with pytest.raises(TypeError):
        sealed.envelope["from"]["id"] = 42


@pytest.mark.parametrize("value", [None, False, ""])
def test_provenance_presence_denies_even_false_or_empty_values(verifier, message, challenge, value):
    message["guest_query_id"] = value
    with pytest.raises(AuthenticationDenied):
        verifier.verify(trusted_bot_message_from_transport(message), challenge)
