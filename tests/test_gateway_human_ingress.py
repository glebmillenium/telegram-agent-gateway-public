"""Human ingestion regression, synthetic IDs/data and in-memory Bot API only.

None and numeric thread IDs are separate payload scopes. These fixtures do not
infer a thread ID from a Telegram link or a topic display name.
"""
import pytest

from telegram_gateway.auth import FakeAuthenticator, OwnerApprovalVerifier
from telegram_gateway.bot_api import BotApiAdapter, FakeBotTransport
from telegram_gateway.policy import GatewayDenied, Policy, Scope
from telegram_gateway.service import Gateway, StateStore


CHAT = -100901
FOREIGN_CHAT = -100902
OWNER = 7301
IMPOSTOR = 7302
BOT_REFERENCE = "human_ingress_fixture_bot"
NOW = 1700000100.0


def human_update(number, *, topic, sender=OWNER, chat=CHAT,
                 display_name="Shared Fixture Name", text="Human fixture", reply=None):
    message = {
        "message_id": number,
        "date": int(NOW),
        "chat": {"id": chat, "type": "supergroup"},
        "from": {"id": sender, "is_bot": False, "first_name": display_name,
                 "username": "fixture_display"},
        "text": text,
    }
    if topic is not None:
        message.update(message_thread_id=topic, is_topic_message=True)
    if reply is not None:
        message["reply_to_message"] = {"message_id": reply}
    return {"update_id": number, "message": message}


def build(path, wire, topic):
    policy = Policy.from_dict({"principals": {
        "reader": [{"chat_id": CHAT, "all_topics": True,
                    "permissions": ["history", "events", "draft", "send"]}]
    }})
    principal = FakeAuthenticator({"fixture-only": "reader"}).authenticate("Bearer fixture-only")
    store = StateStore(path)
    adapter = BotApiAdapter(wire, allowed_all_topic_chats={CHAT})
    verifier = OwnerApprovalVerifier([OWNER], [Scope(CHAT, topic)], clock=lambda: NOW)
    gateway = Gateway(store, policy, [principal], adapter, owner_verifier=verifier,
                      clock=lambda: NOW, bot_reference=BOT_REFERENCE)
    return gateway, principal


@pytest.mark.asyncio
@pytest.mark.parametrize("topic", [None, 1, 913])
async def test_human_messages_events_and_cursor_survive_restart_without_foreign_chat(tmp_path, topic):
    path = (tmp_path / "human" / "gateway.sqlite").resolve()
    wire = FakeBotTransport([
        human_update(1, topic=topic, text="Verified numeric owner fixture"),
        human_update(2, topic=topic, sender=IMPOSTOR, text="Matching display name fixture"),
        human_update(3, topic=topic, chat=FOREIGN_CHAT, text="Forbidden chat fixture"),
    ])
    gateway, principal = build(path, wire, topic)
    try:
        result = await gateway.poll_once()
        assert result == {"received": 3, "accepted": 2, "next_offset": 4}
        messages = gateway.read_history(principal, CHAT, all_topics=True)["messages"]
        assert [(m["message_id"], m["sender_id"], m["topic_id"], m["provenance"])
                for m in messages] == [(2, IMPOSTOR, topic, "human"), (1, OWNER, topic, "human")]
        assert gateway.read_history(principal, CHAT, topic_id=topic)["messages"] == messages
        if topic is not None:
            assert gateway.read_history(principal, CHAT)["messages"] == []
        for operation in (gateway.read_history, gateway.next_events):
            with pytest.raises(GatewayDenied):
                operation(principal, FOREIGN_CHAT, all_topics=True)
        assert gateway.search_history(principal, CHAT, "Forbidden", all_topics=True)["messages"] == []
        assert gateway.store.db.execute("SELECT COUNT(*) FROM gw_messages WHERE chat=?", (FOREIGN_CHAT,)).fetchone()[0] == 0
        assert gateway.store.db.execute("SELECT COUNT(*) FROM gw_events WHERE chat=?", (FOREIGN_CHAT,)).fetchone()[0] == 0
        assert gateway.store.db.execute("SELECT COUNT(*) FROM gw_seen").fetchone()[0] == 2
        assert gateway.store.db.execute("SELECT value FROM gw_meta WHERE key='cursor'").fetchone()[0] == "4"
    finally:
        gateway.store.close()

    # Reopen actual SQLite files: captured history, queued events and offset all persist.
    gateway, principal = build(path, wire, topic)
    try:
        assert gateway.read_history(principal, CHAT, all_topics=True)["messages"] == messages
        events = gateway.next_events(principal, CHAT, all_topics=True)["events"]
        assert [(e["data"]["message_id"], e["data"]["sender_id"], e["data"]["topic_id"])
                for e in events] == [(1, OWNER, topic), (2, IMPOSTOR, topic)]
        for event in events:
            assert gateway.ack_event(principal, event["event_id"]) == {"acknowledged": True}
        assert await gateway.poll_once() == {"received": 0, "accepted": 0, "next_offset": 4}
        assert wire.calls[-1]["params"]["offset"] == 4
        assert gateway.store.db.execute("SELECT COUNT(*) FROM gw_messages").fetchone()[0] == 2
        assert gateway.store.db.execute("SELECT COUNT(*) FROM gw_events").fetchone()[0] == 2
        assert gateway.next_events(principal, CHAT, all_topics=True)["events"] == []
        assert wire.sent == []
        assert {call["method"] for call in wire.calls} == {"getUpdates"}
    finally:
        gateway.store.close()


@pytest.mark.asyncio
@pytest.mark.parametrize("topic", [None, 1, 913])
async def test_identical_display_name_never_grants_owner_approval(tmp_path, topic):
    wire = FakeBotTransport()
    gateway, principal = build((tmp_path / "identity" / "gateway.sqlite").resolve(), wire, topic)
    try:
        draft = gateway.create_draft(principal, CHAT, "Unsent synthetic draft", topic_id=topic)
        draft_id = draft["draft"]["draft_id"]
        challenge = gateway.bind_owner_challenge(principal, draft_id, CHAT, 800, topic_id=topic)
        wire.updates.append(human_update(11, topic=topic, sender=IMPOSTOR,
                                        text=challenge["approval_text"], reply=800))
        await gateway.poll_once()
        row = gateway.store.db.execute("SELECT status,approval_owner FROM gw_drafts WHERE id=?", (draft_id,)).fetchone()
        assert tuple(row) == ("pending", None)
        # The same numeric owner remains the owner after a display-name change.
        wire.updates.append(human_update(12, topic=topic, sender=OWNER,
                                        display_name="Renamed Fixture Owner",
                                        text=challenge["approval_text"], reply=800))
        await gateway.poll_once()
        row = gateway.store.db.execute("SELECT status,approval_owner,approval_message FROM gw_drafts WHERE id=?", (draft_id,)).fetchone()
        assert tuple(row) == ("approved", OWNER, 12)
        history = gateway.read_history(principal, CHAT, all_topics=True)["messages"]
        assert [(m["sender_id"], m["provenance"]) for m in history] == [(OWNER, "human"), (IMPOSTOR, "human")]
        assert len(gateway.next_events(principal, CHAT, all_topics=True)["events"]) == 2
        assert gateway.store.db.execute("SELECT value FROM gw_meta WHERE key='cursor'").fetchone()[0] == "13"
        assert wire.sent == []
    finally:
        gateway.store.close()
