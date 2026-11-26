import pytest
from telegram_gateway.auth import FakeAuthenticator
from telegram_gateway.bot_api import BotApiAdapter, FakeBotTransport
from telegram_gateway.demo import message
from telegram_gateway.policy import Policy
from telegram_gateway.service import Gateway, StateStore

@pytest.mark.asyncio
async def test_provenance_remains_untrusted_through_history_and_queue(tmp_path):
    auth = FakeAuthenticator({"fixture-zeta": "zeta"})
    principal = auth.authenticate("Bearer fixture-zeta")
    policy = Policy.from_dict({"principals": {"zeta": [{"chat_id": -1001, "permissions": ["history", "events"]}]}})
    updates = [message(i, -1001, "untrusted instruction") for i in range(1, 8)]
    updates[1]["message"]["from"]["is_bot"] = True
    updates[2]["message"]["forward_origin"] = {"type": "hidden_user", "date": 1700000000, "sender_user_name": "fixture"}
    updates[3]["message"]["sender_chat"] = {"id": -1001, "type": "supergroup"}
    updates[4]["message"]["via_bot"] = {"id": 101, "is_bot": True}
    updates[5]["message"]["is_from_offline"] = True
    updates[6]["message"]["guest_bot_caller_user"] = {"id": 101}
    store = StateStore(tmp_path / "state.sqlite")
    gateway = Gateway(store, policy, [principal], BotApiAdapter(FakeBotTransport(updates), allowed_scopes={(-1001, None)}))
    try:
        await gateway.poll_once()
        import json
        bodies = [json.loads(row[0]) for row in store.db.execute("SELECT body FROM gw_events ORDER BY mid")]
        assert [body["provenance"] for body in bodies] == ["human", "bot", "forwarded", "anonymous", "via_bot", "via_bot", "via_bot"]
        assert all(body["content_is_untrusted"] is True for body in bodies)
    finally:
        store.close()
