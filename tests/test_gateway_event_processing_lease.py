"""Synthetic queue claims only: no live files, HTTP, Telegram or acknowledgements."""
from concurrent.futures import ThreadPoolExecutor
from threading import Barrier

import pytest

from telegram_gateway.auth import FakeAuthenticator
from telegram_gateway.bot_api import BotApiAdapter, FakeBotTransport
from telegram_gateway.policy import GatewayDenied, Policy
from telegram_gateway.service import Gateway, StateStore


CHAT = -100701
BOT = "lease_fixture_bot"


def open_gateway(path, now, **options):
    auth = FakeAuthenticator({"fixture-reader": "reader", "fixture-other": "other"})
    principal = auth.authenticate("Bearer fixture-reader")
    foreign = auth.authenticate("Bearer fixture-other")
    policy = Policy.from_dict({"principals": {
        who: [{"chat_id": CHAT, "permissions": ["history", "events"]}]
        for who in ("reader", "other")
    }})
    wire = FakeBotTransport()
    store = StateStore(path)
    try:
        gateway = Gateway(store, policy, [principal], BotApiAdapter(wire, allowed_scopes={(CHAT, None)}),
                          clock=lambda: now[0], bot_reference=BOT, **options)
    except BaseException:
        store.close()
        raise
    return gateway, principal, foreign, wire


async def seed(gateway, wire, count=2):
    wire.updates = [
        {"update_id": number, "message": {
            "message_id": number, "date": 1700000000,
            "chat": {"id": CHAT, "type": "supergroup"},
            "from": {"id": 501, "is_bot": False}, "text": "Synthetic queue event " + str(number),
        }} for number in range(1, count + 1)
    ]
    await gateway.poll_once()


@pytest.mark.asyncio
async def test_two_consumers_reclaim_then_late_ack_excludes_first_event(tmp_path):
    now = [1000.0]
    path = (tmp_path / "queue.sqlite").resolve()
    first, principal, _, wire = open_gateway(path, now)
    second = None
    try:
        await seed(first, wire)
        second, second_principal, _, _ = open_gateway(path, now)
        snapshot_one = first.next_events(principal, CHAT)["events"]
        first_id, second_id = [item["event_id"] for item in snapshot_one]
        assert [item["attempt"] for item in snapshot_one] == [1, 1]
        assert second.next_events(second_principal, CHAT)["events"] == []
        now[0] += 121
        snapshot_two = second.next_events(second_principal, CHAT)["events"]
        assert [item["event_id"] for item in snapshot_two] == [first_id, second_id]
        assert [item["attempt"] for item in snapshot_two] == [2, 2]
        assert first.ack_event(principal, first_id) == {"acknowledged": True}
        # A completed ACK cannot retract a batch already returned to a consumer.
        assert snapshot_two[0]["event_id"] == first_id
        now[0] += 121
        later = second.next_events(second_principal, CHAT)["events"]
        assert [(item["event_id"], item["attempt"]) for item in later] == [(second_id, 3)]
        assert second.ack_event(second_principal, second_id) == {"acknowledged": True}
        assert first.ack_event(principal, second_id) == {"acknowledged": True}
        now[0] += 121
        assert first.next_events(principal, CHAT)["events"] == []
        assert [tuple(row) for row in first.store.db.execute(
            "SELECT status,attempts FROM gw_events ORDER BY id")] == [("acknowledged", 2), ("acknowledged", 3)]
        assert wire.sent == []
    finally:
        if second is not None:
            second.store.close()
        first.store.close()


@pytest.mark.asyncio
async def test_default_processing_lease_holds_at_sixty_seconds_and_reclaims_after_121(tmp_path):
    now = [1000.0]
    gateway, principal, _, wire = open_gateway((tmp_path / "queue.sqlite").resolve(), now)
    try:
        await seed(gateway, wire, count=1)
        first = gateway.next_events(principal, CHAT)["events"][0]
        assert gateway.store.db.execute("SELECT claimed_until FROM gw_events").fetchone()[0] == 1120.0
        now[0] = 1060.0
        assert gateway.next_events(principal, CHAT)["events"] == []
        now[0] = 1121.0
        again = gateway.next_events(principal, CHAT)["events"][0]
        assert (again["event_id"], again["attempt"]) == (first["event_id"], 2)
    finally:
        gateway.store.close()


@pytest.mark.asyncio
async def test_two_connections_claim_atomically_and_foreign_principal_cannot_ack(tmp_path):
    now = [1000.0]
    path = (tmp_path / "queue.sqlite").resolve()
    gateway, principal, foreign, wire = open_gateway(path, now)
    try:
        await seed(gateway, wire)
        barrier = Barrier(2)

        def claim():
            child, who, _, _ = open_gateway(path, now)
            try:
                barrier.wait(timeout=10)
                return child.next_events(who, CHAT, limit=1)["events"]
            finally:
                child.store.close()

        with ThreadPoolExecutor(max_workers=2) as executor:
            futures = [executor.submit(claim) for _ in range(2)]
            results = [future.result(timeout=15) for future in futures]
        assert [len(batch) for batch in results] == [1, 1]
        ids = [batch[0]["event_id"] for batch in results]
        assert len(set(ids)) == 2
        assert all(batch[0]["attempt"] == 1 for batch in results)
        with pytest.raises(GatewayDenied):
            gateway.ack_event(foreign, ids[0])
        assert gateway.next_events(principal, CHAT)["events"] == []
    finally:
        gateway.store.close()


@pytest.mark.asyncio
async def test_expiry_wins_over_an_active_processing_lease(tmp_path):
    now = [1000.0]
    gateway, principal, _, wire = open_gateway((tmp_path / "queue.sqlite").resolve(), now, event_ttl=180)
    try:
        await seed(gateway, wire, count=1)
        gateway.next_events(principal, CHAT)
        now[0] = 1121.0
        assert gateway.next_events(principal, CHAT)["events"][0]["attempt"] == 2
        now[0] = 1181.0
        assert gateway.next_events(principal, CHAT)["events"] == []
        assert tuple(gateway.store.db.execute("SELECT status,attempts FROM gw_events").fetchone()) == ("expired", 2)
    finally:
        gateway.store.close()


@pytest.mark.asyncio
async def test_processing_lease_does_not_remove_five_attempt_retry_ceiling(tmp_path):
    now = [1000.0]
    gateway, principal, _, wire = open_gateway((tmp_path / "queue.sqlite").resolve(), now)
    try:
        await seed(gateway, wire, count=1)
        for attempt in range(1, 6):
            assert gateway.next_events(principal, CHAT)["events"][0]["attempt"] == attempt
            now[0] += 121
        assert gateway.next_events(principal, CHAT)["events"] == []
        assert tuple(gateway.store.db.execute("SELECT status,attempts FROM gw_events").fetchone()) == ("dead", 5)
    finally:
        gateway.store.close()


@pytest.mark.parametrize("seconds", [0, -1, True, False, 1.0, "120", None, 3601])
def test_invalid_processing_lease_fails_closed(tmp_path, seconds):
    with pytest.raises(GatewayDenied):
        open_gateway((tmp_path / "queue.sqlite").resolve(), [1000.0], event_lease_seconds=seconds)


@pytest.mark.parametrize("seconds", [1, 120, 3600])
def test_processing_lease_accepts_documented_integer_bounds(tmp_path, seconds):
    gateway, _, _, _ = open_gateway((tmp_path / "queue.sqlite").resolve(), [1000.0], event_lease_seconds=seconds)
    gateway.store.close()
