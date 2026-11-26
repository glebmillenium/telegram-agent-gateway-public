import asyncio
import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

import pytest

from telegram_gateway.auth import FakeAuthenticator, OwnerApprovalVerifier
from telegram_gateway.policy import Policy, Scope, GatewayDenied
from telegram_gateway.bot_api import BotApiAdapter, FakeBotTransport, DeliveryUncertain
from telegram_gateway.service import Gateway, StateStore, ProcessLock, ConsumerBusy
from telegram_gateway.events import EventHub, MemorySecretStore, WebhookResponse
from telegram_gateway.protocol import Protocol


def raw(update,chat=-1001,mid=None,text="fixture",sender=41,bot=False,reply=None,topic=None,**extra):
    message={"message_id":mid or update,"date":1700000000,"chat":{"id":chat,"type":"supergroup"},"from":{"id":sender,"is_bot":bot},"text":text}
    if reply is not None:
        message["reply_to_message"]={"message_id":reply}
    if topic is not None:
        message["message_thread_id"]=topic
    message.update(extra)
    return {"update_id":update,"message":message}


class Wire:
    def __init__(self,updates=()):
        self.updates=list(updates)
        self.sends=[]
        self.fail=None

    async def request(self,method,params):
        if method=="getUpdates":
            return {"ok":True,"result":[u for u in self.updates if u["update_id"]>=params["offset"]][:params["limit"]]}
        if method=="sendMessage":
            self.sends.append(dict(params))
            if self.fail:
                raise self.fail
            return {"ok":True,"result":{"message_id":1000+len(self.sends),"chat":{"id":params["chat_id"],"type":"supergroup"}}}
        raise AssertionError("Unexpected RPC")


@pytest.fixture
def setup(tmp_path):
    now=[1000.0]
    policy=Policy.from_dict({"principals":{
        "zeta":[{"chat_id":-1001,"permissions":["history","events","draft","send"]}],
        "support":[{"chat_id":-1002,"topic_id":7,"permissions":["history","events"]}]}})
    auth=FakeAuthenticator({"fixture-zeta":"zeta","fixture-support":"support"})
    a=auth.authenticate("Bearer fixture-zeta")
    b=auth.authenticate("Bearer fixture-support")
    store=StateStore((tmp_path/"state"/"gateway.sqlite").resolve())
    wire=Wire()
    adapter=BotApiAdapter(wire,allowed_scopes={(-1001,None),(-1002,7)})
    verifier=OwnerApprovalVerifier([99],[Scope(-1001)],clock=lambda:now[0])
    gateway=Gateway(store,policy,[a,b],adapter,owner_verifier=verifier,clock=lambda:now[0])
    yield gateway,wire,auth,a,b,now
    store.close()


@pytest.mark.asyncio
async def test_cursor_namespaces_search_and_duplicate(setup):
    g,w,_,a,b,_=setup
    w.updates=[raw(1,text="zeta-only"),raw(2,chat=-1002,topic=7,text="SUPPORT-only"),raw(3,chat=-1999,text="foreign secret")]
    result=await g.poll_once()
    assert result["next_offset"]==4
    assert g.read_history(a,-1001)["messages"][0]["text"]=="zeta-only"
    assert g.search_history(b,-1002,"SUPPORT",topic_id=7)["messages"][0]["text"]=="SUPPORT-only"
    with pytest.raises(GatewayDenied): g.read_history(a,-1002,topic_id=7)
    with pytest.raises(GatewayDenied): g.search_history(b,-1001,"zeta")
    with pytest.raises(GatewayDenied): g.read_history(b,-1002)
    await g.poll_once()
    assert g.store.db.execute("SELECT COUNT(*) FROM gw_messages").fetchone()[0]==2
    assert "foreign secret" not in " ".join(str(tuple(r)) for r in g.store.db.execute("SELECT * FROM gw_messages"))


@pytest.mark.asyncio
async def test_queue_redelivery_ack_cross_owner_expiry_and_revocation(setup):
    g,w,_,a,b,now=setup
    w.updates=[raw(1)]
    await g.poll_once()
    event=g.next_events(a,-1001)["events"][0]
    assert not g.next_events(a,-1001)["events"]
    with pytest.raises(GatewayDenied): g.ack_event(b,event["event_id"])
    now[0]+=g.event_lease_seconds+1
    again=g.next_events(a,-1001)["events"][0]
    assert again["event_id"]==event["event_id"] and again["attempt"]==2
    g.ack_event(a,event["event_id"])
    g.ack_event(a,event["event_id"])
    g.policy=Policy.from_dict({"principals":{"zeta":[],"support":[]}})
    with pytest.raises(GatewayDenied): g.next_events(a,-1001)


@pytest.mark.asyncio
async def test_queue_expiry(setup):
    g,w,_,a,_,now=setup
    w.updates=[raw(1)]
    await g.poll_once()
    now[0]+=4000
    assert g.next_events(a,-1001)["events"]==[]


def test_single_consumer_os_lock(setup):
    g,*_=setup
    path=g.store.path.with_suffix(".consumer.lock")
    with ProcessLock(path):
        with pytest.raises(ConsumerBusy):
            with ProcessLock(path): pass
    with ProcessLock(path): pass


@pytest.mark.asyncio
async def test_cursor_commit_rolls_back_on_ingestion_failure(setup,monkeypatch):
    g,w,_,_,_,_=setup
    w.updates=[raw(1)]
    monkeypatch.setattr(g,"_ingest_owner_decision",lambda *_: (_ for _ in ()).throw(RuntimeError("fake failure")))
    with pytest.raises(RuntimeError): await g.poll_once()
    assert g.store.db.execute("SELECT value FROM gw_meta WHERE key='cursor'").fetchone()[0]=="0"
    assert g.store.db.execute("SELECT COUNT(*) FROM gw_seen").fetchone()[0]==0


async def approve(g,w,a,*,text="reviewed",extra=None,bot=False):
    draft=g.create_draft(a,-1001,text)
    did=draft["draft"]["draft_id"]
    challenge=g.bind_owner_challenge(a,did,-1001,800)
    w.updates=[raw(1,mid=801,text=challenge["approval_text"],sender=99,bot=bot,reply=800,**(extra or {}))]
    await g.poll_once()
    return did


@pytest.mark.asyncio
async def test_owner_approval_exact_once_and_no_cross_agent(setup):
    g,w,_,a,b,_=setup
    did=await approve(g,w,a)
    with pytest.raises(GatewayDenied): await g.send_draft(b,did)
    first=await g.send_draft(a,did)
    second=await g.send_draft(a,did)
    assert first["status"]==second["status"]=="sent" and second["reused"]
    assert len(w.sends)==1 and w.sends[0]["text"]=="reviewed"


@pytest.mark.asyncio
@pytest.mark.parametrize("extra,bot",[({},True),({"sender_chat":{"id":-1001}},False),({"forward_origin":{"type":"user"}},False),({"via_bot":{"id":4}},False)])
async def test_untrusted_provenance_cannot_approve(setup,extra,bot):
    g,w,_,a,_,_=setup
    did=await approve(g,w,a,extra=extra,bot=bot)
    with pytest.raises(GatewayDenied): await g.send_draft(a,did)
    assert w.sends==[]


@pytest.mark.asyncio
async def test_expired_or_revoked_send_rejected(setup):
    g,w,_,a,_,now=setup
    did=await approve(g,w,a)
    now[0]+=301
    with pytest.raises(GatewayDenied): await g.send_draft(a,did)
    assert not w.sends


@pytest.mark.asyncio
async def test_unknown_send_never_automatically_retries(setup):
    g,w,_,a,_,_=setup
    did=await approve(g,w,a)
    w.fail=TimeoutError("private transport detail")
    assert (await g.send_draft(a,did))["status"]=="unknown"
    with pytest.raises(GatewayDenied): await g.send_draft(a,did)
    assert len(w.sends)==1


@pytest.mark.asyncio
async def test_restart_recovery_marks_sending_unknown(setup):
    g,w,_,a,_,_=setup
    did=await approve(g,w,a)
    g.store.db.execute("UPDATE gw_drafts SET status='sending',consumed=1000 WHERE id=?",(did,))
    assert g.recover_uncertain()=={"recovered_as_unknown":1}
    with pytest.raises(GatewayDenied): await g.send_draft(a,did)
    assert not w.sends


@pytest.mark.asyncio
async def test_read_does_not_grant_forward_or_draft(setup):
    g,w,_,a,b,_=setup
    w.updates=[raw(1)]
    await g.poll_once()
    with pytest.raises(GatewayDenied): g.create_forward_draft(a,-1001,1,-1002,topic_id=7)
    with pytest.raises(GatewayDenied): g.create_draft(b,-1002,"text",topic_id=7)


@pytest.mark.asyncio
async def test_immutable_attachment_digest_after_approval(setup):
    g,w,_,a,_,_=setup
    did=await approve(g,w,a)
    body=json.loads(g._draft(a,did)["body"])
    body["attachments"]=[{"name":"tampered.txt","sha256":"a"*64}]
    g.store.db.execute("UPDATE gw_drafts SET body=? WHERE id=?",(json.dumps(body),did))
    with pytest.raises(GatewayDenied): await g.send_draft(a,did)
    assert not w.sends


@pytest.mark.asyncio
async def test_reply_chain_limits_and_persistence(setup):
    g,w,_,a,_,_=setup
    g.max_chain_depth=1
    w.updates=[raw(1),raw(2,reply=1),raw(3,reply=2)]
    await g.poll_once()
    events=g.next_events(a,-1001)["events"]
    assert len(events)==2
    assert events[0]["data"]["task_id"]==events[1]["data"]["task_id"]
    with pytest.raises(GatewayDenied): g.create_draft(a,-1001,"reply",reply_to_message_id=3)


@pytest.mark.asyncio
@pytest.mark.parametrize("uncertain",[False,True])
async def test_chain_cap_rechecked_for_precreated_approved_drafts(setup,uncertain):
    g,w,_,a,_,_=setup
    g.max_chain_steps=1
    w.updates=[raw(1)]
    await g.poll_once()
    first=g.create_draft(a,-1001,"first",reply_to_message_id=1)["draft"]["draft_id"]
    second=g.create_draft(a,-1001,"second",reply_to_message_id=1)["draft"]["draft_id"]
    for index,did in enumerate((first,second),800):
        challenge=g.bind_owner_challenge(a,did,-1001,index)
        w.updates.append(raw(index+10,mid=index+10,text=challenge["approval_text"],sender=99,reply=index))
    await g.poll_once()
    if uncertain:
        w.fail=TimeoutError("simulated ambiguity")
    assert (await g.send_draft(a,first))["status"]==("unknown" if uncertain else "sent")
    with pytest.raises(GatewayDenied): await g.send_draft(a,second)
    assert len(w.sends)==1


@pytest.mark.asyncio
async def test_explicit_forward_is_immutable_snapshot_same_principal(setup):
    g,w,_,a,_,_=setup
    g.policy=Policy.from_dict({"principals":{"zeta":[{"chat_id":-1001,"permissions":["history","events","draft","send","forward"]}],"support":[]}})
    w.updates=[raw(1,text="original")]
    await g.poll_once()
    draft=g.create_forward_draft(a,-1001,1,-1001)
    did=draft["draft"]["draft_id"]
    challenge=g.bind_owner_challenge(a,did,-1001,800)
    w.updates.append(raw(2,mid=801,text=challenge["approval_text"],sender=99,reply=800))
    await g.poll_once()
    g.store.db.execute("UPDATE gw_messages SET body=? WHERE owner=? AND mid=1",(json.dumps({"text":"edited later"}),a.id))
    assert (await g.send_draft(a,did))["status"]=="sent"
    assert w.sends[0]["text"]=="original"


@pytest.mark.asyncio
async def test_state_restart_keeps_cursor_and_unacked_events(setup):
    g,w,_,a,_,_=setup
    w.updates=[raw(1)]
    await g.poll_once()
    second=StateStore(g.store.path)
    try:
        restarted=Gateway(second,g.policy,g.principals,g.bot,clock=g.clock)
        assert second.db.execute("SELECT value FROM gw_meta WHERE key='cursor'").fetchone()[0]=="2"
        assert len(restarted.next_events(a,-1001)["events"])==1
    finally:
        second.close()


def test_state_inside_checkout_rejected():
    import telegram_gateway.service as module
    with pytest.raises(ValueError): StateStore(Path(module.__file__).resolve().parents[2]/"must-not-create.sqlite")


@pytest.mark.asyncio
async def test_fake_protocol_end_to_end_events_and_owner_send(setup,tmp_path):
    g,w,auth,a,b,now=setup
    deliveries=[]
    async def receiver(target,body,headers):
        obj=json.loads(body)
        if obj.get("type")=="verification":
            return WebhookResponse(200,json.dumps({"challenge":obj["challenge"]}).encode())
        deliveries.append((target,body,headers))
        return WebhookResponse(204)
    def authorize(p,name,args):
        assert name=="telegram.message.created"
        g.policy.require(p,"events",Scope(args["chat_id"],args.get("topic_id")))
    def callback_authorize(p,url):
        if url != "https://events.example.test/"+p.id:
            raise GatewayDenied("Callback not bound to principal")
    hub=EventHub((tmp_path/"events.sqlite").resolve(),authorize,sender=receiver,resolver=lambda _: ["8.8.8.8"],secret_store=MemorySecretStore(),clock=g.clock,catalog_authorizer=lambda p:bool(g.policy.allowed_scopes(p,"events")),callback_authorizer=callback_authorize)
    protocol=Protocol(auth,g,hub)
    async def rpc(method,params=None,credential="fixture-zeta"):
        return await protocol.request({"jsonrpc":"2.0","id":1,"method":method,"params":params or {}},authorization="Bearer "+credential)
    assert "result" in await rpc("server/discover")
    tools=(await rpc("tools/list",credential="fixture-support"))["result"]["tools"]
    assert "send_draft" not in {t["name"] for t in tools}
    assert "error" in await rpc("tools/call",{"name":"read_history","arguments":{"chat_id":-1001,"agent_id":"support"}})
    assert "error" in await rpc("tools/call",{"name":"bind_owner_challenge","arguments":{}})
    assert "error" in await rpc("events/subscribe",{"name":"telegram.message.created","arguments":{"chat_id":-1002,"topic_id":7},"delivery":{"mode":"webhook","url":"https://events.example.test/receiver","secret":"whsec_"+"YWFh"*8}})
    sub={"name":"telegram.message.created","arguments":{"chat_id":-1001,"topic_id":None},"delivery":{"mode":"webhook","url":"https://events.example.test/zeta","secret":"whsec_"+"YWFh"*8}}
    subscribed=await rpc("events/subscribe",sub)
    assert "result" in subscribed,subscribed
    w.updates=[raw(1,text="fake protocol event"),raw(2,chat=-1002,topic=7,text="SUPPORT private")]
    await g.poll_once()
    captured_at = now[0]
    now[0] += 40
    assert g.export_events(a,hub)=={"exported":1}
    await hub.deliver_due(principal=a)
    assert len(deliveries)==1
    assert json.loads(deliveries[0][1])["data"]["text"]=="fake protocol event"
    assert json.loads(deliveries[0][1])["timestamp"] == datetime.fromtimestamp(captured_at, timezone.utc).isoformat()
    assert int(deliveries[0][2]["webhook-timestamp"]) == int(now[0])
    assert "webhook-signature" in deliveries[0][2]
    assert "result" in await rpc("events/unsubscribe",{k:v for k,v in sub.items() if k!="delivery"}|{"delivery":{"mode":"webhook","url":sub["delivery"]["url"]}})
    assert len(w.sends)==0
    hub.close()


@pytest.fixture
def multibot(tmp_path):
    from telegram_gateway.bot_api import FakeBotTransport
    policy = Policy.from_dict({"principals": {"zeta": [{"chat_id": -1001,
        "permissions": ["history", "events", "draft", "send", "forward"]}]}})
    principal = FakeAuthenticator({"fixture-multi": "zeta"}).authenticate("Bearer fixture-multi")
    gateways, wires = [], []
    for index, ref in enumerate(("@Coordinator_Demo_Bot", "planner_demo_ai")):
        store = StateStore((tmp_path / f"bot-{index}" / "state.sqlite").resolve())
        wire = FakeBotTransport()
        adapter = BotApiAdapter(wire, allowed_scopes={(-1001, None)})
        verifier = OwnerApprovalVerifier([99], [Scope(-1001)], clock=lambda: 1000.0)
        gateways.append(Gateway(store, policy, [principal], adapter, owner_verifier=verifier,
                                clock=lambda: 1000.0, bot_reference=ref))
        wires.append(wire)
    yield gateways, wires, principal
    for gateway in gateways:
        gateway.store.close()


async def test_same_chat_and_message_ids_have_separate_tasks_payloads_and_exports(multibot):
    gateways, wires, p = multibot
    class Collector:
        def __init__(self):
            self.items = {}
        def enqueue(self, principal, event_name, args, body, event_id, *, occurred_at):
            assert occurred_at == 1000.0
            key = (principal.id, event_id)
            assert key not in self.items, "cross-bot event dedup collision"
            self.items[key] = body
    hub = Collector()
    tasks, exported_ids = [], []
    for index, (g, wire) in enumerate(zip(gateways, wires)):
        wire.updates = [raw(1, text=f"private bot {index}")]
        await g.poll_once()
        message = g.read_history(p, -1001)["messages"][0]
        assert message["text"] == f"private bot {index}"
        assert message["bot_reference"] == g.bot_reference
        assert message["task_id"].startswith(f"bot:{g.bot_reference}:")
        tasks.append(message["task_id"])
        event = g.next_events(p, -1001)["events"][0]
        assert event["data"]["bot_reference"] == g.bot_reference
        assert g.export_events(p, hub) == {"exported": 1}
        assert g.export_events(p, hub) == {"exported": 0}
    assert len(set(tasks)) == 2 and len(hub.items) == 2
    for (_, event_id), body in hub.items.items():
        assert "bot_reference" not in body
        assert event_id.startswith(body["task_id"].split("tg:")[0] + "tg-")
        exported_ids.append(event_id)
    assert len(set(exported_ids)) == 2


async def test_equal_draft_ids_cannot_cross_approve_and_send_receipts_are_namespaced(multibot, monkeypatch):
    import telegram_gateway.service as service
    from types import SimpleNamespace
    gateways, wires, p = multibot
    monkeypatch.setattr(service.uuid, "uuid4", lambda: SimpleNamespace(hex="a" * 32))
    drafts = [g.create_draft(p, -1001, "same text") for g in gateways]
    did = drafts[0]["draft"]["draft_id"]
    assert did == drafts[1]["draft"]["draft_id"]
    assert drafts[0]["digest"] != drafts[1]["digest"]
    challenges = [g.bind_owner_challenge(p, did, -1001, 800) for g in gateways]
    for g, w in zip(gateways, wires):
        w.updates = [raw(1, mid=801, text=challenges[0]["approval_text"], sender=99, reply=800)]
        await g.poll_once()
    assert gateways[0]._draft(p, did)["status"] == "approved"
    assert gateways[1]._draft(p, did)["status"] == "pending"
    with pytest.raises(GatewayDenied):
        await gateways[1].send_draft(p, did)
    assert wires[1].sent == []
    wires[1].updates.append(raw(2, mid=802, text=challenges[1]["approval_text"], sender=99, reply=800))
    await gateways[1].poll_once()
    operation_ids = []
    for g, wire in zip(gateways, wires):
        result = await g.send_draft(p, did)
        assert result["status"] == "sent" and result["receipt"]["bot_reference"] == g.bot_reference
        assert result["receipt"]["operation_id"] == f"bot:{g.bot_reference}:{did}"
        assert len(wire.sent) == 1
        operation_ids.append(result["receipt"]["operation_id"])
        assert (await g.send_draft(p, did))["reused"] is True
        assert len(wire.sent) == 1
    assert len(set(operation_ids)) == 2


@pytest.mark.parametrize("requested", [None, "another_gateway_bot"])
def test_store_cannot_reopen_under_omitted_or_different_bot(multibot, requested):
    gateways, _, p = multibot
    g = gateways[0]
    with pytest.raises(GatewayDenied):
        Gateway(g.store, g.policy, [p], g.bot, bot_reference=requested)
    assert g.store.db.execute("SELECT value FROM gw_meta WHERE key='gateway_bot_reference'").fetchone()[0] == "coordinator_demo_bot"


async def test_same_normalized_bot_restart_preserves_cursor_queue_and_namespace(multibot):
    gateways, wires, p = multibot
    g, wire = gateways[0], wires[0]
    wire.updates = [raw(1)]
    await g.poll_once()
    secondary = StateStore(g.store.path)
    try:
        restarted = Gateway(secondary, g.policy, [p], g.bot, clock=g.clock, bot_reference="@COORDINATOR_DEMO_BOT")
        assert restarted.bot_reference == "coordinator_demo_bot"
        assert secondary.db.execute("SELECT value FROM gw_meta WHERE key='cursor'").fetchone()[0] == "2"
        assert restarted.next_events(p, -1001)["events"][0]["data"]["bot_reference"] == "coordinator_demo_bot"
    finally:
        secondary.close()


@pytest.mark.parametrize("reference", ["@@coordinator_demo_bot", "zeta", "../coordinator_demo_bot", {"bot_reference": "coordinator_demo_bot"}])
def test_invalid_reference_rejected_before_state_access(reference):
    class NoStateAccess:
        def transaction(self):
            pytest.fail("invalid bot reference accessed state")
    with pytest.raises(GatewayDenied):
        Gateway(NoStateAccess(), None, [], None, bot_reference=reference)


def test_existing_empty_legacy_instance_cannot_be_relabelled(setup):
    g, _, _, a, _, _ = setup
    with pytest.raises(GatewayDenied):
        Gateway(g.store, g.policy, [a], g.bot, bot_reference="coordinator_demo_bot")


@pytest.mark.parametrize("legacy_data", ["draft", "cursor"])
def test_pre_namespace_legacy_state_with_data_cannot_be_adopted(setup, legacy_data):
    g, _, _, a, _, _ = setup
    g.store.db.execute("DELETE FROM gw_meta WHERE key='gateway_bot_reference'")
    if legacy_data == "draft":
        g.create_draft(a, -1001, "legacy provenance unknown")
    else:
        g.store.db.execute("UPDATE gw_meta SET value='100' WHERE key='cursor'")
    with pytest.raises(GatewayDenied):
        Gateway(g.store, g.policy, [a], g.bot, bot_reference="coordinator_demo_bot")
    assert not g.store.db.execute("SELECT 1 FROM gw_meta WHERE key='gateway_bot_reference'").fetchone()


async def test_copied_foreign_draft_cannot_bind_approve_or_send(multibot):
    import hashlib
    from telegram_gateway.service import canonical
    gateways, wires, p = multibot
    g = gateways[1]
    d = g.create_draft(p, -1001, "reviewed only for agent_beta")
    did = d["draft"]["draft_id"]
    g.bind_owner_challenge(p, did, -1001, 800)
    d["draft"]["bot_reference"] = gateways[0].bot_reference
    payload = canonical(d["draft"])
    digest = hashlib.sha256(payload.encode()).hexdigest()
    g.store.db.execute("UPDATE gw_drafts SET body=?,digest=? WHERE id=?", (payload, digest, did))
    wires[1].updates = [raw(1, mid=801, text=f"approve {did} {digest}", sender=99, reply=800)]
    await g.poll_once()
    assert g.store.db.execute("SELECT status FROM gw_drafts WHERE id=?", (did,)).fetchone()[0] == "pending"
    with pytest.raises(GatewayDenied):
        g.bind_owner_challenge(p, did, -1001, 900)
    g.store.db.execute("UPDATE gw_drafts SET status='approved' WHERE id=?", (did,))
    with pytest.raises(GatewayDenied):
        await g.send_draft(p, did)
    assert wires[1].sent == []


async def test_forward_snapshot_and_reply_task_keep_source_bot(multibot):
    gateways, wires, p = multibot
    for g, wire in zip(gateways, wires):
        wire.updates = [raw(1, text="source")]
        await g.poll_once()
        forwarded = g.create_forward_draft(p, -1001, 1, -1001)["draft"]
        assert forwarded["bot_reference"] == g.bot_reference
        assert forwarded["source"]["bot_reference"] == g.bot_reference
        reply = g.create_draft(p, -1001, "response", reply_to_message_id=1)["draft"]
        original = g.read_history(p, -1001)["messages"][0]
        assert reply["task_id"] == original["task_id"]
        assert reply["task_id"].startswith(f"bot:{g.bot_reference}:")
