"""Finite offline acceptance run. No sockets, Telegram token or production auth."""
import argparse
import asyncio
import json
from pathlib import Path

from .auth import FakeAuthenticator, OwnerApprovalVerifier
from .policy import Policy, Scope, GatewayDenied
from .bot_api import BotApiAdapter, FakeBotTransport
from .service import Gateway, StateStore, ProcessLock
from .events import EventHub, MemorySecretStore, WebhookResponse
from .protocol import Protocol


def message(update,chat,text,*,topic=None,sender=41,reply=None):
    value={"message_id":update,"date":1700000000,"chat":{"id":chat,"type":"supergroup"},
           "from":{"id":sender,"is_bot":False},"text":text}
    if topic is not None:
        value["message_thread_id"]=topic
    if reply is not None:
        value["reply_to_message"]={"message_id":reply}
    return {"update_id":update,"message":value}


async def run(state_dir,config):
    state_dir=Path(state_dir).resolve()
    if not state_dir.is_absolute() or state_dir.is_relative_to(Path(__file__).resolve().parents[2]):
        raise ValueError("Use an external absolute state directory")
    state_dir.mkdir(parents=True,exist_ok=True)
    # A demo must not silently append/replay fixtures into existing production/previous state.
    if any(state_dir.glob("*.sqlite*")):
        raise ValueError("Use a fresh state directory for the demo")
    policy=Policy.from_dict(json.loads(Path(config).read_text(encoding="utf-8")))
    auth=FakeAuthenticator({"fixture-coordinator":"coordinator","fixture-support":"support"})
    a,b=(auth.authenticate("Bearer fixture-"+name) for name in ("coordinator","support"))
    fake=FakeBotTransport()
    bot=BotApiAdapter(fake,allowed_scopes={(-1001,None),(-1002,7)})
    store=StateStore(state_dir/"gateway.sqlite")
    gateway=Gateway(store,policy,[a,b],bot,owner_verifier=OwnerApprovalVerifier([99],[Scope(-1001)]))
    received=[]
    async def receiver(target,body,headers):
        value=json.loads(body)
        if value.get("type")=="verification":
            return WebhookResponse(200,json.dumps({"challenge":value["challenge"]}).encode())
        received.append(value)
        return WebhookResponse(204)
    def event_auth(p,name,args):
        if name!="telegram.message.created":
            raise GatewayDenied("Unknown event")
        policy.require(p,"events",Scope(args["chat_id"],args.get("topic_id")))
    def callback_auth(p,url):
        if url!="https://events.example.test/"+p.id:
            raise GatewayDenied("Destination unavailable")
    hub=EventHub(state_dir/"events.sqlite",event_auth,sender=receiver,resolver=lambda _: ["8.8.8.8"],
                 secret_store=MemorySecretStore(),catalog_authorizer=lambda p:bool(policy.allowed_scopes(p,"events")),callback_authorizer=callback_auth)
    protocol=Protocol(auth,gateway,hub)
    async def rpc(method,params=None,who="coordinator"):
        answer=await protocol.request({"jsonrpc":"2.0","id":1,"method":method,"params":params or {}},authorization="Bearer fixture-"+who)
        if "error" in answer:
            raise RuntimeError("Offline acceptance request rejected")
        return answer["result"]
    try:
        with ProcessLock(state_dir/"demo.lock"):
            gateway.recover_uncertain()
            discover=await rpc("server/discover")
            await rpc("events/list")
            for who in ("coordinator","support"):
                scope={"chat_id":-1001,"topic_id":None} if who=="coordinator" else {"chat_id":-1002,"topic_id":7}
                await rpc("events/subscribe",{"name":"telegram.message.created","arguments":scope,
                          "delivery":{"mode":"webhook","url":"https://events.example.test/"+who,"secret":"whsec_"+"YWFh"*8}},who)
            fake.updates.extend([message(1,-1001,"FAKE: message for Coordinator"),message(2,-1002,"FAKE: message for SUPPORT",topic=7),message(3,-1999,"FAKE: must be discarded")])
            await gateway.poll_once()
            for principal in (a,b):
                gateway.export_events(principal,hub)
                await hub.deliver_due(principal=principal)
            denied=await protocol.request({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_history","arguments":{"chat_id":-1002,"topic_id":7}}},authorization="Bearer fixture-coordinator")
            assert "error" in denied and len(received)==2
            draft=(await rpc("tools/call",{"name":"create_draft","arguments":{"chat_id":-1001,"text":"FAKE: reviewed response","reply_to_message_id":1}}))["structuredContent"]
            did=draft["draft"]["draft_id"]
            challenge=gateway.bind_owner_challenge(a,did,-1001,800)
            # Synthetic direct-human envelope, never a real approval or Telegram send.
            fake.updates.append(message(4,-1001,challenge["approval_text"],sender=99,reply=800))
            await gateway.poll_once()
            sent=(await rpc("tools/call",{"name":"send_draft","arguments":{"draft_id":did}}))["structuredContent"]
            repeat=(await rpc("tools/call",{"name":"send_draft","arguments":{"draft_id":did}}))["structuredContent"]
            assert sent["status"]=="sent" and repeat["reused"] and len(fake.sent)==1
            for who in ("coordinator","support"):
                scope={"chat_id":-1001,"topic_id":None} if who=="coordinator" else {"chat_id":-1002,"topic_id":7}
                await rpc("events/unsubscribe",{"name":"telegram.message.created","arguments":scope,"delivery":{"mode":"webhook","url":"https://events.example.test/"+who}},who)
            return {"result":"PASS","mode":"offline-fake-only","protocol":"2026-07-28",
                    "isolated_principals":2,"accepted_fake_webhooks":len(received),"fake_sends":len(fake.sent),
                    "cross_scope_denied":True,"repeat_send_reused_receipt":True,
                    "telegram_connected":False,"dot_wakeup_verified":False,"state_directory":str(state_dir)}
    finally:
        hub.close()
        store.close()


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state-dir",type=Path,required=True)
    parser.add_argument("--config",type=Path,required=True)
    args=parser.parse_args()
    try:
        result=asyncio.run(run(args.state_dir,args.config))
    except Exception:
        parser.exit(2,"Offline demo rejected; check fresh external state directory and fake policy.\n")
    print(json.dumps(result,ensure_ascii=False,indent=2))


if __name__=="__main__":
    main()
