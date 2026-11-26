import json
import pytest
from telegram_gateway.auth import FakeAuthenticator
from telegram_gateway.policy import GatewayDenied,Policy
from telegram_gateway.bot_api import BotApiAdapter,DeliveryUncertain
from telegram_gateway.service import Gateway,StateStore
from telegram_gateway.standing import StandingSendPolicy
from test_gateway_service import Wire,raw

@pytest.fixture
def live_shape(tmp_path):
    clock=[1000.0]
    auth=FakeAuthenticator({'fixture-zeta':'zeta','fixture-agent_beta':'agent_beta'})
    zeta=auth.authenticate('Bearer fixture-zeta');agent_beta=auth.authenticate('Bearer fixture-agent_beta')
    policy=Policy.from_dict({'principals':{p:[{'chat_id':-1001,'topic_id':None,'all_topics':True,
                          'permissions':['history','events','draft']},
                         {'chat_id':-1001,'topic_id':None,'permissions':['send']}] for p in ['zeta','agent_beta']}})
    store=StateStore((tmp_path/'gateway.sqlite').resolve());wire=Wire()
    bot=BotApiAdapter(wire,allowed_scopes={(-1001,None)},allowed_all_topic_chats={-1001})
    standing=StandingSendPolicy(principal_id='zeta',bot_reference='fixture_zeta_bot',expected_bot_id=123,
                               chat_id=-1001,topic_id=None,purpose='gateway_technical_test')
    g=Gateway(store,policy,[zeta,agent_beta],bot,clock=lambda:clock[0],bot_reference='fixture_zeta_bot',
              bot_id=123,standing_send=standing)
    yield g,wire,zeta,agent_beta,clock
    store.close()

def draft(g,p,text='gateway test',**kw):
    return g.create_draft(p,-1001,text,**kw)['draft']['draft_id']

@pytest.mark.asyncio
async def test_exact_standing_send_and_same_draft_receipt_reuse(live_shape):
    g,w,p,_,_=live_shape;d=draft(g,p)
    a=await g.send_draft(p,d);b=await g.send_draft(p,d)
    assert a['status']==b['status']=='sent' and b['reused'] and len(w.sends)==1
    assert g.store.db.execute('SELECT COUNT(*) FROM gw_standing_attempts').fetchone()[0]==1

@pytest.mark.asyncio
async def test_recreated_draft_dedup(live_shape):
    g,w,p,_,_=live_shape
    await g.send_draft(p,draft(g,p))
    with pytest.raises(GatewayDenied):await g.send_draft(p,draft(g,p))
    assert len(w.sends)==1

@pytest.mark.asyncio
@pytest.mark.parametrize('case',['foreign_principal','topic','expired','attachments','tampered','wrong_bot_id','no_standing'])
async def test_denied_without_transport(live_shape,case):
    g,w,p,other,clock=live_shape
    if case=='foreign_principal':p=other
    kw={'topic_id':7} if case=='topic' else {}
    if case=='attachments':kw['attachments']=[{'name':'x','sha256':'0'*64}]
    d=draft(g,p,**kw)
    if case=='expired':clock[0]+=901
    if case=='tampered':g.store.db.execute("UPDATE gw_drafts SET digest=? WHERE id=?",('0'*64,d))
    if case=='wrong_bot_id':g.bot_id=124
    if case=='no_standing':g.standing_send=None
    with pytest.raises(GatewayDenied):await g.send_draft(p,d)
    assert w.sends==[]

@pytest.mark.asyncio
async def test_unknown_circuit_survives_gateway_recovery(live_shape):
    g,w,p,_,_=live_shape;w.fail=DeliveryUncertain('fixture')
    assert (await g.send_draft(p,draft(g,p)))['status']=='unknown'
    g.recover_uncertain();w.fail=None
    with pytest.raises(GatewayDenied):await g.send_draft(p,draft(g,p,'different'))
    assert len(w.sends)==1

@pytest.mark.asyncio
async def test_conversation_ceiling_newroots_and_bot_messages_cannot_reset(live_shape):
    g,w,p,_,clock=live_shape
    for i in range(8):await g.send_draft(p,draft(g,p,f'unique {i}'))
    clock[0]+=1000
    w.updates=[raw(1,bot=True,text='bot cannot reopen')];await g.poll_once()
    with pytest.raises(GatewayDenied):await g.send_draft(p,draft(g,p,'new root denied'))
    w.updates.append(raw(2,text='human starts a new exchange'));await g.poll_once()
    assert (await g.send_draft(p,draft(g,p,'human scoped continuation')))['status']=='sent'
    assert len(w.sends)==9

@pytest.mark.asyncio
async def test_forwarded_or_anonymous_human_cannot_reset(live_shape):
    g,w,p,_,clock=live_shape
    for i in range(8):await g.send_draft(p,draft(g,p,f'unique {i}'))
    clock[0]+=1000
    w.updates=[raw(1,forward_origin={'type':'user'}),raw(2,sender_chat={'id':-1001})]
    await g.poll_once()
    with pytest.raises(GatewayDenied):await g.send_draft(p,draft(g,p,'denied'))
    assert len(w.sends)==8

@pytest.mark.asyncio
async def test_rate_window_independent_of_human_reset(live_shape):
    g,w,p,_,_=live_shape
    for i in range(8):await g.send_draft(p,draft(g,p,f'unique {i}'))
    w.updates=[raw(1,text='human new exchange')];await g.poll_once()
    with pytest.raises(GatewayDenied):await g.send_draft(p,draft(g,p,'still rate limited'))
    assert len(w.sends)==8

@pytest.mark.asyncio
async def test_restart_sending_attempt_opens_circuit(live_shape):
    g,w,p,_,_=live_shape;d=draft(g,p)
    await g.send_draft(p,d)
    g.store.db.execute("UPDATE gw_drafts SET status='sending',receipt=NULL WHERE id=?",(d,))
    g.recover_uncertain()
    with pytest.raises(GatewayDenied):await g.send_draft(p,draft(g,p,'after restart'))
    assert len(w.sends)==1

@pytest.mark.asyncio
async def test_receipt_finalization_failure_blocks_without_restart(live_shape,monkeypatch):
    import telegram_gateway.service as service
    g,w,p,_,_=live_shape;d=draft(g,p)
    monkeypatch.setattr(service,'asdict',lambda _:(_ for _ in ()).throw(ValueError('fixture finalization')))
    assert (await g.send_draft(p,d))['status']=='unknown'
    with pytest.raises(GatewayDenied):await g.send_draft(p,draft(g,p,'distinct'))
    assert len(w.sends)==1

@pytest.mark.asyncio
async def test_unreconciled_sending_blocks_without_circuit_flag(live_shape):
    g,w,p,_,_=live_shape;d=draft(g,p)
    await g.send_draft(p,d)
    g.store.db.execute("UPDATE gw_drafts SET status='sending',receipt=NULL WHERE id=?",(d,))
    with pytest.raises(GatewayDenied):await g.send_draft(p,draft(g,p,'distinct'))
    assert len(w.sends)==1
