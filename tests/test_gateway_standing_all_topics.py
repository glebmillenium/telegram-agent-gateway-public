from dataclasses import replace
import pytest
from telegram_gateway.auth import FakeAuthenticator,OwnerApprovalVerifier
from telegram_gateway.policy import GatewayDenied,Scope,Policy
from telegram_gateway.bot_api import BotApiAdapter
from telegram_gateway.standing import StandingSendPolicy
from test_gateway_standing_integration import live_shape
from test_gateway_service import raw

@pytest.mark.parametrize('topic',[None,1,7,999])
def test_explicit_all_topics_only_same_chat(live_shape,topic):
    g,_,p,_,_=live_shape
    policy=replace(g.standing_send,all_topics=True)
    body=g.create_draft(p,-1001,'fixture',topic_id=topic)['draft']
    assert policy.authorize(p,bot_reference=g.bot_reference,bot_id=g.bot_id,body=body).authorized
    body['chat_id']=-1002
    with pytest.raises(GatewayDenied):policy.authorize(p,bot_reference=g.bot_reference,bot_id=g.bot_id,body=body)

@pytest.mark.parametrize('changes',[{'all_topics':'true'},{'all_topics':1},{'all_topics':True,'topic_id':7}])
def test_invalid_all_topics(live_shape,changes):
    g,*_=live_shape
    with pytest.raises(GatewayDenied):replace(g.standing_send,**changes)

def test_standing_draft_status_and_long_authorized_text(live_shape):
    g,_,p,_,_=live_shape
    draft=g.create_draft(p,-1001,'x'*4000)
    assert draft['status']=='pending-scoped-send' and draft['approval_mode']=='standing'
    assert g.store.db.execute('SELECT status FROM gw_drafts WHERE id=?',(draft['draft']['draft_id'],)).fetchone()[0]=='pending'
    other=g.create_draft(p,-1001,'fixture',topic_id=7)
    assert other['status']=='pending-owner-approval'

@pytest.mark.asyncio
async def test_owner_approval_coexists_for_other_permitted_destination(live_shape):
    g,w,p,_,clock=live_shape
    g.policy=Policy.from_dict({'principals':{'zeta':[{'chat_id':c,'permissions':['history','events','draft','send']} for c in [-1001,-1002]],'agent_beta':[]}})
    g.bot=BotApiAdapter(w,allowed_scopes={(-1001,None),(-1002,None)})
    g.owner_verifier=OwnerApprovalVerifier([99],[Scope(-1001)],clock=lambda:clock[0])
    d=g.create_draft(p,-1002,'owner reviewed different destination')['draft']['draft_id']
    with pytest.raises(GatewayDenied):await g.send_draft(p,d)
    challenge=g.bind_owner_challenge(p,d,-1001,800)
    w.updates=[raw(1,mid=801,text=challenge['approval_text'],sender=99,reply=800)]
    await g.poll_once()
    assert (await g.send_draft(p,d))['status']=='sent'
    assert w.sends[0]['chat_id']==-1002
    assert g.store.db.execute('SELECT COUNT(*) FROM gw_standing_attempts').fetchone()[0]==0
