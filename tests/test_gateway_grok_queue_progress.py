import pytest
from telegram_gateway import grok_routine
from telegram_gateway.demo import message
from telegram_gateway.runtime import make_runtime
from test_gateway_grok_runtime import config,dependencies,ALPHA,CHAT

@pytest.mark.asyncio
async def test_full_outbox_drains_and_cursor_retries_only_unenqueued_row(tmp_path,monkeypatch):
    monkeypatch.setattr(grok_routine,'MAX_QUEUE',2)
    deps,sent,_=dependencies(updates=False)
    runtime=make_runtime(config(tmp_path),**deps)
    await runtime.start()
    try:
        child=runtime.children[ALPHA]
        deps['transports'][ALPHA].updates=[message(i,CHAT,f'@{ALPHA} fixture {i}',topic=7) for i in (1,2,3)]
        await child.gateway.poll_once()
        first=await child.routine_once('alpha_routine')
        assert first=={'status':'accepted','run_completed':False,'export_deferred':True}
        assert child.store.db.execute('SELECT cursor FROM gw_routine_exports').fetchone()[0]==2
        assert len(sent[ALPHA])==1
        second=await child.routine_once('alpha_routine')
        assert second=={'status':'accepted','run_completed':False}
        assert child.store.db.execute('SELECT cursor FROM gw_routine_exports').fetchone()[0]==3
        assert (await child.routine_once('alpha_routine'))['status']=='accepted'
        assert (await child.routine_once('alpha_routine'))['status']=='idle'
        assert len(sent[ALPHA])==3
        assert len({item['eventId'] for item in sent[ALPHA]})==3
    finally:await runtime.close()
