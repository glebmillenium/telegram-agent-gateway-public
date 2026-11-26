"""Count-only operator diagnostics; no live I/O or secret/message logging."""
import json
import sqlite3

import pytest

from telegram_gateway.bot_api import BotRejected, FakeBotTransport
from telegram_gateway.runtime import Runtime
from telegram_gateway.runtime_config import RuntimeConfig


def config(tmp_path):
    return RuntimeConfig.from_dict({"version": 1, "mode": "fake", "state_dir": str(tmp_path / "state"),
        "policy": {"principals": {"reader": [{"chat_id": -1001, "all_topics": True,
            "permissions": ["history", "events"]}]}},
        "auth": {"mode": "fake", "credentials": {"fixture-reader": "reader"}},
        "bot": {"approved_groups": [{"chat_id": -1001, "type": "supergroup", "title": "Synthetic"}]},
        "poll_interval_seconds": .1})


def message(update_id, chat=-1001, bot=False, topic=None):
    body={"message_id": update_id, "date": 1700000000, "chat": {"id": chat, "type": "supergroup"},
          "from": {"id": 41, "is_bot": bot}, "text": "SYNTHETIC_PRIVATE_MESSAGE"}
    if topic is not None:body.update(message_thread_id=topic,is_topic_message=True)
    return {"update_id": update_id, "message": body}


@pytest.mark.asyncio
async def test_operator_counts_distinguish_received_filtered_stored_and_empty_polls(tmp_path,monkeypatch):
    transport=FakeBotTransport([message(1),message(2,bot=True,topic=1),message(3,chat=-9999),
        {"update_id":4,"edited_message":{"text":"SYNTHETIC_PRIVATE_OTHER_TYPE"}}])
    runtime=Runtime(config(tmp_path),transport=transport)
    await runtime.start()
    snapshots=[]
    async def sleep(_):
        snapshots.append(json.loads((runtime.cfg.state_dir/'runtime-status.json').read_text()))
        if len(snapshots)==2:runtime.stopping=True
    monkeypatch.setattr('telegram_gateway.runtime.asyncio.sleep',sleep)
    try:
        await runtime.poll_loop()
        first=snapshots[0]['poll_diagnostics']['last_batch']
        assert (first['offset_before'],first['offset_after'])==(0,5)
        assert (first['updates_received'],first['messages_accepted'],first['message_rows_stored'],first['event_rows_created'])==(4,2,2,2)
        assert first['accepted_human_senders']==first['accepted_bot_senders']==first['accepted_threaded']==1
        assert first['discard_counts']['outside_scope']==first['discard_counts']['non_message_update']==1
        final=snapshots[1]['poll_diagnostics']
        assert final['successful_polls']==2 and final['failed_polls']==0
        assert final['updates_received']==4 and final['messages_accepted']==2
        assert final['message_rows_stored']==final['event_rows_created']==2
        assert final['last_batch']['updates_received']==0
        assert (final['last_batch']['offset_before'],final['last_batch']['offset_after'])==(5,5)
        assert final['allowed_updates']==['message']
        text=json.dumps(snapshots)
        assert 'SYNTHETIC_PRIVATE' not in text and '-1001' not in text and '-9999' not in text
        principal=runtime.auth.authenticate('Bearer fixture-reader')
        assert 'poll_diagnostics' not in runtime.gateway.status(principal)
        assert len(runtime.gateway.read_history(principal,-1001,all_topics=True)['messages'])==2
        assert transport.sent==[]
    finally:await runtime.close()


@pytest.mark.asyncio
async def test_conflict_is_retained_as_safe_code_after_polling_recovers(tmp_path,monkeypatch):
    class ConflictOnce(FakeBotTransport):
        first=True
        async def request(self,method,params):
            if self.first:
                self.first=False
                raise BotRejected('SYNTHETIC_PRIVATE_ERROR',api_error_code=409)
            return await super().request(method,params)
    runtime=Runtime(config(tmp_path),transport=ConflictOnce([message(1)]))
    await runtime.start()
    snapshots=[]
    async def sleep(_):
        snapshots.append(json.loads((runtime.cfg.state_dir/'runtime-status.json').read_text()))
        if len(snapshots)==2:runtime.stopping=True
    monkeypatch.setattr('telegram_gateway.runtime.asyncio.sleep',sleep)
    try:
        await runtime.poll_loop()
        assert snapshots[0]['poll_state']=='retrying'
        diagnostics=snapshots[1]['poll_diagnostics']
        assert diagnostics['failed_polls']==diagnostics['successful_polls']==1
        assert diagnostics['last_error']['kind']=='telegram_conflict'
        assert diagnostics['last_error']['api_error_code']==409
        assert snapshots[1]['poll_state']=='ok'
        assert 'SYNTHETIC_PRIVATE' not in json.dumps(snapshots)
    finally:await runtime.close()


@pytest.mark.asyncio
async def test_failed_transaction_does_not_report_committed_messages_or_advance_cursor(tmp_path,monkeypatch):
    runtime=Runtime(config(tmp_path),transport=FakeBotTransport([message(1)]))
    await runtime.start()
    def fail(*_):raise sqlite3.OperationalError('SYNTHETIC_PRIVATE_ERROR')
    async def sleep(_):runtime.stopping=True
    monkeypatch.setattr(runtime.gateway,'_ingest_owner_decision',fail)
    monkeypatch.setattr('telegram_gateway.runtime.asyncio.sleep',sleep)
    try:
        await runtime.poll_loop()
        diagnostics=json.loads((runtime.cfg.state_dir/'runtime-status.json').read_text())['poll_diagnostics']
        assert diagnostics['last_error']['kind']=='storage_error'
        assert diagnostics['successful_polls']==0 and diagnostics['failed_polls']==1
        assert diagnostics['last_batch'] is None
        assert diagnostics['message_rows_stored']==diagnostics['event_rows_created']==0
        assert runtime.store.db.execute("SELECT value FROM gw_meta WHERE key='cursor'").fetchone()[0]=='0'
        assert runtime.store.db.execute('SELECT count(*) FROM gw_messages').fetchone()[0]==0
        assert runtime.gateway.last_poll_stats is None
        assert 'SYNTHETIC_PRIVATE' not in json.dumps(diagnostics)
    finally:await runtime.close()

@pytest.mark.asyncio
async def test_missing_sender_is_not_reported_as_confirmed_bot(tmp_path):
    update = message(1)
    del update['message']['from']
    runtime = Runtime(config(tmp_path), transport=FakeBotTransport([update]))
    await runtime.start()
    try:
        await runtime.gateway.poll_once()
        stats = runtime.gateway.last_poll_stats
        assert stats['messages_accepted'] == stats['message_rows_stored'] == 1
        assert stats['accepted_bot_senders'] == stats['accepted_human_senders'] == 0
    finally:
        await runtime.close()
