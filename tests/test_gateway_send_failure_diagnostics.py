"""Synthetic rejected replies remain definite; uncertain sends never retry."""
import asyncio
import json
import sqlite3

import pytest

from telegram_gateway.bot_api import BotRejected, DeliveryUncertain
from telegram_gateway.policy import GatewayDenied
from telegram_gateway.service import StateStore
from test_gateway_service import setup, approve, raw
from test_gateway_standing_integration import live_shape, draft


@pytest.mark.asyncio
async def test_deleted_reply_rejection_is_persisted_without_fallback_or_private_description(setup, monkeypatch):
    g, wire, _, actor, _, _ = setup
    wire.updates = [raw(1, mid=20)]
    await g.poll_once()
    draft = g.create_draft(actor, -1001, 'Synthetic reply', reply_to_message_id=20)['draft']['draft_id']
    challenge = g.bind_owner_challenge(actor, draft, -1001, 800)
    wire.updates.append(raw(2, mid=801, text=challenge['approval_text'], sender=99, reply=800))
    await g.poll_once()

    async def rejected(method, params):
        assert method == 'sendMessage'
        wire.sends.append(dict(params))
        return {'ok':False, 'error_code':400,
                'description':'Bad Request: message to be replied not found SYNTHETIC_PRIVATE_DETAIL'}

    monkeypatch.setattr(wire, 'request', rejected)
    result = await g.send_draft(actor, draft)
    expected = {'kind':'telegram_rejected', 'api_error_code':400, 'retry_after_seconds':None}
    assert result['status'] == 'failed' and result['failure'] == expected
    row = g.store.db.execute('SELECT status,receipt,failure FROM gw_drafts WHERE id=?', (draft,)).fetchone()
    assert row['status'] == 'failed' and row['receipt'] is None
    assert json.loads(row['failure']) == expected
    assert 'SYNTHETIC_PRIVATE_DETAIL' not in json.dumps(result) + row['failure']
    with pytest.raises(GatewayDenied):
        await g.send_draft(actor, draft)
    assert len(wire.sends) == 1
    assert wire.sends[0]['reply_parameters'] == {'message_id':20, 'allow_sending_without_reply':False}
    reopened = StateStore(g.store.path)
    try:
        assert json.loads(reopened.db.execute('SELECT failure FROM gw_drafts WHERE id=?',(draft,)).fetchone()[0]) == expected
    finally:
        reopened.close()


@pytest.mark.asyncio
@pytest.mark.parametrize('code,delay', [(None,None),(429,7),(400,True),(400,90000)])
async def test_only_safe_rejection_fields_are_returned_and_saved(setup, code, delay):
    g, wire, _, actor, _, _ = setup
    draft = await approve(g, wire, actor)
    wire.fail = BotRejected('SYNTHETIC_PRIVATE_DETAIL', api_error_code=code, retry_after=delay)
    result = await g.send_draft(actor, draft)
    expected = {'kind':'telegram_rejected' if code else 'rejected_without_api_code',
                'api_error_code':code, 'retry_after_seconds':7 if delay == 7 else None}
    assert result['status'] == 'failed' and result['failure'] == expected
    assert 'SYNTHETIC_PRIVATE_DETAIL' not in json.dumps(result)
    assert len(wire.sends) == 1


@pytest.mark.asyncio
@pytest.mark.parametrize('cause', [TimeoutError, asyncio.CancelledError])
async def test_adapter_uncertainty_does_not_invent_the_underlying_cause(setup, cause):
    g, wire, _, actor, _, _ = setup
    draft = await approve(g, wire, actor)
    wire.fail = cause('SYNTHETIC_PRIVATE_DETAIL')
    result = await g.send_draft(actor, draft)
    expected = {'kind':'delivery_uncertain', 'stage':'transport', 'error_category':'adapter_uncertain'}
    # BotApiAdapter has intentionally erased the underlying transport cause.
    assert result['status'] == 'unknown' and result['failure'] == expected
    row = g.store.db.execute('SELECT status,receipt,failure FROM gw_drafts WHERE id=?',(draft,)).fetchone()
    assert row['status'] == 'unknown' and row['receipt'] is None
    assert json.loads(row['failure']) == expected
    assert 'SYNTHETIC_PRIVATE_DETAIL' not in json.dumps(result) + row['failure']
    with pytest.raises(GatewayDenied):
        await g.send_draft(actor, draft)
    assert len(wire.sends) == 1


@pytest.mark.parametrize('status', ['failed', 'unknown'])
def test_legacy_consumed_draft_does_not_acquire_invented_error_details(tmp_path, status):
    path = (tmp_path/'legacy.sqlite').resolve()
    with sqlite3.connect(path) as db:
        db.execute('CREATE TABLE gw_drafts(id TEXT PRIMARY KEY,owner TEXT,body TEXT NOT NULL,digest TEXT NOT NULL,status TEXT NOT NULL,expires REAL,created REAL,consumed REAL,receipt TEXT,approval_owner INTEGER,approval_message INTEGER)')
        db.execute("INSERT INTO gw_drafts(id,owner,body,digest,status) VALUES('legacy','fixture','{}','fixture',?)", (status,))
    for _ in range(2):
        store = StateStore(path)
        try:
            assert tuple(store.db.execute("SELECT status,failure FROM gw_drafts WHERE id='legacy'").fetchone()) == (status,None)
        finally:
            store.close()


@pytest.mark.asyncio
@pytest.mark.parametrize('error,category', [
    (TimeoutError('SYNTHETIC_PRIVATE_DETAIL https://example.invalid/private'), 'timeout'),
    (ConnectionError('SYNTHETIC_PRIVATE_DETAIL'), 'connection'),
    (sqlite3.OperationalError('SYNTHETIC_PRIVATE_DETAIL'), 'sqlite'),
    (DeliveryUncertain('SYNTHETIC_PRIVATE_DETAIL'), 'adapter_uncertain'),
    (RuntimeError('SYNTHETIC_PRIVATE_DETAIL'), 'unexpected'),
])
async def test_unwrapped_transport_error_categories_are_fixed_and_no_retry(live_shape, monkeypatch, error, category):
    g, wire, actor, _, _ = live_shape
    did = draft(g, actor)
    attempts = []
    async def transport_failure(**kwargs):
        attempts.append(kwargs)
        raise error
    monkeypatch.setattr(g.bot, 'send_message', transport_failure)
    result = await g.send_draft(actor, did)
    expected = {'kind':'delivery_uncertain', 'stage':'transport', 'error_category':category}
    assert result['status'] == 'unknown' and result['failure'] == expected
    row = g.store.db.execute('SELECT status,receipt,failure FROM gw_drafts WHERE id=?',(did,)).fetchone()
    assert row['status'] == 'unknown' and row['receipt'] is None
    assert json.loads(row['failure']) == expected
    assert 'SYNTHETIC_PRIVATE_DETAIL' not in json.dumps(result) + row['failure']
    assert 'https://' not in json.dumps(result) + row['failure']
    assert g.store.db.execute("SELECT value FROM gw_meta WHERE key='standing_send_circuit'").fetchone()[0] == 'open'
    with pytest.raises(GatewayDenied):
        await g.send_draft(actor, did)
    with pytest.raises(GatewayDenied):
        await g.send_draft(actor, draft(g, actor, 'different after uncertainty'))
    assert len(attempts) == 1 and wire.sends == []


@pytest.mark.asyncio
async def test_cancellation_records_safe_stage_and_propagates_without_retry(live_shape, monkeypatch):
    g, _, actor, _, _ = live_shape
    did = draft(g, actor)
    attempts = []
    async def cancelled(**kwargs):
        attempts.append(kwargs)
        raise asyncio.CancelledError('SYNTHETIC_PRIVATE_DETAIL')
    monkeypatch.setattr(g.bot, 'send_message', cancelled)
    with pytest.raises(asyncio.CancelledError):
        await g.send_draft(actor, did)
    row = g.store.db.execute('SELECT status,receipt,failure FROM gw_drafts WHERE id=?',(did,)).fetchone()
    assert row['status'] == 'unknown' and row['receipt'] is None
    assert json.loads(row['failure']) == {'kind':'delivery_uncertain', 'stage':'transport', 'error_category':'cancelled'}
    assert 'SYNTHETIC_PRIVATE_DETAIL' not in row['failure']
    with pytest.raises(GatewayDenied):
        await g.send_draft(actor, did)
    with pytest.raises(GatewayDenied):
        await g.send_draft(actor, draft(g, actor, 'new after cancellation'))
    assert len(attempts) == 1


class FailingFinalizationDatabase:
    def __init__(self, db, *, fail_receipt=True, fail_diagnostics=False):
        self.db = db
        self.fail_receipt = fail_receipt
        self.fail_diagnostics = fail_diagnostics

    def execute(self, sql, parameters=()):
        if self.fail_receipt and "SET status='sent',receipt=" in sql:
            raise sqlite3.OperationalError('SYNTHETIC_PRIVATE_RECEIPT_DETAIL')
        if self.fail_diagnostics and ("SET status='unknown',failure=" in sql or
                                     sql.startswith("INSERT INTO gw_meta(key,value) VALUES('standing_send_circuit'")):
            raise sqlite3.OperationalError('SYNTHETIC_PRIVATE_DIAGNOSTIC_DETAIL')
        return self.db.execute(sql, parameters)

    def __getattr__(self, name):
        return getattr(self.db, name)


@pytest.mark.asyncio
async def test_receipt_write_failure_records_uncertainty_without_false_rejection(live_shape, monkeypatch):
    g, wire, actor, _, _ = live_shape
    did = draft(g, actor)
    monkeypatch.setattr(g.store, 'db', FailingFinalizationDatabase(g.store.db))
    result = await g.send_draft(actor, did)
    expected = {'kind':'delivery_uncertain', 'stage':'receipt_persistence', 'error_category':'sqlite'}
    assert result['status'] == 'unknown' and result['failure'] == expected
    row = g.store.db.execute('SELECT status,receipt,failure FROM gw_drafts WHERE id=?',(did,)).fetchone()
    assert row['status'] == 'unknown' and row['receipt'] is None
    assert json.loads(row['failure']) == expected
    assert 'SYNTHETIC_PRIVATE' not in json.dumps(result) + row['failure']
    with pytest.raises(GatewayDenied):
        await g.send_draft(actor, did)
    with pytest.raises(GatewayDenied):
        await g.send_draft(actor, draft(g, actor, 'new after receipt failure'))
    assert len(wire.sends) == 1


@pytest.mark.asyncio
async def test_receipt_serialization_error_is_only_reported_as_persistence(live_shape, monkeypatch):
    import telegram_gateway.service as service
    g, wire, actor, _, _ = live_shape
    did = draft(g, actor)
    def invalid_receipt(_):
        raise ValueError('SYNTHETIC_PRIVATE_SERIALIZATION_DETAIL')
    monkeypatch.setattr(service, 'asdict', invalid_receipt)
    result = await g.send_draft(actor, did)
    assert result['status'] == 'unknown'
    assert result['failure'] == {'kind':'delivery_uncertain', 'stage':'receipt_persistence', 'error_category':'persistence'}
    assert 'SYNTHETIC_PRIVATE' not in json.dumps(result)
    assert len(wire.sends) == 1


@pytest.mark.asyncio
@pytest.mark.parametrize('stage', ['transport', 'receipt_persistence'])
async def test_diagnostic_and_circuit_write_failure_keeps_durable_no_resend_guard(live_shape, monkeypatch, stage):
    g, wire, actor, _, _ = live_shape
    did = draft(g, actor)
    if stage == 'transport':
        wire.fail = DeliveryUncertain('SYNTHETIC_PRIVATE_TRANSPORT_DETAIL')
    monkeypatch.setattr(g.store, 'db', FailingFinalizationDatabase(
        g.store.db, fail_receipt=stage == 'receipt_persistence', fail_diagnostics=True))
    result = await g.send_draft(actor, did)
    assert result['status'] == 'unknown' and result['failure']['stage'] == stage
    assert 'SYNTHETIC_PRIVATE' not in json.dumps(result)
    row = g.store.db.execute('SELECT status,consumed,receipt,failure FROM gw_drafts WHERE id=?',(did,)).fetchone()
    assert row['status'] == 'sending' and row['consumed'] is not None
    assert row['receipt'] is None and row['failure'] is None
    assert not g.store.db.execute("SELECT 1 FROM gw_meta WHERE key='standing_send_circuit'").fetchone()
    with pytest.raises(GatewayDenied):
        await g.send_draft(actor, did)
    with pytest.raises(GatewayDenied):
        await g.send_draft(actor, draft(g, actor, 'new after diagnostic failure'))
    assert len(wire.sends) == 1
