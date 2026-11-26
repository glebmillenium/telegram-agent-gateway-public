import copy
import json
from pathlib import Path
import pytest
from telegram_gateway.webhook_import import (
    parse_bundle,load_bundle,prepare_plan,merge_private_entries,summary,main,WebhookImportError,
)
from telegram_gateway.runtime_config import RuntimeConfig

def block(agent='Alpha',telegram='@Alpha_Test_Bot',url='https://hooks.cursor.sh/fixture-alpha',key='PUBLIC_A',scheme='Bearer'):
    return f'AGENT: {agent}\nTELEGRAM: {telegram}\nPOST: {url}\nKEY: {key}\nHEADER: Authorization: {scheme} {key}'

def bundle():
    return (block()+'\n\n'+block('Beta','нет','https://hooks.cursor.sh/fixture-beta','PUBLIC_B','Token')).encode('utf-8')

def bindings():
    return {name:{'profile_id':name,'webhook_ref':name+'_routine','platform':'grok_bot'} for name in ('alpha','beta')}

def test_multiple_bots_missing_username_and_exact_headers():
    entries=parse_bundle(bundle())
    assert entries[0].telegram_username=='alpha_test_bot'
    assert entries[1].telegram_username is None
    assert entries[1].authorization_header=='Token PUBLIC_B'
    assert summary(entries)=={'valid':True,'entries':2,'telegram_missing':1,
                             'endpoints_verified':False,'saved':False,'activated':False,'network_called':False}
    assert 'PUBLIC_' not in repr(entries) and 'cursor.sh' not in repr(entries)

def test_utf8_bom_crlf_and_extra_blank_lines():
    raw=('\ufeff\n'+block(agent='Альфа')+'\n\n').replace('\n','\r\n').encode()
    assert parse_bundle(raw)[0].agent=='Альфа'

@pytest.mark.parametrize('raw',[
    b'',b'x'*65537,b'\xff',
    block().replace('KEY: PUBLIC_A','KEY: PUBLIC_B').encode(),
    block().replace('HEADER: Authorization: Bearer PUBLIC_A','HEADER: Authorization').encode(),
    block().replace('HEADER: Authorization:','HEADER: X-API-Key:').encode(),
    block().replace('TELEGRAM: @Alpha_Test_Bot','TELEGRAM: unknown').replace('unknown','').encode(),
    block().replace('https://hooks.cursor.sh/fixture-alpha','http://hooks.cursor.sh/fixture-alpha').encode(),
    block().replace('https://hooks.cursor.sh/fixture-alpha','https://127.0.0.1/secret').encode(),
    block().replace('https://hooks.cursor.sh/fixture-alpha','https://user:pass@hooks.cursor.sh/x').encode(),
    block().replace('https://hooks.cursor.sh/fixture-alpha','https://hooks.cursor.sh/x#secret').encode(),
    (block()+'\nTOKEN: PRIVATE_SENTINEL').encode(),
    (block()+'\nKEY: PRIVATE_SENTINEL').encode(),
    block().replace('PUBLIC_A','`PRIVATE_SENTINEL`').encode(),
    block().replace('PUBLIC_A','PRIVATE_SENTINEL\tINJECT').encode(),
    (block()+'\r\nX-Injected: PRIVATE_SENTINEL').encode(),
    (block()+'\n'+block('Beta','beta_test_bot','https://hooks.cursor.sh/b','PUBLIC_B')).encode(),
],ids=lambda _: 'synthetic-input')
def test_invalid_inputs_redacted(raw):
    with pytest.raises(WebhookImportError) as caught:parse_bundle(raw)
    assert 'PRIVATE_SENTINEL' not in str(caught.value)
    assert 'cursor.sh' not in str(caught.value)
    assert caught.value.__suppress_context__

@pytest.mark.parametrize('second',[
    block('ALPHA','beta_test_bot','https://hooks.cursor.sh/b','PUBLIC_B'),
    block('Beta','@ALPHA_TEST_BOT','https://hooks.cursor.sh/b','PUBLIC_B'),
    block('Beta','beta_test_bot','https://hooks.cursor.sh/fixture-alpha','PUBLIC_B'),
    block('Beta','beta_test_bot','https://hooks.cursor.sh/b','PUBLIC_A'),
])
def test_duplicate_agent_bot_url_or_key_rejected(second):
    with pytest.raises(WebhookImportError):parse_bundle((block()+'\n\n'+second).encode())

def test_inert_plan_compiles_without_credentials_or_grants(tmp_path,monkeypatch):
    entries=parse_bundle(bundle())
    plan=prepare_plan(entries,bindings())
    assert 'PUBLIC_' not in repr(plan) and 'cursor.sh' not in repr(plan)
    def deny(*args,**kwargs):raise AssertionError('Unexpected filesystem access')
    monkeypatch.setattr(Path,'open',deny)
    cfg=RuntimeConfig.from_dict({'version':1,'mode':'disabled','network_enabled':False,
        'outbound_enabled':False,'agents':list(plan.profiles)},project_root=tmp_path/'code')
    assert cfg.agent_bindings=={} and cfg.principals==() and cfg.routine_routes=={}
    for profile in cfg.agent_profiles:
        assert profile['auth_principal'] is None and not profile['enabled'] and not profile['chats']
        assert profile['prompt']==''
    assert plan.webhooks['beta_routine']['authorization_header']=='Token PUBLIC_B'

@pytest.mark.parametrize('change',['missing','extra','duplicate_id','duplicate_ref','invalid_platform'])
def test_operator_bindings_fail_closed(change):
    supplied=bindings()
    if change=='missing':supplied.pop('beta')
    elif change=='extra':supplied['third']=supplied['beta']
    elif change=='duplicate_id':supplied['beta']['profile_id']='alpha'
    elif change=='duplicate_ref':supplied['beta']['webhook_ref']='alpha_routine'
    else:supplied['alpha']['platform']='https://PRIVATE_SENTINEL'
    with pytest.raises(WebhookImportError,match='^Webhook import bindings rejected$'):
        prepare_plan(parse_bundle(bundle()),supplied)

def test_memory_merge_preserves_existing_tokens_and_is_idempotent():
    existing={'version':1,'bots':{'existing_bot':{'token':'PUBLIC_EXISTING_TOKEN'}},
              'webhooks':{'existing_routine':{'url':'https://hooks.cursor.sh/old','authorization_header':'Bearer PUBLIC_OLD'}}}
    before=copy.deepcopy(existing)
    plan=prepare_plan(parse_bundle(bundle()),bindings())
    merged=merge_private_entries(existing,plan)
    assert existing==before and merged['bots']==existing['bots']
    assert merged['webhooks']['existing_routine']==existing['webhooks']['existing_routine']
    assert merge_private_entries(merged,plan)==merged

@pytest.mark.parametrize('kind',['same_ref','same_url','same_header'])
def test_memory_merge_never_overwrites_or_aliases_existing_credentials(kind):
    plan=prepare_plan(parse_bundle(bundle()),bindings())
    value={'url':'https://hooks.cursor.sh/other','authorization_header':'Bearer PUBLIC_OLD'}
    ref='alpha_routine' if kind=='same_ref' else 'old'
    if kind=='same_url':value['url']=plan.webhooks['alpha_routine']['url']
    if kind=='same_header':value['authorization_header']=plan.webhooks['alpha_routine']['authorization_header']
    existing={'version':1,'bots':{},'webhooks':{ref:value}}
    before=copy.deepcopy(existing)
    with pytest.raises(WebhookImportError):merge_private_entries(existing,plan)
    assert existing==before

def test_explicit_file_check_reports_counts_only_and_leaves_source_unchanged(tmp_path,capsys):
    path=tmp_path/'fixture.txt';path.write_bytes(bundle())
    assert main(['--check',str(path)])==0
    report=capsys.readouterr().out
    assert json.loads(report)['entries']==2
    assert 'PUBLIC_' not in report and 'cursor.sh' not in report and 'Alpha' not in report
    assert path.read_bytes()==bundle()

def test_cli_failure_does_not_echo_path_or_unexpected_argument(tmp_path,capsys):
    missing=tmp_path/'PRIVATE_SENTINEL'
    assert main(['--check',str(missing)])==1
    assert 'PRIVATE_SENTINEL' not in capsys.readouterr().out
    with pytest.raises(SystemExit):main(['--PRIVATE_SENTINEL'])
    assert 'PRIVATE_SENTINEL' not in capsys.readouterr().err

def test_relative_path_not_read():
    with pytest.raises(WebhookImportError):load_bundle('BotsWebhooks.txt')
