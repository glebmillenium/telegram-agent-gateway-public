import pytest
from telegram_gateway.grok_routine import Route,GrokRoutineError,authorization_headers,_headers
from telegram_gateway.runtime_config import SecretRef
from test_gateway_grok_routine import Setup,BOT,URL

@pytest.mark.parametrize('value',['Bearer public-fixture','Token public-fixture','public-fixture'])
def test_full_authorization_preserved_without_scheme_guessing(value):
    headers=authorization_headers(value)
    assert headers['Authorization']==value
    assert value not in repr(headers)
    assert _headers(headers,'routine.example')['Authorization']==value

@pytest.mark.parametrize('value',['',' ',' x','x ','x\r\nHost: evil','x\ty','x\x00y','ключ',None,True])
def test_header_injection_or_invalid_shape_denied_without_echo(value):
    with pytest.raises(GrokRoutineError,match='^Routine credential rejected$'):
        authorization_headers(value)

@pytest.mark.asyncio
async def test_local_webhook_dispatch_preserves_full_header(tmp_path):
    fixture=Setup(tmp_path)
    fixture.sink.close();fixture.sinks.clear()
    fixture.path=tmp_path/'full-header.sqlite'
    fixture.route=Route('fixture_route','alpha',BOT,URL,SecretRef('local_webhook','fixture_route'))
    fixture.key='Token public-synthetic-credential'
    fixture.sink=fixture.open()
    try:
        fixture.enqueue()
        assert (await fixture.dispatch())['status']=='accepted'
        assert fixture.receiver.calls[0][2]['Authorization']==fixture.key
    finally:
        for sink in fixture.sinks:sink.close()
