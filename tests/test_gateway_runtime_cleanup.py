import pytest
from telegram_gateway.runtime import Runtime, RuntimeBlocked

@pytest.mark.asyncio
@pytest.mark.parametrize('failure', ['status','first_sink','second_sink','events','secrets','state','lock'])
async def test_cleanup_failure_does_not_skip_other_resources_or_leak_error(failure):
    closed=[]
    class Resource:
        def __init__(self,name):self.name=name
        def close(self):
            closed.append(self.name)
            if self.name==failure:raise ValueError('PRIVATE_CALLBACK_CREDENTIAL')
        def __exit__(self,*args):self.close()
    runtime=Runtime.__new__(Runtime)
    runtime.tasks=[]
    runtime.routine_sinks={'first':Resource('first_sink'),'second':Resource('second_sink')}
    runtime.hub=Resource('events')
    runtime.secrets=Resource('secrets')
    runtime.store=Resource('state')
    runtime.lock=Resource('lock')
    def status(_):
        closed.append('status')
        if failure=='status':raise OSError('PRIVATE_CALLBACK_CREDENTIAL')
    runtime._write_status=status
    with pytest.raises(RuntimeBlocked) as error:await runtime.close()
    assert 'PRIVATE_CALLBACK_CREDENTIAL' not in str(error.value)
    assert closed==['status','first_sink','second_sink','events','secrets','state','lock']
    assert runtime.routine_sinks=={} and runtime.lock is None
    assert runtime.hub is None and runtime.secrets is None and runtime.store is None
    await runtime.close()
    assert len(closed)==7
