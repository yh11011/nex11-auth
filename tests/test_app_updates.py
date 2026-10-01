import pytest
import app_updates as updates
from test_ai_mcp import env

TAG='v1.2.0-beta.1'
URL=f'https://github.com/yh11011/NexAlarm/releases/download/{TAG}/NexAlarm-{TAG}.apk'

def release():
    return {'tag_name':TAG,'draft':False,'html_url':f'{updates.SOURCE}/tag/{TAG}','assets':[{'name':f'NexAlarm-{TAG}.apk','browser_download_url':URL,'size':100}],'body':'Changes'}

def metadata():
    return {'package_name':'com.nexalarm.app','version_name':TAG[1:],'version_code':42,'min_sdk':26,'size_bytes':100,'sha256':'a'*64,'signer_sha256':'b'*64}

def test_update_metadata_requires_trusted_release_and_complete_digests():
    assert updates.validate_release(release(),metadata())['apk_url']==URL
    for field,value in [('sha256','bad'),('signer_sha256',''),('package_name','another.app'),('size_bytes',99),('version_code',True)]:
        with pytest.raises(ValueError): updates.validate_release(release(),metadata() | {field:value})
    historical=release() | {'tag_name':'v1.0.0-beta'}
    with pytest.raises(ValueError): updates.validate_release(historical,metadata())
    unsafe=release(); unsafe['assets'][0]['browser_download_url']='https://example.com/app.apk'
    with pytest.raises(ValueError): updates.validate_release(unsafe,metadata())

@pytest.mark.asyncio
async def test_update_check_public_without_premium_and_handles_no_release(env,monkeypatch):
    monkeypatch.setattr(updates,'_cache',None)
    async def absent(): return {'available':False,'source_url':updates.SOURCE,'channel':'beta'}
    monkeypatch.setattr(updates,'fetch_latest',absent)
    result=await env.get('/api/v1/app/releases/latest')
    assert result.status_code==200 and result.json()['available'] is False
    assert (await env.get('/api/v1/app/releases/latest?channel=unknown')).status_code==400

@pytest.mark.asyncio
async def test_update_network_failure_is_not_no_update(env,monkeypatch):
    import httpx
    monkeypatch.setattr(updates,'_cache',None)
    async def fail(): raise httpx.ConnectError('offline')
    monkeypatch.setattr(updates,'fetch_latest',fail)
    assert (await env.get('/api/v1/app/releases/latest')).status_code==503
