import asyncio
import hashlib
import json
import os
import secrets

os.environ.setdefault("JWT_SECRET_KEY", "isolated-test-secret")
import httpx
import pytest
import pytest_asyncio
from fastapi import FastAPI
import database
import ai_delivery as ai
import oauth_routes as oauth
from mcp_remote import router as metadata, remote_app, mcp
from jwt_utils import encode_token

@pytest_asyncio.fixture
async def env(tmp_path, monkeypatch):
    monkeypatch.setattr(database,"DB_PATH",str(tmp_path/"test.db"))
    await database.init_db()
    await ai.init_ai_db()
    db = await database.get_db()
    for uid in (1,2,3):
        await db.execute("INSERT INTO users(id,username,is_premium) VALUES (?,?,?)",(uid,f"test{uid}",int(uid!=3)))
    await db.commit()
    await db.close()
    async def no_push(devices): pass
    monkeypatch.setattr(ai,"push_devices",no_push)
    from rate_limiter import check_ip_rate
    monkeypatch.setattr(oauth,"check_ip_rate",lambda *args:(True,0))
    app=FastAPI()
    app.include_router(ai.router)
    app.include_router(oauth.router)
    app.include_router(metadata)
    app.mount("/",remote_app)
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app),base_url="http://testserver") as client:
        yield client

def jwt_headers(uid=1):
    return {"Authorization":"Bearer "+encode_token({"id":uid})}

async def register(client,uid=1,device="a"*32):
    r=await client.post('/api/v1/devices/register',headers=jwt_headers(uid),json={"device_id":device,"name":"Test phone","timezone":"Asia/Taipei"})
    assert r.status_code==200,r.text
    return device

async def grant(client, scope="alarm:read alarm:write", uid=1):
    r=await client.post('/oauth/register',json={"redirect_uris":["http://127.0.0.1/callback"],"client_name":"test client","token_endpoint_auth_method":"none"})
    cid=r.json()['client_id']
    verifier=secrets.token_urlsafe(32)
    challenge=oauth._b64url(hashlib.sha256(verifier.encode()).digest())
    args={"client_id":cid,"redirect_uri":"http://127.0.0.1:45551/callback","scope":scope,"state":"test-state","code_challenge":challenge,"code_challenge_method":"S256","resource":ai.RESOURCE,"token":encode_token({"id":uid})}
    r=await client.post('/oauth/authorize',json=args)
    if r.status_code!=200: return r,None
    from urllib.parse import parse_qs,urlsplit
    query=parse_qs(urlsplit(r.json()['redirect_url']).query)
    assert query['iss']==[ai.BASE]
    token_args={"grant_type":"authorization_code","code":query['code'][0],"client_id":cid,"redirect_uri":args['redirect_uri'],"code_verifier":verifier,"resource":ai.RESOURCE}
    r=await client.post('/oauth/token',data=token_args)
    assert r.status_code==200,r.text
    return r.json(), token_args

@pytest.mark.asyncio
async def test_oauth_form_pkce_replay_refresh_revoke(env):
    token,args=await grant(env)
    assert (await env.post('/oauth/token',data=args)).status_code==400
    refresh={"grant_type":"refresh_token","refresh_token":token['refresh_token'],"client_id":args['client_id'],"resource":ai.RESOURCE}
    rotated=await env.post('/oauth/token',data=refresh)
    assert rotated.status_code==200
    assert (await env.post('/oauth/token',data=refresh)).status_code==400
    await env.post('/oauth/revoke',data={"token":rotated.json()['refresh_token']})
    r=await env.post('/mcp',headers={"Authorization":"Bearer "+rotated.json()['access_token']},json={"jsonrpc":"2.0","id":1,"method":"tools/list"})
    assert r.status_code==401

@pytest.mark.asyncio
async def test_oauth_wrong_verifier_resource_and_scope(env):
    token,args=await grant(env)
    args['code_verifier']='bad'
    assert (await env.post('/oauth/token',data=args)).status_code==400
    denied,_=await grant(env,uid=3)
    assert denied.status_code==403
    r=await env.post('/oauth/authorize',json={"client_id":"unknown","redirect_uri":"https://example.com","scope":"admin","state":"","token":encode_token({"id":1})})
    assert r.status_code==400

@pytest.mark.asyncio
async def test_mcp_protocol_and_account_scope(env):
    # Run SDK lifecycle in the same task as the protocol calls.
    mcp._session_manager = None
    remote_app.app = mcp.streamable_http_app()
    async with mcp.session_manager.run():
        await exercise_mcp(env)

async def exercise_mcp(env):
    # ASGI client exercises actual MCP transport headers and structured tool result.
    token,_=await grant(env)
    headers={"Authorization":"Bearer "+token['access_token'],"Accept":"application/json, text/event-stream"}
    init=await env.post('/mcp',headers=headers,json={"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"test","version":"1"}}})
    assert init.status_code==200,init.text
    result=await env.post('/mcp',headers=headers,json={"jsonrpc":"2.0","id":2,"method":"tools/list"})
    assert {t['name'] for t in result.json()['result']['tools']}=={'list_alarms','create_alarm','update_alarm','delete_alarm','get_delivery_status'}
    anonymous=await env.post('/mcp',json={})
    assert anonymous.status_code==401
    assert 'resource_metadata' in anonymous.headers['www-authenticate']
    result=await env.post('/mcp',headers=headers,json={"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"list_alarms","arguments":{}}})
    assert result.status_code==200,result.text
    assert result.json()['result']['structuredContent']['alarms']==[], result.text

@pytest.mark.asyncio
async def test_scope_and_downgrade(env):
    token,_=await grant(env,scope="alarm:read")
    with pytest.raises(Exception) as e:
        await ai.identity("Bearer "+token['access_token'],"alarm:write")
    assert e.value.status_code==403
    db=await database.get_db()
    await db.execute('UPDATE users SET is_premium=0 WHERE id=1');await db.commit();await db.close()
    with pytest.raises(Exception) as e:
        await ai.mutate(1,'create',{'hour':7,'minute':0})
    assert e.value.status_code==403

@pytest.mark.asyncio
async def test_idempotency_and_preserved_fields(env):
    op=await ai.mutate(1,'create',{'hour':7,'minute':0,'date':'2030-01-01','volume':35},idempotency_key='first')
    assert await ai.mutate(1,'create',{'hour':7,'minute':0,'date':'2030-01-01','volume':35},idempotency_key='first')==op
    with pytest.raises(Exception) as e:
        await ai.mutate(1,'create',{'hour':8,'minute':0},idempotency_key='first')
    assert e.value.status_code==409
    result=await ai.status(1,op)
    assert not result['complete'] and not result['devices']
    await ai.mutate(1,'update',{'title':'Renamed'},result['client_id'])
    db=await database.get_db()
    row=await (await db.execute('SELECT data FROM synced_alarms')).fetchone()
    assert json.loads(row['data'])['volume']==35
    assert json.loads(row['data'])['scheduledDate']=='2030-01-01'
    await db.close()

@pytest.mark.asyncio
async def test_snapshot_receipts_and_isolation(env):
    device=await register(env)
    second=await register(env,device='b'*32)
    op=await ai.mutate(1,'create',{'hour':7,'minute':0})
    await register(env,device='c'*32)
    result=await ai.status(1,op)
    assert len(result['devices'])==2 and not result['complete']
    body={'operation_id':op,'version':result['version'],'status':'scheduled','trigger_at':1900000000000,'timezone':'Asia/Taipei'}
    assert (await env.post(f'/api/v1/devices/{device}/receipt',headers=jwt_headers(2),json=body)).status_code==404
    assert (await env.post(f'/api/v1/devices/{device}/receipt',headers=jwt_headers(),json={**body,'version':0})).status_code==409
    assert (await env.post(f'/api/v1/devices/{device}/receipt',headers=jwt_headers(),json=body)).status_code==200
    assert not (await ai.status(1,op))['complete']
    await env.post(f'/api/v1/devices/{second}/receipt',headers=jwt_headers(),json={**body,'status':'fallback'})
    assert not (await ai.status(1,op))['complete']
    with pytest.raises(Exception) as e: await ai.status(2,op)
    assert e.value.status_code==404

@pytest.mark.asyncio
async def test_unregister_pending_and_old_receipt(env):
    device=await register(env)
    op=await ai.mutate(1,'create',{'hour':7,'minute':0})
    await env.post(f'/api/v1/devices/{device}/unregister',headers=jwt_headers(),json={})
    result=await ai.status(1,op)
    assert result['devices'][0]['status']=='failed'
    assert (await env.get(f'/api/v1/devices/{device}/pending',headers=jwt_headers())).status_code==404

@pytest.mark.asyncio
async def test_validation_and_weekly_repeat(env):
    for args in ({'hour':24,'minute':0},{'hour':7,'minute':0,'date':'2030-01-01','repeat_days':[1]}, {'hour':7,'minute':0,'repeat_days':[8]}, {'hour':7,'minute':0,'date':'not-a-date'}):
        with pytest.raises(Exception) as e: await ai.mutate(1,'create',args)
        assert e.value.status_code==400
    op=await ai.mutate(1,'create',{'hour':7,'minute':0,'repeat_days':[1,2,3,4,5]})
    db=await database.get_db()
    row=await (await db.execute('SELECT data FROM synced_alarms')).fetchone()
    assert json.loads(row['data'])['isRecurring'] is True
    await db.close()

@pytest.mark.asyncio
async def test_latest_operation_supersedes_pending_and_old_ack(env):
    device=await register(env)
    first=await ai.mutate(1,'create',{'hour':7,'minute':0})
    before=await ai.status(1,first)
    second=await ai.mutate(1,'update',{'hour':8},before['client_id'])
    pending=await env.get(f'/api/v1/devices/{device}/pending',headers=jwt_headers())
    assert [o['operation_id'] for o in pending.json()['operations']]==[second]
    assert (await ai.status(1,first))['devices'][0]['status']=='superseded'
    assert not (await ai.status(1,second))['complete']

@pytest.mark.asyncio
async def test_ack_all_devices_complete_and_cancel(env):
    device=await register(env)
    first=await ai.mutate(1,'create',{'hour':7,'minute':0})
    state=await ai.status(1,first)
    payload={'operation_id':first,'version':state['version'],'status':'scheduled','trigger_at':1900000000000,'timezone':'Asia/Taipei'}
    assert (await env.post(f'/api/v1/devices/{device}/receipt',headers=jwt_headers(),json=payload)).status_code==200
    assert (await ai.status(1,first))['complete']
    op=await ai.mutate(1,'delete',{},state['client_id'])
    state=await ai.status(1,op)
    payload={**payload,'operation_id':op,'version':state['version'],'status':'cancelled','trigger_at':None}
    assert (await env.post(f'/api/v1/devices/{device}/receipt',headers=jwt_headers(),json=payload)).status_code==200
    assert (await ai.status(1,op))['complete']

@pytest.mark.asyncio
async def test_concurrent_idempotent_creation_and_invalid_data(env):
    ops=await asyncio.gather(*(ai.mutate(1,'create',{'hour':7,'minute':0},idempotency_key='shared') for _ in range(4)))
    assert len(set(ops))==1
    for invalid in ({'repeat_days':[{}]}, {'is_enabled':'true'}, {'volume':True}):
        with pytest.raises(Exception) as e: await ai.mutate(1,'create',{'hour':7,'minute':0,**invalid})
        assert e.value.status_code==400

@pytest.mark.asyncio
async def test_integrated_sync_hides_dates_from_legacy_apps(env, monkeypatch):
    monkeypatch.setenv('AI_KEY_ENCRYPTION_SECRET','00'*32)
    import main
    async with httpx.AsyncClient(transport=httpx.ASGITransport(main.app),base_url='http://testserver') as client:
        op=await ai.mutate(1,'create',{'hour':7,'minute':0,'date':'2030-01-01'})
        state=await ai.status(1,op)
        legacy_list=await client.get('/alarms',headers=jwt_headers())
        assert legacy_list.status_code==200 and legacy_list.json()['alarms']==[]
        old=await client.post('/alarms/sync',headers=jwt_headers(),json={'alarms':[]})
        assert old.status_code==200,old.text
        assert old.json()['alarms']==[]
        newer=await client.post('/alarms/sync',headers=jwt_headers(),json={'capabilities':2,'alarms':[]})
        assert newer.json()['alarms'][0]['data']['scheduledDate']=='2030-01-01'
        old_upload=await client.post('/alarms/sync',headers=jwt_headers(),json={'alarms':[{'client_id':state['client_id'],'data':{'hour':8,'minute':0},'updated_at':state['version']+100,'is_deleted':False}]})
        assert old_upload.status_code==200
        newer=await client.post('/alarms/sync',headers=jwt_headers(),json={'capabilities':2,'alarms':[]})
        assert newer.json()['alarms'][0]['data']['scheduledDate']=='2030-01-01'
        assert newer.json()['alarms'][0]['data']['hour']==7
        assert (await client.get('/mcp-connect')).status_code==200
        assert (await client.get('/health')).json()=={'status':'ok'}
