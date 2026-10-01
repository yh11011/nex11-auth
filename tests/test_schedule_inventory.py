import json
import time
import pytest
import ai_delivery as ai
import database
from test_ai_mcp import env, register, jwt_headers

async def upload(client, device, cid, version, status='scheduled', trigger=None):
    return await client.post(f'/api/v1/devices/{device}/schedule-status', headers=jwt_headers(), json={'alarms':[{
        'client_id':cid,'version':version,'status':status,'trigger_at':trigger if trigger is not None else int(time.time()*1000)+3600000,
        'timezone':'Asia/Taipei','reported_at':int(time.time()*1000),
    }]})

@pytest.mark.asyncio
async def test_phone_created_alarm_and_per_device_evidence(env):
    first=await register(env)
    second=await register(env,device='b'*32)
    db=await database.get_db()
    await db.execute('INSERT INTO synced_alarms(user_id,client_id,data,updated_at,is_deleted) VALUES(?,?,?,?,0)',(1,'phone-alarm',json.dumps({'hour':7,'minute':0,'isEnabled':True}),100))
    await db.commit(); await db.close()
    before=await ai.alarm_inventory(1)
    assert before['summary']=={'registered_device_count':2,'cloud_alarm_count':1,'enabled_alarm_count':1}
    assert all(d['unconfirmed_count']==1 and d['scheduled_count']==0 for d in before['devices'])
    assert (await upload(env,first,'phone-alarm',100)).status_code==200
    assert (await upload(env,second,'phone-alarm',100,'fallback')).status_code==200
    after=await ai.alarm_inventory(1)
    assert sum(d['scheduled_count'] for d in after['devices'])==1
    assert sum(d['fallback_count'] for d in after['devices'])==1
    assert all(d['last_report_at'] is not None for d in after['devices'])
    assert (await ai.alarm_inventory(2))['summary']['cloud_alarm_count']==0

@pytest.mark.asyncio
async def test_outdated_expired_reports_and_account_isolation(env):
    device=await register(env)
    op=await ai.mutate(1,'create',{'hour':7,'minute':0})
    old=await ai.status(1,op)
    assert (await upload(env,device,old['client_id'],old['version'],trigger=1)).status_code==200
    inventory=await ai.alarm_inventory(1)
    assert inventory['devices'][0]['scheduled_count']==0
    assert inventory['alarms'][0]['device_statuses'][0]['status']=='expired'
    later=await ai.mutate(1,'update',{'hour':8},old['client_id'])
    assert (await upload(env,device,old['client_id'],old['version'])).json()['ignored']==1
    assert (await ai.alarm_inventory(1))['alarms'][0]['device_statuses'][0]['status']=='unknown'
    r=await env.post(f'/api/v1/devices/{device}/schedule-status',headers=jwt_headers(2),json={'alarms':[]})
    assert r.status_code==404
    r=await env.post(f'/api/v1/devices/{device}/schedule-status',headers={'Authorization':'Bearer nxai_fake'},json={'alarms':[]})
    assert r.status_code==401

@pytest.mark.asyncio
async def test_report_cannot_claim_cancellation_of_enabled_alarm(env):
    device=await register(env)
    op=await ai.mutate(1,'create',{'hour':7,'minute':0})
    state=await ai.status(1,op)
    assert (await upload(env,device,state['client_id'],state['version'],'cancelled')).status_code==400
    assert (await upload(env,device,state['client_id'],state['version'],'unexpected')).status_code==400

@pytest.mark.asyncio
async def test_fcm_only_sends_high_priority_fetch_hint(monkeypatch):
    import firebase_admin
    from firebase_admin import messaging
    sent=[]
    monkeypatch.setattr(firebase_admin,'get_app',lambda:object())
    monkeypatch.setattr(messaging,'send',lambda message:sent.append(message) or 'mock-message')
    await ai.push_devices([{'fcm_token':'isolated-fake-token','device_id':'a'*32}])
    assert len(sent)==1
    assert sent[0].data=={'type':'alarm_sync'}
    assert sent[0].android.priority=='high'
    assert sent[0].android.ttl.total_seconds()==300
    assert sent[0].notification is None
