"""Account-scoped AI operations and durable per-device delivery receipts."""
import asyncio
import hashlib
import json
import logging
import os
import time
import uuid
from datetime import date

from fastapi import APIRouter, Header, HTTPException
from pydantic import BaseModel, Field
from database import get_db
from jwt_utils import decode_token
from api_v1 import _resolve_token_with_scope
from rate_limiter import check_token_rate

log = logging.getLogger(__name__)
BASE = os.environ.get("BASE_URL", "https://login.nex11.me").rstrip("/")
RESOURCE = BASE + "/mcp"
router = APIRouter()

SQL = """
CREATE TABLE IF NOT EXISTS device_schedule_status (
 device_id TEXT NOT NULL, client_id TEXT NOT NULL, version INTEGER NOT NULL,
 status TEXT NOT NULL, trigger_at INTEGER, timezone TEXT NOT NULL,
 reason TEXT, reported_at INTEGER NOT NULL, received_at INTEGER NOT NULL,
 PRIMARY KEY(device_id, client_id)
);
CREATE TABLE IF NOT EXISTS ai_devices (
 device_id TEXT PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id),
 name TEXT NOT NULL, fcm_token TEXT NOT NULL DEFAULT '', timezone TEXT NOT NULL,
 capabilities INTEGER NOT NULL DEFAULT 1, active INTEGER NOT NULL DEFAULT 1,
 last_seen INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS ai_operations (
 operation_id TEXT PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id),
 client_id TEXT NOT NULL, version INTEGER NOT NULL, action TEXT NOT NULL,
 payload TEXT NOT NULL, idempotency_key TEXT, request_hash TEXT NOT NULL,
 created_at INTEGER NOT NULL, UNIQUE(user_id, idempotency_key)
);
CREATE TABLE IF NOT EXISTS ai_receipts (
 operation_id TEXT NOT NULL REFERENCES ai_operations(operation_id),
 device_id TEXT NOT NULL REFERENCES ai_devices(device_id), status TEXT NOT NULL DEFAULT 'pending',
 trigger_at INTEGER, timezone TEXT, reason TEXT, updated_at INTEGER NOT NULL,
 PRIMARY KEY(operation_id, device_id)
);
CREATE TABLE IF NOT EXISTS oauth_refresh_tokens (
 token_hash TEXT PRIMARY KEY, access_hash TEXT NOT NULL, client_id TEXT NOT NULL,
 user_id INTEGER NOT NULL, scope TEXT NOT NULL, resource TEXT NOT NULL,
 expires_at INTEGER NOT NULL, revoked INTEGER NOT NULL DEFAULT 0
);
"""

async def init_ai_db():
    db = await get_db()
    try:
        await db.executescript(SQL)
        for table in ("oauth_codes", "oauth_tokens"):
            cols = await (await db.execute(f"PRAGMA table_info({table})")).fetchall()
            if "resource" not in {r["name"] for r in cols}:
                await db.execute(f"ALTER TABLE {table} ADD COLUMN resource TEXT NOT NULL DEFAULT ''")
        cols = {r['name'] for r in await (await db.execute('PRAGMA table_info(ai_devices)')).fetchall()}
        for column, declaration in [('app_version', "TEXT NOT NULL DEFAULT ''"), ('app_version_code', 'INTEGER NOT NULL DEFAULT 0')]:
            if column not in cols:
                await db.execute(f'ALTER TABLE ai_devices ADD COLUMN {column} {declaration}')
        await db.commit()
    finally:
        await db.close()

async def premium(user_id):
    db = await get_db()
    try:
        row = await (await db.execute("SELECT is_premium FROM users WHERE id=?", (user_id,))).fetchone()
        if not row or not row["is_premium"]:
            raise HTTPException(403, "Premium required for AI integration")
    finally:
        await db.close()

async def identity(authorization, scope):
    uid, token = await _resolve_token_with_scope(authorization, scope)
    await premium(uid)
    allowed, retry = check_token_rate(token + ":mcp", 60)
    if not allowed:
        raise HTTPException(429, "Rate limit exceeded", headers={"Retry-After": str(retry)})
    return uid

async def mobile_identity(authorization):
    try:
        if not authorization or not authorization.startswith("Bearer "):
            raise ValueError()
        return int(decode_token(authorization[7:])["sub"])
    except Exception:
        raise HTTPException(401, "Unauthorized")

async def push_devices(devices):
    """Best effort hint only. Credentials use ADC; never expose payload or token."""
    if not devices:
        return
    try:
        import firebase_admin
        from firebase_admin import messaging
        try:
            firebase_admin.get_app()
        except ValueError:
            firebase_admin.initialize_app()
        for device in devices:
            if not device["fcm_token"]:
                continue
            try:
                await asyncio.to_thread(messaging.send, messaging.Message(
                    token=device["fcm_token"], data={"type": "alarm_sync"},
                    android=messaging.AndroidConfig(priority="high", ttl=__import__('datetime').timedelta(minutes=5))))
            except messaging.UnregisteredError:
                db = await get_db()
                try:
                    await db.execute("UPDATE ai_devices SET active=0 WHERE device_id=? AND fcm_token=?",
                                     (device["device_id"], device["fcm_token"]))
                    await db.commit()
                finally:
                    await db.close()
            except Exception:
                log.warning("AI delivery push failed; operation remains pending")
    except Exception:
        log.warning("FCM credentials unavailable; operation remains pending")

FIELDS = {"title":"title", "hour":"hour", "minute":"minute", "repeat_days":"repeatDays",
          "date":"scheduledDate", "is_enabled":"isEnabled", "snooze_enabled":"snoozeEnabled",
          "vibrate_only":"vibrateOnly", "volume":"volume"}

def validate(data):
    if not isinstance(data.get("title", ""), str) or len(data.get("title", "")) > 100:
        raise HTTPException(400, "Title must be at most 100 characters")
    for k, maximum in (("hour",23),("minute",59),("volume",100)):
        v = data.get(k, 80 if k == "volume" else None)
        if type(v) is not int or not 0 <= v <= maximum:
            raise HTTPException(400, f"Invalid {k}")
    days = data.get("repeatDays", [])
    if not isinstance(days, list) or len(days) > 7 or any(type(d) is not int or not 1 <= d <= 7 for d in days) or len(set(days)) != len(days):
        raise HTTPException(400, "repeat_days must contain unique weekdays 1-7")
    if data.get("scheduledDate"):
        try:
            parsed = date.fromisoformat(data["scheduledDate"])
            if parsed.isoformat() != data["scheduledDate"]:
                raise ValueError()
        except (ValueError, TypeError):
            raise HTTPException(400, "date must be YYYY-MM-DD")
        if days:
            raise HTTPException(400, "date and repeat_days are mutually exclusive")
    for key in ("isEnabled", "snoozeEnabled", "vibrateOnly"):
        if type(data.get(key)) is not bool:
            raise HTTPException(400, f"Invalid {key}")
    data["isRecurring"] = bool(days)
    data["timePolicy"] = "device_local"

async def mutate(user_id, action, arguments, client_id=None, idempotency_key=None):
    await premium(user_id)
    fingerprint = hashlib.sha256(json.dumps([action, client_id, arguments], sort_keys=True).encode()).hexdigest()
    db = await get_db()
    devices = []
    try:
        await db.execute("BEGIN IMMEDIATE")
        if idempotency_key:
            existing = await (await db.execute("SELECT operation_id,request_hash FROM ai_operations WHERE user_id=? AND idempotency_key=?", (user_id,idempotency_key))).fetchone()
            if existing:
                if existing["request_hash"] != fingerprint:
                    raise HTTPException(409, "Idempotency key already used for different arguments")
                return existing["operation_id"]
        row = None
        if action != "create":
            row = await (await db.execute("SELECT * FROM synced_alarms WHERE user_id=? AND client_id=? AND is_deleted=0", (user_id,client_id))).fetchone()
            if not row:
                raise HTTPException(404, "Alarm not found")
        data = json.loads(row["data"]) if row else {
            "title":"", "isEnabled":True, "repeatDays":[], "volume":80,
            "snoozeEnabled":True,"snoozeDelay":10,"maxSnoozeCount":3,
            "vibrateOnly":False,"keepAfterRinging":False,"folderId":None}
        for k,v in arguments.items():
            if k not in FIELDS:
                raise HTTPException(400, f"Unsupported field: {k}")
            data[FIELDS[k]] = v
        if action != "delete":
            validate(data)
        now = max(int(time.time()*1000), (row["updated_at"]+1) if row else 0)
        cid = client_id or str(uuid.uuid4())
        data.setdefault("createdAt", now)
        if action == "create":
            await db.execute("INSERT INTO synced_alarms(user_id,client_id,data,updated_at,is_deleted) VALUES (?,?,?,?,0)", (user_id,cid,json.dumps(data),now))
        else:
            await db.execute("UPDATE synced_alarms SET data=?,updated_at=?,is_deleted=? WHERE user_id=? AND client_id=?", (json.dumps(data),now,int(action=="delete"),user_id,cid))
        op = str(uuid.uuid4())
        payload = {"client_id":cid,"data":data,"updated_at":now,"is_deleted":action=="delete"}
        await db.execute("INSERT INTO ai_operations VALUES (?,?,?,?,?,?,?,?,?)", (op,user_id,cid,now,action,json.dumps(payload),idempotency_key,fingerprint,now))
        devices = await (await db.execute("SELECT * FROM ai_devices WHERE user_id=? AND active=1", (user_id,))).fetchall()
        for device in devices:
            await db.execute("INSERT INTO ai_receipts(operation_id,device_id,status,reason,updated_at) VALUES (?,?,?,?,?)",
                             (op,device["device_id"], "pending" if device["capabilities"]>=2 or not data.get("scheduledDate") else "failed",
                              None if device["capabilities"]>=2 or not data.get("scheduledDate") else "App update required for dated alarms",now))
        await db.commit()
    finally:
        await db.close()
    try:
        await asyncio.wait_for(push_devices(devices), timeout=5)
    except TimeoutError:
        log.warning("FCM push timed out; operation remains pending")
    log.info("AI operation created: %s targets=%d", op, len(devices))
    return op

async def status(user_id, operation_id):
    db = await get_db()
    try:
        op = await (await db.execute("SELECT * FROM ai_operations WHERE user_id=? AND operation_id=?",(user_id,operation_id))).fetchone()
        if not op:
            raise HTTPException(404, "Operation not found")
        rows = await (await db.execute("SELECT r.device_id,d.name,r.status,r.trigger_at,r.timezone,r.reason FROM ai_receipts r JOIN ai_devices d USING(device_id) WHERE operation_id=?", (operation_id,))).fetchall()
        devices = [dict(r) for r in rows]
        complete = bool(devices) and all(d["status"] in ("scheduled","cancelled") for d in devices)
        return {"operation_id":operation_id,"client_id":op["client_id"],"version":op["version"],
                "complete":complete,"devices":devices,
                "message":"All target devices confirmed" if complete else "Not fully confirmed; check per-device status" if devices else "No registered phones; open the updated app while signed in"}
    finally:
        await db.close()

async def wait_status(user_id, op, seconds=20):
    end = time.monotonic()+seconds
    while True:
        result = await status(user_id,op)
        if not result["devices"] or all(d["status"] != "pending" for d in result["devices"]) or time.monotonic()>=end:
            return result
        await asyncio.sleep(.5)

class Device(BaseModel):
    device_id: str = Field(min_length=32,max_length=64)
    name: str = Field(min_length=1,max_length=100)
    fcm_token: str = Field(default="",max_length=4096)
    timezone: str = Field(min_length=1,max_length=100)
    capabilities: int = Field(default=2,ge=1,le=2)
    app_version: str = Field(default="",max_length=100)
    app_version_code: int = Field(default=0,ge=0)

@router.post("/api/v1/devices/register")
async def register_device(req: Device, authorization: str = Header(None)):
    uid = await mobile_identity(authorization)
    await premium(uid)
    db = await get_db()
    try:
        old = await (await db.execute("SELECT user_id FROM ai_devices WHERE device_id=?",(req.device_id,))).fetchone()
        if old and old["user_id"] != uid:
            raise HTTPException(409,"Device belongs to another account; use a new registration ID")
        await db.execute("INSERT INTO ai_devices(device_id,user_id,name,fcm_token,timezone,capabilities,active,last_seen) VALUES (?,?,?,?,?,?,1,?) ON CONFLICT(device_id) DO UPDATE SET name=excluded.name,fcm_token=excluded.fcm_token,timezone=excluded.timezone,capabilities=excluded.capabilities,active=1,last_seen=excluded.last_seen",(req.device_id,uid,req.name,req.fcm_token,req.timezone,req.capabilities,int(time.time()*1000)))
        await db.commit()
        await db.execute('UPDATE ai_devices SET app_version=?,app_version_code=? WHERE device_id=? AND user_id=?', (req.app_version,req.app_version_code,req.device_id,uid))
        await db.commit()
        return {"registered":True}
    finally:
        await db.close()

@router.post("/api/v1/devices/{device_id}/unregister")
async def unregister_device(device_id: str, authorization: str = Header(None)):
    uid = await mobile_identity(authorization)
    db = await get_db()
    try:
        await db.execute("UPDATE ai_devices SET active=0,fcm_token='' WHERE device_id=? AND user_id=?",(device_id,uid))
        await db.execute("UPDATE ai_receipts SET status='failed',reason='Device signed out' WHERE device_id=? AND status='pending' AND operation_id IN (SELECT operation_id FROM ai_operations WHERE user_id=?)",(device_id,uid))
        await db.commit()
        return {"unregistered":True}
    finally:
        await db.close()

async def require_device(db, uid, device_id):
    row = await (await db.execute("SELECT active FROM ai_devices WHERE device_id=? AND user_id=?",(device_id,uid))).fetchone()
    if not row or not row["active"]:
        raise HTTPException(404,"Device not registered")

@router.get("/api/v1/devices/{device_id}/pending")
async def pending(device_id: str, authorization: str = Header(None)):
    uid = await mobile_identity(authorization)
    db = await get_db()
    try:
        await require_device(db,uid,device_id)
        await db.execute("UPDATE ai_receipts SET status='superseded',reason='Newer alarm version exists' WHERE device_id=? AND status='pending' AND operation_id IN (SELECT o.operation_id FROM ai_operations o JOIN synced_alarms a ON a.user_id=o.user_id AND a.client_id=o.client_id WHERE o.user_id=? AND a.updated_at>o.version)", (device_id,uid))
        await db.commit()
        rows = await (await db.execute("SELECT o.operation_id,o.version,o.payload FROM ai_operations o JOIN ai_receipts r USING(operation_id) WHERE o.user_id=? AND r.device_id=? AND r.status='pending' ORDER BY o.version LIMIT 100",(uid,device_id))).fetchall()
        return {"operations":[{"operation_id":r["operation_id"],"version":r["version"],"alarm":json.loads(r["payload"])} for r in rows]}
    finally:
        await db.close()

class Receipt(BaseModel):
    operation_id: str
    version: int
    status: str
    trigger_at: int | None = None
    timezone: str = Field(max_length=100)
    reason: str | None = Field(default=None,max_length=200)

@router.post("/api/v1/devices/{device_id}/receipt")
async def receipt(device_id: str, req: Receipt, authorization: str = Header(None)):
    uid = await mobile_identity(authorization)
    if req.status not in {"scheduled","fallback","cancelled","failed","superseded"}:
        raise HTTPException(400,"Invalid receipt status")
    db = await get_db()
    try:
        await require_device(db,uid,device_id)
        op = await (await db.execute("SELECT o.version,o.action,o.payload,o.client_id FROM ai_operations o JOIN ai_receipts r USING(operation_id) WHERE o.operation_id=? AND o.user_id=? AND r.device_id=?",(req.operation_id,uid,device_id))).fetchone()
        if not op or op["version"] != req.version:
            raise HTTPException(409,"Operation version mismatch")
        current = await (await db.execute("SELECT updated_at FROM synced_alarms WHERE user_id=? AND client_id=?",(uid,op["client_id"]))).fetchone()
        if current and current["updated_at"] > req.version:
            req.status = "superseded"
            req.reason = "Newer alarm version exists"
        expected_cancel = op["action"] == "delete" or not json.loads(op["payload"])["data"].get("isEnabled",True)
        if (expected_cancel and req.status in {"scheduled","fallback"}) or (not expected_cancel and req.status == "cancelled"):
            raise HTTPException(400,"Receipt does not match operation")
        if req.status in {"scheduled","fallback"} and (req.trigger_at is None or req.trigger_at<=0):
            raise HTTPException(400,"Scheduled receipt requires trigger_at")
        await db.execute("UPDATE ai_receipts SET status=?,trigger_at=?,timezone=?,reason=?,updated_at=? WHERE operation_id=? AND device_id=? AND status='pending'",(req.status,req.trigger_at,req.timezone,req.reason,int(time.time()*1000),req.operation_id,device_id))
        await db.commit()
        return {"accepted":True}
    finally:
        await db.close()

@router.get("/api/v1/ai/connections")
async def connections(authorization: str = Header(None)):
    uid = await mobile_identity(authorization)
    await premium(uid)
    db = await get_db()
    try:
        devices = await (await db.execute("SELECT device_id,name,timezone,last_seen FROM ai_devices WHERE user_id=? AND active=1",(uid,))).fetchall()
        grants = await (await db.execute("SELECT DISTINCT t.client_id,c.client_name FROM oauth_tokens t JOIN oauth_clients c USING(client_id) WHERE t.user_id=? AND t.resource=? AND t.revoked=0 AND t.expires_at>?",(uid,RESOURCE,int(time.time()*1000)))).fetchall()
        return {"mcp_url":RESOURCE,"devices":[dict(r) for r in devices],"connections":[dict(r) for r in grants]}
    finally:
        await db.close()

class RevokeConnection(BaseModel):
    client_id: str

@router.post("/api/v1/ai/connections/revoke")
async def revoke_connection(req: RevokeConnection, authorization: str = Header(None)):
    uid = await mobile_identity(authorization)
    db = await get_db()
    try:
        await db.execute("UPDATE oauth_tokens SET revoked=1 WHERE user_id=? AND client_id=?",(uid,req.client_id))
        await db.execute("UPDATE oauth_refresh_tokens SET revoked=1 WHERE user_id=? AND client_id=?",(uid,req.client_id))
        await db.commit()
        return {"revoked":True}
    finally:
        await db.close()


@router.get("/mcp-connect")
async def connect_guide():
    from pathlib import Path
    from fastapi.responses import HTMLResponse
    return HTMLResponse((Path(__file__).parent / "static/mcp-connect.html").read_text())


class ScheduleEntry(BaseModel):
    client_id: str = Field(min_length=1,max_length=100)
    version: int = Field(ge=0)
    status: str
    trigger_at: int | None = None
    timezone: str = Field(min_length=1,max_length=100)
    reason: str | None = Field(default=None,max_length=200)
    reported_at: int = Field(gt=0)

class ScheduleReport(BaseModel):
    alarms: list[ScheduleEntry] = Field(max_length=20)

@router.post('/api/v1/devices/{device_id}/schedule-status')
async def schedule_report(device_id: str, req: ScheduleReport, authorization: str = Header(None)):
    uid = await mobile_identity(authorization)
    now = int(time.time()*1000)
    db = await get_db()
    accepted = 0
    try:
        await db.execute('BEGIN IMMEDIATE')
        await require_device(db,uid,device_id)
        for entry in req.alarms:
            if entry.status not in {'scheduled','fallback','cancelled','failed','unknown'}:
                raise HTTPException(400,'Invalid schedule status')
            if entry.status in {'scheduled','fallback'} and (entry.trigger_at is None or entry.trigger_at <= 0):
                raise HTTPException(400,'Scheduled status requires trigger_at')
            alarm = await (await db.execute('SELECT data,updated_at,is_deleted FROM synced_alarms WHERE user_id=? AND client_id=?',(uid,entry.client_id))).fetchone()
            if not alarm or alarm['updated_at'] != entry.version:
                continue  # a later sync will report the current version
            enabled = not alarm['is_deleted'] and json.loads(alarm['data']).get('isEnabled',True)
            if (enabled and entry.status == 'cancelled') or (not enabled and entry.status in {'scheduled','fallback'}):
                raise HTTPException(400,'Schedule status contradicts current alarm')
            # Device clock changes must not prevent subsequent reports replacing old ones.
            await db.execute('INSERT INTO device_schedule_status VALUES(?,?,?,?,?,?,?,?,?) ON CONFLICT(device_id,client_id) DO UPDATE SET version=excluded.version,status=excluded.status,trigger_at=excluded.trigger_at,timezone=excluded.timezone,reason=excluded.reason,reported_at=excluded.reported_at,received_at=excluded.received_at',
                (device_id,entry.client_id,entry.version,entry.status,entry.trigger_at,entry.timezone,entry.reason,entry.reported_at,now))
            accepted += 1
        await db.commit()
        return {'accepted':accepted,'ignored':len(req.alarms)-accepted}
    finally:
        await db.close()

async def alarm_inventory(user_id):
    now = int(time.time()*1000)
    db = await get_db()
    try:
        alarms = await (await db.execute('SELECT client_id,data,updated_at FROM synced_alarms WHERE user_id=? AND is_deleted=0 ORDER BY updated_at DESC',(user_id,))).fetchall()
        devices = await (await db.execute('SELECT device_id,name,timezone,last_seen,app_version,app_version_code FROM ai_devices WHERE user_id=? AND active=1',(user_id,))).fetchall()
        reports = await (await db.execute('SELECT s.* FROM device_schedule_status s JOIN ai_devices d USING(device_id) WHERE d.user_id=? AND d.active=1',(user_id,))).fetchall()
        indexed = {(r['device_id'],r['client_id']):dict(r) for r in reports}
        output = []
        summaries = [dict(d,scheduled_count=0,fallback_count=0,unconfirmed_count=0,last_report_at=None) for d in devices]
        for alarm in alarms:
            data = json.loads(alarm['data']); outcomes = []
            for device in summaries:
                report = indexed.get((device['device_id'],alarm['client_id']))
                outcome = {'device_id':device['device_id'],'status':'unknown','reported_at':None}
                if report:
                    outcome.update({k:report[k] for k in ('status','trigger_at','timezone','reason','reported_at','received_at')})
                    device['last_report_at'] = max(device['last_report_at'] or 0,report['received_at'])
                    if report['version'] != alarm['updated_at']: outcome['status'] = 'unknown'
                    elif outcome['status'] in {'scheduled','fallback'} and (not data.get('isEnabled',True) or (outcome['trigger_at'] or 0) <= now): outcome['status'] = 'expired'
                if data.get('isEnabled',True):
                    key = 'scheduled_count' if outcome['status']=='scheduled' else 'fallback_count' if outcome['status']=='fallback' else 'unconfirmed_count'
                    device[key] += 1
                outcomes.append(outcome)
            output.append({'client_id':alarm['client_id'],'data':data,'version':alarm['updated_at'],'device_statuses':outcomes})
        return {'alarms':output,'devices':summaries,'summary':{'registered_device_count':len(devices),'cloud_alarm_count':len(output),'enabled_alarm_count':sum(a['data'].get('isEnabled',True) for a in output)},'schedule_evidence':'Last device report of submission to Android scheduler; does not guarantee future ringing.'}
    finally:
        await db.close()

# Public app updates are available independently of Premium and account login.
from app_updates import router as updates_router
router.include_router(updates_router)
