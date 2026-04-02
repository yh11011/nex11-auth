"""
REST API v1 — /api/v1/
Exposes CRUD endpoints for alarms and folders.
Accepts both JWT Bearer tokens (existing) and OAuth access tokens (nxai_…).
"""
import hashlib
import json
import time
import uuid

from fastapi import APIRouter, Header, HTTPException, Request
from pydantic import BaseModel

from database import get_db
from jwt_utils import decode_token
from rate_limiter import check_token_rate

router = APIRouter(prefix="/api/v1", tags=["API v1"])


# ─── Auth helper: JWT or OAuth token ─────────────────────────────────────────

async def _resolve_token(authorization: str | None) -> tuple[int, str]:
    """Returns (user_id, raw_token). Raises 401 on any failure."""
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(401, "Unauthorized")
    token = authorization.split(" ", 1)[1].strip()

    # JWT detection: three dot-separated Base64url segments
    if token.count(".") == 2:
        try:
            payload = decode_token(token)
            return int(payload["sub"]), token
        except Exception:
            raise HTTPException(401, "Unauthorized")

    # OAuth access token (nxai_…)
    if token.startswith("nxai_"):
        token_hash = hashlib.sha256(token.encode()).hexdigest()
        now_ms = int(time.time() * 1000)
        db = await get_db()
        try:
            async with db.execute(
                "SELECT user_id, scope FROM oauth_tokens "
                "WHERE token_hash=? AND revoked=0 AND expires_at>?",
                (token_hash, now_ms)
            ) as cur:
                row = await cur.fetchone()
            if not row:
                raise HTTPException(401, "Unauthorized")
            return row["user_id"], token
        finally:
            await db.close()

    raise HTTPException(401, "Unauthorized")


def _check_write_scope(authorization: str | None):
    """For OAuth tokens, verify alarm:write scope is granted."""
    # JWT tokens always have full access; OAuth tokens checked separately
    pass  # scope enforcement is handled in _resolve_token_with_scope


async def _resolve_token_with_scope(authorization: str | None, required: str) -> tuple[int, str]:
    """Like _resolve_token but also verifies OAuth scope for non-JWT tokens."""
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(401, "Unauthorized")
    token = authorization.split(" ", 1)[1].strip()

    if token.count(".") == 2:
        try:
            payload = decode_token(token)
            return int(payload["sub"]), token
        except Exception:
            raise HTTPException(401, "Unauthorized")

    if token.startswith("nxai_"):
        token_hash = hashlib.sha256(token.encode()).hexdigest()
        now_ms = int(time.time() * 1000)
        db = await get_db()
        try:
            async with db.execute(
                "SELECT user_id, scope FROM oauth_tokens "
                "WHERE token_hash=? AND revoked=0 AND expires_at>?",
                (token_hash, now_ms)
            ) as cur:
                row = await cur.fetchone()
            if not row:
                raise HTTPException(401, "Unauthorized")
            granted_scopes = row["scope"].split()
            if required not in granted_scopes:
                raise HTTPException(403, "Insufficient scope")
            return row["user_id"], token
        finally:
            await db.close()

    raise HTTPException(401, "Unauthorized")


# ─── Request models ───────────────────────────────────────────────────────────

class AlarmV1Create(BaseModel):
    title: str
    hour: int
    minute: int
    repeat_days: list[int] = []
    folder_id: int | None = None
    snooze_enabled: bool = True


class AlarmV1Patch(BaseModel):
    title: str | None = None
    hour: int | None = None
    minute: int | None = None
    repeat_days: list[int] | None = None
    is_enabled: bool | None = None
    folder_id: int | None = None
    snooze_enabled: bool | None = None


# ─── Response builder ─────────────────────────────────────────────────────────

def _alarm_v1_response(row) -> dict:
    data = json.loads(row["data"])
    return {
        "id": row["id"],
        "client_id": row["client_id"],
        "title": data.get("title", ""),
        "hour": data.get("hour", 0),
        "minute": data.get("minute", 0),
        "repeat_days": data.get("repeatDays", []),
        "is_enabled": data.get("isEnabled", True),
        "folder_id": data.get("folderId"),
        "snooze_enabled": data.get("snoozeEnabled", True),
        "updated_at": row["updated_at"],
    }


def _validate_alarm_fields(title: str | None, hour: int | None, minute: int | None,
                            repeat_days: list | None):
    if title is not None and len(title) > 100:
        raise HTTPException(400, "title must be at most 100 characters")
    if hour is not None and not (0 <= hour <= 23):
        raise HTTPException(400, "hour must be 0-23")
    if minute is not None and not (0 <= minute <= 59):
        raise HTTPException(400, "minute must be 0-59")
    if repeat_days is not None:
        if len(repeat_days) > 7:
            raise HTTPException(400, "repeat_days cannot have more than 7 items")
        if any(d not in range(1, 8) for d in repeat_days):
            raise HTTPException(400, "repeat_days items must be 1-7 (Mon=1…Sun=7)")


# ─── Endpoints ────────────────────────────────────────────────────────────────

@router.get("/alarms", summary="列出所有鬧鐘")
async def list_alarms(request: Request, authorization: str = Header(None)):
    user_id, token = await _resolve_token_with_scope(authorization, "alarm:read")

    allowed, retry = check_token_rate(token, 60)
    if not allowed:
        raise HTTPException(429, "Rate limit exceeded",
                            headers={"Retry-After": str(retry)})

    db = await get_db()
    try:
        async with db.execute(
            "SELECT id, client_id, data, updated_at FROM synced_alarms "
            "WHERE user_id=? AND is_deleted=0 ORDER BY updated_at DESC",
            (user_id,)
        ) as cur:
            rows = await cur.fetchall()
        return {"alarms": [_alarm_v1_response(r) for r in rows]}
    finally:
        await db.close()


@router.post("/alarms", status_code=201, summary="新增鬧鐘")
async def create_alarm(req: AlarmV1Create, request: Request, authorization: str = Header(None)):
    user_id, token = await _resolve_token_with_scope(authorization, "alarm:write")

    # Strict rate limit for creation (10/min per token)
    allowed, retry = check_token_rate(token + ":create", 10)
    if not allowed:
        raise HTTPException(429, "Rate limit exceeded",
                            headers={"Retry-After": str(retry)})

    _validate_alarm_fields(req.title, req.hour, req.minute, req.repeat_days)

    client_id = str(uuid.uuid4())
    now = int(time.time() * 1000)
    data = {
        "title": req.title,
        "hour": req.hour,
        "minute": req.minute,
        "isEnabled": True,
        "repeatDays": req.repeat_days,
        "snoozeEnabled": req.snooze_enabled,
        "folderId": req.folder_id,
        "clientId": client_id,
        "updatedAt": now,
    }

    db = await get_db()
    try:
        await db.execute(
            "INSERT INTO synced_alarms (user_id, client_id, data, updated_at, is_deleted) "
            "VALUES (?,?,?,?,0)",
            (user_id, client_id, json.dumps(data, ensure_ascii=False), now)
        )
        await db.commit()
        async with db.execute(
            "SELECT id, client_id, data, updated_at FROM synced_alarms "
            "WHERE user_id=? AND client_id=?",
            (user_id, client_id)
        ) as cur:
            row = await cur.fetchone()
        return {"alarm": _alarm_v1_response(row)}
    finally:
        await db.close()


@router.patch("/alarms/{client_id}", summary="修改鬧鐘（部分更新）")
async def patch_alarm(client_id: str, req: AlarmV1Patch, request: Request,
                      authorization: str = Header(None)):
    user_id, token = await _resolve_token_with_scope(authorization, "alarm:write")

    allowed, retry = check_token_rate(token, 60)
    if not allowed:
        raise HTTPException(429, "Rate limit exceeded",
                            headers={"Retry-After": str(retry)})

    _validate_alarm_fields(req.title, req.hour, req.minute, req.repeat_days)

    db = await get_db()
    try:
        async with db.execute(
            "SELECT id, client_id, data, updated_at FROM synced_alarms "
            "WHERE user_id=? AND client_id=? AND is_deleted=0",
            (user_id, client_id)
        ) as cur:
            row = await cur.fetchone()
        if not row:
            raise HTTPException(404, "Alarm not found")

        data = json.loads(row["data"])
        if req.title          is not None: data["title"]         = req.title
        if req.hour           is not None: data["hour"]          = req.hour
        if req.minute         is not None: data["minute"]        = req.minute
        if req.repeat_days    is not None: data["repeatDays"]    = req.repeat_days
        if req.is_enabled     is not None: data["isEnabled"]     = req.is_enabled
        if req.folder_id      is not None: data["folderId"]      = req.folder_id
        if req.snooze_enabled is not None: data["snoozeEnabled"] = req.snooze_enabled

        now = int(time.time() * 1000)
        data["updatedAt"] = now
        await db.execute(
            "UPDATE synced_alarms SET data=?, updated_at=? WHERE user_id=? AND client_id=?",
            (json.dumps(data, ensure_ascii=False), now, user_id, client_id)
        )
        await db.commit()

        async with db.execute(
            "SELECT id, client_id, data, updated_at FROM synced_alarms "
            "WHERE user_id=? AND client_id=?",
            (user_id, client_id)
        ) as cur:
            updated = await cur.fetchone()
        return {"alarm": _alarm_v1_response(updated)}
    finally:
        await db.close()


@router.delete("/alarms/{client_id}", summary="刪除鬧鐘")
async def delete_alarm(client_id: str, request: Request,
                       authorization: str = Header(None)):
    user_id, token = await _resolve_token_with_scope(authorization, "alarm:write")

    allowed, retry = check_token_rate(token, 60)
    if not allowed:
        raise HTTPException(429, "Rate limit exceeded",
                            headers={"Retry-After": str(retry)})

    db = await get_db()
    try:
        async with db.execute(
            "SELECT id FROM synced_alarms WHERE user_id=? AND client_id=? AND is_deleted=0",
            (user_id, client_id)
        ) as cur:
            if not await cur.fetchone():
                raise HTTPException(404, "Alarm not found")

        now = int(time.time() * 1000)
        await db.execute(
            "UPDATE synced_alarms SET is_deleted=1, updated_at=? WHERE user_id=? AND client_id=?",
            (now, user_id, client_id)
        )
        await db.commit()
        return {"success": True}
    finally:
        await db.close()


@router.get("/folders", summary="列出資料夾")
async def list_folders(request: Request, authorization: str = Header(None)):
    user_id, token = await _resolve_token_with_scope(authorization, "alarm:read")

    allowed, retry = check_token_rate(token, 60)
    if not allowed:
        raise HTTPException(429, "Rate limit exceeded",
                            headers={"Retry-After": str(retry)})

    db = await get_db()
    try:
        # Folders are local to the Android app; server returns registered folder IDs
        # extracted from synced alarm data, plus any server-side folder records
        async with db.execute(
            "SELECT id, name, emoji FROM user_folders WHERE user_id=? ORDER BY id",
            (user_id,)
        ) as cur:
            rows = await cur.fetchall()

        # Also extract folder_ids mentioned in alarm data but not in user_folders
        async with db.execute(
            "SELECT data FROM synced_alarms WHERE user_id=? AND is_deleted=0",
            (user_id,)
        ) as cur:
            alarm_rows = await cur.fetchall()

        known_ids = {r["id"] for r in rows}
        extra = {}
        for ar in alarm_rows:
            d = json.loads(ar["data"])
            fid = d.get("folderId")
            if fid and fid not in known_ids:
                extra[fid] = {"id": fid, "name": None, "emoji": None}

        result = [{"id": r["id"], "name": r["name"], "emoji": r["emoji"]} for r in rows]
        result.extend(extra.values())
        return {"folders": result}
    finally:
        await db.close()
