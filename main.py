import os
import re
import secrets
import urllib.parse
from contextlib import asynccontextmanager
from pathlib import Path

import httpx
from fastapi import FastAPI, HTTPException, Header, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError

from database import init_db, get_db
from jwt_utils import encode_token, decode_token

# OAuth credentials (set in .env)
GITHUB_CLIENT_ID     = os.environ.get("GITHUB_CLIENT_ID", "")
GITHUB_CLIENT_SECRET = os.environ.get("GITHUB_CLIENT_SECRET", "")
GOOGLE_CLIENT_ID     = os.environ.get("GOOGLE_CLIENT_ID", "")
GOOGLE_CLIENT_SECRET = os.environ.get("GOOGLE_CLIENT_SECRET", "")

BASE_URL = os.environ.get("BASE_URL", "https://login.nex11.me")  # for OAuth callback URIs

ph = PasswordHasher()

TOKEN_EXPIRE_MINUTES = int(os.environ.get("TOKEN_EXPIRE_MINUTES", 10080))  # 7 days

# 優惠碼從環境變數讀取，逗號分隔，不區分大小寫
PROMO_CODES: set[str] = {
    c.strip().lower()
    for c in os.environ.get("PROMO_CODES", "").split(",")
    if c.strip()
}

CORS_ORIGINS = [o.strip() for o in os.environ.get("AUTH_CORS_ORIGINS", ",".join([
    "http://localhost:5000",
    "http://localhost:5001",
    "http://localhost:5173",
    "https://cybersecurity.nex11.me",
    "https://yh11011.github.io",
])).split(",") if o.strip()]


@asynccontextmanager
async def lifespan(app: FastAPI):
    await init_db()
    yield


app = FastAPI(title="Nex11 Auth Service", lifespan=lifespan)
app.mount("/static", StaticFiles(directory=str(Path(__file__).parent / "static")), name="static")

app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type"],
)


# ---------- helpers ----------

EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def _is_email(value: str) -> bool:
    return bool(EMAIL_RE.match(value))


def _user_to_dict(row) -> dict:
    return {
        "id": row["id"],
        "username": row["username"],
        "email": row["email"],
        "display_name": row["display_name"],
        "created_at": row["created_at"],
        "is_premium": bool(row["is_premium"]) if "is_premium" in row.keys() else False,
    }


# ---------- request / response models ----------

class AuthRequest(BaseModel):
    username_or_email: str
    password: str
    display_name: str | None = None


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user: dict


class PromoRequest(BaseModel):
    code: str


# ---------- routes ----------

@app.get("/", response_class=HTMLResponse)
async def root():
    html = (Path(__file__).parent / "static" / "index.html").read_text(encoding="utf-8")
    return HTMLResponse(content=html)


@app.get("/ai-setup", response_class=HTMLResponse)
async def ai_setup():
    html = (Path(__file__).parent / "static" / "ai-setup.html").read_text(encoding="utf-8")
    return HTMLResponse(content=html)


@app.get("/health")
async def health():
    return {"status": "ok"}


@app.post("/promo/validate")
async def validate_promo(req: PromoRequest):
    """驗證優惠碼（不記錄使用次數，純驗證）"""
    if not req.code.strip():
        raise HTTPException(400, "code is required")
    if req.code.strip().lower() in PROMO_CODES:
        return {"valid": True}
    raise HTTPException(400, "Invalid promo code")


@app.post("/promo/redeem")
async def redeem_promo(req: PromoRequest, authorization: str = Header(None)):
    """驗證優惠碼並將帳號升級為 Premium（需登入）"""
    user_id = _require_auth(authorization)
    if not req.code.strip():
        raise HTTPException(400, "code is required")
    if req.code.strip().lower() not in PROMO_CODES:
        raise HTTPException(400, "Invalid promo code")
    db = await get_db()
    try:
        await db.execute("UPDATE users SET is_premium = 1 WHERE id = ?", (user_id,))
        await db.commit()
        return {"success": True, "is_premium": True}
    finally:
        await db.close()


@app.post("/premium/activate")
async def activate_premium(authorization: str = Header(None)):
    """將帳號標記為 Premium（Google Play 購買後呼叫，需登入）"""
    user_id = _require_auth(authorization)
    db = await get_db()
    try:
        await db.execute("UPDATE users SET is_premium = 1 WHERE id = ?", (user_id,))
        await db.commit()
        return {"success": True, "is_premium": True}
    finally:
        await db.close()


@app.post("/register", response_model=TokenResponse)
async def register(req: AuthRequest):
    identifier = req.username_or_email.strip()
    if not identifier:
        raise HTTPException(400, "username_or_email is required")
    if len(req.password) < 8:
        raise HTTPException(400, "password must be at least 8 characters")

    is_email = _is_email(identifier)

    if is_email:
        if len(identifier) > 254:
            raise HTTPException(400, "email too long")
        username_val, email_val = None, identifier.lower()
    else:
        if len(identifier) < 2 or len(identifier) > 30:
            raise HTTPException(400, "username must be 2-30 characters")
        username_val, email_val = identifier, None

    pw_hash = ph.hash(req.password)

    db = await get_db()
    try:
        # Check uniqueness before insert for a clearer error message
        if is_email:
            async with db.execute("SELECT id FROM users WHERE email = ?", (email_val,)) as cur:
                if await cur.fetchone():
                    raise HTTPException(409, "email already registered")
        else:
            async with db.execute("SELECT id FROM users WHERE username = ? COLLATE NOCASE", (username_val,)) as cur:
                if await cur.fetchone():
                    raise HTTPException(409, "username already taken")

        await db.execute(
            "INSERT INTO users (username, email, password_hash, display_name) VALUES (?, ?, ?, ?)",
            (username_val, email_val, pw_hash, req.display_name),
        )
        await db.commit()

        async with db.execute(
            "SELECT * FROM users WHERE " + ("email = ?" if is_email else "username = ? COLLATE NOCASE"),
            (email_val if is_email else username_val,),
        ) as cur:
            row = await cur.fetchone()

        user = _user_to_dict(row)
        token = encode_token(user, TOKEN_EXPIRE_MINUTES)
        return TokenResponse(access_token=token, user=user)
    finally:
        await db.close()


@app.post("/login", response_model=TokenResponse)
async def login(req: AuthRequest):
    identifier = req.username_or_email.strip()
    if not identifier:
        raise HTTPException(400, "username_or_email is required")

    is_email = _is_email(identifier)

    db = await get_db()
    try:
        if is_email:
            async with db.execute("SELECT * FROM users WHERE email = ?", (identifier.lower(),)) as cur:
                row = await cur.fetchone()
        else:
            async with db.execute("SELECT * FROM users WHERE username = ? COLLATE NOCASE", (identifier,)) as cur:
                row = await cur.fetchone()

        if not row:
            raise HTTPException(401, "Invalid credentials")

        try:
            ph.verify(row["password_hash"], req.password)
        except VerifyMismatchError:
            raise HTTPException(401, "Invalid credentials")

        # Rehash if needed (Argon2 parameter upgrade)
        if ph.check_needs_rehash(row["password_hash"]):
            new_hash = ph.hash(req.password)
            await db.execute("UPDATE users SET password_hash = ? WHERE id = ?", (new_hash, row["id"]))
            await db.commit()

        user = _user_to_dict(row)
        token = encode_token(user, TOKEN_EXPIRE_MINUTES)
        return TokenResponse(access_token=token, user=user)
    finally:
        await db.close()


@app.get("/me")
async def me(authorization: str = Header(None)):
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(401, "Missing or invalid Authorization header")
    token = authorization.split(" ", 1)[1].strip()
    try:
        payload = decode_token(token)
    except Exception:
        raise HTTPException(401, "Invalid or expired token")

    db = await get_db()
    try:
        async with db.execute("SELECT * FROM users WHERE id = ?", (int(payload["sub"]),)) as cur:
            row = await cur.fetchone()
        if not row:
            raise HTTPException(404, "User not found")
        return _user_to_dict(row)
    finally:
        await db.close()


@app.post("/logout")
async def logout():
    # JWT is stateless; client must discard the token
    return {"message": "logged out"}


# ─────────────────────────────────────────────
# 鬧鐘同步 API
# ─────────────────────────────────────────────

def _require_auth(authorization: str | None) -> int:
    """從 Authorization header 解析 user_id，失敗拋 401"""
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(401, "Missing or invalid Authorization header")
    token = authorization.split(" ", 1)[1].strip()
    try:
        payload = decode_token(token)
        return int(payload["sub"])
    except Exception:
        raise HTTPException(401, "Invalid or expired token")


class AlarmSyncItem(BaseModel):
    client_id: str
    data: dict
    updated_at: int   # Unix ms
    is_deleted: bool = False


class AlarmSyncRequest(BaseModel):
    alarms: list[AlarmSyncItem]


async def _require_premium(user_id: int):
    """確認使用者為 Premium，否則拋 403"""
    db = await get_db()
    try:
        async with db.execute("SELECT is_premium FROM users WHERE id = ?", (user_id,)) as cur:
            row = await cur.fetchone()
        if not row or not row["is_premium"]:
            raise HTTPException(403, "Cloud sync is a Premium feature. Please upgrade to continue.")
    finally:
        await db.close()


@app.get("/alarms")
async def get_alarms(authorization: str = Header(None)):
    """取得使用者所有未刪除的鬧鐘（Premium 限定）"""
    user_id = _require_auth(authorization)
    await _require_premium(user_id)
    db = await get_db()
    try:
        async with db.execute(
            "SELECT client_id, data, updated_at FROM synced_alarms WHERE user_id = ? AND is_deleted = 0",
            (user_id,)
        ) as cur:
            rows = await cur.fetchall()
        return {"alarms": [
            {"client_id": r["client_id"], "data": r["data"], "updated_at": r["updated_at"]}
            for r in rows
        ]}
    finally:
        await db.close()


@app.post("/alarms/sync")
async def sync_alarms(req: AlarmSyncRequest, authorization: str = Header(None)):
    """
    雙向同步：last-write-wins（依 updated_at 時間戳記決定）（Premium 限定）
    - 收到客戶端鬧鐘：若比伺服器版本新 → 更新伺服器
    - 回傳伺服器上全部鬧鐘（包含軟刪除）供客戶端應用
    """
    import json
    user_id = _require_auth(authorization)
    await _require_premium(user_id)
    db = await get_db()
    try:
        for item in req.alarms:
            # 查詢伺服器現有版本
            async with db.execute(
                "SELECT updated_at FROM synced_alarms WHERE user_id = ? AND client_id = ?",
                (user_id, item.client_id)
            ) as cur:
                existing = await cur.fetchone()

            data_json = json.dumps(item.data, ensure_ascii=False)

            if existing is None:
                # 新增
                await db.execute(
                    "INSERT INTO synced_alarms (user_id, client_id, data, updated_at, is_deleted) VALUES (?,?,?,?,?)",
                    (user_id, item.client_id, data_json, item.updated_at, int(item.is_deleted))
                )
            elif item.updated_at > existing["updated_at"]:
                # 客戶端比較新 → 覆蓋伺服器
                await db.execute(
                    "UPDATE synced_alarms SET data=?, updated_at=?, is_deleted=? WHERE user_id=? AND client_id=?",
                    (data_json, item.updated_at, int(item.is_deleted), user_id, item.client_id)
                )
            # 否則伺服器版本較新，保留伺服器版本

        await db.commit()

        # 回傳伺服器全部鬧鐘（包含軟刪除，讓客戶端知道哪些要刪）
        async with db.execute(
            "SELECT client_id, data, updated_at, is_deleted FROM synced_alarms WHERE user_id = ?",
            (user_id,)
        ) as cur:
            rows = await cur.fetchall()

        return {"alarms": [
            {
                "client_id": r["client_id"],
                "data": json.loads(r["data"]),
                "updated_at": r["updated_at"],
                "is_deleted": bool(r["is_deleted"])
            }
            for r in rows
        ]}
    finally:
        await db.close()


# ─────────────────────────────────────────────
# OAuth 輔助函數
# ─────────────────────────────────────────────

def _oauth_redirect_url(token: str, next_url: str) -> str:
    """登入成功後的前端跳轉 URL（帶 token）"""
    base = f"{BASE_URL}/"
    params = {"token": token}
    if next_url:
        params["next"] = next_url
    return base + "?" + urllib.parse.urlencode(params)


async def _upsert_oauth_user(provider: str, provider_id: str, email: str | None,
                              display_name: str | None, username_hint: str) -> dict:
    """找到或建立 OAuth 使用者，回傳 user dict"""
    db = await get_db()
    try:
        # 先用 oauth_provider + oauth_id 查
        async with db.execute(
            "SELECT * FROM users WHERE oauth_provider = ? AND oauth_id = ?",
            (provider, provider_id)
        ) as cur:
            row = await cur.fetchone()

        if row:
            return _user_to_dict(row)

        # 沒有 → 嘗試用 email 找現有帳號
        if email:
            async with db.execute("SELECT * FROM users WHERE email = ?", (email.lower(),)) as cur:
                row = await cur.fetchone()
            if row:
                # 綁定 OAuth 到現有帳號
                await db.execute(
                    "UPDATE users SET oauth_provider=?, oauth_id=? WHERE id=?",
                    (provider, provider_id, row["id"])
                )
                await db.commit()
                return _user_to_dict(row)

        # 新建帳號：產生不重複的 username
        base_name = re.sub(r"[^a-z0-9_]", "", username_hint.lower())[:20] or provider
        username = base_name
        suffix = 1
        while True:
            async with db.execute(
                "SELECT id FROM users WHERE username = ? COLLATE NOCASE", (username,)
            ) as cur:
                if not await cur.fetchone():
                    break
            username = f"{base_name}{suffix}"
            suffix += 1

        await db.execute(
            "INSERT INTO users (username, email, password_hash, display_name, oauth_provider, oauth_id) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (username, email.lower() if email else None, "", display_name or username_hint, provider, provider_id)
        )
        await db.commit()
        async with db.execute("SELECT * FROM users WHERE username = ?", (username,)) as cur:
            row = await cur.fetchone()
        return _user_to_dict(row)
    finally:
        await db.close()


# ─────────────────────────────────────────────
# GitHub OAuth
# ─────────────────────────────────────────────

@app.get("/auth/github")
async def github_login(
    origin: str = Query(default=""),
    next: str = Query(default="")
):
    if not GITHUB_CLIENT_ID:
        raise HTTPException(501, "GitHub OAuth not configured")
    state = secrets.token_urlsafe(16)
    # encode next + origin into state (simple pipe-separated)
    state_data = urllib.parse.quote(f"{state}|{next}|{origin}")
    callback = f"{BASE_URL}/auth/github/callback"
    url = (
        "https://github.com/login/oauth/authorize"
        f"?client_id={GITHUB_CLIENT_ID}"
        f"&redirect_uri={urllib.parse.quote(callback)}"
        f"&scope=user:email"
        f"&state={state_data}"
    )
    return RedirectResponse(url)


@app.get("/auth/github/callback")
async def github_callback(code: str = Query(...), state: str = Query(default="")):
    if not GITHUB_CLIENT_ID:
        raise HTTPException(501, "GitHub OAuth not configured")
    try:
        # Decode state
        decoded = urllib.parse.unquote(state)
        parts = decoded.split("|", 2)
        next_url = parts[1] if len(parts) > 1 else ""

        # Exchange code for token
        async with httpx.AsyncClient() as client:
            resp = await client.post(
                "https://github.com/login/oauth/access_token",
                json={"client_id": GITHUB_CLIENT_ID, "client_secret": GITHUB_CLIENT_SECRET, "code": code},
                headers={"Accept": "application/json"},
                timeout=15,
            )
            token_data = resp.json()
            access_token = token_data.get("access_token")
            if not access_token:
                raise HTTPException(400, "GitHub OAuth failed")

            # Get user info
            user_resp = await client.get(
                "https://api.github.com/user",
                headers={"Authorization": f"Bearer {access_token}", "Accept": "application/vnd.github+json"},
                timeout=15,
            )
            gh_user = user_resp.json()

            # Get primary email
            email_resp = await client.get(
                "https://api.github.com/user/emails",
                headers={"Authorization": f"Bearer {access_token}", "Accept": "application/vnd.github+json"},
                timeout=15,
            )
            emails = email_resp.json() if email_resp.status_code == 200 else []
            primary_email = next(
                (e["email"] for e in emails if isinstance(e, dict) and e.get("primary") and e.get("verified")),
                gh_user.get("email")
            )

        user = await _upsert_oauth_user(
            provider="github",
            provider_id=str(gh_user["id"]),
            email=primary_email,
            display_name=gh_user.get("name") or gh_user.get("login"),
            username_hint=gh_user.get("login", "user"),
        )
        jwt = encode_token(user, TOKEN_EXPIRE_MINUTES)
        return RedirectResponse(_oauth_redirect_url(jwt, next_url))
    except HTTPException:
        raise
    except Exception as e:
        return RedirectResponse(f"{BASE_URL}/?error=github_failed")


# ─────────────────────────────────────────────
# Google OAuth
# ─────────────────────────────────────────────

@app.get("/auth/google")
async def google_login(
    origin: str = Query(default=""),
    next: str = Query(default="")
):
    if not GOOGLE_CLIENT_ID:
        raise HTTPException(501, "Google OAuth not configured")
    state = urllib.parse.quote(f"{secrets.token_urlsafe(16)}|{next}|{origin}")
    callback = f"{BASE_URL}/auth/google/callback"
    url = (
        "https://accounts.google.com/o/oauth2/v2/auth"
        f"?client_id={GOOGLE_CLIENT_ID}"
        f"&redirect_uri={urllib.parse.quote(callback)}"
        f"&response_type=code"
        f"&scope=openid%20email%20profile"
        f"&state={state}"
        f"&access_type=offline"
    )
    return RedirectResponse(url)


@app.get("/auth/google/callback")
async def google_callback(code: str = Query(...), state: str = Query(default="")):
    if not GOOGLE_CLIENT_ID:
        raise HTTPException(501, "Google OAuth not configured")
    try:
        decoded = urllib.parse.unquote(state)
        parts = decoded.split("|", 2)
        next_url = parts[1] if len(parts) > 1 else ""

        callback = f"{BASE_URL}/auth/google/callback"
        async with httpx.AsyncClient() as client:
            token_resp = await client.post(
                "https://oauth2.googleapis.com/token",
                data={
                    "client_id": GOOGLE_CLIENT_ID,
                    "client_secret": GOOGLE_CLIENT_SECRET,
                    "code": code,
                    "redirect_uri": callback,
                    "grant_type": "authorization_code",
                },
                timeout=15,
            )
            token_data = token_resp.json()
            access_token = token_data.get("access_token")
            if not access_token:
                raise HTTPException(400, "Google OAuth failed")

            userinfo_resp = await client.get(
                "https://www.googleapis.com/oauth2/v2/userinfo",
                headers={"Authorization": f"Bearer {access_token}"},
                timeout=15,
            )
            guser = userinfo_resp.json()

        user = await _upsert_oauth_user(
            provider="google",
            provider_id=str(guser["id"]),
            email=guser.get("email"),
            display_name=guser.get("name"),
            username_hint=re.sub(r"[^a-z0-9]", "", (guser.get("email", "user").split("@")[0]).lower()) or "user",
        )
        jwt = encode_token(user, TOKEN_EXPIRE_MINUTES)
        return RedirectResponse(_oauth_redirect_url(jwt, next_url))
    except HTTPException:
        raise
    except Exception:
        return RedirectResponse(f"{BASE_URL}/?error=google_failed")


# ─────────────────────────────────────────────
# AI 友善的鬧鐘 CRUD API（供 AI tool use / MCP 使用）
# ─────────────────────────────────────────────

import uuid
import time as _time


class AlarmCreateRequest(BaseModel):
    title: str
    hour: int
    minute: int
    repeat_days: list[int] = []   # 1=Mon…7=Sun，空=單次
    vibrate_only: bool = False
    snooze_enabled: bool = True
    volume: int = 80              # 0–100


class AlarmUpdateRequest(BaseModel):
    title: str | None = None
    hour: int | None = None
    minute: int | None = None
    repeat_days: list[int] | None = None
    is_enabled: bool | None = None
    vibrate_only: bool | None = None
    snooze_enabled: bool | None = None
    volume: int | None = None


def _alarm_to_response(client_id: str, data: dict, updated_at: int) -> dict:
    return {
        "client_id": client_id,
        "title": data.get("title", ""),
        "hour": data.get("hour", 0),
        "minute": data.get("minute", 0),
        "is_enabled": data.get("isEnabled", True),
        "repeat_days": data.get("repeatDays", []),
        "vibrate_only": data.get("vibrateOnly", False),
        "snooze_enabled": data.get("snoozeEnabled", True),
        "volume": data.get("alarmVolume", 80),
        "updated_at": updated_at,
        "time_label": f"{data.get('hour',0):02d}:{data.get('minute',0):02d}",
    }


@app.get("/api/alarms", summary="列出所有鬧鐘", tags=["AI Alarm API"])
async def api_list_alarms(authorization: str = Header(None)):
    """取得目前使用者的所有已啟用鬧鐘列表。"""
    import json
    user_id = _require_auth(authorization)
    db = await get_db()
    try:
        async with db.execute(
            "SELECT client_id, data, updated_at FROM synced_alarms WHERE user_id=? AND is_deleted=0",
            (user_id,)
        ) as cur:
            rows = await cur.fetchall()
        return {"alarms": [
            _alarm_to_response(r["client_id"], json.loads(r["data"]), r["updated_at"])
            for r in rows
        ]}
    finally:
        await db.close()


@app.post("/api/alarms", summary="新增鬧鐘", tags=["AI Alarm API"])
async def api_create_alarm(req: AlarmCreateRequest, authorization: str = Header(None)):
    """
    新增一個鬧鐘。
    - repeat_days: 留空 = 單次鬧鐘；填入 [1,2,3,4,5] = 週一到週五重複
    - hour/minute: 24 小時制
    """
    import json
    user_id = _require_auth(authorization)
    client_id = str(uuid.uuid4())
    now = int(_time.time() * 1000)
    data = {
        "title": req.title,
        "hour": req.hour,
        "minute": req.minute,
        "isEnabled": True,
        "repeatDays": req.repeat_days,
        "vibrateOnly": req.vibrate_only,
        "snoozeEnabled": req.snooze_enabled,
        "alarmVolume": req.volume,
        "clientId": client_id,
        "updatedAt": now,
    }
    db = await get_db()
    try:
        await db.execute(
            "INSERT INTO synced_alarms (user_id, client_id, data, updated_at, is_deleted) VALUES (?,?,?,?,0)",
            (user_id, client_id, json.dumps(data, ensure_ascii=False), now)
        )
        await db.commit()
        return {"alarm": _alarm_to_response(client_id, data, now), "message": f"鬧鐘「{req.title}」已新增"}
    finally:
        await db.close()


@app.put("/api/alarms/{client_id}", summary="更新鬧鐘", tags=["AI Alarm API"])
async def api_update_alarm(client_id: str, req: AlarmUpdateRequest, authorization: str = Header(None)):
    """更新指定鬧鐘的任意欄位（只傳要改的欄位即可）。"""
    import json
    user_id = _require_auth(authorization)
    db = await get_db()
    try:
        async with db.execute(
            "SELECT data, updated_at FROM synced_alarms WHERE user_id=? AND client_id=? AND is_deleted=0",
            (user_id, client_id)
        ) as cur:
            row = await cur.fetchone()
        if not row:
            raise HTTPException(404, "Alarm not found")

        data = json.loads(row["data"])
        if req.title       is not None: data["title"]        = req.title
        if req.hour        is not None: data["hour"]         = req.hour
        if req.minute      is not None: data["minute"]       = req.minute
        if req.repeat_days is not None: data["repeatDays"]   = req.repeat_days
        if req.is_enabled  is not None: data["isEnabled"]    = req.is_enabled
        if req.vibrate_only is not None: data["vibrateOnly"] = req.vibrate_only
        if req.snooze_enabled is not None: data["snoozeEnabled"] = req.snooze_enabled
        if req.volume      is not None: data["alarmVolume"]  = req.volume

        now = int(_time.time() * 1000)
        data["updatedAt"] = now
        await db.execute(
            "UPDATE synced_alarms SET data=?, updated_at=? WHERE user_id=? AND client_id=?",
            (json.dumps(data, ensure_ascii=False), now, user_id, client_id)
        )
        await db.commit()
        return {"alarm": _alarm_to_response(client_id, data, now), "message": "鬧鐘已更新"}
    finally:
        await db.close()


@app.delete("/api/alarms/{client_id}", summary="刪除鬧鐘", tags=["AI Alarm API"])
async def api_delete_alarm(client_id: str, authorization: str = Header(None)):
    """刪除指定的鬧鐘。"""
    user_id = _require_auth(authorization)
    db = await get_db()
    try:
        async with db.execute(
            "SELECT id FROM synced_alarms WHERE user_id=? AND client_id=? AND is_deleted=0",
            (user_id, client_id)
        ) as cur:
            if not await cur.fetchone():
                raise HTTPException(404, "Alarm not found")
        now = int(_time.time() * 1000)
        await db.execute(
            "UPDATE synced_alarms SET is_deleted=1, updated_at=? WHERE user_id=? AND client_id=?",
            (now, user_id, client_id)
        )
        await db.commit()
        return {"message": "鬧鐘已刪除", "client_id": client_id}
    finally:
        await db.close()


@app.patch("/api/alarms/{client_id}/toggle", summary="開啟/關閉鬧鐘", tags=["AI Alarm API"])
async def api_toggle_alarm(client_id: str, authorization: str = Header(None)):
    """切換鬧鐘的啟用狀態。"""
    import json
    user_id = _require_auth(authorization)
    db = await get_db()
    try:
        async with db.execute(
            "SELECT data FROM synced_alarms WHERE user_id=? AND client_id=? AND is_deleted=0",
            (user_id, client_id)
        ) as cur:
            row = await cur.fetchone()
        if not row:
            raise HTTPException(404, "Alarm not found")
        data = json.loads(row["data"])
        data["isEnabled"] = not data.get("isEnabled", True)
        now = int(_time.time() * 1000)
        data["updatedAt"] = now
        await db.execute(
            "UPDATE synced_alarms SET data=?, updated_at=? WHERE user_id=? AND client_id=?",
            (json.dumps(data, ensure_ascii=False), now, user_id, client_id)
        )
        await db.commit()
        status = "已開啟" if data["isEnabled"] else "已關閉"
        return {"alarm": _alarm_to_response(client_id, data, now), "message": f"鬧鐘{status}"}
    finally:
        await db.close()


if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("PORT", 9000))
    uvicorn.run("main:app", host="0.0.0.0", port=port, reload=True)
