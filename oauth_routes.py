"""
OAuth 2.0 Authorization Server — /oauth/
Implements Authorization Code flow with PKCE (S256).
Supports Dynamic Client Registration (RFC 7591) for ChatGPT / Claude actions.
"""
import base64
import hashlib
import html
import hmac
import re
import json
import secrets
import time
import urllib.parse
from pathlib import Path

from fastapi import APIRouter, Header, HTTPException, Query, Request
from fastapi.responses import HTMLResponse
from pydantic import BaseModel

from database import get_db
from jwt_utils import decode_token
from rate_limiter import check_ip_rate
from ai_delivery import BASE, RESOURCE, premium

router = APIRouter(prefix="/oauth", tags=["OAuth 2.0"])

VALID_SCOPES = {"alarm:read", "alarm:write"}


# ─── Crypto helpers ───────────────────────────────────────────────────────────

def _sha256_hex(val: str) -> str:
    return hashlib.sha256(val.encode()).hexdigest()


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _verify_pkce_s256(verifier: str, challenge: str) -> bool:
    """base64url(sha256(verifier)) must equal challenge."""
    return bool(re.fullmatch(r"[A-Za-z0-9._~-]{43,128}", verifier)) and hmac.compare_digest(_b64url(hashlib.sha256(verifier.encode("ascii")).digest()), challenge)


# ─── Client helpers ───────────────────────────────────────────────────────────

async def _get_client(client_id: str) -> dict | None:
    db = await get_db()
    try:
        async with db.execute(
            "SELECT client_id, client_secret_hash, client_name, redirect_uris "
            "FROM oauth_clients WHERE client_id=?",
            (client_id,)
        ) as cur:
            row = await cur.fetchone()
        if not row:
            return None
        return {
            "client_id":          row["client_id"],
            "client_secret_hash": row["client_secret_hash"],
            "client_name":        row["client_name"],
            "redirect_uris":      json.loads(row["redirect_uris"]),
        }
    finally:
        await db.close()


async def _user_id_from_jwt(token: str) -> int:
    """Decode JWT and return user_id. Raises 401 on failure."""
    try:
        payload = decode_token(token)
        return int(payload["sub"])
    except Exception:
        raise HTTPException(401, "Unauthorized")


# ─── Request/Response models ──────────────────────────────────────────────────

class OAuthRegisterRequest(BaseModel):
    redirect_uris: list[str]
    client_name: str = "Unknown"
    token_endpoint_auth_method: str = "none"


class OAuthTokenRequest(BaseModel):
    grant_type: str
    code: str = ""
    redirect_uri: str = ""
    client_id: str
    client_secret: str | None = None
    refresh_token: str | None = None
    resource: str = ""
    code_verifier: str | None = None


class OAuthRevokeRequest(BaseModel):
    token: str


class OAuthApproveRequest(BaseModel):
    client_id: str
    redirect_uri: str       # URL-encoded
    scope: str
    state: str              # URL-encoded
    code_challenge: str | None = None
    code_challenge_method: str | None = None
    resource: str = ""
    token: str              # user's JWT


# ─── Dynamic Client Registration ─────────────────────────────────────────────

@router.post("/register", summary="動態客戶端註冊 (RFC 7591)")
async def oauth_register(req: OAuthRegisterRequest, request: Request):
    """
    Registers a new OAuth client. Required by OpenAI for Custom GPT Actions.
    Returns client_id and client_secret (shown only once).
    """
    ip = request.client.host
    allowed, retry = check_ip_rate(f"{ip}:oauth_register", 5)
    if not allowed:
        raise HTTPException(429, "Too many requests", headers={"Retry-After": str(retry)})

    if not req.redirect_uris:
        raise HTTPException(400, "redirect_uris is required")
    if len(req.redirect_uris) > 10:
        raise HTTPException(400, "Too many redirect_uris")

    client_id     = f"nxai_client_{secrets.token_urlsafe(16)}"
    client_secret = f"nxai_secret_{secrets.token_urlsafe(32)}"
    if req.token_endpoint_auth_method not in {"none", "client_secret_post"}:
        raise HTTPException(400,"Unsupported token endpoint authentication")
    for uri in req.redirect_uris:
        u = urllib.parse.urlsplit(uri)
        if u.fragment or u.username or not u.hostname or not (u.scheme=="https" or (u.scheme=="http" and u.hostname in {"127.0.0.1","localhost","::1"})):
            raise HTTPException(400,"Invalid redirect URI")
    secret_hash = _sha256_hex(client_secret) if req.token_endpoint_auth_method != "none" else ""

    db = await get_db()
    try:
        await db.execute(
            "INSERT INTO oauth_clients (client_id, client_secret_hash, client_name, redirect_uris) "
            "VALUES (?,?,?,?)",
            (client_id, secret_hash, req.client_name[:100], json.dumps(req.redirect_uris))
        )
        await db.commit()
    finally:
        await db.close()

    return {
        "client_id":     client_id,
        "client_secret": client_secret if secret_hash else None,
        "token_endpoint_auth_method": req.token_endpoint_auth_method,
        "grant_types": ["authorization_code", "refresh_token"],
        "response_types": ["code"],
        "client_name":   req.client_name,
        "redirect_uris": req.redirect_uris,
    }


# ─── Authorization Endpoint ───────────────────────────────────────────────────

@router.get("/authorize", response_class=HTMLResponse, summary="顯示授權同意頁面")
async def oauth_authorize_page(
    request: Request,
    client_id: str = Query(...),
    redirect_uri: str = Query(...),
    scope: str = Query(default="alarm:read alarm:write"),
    state: str = Query(default=""),
    code_challenge: str = Query(default=""),
    code_challenge_method: str = Query(default="S256"),
    response_type: str = Query(default="code"),
    resource: str = Query(default=""),
):
    """Renders the user consent page. User logs in (if needed) and approves/denies."""
    ip = request.client.host
    allowed, retry = check_ip_rate(f"{ip}:oauth_authorize", 20)
    if not allowed:
        raise HTTPException(429, "Too many requests", headers={"Retry-After": str(retry)})

    if response_type != "code":
        raise HTTPException(400, "Only response_type=code is supported")

    client = await _get_client(client_id)
    if not client:
        raise HTTPException(400, "Invalid client_id")

    if not redirect_matches(redirect_uri, client["redirect_uris"]):
        raise HTTPException(400, "redirect_uri not registered for this client")

    # Validate requested scopes
    requested = set(scope.split())
    if not requested.issubset(VALID_SCOPES):
        raise HTTPException(400, f"Invalid scope. Allowed: {' '.join(VALID_SCOPES)}")

    validate_authorization(scope, code_challenge, code_challenge_method, resource)
    page = (Path(__file__).parent / "static" / "oauth-authorize.html").read_text(encoding="utf-8")
    # Server-side substitution so values are always correct even if JS params differ
    page = (page
        .replace("__CLIENT_ID__",             urllib.parse.quote(client_id, safe=""))
        .replace("__CLIENT_NAME_HTML__", html.escape(client["client_name"]))
        .replace("__CLIENT_NAME__", html.escape(client["client_name"], quote=True))
        .replace("__REDIRECT_URI_ENCODED__",  urllib.parse.quote(redirect_uri, safe=""))
        .replace("__SCOPE__",                 " ".join(sorted(requested)))
        .replace("__STATE_ENCODED__",         urllib.parse.quote(state, safe=""))
        .replace("__CODE_CHALLENGE__",        code_challenge)
        .replace("__CODE_CHALLENGE_METHOD__", code_challenge_method)
        .replace("__RESOURCE__", urllib.parse.quote(resource, safe=""))
    )
    return HTMLResponse(content=page)


@router.post("/authorize", summary="確認授權（同意頁面呼叫）")
async def oauth_authorize_confirm(req: OAuthApproveRequest, request: Request):
    """
    Called by the consent page JavaScript when the user clicks Allow.
    Validates the JWT, generates a single-use auth code, and returns the redirect URL.
    """
    ip = request.client.host
    allowed, retry = check_ip_rate(f"{ip}:oauth_authorize", 20)
    if not allowed:
        raise HTTPException(429, "Too many requests", headers={"Retry-After": str(retry)})

    user_id = await _user_id_from_jwt(req.token)

    client = await _get_client(req.client_id)
    if not client:
        raise HTTPException(400, "Invalid client_id")

    decoded_redirect = urllib.parse.unquote(req.redirect_uri)
    if not redirect_matches(decoded_redirect, client["redirect_uris"]):
        raise HTTPException(400, "Invalid redirect_uri")

    validate_authorization(req.scope, req.code_challenge or "", req.code_challenge_method or "", req.resource)
    if req.resource:
        await premium(user_id)
    # Generate single-use auth code (valid 10 minutes)
    raw_code  = secrets.token_urlsafe(32)
    code_hash = _sha256_hex(raw_code)
    expires   = int(time.time() * 1000) + 10 * 60 * 1000

    db = await get_db()
    try:
        await db.execute(
            "INSERT INTO oauth_codes "
            "(code_hash, client_id, user_id, scope, redirect_uri, code_challenge, expires_at, used, resource) "
            "VALUES (?,?,?,?,?,?,?,0,?)",
            (code_hash, req.client_id, user_id, req.scope, decoded_redirect,
             req.code_challenge or "", expires, req.resource)
        )
        await db.commit()
    finally:
        await db.close()

    decoded_state = urllib.parse.unquote(req.state)
    params = {"code": raw_code, "state": decoded_state}
    if req.resource:
        params["iss"] = BASE
    redirect_url = decoded_redirect + ("&" if "?" in decoded_redirect else "?") + urllib.parse.urlencode(params)
    return {"redirect_url": redirect_url}


# ─── Token Endpoint ───────────────────────────────────────────────────────────

@router.post("/token", summary="OAuth token exchange")
async def oauth_token(request: Request):
    ip = request.client.host if request.client else "unknown"
    allowed, retry = check_ip_rate(f"{ip}:oauth_token", 30)
    if not allowed:
        raise HTTPException(429, "Too many requests", headers={"Retry-After":str(retry)})
    if "application/json" in request.headers.get("content-type", ""):
        body = await request.json()  # backwards-compatible legacy clients
    else:
        body = dict(await request.form())
    req = OAuthTokenRequest.model_validate(body)
    client = await _get_client(req.client_id)
    if not client:
        raise HTTPException(400, "invalid_client")
    if client["client_secret_hash"] and not hmac.compare_digest(client["client_secret_hash"], _sha256_hex(req.client_secret or "")):
        raise HTTPException(400, "invalid_client")
    db = await get_db()
    now = int(time.time()*1000)
    try:
        await db.execute("BEGIN IMMEDIATE")
        if req.grant_type == "authorization_code":
            row = await (await db.execute("SELECT * FROM oauth_codes WHERE code_hash=? AND used=0 AND expires_at>?",(_sha256_hex(req.code),now))).fetchone()
            if not row or row["client_id"] != req.client_id or row["redirect_uri"] != req.redirect_uri or row["resource"] != req.resource:
                raise HTTPException(400,"invalid_grant")
            if row["code_challenge"] and (not req.code_verifier or not _verify_pkce_s256(req.code_verifier,row["code_challenge"])):
                raise HTTPException(400,"invalid_grant")
            await db.execute("UPDATE oauth_codes SET used=1 WHERE code_hash=?",(_sha256_hex(req.code),))
        elif req.grant_type == "refresh_token":
            row = await (await db.execute("SELECT * FROM oauth_refresh_tokens WHERE token_hash=? AND revoked=0 AND expires_at>?",(_sha256_hex(req.refresh_token or ""),now))).fetchone()
            if not row or row["client_id"] != req.client_id or row["resource"] != req.resource:
                raise HTTPException(400,"invalid_grant")
            await db.execute("UPDATE oauth_refresh_tokens SET revoked=1 WHERE token_hash=?",(_sha256_hex(req.refresh_token),))
            await db.execute("UPDATE oauth_tokens SET revoked=1 WHERE token_hash=?",(row["access_hash"],))
        else:
            raise HTTPException(400,"unsupported_grant_type")
        if req.resource:
            user = await (await db.execute("SELECT is_premium FROM users WHERE id=?",(row["user_id"],))).fetchone()
            if not user or not user["is_premium"]:
                raise HTTPException(403,"Premium required for AI integration")
        raw = "nxai_" + secrets.token_urlsafe(32)
        ttl = 3600 if req.resource else 90*24*3600
        await db.execute("INSERT INTO oauth_tokens(token_hash,client_id,user_id,scope,expires_at,revoked,resource) VALUES (?,?,?,?,?,0,?)",(_sha256_hex(raw),req.client_id,row["user_id"],row["scope"],now+ttl*1000,req.resource))
        result = {"access_token":raw,"token_type":"Bearer","expires_in":ttl,"scope":row["scope"]}
        if req.resource:
            refresh = "nxrefresh_"+secrets.token_urlsafe(32)
            await db.execute("INSERT INTO oauth_refresh_tokens VALUES (?,?,?,?,?,?,?,0)",(_sha256_hex(refresh),_sha256_hex(raw),req.client_id,row["user_id"],row["scope"],req.resource,now+30*24*3600*1000))
            result["refresh_token"] = refresh
        await db.commit()
        from fastapi.responses import JSONResponse
        return JSONResponse(result,headers={"Cache-Control":"no-store","Pragma":"no-cache"})
    finally:
        await db.close()


# ─── Revoke Endpoint ──────────────────────────────────────────────────────────

@router.post("/revoke", summary="撤銷 access token")
async def oauth_revoke(request: Request):
    body = await request.json() if "application/json" in request.headers.get("content-type", "") else dict(await request.form())
    req = OAuthRevokeRequest.model_validate(body)
    """
    Revokes an access token. Safe to call even if token is already revoked.
    Always returns 200 (RFC 7009 §2.2).
    """
    if not req.token:
        raise HTTPException(400, "token is required")

    token_hash = _sha256_hex(req.token)
    db = await get_db()
    try:
        await db.execute(
            "UPDATE oauth_tokens SET revoked=1 WHERE token_hash=?", (token_hash,)
        )
        await db.execute("UPDATE oauth_refresh_tokens SET revoked=1 WHERE token_hash=? OR access_hash=?",(token_hash,token_hash))
        await db.execute("UPDATE oauth_tokens SET revoked=1 WHERE token_hash IN (SELECT access_hash FROM oauth_refresh_tokens WHERE token_hash=?)",(token_hash,))
        await db.commit()
    finally:
        await db.close()

    return {"revoked": True}


def validate_authorization(scope, challenge, method, resource):
    if not set(scope.split()).issubset(VALID_SCOPES) or not scope.strip():
        raise HTTPException(400,"Invalid scope")
    if resource and resource != RESOURCE:
        raise HTTPException(400,"invalid_target")
    if resource and (method != "S256" or not re.fullmatch(r"[A-Za-z0-9_-]{43}",challenge)):
        raise HTTPException(400,"PKCE S256 required")
    if challenge and (method != "S256" or not re.fullmatch(r"[A-Za-z0-9_-]{43}",challenge)):
        raise HTTPException(400,"Invalid PKCE challenge")


def redirect_matches(uri, registered):
    if uri in registered:
        return True
    target = urllib.parse.urlsplit(uri)
    if target.scheme != "http" or target.hostname not in {"127.0.0.1","::1"}:
        return False
    for value in registered:
        item = urllib.parse.urlsplit(value)
        if (item.scheme,item.hostname,item.path,item.query,item.fragment)==(target.scheme,target.hostname,target.path,target.query,target.fragment):
            return True  # native loopback client may choose an ephemeral port
    return False
