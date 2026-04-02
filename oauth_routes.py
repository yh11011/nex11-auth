"""
OAuth 2.0 Authorization Server — /oauth/
Implements Authorization Code flow with PKCE (S256).
Supports Dynamic Client Registration (RFC 7591) for ChatGPT / Claude actions.
"""
import base64
import hashlib
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

router = APIRouter(prefix="/oauth", tags=["OAuth 2.0"])

VALID_SCOPES = {"alarm:read", "alarm:write"}


# ─── Crypto helpers ───────────────────────────────────────────────────────────

def _sha256_hex(val: str) -> str:
    return hashlib.sha256(val.encode()).hexdigest()


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _verify_pkce_s256(verifier: str, challenge: str) -> bool:
    """base64url(sha256(verifier)) must equal challenge."""
    return _b64url(hashlib.sha256(verifier.encode("ascii")).digest()) == challenge


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


class OAuthTokenRequest(BaseModel):
    grant_type: str
    code: str
    redirect_uri: str
    client_id: str
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
    secret_hash   = _sha256_hex(client_secret)

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
        "client_secret": client_secret,
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

    if redirect_uri not in client["redirect_uris"]:
        raise HTTPException(400, "redirect_uri not registered for this client")

    # Validate requested scopes
    requested = set(scope.split())
    if not requested.issubset(VALID_SCOPES):
        raise HTTPException(400, f"Invalid scope. Allowed: {' '.join(VALID_SCOPES)}")

    html = (Path(__file__).parent / "static" / "oauth-authorize.html").read_text(encoding="utf-8")
    # Server-side substitution so values are always correct even if JS params differ
    html = (html
        .replace("__CLIENT_ID__",             client_id)
        .replace("__CLIENT_NAME__",           client["client_name"])
        .replace("__REDIRECT_URI_ENCODED__",  urllib.parse.quote(redirect_uri, safe=""))
        .replace("__SCOPE__",                 scope)
        .replace("__STATE_ENCODED__",         urllib.parse.quote(state, safe=""))
        .replace("__CODE_CHALLENGE__",        code_challenge)
        .replace("__CODE_CHALLENGE_METHOD__", code_challenge_method)
    )
    return HTMLResponse(content=html)


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
    if decoded_redirect not in client["redirect_uris"]:
        raise HTTPException(400, "Invalid redirect_uri")

    # Generate single-use auth code (valid 10 minutes)
    raw_code  = secrets.token_urlsafe(32)
    code_hash = _sha256_hex(raw_code)
    expires   = int(time.time() * 1000) + 10 * 60 * 1000

    db = await get_db()
    try:
        await db.execute(
            "INSERT INTO oauth_codes "
            "(code_hash, client_id, user_id, scope, redirect_uri, code_challenge, expires_at, used) "
            "VALUES (?,?,?,?,?,?,?,0)",
            (code_hash, req.client_id, user_id, req.scope, decoded_redirect,
             req.code_challenge or "", expires)
        )
        await db.commit()
    finally:
        await db.close()

    decoded_state = urllib.parse.unquote(req.state)
    redirect_url = (
        decoded_redirect
        + "?code="  + urllib.parse.quote(raw_code, safe="")
        + "&state=" + urllib.parse.quote(decoded_state, safe="")
    )
    return {"redirect_url": redirect_url}


# ─── Token Endpoint ───────────────────────────────────────────────────────────

@router.post("/token", summary="用授權碼換取 access token")
async def oauth_token(req: OAuthTokenRequest, request: Request):
    """
    Exchanges a one-time auth code for a long-lived access token (90 days).
    Validates PKCE S256 if code_challenge was set during authorization.
    """
    ip = request.client.host
    allowed, retry = check_ip_rate(f"{ip}:oauth_token", 5)
    if not allowed:
        raise HTTPException(429, "Too many requests", headers={"Retry-After": str(retry)})

    if req.grant_type != "authorization_code":
        raise HTTPException(400, "unsupported_grant_type")

    code_hash = _sha256_hex(req.code)
    now_ms    = int(time.time() * 1000)

    db = await get_db()
    try:
        async with db.execute(
            "SELECT * FROM oauth_codes WHERE code_hash=? AND used=0 AND expires_at>?",
            (code_hash, now_ms)
        ) as cur:
            code_row = await cur.fetchone()

        if not code_row:
            raise HTTPException(400, "invalid_grant")

        # Validate client_id matches
        if code_row["client_id"] != req.client_id:
            raise HTTPException(400, "invalid_client")

        # Validate redirect_uri matches
        if code_row["redirect_uri"] != req.redirect_uri:
            raise HTTPException(400, "invalid_grant")

        # Verify PKCE if challenge was stored
        if code_row["code_challenge"]:
            if not req.code_verifier:
                raise HTTPException(400, "code_verifier required")
            if not _verify_pkce_s256(req.code_verifier, code_row["code_challenge"]):
                raise HTTPException(400, "invalid_grant")

        # Mark code as used immediately (single-use)
        await db.execute("UPDATE oauth_codes SET used=1 WHERE code_hash=?", (code_hash,))

        # Issue access token
        raw_token   = f"nxai_{secrets.token_urlsafe(32)}"
        token_hash  = _sha256_hex(raw_token)
        expires_at  = now_ms + 90 * 24 * 60 * 60 * 1000  # 90 days in ms

        await db.execute(
            "INSERT INTO oauth_tokens (token_hash, client_id, user_id, scope, expires_at, revoked) "
            "VALUES (?,?,?,?,?,0)",
            (token_hash, req.client_id, code_row["user_id"], code_row["scope"], expires_at)
        )
        await db.commit()

        return {
            "access_token": raw_token,
            "token_type":   "bearer",
            "expires_in":   90 * 24 * 60 * 60,   # seconds
            "scope":        code_row["scope"],
        }
    finally:
        await db.close()


# ─── Revoke Endpoint ──────────────────────────────────────────────────────────

@router.post("/revoke", summary="撤銷 access token")
async def oauth_revoke(req: OAuthRevokeRequest, request: Request):
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
        await db.commit()
    finally:
        await db.close()

    return {"revoked": True}
