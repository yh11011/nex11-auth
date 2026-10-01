"""Remote MCP transport; authentication stays scoped to each HTTP request."""
import hashlib
import json
import time
from datetime import datetime, timezone
from zoneinfo import ZoneInfo
from typing import Annotated, Any

from fastapi import APIRouter, HTTPException
from mcp.server.fastmcp import FastMCP
from mcp.server.transport_security import TransportSecuritySettings
from mcp.types import ToolAnnotations
from pydantic import Field
from starlette.responses import JSONResponse

from ai_delivery import BASE, RESOURCE, identity, mutate, wait_status, status
from database import get_db

router = APIRouter()

@router.get("/.well-known/oauth-protected-resource")
@router.get("/.well-known/oauth-protected-resource/mcp")
async def resource_metadata():
    return {"resource":RESOURCE,"authorization_servers":[BASE],"scopes_supported":["alarm:read","alarm:write"]}

@router.get("/.well-known/oauth-authorization-server")
async def authorization_metadata():
    return {"issuer":BASE,"authorization_endpoint":BASE+"/oauth/authorize",
            "token_endpoint":BASE+"/oauth/token","registration_endpoint":BASE+"/oauth/register",
            "revocation_endpoint":BASE+"/oauth/revoke","response_types_supported":["code"],
            "grant_types_supported":["authorization_code","refresh_token"],
            "token_endpoint_auth_methods_supported":["none","client_secret_post"],
            "code_challenge_methods_supported":["S256"],"scopes_supported":["alarm:read","alarm:write"],
            "authorization_response_iss_parameter_supported":True}

mcp = FastMCP("NexAlarm", stateless_http=True, json_response=True,
    instructions="Premium alarm manager. Times and dates use EACH phone's local timezone. Ask for missing dates/times; never claim a phone is scheduled without its receipt. Reuse the same idempotency_key for retries. If complete=false report the device statuses and use get_delivery_status later. Do not request account passwords in chat.",
    transport_security=TransportSecuritySettings(enable_dns_rebinding_protection=True,
        allowed_hosts=["login.nex11.me","login.nex11.me:*","127.0.0.1:*","localhost:*","testserver"],
        allowed_origins=["https://login.nex11.me","https://chatgpt.com"]))

def tool_options(scope, write=False, delete=False):
    return {"structured_output":True,"annotations":ToolAnnotations(readOnlyHint=not write,destructiveHint=delete,idempotentHint=True,openWorldHint=False),
            "meta":{"securitySchemes":[{"type":"oauth2","scopes":[scope]}]}}

async def uid(scope):
    return await identity(mcp.get_context().request_context.request.headers.get("authorization"), scope)

@mcp.tool(**tool_options("alarm:read"))
async def list_alarms() -> dict[str, Any]:
    """List alarms with complete client IDs, single dates, and repeat weekdays."""
    user_id = await uid("alarm:read")
    db = await get_db()
    try:
        rows = await (await db.execute("SELECT client_id,data,updated_at FROM synced_alarms WHERE user_id=? AND is_deleted=0 ORDER BY updated_at DESC",(user_id,))).fetchall()
        devices = await (await db.execute("SELECT name,timezone FROM ai_devices WHERE user_id=? AND active=1",(user_id,))).fetchall()
        clocks = []
        for device in devices:
            try:
                clocks.append({"name":device["name"],"timezone":device["timezone"],"local_time":datetime.now(ZoneInfo(device["timezone"])).isoformat()})
            except (ValueError, KeyError):
                clocks.append({"name":device["name"],"timezone":device["timezone"]})
        return {"alarms":[{"client_id":r["client_id"],"data":json.loads(r["data"]),"version":r["updated_at"]} for r in rows], "devices":clocks,"server_time":datetime.now(timezone.utc).isoformat()}
    finally:
        await db.close()

@mcp.tool(**tool_options("alarm:write",write=True))
async def create_alarm(hour: Annotated[int,Field(ge=0,le=23)], minute: Annotated[int,Field(ge=0,le=59)],
                       idempotency_key: Annotated[str,Field(min_length=1,max_length=100)], title: str="",
                       date: str | None=None, repeat_days: list[int] | None=None,
                       vibrate_only: bool=False, snooze_enabled: bool=True) -> dict[str, Any]:
    """Create on all registered phones. date=YYYY-MM-DD OR repeat_days=1..7 (Mon..Sun); neither means next occurrence. Wait up to 20 seconds for receipts. Pending is not success."""
    user_id = await uid("alarm:write")
    op = await mutate(user_id,"create",{"hour":hour,"minute":minute,"title":title,"date":date,
        "repeat_days":repeat_days or [],"vibrate_only":vibrate_only,"snooze_enabled":snooze_enabled},idempotency_key=idempotency_key)
    return await wait_status(user_id,op)

@mcp.tool(**tool_options("alarm:write",write=True))
async def update_alarm(client_id: str, changes: dict, idempotency_key: Annotated[str,Field(min_length=1,max_length=100)]) -> dict[str, Any]:
    """Partially update title/hour/minute/date/repeat_days/is_enabled/vibrate_only/snooze_enabled/volume. Preserve unspecified fields. Use date:null to clear a date before enabling repeats."""
    user_id = await uid("alarm:write")
    op = await mutate(user_id,"update",changes,client_id,idempotency_key)
    return await wait_status(user_id,op)

@mcp.tool(**tool_options("alarm:write",write=True,delete=True))
async def delete_alarm(client_id: str, idempotency_key: Annotated[str,Field(min_length=1,max_length=100)]) -> dict[str, Any]:
    """Delete a specific alarm; return cancellation receipts from each phone."""
    user_id = await uid("alarm:write")
    op = await mutate(user_id,"delete",{},client_id,idempotency_key)
    return await wait_status(user_id,op)

@mcp.tool(**tool_options("alarm:read"))
async def get_delivery_status(operation_id: str) -> dict[str, Any]:
    """Check whether every target phone scheduled/cancelled an operation; fallback is not exact success."""
    return await status(await uid("alarm:read"),operation_id)

class AuthenticatedMCP:
    def __init__(self):
        self.app = mcp.streamable_http_app()

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope,receive,send)
        # This catch-all mount must not challenge unrelated discovery or asset URLs.
        if scope.get("path") not in {"/mcp", "/mcp/"}:
            return await JSONResponse({"detail":"Not Found"}, status_code=404)(scope,receive,send)
        headers = dict(scope["headers"])
        auth = headers.get(b"authorization",b"").decode()
        db = await get_db()
        try:
            token = auth[7:] if auth.startswith("Bearer ") else ""
            row = await (await db.execute("SELECT user_id,scope FROM oauth_tokens WHERE token_hash=? AND resource=? AND revoked=0 AND expires_at>?",(hashlib.sha256(token.encode()).hexdigest(),RESOURCE,int(time.time()*1000)))).fetchone()
        finally:
            await db.close()
        if not row:
            return await JSONResponse({"error":"invalid_token"},status_code=401,
                headers={"WWW-Authenticate":f'Bearer resource_metadata="{BASE}/.well-known/oauth-protected-resource", scope="alarm:read alarm:write"'})(scope,receive,send)
        try:
            await identity(auth,"alarm:read")
        except HTTPException as exc:
            return await JSONResponse({"detail":exc.detail},status_code=exc.status_code)(scope,receive,send)
        await self.app(scope,receive,send)

remote_app = AuthenticatedMCP()
