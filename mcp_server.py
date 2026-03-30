#!/usr/bin/env python3
"""
NexAlarm MCP Server
讓 Claude（或任何支援 MCP 的 AI）透過工具管理 NexAlarm 鬧鐘。

使用方式：
  pip install mcp httpx
  NEXALARM_TOKEN=your_jwt_token python3 mcp_server.py

Claude Desktop 設定（~/.claude/claude_desktop_config.json）：
  {
    "mcpServers": {
      "nexalarm": {
        "command": "python3",
        "args": ["/path/to/mcp_server.py"],
        "env": {
          "NEXALARM_TOKEN": "your_jwt_token",
          "NEXALARM_API": "https://login.nex11.me"
        }
      }
    }
  }
"""

import os
import sys
import json
import asyncio
import httpx
from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp import types

API_BASE = os.environ.get("NEXALARM_API", "https://login.nex11.me")
TOKEN    = os.environ.get("NEXALARM_TOKEN", "")

server = Server("nexalarm")


def _headers():
    return {"Authorization": f"Bearer {TOKEN}", "Content-Type": "application/json"}


async def _get(path: str) -> dict:
    async with httpx.AsyncClient() as c:
        r = await c.get(f"{API_BASE}{path}", headers=_headers(), timeout=15)
        r.raise_for_status()
        return r.json()


async def _post(path: str, body: dict) -> dict:
    async with httpx.AsyncClient() as c:
        r = await c.post(f"{API_BASE}{path}", json=body, headers=_headers(), timeout=15)
        r.raise_for_status()
        return r.json()


async def _put(path: str, body: dict) -> dict:
    async with httpx.AsyncClient() as c:
        r = await c.put(f"{API_BASE}{path}", json=body, headers=_headers(), timeout=15)
        r.raise_for_status()
        return r.json()


async def _delete(path: str) -> dict:
    async with httpx.AsyncClient() as c:
        r = await c.delete(f"{API_BASE}{path}", headers=_headers(), timeout=15)
        r.raise_for_status()
        return r.json()


async def _patch(path: str) -> dict:
    async with httpx.AsyncClient() as c:
        r = await c.patch(f"{API_BASE}{path}", headers=_headers(), timeout=15)
        r.raise_for_status()
        return r.json()


# ── Tool definitions ──────────────────────────────────────────

@server.list_tools()
async def list_tools() -> list[types.Tool]:
    return [
        types.Tool(
            name="list_alarms",
            description="列出使用者的所有鬧鐘，包含時間、標題、是否啟用等資訊。",
            inputSchema={"type": "object", "properties": {}, "required": []},
        ),
        types.Tool(
            name="create_alarm",
            description="新增一個鬧鐘。",
            inputSchema={
                "type": "object",
                "properties": {
                    "title":        {"type": "string",  "description": "鬧鐘名稱，例如：起床、吃藥"},
                    "hour":         {"type": "integer", "description": "小時（0–23，24小時制）"},
                    "minute":       {"type": "integer", "description": "分鐘（0–59）"},
                    "repeat_days":  {"type": "array",   "items": {"type": "integer"},
                                     "description": "重複的星期（1=週一, 2=週二, …, 7=週日）。留空為單次鬧鐘。"},
                    "vibrate_only": {"type": "boolean", "description": "僅震動不響鈴，預設 false"},
                    "snooze_enabled": {"type": "boolean", "description": "允許貪睡，預設 true"},
                    "volume":       {"type": "integer", "description": "音量 0–100，預設 80"},
                },
                "required": ["title", "hour", "minute"],
            },
        ),
        types.Tool(
            name="update_alarm",
            description="更新指定鬧鐘的欄位（只需傳入要修改的欄位）。",
            inputSchema={
                "type": "object",
                "properties": {
                    "client_id":    {"type": "string",  "description": "要更新的鬧鐘 client_id（從 list_alarms 取得）"},
                    "title":        {"type": "string"},
                    "hour":         {"type": "integer"},
                    "minute":       {"type": "integer"},
                    "repeat_days":  {"type": "array",   "items": {"type": "integer"}},
                    "is_enabled":   {"type": "boolean", "description": "true=開啟, false=關閉"},
                    "vibrate_only": {"type": "boolean"},
                    "snooze_enabled": {"type": "boolean"},
                    "volume":       {"type": "integer"},
                },
                "required": ["client_id"],
            },
        ),
        types.Tool(
            name="delete_alarm",
            description="刪除指定的鬧鐘。",
            inputSchema={
                "type": "object",
                "properties": {
                    "client_id": {"type": "string", "description": "要刪除的鬧鐘 client_id（從 list_alarms 取得）"},
                },
                "required": ["client_id"],
            },
        ),
        types.Tool(
            name="toggle_alarm",
            description="切換指定鬧鐘的開啟/關閉狀態。",
            inputSchema={
                "type": "object",
                "properties": {
                    "client_id": {"type": "string", "description": "鬧鐘的 client_id"},
                },
                "required": ["client_id"],
            },
        ),
    ]


# ── Tool execution ────────────────────────────────────────────

@server.call_tool()
async def call_tool(name: str, arguments: dict) -> list[types.TextContent]:
    try:
        if name == "list_alarms":
            result = await _get("/api/alarms")
            alarms = result.get("alarms", [])
            if not alarms:
                text = "目前沒有任何鬧鐘。"
            else:
                lines = ["📋 你的鬧鐘列表：\n"]
                for a in alarms:
                    status = "✅" if a["is_enabled"] else "⏸️"
                    repeat = f"重複：{a['repeat_days']}" if a["repeat_days"] else "單次"
                    lines.append(
                        f"{status} {a['time_label']} - {a['title']} ({repeat})\n"
                        f"   client_id: {a['client_id']}"
                    )
                text = "\n".join(lines)

        elif name == "create_alarm":
            result = await _post("/api/alarms", arguments)
            text = f"✅ {result['message']}\n時間：{result['alarm']['time_label']}，client_id：{result['alarm']['client_id']}"

        elif name == "update_alarm":
            cid = arguments.pop("client_id")
            result = await _put(f"/api/alarms/{cid}", arguments)
            text = f"✅ {result['message']}"

        elif name == "delete_alarm":
            result = await _delete(f"/api/alarms/{arguments['client_id']}")
            text = f"🗑️ {result['message']}"

        elif name == "toggle_alarm":
            result = await _patch(f"/api/alarms/{arguments['client_id']}/toggle")
            text = f"🔔 {result['message']}"

        else:
            text = f"未知工具：{name}"

    except httpx.HTTPStatusError as e:
        text = f"API 錯誤 {e.response.status_code}：{e.response.text}"
    except Exception as e:
        text = f"錯誤：{e}"

    return [types.TextContent(type="text", text=text)]


async def main():
    if not TOKEN:
        print("❌ 請設定環境變數 NEXALARM_TOKEN", file=sys.stderr)
        print("   export NEXALARM_TOKEN=your_jwt_token", file=sys.stderr)
        sys.exit(1)
    async with stdio_server() as (read_stream, write_stream):
        await server.run(read_stream, write_stream, server.create_initialization_options())


if __name__ == "__main__":
    asyncio.run(main())
