# NEX11 Auth — 專案地圖

路徑相對於本檔目錄。先按功能讀第一站，只有涉及跨模組才擴大；程式與地圖不符時以程式為準並更新。

| 功能 | 第一站 | 需要時再看 | 驗證入口 |
| --- | --- | --- | --- |
| 登入、帳號及鬧鐘同步 | `main.py` | `database.py`、`jwt_utils.py` | 隔離資料測試及 /health |
| OAuth 授權 | `oauth_routes.py` | `main.py` | 授權、scope 與錯誤分支 |
| V1 鬧鐘 API | `api_v1.py` | `main.py` | 驗證讀寫 scope |
| 帳號與 AI 設定頁 | `static/index.html` | `static/ai-setup.html`、`static/dashboard.html` | 瀏覽器登入及設定 |
| MCP 入口 | `mcp_server.py` | `api_v1.py` | 協定及權限驗證 |

## 部署與交付入口

目前 `nex11-auth.service` 使用本目錄 uvicorn main:app，loopback 615。更新後重啟此服務，檢查 https://login.nex11.me/health 及登入頁；共用端點也供 alarm.nex11.me 使用。

## 最近更新

每輪修改後核對並新增一筆，最多 20 筆，最新在前；純討論與唯讀查詢不新增。

- 2026-09-29：核對功能入口、驗證與部署方式，建立精簡導航並統一 Codex 工作規則。
