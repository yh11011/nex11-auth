# NEX11 Auth — 專案地圖

路徑相對於本檔目錄。先按功能讀第一站，只有涉及跨模組才擴大；程式與地圖不符時以程式為準並更新。

| 功能 | 第一站 | 需要時再看 | 驗證入口 |
| --- | --- | --- | --- |
| 登入、帳號及鬧鐘同步 | `main.py` | `database.py`、`jwt_utils.py` | 隔離資料測試及 /health |
| OAuth 授權及 Study 服務驗證 | `oauth_routes.py` | `main.py`、`mcp_remote.py` | tests/test_oauth_security.py；tests/test_study_oauth.py |
| V1 鬧鐘 API | `api_v1.py` | `main.py` | 驗證讀寫 scope |
| 帳號與 AI 設定頁 | `static/index.html` | `static/ai-setup.html`、`static/dashboard.html` | 瀏覽器登入及設定 |
| 遠端 MCP 與 OAuth metadata | `mcp_remote.py` | `oauth_routes.py`、`mcp_server.py`（舊本機入口） | `tests/test_ai_mcp.py`、`tests/test_oauth_security.py` |
| 公開 App 更新 metadata | `app_updates.py` | NexAlarm `scripts/release_metadata.py` 與 release workflow | `tests/test_app_updates.py` |
| 手機註冊、AI 指令與逐裝置回報 | `ai_delivery.py` | `database.py`、`static/mcp-connect.html` | 隔離資料與 mock FCM |

## 部署與交付入口

目前 `nex11-auth.service` 使用本目錄 uvicorn main:app，loopback 615。更新後重啟此服務，檢查 https://login.nex11.me/health 及登入頁；共用端點也供 alarm.nex11.me 使用。

## 最近更新

每輪修改後核對並新增一筆，最多 20 筆，最新在前；純討論與唯讀查詢不新增。

- 2026-10-03：OAuth 新增 Study resource 與獨立讀取／摘要權限、loopback 服務驗證；隔離鬧鐘權杖並保留其 Premium 限制。
- 2026-10-01：新增手機全鬧鐘排程回報、版本綁定的 MCP 庫存統計及 GitHub Beta 更新資訊端點；既有 OAuth／同步路徑不變。
- 2026-10-01：修正私人 MCP 建立階段的 OAuth 註冊回應（201、公開客戶端省略 secret）與未知網址的 404；端點路徑不變。
- 2026-10-01：新增遠端 MCP、OAuth discovery／refresh、裝置指令與回報；新增隔離測試與私人連接／欄位複製指南，保留舊版同步相容性。
- 2026-09-29：核對功能入口、驗證與部署方式，建立精簡導航並統一 Codex 工作規則。
