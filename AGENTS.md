# NEX11 Auth — 專案工作守則

開工先讀同目錄的 `PROJECT_MAP.md`，依功能入口定位；共同合作方式、獨立判斷及交付規則由 `~/.codex/AGENTS.md` 管理。此檔只補充本專案規則。

## 特殊規則

- JWT、OAuth scope 及跨服務 API 變更先確認相容性；auth 是共享帳號來源，不能默默改變其他服務的 user id 語意。
- SQL 參數化；資料遷移保留帳號、OAuth 與鬧鐘資料。測試不能使用正式 auth.db 或寄送真實通知。
- keys/、auth.db、備份與環境密鑰不得提交。

## 驗證與交付

目前沒有 tests/ 自動測試套件；新增認證或狀態邏輯需補隔離回歸測試。現有唯讀檢查為 `/health`，不以正式註冊 API 當健康檢查。

目前 `nex11-auth.service` 使用本目錄 uvicorn main:app，loopback 615。更新後重啟此服務，檢查 https://login.nex11.me/health 及登入頁；共用端點也供 alarm.nex11.me 使用。
