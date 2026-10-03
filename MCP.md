# NexAlarm remote MCP

Endpoint: `https://login.nex11.me/mcp`. Public connection guide: `/mcp-connect`.

`mcp_remote.py` uses the official MCP SDK over stateless Streamable HTTP. OAuth discovery identifies the canonical login origin and resource; browser authorization uses PKCE S256, form token exchange, one-hour resource-bound access tokens, rotating refresh tokens and revocation. Existing JSON exchange remains compatible for legacy clients. Premium entitlement and scopes are checked at each operation. Device registration/receipts require the Android login JWT, not an AI access token.

`ai_delivery.py` adds account-scoped device registrations, immutable operation snapshots and per-device receipts. Mutations are serialized with SQLite transactions, deduplicated by a per-account idempotency key, and preserve unspecified fields. Superseded operations never become current delivery success. Data is fetched through authenticated API calls; FCM contains only a synchronization hint.

Android schema 9 supports a nullable `scheduledDate` and `device_local` policy. `main.py`'s sync endpoint accepts `capabilities:2`; old clients never receive dated records and cannot remove dates by uploading old models. The new Kotlin app applies operations through Room and `AlarmScheduler`, and reports exact/fallback/cancelled/failed results. All snapshot devices must confirm exact scheduling or cancellation for `complete:true`; zero devices is not success.

## Deployment and credentials

Install `requirements.txt` in the existing service virtualenv. The existing service's lifespan adds the new tables and nullable/default OAuth resource columns. These are additive migrations; keep an encrypted/access-restricted database backup before restart.

For FCM, configure `GOOGLE_APPLICATION_CREDENTIALS` outside Git with a service account for the Android Firebase project and permission to send messages, and enable FCM HTTP v1. No Firebase server credentials were available at implementation time. Missing credentials and offline phones leave operations pending until foreground/periodic fetch. A push is not proof of scheduling.

The resource's OAuth grants are separate from existing REST tokens. Disconnect via `/api/v1/ai/connections/revoke`; logout unregisters a phone and the Android app persists offline deregistration requests in its encrypted authentication storage. Downgrades prevent new commands without cancelling previously scheduled alarms.

## Validation

```sh
python -m pytest tests -q
```

Tests isolate the database and mock FCM. They exercise real SDK initialization/tool discovery/calls, OAuth form/PKCE/replay/refresh/revoke, entitlement/scope/account isolation, concurrent idempotency, immutable snapshots, fallback, cancellation, superseded receipts and legacy date protection. Use `/health` and anonymous MCP/discovery requests for live smoke tests, never production account mutations.

Android/AI-host end-to-end verification requires actual phones, FCM credentials and interactive OAuth consent in Codex/ChatGPT. Details and private-connection instructions live in the NexAlarm repository under `docs/mcp/`.

## All-alarm scheduling evidence and updates

Authenticated phones upload `/api/v1/devices/{id}/schedule-status` in batches of at most 20 records. The server validates account/device ownership, current cloud version and scheduling/cancellation consistency. `list_alarms` preserves existing fields and adds per-alarm device statuses, registered-device/active-cloud/enabled counts, per-device exact/fallback/unconfirmed counts and report times. No report, outdated versions or expired triggers are not scheduling confirmation. These attest Android scheduler submission, not future ringing. Registration records installed app version for diagnosis.

`app_updates.py` exposes the public `/api/v1/app/releases/latest?channel=beta` independently of Premium. It caches GitHub metadata for five minutes and excludes drafts, the historical Debug release, absent metadata, invalid digest/package/version/size/source. Network failure returns 503 rather than claiming no update. No signed update metadata is published currently. Original signing-key recovery and Firebase sending credentials remain prerequisites for real compatible upgrades/push verification.

## Study resource

Study 使用 `https://nex11.me/study/mcp`，權限為 `study:read` 與 `study:summary:write`。與鬧鐘 resource 分開，不要求 NexAlarm Premium；既有鬧鐘 Premium、scope 及舊版空 resource 權杖相容性保留。

`/oauth/introspect-study` 僅接受 loopback 來源加上服務證明 JWT（audience `study-introspection`、30 秒有效、綁定待驗權杖 SHA256）。服務證明使用既有 JWT 環境金鑰，不對瀏覽器或 AI 提供。回應限 active、使用者 ID、scope、resource、到期時間；不回傳憑證或帳號私人欄位。權杖更新／撤銷即時反映於 Study 下一次請求。

授權頁依 resource 顯示 Study 或 NexAlarm 及對應權限。Study 的工具與網站說明見 Study 專案的 `MCP.md`。驗證使用 `tests/test_study_oauth.py` 的隔離資料庫，不使用正式帳號或 auth.db。
