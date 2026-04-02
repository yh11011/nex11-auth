import os
import aiosqlite

DB_PATH = os.environ.get("DB_PATH", "auth.db")

CREATE_SQL = """
PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS users (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    username       TEXT UNIQUE,
    email          TEXT UNIQUE,
    password_hash  TEXT NOT NULL DEFAULT '',
    display_name   TEXT,
    created_at     TEXT NOT NULL DEFAULT (datetime('now')),
    oauth_provider TEXT,
    oauth_id       TEXT,
    is_premium     INTEGER NOT NULL DEFAULT 0,
    CHECK (username IS NOT NULL OR email IS NOT NULL)
);

CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
CREATE INDEX IF NOT EXISTS idx_users_email    ON users(email);

-- 鬧鐘雲端同步表（每個使用者的鬧鐘，以 client_id 為跨裝置識別符）
CREATE TABLE IF NOT EXISTS synced_alarms (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    client_id  TEXT    NOT NULL,
    data       TEXT    NOT NULL DEFAULT '{}',
    updated_at INTEGER NOT NULL DEFAULT 0,
    is_deleted INTEGER NOT NULL DEFAULT 0,
    UNIQUE(user_id, client_id)
);

CREATE INDEX IF NOT EXISTS idx_synced_alarms_user ON synced_alarms(user_id);

-- AI 服務綁定表（儲存使用者的 API key，用於 BYOK 模式）
CREATE TABLE IF NOT EXISTS user_ai_keys (
    id                 INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id            INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    provider           TEXT    NOT NULL,  -- 'groq' | 'openai' | 'anthropic' | 'gemini'
    api_key_encrypted  TEXT    NOT NULL,  -- AES-256-GCM 加密後的 API key
    created_at         TEXT    NOT NULL DEFAULT (datetime('now')),
    updated_at         TEXT    NOT NULL DEFAULT (datetime('now')),
    UNIQUE(user_id, provider)
);

CREATE INDEX IF NOT EXISTS idx_user_ai_keys_user ON user_ai_keys(user_id);

-- OAuth 2.0 客戶端（Dynamic Client Registration）
CREATE TABLE IF NOT EXISTS oauth_clients (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    client_id           TEXT    NOT NULL UNIQUE,
    client_secret_hash  TEXT    NOT NULL,
    client_name         TEXT    NOT NULL DEFAULT '',
    redirect_uris       TEXT    NOT NULL DEFAULT '[]',  -- JSON array
    created_at          TEXT    NOT NULL DEFAULT (datetime('now'))
);

-- OAuth 2.0 授權碼（單次使用，10 分鐘有效）
CREATE TABLE IF NOT EXISTS oauth_codes (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    code_hash       TEXT    NOT NULL UNIQUE,
    client_id       TEXT    NOT NULL,
    user_id         INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    scope           TEXT    NOT NULL DEFAULT '',
    redirect_uri    TEXT    NOT NULL DEFAULT '',
    code_challenge  TEXT    NOT NULL DEFAULT '',
    expires_at      INTEGER NOT NULL,
    used            INTEGER NOT NULL DEFAULT 0
);

-- OAuth 2.0 存取 Token（SHA-256 hash 儲存，原始值只給使用者一次）
CREATE TABLE IF NOT EXISTS oauth_tokens (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    token_hash  TEXT    NOT NULL UNIQUE,
    client_id   TEXT    NOT NULL,
    user_id     INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    scope       TEXT    NOT NULL DEFAULT '',
    expires_at  INTEGER NOT NULL,
    revoked     INTEGER NOT NULL DEFAULT 0,
    created_at  TEXT    NOT NULL DEFAULT (datetime('now'))
);

-- 使用者資料夾（供網頁前端管理，Android App 透過 sync 取得）
CREATE TABLE IF NOT EXISTS user_folders (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name       TEXT    NOT NULL,
    emoji      TEXT    NOT NULL DEFAULT '📁',
    created_at TEXT    NOT NULL DEFAULT (datetime('now')),
    UNIQUE(user_id, name)
);

CREATE INDEX IF NOT EXISTS idx_oauth_codes_hash  ON oauth_codes(code_hash);
CREATE INDEX IF NOT EXISTS idx_oauth_tokens_hash ON oauth_tokens(token_hash);
CREATE INDEX IF NOT EXISTS idx_user_folders_user ON user_folders(user_id);
"""


async def get_db() -> aiosqlite.Connection:
    db = await aiosqlite.connect(DB_PATH)
    db.row_factory = aiosqlite.Row
    await db.execute("PRAGMA journal_mode = WAL")
    await db.execute("PRAGMA foreign_keys = ON")
    return db


async def init_db():
    async with aiosqlite.connect(DB_PATH) as db:
        await db.executescript(CREATE_SQL)
        # 遷移：為舊版 DB 補上欄位（若不存在）
        for col, definition in [
            ("oauth_provider", "TEXT"),
            ("oauth_id", "TEXT"),
            ("is_premium", "INTEGER NOT NULL DEFAULT 0"),
        ]:
            try:
                await db.execute(f"ALTER TABLE users ADD COLUMN {col} {definition}")
                await db.commit()
            except Exception:
                pass  # 欄位已存在

