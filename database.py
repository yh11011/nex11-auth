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
        # 遷移：為舊版 DB 補上 OAuth 欄位（若不存在）
        for col, definition in [("oauth_provider", "TEXT"), ("oauth_id", "TEXT")]:
            try:
                await db.execute(f"ALTER TABLE users ADD COLUMN {col} {definition}")
                await db.commit()
            except Exception:
                pass  # 欄位已存在

