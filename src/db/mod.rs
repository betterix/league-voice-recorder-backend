pub mod models;

use sqlx::sqlite::{
    SqliteConnectOptions, SqliteJournalMode, SqlitePool, SqlitePoolOptions, SqliteSynchronous,
};
use std::path::Path;
use std::str::FromStr;
use std::time::Duration;

pub type DbPool = SqlitePool;

pub async fn init_db(db_path: &Path) -> Result<DbPool, sqlx::Error> {
    if let Some(parent) = db_path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }

    let conn_str = format!("sqlite://{}", db_path.to_string_lossy());
    let options = SqliteConnectOptions::from_str(&conn_str)?
        .create_if_missing(true)
        .journal_mode(SqliteJournalMode::Wal)
        .synchronous(SqliteSynchronous::Normal)
        .foreign_keys(true)
        .busy_timeout(Duration::from_secs(30));

    let pool = SqlitePoolOptions::new()
        .max_connections(10)
        .acquire_timeout(Duration::from_secs(30))
        .connect_with(options)
        .await?;

    run_migrations(&pool).await?;

    Ok(pool)
}

pub async fn run_migrations(pool: &DbPool) -> Result<(), sqlx::Error> {
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS recordings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            game_id TEXT UNIQUE NOT NULL,
            filename TEXT NOT NULL,
            file_size INTEGER NOT NULL,
            duration REAL NOT NULL,
            bitrate INTEGER NOT NULL,
            sample_rate INTEGER NOT NULL,
            sha256 TEXT NOT NULL,
            team_tag TEXT,
            notes TEXT,
            match_date TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS ix_recordings_game_id_team_tag ON recordings (game_id, team_tag);
        CREATE INDEX IF NOT EXISTS ix_recordings_created_at ON recordings (created_at);

        CREATE TABLE IF NOT EXISTS banned_ips (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip TEXT UNIQUE NOT NULL,
            reason TEXT NOT NULL,
            violation_count INTEGER NOT NULL DEFAULT 1,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS ix_banned_ips_ip ON banned_ips (ip);

        CREATE TABLE IF NOT EXISTS ip_activity (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip TEXT NOT NULL,
            method TEXT NOT NULL,
            path TEXT NOT NULL,
            status_code INTEGER NOT NULL,
            category TEXT NOT NULL,
            details TEXT,
            created_at TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS ix_ip_activity_created_at_desc ON ip_activity (created_at DESC);
        CREATE INDEX IF NOT EXISTS ix_ip_activity_cat_created ON ip_activity (category, created_at);

        CREATE TABLE IF NOT EXISTS ip_intel (
            ip TEXT PRIMARY KEY NOT NULL,
            is_datacenter BOOLEAN NOT NULL DEFAULT 0,
            isp TEXT,
            org TEXT,
            as_info TEXT,
            country TEXT,
            created_at TEXT NOT NULL
        );
        "#,
    )
    .execute(pool)
    .await?;

    Ok(())
}
