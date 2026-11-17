use chrono::Utc;
use serde::{Deserialize, Serialize};
use sqlx::FromRow;

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct Recording {
    pub id: i64,
    pub game_id: String,
    pub filename: String,
    pub file_size: i64,
    pub duration: f64,
    pub bitrate: i64,
    pub sample_rate: i64,
    pub sha256: String,
    pub team_tag: Option<String>,
    pub notes: Option<String>,
    pub match_date: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecordingMetadataResponse {
    pub game_id: String,
    pub filename: String,
    pub file_size: i64,
    pub duration: f64,
    pub bitrate: i64,
    pub sample_rate: i64,
    pub upload_timestamp: String,
    pub team_tag: Option<String>,
    pub notes: Option<String>,
    pub match_date: Option<String>,
    pub sha256: String,
}

impl From<Recording> for RecordingMetadataResponse {
    fn from(r: Recording) -> Self {
        Self {
            game_id: r.game_id,
            filename: r.filename,
            file_size: r.file_size,
            duration: r.duration,
            bitrate: r.bitrate,
            sample_rate: r.sample_rate,
            upload_timestamp: r.created_at,
            team_tag: r.team_tag,
            notes: r.notes,
            match_date: r.match_date,
            sha256: r.sha256,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct BannedIP {
    pub id: i64,
    pub ip: String,
    pub reason: String,
    pub violation_count: i64,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct IPActivity {
    pub id: i64,
    pub ip: String,
    pub method: String,
    pub path: String,
    pub status_code: i64,
    pub category: String,
    pub details: Option<String>,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct IPIntelRecord {
    pub ip: String,
    pub is_datacenter: bool,
    pub isp: Option<String>,
    pub org: Option<String>,
    pub as_info: Option<String>,
    pub country: Option<String>,
    pub created_at: String,
}

pub fn now_iso() -> String {
    Utc::now().to_rfc3339()
}
