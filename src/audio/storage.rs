use axum::body::Body;
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use futures_util::StreamExt;
use regex::Regex;
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use std::sync::LazyLock;
use subtle::ConstantTimeEq;
use tokio::fs::File;
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt, SeekFrom};
use tokio_util::io::ReaderStream;
use uuid::Uuid;

use super::mp3::{AudioInfo, parse_mp3_file};

static GAME_ID_REGEX: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[a-zA-Z0-9_-]{1,64}$").unwrap());

pub const CHUNK_SIZE: usize = 64 * 1024; // 64 KB

#[derive(Debug, thiserror::Error)]
pub enum StorageError {
    #[error("Game ID cannot be empty")]
    EmptyGameId,
    #[error("Invalid Game ID: Directory traversal characters are forbidden")]
    DirectoryTraversal,
    #[error(
        "Invalid Game ID format: Allowed characters are alphanumeric, underscores, and hyphens (1-64 chars)"
    )]
    InvalidFormat,
    #[error("Security violation: Path escapes configured storage directory")]
    EscapesStorage,
    #[error("Recording for Game ID '{0}' already exists")]
    AlreadyExists(String),
    #[error("Uploaded file is empty")]
    EmptyFile,
    #[error("Upload exceeds maximum allowable limit of {0} MB")]
    PayloadTooLarge(usize),
    #[error("SHA-256 checksum mismatch (calculated: {0})")]
    ChecksumMismatch(String),
    #[error("Recording '{0}' not found on storage")]
    NotFound(String),
    #[error("Audio validation failed: {0}")]
    AudioValidation(String),
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}

impl IntoResponse for StorageError {
    fn into_response(self) -> Response {
        let (status, detail) = match &self {
            StorageError::EmptyGameId
            | StorageError::DirectoryTraversal
            | StorageError::InvalidFormat
            | StorageError::EscapesStorage
            | StorageError::EmptyFile
            | StorageError::ChecksumMismatch(_)
            | StorageError::AudioValidation(_) => (StatusCode::BAD_REQUEST, self.to_string()),
            StorageError::AlreadyExists(_) => (StatusCode::CONFLICT, self.to_string()),
            StorageError::PayloadTooLarge(_) => (StatusCode::PAYLOAD_TOO_LARGE, self.to_string()),
            StorageError::NotFound(_) => (StatusCode::NOT_FOUND, self.to_string()),
            StorageError::Io(e) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Storage IO error: {e}"),
            ),
        };

        let body = serde_json::json!({ "detail": detail });
        (status, axum::Json(body)).into_response()
    }
}

pub fn validate_game_id(game_id: &str) -> Result<String, StorageError> {
    let clean_id = game_id.trim();
    if clean_id.is_empty() {
        return Err(StorageError::EmptyGameId);
    }
    if clean_id.contains("..")
        || clean_id.contains('/')
        || clean_id.contains('\\')
        || clean_id.contains('\0')
    {
        return Err(StorageError::DirectoryTraversal);
    }
    if !GAME_ID_REGEX.is_match(clean_id) {
        return Err(StorageError::InvalidFormat);
    }
    Ok(clean_id.to_string())
}

pub fn get_recording_path(game_id: &str, storage_dir: &Path) -> Result<PathBuf, StorageError> {
    let clean_id = validate_game_id(game_id)?;
    let base = storage_dir
        .canonicalize()
        .unwrap_or_else(|_| storage_dir.to_path_buf());
    let target = base.join(format!("{clean_id}.mp3"));
    Ok(target)
}

#[derive(Debug, Clone)]
pub struct ProcessedUpload {
    pub audio_info: AudioInfo,
    pub sha256: String,
}

pub async fn stream_save_upload<S, B, E>(
    mut stream: S,
    game_id: &str,
    expected_sha256: Option<&str>,
    storage_dir: &Path,
    max_upload_bytes: usize,
    max_upload_mb: usize,
) -> Result<ProcessedUpload, StorageError>
where
    S: futures_util::Stream<Item = Result<B, E>> + Unpin,
    B: bytes::Buf,
    E: std::error::Error + Send + Sync + 'static,
{
    let clean_id = validate_game_id(game_id)?;
    let target_path = get_recording_path(&clean_id, storage_dir)?;

    if target_path.exists() {
        return Err(StorageError::AlreadyExists(clean_id));
    }

    let temp_name = format!(".tmp_{}_{}.mp3", clean_id, Uuid::new_v4().simple());
    let temp_path = storage_dir.join(&temp_name);

    let mut temp_file = File::create(&temp_path).await?;
    let mut hasher = Sha256::new();
    let mut total_bytes = 0usize;

    let write_result: Result<(), StorageError> = async {
        while let Some(chunk_res) = stream.next().await {
            let chunk = chunk_res.map_err(|e| StorageError::AudioValidation(e.to_string()))?;
            let slice = chunk.chunk();
            if !slice.is_empty() {
                total_bytes += slice.len();
                if total_bytes > max_upload_bytes {
                    return Err(StorageError::PayloadTooLarge(max_upload_mb));
                }
                hasher.update(slice);
                temp_file.write_all(slice).await?;
            }
        }
        temp_file.flush().await?;
        Ok(())
    }
    .await;

    if let Err(e) = write_result {
        let _ = tokio::fs::remove_file(&temp_path).await;
        return Err(e);
    }

    if total_bytes == 0 {
        let _ = tokio::fs::remove_file(&temp_path).await;
        return Err(StorageError::EmptyFile);
    }

    let actual_sha256 = hex::encode(hasher.finalize());

    if let Some(expected) = expected_sha256 {
        let clean_expected = expected.trim().to_lowercase();
        if clean_expected
            .as_bytes()
            .ct_eq(actual_sha256.as_bytes())
            .unwrap_u8()
            != 1
        {
            let _ = tokio::fs::remove_file(&temp_path).await;
            return Err(StorageError::ChecksumMismatch(actual_sha256));
        }
    }

    // Mutagen/MPEG frame validation
    let temp_path_clone = temp_path.clone();
    let audio_info =
        match tokio::task::spawn_blocking(move || parse_mp3_file(&temp_path_clone)).await {
            Ok(Ok(info)) => info,
            Ok(Err(e)) => {
                let _ = tokio::fs::remove_file(&temp_path).await;
                return Err(StorageError::AudioValidation(e.to_string()));
            }
            Err(join_err) => {
                let _ = tokio::fs::remove_file(&temp_path).await;
                return Err(StorageError::AudioValidation(join_err.to_string()));
            }
        };

    // Atomic rename
    tokio::fs::rename(&temp_path, &target_path).await?;

    Ok(ProcessedUpload {
        audio_info,
        sha256: actual_sha256,
    })
}

pub fn parse_range_header(range_header: &str, file_size: u64) -> Option<(u64, u64)> {
    if !range_header.starts_with("bytes=") {
        return None;
    }
    let spec = &range_header[6..].trim();
    if spec.contains(',') {
        return None;
    }

    let parts: Vec<&str> = spec.split('-').collect();
    if parts.len() != 2 {
        return None;
    }

    let start_str = parts[0].trim();
    let end_str = parts[1].trim();

    if !start_str.is_empty() && !end_str.is_empty() {
        let start = start_str.parse::<u64>().ok()?;
        let mut end = end_str.parse::<u64>().ok()?;
        if start > end || start >= file_size {
            return None;
        }
        if end >= file_size {
            end = file_size - 1;
        }
        Some((start, end))
    } else if !start_str.is_empty() && end_str.is_empty() {
        let start = start_str.parse::<u64>().ok()?;
        if start >= file_size {
            return None;
        }
        Some((start, file_size - 1))
    } else if start_str.is_empty() && !end_str.is_empty() {
        let suffix_len = end_str.parse::<u64>().ok()?;
        if suffix_len == 0 {
            return None;
        }
        let start = file_size.saturating_sub(suffix_len);
        Some((start, file_size - 1))
    } else {
        None
    }
}

pub async fn build_range_download_response(
    game_id: &str,
    range_header: Option<&str>,
    storage_dir: &Path,
    inline: bool,
) -> Result<Response, StorageError> {
    let clean_id = validate_game_id(game_id)?;
    let target_path = get_recording_path(&clean_id, storage_dir)?;

    if !target_path.exists() {
        return Err(StorageError::NotFound(clean_id));
    }

    let metadata = tokio::fs::metadata(&target_path).await?;
    let file_size = metadata.len();
    let filename = format!("{clean_id}.mp3");
    let disposition_type = if inline { "inline" } else { "attachment" };
    let content_disposition = format!("{disposition_type}; filename=\"{filename}\"");

    let mut headers = HeaderMap::new();
    headers.insert(header::ACCEPT_RANGES, "bytes".parse().unwrap());
    headers.insert(
        header::CONTENT_DISPOSITION,
        content_disposition.parse().unwrap(),
    );
    headers.insert(
        header::CACHE_CONTROL,
        "private, no-cache, no-transform".parse().unwrap(),
    );
    headers.insert(header::CONTENT_TYPE, "audio/mpeg".parse().unwrap());

    let mut file = File::open(&target_path).await?;

    if let Some(range_str) = range_header {
        match parse_range_header(range_str, file_size) {
            Some((start, end)) => {
                let length = end - start + 1;
                file.seek(SeekFrom::Start(start)).await?;
                let limited_file = file.take(length);
                let stream = ReaderStream::with_capacity(limited_file, CHUNK_SIZE);
                let body = Body::from_stream(stream);

                headers.insert(
                    header::CONTENT_RANGE,
                    format!("bytes {start}-{end}/{file_size}").parse().unwrap(),
                );
                headers.insert(header::CONTENT_LENGTH, length.to_string().parse().unwrap());

                let mut response = Response::new(body);
                *response.status_mut() = StatusCode::PARTIAL_CONTENT;
                *response.headers_mut() = headers;
                return Ok(response);
            }
            None => {
                let mut response = Response::new(Body::empty());
                *response.status_mut() = StatusCode::RANGE_NOT_SATISFIABLE;
                headers.insert(
                    header::CONTENT_RANGE,
                    format!("bytes */{file_size}").parse().unwrap(),
                );
                *response.headers_mut() = headers;
                return Ok(response);
            }
        }
    }

    headers.insert(
        header::CONTENT_LENGTH,
        file_size.to_string().parse().unwrap(),
    );
    let stream = ReaderStream::with_capacity(file, CHUNK_SIZE);
    let body = Body::from_stream(stream);

    let mut response = Response::new(body);
    *response.status_mut() = StatusCode::OK;
    *response.headers_mut() = headers;
    Ok(response)
}

pub async fn delete_recording_file(game_id: &str, storage_dir: &Path) -> bool {
    if let Ok(path) = get_recording_path(game_id, storage_dir)
        && path.exists()
    {
        return tokio::fs::remove_file(path).await.is_ok();
    }
    false
}
