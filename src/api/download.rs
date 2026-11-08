//! Streaming file downloads and multipart uploads shared by several handlers.

use crate::api::error::{ApiError, ApiResult};
use axum::{
    body::Body,
    extract::Multipart,
    http::{header, HeaderValue},
    response::{IntoResponse, Response},
};
use std::path::{Path, PathBuf};
use tokio::io::AsyncWriteExt;

/// `Content-Disposition` with an ASCII-safe filename.
fn disposition(name: &str) -> HeaderValue {
    let safe: String = name
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || "._-".contains(c) {
                c
            } else {
                '_'
            }
        })
        .collect();
    HeaderValue::from_str(&format!("attachment; filename=\"{safe}\"")).unwrap_or(HeaderValue::from_static("attachment"))
}

/// Stream a file as an attachment.
pub async fn file_response(path: PathBuf, name: &str) -> ApiResult<Response> {
    let file = tokio::fs::File::open(&path)
        .await
        .map_err(|_| ApiError::NotFound("File"))?;
    open_file_response(file, name).await
}

/// Stream an already open file as an attachment, for one the panel opened safely itself.
pub async fn open_file_response(file: tokio::fs::File, name: &str) -> ApiResult<Response> {
    let len = file.metadata().await.map(|m| m.len()).ok();
    let stream = tokio_util::io::ReaderStream::new(file);
    let mut res = Body::from_stream(stream).into_response();
    let h = res.headers_mut();
    h.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/octet-stream"),
    );
    h.insert(header::CONTENT_DISPOSITION, disposition(name));
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    if let Some(l) = len {
        if let Ok(v) = HeaderValue::from_str(&l.to_string()) {
            h.insert(header::CONTENT_LENGTH, v);
        }
    }
    Ok(res)
}

/// A file received from a multipart upload, plus the other text fields.
pub struct Upload {
    pub file_name: String,
    pub temp_path: PathBuf,
    pub size: u64,
    /// What identifies the temp file the panel wrote, as its directory may be someone else's.
    pub written: (u64, u64),
    pub fields: std::collections::HashMap<String, String>,
    /// Held open until this is dropped, so that while it's in use, no other file can be given the
    /// same identity, even if the temp file's name is deleted.
    _held: Option<tokio::fs::File>,
}

impl Drop for Upload {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.temp_path);
    }
}

/// Stream the `file` part of a multipart request to a temp file in `dir`, enforcing `max` bytes.
pub async fn receive_upload(mut mp: Multipart, dir: &Path, max: u64) -> ApiResult<Upload> {
    tokio::fs::create_dir_all(dir).await.map_err(ApiError::internal)?;
    let mut fields = std::collections::HashMap::new();
    let mut upload: Option<Upload> = None;
    while let Some(mut field) = mp
        .next_field()
        .await
        .map_err(|e| ApiError::BadRequest(format!("Invalid upload: {e}")))?
    {
        let name = field.name().unwrap_or("").to_string();
        if name != "file" {
            let text = field.text().await.map_err(|e| ApiError::BadRequest(e.to_string()))?;
            if text.len() <= 4096 {
                fields.insert(name, text);
            }
            continue;
        }
        if upload.is_some() {
            return Err(ApiError::BadRequest("Upload one file at a time".into()));
        }
        let file_name = field
            .file_name()
            .map(|n| n.rsplit(['/', '\\']).next().unwrap_or(n).to_string())
            .unwrap_or_else(|| "upload".into());
        let temp_path = dir.join(format!(".upload-{}", crate::auth::random_password(16)));
        // Only root can read it until it's in place. The directory can belong to a site's user, so
        // a name that's already there is never reused and a link is never followed.
        let mut opts = tokio::fs::OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(unix)]
        opts.mode(0o600);
        let mut out = opts.open(&temp_path).await.map_err(ApiError::internal)?;
        let meta = out.metadata().await.map_err(ApiError::internal)?;
        let mut up = Upload {
            file_name,
            temp_path,
            size: 0,
            written: crate::fsutil::identity(&meta),
            fields: Default::default(),
            _held: None,
        };
        while let Some(chunk) = field
            .chunk()
            .await
            .map_err(|e| ApiError::BadRequest(format!("Upload interrupted: {e}")))?
        {
            up.size += chunk.len() as u64;
            if up.size > max {
                return Err(ApiError::BadRequest(format!(
                    "File is larger than {} MB",
                    max / 1024 / 1024
                )));
            }
            out.write_all(&chunk).await.map_err(ApiError::internal)?;
        }
        out.flush().await.map_err(ApiError::internal)?;
        up._held = Some(out);
        upload = Some(up);
    }
    let mut up = upload.ok_or_else(|| ApiError::BadRequest("No file was uploaded".into()))?;
    up.fields = fields;
    Ok(up)
}
