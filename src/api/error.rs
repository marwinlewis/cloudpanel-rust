use axum::{
    http::{header, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    Json,
};

/// Error type returned by every API handler. Internal details are logged, never sent to clients.
#[derive(Debug)]
pub enum ApiError {
    BadRequest(String),
    Unauthorized(String),
    Forbidden,
    NotFound(&'static str),
    Conflict(String),
    TooManyRequests(u64),
    Unprocessable(String),
    Internal(String),
}

pub type ApiResult<T> = Result<T, ApiError>;

impl ApiError {
    pub fn internal(e: impl std::fmt::Display) -> Self {
        ApiError::Internal(e.to_string())
    }
}

impl From<rusqlite::Error> for ApiError {
    fn from(e: rusqlite::Error) -> Self {
        ApiError::Internal(format!("database: {e}"))
    }
}

impl From<r2d2::Error> for ApiError {
    fn from(e: r2d2::Error) -> Self {
        ApiError::Internal(format!("db pool: {e}"))
    }
}

impl From<tokio::task::JoinError> for ApiError {
    fn from(e: tokio::task::JoinError) -> Self {
        ApiError::Internal(format!("task: {e}"))
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, message) = match self {
            ApiError::BadRequest(m) => (StatusCode::BAD_REQUEST, m),
            ApiError::Unauthorized(m) => (StatusCode::UNAUTHORIZED, m),
            ApiError::Forbidden => (StatusCode::FORBIDDEN, "You do not have permission to do that".into()),
            ApiError::NotFound(what) => (StatusCode::NOT_FOUND, format!("{what} not found")),
            ApiError::Conflict(m) => (StatusCode::CONFLICT, m),
            ApiError::Unprocessable(m) => (StatusCode::UNPROCESSABLE_ENTITY, m),
            ApiError::TooManyRequests(secs) => {
                let mut res = (
                    StatusCode::TOO_MANY_REQUESTS,
                    Json(serde_json::json!({
                        "error": format!("Too many failed attempts. Try again in {} minutes.", secs.div_ceil(60))
                    })),
                )
                    .into_response();
                if let Ok(v) = HeaderValue::from_str(&secs.to_string()) {
                    res.headers_mut().insert(header::RETRY_AFTER, v);
                }
                return res;
            }
            ApiError::Internal(detail) => {
                tracing::error!("internal error: {detail}");
                (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error".into())
            }
        };
        (status, Json(serde_json::json!({ "error": message }))).into_response()
    }
}
