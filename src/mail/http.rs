//! The HTTP sending API, shaped like Resend's: `POST /emails`, `POST /emails/batch`,
//! `GET /emails/{id}`, authenticated with `Authorization: Bearer <api key>`.

use super::keys;
use super::message::{self, SendRequest};
use super::send::{Mailer, SendError, Source};
use super::store::{self, ApiKey};
use axum::extract::{DefaultBodyLimit, Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde_json::json;
use std::sync::Arc;

const MAX_BATCH: usize = 100;

pub struct ApiError(StatusCode, &'static str, String);

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let body = json!({ "statusCode": self.0.as_u16(), "name": self.1, "message": self.2 });
        (self.0, Json(body)).into_response()
    }
}

impl From<SendError> for ApiError {
    fn from(e: SendError) -> Self {
        let msg = e.to_string();
        match e {
            SendError::Invalid(_) => ApiError(StatusCode::UNPROCESSABLE_ENTITY, "validation_error", msg),
            SendError::Forbidden(_) => ApiError(StatusCode::FORBIDDEN, "invalid_from_address", msg),
            SendError::RateLimited(_) => ApiError(StatusCode::TOO_MANY_REQUESTS, "rate_limit_exceeded", msg),
            SendError::Internal(_) => ApiError(StatusCode::INTERNAL_SERVER_ERROR, "application_error", msg),
        }
    }
}

type ApiResult<T> = Result<T, ApiError>;

async fn blocking<T: Send + 'static>(f: impl FnOnce() -> T + Send + 'static) -> ApiResult<T> {
    tokio::task::spawn_blocking(f)
        .await
        .map_err(|e| ApiError(StatusCode::INTERNAL_SERVER_ERROR, "application_error", e.to_string()))
}

async fn authenticate(mailer: &Arc<Mailer>, headers: &HeaderMap) -> ApiResult<ApiKey> {
    let token = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .map(str::to_string)
        .ok_or_else(|| {
            ApiError(
                StatusCode::UNAUTHORIZED,
                "missing_api_key",
                "Missing API key in the Authorization header".into(),
            )
        })?;
    let m = mailer.clone();
    blocking(move || keys::authenticate(&m.conn(), &token))
        .await?
        .ok_or_else(|| ApiError(StatusCode::FORBIDDEN, "invalid_api_key", "API key is invalid".into()))
}

async fn send_one(mailer: &Arc<Mailer>, key: &ApiKey, req: SendRequest) -> ApiResult<String> {
    let built = message::build(&req, &mailer.config.hostname)
        .map_err(|m| ApiError(StatusCode::UNPROCESSABLE_ENTITY, "validation_error", m))?;
    let (m, k) = (mailer.clone(), key.clone());
    Ok(blocking(move || m.send(&k, Source::Api, &built.envelope_from, &built.recipients, built.raw)).await??)
}

async fn create_email(
    State(mailer): State<Arc<Mailer>>,
    headers: HeaderMap,
    Json(req): Json<SendRequest>,
) -> ApiResult<impl IntoResponse> {
    let key = authenticate(&mailer, &headers).await?;
    let id = send_one(&mailer, &key, req).await?;
    Ok(Json(json!({ "id": id })))
}

async fn create_batch(
    State(mailer): State<Arc<Mailer>>,
    headers: HeaderMap,
    Json(reqs): Json<Vec<SendRequest>>,
) -> ApiResult<impl IntoResponse> {
    let key = authenticate(&mailer, &headers).await?;
    if reqs.is_empty() || reqs.len() > MAX_BATCH {
        return Err(ApiError(
            StatusCode::UNPROCESSABLE_ENTITY,
            "validation_error",
            format!("Send between 1 and {MAX_BATCH} emails per batch"),
        ));
    }
    // Check every email before sending any.
    for (i, r) in reqs.iter().enumerate() {
        message::build(r, &mailer.config.hostname).map_err(|m| {
            ApiError(
                StatusCode::UNPROCESSABLE_ENTITY,
                "validation_error",
                format!("Email {i}: {m}"),
            )
        })?;
    }
    let mut ids = Vec::with_capacity(reqs.len());
    for r in reqs {
        match send_one(&mailer, &key, r).await {
            Ok(id) => ids.push(json!({ "id": id })),
            Err(ApiError(code, name, msg)) => {
                return Err(ApiError(
                    code,
                    name,
                    format!("{msg} (sent {} of the batch before this)", ids.len()),
                ))
            }
        }
    }
    Ok(Json(json!({ "data": ids })))
}

async fn get_email(
    State(mailer): State<Arc<Mailer>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> ApiResult<impl IntoResponse> {
    let key = authenticate(&mailer, &headers).await?;
    let m = mailer.clone();
    let (msg, events) = blocking(move || {
        let c = m.conn();
        let msg = store::get_message(&c, &id).ok().flatten();
        let events = msg
            .as_ref()
            .map(|x| store::events_for(&c, &x.id).unwrap_or_default())
            .unwrap_or_default();
        (msg, events)
    })
    .await?;
    let not_found = || ApiError(StatusCode::NOT_FOUND, "not_found", "Email not found".into());
    let msg = msg.ok_or_else(not_found)?;
    // A sending key sees its own emails; a full-access key sees all.
    if key.permission != "full" && msg.key_id != key.id {
        return Err(not_found());
    }
    Ok(Json(json!({
        "object": "email",
        "id": msg.id,
        "from": msg.from,
        "to": msg.to,
        "subject": msg.subject,
        "created_at": msg.created_at,
        "last_event": msg.status,
        "events": events,
    })))
}

async fn health() -> impl IntoResponse {
    Json(json!({ "ok": true }))
}

pub fn router(mailer: Arc<Mailer>) -> Router {
    Router::new()
        .route("/emails", post(create_email))
        .route("/emails/batch", post(create_batch))
        .route("/emails/:id", get(get_email))
        .route("/health", get(health))
        // Base64 attachments are a third larger than the message they make.
        .layer(DefaultBodyLimit::max(super::MAX_MESSAGE_BYTES / 3 * 4 + 64 * 1024))
        .with_state(mailer)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mail::send::tests::fixture;
    use axum::body::Body;
    use axum::http::Request;
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    async fn call(
        app: &Router,
        method: &str,
        uri: &str,
        key: Option<&str>,
        body: serde_json::Value,
    ) -> (StatusCode, serde_json::Value) {
        let mut req = Request::builder()
            .method(method)
            .uri(uri)
            .header("content-type", "application/json");
        if let Some(k) = key {
            req = req.header("authorization", format!("Bearer {k}"));
        }
        let resp = app
            .clone()
            .oneshot(req.body(Body::from(body.to_string())).unwrap())
            .await
            .unwrap();
        let status = resp.status();
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        (
            status,
            serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null),
        )
    }

    #[tokio::test]
    async fn send_and_read_back() {
        let (m, cap, _key, full, _d) = fixture();
        let app = router(Arc::new(m));
        let email =
            json!({"from": "Acme <hi@example.com>", "to": ["you@example.org"], "subject": "Hi", "text": "Hello"});
        let (s, body) = call(&app, "POST", "/emails", Some(&full), email.clone()).await;
        assert_eq!(s, StatusCode::OK, "{body}");
        let id = body["id"].as_str().unwrap().to_string();
        assert_eq!(cap.0.lock().unwrap().len(), 1);

        let (s, body) = call(&app, "GET", &format!("/emails/{id}"), Some(&full), json!(null)).await;
        assert_eq!(s, StatusCode::OK);
        assert_eq!(body["last_event"], "sent");
        assert_eq!(body["to"][0], "you@example.org");

        let (s, body) = call(
            &app,
            "POST",
            "/emails/batch",
            Some(&full),
            json!([email.clone(), email]),
        )
        .await;
        assert_eq!(s, StatusCode::OK, "{body}");
        assert_eq!(body["data"].as_array().unwrap().len(), 2);
    }

    #[tokio::test]
    async fn errors_look_like_resend() {
        let (m, cap, _key, full, _d) = fixture();
        let app = router(Arc::new(m));
        let ok = json!({"from": "hi@example.com", "to": "you@example.org", "subject": "Hi", "text": "x"});
        let (s, b) = call(&app, "POST", "/emails", None, ok.clone()).await;
        assert_eq!(s, StatusCode::UNAUTHORIZED);
        assert_eq!(b["name"], "missing_api_key");
        let (s, _) = call(&app, "POST", "/emails", Some("cp_wrong"), ok).await;
        assert_eq!(s, StatusCode::FORBIDDEN);
        let (s, b) = call(
            &app,
            "POST",
            "/emails",
            Some(&full),
            json!({"from": "x@gmail.com", "to": "a@b.org", "subject": "s", "text": "t"}),
        )
        .await;
        assert_eq!(s, StatusCode::FORBIDDEN);
        assert_eq!(b["name"], "invalid_from_address");
        let (s, b) = call(
            &app,
            "POST",
            "/emails",
            Some(&full),
            json!({"from": "hi@example.com", "to": [], "subject": "s", "text": "t"}),
        )
        .await;
        assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY);
        assert_eq!(b["statusCode"], 422);
        let (s, _) = call(&app, "GET", "/emails/nope", Some(&full), json!(null)).await;
        assert_eq!(s, StatusCode::NOT_FOUND);
        assert!(cap.0.lock().unwrap().is_empty());
    }
}
