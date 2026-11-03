use axum::{
    http::{header, HeaderName, HeaderValue, StatusCode, Uri},
    response::IntoResponse,
    Router,
};
use rust_embed::RustEmbed;
use tower_http::set_header::SetResponseHeaderLayer;

#[derive(RustEmbed)]
#[folder = "ui/"]
pub struct Asset;

const CSP: &str = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; \
                   connect-src 'self'; font-src 'self'; object-src 'none'; base-uri 'none'; \
                   form-action 'self'; frame-ancestors 'none'";

pub async fn static_handler(uri: Uri) -> impl IntoResponse {
    let path = uri.path().trim_start_matches('/');
    let path = if path.is_empty() { "index.html" } else { path };

    // Unknown paths without an extension are SPA routes; anything else is a real 404.
    let (path, content) = match Asset::get(path) {
        Some(c) => (path, c),
        None if !path.rsplit('/').next().unwrap_or("").contains('.') => match Asset::get("index.html") {
            Some(c) => ("index.html", c),
            None => return (StatusCode::NOT_FOUND, "Not found").into_response(),
        },
        None => return (StatusCode::NOT_FOUND, "Not found").into_response(),
    };

    let mime = mime_guess::from_path(path).first_or_octet_stream();
    (
        [
            (header::CONTENT_TYPE, mime.as_ref().to_string()),
            (header::CACHE_CONTROL, "no-cache".to_string()),
        ],
        content.data,
    )
        .into_response()
}

/// Browser security headers for every response.
pub fn with_security_headers(router: Router, tls: bool) -> Router {
    let mut headers: Vec<(HeaderName, &'static str)> = vec![
        (header::CONTENT_SECURITY_POLICY, CSP),
        (header::X_FRAME_OPTIONS, "DENY"),
        (header::X_CONTENT_TYPE_OPTIONS, "nosniff"),
        (header::REFERRER_POLICY, "no-referrer"),
        (
            HeaderName::from_static("permissions-policy"),
            "camera=(), microphone=(), geolocation=()",
        ),
        (HeaderName::from_static("cross-origin-opener-policy"), "same-origin"),
        (HeaderName::from_static("cross-origin-resource-policy"), "same-origin"),
    ];
    if tls {
        headers.push((header::STRICT_TRANSPORT_SECURITY, "max-age=31536000"));
    }
    headers.into_iter().fold(router, |r, (name, value)| {
        r.layer(SetResponseHeaderLayer::if_not_present(
            name,
            HeaderValue::from_static(value),
        ))
    })
}
