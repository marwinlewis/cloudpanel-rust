//! Security tests against the real router. Each module covers one part of the threat model:
//! who may call what ([`route_matrix`]), proving who you are ([`auth`], [`session`]), browsers and
//! their cross-site rules ([`browser`]), reaching other sites' records ([`idor`]), hostile values
//! ([`input`]), and resource limits and what gets logged ([`limits`]).

mod auth;
mod browser;
mod idor;
mod input;
mod limits;
mod route_matrix;
mod session;

// Tests for findings that aren't fixed yet. They stay out of public commits until they are.
// RUSTFLAGS="--cfg sec_open" cargo test -- --ignored
#[cfg(sec_open)]
mod open {
    include!("open.rs");
}

use super::tests::Harness;
use crate::auth::jwt::Claims;
use crate::db::{self, NewSite};
use axum::{
    body::Body,
    extract::ConnectInfo,
    http::{header, HeaderMap, Request, StatusCode},
};
use http_body_util::BodyExt;
use serde_json::Value;
use std::net::SocketAddr;
use tower::ServiceExt;

/// The secret the harness signs tokens with.
pub(super) const SECRET: &[u8] = b"test-secret-test-secret-test-secret!!";

/// The user running the tests. Files are chowned to a site's user, and without root only your own
/// user will do.
pub(super) fn current_user() -> String {
    std::process::Command::new("id")
        .arg("-un")
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .filter(|u| !u.is_empty())
        .unwrap_or_else(|| "nobody".into())
}

pub(super) struct Response {
    pub status: StatusCode,
    pub headers: HeaderMap,
    pub bytes: Vec<u8>,
}

impl Response {
    pub fn json(&self) -> Value {
        serde_json::from_slice(&self.bytes).unwrap_or(Value::Null)
    }

    pub fn text(&self) -> String {
        String::from_utf8_lossy(&self.bytes).into_owned()
    }
}

/// One request, spelled out completely. The harness's `call` adds a CSRF header and a body type,
/// which is what several of these tests need to leave out.
pub(super) async fn send(h: &Harness, peer: &str, req: axum::http::request::Builder, body: Body) -> Response {
    let mut req: Request<Body> = req.body(body).unwrap();
    let addr: SocketAddr = format!("{peer}:5555")
        .parse()
        .or_else(|_| format!("[{peer}]:5555").parse())
        .unwrap();
    req.extensions_mut().insert(ConnectInfo(addr));
    let res = h.app.clone().oneshot(req).await.unwrap();
    let (status, headers) = (res.status(), res.headers().clone());
    let bytes = res.into_body().collect().await.unwrap().to_bytes().to_vec();
    Response { status, headers, bytes }
}

pub(super) fn json_body(v: &Value) -> Body {
    Body::from(v.to_string())
}

/// `method /api{path}` with a JSON body, as the UI sends it.
pub(super) fn api(method: &str, path: &str) -> axum::http::request::Builder {
    api_untyped(method, path).header(header::CONTENT_TYPE, "application/json")
}

/// The same without a body type, for the requests that send their own.
pub(super) fn api_untyped(method: &str, path: &str) -> axum::http::request::Builder {
    Request::builder()
        .method(method)
        .uri(format!("/api{path}"))
        .header(super::CSRF_HEADER, super::CSRF_VALUE)
}

pub(super) fn sign(claims: &Claims, secret: &[u8]) -> String {
    jsonwebtoken::encode(
        &jsonwebtoken::Header::new(jsonwebtoken::Algorithm::HS256),
        claims,
        &jsonwebtoken::EncodingKey::from_secret(secret),
    )
    .unwrap()
}

pub(super) fn user_id(h: &Harness, name: &str) -> i64 {
    let conn = h.pool.get().unwrap();
    db::find_user_by_username(&conn, name).unwrap().unwrap().id
}

pub(super) fn site_id(h: &Harness, domain: &str) -> i64 {
    let conn = h.pool.get().unwrap();
    db::list_sites(&conn)
        .unwrap()
        .into_iter()
        .find(|s| s.domain == domain)
        .unwrap()
        .id
}

pub(super) fn add_site(h: &Harness, domain: &str, site_type: &str, home: Option<&str>, user: &str) -> i64 {
    let conn = h.pool.get().unwrap();
    db::create_site(
        &conn,
        &NewSite {
            domain,
            site_type,
            target_port: (site_type != "static").then_some(3000),
            document_root: None,
            system_user: user,
            include_www: false,
            www_redirect: false,
            home_dir: home,
            app_command: None,
            app_manager: "systemd",
            php_version: None,
        },
    )
    .unwrap()
}

/// A site with a real home directory, owned by the user running the tests, which `manager` looks
/// after. Returns its id and home. It lives in the harness's temp directory.
pub(super) fn managed_site_with_home(h: &Harness, domain: &str) -> (i64, std::path::PathBuf) {
    let home = h._dir.path().join("home").join(domain);
    std::fs::create_dir_all(home.join("htdocs").join(domain)).unwrap();
    std::fs::create_dir_all(home.join("databases")).unwrap();
    let id = add_site(h, domain, "static", Some(&home.to_string_lossy()), &current_user());
    let conn = h.pool.get().unwrap();
    db::grant_site(&conn, user_id(h, "manager"), id).unwrap();
    (id, home)
}
