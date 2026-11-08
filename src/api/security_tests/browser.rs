//! What a browser is told, and what a hostile page can make one do.

use super::*;
use crate::web;
use serde_json::json;

fn post_logout_all() -> axum::http::request::Builder {
    axum::http::Request::builder()
        .method("POST")
        .uri("https://panel.example.com:8443/api/auth/logout-all")
        .header(header::HOST, "panel.example.com:8443")
}

/// Whatever the request carries, the session must still work afterwards.
async fn refused(h: &Harness, req: axum::http::request::Builder, why: &str) {
    let cookie = h.login("admin").await;
    let r = send(h, "127.0.0.1", req.header(header::COOKIE, &cookie), Body::empty()).await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST, "{why}");
    assert_eq!(
        h.call("GET", "/auth/me", Some(&cookie), None, false).await.0,
        StatusCode::OK,
        "{why}: the request took effect"
    );
}

#[tokio::test]
async fn cross_site_requests_are_refused_however_they_are_dressed() {
    let h = super::super::tests::harness();
    refused(&h, post_logout_all(), "no CSRF header").await;
    refused(
        &h,
        post_logout_all().header(crate::api::CSRF_HEADER, "XMLHttpRequest"),
        "the usual value of that header isn't this panel's",
    )
    .await;
    let with_csrf = || post_logout_all().header(crate::api::CSRF_HEADER, crate::api::CSRF_VALUE);
    for site in ["cross-site", "same-site"] {
        refused(&h, with_csrf().header("sec-fetch-site", site), site).await;
    }
    for origin in [
        "https://evil.example.com",
        "https://panel.example.com.evil.com:8443",
        "https://panel.example.com:9999",
        "null",
        "panel.example.com:8443",
    ] {
        refused(&h, with_csrf().header(header::ORIGIN, origin), origin).await;
    }
}

/// The body types a form can send without a preflight.
#[tokio::test]
async fn a_form_post_cannot_stand_in_for_json() {
    let h = super::super::tests::harness();
    for kind in ["text/plain", "application/x-www-form-urlencoded", "multipart/form-data"] {
        let r = send(
            &h,
            "127.0.0.1",
            api_untyped("POST", "/auth/login").header(header::CONTENT_TYPE, kind),
            json_body(&json!({"username": "admin", "password": "admin-password-1"})),
        )
        .await;
        assert_eq!(r.status, StatusCode::UNSUPPORTED_MEDIA_TYPE, "{kind}");
    }
}

#[tokio::test]
async fn other_sites_are_never_invited_to_read_the_api() {
    let h = super::super::tests::harness();
    let preflight = send(
        &h,
        "127.0.0.1",
        axum::http::Request::builder()
            .method("OPTIONS")
            .uri("/api/auth/me")
            .header(header::ORIGIN, "https://evil.example.com")
            .header("access-control-request-method", "GET")
            .header("access-control-request-headers", "x-requested-with"),
        Body::empty(),
    )
    .await;
    let plain = send(
        &h,
        "127.0.0.1",
        api("GET", "/auth/me").header(header::ORIGIN, "https://evil.example.com"),
        Body::empty(),
    )
    .await;
    for r in [preflight, plain] {
        let cors: Vec<_> = r
            .headers
            .keys()
            .filter(|k| k.as_str().starts_with("access-control-"))
            .collect();
        assert!(cors.is_empty(), "{cors:?}");
    }
}

fn with_headers(h: &Harness, tls: bool) -> axum::Router {
    web::with_security_headers(h.app.clone(), tls)
}

async fn through(app: axum::Router, path: &str) -> axum::http::Response<Body> {
    let mut req = axum::http::Request::builder().uri(path).body(Body::empty()).unwrap();
    req.extensions_mut()
        .insert(ConnectInfo::<SocketAddr>("127.0.0.1:5555".parse().unwrap()));
    app.oneshot(req).await.unwrap()
}

#[tokio::test]
async fn every_response_carries_the_browser_protections() {
    let h = super::super::tests::harness();
    for path in ["/", "/api/auth/me", "/api/no-such-thing", "/no-such-file.js"] {
        let r = through(with_headers(&h, true), path).await;
        let get = |n: &str| r.headers().get(n).map(|v| v.to_str().unwrap().to_string());
        let csp = get("content-security-policy").unwrap_or_default();
        for need in [
            "default-src 'self'",
            "script-src 'self'",
            "object-src 'none'",
            "base-uri 'none'",
            "frame-ancestors 'none'",
            "form-action 'self'",
        ] {
            assert!(csp.contains(need), "{path}: {need} not in {csp}");
        }
        for allowed_nowhere in ["unsafe-inline", "unsafe-eval", "*", "http:"] {
            assert!(!csp.contains(allowed_nowhere), "{path}: {csp}");
        }
        assert_eq!(get("x-frame-options").as_deref(), Some("DENY"), "{path}");
        assert_eq!(get("x-content-type-options").as_deref(), Some("nosniff"), "{path}");
        assert_eq!(get("referrer-policy").as_deref(), Some("no-referrer"), "{path}");
        assert_eq!(
            get("cross-origin-resource-policy").as_deref(),
            Some("same-origin"),
            "{path}"
        );
        assert_eq!(
            get("cross-origin-opener-policy").as_deref(),
            Some("same-origin"),
            "{path}"
        );
        assert!(get("strict-transport-security").is_some(), "{path}");
    }
}

/// HSTS over plain HTTP would lock people out of a panel that has no certificate yet.
#[tokio::test]
async fn hsts_is_only_sent_with_tls() {
    let h = super::super::tests::harness();
    let r = through(with_headers(&h, false), "/").await;
    assert!(r.headers().get("strict-transport-security").is_none());
}

#[tokio::test]
async fn api_answers_are_never_cached() {
    let h = super::super::tests::harness();
    for path in ["/auth/me", "/sites", "/no-such-thing"] {
        let r = send(&h, "127.0.0.1", api("GET", path), Body::empty()).await;
        assert_eq!(
            r.headers.get(header::CACHE_CONTROL).unwrap().to_str().unwrap(),
            "no-store",
            "{path}"
        );
    }
}

/// The UI builds the page with `textContent`, which is why a hostile filename, log line or domain
/// can't become a script. This keeps it that way, and the CSP above is the second line of defence.
#[test]
fn the_ui_uses_no_html_injection_sinks() {
    let mut scanned = 0;
    let mut found = Vec::new();
    for name in web::Asset::iter() {
        if !name.ends_with(".js") {
            continue;
        }
        scanned += 1;
        let file = web::Asset::get(&name).unwrap();
        let text = String::from_utf8_lossy(&file.data);
        for sink in [
            ".innerHTML",
            ".outerHTML",
            "insertAdjacentHTML",
            "document.write",
            "eval(",
            "new Function",
            "javascript:",
            "srcdoc",
            ".setHTML",
        ] {
            if text.contains(sink) {
                found.push(format!("{name}: {sink}"));
            }
        }
        // Tokens in web storage could be read by any script that got in.
        for stored in [
            "localStorage.setItem('token",
            "localStorage.setItem(\"token",
            "cp_session",
        ] {
            if text.contains(stored) {
                found.push(format!("{name}: {stored}"));
            }
        }
    }
    assert!(scanned > 3, "the UI wasn't found");
    assert!(found.is_empty(), "{found:?}");
}

#[test]
fn the_page_loads_no_inline_or_third_party_scripts() {
    let file = web::Asset::get("index.html").unwrap();
    let html = String::from_utf8_lossy(&file.data).to_lowercase();
    assert!(!html.contains("http://") && !html.contains("https://"), "{html}");
    assert!(!html.contains(" onload=") && !html.contains(" onclick="), "{html}");
    for tag in html.split("<script").skip(1) {
        let open = tag.split('>').next().unwrap();
        assert!(open.contains("src="), "inline script: {tag}");
    }
}

/// A file named so as to be an attack on whoever downloads it.
#[tokio::test]
async fn downloads_are_attachments_and_their_name_cannot_inject_headers() {
    let h = super::super::tests::harness();
    let (id, home) = managed_site_with_home(&h, "dl.example.com");
    let name = "evil\".html";
    if std::fs::write(home.join(name), "<script>alert(1)</script>").is_err() {
        return; // Not a legal file name on Windows.
    }
    let cookie = h.login("manager").await;
    let r = send(
        &h,
        "127.0.0.1",
        axum::http::Request::builder()
            .uri(format!("/api/sites/{id}/files/download?path=evil%22.html"))
            .header(header::COOKIE, cookie),
        Body::empty(),
    )
    .await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.text());
    assert_eq!(r.headers.get(header::CONTENT_TYPE).unwrap(), "application/octet-stream");
    assert_eq!(
        r.headers.get(header::CONTENT_DISPOSITION).unwrap(),
        "attachment; filename=\"evil_.html\""
    );
}

/// The file manager returns file contents in JSON, not as a page a browser would run.
#[tokio::test]
async fn file_contents_come_back_as_json() {
    let h = super::super::tests::harness();
    let (id, home) = managed_site_with_home(&h, "view.example.com");
    std::fs::write(home.join("page.html"), "<script>alert(1)</script>").unwrap();
    let cookie = h.login("manager").await;
    let r = send(
        &h,
        "127.0.0.1",
        axum::http::Request::builder()
            .uri(format!("/api/sites/{id}/files/content?path=page.html"))
            .header(header::COOKIE, cookie),
        Body::empty(),
    )
    .await;
    assert_eq!(r.status, StatusCode::OK);
    assert!(r
        .headers
        .get(header::CONTENT_TYPE)
        .unwrap()
        .to_str()
        .unwrap()
        .starts_with("application/json"));
}
