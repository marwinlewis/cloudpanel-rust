//! Hostile values at the API. Most of the panel's strings end up in a config file, a command line
//! or a SQL statement run by root, so anything that isn't plainly valid has to stop at the door.

use super::*;
use crate::validate;
use serde_json::json;

/// What an attacker would try in any field that reaches a shell, a config file or a statement.
const INJECTIONS: &[&str] = &[
    "x;id",
    "x && id",
    "x|id",
    "$(id)",
    "`id`",
    "x\nid",
    "x\r\nid",
    "x\0y",
    "x'y",
    "x\"y",
    "x y",
    "../x",
    "..",
    "-rf",
    "--help",
    "x{y}",
    "x;\n}\nserver {",
    "%0aid",
    "x\u{202e}y",
];

#[test]
fn identifiers_refuse_every_injection() {
    type Check = fn(&str) -> bool;
    let checks: &[(&str, Check)] = &[
        ("domain", |s| validate::domain(s).is_ok()),
        ("system_user", |s| validate::system_user(s).is_ok()),
        ("username", |s| validate::username(s).is_ok()),
        ("email", |s| validate::email(s).is_ok()),
        ("db_identifier", |s| validate::db_identifier(s).is_ok()),
        ("container_id", |s| validate::container_id(s).is_ok()),
        ("image_ref", |s| validate::image_ref(s).is_ok()),
        ("cidr", |s| validate::cidr(s).is_ok()),
        ("file_mode", |s| validate::file_mode(s).is_ok()),
    ];
    for (name, ok) in checks {
        for bad in INJECTIONS {
            // Panel usernames never reach a command line, and may start with a dash.
            if *name == "username" && bad.starts_with('-') {
                continue;
            }
            assert!(!ok(bad), "{name} accepted {bad:?}");
        }
    }
}

#[test]
fn free_text_fields_cannot_break_out_of_their_line() {
    for bad in ["x\ny", "x\ry", "x\0y"] {
        assert!(validate::cron_command(bad).is_err(), "{bad:?}");
        assert!(validate::app_command(bad).is_err(), "{bad:?}");
        assert!(validate::cron_schedule(bad).is_err(), "{bad:?}");
    }
    assert!(validate::short_text(Some("x\ny"), 80).is_err());
    assert!(validate::cron_command(&"x".repeat(1001)).is_err());
}

#[test]
fn a_cron_schedule_is_only_a_schedule() {
    for bad in [
        "* * * * * root id",
        "* * * * *; id",
        "$(id) * * * *",
        "* * * *",
        "@reboot\nid",
        "* * * * * *",
    ] {
        assert!(validate::cron_schedule(bad).is_err(), "{bad:?}");
    }
    assert!(validate::cron_schedule("*/5 * * * *").is_ok());
}

#[test]
fn file_names_cannot_name_a_path() {
    for bad in ["", ".", "..", "a/b", "../a", "/etc/passwd", "a\\b", "a\0b", "a\nb"] {
        assert!(validate::file_name(bad).is_err(), "{bad:?}");
    }
    assert!(validate::file_name("report.pdf").is_ok());
}

#[test]
fn setuid_bits_cannot_be_set_through_file_mode_or_are_stopped_later() {
    for bad in ["8888", "abc", "", "77777", "-1", "0o777"] {
        assert!(validate::file_mode(bad).is_err(), "{bad:?}");
    }
}

#[test]
fn ssh_keys_cannot_carry_options_that_run_commands() {
    for bad in [
        "command=\"id\" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJ x",
        "no-pty ssh-rsa AAAA x",
        "ssh-ed25519 AAAA x\nssh-rsa BBBB y",
        "from=\"*\" ssh-rsa AAAA",
        "",
        "not a key",
    ] {
        assert!(validate::ssh_public_key(bad).is_err(), "{bad:?}");
    }
}

#[test]
fn env_keys_cannot_inject_lines() {
    for bad in ["", "A B", "A=B", "A\nB", "1A", "A;B", "$A", "A-B"] {
        assert!(validate::env_key(bad).is_err(), "{bad:?}");
    }
}

/// A shortlist, not a sandbox, as admin directives are trusted. See the open finding about what
/// gets past the first word of a line.
#[test]
fn nginx_directives_refuse_the_obvious_ways_out() {
    for bad in ["include /etc/shadow;", "load_module x.so;", "}\nserver {"] {
        assert!(validate::nginx_directives(bad).is_err(), "{bad:?}");
    }
}

#[test]
#[cfg(unix)]
fn panel_paths_stay_inside_their_base() {
    let base = std::path::Path::new("/home/u/htdocs");
    for bad in [
        "/etc",
        "/home/u/htdocs/../../..",
        "/home/u/htdocs/x/../../y",
        "/home/u/htdocsx",
        "/home/u/htdocs/x\ny",
        "/home/u/htdocs/x y",
        "/home/u/htdocs/x;y",
        "/home/u/htdocs/$x",
    ] {
        assert!(validate::path_within(bad, base).is_err(), "{bad:?}");
    }
    assert!(validate::path_within("/home/u/htdocs/x", base).is_ok());
}

#[test]
fn php_versions_cannot_reach_paths_or_unit_names() {
    use crate::services::php::valid_version;
    for bad in ["../..", "8.4;id", "8.4\n", "8.4/../..", "-8.4", "8.4 "] {
        assert!(!valid_version(bad), "{bad:?}");
    }
}

// ---------- Through the router ----------

/// A rejected create must never reach the code that makes a Linux user, an nginx file and so on.
#[tokio::test]
async fn hostile_domains_are_refused_before_anything_is_created() {
    let h = super::super::tests::harness();
    let cookie = h.login("admin").await;
    let before = db::list_sites(&h.pool.get().unwrap()).unwrap().len();
    for bad in INJECTIONS.iter().chain(&[
        "example.com;",
        "example.com\nserver_name evil",
        "*.example.com",
        "localhost",
        "a..b.com",
        "-a.com",
    ]) {
        let (s, v, _) = h
            .call(
                "POST",
                "/sites",
                Some(&cookie),
                Some(json!({"domain": bad, "site_type": "static"})),
                true,
            )
            .await;
        assert_eq!(s, StatusCode::BAD_REQUEST, "{bad:?} {v}");
    }
    assert_eq!(db::list_sites(&h.pool.get().unwrap()).unwrap().len(), before);
}

#[tokio::test]
async fn hostile_database_names_are_refused() {
    let h = super::super::tests::harness();
    let (id, home) = managed_site_with_home(&h, "dbnames.example.com");
    let cookie = h.login("manager").await;
    for bad in INJECTIONS
        .iter()
        .chain(&["x`; DROP DATABASE y; --", "A", "1a", "x.y", "x%"])
    {
        let (s, v, _) = h
            .call(
                "POST",
                &format!("/sites/{id}/databases"),
                Some(&cookie),
                Some(json!({"engine": "sqlite", "name": bad})),
                true,
            )
            .await;
        assert_eq!(s, StatusCode::BAD_REQUEST, "{bad:?} {v}");
    }
    assert_eq!(std::fs::read_dir(home.join("databases")).unwrap().count(), 0);
}

/// `admin`, `mysql` and the like already exist on the server. Taking one over gives the site user
/// credentials on it, an export of it, or a way to drop it.
#[test]
fn sec03_names_the_database_server_uses_itself_are_refused() {
    for reserved in [
        "admin",
        "config",
        "local",
        "mysql",
        "information_schema",
        "performance_schema",
        "sys",
        "root",
    ] {
        assert!(validate::db_identifier(reserved).is_err(), "{reserved}");
    }
    assert!(validate::db_identifier("shop_admin").is_ok());
    assert!(validate::db_identifier("myapp").is_ok());
}

#[tokio::test]
async fn hostile_file_paths_go_nowhere() {
    let h = super::super::tests::harness();
    let (id, home) = managed_site_with_home(&h, "paths.example.com");
    // Something to find, should a path get out.
    let outside = home.parent().unwrap().join("outside.txt");
    std::fs::write(&outside, "secret").unwrap();
    let cookie = h.login("manager").await;
    for bad in [
        "../outside.txt",
        "..%2foutside.txt",
        "%2e%2e/outside.txt",
        "htdocs/../../outside.txt",
        "./../outside.txt",
        "....//outside.txt",
        "..\\outside.txt",
        "..%5coutside.txt",
        "%00",
        "/proc/self/environ",
        "/etc/passwd",
        "/../outside.txt",
    ] {
        let path = bad.replace('\\', "%5c");
        for route in ["content", "download"] {
            let (s, v, _) = h
                .call(
                    "GET",
                    &format!("/sites/{id}/files/{route}?path={path}"),
                    Some(&cookie),
                    None,
                    false,
                )
                .await;
            assert_ne!(s, StatusCode::OK, "{route} {bad:?}: {v}");
            assert!(!v.to_string().contains("secret"), "{route} {bad:?}: {v}");
        }
        for (op, body) in [
            ("delete", json!({"op": "delete", "path": path})),
            ("chmod", json!({"op": "chmod", "path": path, "mode": "0777"})),
            (
                "rename",
                json!({"op": "rename", "path": "htdocs", "to": format!("x/{path}")}),
            ),
        ] {
            let (s, _, _) = h
                .call(
                    "POST",
                    &format!("/sites/{id}/files/op"),
                    Some(&cookie),
                    Some(body),
                    true,
                )
                .await;
            assert_ne!(s, StatusCode::OK, "{op} {bad:?}");
        }
    }
    assert_eq!(std::fs::read_to_string(&outside).unwrap(), "secret");
}

#[tokio::test]
async fn setuid_and_setgid_bits_cannot_be_set_through_the_file_manager() {
    let h = super::super::tests::harness();
    let (id, home) = managed_site_with_home(&h, "suid.example.com");
    std::fs::write(home.join("prog"), "x").unwrap();
    let cookie = h.login("manager").await;
    for mode in ["4755", "2755", "6755", "1777"] {
        let (s, _, _) = h
            .call(
                "POST",
                &format!("/sites/{id}/files/op"),
                Some(&cookie),
                Some(json!({"op": "chmod", "path": "prog", "mode": mode})),
                true,
            )
            .await;
        assert_eq!(s, StatusCode::BAD_REQUEST, "{mode}");
    }
}

#[tokio::test]
async fn a_cron_job_with_a_hostile_schedule_is_never_stored() {
    let h = super::super::tests::harness();
    let (id, _) = managed_site_with_home(&h, "cronin.example.com");
    let cookie = h.login("manager").await;
    for (schedule, command) in [
        ("* * * * *\n* * * * * root id", "true"),
        ("* * * * * root", "true"),
        ("* * * * *", "true\n* * * * * root id"),
    ] {
        let (s, _, _) = h
            .call(
                "POST",
                "/cron/jobs",
                Some(&cookie),
                Some(json!({"site_id": id, "schedule": schedule, "command": command})),
                true,
            )
            .await;
        assert_eq!(s, StatusCode::BAD_REQUEST, "{schedule:?} {command:?}");
    }
    assert!(db::list_cron_jobs(&h.pool.get().unwrap()).unwrap().is_empty());
}

// ---------- Generated config ----------

fn site(site_type: &str) -> crate::db::models::Site {
    let mut s = crate::services::nginx::test_site(site_type);
    s.document_root = Some("/home/u/htdocs/x".into());
    s
}

fn config() -> crate::config::Config {
    crate::config::Config::from_env()
}

/// Static and PHP sites serve files that their own user can arrange. Without this, a link to
/// another site's file is served by nginx, whose user is in every site's group.
#[test]
fn sec08_nginx_only_follows_a_link_to_the_links_own_user() {
    for kind in ["static", "php"] {
        let c = crate::services::nginx::NginxService::generate_config(&config(), &site(kind));
        assert!(c.contains("disable_symlinks if_not_owner"), "{kind}:\n{c}");
    }
}

/// Cross-site reads again: a site manager can set their document root, and a link inside the home
/// is a way to point it at somewhere else.
#[tokio::test]
#[cfg(unix)]
async fn sec08_a_document_root_cannot_be_a_link_out_of_the_site() {
    let h = super::super::tests::harness();
    let (id, home) = managed_site_with_home(&h, "docroot.example.com");
    let elsewhere = home.parent().unwrap().join("elsewhere");
    std::fs::create_dir_all(&elsewhere).unwrap();
    let link = home.join("htdocs/docroot.example.com/out");
    std::os::unix::fs::symlink(&elsewhere, &link).unwrap();
    let cookie = h.login("manager").await;
    let (s, v, _) = h
        .call(
            "PATCH",
            &format!("/sites/{id}"),
            Some(&cookie),
            Some(json!({"document_root": link.to_string_lossy()})),
            true,
        )
        .await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "{v}");
    let stored = db::find_site_by_id(&h.pool.get().unwrap(), id).unwrap().unwrap();
    assert_ne!(stored.document_root.as_deref(), Some(&*link.to_string_lossy()));
}

/// Whoever gets the panel's port while it restarts must not be sent admin cookies and the secret.
#[test]
fn sec09_nginx_checks_who_it_is_talking_to_before_sending_the_panel_secret() {
    use crate::services::nginx::{NginxService, PanelVhost};
    let c = NginxService::render_panel_vhost(
        &config(),
        &PanelVhost {
            hostname: "panel.example.com".into(),
            cert: "/etc/x.pem".into(),
            key: "/etc/x.key".into(),
            upstream: "https://127.0.0.1:8443".into(),
            secret: "s3cret".into(),
            real_ip_from: vec![],
        },
    );
    assert!(c.contains("proxy_ssl_verify on;"), "{c}");
    assert!(!c.contains("proxy_ssl_verify off"), "{c}");
    assert!(c.contains("proxy_ssl_trusted_certificate "), "{c}");
    assert!(c.contains("proxy_ssl_name panel.example.com;"), "{c}");
}

/// nginx hands PHP only files that exist, or an uploaded `x.jpg/y.php` runs the image as a script.
#[test]
fn php_only_runs_files_that_exist() {
    let c = crate::services::nginx::NginxService::generate_config(&config(), &site("php"));
    assert!(c.contains("try_files $uri =404;"), "{c}");
}

#[test]
fn dotfiles_are_not_served() {
    for kind in ["static", "php"] {
        let c = crate::services::nginx::NginxService::generate_config(&config(), &site(kind));
        assert!(c.contains(r"location ~ /\.(?!well-known)"), "{kind}:\n{c}");
        assert!(c.contains("deny all;"), "{kind}:\n{c}");
    }
}

#[test]
fn each_php_site_runs_as_its_own_user_on_its_own_socket() {
    use crate::services::php::{render_pool, socket_path};
    let p = render_pool("a.example.com", "a-user");
    assert!(p.contains("user = a-user\ngroup = a-user\n"), "{p}");
    assert!(
        p.contains(&format!("listen = {}\n", socket_path("a.example.com"))),
        "{p}"
    );
    // Only nginx may connect, not another site's user.
    assert!(
        p.contains("listen.owner = www-data\nlisten.group = www-data\nlisten.mode = 0660\n"),
        "{p}"
    );
    assert!(!p.contains("root"), "{p}");
    assert_ne!(socket_path("a.example.com"), socket_path("b.example.com"));
}
