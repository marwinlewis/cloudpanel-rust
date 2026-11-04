//! Audit log: who did what, when, from where.

use crate::auth::AuthUser;
use crate::db::{insert_event, NewEvent};
use rusqlite::Connection;

/// Record an action by `actor`. Failures are logged, never surfaced: auditing must not
/// break the operation that already happened.
pub fn record(conn: &Connection, actor: &AuthUser, action: &str, target: Option<&str>, detail: Option<&str>) {
    let ev = NewEvent {
        user_id: Some(actor.id),
        username: Some(&actor.username),
        ip: actor.ip.as_deref(),
        action,
        target,
        detail,
    };
    if let Err(e) = insert_event(conn, &ev) {
        tracing::warn!("audit log write failed for {action}: {e}");
    }
}

/// Record an event without an authenticated user (failed logins, scheduler, CLI).
pub fn record_system(
    conn: &Connection,
    username: Option<&str>,
    ip: Option<&str>,
    action: &str,
    target: Option<&str>,
    detail: Option<&str>,
) {
    let ev = NewEvent {
        user_id: None,
        username,
        ip,
        action,
        target,
        detail,
    };
    if let Err(e) = insert_event(conn, &ev) {
        tracing::warn!("audit log write failed for {action}: {e}");
    }
}
