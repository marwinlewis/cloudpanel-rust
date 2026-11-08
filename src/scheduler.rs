//! Minute-resolution background scheduler: backups, alerts, retention and the panel
//! certificate reload.

use crate::state::SharedState;
use chrono::{Duration as ChronoDuration, Utc};
use std::time::Duration;

pub fn start(state: SharedState) {
    tokio::spawn(async move {
        // Let the server finish starting first.
        tokio::time::sleep(Duration::from_secs(5)).await;
        let mut tick = tokio::time::interval(Duration::from_secs(60));
        let mut minute: u64 = 0;
        loop {
            tick.tick().await;
            let st = state.clone();
            let m = minute;
            let _ = tokio::task::spawn_blocking(move || run_tick(&st, m)).await;
            minute = minute.wrapping_add(1);
        }
    });
}

fn run_tick(state: &SharedState, minute: u64) {
    crate::services::backups::run_scheduled(state);
    crate::services::alerts::evaluate(state);
    if minute % 60 == 0 {
        retention(state);
    }
    if minute % (60 * 12) == 0 {
        crate::services::panel_cert::reload_if_changed(state);
    }
}

fn retention(state: &SharedState) {
    let Ok(conn) = state.pool.get() else { return };
    let _ = crate::db::prune_events(&conn, Utc::now() - ChronoDuration::days(90));
    let _ = crate::db::prune_jobs(&conn, Utc::now() - ChronoDuration::days(14));
    let _ = crate::db::prune_revoked_tokens(&conn, Utc::now());
}
