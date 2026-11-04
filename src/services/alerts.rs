use crate::config::Config;
use crate::db::DbPool;
use crate::state::SharedState;

pub fn evaluate(_state: &SharedState) {}

/// Send a one-off notification (e.g. a failed backup) to every enabled channel.
pub fn notify_event(_config: &Config, _pool: &DbPool, title: &str, body: &str) {
    tracing::warn!("{title}: {body}");
}
